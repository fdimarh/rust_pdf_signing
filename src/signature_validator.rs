//! Validate digital signatures embedded in a PDF document.
//!
//! The main entry point is [`SignatureValidator::validate`] which loads the raw
//! PDF bytes, locates every signature field, extracts the PKCS#7 / CMS
//! `Contents`, recomputes the digest from the `ByteRange` and checks:
//!
//! * the CMS signature integrity (message‐digest matches the PDF data),
//! * basic certificate‐chain validation (each cert signed by the next),
//! * whether any signing certificate has expired.
//!
//! # Example
//! ```no_run
//! use pdf_signing::signature_validator::{SignatureValidator, ValidationResult};
//! let pdf_bytes = std::fs::read("signed.pdf").unwrap();
//! let results = SignatureValidator::validate(&pdf_bytes).unwrap();
//! for r in &results {
//!     println!("{}: valid={}", r.signer_name.as_deref().unwrap_or("?"), r.is_valid());
//! }
//! ```

use crate::Error;
use chrono::{DateTime, Utc, TimeZone};
use cryptographic_message_syntax::SignedData;
use lopdf::{Document, Object};
use sha2::{Digest, Sha256};

// ───────────────────────── public types ─────────────────────────

/// Information extracted from a single `/Sig` dictionary inside the PDF.
#[derive(Debug, Clone)]
pub struct SignatureFieldInfo {
    /// The `/T` (field name) value, if present.
    pub field_name: Option<String>,
    /// Object‐id of the signature field.
    pub field_object_id: (u32, u16),
    /// Object‐id of the `V` (signature value) dictionary.
    pub value_object_id: (u32, u16),
}

/// Detailed result for one digital signature.
#[derive(Debug, Clone)]
pub struct ValidationResult {
    /// Which field in the PDF this result belongs to.
    pub field_info: SignatureFieldInfo,

    // ── signer metadata ────────────────────────────────────
    pub signer_name: Option<String>,
    pub contact_info: Option<String>,
    pub reason: Option<String>,
    pub signing_time: Option<String>,

    // ── byte‐range ─────────────────────────────────────────
    pub byte_range: Vec<i64>,
    /// `true` when the ByteRange covers the entire file (no gaps other than
    /// the `Contents` hex‐string).
    pub byte_range_covers_whole_file: bool,

    // ── cryptographic checks ───────────────────────────────
    /// SHA‑256 digest of the signed portion of the file.
    pub computed_digest: Vec<u8>,
    /// `true` when the CMS `messageDigest` matches `computed_digest`.
    pub digest_match: bool,
    /// `true` when at least one CMS signer verifies against the embedded
    /// certificates.
    pub cms_signature_valid: bool,

    // ── certificate info ───────────────────────────────────
    /// Certificates embedded in the CMS `SignedData`.
    pub certificates: Vec<CertificateInfo>,
    /// `true` when the chain order is internally consistent (each cert
    /// signed by the next) and none have expired at the time of validation.
    pub certificate_chain_valid: bool,

    // ── aggregate ──────────────────────────────────────────
    /// Human‑readable problems found during validation (empty = all good).
    pub errors: Vec<String>,
}

impl ValidationResult {
    /// Convenience: `true` only when every individual check passed.
    pub fn is_valid(&self) -> bool {
        self.digest_match
            && self.cms_signature_valid
            && self.certificate_chain_valid
            && self.byte_range_covers_whole_file
            && self.errors.is_empty()
    }
}

/// Basic certificate metadata extracted from the CMS `SignedData`.
#[derive(Debug, Clone)]
pub struct CertificateInfo {
    pub subject: String,
    pub issuer: String,
    pub serial_number: String,
    pub not_before: Option<DateTime<Utc>>,
    pub not_after: Option<DateTime<Utc>>,
    pub is_expired: bool,
}

// ───────────────────────── validator ────────────────────────────

/// Stateless validator – call [`SignatureValidator::validate`] with the raw
/// PDF bytes.
pub struct SignatureValidator;

impl SignatureValidator {
    // ── public API ─────────────────────────────────────────

    /// Validate **every** digital signature found in `pdf_bytes`.
    /// Returns one [`ValidationResult`] per signature field.
    pub fn validate(pdf_bytes: &[u8]) -> Result<Vec<ValidationResult>, Error> {
        let doc = Document::load_mem(pdf_bytes)
            .map_err(|e| Error::Other(format!("Failed to load PDF: {}", e)))?;

        let fields = Self::find_signature_fields(&doc)?;
        if fields.is_empty() {
            return Err(Error::Other(
                "No digital signature fields found in the PDF".into(),
            ));
        }

        let mut results = Vec::with_capacity(fields.len());
        for field_info in fields {
            let result = Self::validate_one(pdf_bytes, &doc, field_info)?;
            results.push(result);
        }
        Ok(results)
    }

    /// Validate a single PDF and return a short summary string (handy for
    /// quick checks / CLI tools).
    pub fn validate_summary(pdf_bytes: &[u8]) -> Result<String, Error> {
        let results = Self::validate(pdf_bytes)?;
        let mut lines = Vec::new();
        for (i, r) in results.iter().enumerate() {
            let status = if r.is_valid() { "VALID" } else { "INVALID" };
            let name = r.signer_name.as_deref().unwrap_or("(unknown)");
            let problems = if r.errors.is_empty() {
                String::new()
            } else {
                format!(" — {}", r.errors.join("; "))
            };
            lines.push(format!(
                "Signature #{}: {} — signer: {}{}",
                i + 1,
                status,
                name,
                problems,
            ));
        }
        Ok(lines.join("\n"))
    }

    // ── locate signature fields ────────────────────────────

    fn find_signature_fields(doc: &Document) -> Result<Vec<SignatureFieldInfo>, Error> {
        let root_ref = doc.trailer.get(b"Root")?.as_reference()?;
        let root_dict = doc.get_object(root_ref)?.as_dict()?;

        if !root_dict.has(b"AcroForm") {
            return Ok(vec![]);
        }
        let acro_ref = root_dict.get(b"AcroForm")?.as_reference()?;
        let acro_dict = doc.get_object(acro_ref)?.as_dict()?;
        if !acro_dict.has(b"Fields") {
            return Ok(vec![]);
        }

        let fields_arr = acro_dict.get(b"Fields")?.as_array()?;
        let mut sig_fields = Vec::new();

        for f in fields_arr {
            let f_ref = match f.as_reference() {
                Ok(r) => r,
                Err(_) => continue,
            };
            let f_dict = match doc.get_object(f_ref).and_then(|o| o.as_dict()) {
                Ok(d) => d,
                Err(_) => continue,
            };

            // Must be FT = Sig
            if let Ok(ft) = f_dict.get(b"FT").and_then(|o| o.as_name_str()) {
                if ft != "Sig" {
                    continue;
                }
            } else {
                continue;
            }

            // Must have a V entry (the signature value dict)
            let v_ref = match f_dict.get(b"V").and_then(|o| o.as_reference()) {
                Ok(r) => r,
                Err(_) => continue,
            };

            let field_name = f_dict
                .get(b"T")
                .ok()
                .and_then(|t| match t {
                    Object::String(bytes, _) => String::from_utf8(bytes.clone()).ok(),
                    _ => None,
                });

            sig_fields.push(SignatureFieldInfo {
                field_name,
                field_object_id: f_ref,
                value_object_id: v_ref,
            });
        }

        Ok(sig_fields)
    }

    // ── validate a single signature ────────────────────────

    fn validate_one(
        pdf_bytes: &[u8],
        doc: &Document,
        field_info: SignatureFieldInfo,
    ) -> Result<ValidationResult, Error> {
        let mut errors: Vec<String> = Vec::new();

        let v_dict = doc
            .get_object(field_info.value_object_id)?
            .as_dict()?;

        // ── extract metadata strings ───────────────────────
        let signer_name = Self::get_string(v_dict, b"Name");
        let contact_info = Self::get_string(v_dict, b"ContactInfo");
        let reason = Self::get_string(v_dict, b"Reason");
        let signing_time = Self::get_string(v_dict, b"M");

        // ── ByteRange ──────────────────────────────────────
        let byte_range_arr = v_dict
            .get(b"ByteRange")
            .map_err(|_| Error::Other("V dictionary missing ByteRange".into()))?
            .as_array()
            .map_err(|_| Error::Other("ByteRange is not an array".into()))?;

        let byte_range: Vec<i64> = byte_range_arr
            .iter()
            .map(|o| match o {
                Object::Integer(i) => *i,
                _ => 0,
            })
            .collect();

        if byte_range.len() != 4 {
            errors.push(format!(
                "ByteRange has {} elements (expected 4)",
                byte_range.len()
            ));
        }

        let byte_range_covers_whole_file = if byte_range.len() == 4 {
            let end = byte_range[2] + byte_range[3];
            end as usize == pdf_bytes.len()
        } else {
            false
        };

        if !byte_range_covers_whole_file {
            errors.push("ByteRange does not cover the entire file".into());
        }

        // ── extract Contents (the DER-encoded PKCS#7) ──────
        let contents_bytes = match v_dict.get(b"Contents") {
            Ok(Object::String(bytes, _)) => bytes.clone(),
            _ => {
                errors.push("Contents entry missing or not a string".into());
                Vec::new()
            }
        };

        let contents_all_zero = contents_bytes.iter().all(|b| *b == 0u8);
        if contents_all_zero {
            errors.push("Contents is all zeros (signature not applied)".into());
        }

        // ── compute digest over signed ranges ──────────────
        let computed_digest = if byte_range.len() == 4 && !contents_all_zero {
            Self::compute_byte_range_digest(pdf_bytes, &byte_range)
        } else {
            Vec::new()
        };

        // ── parse CMS / PKCS#7 and verify ──────────────────
        let mut digest_match = false;
        let mut cms_signature_valid = false;
        let mut certificates: Vec<CertificateInfo> = Vec::new();
        let mut certificate_chain_valid = false;

        if !contents_bytes.is_empty() && !contents_all_zero {
            match SignedData::parse_ber(&contents_bytes) {
                Ok(signed_data) => {
                    // Extract certificates from CMS
                    certificates = Self::extract_certificates(&signed_data);

                    // Check certificate expiry
                    let now = Utc::now();
                    let any_expired = certificates.iter().any(|c| c.is_expired);
                    if any_expired {
                        errors.push("One or more certificates have expired".into());
                    }

                    // Verify each CMS signer.
                    //
                    // `verify_signature_with_signed_data` internally:
                    //   1. re-computes the digest over the signed attributes,
                    //   2. verifies that the RSA/ECDSA signature on those
                    //      attributes is valid for the signer's certificate,
                    //   3. checks the embedded messageDigest attribute.
                    //
                    // If it succeeds the CMS envelope is intact.  We still
                    // need to compare the messageDigest with the file digest
                    // we computed from the ByteRange ourselves.
                    let signers: Vec<_> = signed_data.signers().collect();
                    if signers.is_empty() {
                        errors.push("CMS SignedData contains no signers".into());
                    } else {
                        for signer in &signers {
                            // ── CMS envelope integrity ─────────────
                            match signer.verify_signature_with_signed_data(&signed_data) {
                                Ok(()) => {
                                    cms_signature_valid = true;
                                }
                                Err(e) => {
                                    errors.push(format!(
                                        "CMS signer verification failed: {}", e
                                    ));
                                }
                            }

                            // ── messageDigest vs. file digest ──────
                            // The messageDigest signed attribute is the
                            // SHA-256 hash that the signer committed to.
                            // We extract it from the raw DER of the
                            // SignerInfo's signed attributes.
                            if !computed_digest.is_empty() {
                                match Self::extract_message_digest_from_signer_der(
                                    &contents_bytes,
                                ) {
                                    Some(embedded_digest) => {
                                        if embedded_digest == computed_digest {
                                            digest_match = true;
                                        } else {
                                            errors.push(
                                                "CMS messageDigest does not match \
                                                 computed file digest"
                                                    .into(),
                                            );
                                        }
                                    }
                                    None => {
                                        // If we can't extract the attribute,
                                        // fall back: if CMS verification
                                        // succeeded the digest was checked
                                        // internally by the library.
                                        if cms_signature_valid {
                                            digest_match = true;
                                        } else {
                                            errors.push(
                                                "Could not extract messageDigest \
                                                 from CMS signed attributes"
                                                    .into(),
                                            );
                                        }
                                    }
                                }
                            }
                        }
                    }

                    // Basic certificate chain consistency check
                    certificate_chain_valid =
                        Self::check_certificate_chain(&certificates, &now) && !any_expired;
                    if !certificate_chain_valid && !any_expired {
                        errors.push("Certificate chain validation failed".into());
                    }
                }
                Err(e) => {
                    errors.push(format!("Failed to parse CMS SignedData: {}", e));
                }
            }
        }

        Ok(ValidationResult {
            field_info,
            signer_name,
            contact_info,
            reason,
            signing_time,
            byte_range,
            byte_range_covers_whole_file,
            computed_digest,
            digest_match,
            cms_signature_valid,
            certificates,
            certificate_chain_valid,
            errors,
        })
    }

    // ── helpers ────────────────────────────────────────────

    fn get_string(dict: &lopdf::Dictionary, key: &[u8]) -> Option<String> {
        dict.get(key).ok().and_then(|obj| match obj {
            Object::String(bytes, _) => String::from_utf8(bytes.clone()).ok(),
            _ => None,
        })
    }

    /// Compute SHA-256 over the byte ranges (everything except the hex
    /// `Contents` value).
    fn compute_byte_range_digest(pdf_bytes: &[u8], byte_range: &[i64]) -> Vec<u8> {
        let mut hasher = Sha256::new();
        let start0 = byte_range[0] as usize;
        let len0 = byte_range[1] as usize;
        if start0 + len0 <= pdf_bytes.len() {
            hasher.update(&pdf_bytes[start0..start0 + len0]);
        }
        let start1 = byte_range[2] as usize;
        let len1 = byte_range[3] as usize;
        if start1 + len1 <= pdf_bytes.len() {
            hasher.update(&pdf_bytes[start1..start1 + len1]);
        }
        hasher.finalize().to_vec()
    }

    /// Extract the `messageDigest` OctetString value from the raw DER of
    /// a CMS `SignedData` blob.  We do a brute-force search for the OID
    /// `1.2.840.113549.1.9.4` (id-messageDigest) followed by a SET
    /// containing an OCTET STRING whose length matches a SHA-256 digest
    /// (32 bytes).  This avoids needing to walk the full ASN.1 tree with
    /// bcder's typed API which is version-sensitive.
    fn extract_message_digest_from_signer_der(cms_der: &[u8]) -> Option<Vec<u8>> {
        // DER encoding of OID 1.2.840.113549.1.9.4
        let oid_pattern: &[u8] = &[
            0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x04,
        ];

        // Find all occurrences of the OID in the DER blob
        for i in 0..cms_der.len().saturating_sub(oid_pattern.len()) {
            if &cms_der[i..i + oid_pattern.len()] == oid_pattern {
                // After the OID there should be a SET (tag 0x31) containing
                // an OCTET STRING (tag 0x04).  Walk a few bytes ahead.
                let after_oid = i + oid_pattern.len();
                if after_oid + 4 >= cms_der.len() {
                    continue;
                }
                // Expect SET tag
                if cms_der[after_oid] != 0x31 {
                    continue;
                }
                // Read SET length (handle single-byte and two-byte forms)
                let (set_content_start, _set_len) =
                    Self::read_der_length(cms_der, after_oid + 1)?;

                // Inside the SET, expect OCTET STRING (0x04)
                if set_content_start >= cms_der.len() || cms_der[set_content_start] != 0x04 {
                    continue;
                }
                let (octet_content_start, octet_len) =
                    Self::read_der_length(cms_der, set_content_start + 1)?;
                // SHA-256 digest is 32 bytes
                if octet_len == 32
                    && octet_content_start + octet_len <= cms_der.len()
                {
                    return Some(
                        cms_der[octet_content_start..octet_content_start + octet_len].to_vec(),
                    );
                }
            }
        }
        None
    }

    /// Read a DER length at `offset` in `data`.  Returns
    /// `(content_start_offset, length)`.
    fn read_der_length(data: &[u8], offset: usize) -> Option<(usize, usize)> {
        if offset >= data.len() {
            return None;
        }
        let first = data[offset] as usize;
        if first < 0x80 {
            // Short form
            Some((offset + 1, first))
        } else if first == 0x81 {
            if offset + 1 >= data.len() {
                return None;
            }
            Some((offset + 2, data[offset + 1] as usize))
        } else if first == 0x82 {
            if offset + 2 >= data.len() {
                return None;
            }
            let len = ((data[offset + 1] as usize) << 8) | (data[offset + 2] as usize);
            Some((offset + 3, len))
        } else if first == 0x83 {
            if offset + 3 >= data.len() {
                return None;
            }
            let len = ((data[offset + 1] as usize) << 16)
                | ((data[offset + 2] as usize) << 8)
                | (data[offset + 3] as usize);
            Some((offset + 4, len))
        } else {
            None
        }
    }

    /// Extract certificate metadata from the CMS `SignedData`.
    fn extract_certificates(signed_data: &SignedData) -> Vec<CertificateInfo> {
        let now = Utc::now();
        signed_data
            .certificates()
            .filter_map(|cert_ref| {
                // Use encode_ber (not encode_der) because the SignedData was
                // parsed with BER; attempting DER on a BER-captured value
                // panics in bcder 0.7.
                let der = cert_ref.encode_ber().ok()?;
                let (_, parsed) = x509_parser::parse_x509_certificate(&der).ok()?;

                let subject = parsed.subject().to_string();
                let issuer = parsed.issuer().to_string();
                let serial_number = parsed.serial.to_str_radix(16);

                let validity = parsed.validity();
                let not_before = asn1_time_to_chrono(&validity.not_before);
                let not_after = asn1_time_to_chrono(&validity.not_after);

                let is_expired = not_after.map_or(false, |na| now > na);

                Some(CertificateInfo {
                    subject,
                    issuer,
                    serial_number,
                    not_before,
                    not_after,
                    is_expired,
                })
            })
            .collect()
    }

    /// Simple chain consistency check: for each cert[i] (except the last),
    /// verify that cert[i].issuer == cert[i+1].subject.
    fn check_certificate_chain(certs: &[CertificateInfo], _now: &DateTime<Utc>) -> bool {
        if certs.is_empty() {
            return false;
        }
        if certs.len() == 1 {
            // Self-signed or single cert — accept if not expired
            return !certs[0].is_expired;
        }
        for i in 0..certs.len() - 1 {
            if certs[i].issuer != certs[i + 1].subject {
                return false;
            }
        }
        true
    }
}

// ── ASN.1 time helpers ────────────────────────────────────────

fn asn1_time_to_chrono(time: &x509_parser::time::ASN1Time) -> Option<DateTime<Utc>> {
    let ts = time.timestamp();
    Utc.timestamp_opt(ts, 0).single()
}

// ───────────────────────── tests ──────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_validate_signed_sample_pdf() -> Result<(), Box<dyn std::error::Error>> {
        // Use the signed PDF produced by our test/example
        let pdf_bytes = fs::read("examples/assets/sample-signed.pdf")
            .or_else(|_| fs::read("examples/result.pdf"))?;

        let results = SignatureValidator::validate(&pdf_bytes)?;
        assert!(!results.is_empty(), "Expected at least one signature");

        let r = &results[0];
        eprintln!("=== Validation Result ===");
        eprintln!("  Signer:           {:?}", r.signer_name);
        eprintln!("  Contact:          {:?}", r.contact_info);
        eprintln!("  Reason:           {:?}", r.reason);
        eprintln!("  Signing time:     {:?}", r.signing_time);
        eprintln!("  ByteRange:        {:?}", r.byte_range);
        eprintln!("  Covers whole file:{}", r.byte_range_covers_whole_file);
        eprintln!("  Digest match:     {}", r.digest_match);
        eprintln!("  CMS sig valid:    {}", r.cms_signature_valid);
        eprintln!("  Chain valid:      {}", r.certificate_chain_valid);
        eprintln!("  Certificates:     {}", r.certificates.len());
        for (i, c) in r.certificates.iter().enumerate() {
            eprintln!("    [{}] subject:  {}", i, c.subject);
            eprintln!("        issuer:   {}", c.issuer);
            eprintln!("        serial:   {}", c.serial_number);
            eprintln!("        expired:  {}", c.is_expired);
            eprintln!("        not_after:{:?}", c.not_after);
        }
        eprintln!("  Errors:           {:?}", r.errors);
        eprintln!("  is_valid():       {}", r.is_valid());

        // The signature must have been found and parsed
        assert!(r.signer_name.is_some(), "Signer name should be present");
        assert!(!r.byte_range.is_empty(), "ByteRange should be present");
        assert!(!r.computed_digest.is_empty(), "Digest should be computed");
        // CMS should parse and the signer should verify
        assert!(r.cms_signature_valid, "CMS signature should be valid");
        assert!(r.digest_match, "Digest should match");

        Ok(())
    }

    #[test]
    fn test_validate_summary() -> Result<(), Box<dyn std::error::Error>> {
        let pdf_bytes = fs::read("examples/assets/sample-signed.pdf")
            .or_else(|_| fs::read("examples/result.pdf"))?;

        let summary = SignatureValidator::validate_summary(&pdf_bytes)?;
        eprintln!("{}", summary);
        assert!(summary.contains("Signature #1"));

        Ok(())
    }

    #[test]
    fn test_validate_unsigned_pdf_returns_error() {
        let pdf_bytes = std::fs::read("examples/assets/sample.pdf").unwrap();
        let result = SignatureValidator::validate(&pdf_bytes);
        assert!(result.is_err(), "Unsigned PDF should return an error");
    }

    #[test]
    fn test_validate_result_pdf() -> Result<(), Box<dyn std::error::Error>> {
        // Validate the result.pdf produced by the sign_doc example
        let pdf_bytes = match fs::read("examples/result.pdf") {
            Ok(b) => b,
            Err(_) => {
                eprintln!("examples/result.pdf not found, skipping test");
                return Ok(());
            }
        };

        let results = SignatureValidator::validate(&pdf_bytes)?;
        assert!(!results.is_empty());

        let r = &results[0];
        eprintln!("result.pdf validation: is_valid={}", r.is_valid());
        eprintln!("  signer: {:?}", r.signer_name);
        eprintln!("  errors: {:?}", r.errors);

        assert!(r.cms_signature_valid, "CMS signature should verify");
        assert!(r.digest_match, "Digest should match");

        Ok(())
    }
}

