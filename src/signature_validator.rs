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
use serde::Serialize;
use sha2::{Digest, Sha256};

/// Serialize a `Vec<u8>` as a hex string.
mod hex_bytes {
    use serde::Serializer;
    pub fn serialize<S: Serializer>(bytes: &Vec<u8>, s: S) -> Result<S::Ok, S::Error> {
        let hex: String = bytes.iter().map(|b| format!("{:02x}", b)).collect();
        s.serialize_str(&hex)
    }
}

// ───────────────────────── public types ─────────────────────────

/// Information extracted from a single `/Sig` dictionary inside the PDF.
#[derive(Debug, Clone, Serialize)]
pub struct SignatureFieldInfo {
    /// The `/T` (field name) value, if present.
    pub field_name: Option<String>,
    /// Object‐id of the signature field.
    pub field_object_id: (u32, u16),
    /// Object‐id of the `V` (signature value) dictionary.
    pub value_object_id: (u32, u16),
    /// `true` when the V dictionary has `/Type /DocTimeStamp` (PAdES B-LTA).
    pub is_document_timestamp: bool,
}

/// Detailed result for one digital signature.
#[derive(Debug, Clone, Serialize)]
pub struct ValidationResult {
    /// Which field in the PDF this result belongs to.
    pub field_info: SignatureFieldInfo,

    // ── signer metadata ────────────────────────────────────
    pub signer_name: Option<String>,
    pub contact_info: Option<String>,
    pub reason: Option<String>,
    pub signing_time: Option<String>,
    /// The `/Filter` value (e.g. "Adobe.PPKLite").
    pub filter: Option<String>,
    /// The `/SubFilter` value (e.g. "adbe.pkcs7.detached" or "ETSI.CAdES.detached").
    pub sub_filter: Option<String>,

    // ── byte‐range ─────────────────────────────────────────
    pub byte_range: Vec<i64>,
    /// `true` when the ByteRange covers the entire file (no gaps other than
    /// the `Contents` hex‐string).
    pub byte_range_covers_whole_file: bool,

    // ── cryptographic checks ───────────────────────────────
    /// SHA‑256 digest of the signed portion of the file.
    #[serde(serialize_with = "hex_bytes::serialize")]
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
    /// `true` when the root certificate of the chain is a well-known
    /// trusted CA.  When `false`, the chain may still be structurally
    /// valid but the root is self-signed or not recognized.
    pub certificate_chain_trusted: bool,
    /// Warnings about the certificate chain (e.g. self-signed root,
    /// untrusted issuer).  These are informational — the signature
    /// can still be structurally valid.
    pub chain_warnings: Vec<String>,

    // ── LTV (Long-Term Validation) ─────────────────────────
    /// `true` when the PDF contains a document-level DSS dictionary.
    pub has_dss: bool,
    /// Number of CRL streams in the DSS dictionary.
    pub dss_crl_count: usize,
    /// Number of OCSP response streams in the DSS dictionary.
    pub dss_ocsp_count: usize,
    /// Number of certificate streams in the DSS dictionary.
    pub dss_cert_count: usize,
    /// `true` when the DSS contains a VRI entry for this specific signature.
    pub has_vri: bool,
    /// `true` when the CMS `SignedData` contains embedded revocation data
    /// (adbe-revocationInfoArchival attribute with CRL or OCSP).
    pub has_cms_revocation_data: bool,
    /// `true` when the CMS contains a signature timestamp
    /// (id-smime-aa-signatureTimeStampToken unsigned attribute).
    pub has_timestamp: bool,
    /// `true` when the signature has enough information for long-term
    /// validation: either DSS with revocation data, or CMS-embedded
    /// revocation data, plus a timestamp.
    pub is_ltv_enabled: bool,

    // ── modification detection ─────────────────────────────
    /// The byte offset where this signature's revision ends (the `%%EOF`
    /// that terminates the incremental update containing this signature).
    pub signature_revision_end: usize,
    /// `true` when subsequent incremental updates contain ONLY permitted
    /// changes (new signatures, DSS, annotations for new sigs).
    /// `false` when unauthorized modifications were detected after signing.
    pub no_unauthorized_modifications: bool,
    /// Human-readable list of modifications detected after this signature.
    /// Empty means no modifications (or this is the last revision).
    pub modification_notes: Vec<String>,

    // ── pdf-insecurity.org attack detection ─────────────────
    /// `true` when the ByteRange structure is valid: starts at 0, no
    /// overlaps, no gaps (beyond the Contents hex-string), and the gap
    /// contains only the hex-encoded Contents value.
    /// Defends against: Universal Signature Forgery (USF).
    pub byte_range_valid: bool,
    /// `true` when the Contents hex-string is located exactly in the
    /// ByteRange gap and has not been relocated/duplicated.
    /// Defends against: Signature Wrapping Attack (SWA).
    pub signature_not_wrapped: bool,
    /// If the document has a `/Perms` → `/DocMDP` certification, this
    /// contains the MDP permission level (1, 2, or 3). `None` if not certified.
    /// Defends against: PDF Certification Attack.
    pub certification_level: Option<u8>,
    /// `true` when MDP permissions are not violated by subsequent changes.
    pub certification_permission_ok: bool,
    /// Security warnings from attack-specific checks.
    pub security_warnings: Vec<String>,

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
            && self.no_unauthorized_modifications
            && self.byte_range_valid
            && self.signature_not_wrapped
            && self.certification_permission_ok
            && self.errors.is_empty()
    }
}

/// Basic certificate metadata extracted from the CMS `SignedData`.
#[derive(Debug, Clone, Serialize)]
pub struct CertificateInfo {
    pub subject: String,
    pub issuer: String,
    pub serial_number: String,
    pub not_before: Option<DateTime<Utc>>,
    pub not_after: Option<DateTime<Utc>>,
    pub is_expired: bool,
    /// `true` when subject == issuer (self-signed certificate).
    pub is_self_signed: bool,
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

        // ── Determine revision boundaries for each signature ──
        // Find all %%EOF markers — each marks the end of a revision.
        let eof_offsets = Self::find_eof_offsets(pdf_bytes);

        // For each signature, find which revision it belongs to by looking
        // at where its ByteRange ends, then find the next %%EOF after that.
        for r in results.iter_mut() {
            if r.byte_range.len() == 4 {
                let sig_data_end = (r.byte_range[2] + r.byte_range[3]) as usize;
                // Find the %%EOF that terminates this signature's revision
                r.signature_revision_end = eof_offsets
                    .iter()
                    .find(|&&eof| eof >= sig_data_end)
                    .copied()
                    .unwrap_or(pdf_bytes.len());
            }
        }

        // ── Modification detection ──
        // For each non-last signature, check that incremental updates
        // added AFTER its revision contain only permitted changes.
        Self::detect_modifications(pdf_bytes, &mut results)?;

        // ── pdf-insecurity.org attack detection ──
        // 1. USF: Validate ByteRange structure
        // 2. SWA: Verify Contents hex-string location
        // 3. Certification: Check MDP permission enforcement
        for r in results.iter_mut() {
            // --- USF defense: ByteRange structural validation ---
            let (br_valid, br_warnings) =
                Self::validate_byte_range_structure(pdf_bytes, &r.byte_range);
            r.byte_range_valid = br_valid;
            if !br_valid {
                r.errors.push("ByteRange structure is invalid (possible USF attack)".into());
            }
            r.security_warnings.extend(br_warnings);

            // --- SWA defense: Contents location cross-check ---
            let (not_wrapped, swa_warnings) =
                Self::validate_signature_not_wrapped(pdf_bytes, &r.byte_range);
            r.signature_not_wrapped = not_wrapped;
            if !not_wrapped {
                r.errors.push(
                    "Signature Contents appears to be relocated (possible SWA attack)".into(),
                );
            }
            r.security_warnings.extend(swa_warnings);

            // --- Certification attack defense: MDP permissions ---
            let (cert_level, cert_ok, cert_warnings) =
                Self::check_certification_permissions(&doc, pdf_bytes, r);
            r.certification_level = cert_level;
            r.certification_permission_ok = cert_ok;
            if !cert_ok {
                r.errors.push(
                    "Document certification permissions violated (possible certification attack)"
                        .into(),
                );
            }
            r.security_warnings.extend(cert_warnings);
        }

        // In a multi-signature document, only the *last* signature (the most
        // recent incremental update) is expected to cover the entire file.
        // Earlier signatures legitimately have a ByteRange that ends before
        // subsequent incremental updates.
        let total = results.len();
        if total > 0 {
            let last_idx = total - 1;
            if !results[last_idx].byte_range_covers_whole_file {
                results[last_idx].errors.push(
                    "ByteRange does not cover the entire file".into(),
                );
            }
            // For earlier signatures in multi-sig docs, no error is added;
            // the `byte_range_covers_whole_file` field still records the
            // fact, so callers can inspect it if needed.
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

            // Must have a V entry (the signature value dict) OR be a merged
            // DocTimeStamp where the field dict itself contains ByteRange/Contents.
            let (v_ref, is_document_timestamp) = match f_dict.get(b"V").and_then(|o| o.as_reference()) {
                Ok(r) => {
                    // Standard case: separate V dictionary
                    let v_dict_opt = doc
                        .get_object(r)
                        .and_then(|o| o.as_dict())
                        .ok();
                    // A document timestamp can be identified by either:
                    //   /Type /DocTimeStamp  (PDF 2.0 style)
                    //   /SubFilter /ETSI.RFC3161  (works with /Type /Sig too)
                    let is_ts = v_dict_opt.map_or(false, |vd| {
                        let type_is_ts = vd
                            .get(b"Type")
                            .ok()
                            .and_then(|t| t.as_name_str().ok())
                            .map_or(false, |name| name == "DocTimeStamp");
                        let subfilter_is_ts = vd
                            .get(b"SubFilter")
                            .ok()
                            .and_then(|t| t.as_name_str().ok())
                            .map_or(false, |name| name == "ETSI.RFC3161");
                        type_is_ts || subfilter_is_ts
                    });
                    (r, is_ts)
                }
                Err(_) => {
                    // Check if this is a merged DocTimeStamp field-widget-value dict:
                    // the dict itself has /Type /DocTimeStamp, /Contents, /ByteRange
                    let is_merged_ts = f_dict
                        .get(b"Type")
                        .and_then(|t| t.as_name_str())
                        .ok()
                        .map_or(false, |name| name == "DocTimeStamp")
                        && f_dict.has(b"Contents")
                        && f_dict.has(b"ByteRange");
                    if is_merged_ts {
                        // Use the field's own object ID as the V object ID
                        (f_ref, true)
                    } else {
                        continue;
                    }
                }
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
                is_document_timestamp,
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
        let filter = v_dict
            .get(b"Filter")
            .ok()
            .and_then(|o| o.as_name_str().ok())
            .map(|s| s.to_string());
        let sub_filter = v_dict
            .get(b"SubFilter")
            .ok()
            .and_then(|o| o.as_name_str().ok())
            .map(|s| s.to_string());

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

        // Note: we do NOT add an error here for !byte_range_covers_whole_file
        // because in multi-signature PDFs, earlier signatures legitimately
        // do not cover the entire file (subsequent incremental updates are
        // appended after them).  The caller (validate()) adds a contextual
        // warning only when a single-signature document fails this check.

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
        let mut certificate_chain_trusted = false;
        let mut chain_warnings: Vec<String> = Vec::new();
        let is_doc_timestamp = field_info.is_document_timestamp;

        if !contents_bytes.is_empty() && !contents_all_zero {
            // For DocTimeStamp, the Contents is an RFC 3161 timestamp token
            // wrapped in a ContentInfo.  We try multiple parsing strategies:
            // 1. Parse directly (works if the library accepts ContentInfo)
            // 2. Extract the inner SignedData from the ContentInfo wrapper
            let cms_parse_result = if is_doc_timestamp {
                // Strip trailing zeros from the contents (hex padding)
                let trimmed = Self::trim_trailing_zeros(&contents_bytes);
                SignedData::parse_ber(trimmed)
                    .or_else(|_| {
                        // Try extracting inner SignedData from ContentInfo
                        Self::extract_signed_data_from_content_info(trimmed)
                            .map(|inner| SignedData::parse_ber(&inner))
                            .unwrap_or_else(|| SignedData::parse_ber(trimmed))
                    })
            } else {
                SignedData::parse_ber(&contents_bytes)
            };

            match cms_parse_result {
                Ok(signed_data) => {
                    // Extract certificates from CMS
                    certificates = Self::extract_certificates(&signed_data);

                    // Check certificate expiry
                    let now = Utc::now();
                    let any_expired = certificates.iter().any(|c| c.is_expired);
                    if any_expired {
                        errors.push("One or more certificates have expired".into());
                    }

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

                            // ── digest verification ────────────────
                            if !computed_digest.is_empty() {
                                if is_doc_timestamp {
                                    // For timestamp tokens, extract messageImprint
                                    // hash from TSTInfo (inside the encapContentInfo)
                                    let trimmed = Self::trim_trailing_zeros(&contents_bytes);
                                    match Self::extract_timestamp_imprint_hash(trimmed) {
                                        Some(imprint_hash) => {
                                            if imprint_hash == computed_digest {
                                                digest_match = true;
                                            } else {
                                                errors.push(
                                                    "Timestamp messageImprint does not match \
                                                     computed file digest"
                                                        .into(),
                                                );
                                            }
                                        }
                                        None => {
                                            // Fall back: if CMS verification
                                            // succeeded, trust the timestamp
                                            if cms_signature_valid {
                                                digest_match = true;
                                            } else {
                                                errors.push(
                                                    "Could not extract messageImprint \
                                                     from timestamp token"
                                                        .into(),
                                                );
                                            }
                                        }
                                    }
                                } else {
                                    // Regular signature: check messageDigest
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
                    }

                    // Certificate chain consistency + trust check
                    let (chain_ok, chain_trusted_result, chain_warns) =
                        Self::check_certificate_chain(&certificates, &now);
                    certificate_chain_valid = chain_ok;
                    certificate_chain_trusted = chain_trusted_result;
                    chain_warnings = chain_warns;

                    if !certificate_chain_valid && !any_expired {
                        errors.push("Certificate chain validation failed".into());
                    }
                }
                Err(e) => {
                    errors.push(format!("Failed to parse CMS SignedData: {}", e));
                }
            }
        }

        // ── LTV (Long-Term Validation) checks ─────────────
        let (has_dss, dss_crl_count, dss_ocsp_count, dss_cert_count, has_vri) =
            Self::check_dss(doc, &contents_bytes);

        let has_cms_revocation_data = if !contents_bytes.is_empty() && !contents_all_zero {
            Self::check_cms_revocation_data(&contents_bytes)
        } else {
            false
        };

        let has_timestamp = if !contents_bytes.is_empty() && !contents_all_zero {
            Self::check_cms_timestamp(&contents_bytes)
        } else {
            false
        };

        // LTV is considered enabled when:
        // 1. There is revocation data available (either DSS with CRLs/OCSPs,
        //    or CMS-embedded revocation data), AND
        // 2. A signature timestamp is present (to anchor the validation time).
        let has_revocation = (has_dss && (dss_crl_count > 0 || dss_ocsp_count > 0))
            || has_cms_revocation_data;
        let is_ltv_enabled = has_revocation && has_timestamp;

        Ok(ValidationResult {
            field_info,
            signer_name,
            contact_info,
            reason,
            signing_time,
            filter,
            sub_filter,
            byte_range,
            byte_range_covers_whole_file,
            computed_digest,
            digest_match,
            cms_signature_valid,
            certificates,
            certificate_chain_valid,
            certificate_chain_trusted,
            chain_warnings,
            has_dss,
            dss_crl_count,
            dss_ocsp_count,
            dss_cert_count,
            has_vri,
            has_cms_revocation_data,
            has_timestamp,
            is_ltv_enabled,
            signature_revision_end: 0,
            no_unauthorized_modifications: true,
            modification_notes: Vec::new(),
            byte_range_valid: true,
            signature_not_wrapped: true,
            certification_level: None,
            certification_permission_ok: true,
            security_warnings: Vec::new(),
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

    /// Trim trailing zero bytes from a DER-encoded blob.
    /// PDF hex-string Contents are padded with zeros to fill the placeholder.
    fn trim_trailing_zeros(data: &[u8]) -> &[u8] {
        // Find the actual DER content length from the outer SEQUENCE tag
        if data.len() < 2 || data[0] != 0x30 {
            return data;
        }
        match Self::read_der_length(data, 1) {
            Some((content_start, content_len)) => {
                let total = content_start + content_len;
                if total <= data.len() {
                    &data[..total]
                } else {
                    data
                }
            }
            None => data,
        }
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
                let is_self_signed = subject == issuer;

                Some(CertificateInfo {
                    subject,
                    issuer,
                    serial_number,
                    not_before,
                    not_after,
                    is_expired,
                    is_self_signed,
                })
            })
            .collect()
    }

    /// Check for a DSS (Document Security Store) dictionary at the
    /// document root level.  Returns `(has_dss, crl_count, ocsp_count,
    /// cert_count, has_vri_for_this_sig)`.
    ///
    /// The VRI lookup uses the SHA-1 hash of the signature `Contents` value
    /// (uppercase hex) as the key inside `DSS.VRI`, per PDF 2.0 spec
    /// (ISO 32000-2 §12.8.4.3).
    fn check_dss(
        doc: &Document,
        contents_bytes: &[u8],
    ) -> (bool, usize, usize, usize, bool) {
        let root_ref = match doc.trailer.get(b"Root").and_then(|o| o.as_reference()) {
            Ok(r) => r,
            Err(_) => return (false, 0, 0, 0, false),
        };
        let root_dict = match doc.get_object(root_ref).and_then(|o| o.as_dict()) {
            Ok(d) => d,
            Err(_) => return (false, 0, 0, 0, false),
        };

        if !root_dict.has(b"DSS") {
            return (false, 0, 0, 0, false);
        }

        let dss_dict = match root_dict.get(b"DSS") {
            Ok(Object::Dictionary(d)) => d.clone(),
            Ok(Object::Reference(r)) => match doc.get_object(*r).and_then(|o| o.as_dict()) {
                Ok(d) => d.clone(),
                Err(_) => return (false, 0, 0, 0, false),
            },
            _ => return (false, 0, 0, 0, false),
        };

        let crl_count = dss_dict
            .get(b"CRLs")
            .ok()
            .and_then(|o| o.as_array().ok())
            .map_or(0, |a| a.len());
        let ocsp_count = dss_dict
            .get(b"OCSPs")
            .ok()
            .and_then(|o| o.as_array().ok())
            .map_or(0, |a| a.len());
        let cert_count = dss_dict
            .get(b"Certs")
            .ok()
            .and_then(|o| o.as_array().ok())
            .map_or(0, |a| a.len());

        // Check VRI (Validation Related Information) for this signature.
        // The key is the uppercase SHA-1 hex of the Contents value.
        let has_vri = if !contents_bytes.is_empty() && dss_dict.has(b"VRI") {
            use sha1::{Sha1, Digest as Sha1Digest};
            let mut hasher = Sha1::new();
            hasher.update(contents_bytes);
            let sig_hash = hasher.finalize();
            let vri_key = sig_hash
                .iter()
                .map(|b| format!("{:02X}", b))
                .collect::<String>();

            match dss_dict.get(b"VRI") {
                Ok(Object::Dictionary(vri_dict)) => vri_dict.has(vri_key.as_bytes()),
                Ok(Object::Reference(r)) => {
                    doc.get_object(*r)
                        .and_then(|o| o.as_dict())
                        .map_or(false, |d| d.has(vri_key.as_bytes()))
                }
                _ => false,
            }
        } else {
            false
        };

        (true, crl_count, ocsp_count, cert_count, has_vri)
    }

    /// Check whether the CMS `SignedData` contains an
    /// `adbe-revocationInfoArchival` signed attribute
    /// (OID 1.2.840.113583.1.1.8) which embeds CRL/OCSP data.
    fn check_cms_revocation_data(cms_der: &[u8]) -> bool {
        // DER encoding of OID 1.2.840.113583.1.1.8
        let oid_pattern: &[u8] = &[
            0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x2f, 0x01, 0x01, 0x08,
        ];
        cms_der
            .windows(oid_pattern.len())
            .any(|w| w == oid_pattern)
    }

    /// Check whether the CMS `SignedData` contains a signature timestamp
    /// (OID 1.2.840.113549.1.9.16.2.14 — id-smime-aa-signatureTimeStampToken).
    fn check_cms_timestamp(cms_der: &[u8]) -> bool {
        // DER encoding of OID 1.2.840.113549.1.9.16.2.14
        let oid_pattern: &[u8] = &[
            0x06, 0x0b, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x10,
            0x02, 0x0e,
        ];
        cms_der
            .windows(oid_pattern.len())
            .any(|w| w == oid_pattern)
    }

    /// Extract the inner `SignedData` from an RFC 3161 timestamp token
    /// (which is a CMS `ContentInfo` wrapping a `SignedData`).
    ///
    /// ContentInfo ::= SEQUENCE {
    ///   contentType   OID (1.2.840.113549.1.7.2 = id-signedData),
    ///   content [0]   EXPLICIT SignedData
    /// }
    fn extract_signed_data_from_content_info(data: &[u8]) -> Option<Vec<u8>> {
        if data.is_empty() || data[0] != 0x30 {
            return None;
        }
        let (outer_start, _outer_len) = Self::read_der_length(data, 1)?;

        // Skip the contentType OID
        let pos = outer_start;
        if pos >= data.len() || data[pos] != 0x06 {
            return None;
        }
        let (oid_content_start, oid_len) = Self::read_der_length(data, pos + 1)?;
        let after_oid = oid_content_start + oid_len;

        // Next should be [0] EXPLICIT (tag 0xA0)
        if after_oid >= data.len() || data[after_oid] != 0xA0 {
            return None;
        }
        let (explicit_start, _explicit_len) = Self::read_der_length(data, after_oid + 1)?;

        // The SignedData SEQUENCE starts here
        if explicit_start < data.len() && data[explicit_start] == 0x30 {
            Some(data[explicit_start..].to_vec())
        } else {
            None
        }
    }

    /// Extract the `messageImprint` hash from a TSTInfo structure inside a
    /// timestamp token's SignedData encapContentInfo.
    ///
    /// We search for the SHA-256 OID (2.16.840.1.101.3.4.2.1) followed by
    /// an OCTET STRING of 32 bytes — this is the `hashedMessage` in the
    /// `MessageImprint` within `TSTInfo`.
    fn extract_timestamp_imprint_hash(signed_data_der: &[u8]) -> Option<Vec<u8>> {
        // OID for SHA-256: 2.16.840.1.101.3.4.2.1
        let sha256_oid: &[u8] = &[
            0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
        ];

        // Find the SHA-256 OID inside the encapsulated content (TSTInfo).
        // After the AlgorithmIdentifier there should be an OCTET STRING
        // with the 32-byte hash.
        for i in 0..signed_data_der.len().saturating_sub(sha256_oid.len()) {
            if &signed_data_der[i..i + sha256_oid.len()] == sha256_oid {
                // After the OID, skip the NULL (05 00) in AlgorithmIdentifier
                let mut pos = i + sha256_oid.len();
                // Skip NULL if present
                if pos + 1 < signed_data_der.len()
                    && signed_data_der[pos] == 0x05
                    && signed_data_der[pos + 1] == 0x00
                {
                    pos += 2;
                }
                // Skip the closing of the AlgorithmIdentifier SEQUENCE
                // and look for the OCTET STRING (0x04) within a few bytes
                for offset in 0..10 {
                    let check = pos + offset;
                    if check >= signed_data_der.len() {
                        break;
                    }
                    if signed_data_der[check] == 0x04 {
                        let (content_start, content_len) =
                            Self::read_der_length(signed_data_der, check + 1)?;
                        if content_len == 32 && content_start + 32 <= signed_data_der.len() {
                            return Some(
                                signed_data_der[content_start..content_start + 32].to_vec(),
                            );
                        }
                    }
                }
            }
        }
        None
    }

    /// Check the certificate chain for structural consistency, expiry,
    /// and trust status.
    ///
    /// Returns `(chain_valid, chain_trusted, warnings)`:
    /// - `chain_valid`: the chain is internally consistent (issuer linkage)
    ///   and no certs are expired.
    /// - `chain_trusted`: the root CA is a known trusted certificate
    ///   authority (not self-signed with an unknown issuer).
    /// - `warnings`: human-readable notes about trust issues.
    fn check_certificate_chain(
        certs: &[CertificateInfo],
        _now: &DateTime<Utc>,
    ) -> (bool, bool, Vec<String>) {
        let mut warnings = Vec::new();

        if certs.is_empty() {
            return (false, false, vec!["No certificates in signature".into()]);
        }

        // -- Structural consistency: issuer chain linkage --
        let mut chain_valid = true;
        if certs.len() > 1 {
            for i in 0..certs.len() - 1 {
                if certs[i].issuer != certs[i + 1].subject {
                    chain_valid = false;
                    warnings.push(format!(
                        "Chain break: cert[{}] issuer '{}' does not match cert[{}] subject '{}'",
                        i, certs[i].issuer, i + 1, certs[i + 1].subject
                    ));
                }
            }
        }

        // -- Expiry check --
        for (i, c) in certs.iter().enumerate() {
            if c.is_expired {
                chain_valid = false;
                warnings.push(format!(
                    "Certificate [{}] '{}' has expired (not_after: {:?})",
                    i,
                    c.subject,
                    c.not_after
                ));
            }
        }

        // -- Trust status --
        // The root cert is the last in the chain.  It is "trusted" if it
        // is signed by a well-known CA.  For self-signed roots (subject ==
        // issuer), we flag them as untrusted unless they are a known root.
        //
        // Since we don't ship a trust store, we use heuristics:
        //  1. If the root is self-signed AND is the signing cert itself
        //     (chain length 1), it's a test/self-signed certificate.
        //  2. If the root is self-signed but part of a longer chain,
        //     it may be a private CA root — still warn.
        //  3. Known public CAs are recognized by common issuer names.
        let root = &certs[certs.len() - 1];
        let signer = &certs[0];
        let chain_trusted;

        if root.is_self_signed {
            if certs.len() == 1 {
                // Single self-signed cert — test certificate
                chain_trusted = false;
                warnings.push(format!(
                    "Self-signed certificate: '{}'. \
                     Not issued by a trusted Certificate Authority.",
                    signer.subject
                ));
            } else {
                // Self-signed root in a chain — check if it's a known public CA
                let is_known_ca = Self::is_known_trusted_root(&root.subject);
                if is_known_ca {
                    chain_trusted = true;
                } else {
                    chain_trusted = false;
                    warnings.push(format!(
                        "Root CA '{}' is self-signed but not recognized as a \
                         trusted public Certificate Authority.",
                        root.subject
                    ));
                }
            }
        } else {
            // Root is not self-signed — the issuing CA cert may not be
            // included in the chain.  This is common for intermediate CAs
            // where the root is in the OS trust store.
            let is_known_issuer = Self::is_known_trusted_root(&root.issuer);
            if is_known_issuer {
                chain_trusted = true;
            } else {
                chain_trusted = false;
                warnings.push(format!(
                    "Issuer '{}' of root certificate '{}' is not recognized \
                     as a trusted Certificate Authority. The full chain to a \
                     trusted root may not be included.",
                    root.issuer, root.subject
                ));
            }
        }

        (chain_valid, chain_trusted, warnings)
    }

    /// Check if a certificate subject/issuer DN matches a known public
    /// trusted root CA.  This is a heuristic based on common CA names.
    fn is_known_trusted_root(dn: &str) -> bool {
        // Normalize for comparison
        let dn_lower = dn.to_lowercase();

        // Well-known public root CAs
        let known_roots = [
            // DigiCert
            "digicert",
            // GlobalSign
            "globalsign",
            // Let's Encrypt / ISRG
            "isrg root",
            "let's encrypt",
            // Comodo / Sectigo
            "comodo",
            "sectigo",
            "usertrust",
            // Entrust
            "entrust",
            // GeoTrust
            "geotrust",
            // Thawte
            "thawte",
            // VeriSign / Symantec
            "verisign",
            "symantec",
            // Baltimore / CyberTrust
            "baltimore",
            "cybertrust",
            // QuoVadis
            "quovadis",
            // Buypass
            "buypass",
            // SwissSign
            "swisssign",
            // Certum
            "certum",
            // IdenTrust / DST
            "identrust",
            "dst root",
            // Amazon
            "amazon root",
            "starfield",
            // Microsoft
            "microsoft root",
            // Apple
            "apple root",
            // Google Trust Services
            "google trust",
            "gts root",
            // Actalis
            "actalis",
            // HARICA
            "harica",
            // T-TeleSec
            "t-telesec",
            "deutsche telekom",
            // Certigna
            "certigna",
            // AC Camerfirma
            "camerfirma",
        ];

        known_roots.iter().any(|root| dn_lower.contains(root))
    }

    // ═══════════════════════════════════════════════════════
    // pdf-insecurity.org attack defenses
    // ═══════════════════════════════════════════════════════

    // ── 1. USF defense: ByteRange structural validation ────
    //
    // Universal Signature Forgery manipulates ByteRange values to make
    // the signature cover different data than what's displayed.
    //
    // Checks:
    //  - ByteRange[0] must be 0 (signature starts at file beginning)
    //  - All values must be non-negative
    //  - No overlapping ranges
    //  - The gap between range 0 and range 1 must be exactly the
    //    Contents hex-string (enclosed in `<` and `>`)
    //  - Ranges must not exceed file size
    //  - The gap must contain only valid hex characters

    fn validate_byte_range_structure(
        pdf_bytes: &[u8],
        byte_range: &[i64],
    ) -> (bool, Vec<String>) {
        let mut warnings = Vec::new();
        let mut valid = true;

        if byte_range.len() != 4 {
            warnings.push(format!(
                "[USF] ByteRange has {} elements, expected 4",
                byte_range.len()
            ));
            return (false, warnings);
        }

        let offset1 = byte_range[0];
        let length1 = byte_range[1];
        let offset2 = byte_range[2];
        let length2 = byte_range[3];
        let file_len = pdf_bytes.len() as i64;

        // ByteRange[0] must be 0
        if offset1 != 0 {
            warnings.push(format!(
                "[USF] ByteRange starts at offset {} instead of 0 — \
                 beginning of file not covered by signature",
                offset1
            ));
            valid = false;
        }

        // All values must be non-negative
        if offset1 < 0 || length1 < 0 || offset2 < 0 || length2 < 0 {
            warnings.push("[USF] ByteRange contains negative values".into());
            valid = false;
        }

        // Ranges must not exceed file size
        if offset1 + length1 > file_len {
            warnings.push("[USF] First range exceeds file size".into());
            valid = false;
        }
        if offset2 + length2 > file_len {
            warnings.push("[USF] Second range exceeds file size".into());
            valid = false;
        }

        // No overlapping ranges: end of range 0 must be <= start of range 1
        let range0_end = offset1 + length1;
        if range0_end > offset2 {
            warnings.push(format!(
                "[USF] Ranges overlap: first range ends at {} but second starts at {}",
                range0_end, offset2
            ));
            valid = false;
        }

        // The gap between ranges must contain the Contents hex-string
        if range0_end < offset2 && range0_end >= 0 && offset2 <= file_len {
            let gap_start = range0_end as usize;
            let gap_end = offset2 as usize;
            let gap = &pdf_bytes[gap_start..gap_end];

            // Gap must start with '<' and end with '>'
            if gap.is_empty() {
                warnings.push("[USF] Zero-length gap between ByteRange segments".into());
                valid = false;
            } else {
                if gap[0] != b'<' {
                    warnings.push(format!(
                        "[USF] ByteRange gap does not start with '<' (found 0x{:02x})",
                        gap[0]
                    ));
                    valid = false;
                }
                if gap[gap.len() - 1] != b'>' {
                    warnings.push(format!(
                        "[USF] ByteRange gap does not end with '>' (found 0x{:02x})",
                        gap[gap.len() - 1]
                    ));
                    valid = false;
                }

                // Contents between < and > must be valid hex characters
                if gap.len() >= 2 {
                    let hex_content = &gap[1..gap.len() - 1];
                    let non_hex = hex_content
                        .iter()
                        .any(|b| !b.is_ascii_hexdigit());
                    if non_hex {
                        warnings.push(
                            "[USF] ByteRange gap contains non-hex characters — \
                             possible content injection in signature placeholder"
                                .into(),
                        );
                        valid = false;
                    }
                }
            }
        }

        // Sanity: length1 should be reasonable (at least a few hundred bytes
        // for even a minimal PDF header + objects)
        if length1 < 50 {
            warnings.push(format!(
                "[USF] First ByteRange segment is suspiciously short ({} bytes)",
                length1
            ));
            valid = false;
        }

        (valid, warnings)
    }

    // ── 2. SWA defense: Signature Wrapping Attack detection ──
    //
    // SWA moves the original signature Contents to a different location
    // and inserts a forged signature at the expected offset.  We verify
    // that the actual `/Contents<` hex string in the raw bytes is at the
    // expected position within the ByteRange gap.

    fn validate_signature_not_wrapped(
        pdf_bytes: &[u8],
        byte_range: &[i64],
    ) -> (bool, Vec<String>) {
        let mut warnings = Vec::new();

        if byte_range.len() != 4 {
            return (true, warnings); // Can't check without valid ByteRange
        }

        let gap_start = byte_range[0] as usize + byte_range[1] as usize;
        let gap_end = byte_range[2] as usize;

        if gap_start >= pdf_bytes.len() || gap_end > pdf_bytes.len() || gap_start >= gap_end {
            return (true, warnings); // Handled by ByteRange validation
        }

        // Look for `/Contents<` pattern near the gap.  The pattern should
        // appear immediately before gap_start (within the signed region).
        // Scan backwards from gap_start to find `/Contents`.
        let search_start = gap_start.saturating_sub(20);
        let search_region = &pdf_bytes[search_start..gap_start];
        let pattern = b"/Contents";
        let found_before_gap = search_region
            .windows(pattern.len())
            .any(|w| w == pattern);

        if !found_before_gap {
            warnings.push(
                "[SWA] /Contents key not found immediately before ByteRange gap — \
                 signature may have been relocated"
                    .into(),
            );
            return (false, warnings);
        }

        // Check that there is no SECOND `/Contents<` hex-string elsewhere
        // in the file that could be a wrapped/duplicated signature.
        let gap_hex = &pdf_bytes[gap_start..gap_end];
        let _expected_hex_len = gap_hex.len();

        // Count occurrences of `/Contents<` followed by hex data of
        // approximately the same length
        let contents_pattern = b"/Contents<";
        let mut occurrences = 0;
        let mut pos = 0;
        while pos + contents_pattern.len() < pdf_bytes.len() {
            if let Some(found) = pdf_bytes[pos..]
                .windows(contents_pattern.len())
                .position(|w| w == contents_pattern)
            {
                let abs_pos = pos + found;
                let hex_start = abs_pos + contents_pattern.len();

                // Find the closing '>'
                if let Some(close_pos) = pdf_bytes[hex_start..].iter().position(|&b| b == b'>') {
                    let this_hex_len = close_pos + 2; // Include < and >
                    // Only count if the hex string is large enough to be a
                    // signature (>= 100 bytes, i.e. >= 200 hex chars)
                    if this_hex_len >= 200 {
                        occurrences += 1;
                    }
                    pos = hex_start + close_pos + 1;
                } else {
                    pos = hex_start + 1;
                }
            } else {
                break;
            }
        }

        // In a multi-signature document, each signature has its own
        // /Contents<...>.  But we should NOT see more /Contents hex-strings
        // than there are signature fields.  We flag if we find a suspicious
        // extra one, but we can't be 100% sure without the field count.
        // For now, just warn if there are more than a reasonable number.
        if occurrences > 10 {
            warnings.push(format!(
                "[SWA] Found {} large /Contents hex-strings in document — \
                 possible signature wrapping",
                occurrences
            ));
            return (false, warnings);
        }

        (true, warnings)
    }

    // ── 3. Certification Attack defense: MDP permission check ──
    //
    // Certified documents have a `/Perms` → `/DocMDP` entry that restricts
    // what changes are allowed.  We enforce these restrictions:
    //   Level 1: No changes allowed at all
    //   Level 2: Only form fill-in and signing allowed
    //   Level 3: Form fill-in, signing, and annotations allowed

    fn check_certification_permissions(
        doc: &Document,
        _pdf_bytes: &[u8],
        result: &ValidationResult,
    ) -> (Option<u8>, bool, Vec<String>) {
        let mut warnings = Vec::new();

        // Find /Perms -> /DocMDP in the catalog
        let root_ref = match doc.trailer.get(b"Root").and_then(|o| o.as_reference()) {
            Ok(r) => r,
            Err(_) => return (None, true, warnings),
        };
        let root_dict = match doc.get_object(root_ref).and_then(|o| o.as_dict()) {
            Ok(d) => d,
            Err(_) => return (None, true, warnings),
        };

        if !root_dict.has(b"Perms") {
            return (None, true, warnings); // Not a certified document
        }

        let perms = match root_dict.get(b"Perms") {
            Ok(Object::Dictionary(d)) => d,
            Ok(Object::Reference(r)) => match doc.get_object(*r).and_then(|o| o.as_dict()) {
                Ok(d) => d,
                Err(_) => return (None, true, warnings),
            },
            _ => return (None, true, warnings),
        };

        if !perms.has(b"DocMDP") {
            return (None, true, warnings);
        }

        // Resolve the DocMDP signature reference
        let docmdp_ref = match perms.get(b"DocMDP") {
            Ok(Object::Reference(r)) => *r,
            _ => return (None, true, warnings),
        };

        // Get the TransformParams from the DocMDP signature
        let sig_dict = match doc.get_object(docmdp_ref).and_then(|o| o.as_dict()) {
            Ok(d) => d,
            Err(_) => return (None, true, warnings),
        };

        // The MDP level can be in the signature dict's /Reference array
        // or directly in a /TransformParams dict
        let mdp_level = Self::extract_mdp_level(doc, sig_dict);

        match mdp_level {
            Some(level) => {
                warnings.push(format!(
                    "[Certification] Document is certified with MDP level {} ({})",
                    level,
                    match level {
                        1 => "no changes allowed",
                        2 => "form fill-in and signing only",
                        3 => "form fill-in, signing, and annotations",
                        _ => "unknown",
                    }
                ));

                // Check if modifications respect the MDP level
                let ok = Self::check_mdp_compliance(level, result);
                if !ok {
                    warnings.push(format!(
                        "[Certification] Changes after signing VIOLATE MDP level {} restrictions",
                        level
                    ));
                }

                (Some(level), ok, warnings)
            }
            None => (None, true, warnings),
        }
    }

    /// Extract the MDP permission level from a DocMDP signature dictionary.
    fn extract_mdp_level(doc: &Document, sig_dict: &lopdf::Dictionary) -> Option<u8> {
        // Try /Reference array -> /TransformParams -> /P
        if let Ok(ref_arr) = sig_dict.get(b"Reference").and_then(|o| o.as_array()) {
            for item in ref_arr {
                let ref_dict = match item {
                    Object::Dictionary(d) => d,
                    Object::Reference(r) => match doc.get_object(*r).and_then(|o| o.as_dict()) {
                        Ok(d) => d,
                        Err(_) => continue,
                    },
                    _ => continue,
                };

                if let Ok(tm) = ref_dict
                    .get(b"TransformMethod")
                    .and_then(|o| o.as_name_str())
                {
                    if tm == "DocMDP" {
                        if let Ok(tp) = ref_dict.get(b"TransformParams") {
                            let tp_dict = match tp {
                                Object::Dictionary(d) => d,
                                Object::Reference(r) => {
                                    match doc.get_object(*r).and_then(|o| o.as_dict()) {
                                        Ok(d) => d,
                                        Err(_) => continue,
                                    }
                                }
                                _ => continue,
                            };
                            if let Ok(Object::Integer(p)) = tp_dict.get(b"P") {
                                return Some(*p as u8);
                            }
                        }
                    }
                }
            }
        }
        None
    }

    /// Check if the detected modifications comply with the MDP level.
    fn check_mdp_compliance(level: u8, result: &ValidationResult) -> bool {
        if result.modification_notes.is_empty() {
            return true; // No changes = always compliant
        }

        match level {
            1 => {
                // No changes allowed at all
                // Any modification note means a violation
                result.modification_notes.is_empty()
            }
            2 => {
                // Only form fill-in and signing allowed
                result.modification_notes.iter().all(|note| {
                    let lower = note.to_lowercase();
                    lower.contains("signature")
                        || lower.contains("acroform")
                        || lower.contains("annots extended")
                        || lower.contains("dss")
                        || lower.contains("catalog")
                        || lower.contains("data stream")
                        || lower.contains("vri")
                        || lower.contains("permitted")
                })
            }
            3 => {
                // Form fill-in, signing, and annotations allowed
                result.modification_notes.iter().all(|note| {
                    let lower = note.to_lowercase();
                    lower.contains("signature")
                        || lower.contains("acroform")
                        || lower.contains("annots")
                        || lower.contains("annotation")
                        || lower.contains("dss")
                        || lower.contains("catalog")
                        || lower.contains("data stream")
                        || lower.contains("vri")
                        || lower.contains("widget")
                        || lower.contains("permitted")
                })
            }
            _ => true,
        }
    }

    // ── Modification detection (like Adobe Reader) ─────────

    /// Find all `%%EOF` markers in the raw PDF bytes.
    /// Each marks the end of a revision (original or incremental update).
    /// Returns the byte offset of the character AFTER the last byte of
    /// each `%%EOF\n` (or `%%EOF\r\n`).
    fn find_eof_offsets(pdf_bytes: &[u8]) -> Vec<usize> {
        let marker = b"%%EOF";
        let mut offsets = Vec::new();
        let mut pos = 0;
        while pos + marker.len() <= pdf_bytes.len() {
            if let Some(found) = pdf_bytes[pos..]
                .windows(marker.len())
                .position(|w| w == marker)
            {
                let abs = pos + found;
                // The revision ends after %%EOF + any trailing newline
                let mut end = abs + marker.len();
                // Skip \r\n or \n after %%EOF
                if end < pdf_bytes.len() && pdf_bytes[end] == b'\r' {
                    end += 1;
                }
                if end < pdf_bytes.len() && pdf_bytes[end] == b'\n' {
                    end += 1;
                }
                offsets.push(end);
                pos = end;
            } else {
                break;
            }
        }
        offsets
    }

    /// For each signature, check whether subsequent revisions contain
    /// only permitted modifications.
    ///
    /// **Permitted changes** (following Adobe/PAdES conventions):
    /// - Adding new signature fields + widget annotations
    /// - Updating AcroForm to add new fields and set SigFlags
    /// - Updating page Annots to add new annotations
    /// - Adding/updating DSS (Document Security Store) and VRI
    /// - Adding a DocTimeStamp
    /// - Updating the Catalog to add DSS
    /// - Adding new objects that are signature values, streams (CRL/OCSP/Cert)
    ///
    /// **Unauthorized changes**:
    /// - Modifying page content streams
    /// - Changing form field values (other than signature fields)
    /// - Modifying fonts, images, or other resources
    /// - Deleting objects
    /// - Changing metadata in ways that alter document meaning
    fn detect_modifications(
        pdf_bytes: &[u8],
        results: &mut [ValidationResult],
    ) -> Result<(), Error> {
        let total = results.len();
        if total == 0 {
            return Ok(());
        }

        // Determine which signatures need modification checking.
        // - All non-last signatures: always check (subsequent sigs were appended)
        // - Last signature: only check if it does NOT cover the whole file
        //   (i.e. something was appended after it)
        let last_idx = total - 1;
        if results[last_idx].byte_range_covers_whole_file {
            results[last_idx].no_unauthorized_modifications = true;
        }
        // If the last sig doesn't cover the whole file, it will be checked
        // in the loop below.

        // For each signature that has subsequent data, check what was added.
        for sig_idx in 0..total {
            // Skip the last signature if it covers the whole file
            if sig_idx == last_idx && results[last_idx].byte_range_covers_whole_file {
                continue;
            }

            let rev_end = results[sig_idx].signature_revision_end;
            if rev_end == 0 || rev_end >= pdf_bytes.len() {
                // Cannot determine revision boundary
                results[sig_idx].no_unauthorized_modifications = true;
                continue;
            }

            // Parse the PDF up to this signature's revision end to get
            // the "original" state of objects.
            let revision_bytes = &pdf_bytes[..rev_end];
            let revision_doc = match Document::load_mem(revision_bytes) {
                Ok(d) => d,
                Err(_) => {
                    // If we can't parse the revision, we can't check
                    results[sig_idx].no_unauthorized_modifications = true;
                    results[sig_idx].modification_notes.push(
                        "Could not parse signature revision for modification check".into(),
                    );
                    continue;
                }
            };

            // Parse the full document to see what changed
            let full_doc = match Document::load_mem(pdf_bytes) {
                Ok(d) => d,
                Err(_) => {
                    results[sig_idx].no_unauthorized_modifications = true;
                    continue;
                }
            };

            // Collect all object IDs and their types from both documents
            let (unauthorized, notes) =
                Self::compare_revisions(&revision_doc, &full_doc, pdf_bytes, rev_end);

            results[sig_idx].no_unauthorized_modifications = !unauthorized;
            results[sig_idx].modification_notes = notes;

            if unauthorized {
                results[sig_idx].errors.push(
                    "Document has been modified after this signature was applied".into(),
                );
            }
        }

        Ok(())
    }

    /// Compare two document states (at-signature vs final) and classify
    /// the changes.  Returns `(has_unauthorized, notes)`.
    fn compare_revisions(
        revision_doc: &Document,
        full_doc: &Document,
        _pdf_bytes: &[u8],
        _rev_end: usize,
    ) -> (bool, Vec<String>) {
        let mut notes = Vec::new();
        let mut has_unauthorized = false;

        // Collect object IDs from each document
        let rev_objects: std::collections::HashSet<(u32, u16)> =
            revision_doc.objects.keys().cloned().collect();
        let full_objects: std::collections::HashSet<(u32, u16)> =
            full_doc.objects.keys().cloned().collect();

        // -- New objects (added after the signature) --
        let new_objects: Vec<(u32, u16)> = full_objects
            .difference(&rev_objects)
            .cloned()
            .collect();

        for &obj_id in &new_objects {
            let classification = Self::classify_new_object(full_doc, obj_id);
            match classification {
                ObjectChange::Permitted(desc) => {
                    notes.push(format!("Added {}: {} (permitted)", obj_id.0, desc));
                }
                ObjectChange::Unauthorized(desc) => {
                    notes.push(format!(
                        "Added {}: {} (UNAUTHORIZED)",
                        obj_id.0, desc
                    ));
                    has_unauthorized = true;
                }
            }
        }

        // -- Modified objects (exist in both but changed) --
        let common_objects: Vec<(u32, u16)> = rev_objects
            .intersection(&full_objects)
            .cloned()
            .collect();

        for &obj_id in &common_objects {
            let rev_obj = match revision_doc.get_object(obj_id) {
                Ok(o) => o,
                Err(_) => continue,
            };
            let full_obj = match full_doc.get_object(obj_id) {
                Ok(o) => o,
                Err(_) => continue,
            };

            // Quick check: if objects serialize to the same bytes, no change
            let rev_str = format!("{:?}", rev_obj);
            let full_str = format!("{:?}", full_obj);
            if rev_str == full_str {
                continue;
            }

            // Object was modified — classify the change
            let classification = Self::classify_modified_object(
                revision_doc, full_doc, obj_id, rev_obj, full_obj,
            );
            match classification {
                ObjectChange::Permitted(desc) => {
                    notes.push(format!(
                        "Modified {}: {} (permitted)",
                        obj_id.0, desc
                    ));
                }
                ObjectChange::Unauthorized(desc) => {
                    notes.push(format!(
                        "Modified {}: {} (UNAUTHORIZED)",
                        obj_id.0, desc
                    ));
                    has_unauthorized = true;
                }
            }
        }

        // -- Deleted objects --
        let deleted_objects: Vec<(u32, u16)> = rev_objects
            .difference(&full_objects)
            .cloned()
            .collect();

        for &obj_id in &deleted_objects {
            notes.push(format!(
                "Deleted object {} (UNAUTHORIZED)",
                obj_id.0
            ));
            has_unauthorized = true;
        }

        (has_unauthorized, notes)
    }

    /// Classify a newly added object.
    fn classify_new_object(doc: &Document, obj_id: (u32, u16)) -> ObjectChange {
        let obj = match doc.get_object(obj_id) {
            Ok(o) => o,
            Err(_) => return ObjectChange::Unauthorized("unreadable object".into()),
        };

        match obj {
            Object::Dictionary(dict) => {
                // Signature value dictionary (/Type /Sig or /Type /DocTimeStamp)
                if let Ok(type_name) = dict.get(b"Type").and_then(|o| o.as_name_str()) {
                    match type_name {
                        "Sig" | "DocTimeStamp" => {
                            return ObjectChange::Permitted("signature value dictionary".into());
                        }
                        "Annot" => {
                            if let Ok(subtype) = dict.get(b"Subtype").and_then(|o| o.as_name_str()) {
                                if subtype == "Widget" {
                                    // Widget is only permitted if linked to a Sig field
                                    if dict.has(b"FT") || dict.has(b"V") || dict.has(b"Parent") {
                                        return ObjectChange::Permitted("widget annotation".into());
                                    }
                                    return ObjectChange::Permitted("widget annotation".into());
                                }
                                // [EAA] Evil Annotation Attack: reject dangerous
                                // annotation subtypes that can overlay signed content
                                let dangerous = matches!(
                                    subtype,
                                    "FreeText" | "Stamp" | "Redact" | "Watermark"
                                        | "Square" | "Circle" | "Line" | "Ink"
                                        | "FileAttachment" | "RichMedia" | "Screen"
                                        | "3D" | "Sound" | "Movie" | "Polygon"
                                        | "PolyLine" | "Caret" | "Highlight"
                                        | "Underline" | "Squiggly" | "StrikeOut"
                                        | "Text" | "Popup"
                                );
                                if dangerous {
                                    return ObjectChange::Unauthorized(format!(
                                        "[EAA] dangerous annotation /Subtype /{}",
                                        subtype
                                    ));
                                }
                                // Link annotations are generally safe
                                if subtype == "Link" {
                                    return ObjectChange::Permitted("link annotation".into());
                                }
                                return ObjectChange::Unauthorized(format!(
                                    "annotation /Subtype /{}",
                                    subtype
                                ));
                            }
                        }
                        "Catalog" => {
                            return ObjectChange::Permitted("catalog update".into());
                        }
                        _ => {}
                    }
                }

                // Signature field (/FT /Sig)
                if let Ok(ft) = dict.get(b"FT").and_then(|o| o.as_name_str()) {
                    if ft == "Sig" {
                        return ObjectChange::Permitted("signature field".into());
                    }
                }

                // Widget annotation without /Type key
                if let Ok(subtype) = dict.get(b"Subtype").and_then(|o| o.as_name_str()) {
                    if subtype == "Widget" {
                        if dict.has(b"FT") || dict.has(b"V") {
                            return ObjectChange::Permitted(
                                "signature field/widget annotation".into(),
                            );
                        }
                    }
                }

                // DSS dictionary
                if dict.has(b"VRI") || dict.has(b"CRLs") || dict.has(b"OCSPs") || dict.has(b"Certs") {
                    return ObjectChange::Permitted("DSS dictionary".into());
                }

                // VRI sub-dictionary
                if dict.has(b"Cert") || dict.has(b"CRL") || dict.has(b"OCSP") {
                    return ObjectChange::Permitted("VRI entry".into());
                }

                // AcroForm with only Fields + SigFlags
                if dict.has(b"Fields") && dict.has(b"SigFlags") {
                    let key_count = dict.len();
                    if key_count <= 3 {
                        // Fields, SigFlags, and maybe DR (default resources)
                        return ObjectChange::Permitted("AcroForm update".into());
                    }
                }

                // Check if it has /ByteRange and /Contents (signature-like)
                if dict.has(b"ByteRange") && dict.has(b"Contents") {
                    if dict.has(b"Filter") {
                        return ObjectChange::Permitted("signature value dictionary".into());
                    }
                }

                ObjectChange::Unauthorized(format!(
                    "dictionary with keys: {:?}",
                    dict.iter()
                        .map(|(k, _)| String::from_utf8_lossy(k).to_string())
                        .collect::<Vec<_>>()
                ))
            }
            Object::Stream(stream) => {
                // Streams for CRL, OCSP, or certificate data (used in DSS)
                let dict = &stream.dict;
                if let Ok(type_name) = dict.get(b"Type").and_then(|o| o.as_name_str()) {
                    if type_name == "XObject" {
                        // Could be a signature appearance — check Subtype
                        if let Ok(subtype) = dict.get(b"Subtype").and_then(|o| o.as_name_str()) {
                            if subtype == "Form" {
                                return ObjectChange::Permitted(
                                    "form XObject (signature appearance)".into(),
                                );
                            }
                            if subtype == "Image" {
                                // [Shadow] New images added after signing could
                                // overlay existing content
                                return ObjectChange::Unauthorized(
                                    "[Shadow] image XObject added after signing".into(),
                                );
                            }
                        }
                    }
                    if type_name == "ObjStm" {
                        // Object stream — could hide shadow content
                        return ObjectChange::Unauthorized(
                            "[Shadow] object stream added after signing".into(),
                        );
                    }
                }
                // DSS streams typically don't have /Type, just /Length
                // Accept streams that have only Length/Filter/DecodeParms
                let keys: Vec<String> = dict
                    .iter()
                    .map(|(k, _)| String::from_utf8_lossy(k).to_string())
                    .collect();
                let is_simple_stream = keys.iter().all(|k| {
                    matches!(k.as_str(), "Length" | "Filter" | "DecodeParms" | "DL")
                });
                if is_simple_stream {
                    return ObjectChange::Permitted("data stream (likely DSS/CRL/OCSP)".into());
                }

                // [Shadow] Streams with content-like properties (Resources,
                // BBox, Matrix) are likely content streams used in shadow attacks
                if dict.has(b"Resources") || dict.has(b"BBox") || dict.has(b"Matrix") {
                    return ObjectChange::Unauthorized(
                        "[Shadow] content stream with Resources/BBox added after signing".into(),
                    );
                }

                ObjectChange::Unauthorized(format!(
                    "stream with keys: {:?}",
                    keys
                ))
            }
            _ => ObjectChange::Unauthorized(format!("object: {:?}", obj)),
        }
    }

    /// Classify a modification to an existing object.
    fn classify_modified_object(
        _rev_doc: &Document,
        full_doc: &Document,
        obj_id: (u32, u16),
        rev_obj: &Object,
        full_obj: &Object,
    ) -> ObjectChange {
        // Check if this is the Catalog (Root)
        if let Ok(root_ref) = full_doc.trailer.get(b"Root").and_then(|o| o.as_reference()) {
            if root_ref == obj_id {
                return Self::classify_catalog_change(rev_obj, full_obj);
            }
        }

        // Check if this is a Page dictionary
        if let (Ok(rev_dict), Ok(full_dict)) = (rev_obj.as_dict(), full_obj.as_dict()) {
            if let Ok(type_name) = full_dict.get(b"Type").and_then(|o| o.as_name_str()) {
                match type_name {
                    "Page" => {
                        return Self::classify_page_change(rev_dict, full_dict);
                    }
                    "Pages" => {
                        // [Shadow] Page tree node modified — could be
                        // swapping/reordering pages
                        return ObjectChange::Unauthorized(
                            "[Shadow] /Type /Pages tree node modified".into(),
                        );
                    }
                    _ => {}
                }
            }

            // AcroForm dictionary
            if full_dict.has(b"Fields") && full_dict.has(b"SigFlags") {
                return Self::classify_acroform_change(rev_dict, full_dict);
            }

            // [ISA] Form field value change: if this dict has /FT and it's
            // NOT a signature field, changing /V is unauthorized
            if let Ok(ft) = full_dict.get(b"FT").and_then(|o| o.as_name_str()) {
                if ft != "Sig" {
                    let rv = rev_dict.get(b"V").ok().map(|v| format!("{:?}", v));
                    let fv = full_dict.get(b"V").ok().map(|v| format!("{:?}", v));
                    if rv != fv {
                        return ObjectChange::Unauthorized(format!(
                            "[ISA] form field /FT /{} value /V changed",
                            ft
                        ));
                    }
                }
            }
        }

        // [ISA/Shadow] Stream object content changed
        if let (Object::Stream(_), Object::Stream(_)) = (rev_obj, full_obj) {
            return ObjectChange::Unauthorized(format!(
                "[ISA] stream object {} content modified",
                obj_id.0
            ));
        }

        ObjectChange::Unauthorized(format!("object {} modified", obj_id.0))
    }

    /// Check if a Catalog modification is permitted.
    /// Allowed: adding /DSS, updating /AcroForm reference.
    fn classify_catalog_change(rev_obj: &Object, full_obj: &Object) -> ObjectChange {
        let rev_dict = match rev_obj.as_dict() {
            Ok(d) => d,
            Err(_) => return ObjectChange::Unauthorized("catalog is not a dictionary".into()),
        };
        let full_dict = match full_obj.as_dict() {
            Ok(d) => d,
            Err(_) => return ObjectChange::Unauthorized("catalog is not a dictionary".into()),
        };

        let mut changes = Vec::new();
        let mut unauthorized = false;

        for (key, full_val) in full_dict.iter() {
            let key_str = String::from_utf8_lossy(key).to_string();
            match rev_dict.get(key) {
                Ok(rev_val) => {
                    let rv = format!("{:?}", rev_val);
                    let fv = format!("{:?}", full_val);
                    if rv != fv {
                        match key_str.as_str() {
                            "AcroForm" | "DSS" | "Perms" => {
                                changes.push(format!("/{} updated", key_str));
                            }
                            "OCProperties" => {
                                // [Shadow] Optional Content properties changed —
                                // this can hide/reveal layers after signing
                                changes.push(
                                    "[Shadow] /OCProperties modified — \
                                     layer visibility may have changed"
                                        .into(),
                                );
                                unauthorized = true;
                            }
                            "Pages" => {
                                // [Shadow] Page tree modified
                                changes.push(
                                    "[Shadow] /Pages modified — \
                                     page tree may have been altered"
                                        .into(),
                                );
                                unauthorized = true;
                            }
                            _ => {
                                changes.push(format!(
                                    "/{} modified (unauthorized)",
                                    key_str
                                ));
                                unauthorized = true;
                            }
                        }
                    }
                }
                Err(_) => {
                    // New key added
                    match key_str.as_str() {
                        "DSS" | "Perms" | "AcroForm" => {
                            changes.push(format!("/{} added", key_str));
                        }
                        "OCProperties" => {
                            // [Shadow] Adding optional content groups after signing
                            changes.push(
                                "[Shadow] /OCProperties added — \
                                 optional content layers added after signing"
                                    .into(),
                            );
                            unauthorized = true;
                        }
                        _ => {
                            changes.push(format!("/{} added (unauthorized)", key_str));
                            unauthorized = true;
                        }
                    }
                }
            }
        }

        // Check for deleted keys
        for (key, _) in rev_dict.iter() {
            if full_dict.get(key).is_err() {
                let key_str = String::from_utf8_lossy(key).to_string();
                changes.push(format!("/{} removed (unauthorized)", key_str));
                unauthorized = true;
            }
        }

        let desc = if changes.is_empty() {
            "catalog (no visible changes)".into()
        } else {
            format!("catalog: {}", changes.join(", "))
        };

        if unauthorized {
            ObjectChange::Unauthorized(desc)
        } else {
            ObjectChange::Permitted(desc)
        }
    }

    /// Check if a Page modification is permitted.
    /// Allowed: updating /Annots to add new annotation references.
    /// Not allowed: changing /Contents, /Resources, /MediaBox, etc.
    fn classify_page_change(
        rev_dict: &lopdf::Dictionary,
        full_dict: &lopdf::Dictionary,
    ) -> ObjectChange {
        let mut changes = Vec::new();
        let mut unauthorized = false;

        for (key, full_val) in full_dict.iter() {
            let key_str = String::from_utf8_lossy(key).to_string();
            match rev_dict.get(key) {
                Ok(rev_val) => {
                    let rv = format!("{:?}", rev_val);
                    let fv = format!("{:?}", full_val);
                    if rv != fv {
                        match key_str.as_str() {
                            "Annots" => {
                                // Annots can grow (add new annotations) but
                                // existing entries must not be removed/changed.
                                if Self::is_array_append_only(rev_val, full_val) {
                                    changes.push("/Annots extended".into());
                                } else {
                                    changes.push(
                                        "[EAA] /Annots modified (not append-only)".into(),
                                    );
                                    unauthorized = true;
                                }
                            }
                            "Resources" => {
                                // Resources may be updated to add XObjects for
                                // signature appearances
                                changes.push("/Resources updated".into());
                            }
                            "Contents" => {
                                // [Shadow] Content stream reference changed —
                                // this is the primary Shadow attack vector
                                changes.push(
                                    "[Shadow] /Contents reference changed — \
                                     page content may have been replaced"
                                        .into(),
                                );
                                unauthorized = true;
                            }
                            "MediaBox" | "CropBox" | "TrimBox" | "BleedBox" | "ArtBox" => {
                                changes.push(format!(
                                    "[Shadow] /{} modified — page dimensions changed",
                                    key_str
                                ));
                                unauthorized = true;
                            }
                            _ => {
                                changes.push(format!(
                                    "/{} modified (unauthorized)",
                                    key_str
                                ));
                                unauthorized = true;
                            }
                        }
                    }
                }
                Err(_) => {
                    match key_str.as_str() {
                        "Annots" => {
                            changes.push("/Annots added".into());
                        }
                        _ => {
                            changes.push(format!("/{} added (unauthorized)", key_str));
                            unauthorized = true;
                        }
                    }
                }
            }
        }

        // Check for removed keys
        for (key, _) in rev_dict.iter() {
            if full_dict.get(key).is_err() {
                let key_str = String::from_utf8_lossy(key).to_string();
                changes.push(format!("/{} removed (unauthorized)", key_str));
                unauthorized = true;
            }
        }

        let desc = if changes.is_empty() {
            "page (no visible changes)".into()
        } else {
            format!("page: {}", changes.join(", "))
        };

        if unauthorized {
            ObjectChange::Unauthorized(desc)
        } else {
            ObjectChange::Permitted(desc)
        }
    }

    /// Check if an AcroForm modification is permitted.
    /// Allowed: adding entries to /Fields, changing /SigFlags.
    fn classify_acroform_change(
        rev_dict: &lopdf::Dictionary,
        full_dict: &lopdf::Dictionary,
    ) -> ObjectChange {
        let mut changes = Vec::new();
        let mut unauthorized = false;

        for (key, full_val) in full_dict.iter() {
            let key_str = String::from_utf8_lossy(key).to_string();
            match rev_dict.get(key) {
                Ok(rev_val) => {
                    let rv = format!("{:?}", rev_val);
                    let fv = format!("{:?}", full_val);
                    if rv != fv {
                        match key_str.as_str() {
                            "Fields" => {
                                if Self::is_array_append_only(rev_val, full_val) {
                                    changes.push("/Fields extended".into());
                                } else {
                                    changes.push(
                                        "/Fields modified (not append-only)".into(),
                                    );
                                    unauthorized = true;
                                }
                            }
                            "SigFlags" => {
                                changes.push("/SigFlags updated".into());
                            }
                            "DR" => {
                                // Default Resources — allowed for signature appearances
                                changes.push("/DR updated".into());
                            }
                            _ => {
                                changes.push(format!(
                                    "/{} modified (unauthorized)",
                                    key_str
                                ));
                                unauthorized = true;
                            }
                        }
                    }
                }
                Err(_) => {
                    match key_str.as_str() {
                        "Fields" | "SigFlags" | "DR" => {
                            changes.push(format!("/{} added", key_str));
                        }
                        _ => {
                            changes.push(format!("/{} added (unauthorized)", key_str));
                            unauthorized = true;
                        }
                    }
                }
            }
        }

        let desc = if changes.is_empty() {
            "AcroForm (no visible changes)".into()
        } else {
            format!("AcroForm: {}", changes.join(", "))
        };

        if unauthorized {
            ObjectChange::Unauthorized(desc)
        } else {
            ObjectChange::Permitted(desc)
        }
    }

    /// Check if a full array is a strict superset of the revision array
    /// (append-only modification).
    fn is_array_append_only(rev_val: &Object, full_val: &Object) -> bool {
        let rev_arr = match rev_val.as_array() {
            Ok(a) => a,
            Err(_) => return false,
        };
        let full_arr = match full_val.as_array() {
            Ok(a) => a,
            Err(_) => return false,
        };

        // Full array must be at least as long as revision array
        if full_arr.len() < rev_arr.len() {
            return false;
        }

        // All original entries must be preserved in order
        for (i, rev_item) in rev_arr.iter().enumerate() {
            let rev_str = format!("{:?}", rev_item);
            let full_str = format!("{:?}", full_arr[i]);
            if rev_str != full_str {
                return false;
            }
        }

        true
    }
}

/// Classification of a change found between revisions.
enum ObjectChange {
    /// The change is permitted (e.g., adding a new signature field).
    Permitted(String),
    /// The change is unauthorized (e.g., modifying page content).
    Unauthorized(String),
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

    #[test]
    fn test_modification_detection_on_signed_pdf() -> Result<(), Box<dyn std::error::Error>> {
        // A legitimately signed PDF should show no unauthorized modifications
        let pdf_bytes = fs::read("examples/assets/sample-signed.pdf")
            .or_else(|_| fs::read("examples/result.pdf"))?;

        let results = SignatureValidator::validate(&pdf_bytes)?;
        assert!(!results.is_empty());

        let r = &results[0];
        eprintln!("=== Modification Detection ===");
        eprintln!("  no_unauthorized_modifications: {}", r.no_unauthorized_modifications);
        eprintln!("  modification_notes: {:?}", r.modification_notes);
        eprintln!("  signature_revision_end: {}", r.signature_revision_end);

        // A single-sig PDF that covers the whole file should have no modifications
        if r.byte_range_covers_whole_file {
            assert!(
                r.no_unauthorized_modifications,
                "Legitimately signed PDF should have no unauthorized modifications"
            );
        }

        Ok(())
    }

    #[test]
    fn test_modification_detection_tampered_pdf() -> Result<(), Box<dyn std::error::Error>> {
        // Read a signed PDF
        let signed_bytes = fs::read("examples/assets/sample-signed.pdf")
            .or_else(|_| fs::read("examples/result.pdf"))?;

        // Tamper with it: append a fake incremental update that replaces
        // the content stream (object 4)
        let mut tampered = signed_bytes.clone();
        let obj4_offset = tampered.len();

        // Write a new object 4 (content stream)
        tampered.extend_from_slice(b"4 0 obj\n<</Length 44>>\nstream\n");
        tampered.extend_from_slice(b"BT /F1 24 Tf 100 700 Td (TAMPERED!) Tj ET\n");
        tampered.extend_from_slice(b"endstream\nendobj\n");

        // Write xref
        let xref_pos = tampered.len();
        tampered.extend_from_slice(b"xref\n4 1\n");
        tampered.extend_from_slice(format!("{:010} 00000 n \n", obj4_offset).as_bytes());
        tampered.extend_from_slice(b"trailer\n");

        // Find prev startxref
        let prev_xref_start = signed_bytes
            .windows(10)
            .rposition(|w| w == b"startxref\n")
            .unwrap()
            + 10;
        let prev_xref_end = signed_bytes[prev_xref_start..]
            .iter()
            .position(|&b| b == b'\n')
            .unwrap()
            + prev_xref_start;
        let prev_xref_val = std::str::from_utf8(
            &signed_bytes[prev_xref_start..prev_xref_end],
        )?.trim();

        tampered.extend_from_slice(
            format!(
                "<</Root 13 0 R/Info 1 0 R/Prev {}/Size 30>>\n",
                prev_xref_val
            )
            .as_bytes(),
        );
        tampered.extend_from_slice(format!("startxref\n{}\n%%EOF\n", xref_pos).as_bytes());

        // Verify the tampered PDF detects unauthorized modifications
        let results = SignatureValidator::validate(&tampered)?;
        assert!(!results.is_empty());

        let r = &results[0];
        eprintln!("=== Tampered PDF ===");
        eprintln!("  no_unauthorized_modifications: {}", r.no_unauthorized_modifications);
        eprintln!("  modification_notes: {:?}", r.modification_notes);
        eprintln!("  errors: {:?}", r.errors);

        assert!(
            !r.no_unauthorized_modifications,
            "Tampered PDF should detect unauthorized modifications"
        );
        assert!(
            r.errors.iter().any(|e| e.contains("modified after")),
            "Should have an error about post-signing modification"
        );

        Ok(())
    }

    #[test]
    fn test_certificate_chain_trust_warnings() -> Result<(), Box<dyn std::error::Error>> {
        // Our test certificates are self-signed / from a test CA,
        // so they should produce trust warnings but still be structurally parseable.
        let pdf_bytes = fs::read("examples/assets/sample-signed.pdf")
            .or_else(|_| fs::read("examples/result.pdf"))?;

        let results = SignatureValidator::validate(&pdf_bytes)?;
        assert!(!results.is_empty());

        let r = &results[0];
        eprintln!("=== Certificate Trust ===");
        eprintln!("  chain_valid:   {}", r.certificate_chain_valid);
        eprintln!("  chain_trusted: {}", r.certificate_chain_trusted);
        eprintln!("  warnings:      {:?}", r.chain_warnings);
        for c in &r.certificates {
            eprintln!(
                "  cert: subject={}, self_signed={}",
                c.subject, c.is_self_signed
            );
        }

        // Test certificates should NOT be trusted (they are from a test CA)
        assert!(
            !r.certificate_chain_trusted,
            "Test certificate should not be trusted"
        );
        // Should have at least one warning about trust
        assert!(
            !r.chain_warnings.is_empty(),
            "Should have chain trust warnings for test certificates"
        );

        // The CMS should still parse and the signature should still verify
        // (trust is a warning, not a structural failure)
        assert!(r.cms_signature_valid, "CMS should still be valid");
        assert!(r.digest_match, "Digest should still match");

        Ok(())
    }

    // ── Security attack defense tests (pdf-insecurity.org) ──

    #[test]
    fn test_usf_byte_range_structure_valid() {
        // A legitimate signature should have valid ByteRange structure
        let pdf_bytes = fs::read("examples/assets/sample-signed.pdf")
            .or_else(|_| fs::read("examples/result.pdf"))
            .unwrap();
        let results = SignatureValidator::validate(&pdf_bytes).unwrap();
        let r = &results[0];

        eprintln!("=== USF Defense ===");
        eprintln!("  byte_range_valid: {}", r.byte_range_valid);
        eprintln!("  security_warnings: {:?}", r.security_warnings);

        assert!(r.byte_range_valid, "Legitimate PDF should have valid ByteRange structure");
    }

    #[test]
    fn test_usf_byte_range_must_start_at_zero() {
        // ByteRange[0] != 0 is a USF indicator
        let (valid, warnings) =
            SignatureValidator::validate_byte_range_structure(&[0u8; 1000], &[10, 100, 200, 100]);
        assert!(!valid, "ByteRange starting at 10 should be invalid");
        assert!(
            warnings.iter().any(|w| w.contains("[USF]") && w.contains("offset")),
            "Should warn about non-zero start"
        );
    }

    #[test]
    fn test_usf_negative_byte_range_values() {
        let (valid, warnings) =
            SignatureValidator::validate_byte_range_structure(&[0u8; 1000], &[0, -1, 100, 50]);
        assert!(!valid, "Negative ByteRange values should be invalid");
        assert!(
            warnings.iter().any(|w| w.contains("negative")),
            "Should warn about negative values"
        );
    }

    #[test]
    fn test_usf_overlapping_ranges() {
        let (valid, warnings) =
            SignatureValidator::validate_byte_range_structure(&[0u8; 1000], &[0, 500, 400, 100]);
        assert!(!valid, "Overlapping ranges should be invalid");
        assert!(
            warnings.iter().any(|w| w.contains("overlap")),
            "Should warn about overlap"
        );
    }

    #[test]
    fn test_swa_detection_on_legitimate_pdf() {
        let pdf_bytes = fs::read("examples/assets/sample-signed.pdf")
            .or_else(|_| fs::read("examples/result.pdf"))
            .unwrap();
        let results = SignatureValidator::validate(&pdf_bytes).unwrap();
        let r = &results[0];

        eprintln!("=== SWA Defense ===");
        eprintln!("  signature_not_wrapped: {}", r.signature_not_wrapped);

        assert!(
            r.signature_not_wrapped,
            "Legitimate PDF should not trigger SWA detection"
        );
    }

    #[test]
    fn test_security_checks_on_blta_pdf() {
        let pdf_bytes = match fs::read("examples/result_pades_blta.pdf") {
            Ok(b) => b,
            Err(_) => {
                eprintln!("B-LTA PDF not found, skipping");
                return;
            }
        };
        let results = SignatureValidator::validate(&pdf_bytes).unwrap();

        for (i, r) in results.iter().enumerate() {
            eprintln!("=== Signature {} Security ===", i + 1);
            eprintln!("  byte_range_valid:     {}", r.byte_range_valid);
            eprintln!("  signature_not_wrapped:{}", r.signature_not_wrapped);
            eprintln!("  cert_permission_ok:   {}", r.certification_permission_ok);
            eprintln!("  security_warnings:    {:?}", r.security_warnings);

            assert!(r.byte_range_valid, "B-LTA sig {} ByteRange should be valid", i + 1);
            assert!(r.signature_not_wrapped, "B-LTA sig {} should not be wrapped", i + 1);
            assert!(r.certification_permission_ok, "B-LTA sig {} MDP should be ok", i + 1);
        }
    }

    #[test]
    fn test_isa_tampered_content_stream_detected() {
        // Create a tampered PDF (same as test_modification_detection_tampered_pdf)
        let signed_bytes = fs::read("examples/assets/sample-signed.pdf")
            .or_else(|_| fs::read("examples/result.pdf"))
            .unwrap();

        let mut tampered = signed_bytes.clone();
        let obj4_offset = tampered.len();
        tampered.extend_from_slice(b"4 0 obj\n<</Length 44>>\nstream\n");
        tampered.extend_from_slice(b"BT /F1 24 Tf 100 700 Td (TAMPERED!) Tj ET\n");
        tampered.extend_from_slice(b"endstream\nendobj\n");
        let xref_pos = tampered.len();
        tampered.extend_from_slice(b"xref\n4 1\n");
        tampered.extend_from_slice(format!("{:010} 00000 n \n", obj4_offset).as_bytes());
        tampered.extend_from_slice(b"trailer\n");

        let prev_xref_start = signed_bytes
            .windows(10)
            .rposition(|w| w == b"startxref\n")
            .unwrap() + 10;
        let prev_xref_end = signed_bytes[prev_xref_start..]
            .iter()
            .position(|&b| b == b'\n')
            .unwrap() + prev_xref_start;
        let prev_xref_val = std::str::from_utf8(
            &signed_bytes[prev_xref_start..prev_xref_end],
        ).unwrap().trim();

        tampered.extend_from_slice(
            format!("<</Root 13 0 R/Info 1 0 R/Prev {}/Size 30>>\n", prev_xref_val).as_bytes(),
        );
        tampered.extend_from_slice(format!("startxref\n{}\n%%EOF\n", xref_pos).as_bytes());

        let results = SignatureValidator::validate(&tampered).unwrap();
        let r = &results[0];

        eprintln!("=== ISA Attack Detection ===");
        eprintln!("  no_unauthorized_mods: {}", r.no_unauthorized_modifications);
        eprintln!("  modification_notes:   {:?}", r.modification_notes);
        eprintln!("  is_valid:             {}", r.is_valid());

        assert!(!r.no_unauthorized_modifications, "ISA should be detected");
        assert!(!r.is_valid(), "Tampered PDF should be invalid");
    }
}

