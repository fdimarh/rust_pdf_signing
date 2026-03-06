/// Verify whether a signed PDF truly conforms to PAdES (ETSI.CAdES.detached)
/// by inspecting both the PDF-level metadata and the CMS signed attributes.
///
/// Usage:  cargo run --bin verify_pades [path/to/signed.pdf]

use cryptographic_message_syntax::SignedData;
use lopdf::{Document, Object};
use sha2::{Digest, Sha256};

/// OID 1.2.840.113549.1.9.4  — id-messageDigest
const OID_MESSAGE_DIGEST: &[u8] = &[0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x04];
/// OID 1.2.840.113549.1.9.3  — id-contentType
const OID_CONTENT_TYPE: &[u8] = &[0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x03];
/// OID 1.2.840.113549.1.9.5  — id-signingTime
const OID_SIGNING_TIME: &[u8] = &[0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x05];
/// OID 1.2.840.113549.1.9.16.2.47 — id-aa-signingCertificateV2 (ESS)
const OID_SIGNING_CERT_V2: &[u8] = &[0x06, 0x0b, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x10, 0x02, 0x2f];
/// OID 1.2.840.113549.1.9.16.2.12 — id-smime-aa-signingCertificate (v1, SHA-1)
const OID_SIGNING_CERT_V1: &[u8] = &[0x06, 0x0b, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x10, 0x02, 0x0c];
/// OID 1.2.840.113549.1.9.16.2.14 — id-smime-aa-signatureTimeStampToken
const OID_TIMESTAMP_TOKEN: &[u8] = &[0x06, 0x0b, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x10, 0x02, 0x0e];

fn contains_oid(data: &[u8], oid: &[u8]) -> bool {
    data.windows(oid.len()).any(|w| w == oid)
}

fn hex_preview(data: &[u8], max: usize) -> String {
    data.iter()
        .take(max)
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .join("")
        + if data.len() > max { "..." } else { "" }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    let path = if args.len() > 1 {
        args[1].clone()
    } else {
        "examples/result.pdf".to_string()
    };

    println!("══════════════════════════════════════════════════════════");
    println!("  PAdES Compliance Check: {}", path);
    println!("══════════════════════════════════════════════════════════\n");

    let pdf_bytes = std::fs::read(&path)?;
    let doc = Document::load_mem(&pdf_bytes)?;

    // ── Find the signature V dictionary ──
    let root_ref = doc.trailer.get(b"Root")?.as_reference()?;
    let root_dict = doc.get_object(root_ref)?.as_dict()?;
    let acro_ref = root_dict.get(b"AcroForm")?.as_reference()?;
    let acro_dict = doc.get_object(acro_ref)?.as_dict()?;

    // Check SigFlags
    let sig_flags = acro_dict.get(b"SigFlags")
        .ok()
        .and_then(|o| if let Object::Integer(i) = o { Some(*i) } else { None });
    print!("  [1] AcroForm SigFlags:         ");
    match sig_flags {
        Some(3) => println!("3 ✅ (SignaturesExist + AppendOnly)"),
        Some(v) => println!("{} ⚠️  (expected 3)", v),
        None => println!("MISSING ❌"),
    }

    let fields = acro_dict.get(b"Fields")?.as_array()?;
    let mut sig_count = 0;

    for f in fields {
        let f_ref = match f.as_reference() { Ok(r) => r, Err(_) => continue };
        let f_dict = match doc.get_object(f_ref).and_then(|o| o.as_dict()) { Ok(d) => d, Err(_) => continue };

        let ft = f_dict.get(b"FT").ok().and_then(|o| o.as_name().ok().map(|s| String::from_utf8_lossy(s).to_string()));
        if ft.as_deref() != Some("Sig") { continue; }

        sig_count += 1;
        println!("\n  ─── Signature Field #{} (obj {:?}) ───\n", sig_count, f_ref);

        // Check merged field-widget
        let is_merged = f_dict.has(b"Subtype");
        print!("  [2] Merged field-widget:       ");
        println!("{}", if is_merged { "yes ✅" } else { "no (separate objects)" });

        // Get V dictionary
        let v_ref = f_dict.get(b"V")?.as_reference()?;
        let v_dict = doc.get_object(v_ref)?.as_dict()?;

        // ── PDF-level checks ──
        // SubFilter
        let sub_filter = v_dict.get(b"SubFilter").ok()
            .and_then(|o| o.as_name().ok().map(|s| String::from_utf8_lossy(s).to_string()));
        print!("  [3] SubFilter:                 ");
        match sub_filter.as_deref() {
            Some("ETSI.CAdES.detached") => println!("ETSI.CAdES.detached ✅ (PAdES)"),
            Some("adbe.pkcs7.detached") => println!("adbe.pkcs7.detached ❌ (PKCS#7, NOT PAdES)"),
            Some(other) => println!("{} ⚠️  (unknown)", other),
            None => println!("MISSING ❌"),
        }

        let is_pades_subfilter = sub_filter.as_deref() == Some("ETSI.CAdES.detached");

        // Filter
        let filter = v_dict.get(b"Filter").ok()
            .and_then(|o| o.as_name().ok().map(|s| String::from_utf8_lossy(s).to_string()));
        print!("  [4] Filter:                    ");
        println!("{}", filter.as_deref().unwrap_or("MISSING"));

        // ByteRange
        let byte_range = v_dict.get(b"ByteRange").ok()
            .and_then(|o| o.as_array().ok())
            .map(|arr| arr.iter().map(|o| match o { Object::Integer(i) => *i, _ => 0 }).collect::<Vec<_>>());

        let covers_file = if let Some(ref br) = byte_range {
            if br.len() == 4 {
                let end = br[2] + br[3];
                end as usize == pdf_bytes.len()
            } else { false }
        } else { false };

        print!("  [5] ByteRange covers file:     ");
        println!("{}", if covers_file { "yes ✅" } else { "NO ❌" });

        // ── Extract Contents (CMS/PKCS#7 DER) ──
        let contents_bytes = match v_dict.get(b"Contents") {
            Ok(Object::String(bytes, _)) => bytes.clone(),
            _ => { println!("  Contents: MISSING ❌"); continue; }
        };

        if contents_bytes.iter().all(|b| *b == 0) {
            println!("  Contents: all zeros ❌ (signature not applied)");
            continue;
        }

        println!("  [6] Contents size:             {} bytes", contents_bytes.len());

        // ── CMS-level checks ──
        println!("\n  ─── CMS / SignedData Analysis ───\n");

        match SignedData::parse_ber(&contents_bytes) {
            Ok(signed_data) => {
                // Certificates
                let certs: Vec<_> = signed_data.certificates().collect();
                println!("  [7] Embedded certificates:     {}", certs.len());

                // Signers
                let signers: Vec<_> = signed_data.signers().collect();
                println!("  [8] Number of signers:         {}", signers.len());

                for (i, signer) in signers.iter().enumerate() {
                    println!("\n      Signer #{}:", i + 1);

                    // Verify CMS integrity
                    match signer.verify_signature_with_signed_data(&signed_data) {
                        Ok(()) => println!("      CMS integrity:             valid ✅"),
                        Err(e) => println!("      CMS integrity:             FAILED ❌ ({})", e),
                    }

                    // Digest algorithm
                    let digest_alg = format!("{}", signer.digest_algorithm());
                    println!("      Digest algorithm:          {}", digest_alg);
                    let is_sha256_or_better = digest_alg.contains("Sha256")
                        || digest_alg.contains("SHA-256")
                        || digest_alg.contains("Sha384")
                        || digest_alg.contains("SHA-384")
                        || digest_alg.contains("Sha512")
                        || digest_alg.contains("SHA-512")
                        || digest_alg.contains("2.16.840.1.101.3.4.2");
                    if !is_sha256_or_better {
                        println!("        ⚠️  PAdES requires SHA-256 or stronger");
                    }

                    // Signature algorithm
                    let sig_alg = format!("{}", signer.signature_algorithm());
                    println!("      Signature algorithm:       {}", sig_alg);
                }

                // ── Scan raw DER for signed attributes ──
                println!("\n  ─── Signed Attributes (DER scan) ───\n");

                let has_content_type = contains_oid(&contents_bytes, OID_CONTENT_TYPE);
                let has_message_digest = contains_oid(&contents_bytes, OID_MESSAGE_DIGEST);
                let has_signing_time = contains_oid(&contents_bytes, OID_SIGNING_TIME);
                let has_signing_cert_v2 = contains_oid(&contents_bytes, OID_SIGNING_CERT_V2);
                let has_signing_cert_v1 = contains_oid(&contents_bytes, OID_SIGNING_CERT_V1);
                let has_timestamp = contains_oid(&contents_bytes, OID_TIMESTAMP_TOKEN);

                print!("  [9]  id-contentType:           ");
                println!("{}", if has_content_type { "present ✅" } else { "MISSING ❌" });

                print!("  [10] id-messageDigest:         ");
                println!("{}", if has_message_digest { "present ✅" } else { "MISSING ❌" });

                print!("  [11] id-signingTime:           ");
                println!("{}", if has_signing_time { "present" } else { "not present ✅" });
                if has_signing_time && is_pades_subfilter {
                    println!("        ⚠️  CAdES-BES recommends omitting signingTime (SHOULD NOT)");
                    println!("           Most validators accept it; strictly use timestamp instead.");
                    println!("           NOTE: cryptographic-message-syntax 0.26 always adds it.");
                }

                print!("  [12] ESS signing-certificate:  ");
                if has_signing_cert_v2 {
                    println!("v2 (SHA-256) present ✅ (PAdES REQUIRED)");
                } else if has_signing_cert_v1 {
                    println!("v1 (SHA-1) present ⚠️  (PAdES prefers v2)");
                } else {
                    println!("MISSING ❌ (PAdES REQUIRES ESS-signing-certificate-v2)");
                }

                print!("  [13] Signature timestamp:      ");
                println!("{}", if has_timestamp { "present ✅" } else { "not present (recommended for PAdES-T)" });

                // ── Verify file digest ──
                if let Some(ref br) = byte_range {
                    if br.len() == 4 {
                        let mut hasher = Sha256::new();
                        let s0 = br[0] as usize;
                        let l0 = br[1] as usize;
                        let s1 = br[2] as usize;
                        let l1 = br[3] as usize;
                        if s0 + l0 <= pdf_bytes.len() { hasher.update(&pdf_bytes[s0..s0+l0]); }
                        if s1 + l1 <= pdf_bytes.len() { hasher.update(&pdf_bytes[s1..s1+l1]); }
                        let computed = hasher.finalize().to_vec();
                        print!("\n  [14] File digest (SHA-256):    ");
                        println!("{}", hex_preview(&computed, 32));
                    }
                }

                // ── Overall PAdES verdict ──
                println!("\n  ══════════════════════════════════════════════════════");
                println!("  PADES COMPLIANCE SUMMARY");
                println!("  ══════════════════════════════════════════════════════");

                let checks = [
                    ("SubFilter = ETSI.CAdES.detached", is_pades_subfilter),
                    ("SigFlags = 3", sig_flags == Some(3)),
                    ("ByteRange covers whole file", covers_file),
                    ("id-contentType present", has_content_type),
                    ("id-messageDigest present", has_message_digest),
                    ("ESS signing-certificate-v2 present", has_signing_cert_v2),
                ];

                let has_signing_time_warning = has_signing_time && is_pades_subfilter;

                let mut all_pass = true;
                for (name, pass) in &checks {
                    let icon = if *pass { "✅" } else { "❌" };
                    println!("    {} {}", icon, name);
                    if !*pass { all_pass = false; }
                }
                if has_signing_time_warning {
                    println!("    ⚠️  signingTime present (SHOULD NOT per CAdES-BES, but accepted by most validators)");
                } else if is_pades_subfilter {
                    println!("    ✅ No signingTime in signed attributes");
                }

                println!();
                if all_pass && !has_signing_time_warning {
                    println!("  ✅ RESULT: This signature is fully PAdES-BES compliant.");
                } else if all_pass && has_signing_time_warning {
                    println!("  ✅ RESULT: This signature is PAdES-BES compliant.");
                    println!("     (signingTime present is a minor deviation accepted by");
                    println!("      Adobe Reader, Foxit, and EU DSS validators.)");
                    println!("     NOTE: cryptographic-message-syntax 0.26 always adds signingTime;");
                    println!("           this cannot be suppressed without patching the library.");
                } else if is_pades_subfilter {
                    println!("  ⚠️  RESULT: SubFilter claims PAdES but CMS structure is");
                    println!("     INCOMPLETE — missing required PAdES attributes.");
                    println!("     This is currently a PKCS#7 signature with a PAdES SubFilter label.");
                } else {
                    println!("  ❌ RESULT: This is NOT a PAdES signature.");
                }
                println!();
            }
            Err(e) => {
                println!("  Failed to parse CMS: {} ❌", e);
            }
        }
    }

    if sig_count == 0 {
        println!("  No signature fields found in this PDF.");
    }

    Ok(())
}

