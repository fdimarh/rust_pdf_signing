use pdf_signing::signature_validator::{SignatureValidator, ValidationResult};
use std::env;
use std::process;

fn print_result(r: &ValidationResult, index: usize) {
    let status = if r.is_valid() { "✅ VALID" } else { "❌ INVALID" };
    let sig_type = if r.field_info.is_document_timestamp {
        "Document Timestamp"
    } else {
        "Digital Signature"
    };

    println!("─────────────────────────────────────────────");
    println!("Signature #{}: {} ({})", index + 1, status, sig_type);
    println!("─────────────────────────────────────────────");
    println!(
        "  Signer:             {}",
        r.signer_name.as_deref().unwrap_or("(unknown)")
    );
    println!(
        "  Contact:            {}",
        r.contact_info.as_deref().unwrap_or("(none)")
    );
    println!(
        "  Reason:             {}",
        r.reason.as_deref().unwrap_or("(none)")
    );
    println!(
        "  Signing time:       {}",
        r.signing_time.as_deref().unwrap_or("(none)")
    );
    println!();

    // ByteRange
    println!("  ByteRange:          {:?}", r.byte_range);
    println!(
        "  Covers whole file:  {}",
        if r.byte_range_covers_whole_file {
            "yes"
        } else {
            "NO ⚠️"
        }
    );
    println!();

    // Cryptographic checks
    println!(
        "  Digest match:       {}",
        if r.digest_match { "yes ✅" } else { "NO ❌" }
    );
    println!(
        "  CMS signature:      {}",
        if r.cms_signature_valid {
            "valid ✅"
        } else {
            "INVALID ❌"
        }
    );
    println!(
        "  Certificate chain:  {}",
        if r.certificate_chain_valid {
            "valid ✅"
        } else {
            "INVALID ❌"
        }
    );
    println!();

    // LTV (Long-Term Validation)
    println!(
        "  LTV enabled:        {}",
        if r.is_ltv_enabled {
            "yes ✅"
        } else {
            "NO ❌"
        }
    );
    println!(
        "  Has timestamp:      {}",
        if r.has_timestamp { "yes ✅" } else { "no ❌" }
    );
    println!(
        "  DSS dictionary:     {}",
        if r.has_dss {
            format!(
                "present (CRLs: {}, OCSPs: {}, Certs: {})",
                r.dss_crl_count, r.dss_ocsp_count, r.dss_cert_count
            )
        } else {
            "not present".to_string()
        }
    );
    println!(
        "  DSS VRI entry:      {}",
        if r.has_vri {
            "present ✅"
        } else if r.has_dss {
            "not found for this signature"
        } else {
            "N/A (no DSS)"
        }
    );
    println!(
        "  CMS revocation:     {}",
        if r.has_cms_revocation_data {
            "embedded (adbe-revocationInfoArchival) ✅"
        } else {
            "not embedded"
        }
    );
    println!();

    // Certificates
    println!("  Certificates ({}):", r.certificates.len());
    for (i, c) in r.certificates.iter().enumerate() {
        println!("    [{}] Subject:    {}", i, c.subject);
        println!("        Issuer:     {}", c.issuer);
        println!("        Serial:     {}", c.serial_number);
        if let Some(nb) = c.not_before {
            println!("        Not before: {}", nb.format("%Y-%m-%d %H:%M:%S UTC"));
        }
        if let Some(na) = c.not_after {
            println!("        Not after:  {}", na.format("%Y-%m-%d %H:%M:%S UTC"));
        }
        println!(
            "        Expired:    {}",
            if c.is_expired { "YES ⚠️" } else { "no" }
        );
    }

    // Errors
    if r.errors.is_empty() {
        println!("\n  No errors.");
    } else {
        println!("\n  Errors:");
        for e in &r.errors {
            println!("    • {}", e);
        }
    }
    println!();
}

fn verify_pdf(path: &str) {
    println!("══════════════════════════════════════════════");
    println!("  Verifying: {}", path);
    println!("══════════════════════════════════════════════\n");

    let pdf_bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("Error: could not read file '{}': {}", path, e);
            process::exit(1);
        }
    };

    println!("  File size: {} bytes\n", pdf_bytes.len());

    match SignatureValidator::validate(&pdf_bytes) {
        Ok(results) => {
            println!("  Found {} signature(s)\n", results.len());
            for (i, r) in results.iter().enumerate() {
                print_result(r, i);
            }

            // Print overall summary
            let all_valid = results.iter().all(|r| r.is_valid());
            let all_cms_ok = results.iter().all(|r| r.cms_signature_valid);
            let all_digest_ok = results.iter().all(|r| r.digest_match);

            println!("══════════════════════════════════════════════");
            println!("  SUMMARY");
            println!("══════════════════════════════════════════════");
            println!("  Total signatures:   {}", results.len());
            println!(
                "  All CMS valid:      {}",
                if all_cms_ok { "yes ✅" } else { "NO ❌" }
            );
            println!(
                "  All digests match:  {}",
                if all_digest_ok { "yes ✅" } else { "NO ❌" }
            );
            println!(
                "  Overall:            {}",
                if all_valid {
                    "✅ ALL SIGNATURES VALID"
                } else {
                    "❌ ONE OR MORE SIGNATURES INVALID"
                }
            );
            println!();

            if !all_valid {
                process::exit(1);
            }
        }
        Err(e) => {
            eprintln!("  Verification failed: {}\n", e);
            process::exit(1);
        }
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        // Default: verify examples/result.pdf
        println!("Usage: verify_pdf <file.pdf> [file2.pdf ...]\n");
        println!("No file specified, verifying default: examples/result.pdf\n");
        verify_pdf("./examples/result.pdf");
    } else {
        for path in &args[1..] {
            verify_pdf(path);
        }
    }
}

