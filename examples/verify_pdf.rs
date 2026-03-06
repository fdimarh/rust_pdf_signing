use pdf_signing::signature_validator::{SignatureValidator, ValidationResult};
use std::env;
use std::process;

fn print_result(r: &ValidationResult, index: usize, total_sigs: usize) {
    let status = if r.is_valid() { "✅ VALID" } else { "❌ INVALID" };
    let sig_type = if r.field_info.is_document_timestamp {
        "Document Timestamp"
    } else {
        "Digital Signature"
    };

    println!("─────────────────────────────────────────────");
    println!("Signature #{}: {} ({})", index + 1, status, sig_type);
    println!("─────────────────────────────────────────────");

    // Signature format
    let sub_filter_str = r.sub_filter.as_deref().unwrap_or("(unknown)");
    let format_label = match sub_filter_str {
        "adbe.pkcs7.detached" => "PKCS#7 (pre-PAdES / Adobe legacy)",
        "ETSI.CAdES.detached" => "PAdES (CAdES-based, ETSI standard)",
        "ETSI.RFC3161" => "RFC 3161 Document Timestamp",
        _ => sub_filter_str,
    };
    println!(
        "  Filter:             {}",
        r.filter.as_deref().unwrap_or("(unknown)")
    );
    println!("  SubFilter:          {} — {}", sub_filter_str, format_label);

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
            "yes".to_string()
        } else if total_sigs > 1 && index < total_sigs - 1 {
            "no (expected — subsequent signatures appended after this one)".to_string()
        } else {
            "NO ⚠️".to_string()
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
    println!(
        "  Chain trusted:      {}",
        if r.certificate_chain_trusted {
            "yes — signed by a recognized Certificate Authority ✅"
        } else if r.certificate_chain_valid {
            "NOT TRUSTED ⚠️  — signer identity cannot be verified"
        } else {
            "NOT TRUSTED ❌"
        }
    );
    if !r.chain_warnings.is_empty() {
        for w in &r.chain_warnings {
            println!("    ⚠️  {}", w);
        }
    }
    println!();

    // LTV (Long-Term Validation)
    let is_pkcs7 = r.sub_filter.as_deref() == Some("adbe.pkcs7.detached");
    let is_pades = r.sub_filter.as_deref() == Some("ETSI.CAdES.detached");

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

    // LTV analysis context
    if r.is_ltv_enabled {
        if is_pkcs7 {
            println!("  ─── LTV Method: Adobe Pre-PAdES ───");
            println!("  Revocation data embedded via adbe-revocationInfoArchival");
            println!("  (Adobe proprietary OID 1.2.840.113583.1.1.8)");
            if r.has_dss {
                println!("  Plus DSS dictionary at document level for additional data.");
            }
            println!("  Timestamp anchors signature to a specific time.");
            println!("  → Signature can be validated offline after certificate expiry.");
        } else if is_pades {
            let level = if r.has_dss && r.has_timestamp {
                "B-LT or higher"
            } else if r.has_timestamp {
                "B-T"
            } else {
                "B-B (basic)"
            };
            println!("  ─── LTV Method: PAdES (ETSI EN 319 142) ───");
            println!("  Estimated PAdES level: {}", level);
            if r.has_dss {
                println!("  DSS dictionary provides CRL/OCSP/Certs for offline validation.");
            }
            if r.has_cms_revocation_data {
                println!("  CMS-embedded revocation data also present.");
            }
        }
    } else {
        println!("  ─── LTV Analysis ───");
        if !r.has_timestamp && !(r.has_cms_revocation_data || (r.has_dss && (r.dss_crl_count > 0 || r.dss_ocsp_count > 0))) {
            println!("  Missing: timestamp AND revocation data (CRL/OCSP).");
        } else if !r.has_timestamp {
            println!("  Missing: signature timestamp (needed to anchor validation time).");
        } else {
            println!("  Missing: revocation data (CRL/OCSP) for certificate chain.");
        }
        println!("  → Signature cannot be verified long-term after certificate expiry.");
    }
    println!();

    // Modification detection
    println!(
        "  Modification check: {}",
        if r.no_unauthorized_modifications {
            "no unauthorized changes ✅"
        } else {
            "UNAUTHORIZED MODIFICATIONS DETECTED ❌"
        }
    );
    if !r.modification_notes.is_empty() {
        println!("  Changes after this signature:");
        for note in &r.modification_notes {
            let icon = if note.contains("UNAUTHORIZED") {
                "❌"
            } else {
                "✅"
            };
            println!("    {} {}", icon, note);
        }
    }
    if r.byte_range_covers_whole_file {
        println!("  (last signature — no subsequent revisions)");
    }
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
        if c.is_self_signed {
            println!("        Self-signed: YES ⚠️");
        }
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
                print_result(r, i, results.len());
            }

            // Print overall summary
            let all_valid = results.iter().all(|r| r.is_valid());
            let all_cms_ok = results.iter().all(|r| r.cms_signature_valid);
            let all_digest_ok = results.iter().all(|r| r.digest_match);
            let all_trusted = results.iter().all(|r| r.certificate_chain_trusted);
            let any_untrusted = results.iter().any(|r| !r.certificate_chain_trusted);

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
                "  All chains trusted: {}",
                if all_trusted {
                    "yes ✅"
                } else {
                    "NO ⚠️  (one or more signers not from a recognized CA)"
                }
            );
            println!(
                "  Overall:            {}",
                if all_valid {
                    if all_trusted {
                        "✅ ALL SIGNATURES VALID"
                    } else {
                        "✅ ALL SIGNATURES VALID (but signer identity not verified — see warnings)"
                    }
                } else {
                    "❌ ONE OR MORE SIGNATURES INVALID"
                }
            );
            if any_untrusted && all_valid {
                println!();
                println!("  ⚠️  Note: Signature integrity is intact, but one or more signing");
                println!("     certificates are not issued by a recognized Certificate Authority.");
                println!("     The signer's identity cannot be independently verified.");
            }
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

