use pdf_signing::signature_validator::{SignatureValidator, ValidationResult};
use serde::Serialize;
use std::env;
use std::process;

// ── JSON output structures ─────────────────────────────────

/// Top-level JSON output for a single PDF verification.
#[derive(Serialize)]
struct JsonReport {
    file: String,
    file_size: usize,
    total_signatures: usize,
    all_valid: bool,
    all_cms_valid: bool,
    all_digests_match: bool,
    all_chains_trusted: bool,
    signatures: Vec<JsonSignatureResult>,
}

/// JSON output for one signature within a PDF.
#[derive(Serialize)]
struct JsonSignatureResult {
    index: usize,
    is_valid: bool,
    signature_type: String,

    // metadata
    filter: Option<String>,
    sub_filter: Option<String>,
    format_label: String,
    signer_name: Option<String>,
    contact_info: Option<String>,
    reason: Option<String>,
    signing_time: Option<String>,

    // byte range
    byte_range: Vec<i64>,
    byte_range_covers_whole_file: bool,

    // cryptographic
    digest_match: bool,
    cms_signature_valid: bool,
    computed_digest: String,

    // certificate chain
    certificate_chain_valid: bool,
    certificate_chain_trusted: bool,
    chain_warnings: Vec<String>,
    certificates: Vec<JsonCertificate>,

    // ltv
    is_ltv_enabled: bool,
    has_timestamp: bool,
    has_dss: bool,
    dss_crl_count: usize,
    dss_ocsp_count: usize,
    dss_cert_count: usize,
    has_vri: bool,
    has_cms_revocation_data: bool,

    // modification detection
    no_unauthorized_modifications: bool,
    modification_notes: Vec<String>,

    // security (pdf-insecurity.org)
    byte_range_valid: bool,
    signature_not_wrapped: bool,
    certification_level: Option<u8>,
    certification_permission_ok: bool,
    security_warnings: Vec<String>,

    // errors
    errors: Vec<String>,
}

/// JSON output for one certificate.
#[derive(Serialize)]
struct JsonCertificate {
    subject: String,
    issuer: String,
    serial_number: String,
    not_before: Option<String>,
    not_after: Option<String>,
    is_expired: bool,
    is_self_signed: bool,
}

impl JsonReport {
    fn from_results(path: &str, file_size: usize, results: &[ValidationResult]) -> Self {
        let signatures: Vec<JsonSignatureResult> = results
            .iter()
            .enumerate()
            .map(|(i, r)| {
                let sig_type = if r.field_info.is_document_timestamp {
                    "Document Timestamp"
                } else {
                    "Digital Signature"
                };
                let sub_filter_str = r.sub_filter.as_deref().unwrap_or("unknown");
                let format_label = match sub_filter_str {
                    "adbe.pkcs7.detached" => "PKCS#7 (pre-PAdES / Adobe legacy)",
                    "ETSI.CAdES.detached" => "PAdES (CAdES-based, ETSI standard)",
                    "ETSI.RFC3161" => "RFC 3161 Document Timestamp",
                    _ => sub_filter_str,
                };
                let digest_hex: String = r
                    .computed_digest
                    .iter()
                    .map(|b| format!("{:02x}", b))
                    .collect();

                let certificates: Vec<JsonCertificate> = r
                    .certificates
                    .iter()
                    .map(|c| JsonCertificate {
                        subject: c.subject.clone(),
                        issuer: c.issuer.clone(),
                        serial_number: c.serial_number.clone(),
                        not_before: c
                            .not_before
                            .map(|d| d.format("%Y-%m-%dT%H:%M:%SZ").to_string()),
                        not_after: c
                            .not_after
                            .map(|d| d.format("%Y-%m-%dT%H:%M:%SZ").to_string()),
                        is_expired: c.is_expired,
                        is_self_signed: c.is_self_signed,
                    })
                    .collect();

                JsonSignatureResult {
                    index: i + 1,
                    is_valid: r.is_valid(),
                    signature_type: sig_type.into(),
                    filter: r.filter.clone(),
                    sub_filter: r.sub_filter.clone(),
                    format_label: format_label.into(),
                    signer_name: r.signer_name.clone(),
                    contact_info: r.contact_info.clone(),
                    reason: r.reason.clone(),
                    signing_time: r.signing_time.clone(),
                    byte_range: r.byte_range.clone(),
                    byte_range_covers_whole_file: r.byte_range_covers_whole_file,
                    digest_match: r.digest_match,
                    cms_signature_valid: r.cms_signature_valid,
                    computed_digest: digest_hex,
                    certificate_chain_valid: r.certificate_chain_valid,
                    certificate_chain_trusted: r.certificate_chain_trusted,
                    chain_warnings: r.chain_warnings.clone(),
                    certificates,
                    is_ltv_enabled: r.is_ltv_enabled,
                    has_timestamp: r.has_timestamp,
                    has_dss: r.has_dss,
                    dss_crl_count: r.dss_crl_count,
                    dss_ocsp_count: r.dss_ocsp_count,
                    dss_cert_count: r.dss_cert_count,
                    has_vri: r.has_vri,
                    has_cms_revocation_data: r.has_cms_revocation_data,
                    no_unauthorized_modifications: r.no_unauthorized_modifications,
                    modification_notes: r.modification_notes.clone(),
                    byte_range_valid: r.byte_range_valid,
                    signature_not_wrapped: r.signature_not_wrapped,
                    certification_level: r.certification_level,
                    certification_permission_ok: r.certification_permission_ok,
                    security_warnings: r.security_warnings.clone(),
                    errors: r.errors.clone(),
                }
            })
            .collect();

        JsonReport {
            file: path.into(),
            file_size,
            total_signatures: results.len(),
            all_valid: results.iter().all(|r| r.is_valid()),
            all_cms_valid: results.iter().all(|r| r.cms_signature_valid),
            all_digests_match: results.iter().all(|r| r.digest_match),
            all_chains_trusted: results.iter().all(|r| r.certificate_chain_trusted),
            signatures,
        }
    }
}

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

    // Security checks (pdf-insecurity.org defenses)
    println!(
        "  ByteRange integrity: {}",
        if r.byte_range_valid {
            "valid ✅"
        } else {
            "INVALID ❌ (possible USF attack)"
        }
    );
    println!(
        "  Signature wrapping:  {}",
        if r.signature_not_wrapped {
            "not detected ✅"
        } else {
            "POSSIBLE SWA DETECTED ❌"
        }
    );
    if let Some(level) = r.certification_level {
        println!(
            "  Certification:       MDP level {} — {}",
            level,
            match level {
                1 => "no changes allowed",
                2 => "form fill-in and signing only",
                3 => "form fill-in, signing, and annotations",
                _ => "unknown",
            }
        );
        println!(
            "  MDP compliance:      {}",
            if r.certification_permission_ok {
                "compliant ✅"
            } else {
                "VIOLATED ❌ (possible certification attack)"
            }
        );
    }
    if !r.security_warnings.is_empty() {
        println!("  Security warnings:");
        for w in &r.security_warnings {
            println!("    ⚠️  {}", w);
        }
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

fn verify_pdf(path: &str, json_output: bool) {
    let pdf_bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) => {
            if json_output {
                let err = serde_json::json!({
                    "file": path,
                    "error": format!("could not read file: {}", e),
                });
                println!("{}", serde_json::to_string_pretty(&err).unwrap());
            } else {
                eprintln!("Error: could not read file '{}': {}", path, e);
            }
            process::exit(1);
        }
    };

    match SignatureValidator::validate(&pdf_bytes) {
        Ok(results) => {
            if json_output {
                let report = JsonReport::from_results(path, pdf_bytes.len(), &results);
                println!(
                    "{}",
                    serde_json::to_string_pretty(&report).unwrap()
                );
                if !report.all_valid {
                    process::exit(1);
                }
            } else {
                // Human-readable output
                println!("══════════════════════════════════════════════");
                println!("  Verifying: {}", path);
                println!("══════════════════════════════════════════════\n");
                println!("  File size: {} bytes\n", pdf_bytes.len());
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
        }
        Err(e) => {
            if json_output {
                let err = serde_json::json!({
                    "file": path,
                    "error": format!("{}", e),
                });
                println!("{}", serde_json::to_string_pretty(&err).unwrap());
            } else {
                eprintln!("  Verification failed: {}\n", e);
            }
            process::exit(1);
        }
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();

    let json_output = args.iter().any(|a| a == "--json" || a == "-j");
    let files: Vec<&String> = args[1..]
        .iter()
        .filter(|a| *a != "--json" && *a != "-j" && *a != "--help" && *a != "-h")
        .collect();
    let show_help = args.iter().any(|a| a == "--help" || a == "-h");

    if show_help {
        eprintln!(
            "Usage: verify_pdf [options] <file.pdf> [file2.pdf ...]

Options:
  --json, -j    Output results in JSON format
  --help, -h    Show this help

Examples:
  verify_pdf signed.pdf
  verify_pdf signed.pdf --json
  verify_pdf signed.pdf --json > report.json
  verify_pdf doc1.pdf doc2.pdf"
        );
        return;
    }

    if files.is_empty() {
        if !json_output {
            println!("Usage: verify_pdf [--json] <file.pdf> [file2.pdf ...]\n");
            println!("No file specified, verifying default: examples/result.pdf\n");
        }
        verify_pdf("./examples/result.pdf", json_output);
    } else {
        for path in &files {
            verify_pdf(path, json_output);
        }
    }
}

