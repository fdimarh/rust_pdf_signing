use cryptographic_message_syntax::SignerBuilder;
use pdf_signing::signature_options::PadesLevel;
use pdf_signing::signature_options::SignatureFormat::{PADES, PKCS7};
use pdf_signing::{PDFSigningDocument, Rectangle, SignatureOptions, UserSignatureInfo};
use std::{env, fs::File, io::Write, process};
use x509_certificate::{CapturedX509Certificate, InMemorySigningKeyPair};

fn usage() {
    eprintln!(
        "Usage: sign_doc <input.pdf> [options]

Options:
  -o, --output <path>       Output file path         (default: <input>-signed.pdf)
  -c, --cert <path>         Certificate chain PEM    (default: examples/assets/keystore-local-chain.pem)
  -k, --key <path>          Private key PEM          (default: examples/assets/keystore-local-key.pem)
  -i, --image <path>        Signature image PNG      (default: examples/assets/sig1.png)
  -f, --format <pkcs7|pades> Signature format        (default: pades)
  -l, --level <b-b|b-t|b-lt|b-lta>
                            PAdES conformance level  (default: b-t, only for pades)
  -p, --page <num>          Page number (1-based)    (default: 1)
  -r, --rect <x1,y1,x2,y2> Signature rectangle      (default: 50,50,250,100)
  --invisible               Invisible signature (no image)
  --name <name>             Signer name              (default: Signer)
  --email <email>           Signer email             (default: signer@example.com)
  --reason <text>           Signing reason            (default: Digital Signature)
  -h, --help                Show this help

PAdES Levels:
  b-b    Basic — ESS-signing-certificate-v2 only, no timestamp
  b-t    Timestamp — adds signature timestamp from TSA (default)
  b-lt   Long-Term — adds DSS dictionary with CRL/OCSP for offline validation
  b-lta  Long-Term Archival — adds document timestamp on top of B-LT

Examples:
  sign_doc input.pdf
  sign_doc input.pdf -f pades -l b-lt
  sign_doc input.pdf -f pades -l b-lta --invisible
  sign_doc input.pdf -o signed.pdf -f pkcs7 --invisible
  sign_doc input.pdf -c my-cert.pem -k my-key.pem -p 2 -r 100,100,300,150"
    );
}

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 || args.contains(&"-h".to_string()) || args.contains(&"--help".to_string()) {
        usage();
        if args.len() < 2 {
            process::exit(1);
        }
        return;
    }

    let input_path = &args[1];

    // ── Parse CLI options with defaults ──
    let mut output_path: Option<String> = None;
    let mut cert_path = "examples/assets/keystore-local-chain.pem".to_string();
    let mut key_path = "examples/assets/keystore-local-key.pem".to_string();
    let mut image_path = "examples/assets/sig1.png".to_string();
    let mut format_str = "pades".to_string();
    let mut level_str = "b-t".to_string();
    let mut page: u32 = 1;
    let mut rect = (50.0f64, 50.0f64, 250.0f64, 100.0f64);
    let mut visible = true;
    let mut signer_name = "Signer".to_string();
    let mut signer_email = "signer@example.com".to_string();
    let mut reason = "Digital Signature".to_string();

    let mut i = 2;
    while i < args.len() {
        match args[i].as_str() {
            "-o" | "--output" => {
                i += 1;
                output_path = Some(args.get(i).expect("Missing value for --output").clone());
            }
            "-c" | "--cert" => {
                i += 1;
                cert_path = args.get(i).expect("Missing value for --cert").clone();
            }
            "-k" | "--key" => {
                i += 1;
                key_path = args.get(i).expect("Missing value for --key").clone();
            }
            "-i" | "--image" => {
                i += 1;
                image_path = args.get(i).expect("Missing value for --image").clone();
            }
            "-f" | "--format" => {
                i += 1;
                format_str = args.get(i).expect("Missing value for --format").to_lowercase();
            }
            "-l" | "--level" => {
                i += 1;
                level_str = args.get(i).expect("Missing value for --level").to_lowercase();
            }
            "-p" | "--page" => {
                i += 1;
                page = args
                    .get(i)
                    .expect("Missing value for --page")
                    .parse()
                    .expect("--page must be a number");
            }
            "-r" | "--rect" => {
                i += 1;
                let parts: Vec<f64> = args
                    .get(i)
                    .expect("Missing value for --rect")
                    .split(',')
                    .map(|s| s.trim().parse().expect("--rect values must be numbers"))
                    .collect();
                if parts.len() != 4 {
                    eprintln!("Error: --rect requires 4 comma-separated values (x1,y1,x2,y2)");
                    process::exit(1);
                }
                rect = (parts[0], parts[1], parts[2], parts[3]);
            }
            "--invisible" => {
                visible = false;
            }
            "--name" => {
                i += 1;
                signer_name = args.get(i).expect("Missing value for --name").clone();
            }
            "--email" => {
                i += 1;
                signer_email = args.get(i).expect("Missing value for --email").clone();
            }
            "--reason" => {
                i += 1;
                reason = args.get(i).expect("Missing value for --reason").clone();
            }
            other => {
                eprintln!("Unknown option: {}", other);
                usage();
                process::exit(1);
            }
        }
        i += 1;
    }

    // Default output path: <input>-signed.pdf
    let output = output_path.unwrap_or_else(|| {
        let stem = input_path
            .strip_suffix(".pdf")
            .or_else(|| input_path.strip_suffix(".PDF"))
            .unwrap_or(input_path);
        format!("{}-signed.pdf", stem)
    });

    // ── Load input PDF ──
    let pdf_data = match std::fs::read(input_path) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("Error: cannot read '{}': {}", input_path, e);
            process::exit(1);
        }
    };
    let pdf_file_name = std::path::Path::new(input_path)
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();

    // ── Load certificate & private key ──
    let cert_pem = std::fs::read_to_string(&cert_path).unwrap_or_else(|e| {
        eprintln!("Error: cannot read cert '{}': {}", cert_path, e);
        process::exit(1);
    });
    let x509_certs = CapturedX509Certificate::from_pem_multiple(&cert_pem).unwrap_or_else(|e| {
        eprintln!("Error: invalid cert PEM: {}", e);
        process::exit(1);
    });
    let x509_cert = &x509_certs[0];

    let key_pem = std::fs::read_to_string(&key_path).unwrap_or_else(|e| {
        eprintln!("Error: cannot read key '{}': {}", key_path, e);
        process::exit(1);
    });
    let private_key = InMemorySigningKeyPair::from_pkcs8_pem(&key_pem).unwrap_or_else(|e| {
        eprintln!("Error: invalid private key PEM: {}", e);
        process::exit(1);
    });
    let signer = SignerBuilder::new(&private_key, x509_cert.clone());

    // ── Load signature image ──
    let sig_image = if visible {
        std::fs::read(&image_path).unwrap_or_else(|e| {
            eprintln!("Error: cannot read image '{}': {}", image_path, e);
            process::exit(1);
        })
    } else {
        Vec::new() // not used for invisible signatures
    };

    let user_info = UserSignatureInfo {
        user_id: reason.clone(),
        user_name: signer_name.clone(),
        user_email: signer_email.clone(),
        user_signature: sig_image,
        user_signing_keys: signer,
        user_certificate_chain: x509_certs.clone(),
    };

    // ── Configure signature options ──
    let format = match format_str.as_str() {
        "pkcs7" | "p7" => PKCS7,
        "pades" | "cades" => PADES,
        _ => {
            eprintln!("Error: unknown format '{}' (use pkcs7 or pades)", format_str);
            process::exit(1);
        }
    };

    let pades_level = match level_str.as_str() {
        "b-b" | "bb" => PadesLevel::B_B,
        "b-t" | "bt" => PadesLevel::B_T,
        "b-lt" | "blt" => PadesLevel::B_LT,
        "b-lta" | "blta" => PadesLevel::B_LTA,
        _ => {
            eprintln!("Error: unknown PAdES level '{}' (use b-b, b-t, b-lt, or b-lta)", level_str);
            process::exit(1);
        }
    };

    let mut opts: SignatureOptions = Default::default();
    opts.format = format;
    opts.pades_level = pades_level;
    opts.signature_size = 40_000;
    opts.signature_page = Some(page);
    opts.signature_rect = Some(Rectangle {
        x1: rect.0,
        y1: rect.1,
        x2: rect.2,
        y2: rect.3,
    });
    opts.visible_signature = visible;

    // ── Print summary ──
    println!("══════════════════════════════════════════════");
    println!("  PDF Digital Signing");
    println!("══════════════════════════════════════════════");
    println!("  Input:    {}", input_path);
    println!("  Output:   {}", output);
    println!("  Format:   {}", format_str.to_uppercase());
    if format_str == "pades" || format_str == "cades" {
        println!("  Level:    PAdES {}", level_str.to_uppercase());
    }
    println!("  Page:     {}", page);
    println!("  Visible:  {}", visible);
    if visible {
        println!(
            "  Rect:     ({}, {}, {}, {})",
            rect.0, rect.1, rect.2, rect.3
        );
        println!("  Image:    {}", image_path);
    }
    println!("  Signer:   {}", signer_name);
    println!("  Email:    {}", signer_email);
    println!("  Reason:   {}", reason);
    println!("  Cert:     {}", cert_path);
    println!("  Key:      {}", key_path);
    println!();

    // ── Sign ──
    let mut pdf_signing_document =
        PDFSigningDocument::read_from(&*pdf_data, pdf_file_name).unwrap_or_else(|e| {
            eprintln!("Error: failed to parse PDF: {}", e);
            process::exit(1);
        });

    let signed_pdf = pdf_signing_document
        .sign_document_no_placeholder(&user_info, &opts)
        .unwrap_or_else(|e| {
            eprintln!("Error: signing failed: {}", e);
            process::exit(1);
        });

    // ── Write output ──
    let mut out = File::create(&output).unwrap_or_else(|e| {
        eprintln!("Error: cannot create '{}': {}", output, e);
        process::exit(1);
    });
    out.write_all(&signed_pdf).unwrap();

    println!("✅ Signed PDF written to {} ({} bytes)", output, signed_pdf.len());
}
