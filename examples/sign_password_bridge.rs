use std::fs::File;
use std::io::{Read, Write};
use pdf_signing::encrypt_sign::sign_encrypted_pdf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("╔═══════════════════════════════════════════════════════════════╗");
    println!("║  rust_pdf_signing · Password-Protected TTE (rust-pdfbox API)  ║");
    println!("╚═══════════════════════════════════════════════════════════════╝");

    // 1. Read the encrypted test PDF
    let mut f = File::open("examples/assets/sample_encrypted.pdf")?;
    let mut pdf_bytes = Vec::new();
    f.read_to_end(&mut pdf_bytes)?;

    // 2. Load certificate and key in PEM format
    let mut f_cert = File::open("examples/assets/crl-ocsp-chain.pem")?;
    let mut cert_pem = String::new();
    f_cert.read_to_string(&mut cert_pem)?;

    let mut f_key = File::open("examples/assets/crl-ocsp-key.pem")?;
    let mut key_pem = String::new();
    f_key.read_to_string(&mut key_pem)?;

    // 3. Sign using our bridge to rust-pdfbox
    println!("Signing document with password [admin123]...");
    let result = sign_encrypted_pdf(
        &pdf_bytes,
        &cert_pem,
        &key_pem,
        Some("admin123"), // Document Password
        "Signature1",
    )?;

    // 4. Save the result
    let out_path = "signed_encrypted_bridge.pdf";
    let mut out = File::create(out_path)?;
    out.write_all(&result)?;

    println!("✅ SUCCESS! Signed PDF saved to: {}", out_path);
    
    Ok(())
}
