use rust_pdfbox::{PdfError, signing::{sign_pdf, SignOptions, SignatureFormat, PadesLevel}};

/// Sign a PDF using rust-pdfbox, which fully supports Password-Protected TTE (AES-256 Rev 6).
/// This method acts as a bridge from rust_pdf_signing to the rust-pdfbox engine.
///
/// If `password` is provided, the document is decrypted before signing. The signing process
/// will append the signature using an Incremental Update, preserving the original encryption.
pub fn sign_encrypted_pdf(
    input_pdf_bytes: &[u8],
    cert_chain_pem: &str,
    private_key_pem: &str,
    password: Option<&str>,
    field_name: &str,
) -> Result<Vec<u8>, PdfError> {
    
    // Configure Signature Options for PAdES LTV (B-T or B-LT equivalent)
    let mut options = SignOptions::default();
    options.format = SignatureFormat::PAdES;
    options.pades_level = PadesLevel::B_T;
    options.field_name = field_name.to_string();
    options.include_crl = true;
    options.include_ocsp = true;
    options.include_dss = true;

    // Call the rust-pdfbox sign_pdf API
    sign_pdf(
        input_pdf_bytes,
        cert_chain_pem,
        private_key_pem,
        password,
        &options,
    )
}
