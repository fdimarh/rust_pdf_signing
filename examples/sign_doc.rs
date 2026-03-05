use cryptographic_message_syntax::SignerBuilder;
use pdf_signing::signature_options::SignatureFormat::PKCS7;
use pdf_signing::{PDFSigningDocument, Rectangle, SignatureOptions, UserSignatureInfo};
use std::{fs::File, io::Write};
use x509_certificate::{CapturedX509Certificate, InMemorySigningKeyPair};

fn main() {
    // ── Load the PDF that has NO pre-existing signature placeholder ──
    let pdf_file_name = "sample.pdf";
    let pdf_data = std::fs::read(format!("./examples/assets/{}", pdf_file_name)).unwrap();

    // ── Load certificate & private key ──
    let cert = std::fs::read_to_string("./examples/assets/keystore-local-chain.pem").unwrap();
    let x509_certs = CapturedX509Certificate::from_pem_multiple(cert).unwrap();
    let x509_cert = &x509_certs[0];
    let private_key_data =
        std::fs::read_to_string("./examples/assets/keystore-local-key.pem").unwrap();
    let private_key = InMemorySigningKeyPair::from_pkcs8_pem(&private_key_data).unwrap();
    let signer = SignerBuilder::new(&private_key, x509_cert.clone());

    let user_info = UserSignatureInfo {
        user_id: "272".to_owned(),
        user_name: "Charlie".to_owned(),
        user_email: "charlie@test.com".to_owned(),
        user_signature: std::fs::read("./examples/assets/sig1.png").unwrap(),
        user_signing_keys: signer,
        user_certificate_chain: x509_certs.clone(),
    };

    // ── Configure signature options ──
    let mut opts: SignatureOptions = Default::default();
    opts.format = PKCS7;
    opts.signature_size = 40_000;
    // Place the visible signature on page 1 at position (50,50)→(250,100)
    opts.signature_page = Some(1);
    opts.signature_rect = Some(Rectangle {
        x1: 50.0,
        y1: 50.0,
        x2: 250.0,
        y2: 100.0,
    });

    // ── Sign ──
    let mut pdf_signing_document =
        PDFSigningDocument::read_from(&*pdf_data, pdf_file_name.to_owned()).unwrap();
    let signed_pdf = pdf_signing_document
        .sign_document_no_placeholder(&user_info, &opts)
        .unwrap();

    // ── Write the signed PDF ──
    let mut out = File::create("./examples/result.pdf").unwrap();
    out.write_all(&signed_pdf).unwrap();
    println!(
        "Signed PDF written to ./examples/result.pdf ({} bytes)",
        signed_pdf.len()
    );
}
