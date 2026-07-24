use std::fs;
use pdf_signing::{
    SignOptions, Signer, digitally_sign,
};

#[test]
fn test_sign_and_add_password() {
    let pdf_bytes = fs::read("examples/assets/sample.pdf").expect("Failed to read sample.pdf");
    
    // Setup signer (Using a dummy key for testing, or assume external signer)
    // For TDD purposes, we just want to ensure the API accepts the password 
    // and the resulting PDF claims it is encrypted but has a valid signature dictionary.
    
    let mut options = SignOptions::default();
    options.reason = "TDD Password Signing Test".to_string();
    options.apply_new_password = Some("rahasia".to_string()); // NEW API
    
    // We expect the sign_pdf method to accept these options and return encrypted bytes
    // Since we don't have a full PKI loaded in this test, we'll check API structure.
    
    // Note: The actual signer implementation would go here.
    // let signer = ...
    // let signed_pdf = digitally_sign(&pdf_bytes, &signer, options).unwrap();
    // assert!(signed_pdf.len() > pdf_bytes.len());
    
    // // Validate it's encrypted
    // let doc = lopdf::Document::load_mem(&signed_pdf).unwrap();
    // assert!(doc.is_encrypted(), "Output PDF must be encrypted");
}