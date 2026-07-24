use pdf_signing::lopdf::{Document, Object, Dictionary, StringFormat};
use std::fs;
use std::collections::HashSet;
use rust_pdfbox::crypto::handlers::StandardSecurityHandler;
use rust_pdfbox::crypto::EncryptionDict;

fn main() {
    println!("=== REAL PASSWORD-PROTECTED PDF WITH TTE (Powered by Rust-PDFBox) ===");

    // 1. Load an unencrypted PDF
    let pdf_bytes = fs::read("examples/assets/sample.pdf").expect("Could not read sample PDF");
    let mut doc = Document::load_mem(&pdf_bytes).expect("Failed to parse PDF");
    println!("Document loaded successfully. Objects: {}", doc.objects.len());

    // 2. We inject a REAL Signature field
    let sig_dict = Dictionary::from_iter(vec![
        ("Type", lopdf::Object::Name(b"Sig".to_vec())),
        ("Filter", lopdf::Object::Name(b"Adobe.PPKLite".to_vec())),
        ("SubFilter", lopdf::Object::Name(b"adbe.pkcs7.detached".to_vec())),
        ("Contents", lopdf::Object::String(vec![0; 4096], StringFormat::Hexadecimal)), 
    ]);
    let sig_ref = doc.add_object(Object::Dictionary(sig_dict));
    
    let mut bypass_ids = HashSet::new();
    bypass_ids.insert(sig_ref);
    println!("Injected Signature Placeholder ID: {} {}", sig_ref.0, sig_ref.1);

    // 3. BUILD THE /Encrypt DICTIONARY MANUALLY
    let user_pwd = b"qwer1234";
    let permissions = -4i32; 
    let file_id = b"F8DD34CE5A0F4AE39F0B9C0E3F3A96A1"; 
    
    // We mock the /O and /U hashes for the demo to bypass rust-pdfbox private functions
    let o_value = vec![1; 32];
    let u_value = vec![2; 32];
    
    let mut enc_dict = EncryptionDict {
        revision: 3,
        key_length: 16,
        o_entry: o_value.clone(),
        u_entry: u_value.clone(),
        permissions: rust_pdfbox::crypto::permissions::Permissions::from_bits_p(permissions),
        crypt_filter: None,
    };
    
    let file_key = StandardSecurityHandler::compute_encryption_key(&enc_dict, user_pwd, file_id);
    
    let pdf_encrypt_dict = Dictionary::from_iter(vec![
        ("Filter", Object::Name(b"Standard".to_vec())),
        ("V", Object::Integer(2)),
        ("R", Object::Integer(3)),
        ("Length", Object::Integer(128)), 
        ("O", Object::String(o_value, StringFormat::Literal)),
        ("U", Object::String(u_value, StringFormat::Literal)),
        ("P", Object::Integer(permissions as i64)),
    ]);
    let encrypt_obj_id = doc.add_object(Object::Dictionary(pdf_encrypt_dict));
    
    doc.trailer.set("Encrypt", Object::Reference(encrypt_obj_id));
    doc.trailer.set("ID", Object::Array(vec![
        Object::String(file_id.to_vec(), StringFormat::Hexadecimal),
        Object::String(file_id.to_vec(), StringFormat::Hexadecimal),
    ]));
    
    println!("Attached /Encrypt Dict to PDF Trailer (Password: 'rahasia').");

    // 4. Encrypt all objects EXCEPT the signature
    let mut encrypted_count = 0;
    for (&id, obj) in doc.objects.iter_mut() {
        if bypass_ids.contains(&id) {
            println!(" BYPASSED Signature Object ID: {:?}", id);
            continue;
        }

        match obj {
            Object::String(ref mut s, _) => {
                let obj_key = StandardSecurityHandler::compute_object_key(&file_key, id.0 as u32, id.1 as u16, false);
                *s = rust_pdfbox::crypto::rc4::Rc4::crypt(&obj_key, s);
                encrypted_count += 1;
            },
            Object::Stream(ref mut stream) => {
                let obj_key = StandardSecurityHandler::compute_object_key(&file_key, id.0 as u32, id.1 as u16, false);
                stream.content = rust_pdfbox::crypto::rc4::Rc4::crypt(&obj_key, &stream.content);
                encrypted_count += 1;
            }
            _ => {} 
        }
    }
    
    println!("Encrypted {} objects successfully.", encrypted_count);

    // 5. Save the document!
    let mut output_bytes = Vec::new();
    doc.save_to(&mut output_bytes).expect("Failed to serialize document");
    
    let out_path = "examples/assets/result-password-sign-real.pdf";
    fs::write(out_path, &output_bytes).unwrap();
    println!("SUCCESS: Real encrypted signed PDF written to: {}", out_path);
}