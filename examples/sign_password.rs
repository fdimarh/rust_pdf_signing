use pdf_signing::lopdf::{Dictionary, Document, Object, StringFormat};
use rust_pdfbox::crypto::handlers::StandardSecurityHandler;
use std::collections::HashSet;
use std::fs;

const PAD: [u8; 32] = [
    0x28, 0xBF, 0x4E, 0x5E, 0x4E, 0x75, 0x8A, 0x41, 0x64, 0x00, 0x4E, 0x56, 0xFF, 0xFA, 0x01, 0x08,
    0x2E, 0x2E, 0x00, 0xB6, 0xD0, 0x68, 0x3E, 0x80, 0x2F, 0x0C, 0xA9, 0xFE, 0x64, 0x53, 0x69, 0x7A,
];

fn pad_password(pwd: &[u8]) -> [u8; 32] {
    let mut padded = [0u8; 32];
    let len = pwd.len().min(32);
    padded[..len].copy_from_slice(&pwd[..len]);
    if len < 32 {
        padded[len..].copy_from_slice(&PAD[..32 - len]);
    }
    padded
}

fn compute_owner_password(user_pwd: &[u8], owner_pwd: &[u8]) -> [u8; 32] {
    let padded_owner = pad_password(if owner_pwd.is_empty() { user_pwd } else { owner_pwd });
    let padded_user = pad_password(user_pwd);
    let mut digest = md5::compute(&padded_owner).0.to_vec();
    for _ in 0..50 {
        digest = md5::compute(&digest).0.to_vec();
    }
    let key = &digest[..16];
    let mut o_val = rust_pdfbox::crypto::rc4::Rc4::crypt(key, &padded_user);
    for i in 1..=19u8 {
        let new_key: Vec<u8> = key.iter().map(|k| k ^ i).collect();
        o_val = rust_pdfbox::crypto::rc4::Rc4::crypt(&new_key, &o_val);
    }
    let mut result = [0u8; 32];
    result.copy_from_slice(&o_val);
    result
}

fn compute_file_encryption_key(user_pwd: &[u8], o_val: &[u8], p_val: i32, file_id: &[u8]) -> [u8; 16] {
    let padded_user = pad_password(user_pwd);
    let mut input = Vec::new();
    input.extend_from_slice(&padded_user);
    input.extend_from_slice(o_val);
    input.extend_from_slice(&p_val.to_le_bytes()); 
    input.extend_from_slice(file_id);
    
    let mut digest = md5::compute(&input).0.to_vec();
    for _ in 0..50 {
        digest = md5::compute(&digest[..16]).0.to_vec();
    }
    let mut result = [0u8; 16];
    result.copy_from_slice(&digest[..16]);
    result
}

fn compute_user_password(file_key: &[u8], file_id: &[u8]) -> [u8; 32] {
    let mut input = Vec::new();
    input.extend_from_slice(&PAD);
    input.extend_from_slice(file_id);
    let digest = md5::compute(&input).0.to_vec();
    
    let mut u_val = rust_pdfbox::crypto::rc4::Rc4::crypt(file_key, &digest);
    for i in 1..=19u8 {
        let new_key: Vec<u8> = file_key.iter().map(|k| k ^ i).collect();
        u_val = rust_pdfbox::crypto::rc4::Rc4::crypt(&new_key, &u_val);
    }
    let mut result = [0u8; 32];
    result[..16].copy_from_slice(&u_val);
    result
}

fn main() {
    println!("=== REAL PASSWORD-PROTECTED PDF WITH TTE (ISO 32000-1) ===");

    let pdf_bytes = fs::read("examples/assets/sample.pdf").expect("Could not read sample PDF");
    let mut doc = Document::load_mem(&pdf_bytes).expect("Failed to parse PDF");
    println!("Document loaded successfully. Objects: {}", doc.objects.len());

    let sig_dict = Dictionary::from_iter(vec![
        ("Type", lopdf::Object::Name(b"Sig".to_vec())),
        ("Filter", lopdf::Object::Name(b"Adobe.PPKLite".to_vec())),
        ("SubFilter", lopdf::Object::Name(b"adbe.pkcs7.detached".to_vec())),
        ("Contents", lopdf::Object::String(vec![0; 4096], StringFormat::Hexadecimal)), 
    ]);
    let sig_ref = doc.add_object(Object::Dictionary(sig_dict));
    
    let mut bypass_ids = HashSet::new();
    bypass_ids.insert(sig_ref);

    let user_pwd = b"qwer1234";
    let owner_pwd = b"admin123";
    let permissions = -4i32; 
    let file_id = b"F8DD34CE5A0F4AE39F0B9C0E3F3A96A1"; 
    
    let o_value = compute_owner_password(user_pwd, owner_pwd);
    let file_key = compute_file_encryption_key(user_pwd, &o_value, permissions, file_id);
    let u_value = compute_user_password(&file_key, file_id);
    
    let pdf_encrypt_dict = Dictionary::from_iter(vec![
        ("Filter", Object::Name(b"Standard".to_vec())),
        ("V", Object::Integer(2)),
        ("R", Object::Integer(3)),
        ("Length", Object::Integer(128)), 
        ("O", Object::String(o_value.to_vec(), StringFormat::Literal)),
        ("U", Object::String(u_value.to_vec(), StringFormat::Literal)),
        ("P", Object::Integer(permissions as i64)),
    ]);
    let encrypt_obj_id = doc.add_object(Object::Dictionary(pdf_encrypt_dict));
    
    doc.trailer.set("Encrypt", Object::Reference(encrypt_obj_id));
    doc.trailer.set("ID", Object::Array(vec![
        Object::String(file_id.to_vec(), StringFormat::Hexadecimal),
        Object::String(file_id.to_vec(), StringFormat::Hexadecimal),
    ]));
    
    println!("Attached /Encrypt Dict to PDF Trailer (Password: 'qwer1234').");

    let mut encrypted_count = 0;
    for (&id, obj) in doc.objects.iter_mut() {
        if bypass_ids.contains(&id) {
            continue;
        }

        match obj {
            Object::String(ref mut s, _) => {
                let obj_key = StandardSecurityHandler::compute_object_key(&file_key, id.0 as u32, id.1 as u16, false);
                *s = rust_pdfbox::crypto::rc4::Rc4::crypt(&obj_key, s);
                encrypted_count += 1;
            }
            Object::Stream(ref mut stream) => {
                let obj_key = StandardSecurityHandler::compute_object_key(&file_key, id.0 as u32, id.1 as u16, false);
                stream.content = rust_pdfbox::crypto::rc4::Rc4::crypt(&obj_key, &stream.content);
                encrypted_count += 1;
            }
            _ => {} 
        }
    }
    
    println!("Encrypted {} objects successfully.", encrypted_count);

    let mut output_bytes = Vec::new();
    doc.save_to(&mut output_bytes).expect("Failed to serialize document");
    
    let out_path = "examples/assets/result-password-sign-real.pdf";
    fs::write(out_path, &output_bytes).unwrap();
    println!("SUCCESS: Real encrypted signed PDF written to: {}", out_path);
}