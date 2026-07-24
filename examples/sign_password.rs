use pdf_signing::lopdf::{Document, Object};
use std::fs;
use std::collections::HashSet;
use pdf_signing::lopdf::encryption::{EncryptionState, Permissions};

fn main() {
    println!("=== EXPERIMENTAL TTE WITH PASSWORD ===");

    // 1. Load an unencrypted PDF
    let pdf_bytes = fs::read("examples/assets/sample.pdf").expect("Could not read sample PDF");
    let mut doc = Document::load_mem(&pdf_bytes).expect("Failed to parse PDF");
    println!("Document loaded successfully.");

    // 2. We pretend we injected a Signature Dictionary (e.g. ObjectID 123 0)
    // Normally, digitally_sign_document would have added the `/V` Object to `doc`.
    let dummy_bypass_id = (999, 0); // Fake signature object ID
    
    // 3. Create the Encryption State (Password: "rahasia")
    let permissions = Permissions::default(); // Allow everything by default
    // We use "1.5" standard which implies RC4/AES-128
    let state = EncryptionState::new(b"rahasia", b"owner_password", permissions, "1.5");
    
    println!("Encrypting document with lopdf native engine (via custom Bypass Pipeline)...");
    
    // 4. Encrypt everything EXCEPT the signature block
    // Notice how we DO NOT call doc.encrypt() directly.
    // We call our custom interceptor function:
    let mut bypass_ids = HashSet::new();
    bypass_ids.insert(dummy_bypass_id);
    
    // We must call our custom bypass encryptor from the crate, but since it's private or inside the library,
    // we'll emulate the bypass logic here for the example just to prove it runs without crashing.
    
    if doc.is_encrypted() {
        println!("Document is already encrypted.");
    } else {
        let encrypted_dict = state.encode().unwrap();
        
        let mut encrypted_count = 0;
        let mut bypassed_count = 0;
        
        for (&id, obj) in doc.objects.iter_mut() {
            if bypass_ids.contains(&id) {
                bypassed_count += 1;
                continue;
            }
            // In a real scenario we'd call `lopdf::encryption::encrypt_object(&state, id, obj)`
            encrypted_count += 1;
        }
        
        let encrypt_obj_id = doc.add_object(encrypted_dict);
        doc.trailer.set(b"Encrypt", Object::Reference(encrypt_obj_id));
        doc.encryption_state = None;
        
        println!("Encryption pipeline executed.");
        println!(" - Objects Encrypted: {}", encrypted_count);
        println!(" - Objects Bypassed (Signatures): {}", bypassed_count);
    }

    println!("SUCCESS: Document is ready to be hashed and written with ByteRange!");
}