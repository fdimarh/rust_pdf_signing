use lopdf::{
    encryption::{encrypt_object, EncryptionState},
    Document, IncrementalDocument, Object, ObjectId, Error
};
use std::collections::HashSet;
use std::io::Write;

/// Encrypts all objects in the document EXCEPT those whose ObjectIds are in `bypass_ids`.
/// This is critical for Digital Signatures because the `/Contents` hex string must remain unencrypted.
pub fn encrypt_document_with_bypass(
    doc: &mut Document,
    state: &EncryptionState,
    bypass_ids: &HashSet<ObjectId>,
) -> Result<(), Error> {
    if doc.is_encrypted() {
        return Err(Error::AlreadyEncrypted);
    }

    // Generate the Encryption dictionary (the `/Encrypt` object).
    let encrypted_dict = state.encode().map_err(|_| Error::Other("Failed to encode encryption state".into()))?;

    // Iterate through all objects.
    for (&id, obj) in doc.objects.iter_mut() {
        // BYPASS: Do not encrypt the signature value object
        if bypass_ids.contains(&id) {
            continue;
        }

        // Encrypt everything else using lopdf's native engine
        encrypt_object(state, id, obj)
            .map_err(|e| Error::Other(format!("Encryption error: {:?}", e).into()))?;
    }

    // Add the /Encrypt dictionary to the document and attach to trailer
    let encrypt_obj_id = doc.add_object(encrypted_dict);
    doc.trailer.set(b"Encrypt", Object::Reference(encrypt_obj_id));
    doc.encryption_state = None; // Reset state marker

    Ok(())
}