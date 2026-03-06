//! Helpers to build and insert a PDF signature placeholder (`V` dictionary and default
//! `ByteRange`/`Contents`). These helpers are crate-private and intended to be used by
//! the signing flow (for example from `signature_info.rs` or `digitally_sign.rs`).

use crate::{Error, SignatureOptions, UserSignatureInfo};
use chrono::Utc;
use lopdf::{Dictionary, Document, Object, ObjectId, StringFormat};

#[cfg(test)]
use crate::PDFSigningDocument;
#[cfg(test)]
use crate::rectangle::Rectangle;

// ---------------------------------------------------------------------------
// Page-tree helpers
// ---------------------------------------------------------------------------

/// Collect all leaf page object-ids in document order by walking the `/Pages` tree.
fn collect_leaf_pages(doc: &Document, node: ObjectId) -> Result<Vec<ObjectId>, Error> {
    let dict = doc.get_object(node)?.as_dict()?;
    if let Ok(type_name) = dict.get(b"Type").and_then(|t| t.as_name()) {
        if type_name == b"Page" {
            return Ok(vec![node]);
        }
    }
    let mut pages = Vec::new();
    if dict.has(b"Kids") {
        for kid in dict.get(b"Kids")?.as_array()? {
            if let Ok(kid_ref) = kid.as_reference() {
                pages.extend(collect_leaf_pages(doc, kid_ref)?);
            }
        }
    }
    Ok(pages)
}

/// Return the object-id of a leaf page selected by a **1-based** page number.
/// If `page_number` is `None` or `Some(0)` the first page is returned.
pub(crate) fn find_page_object_id(
    doc: &Document,
    page_number: Option<u32>,
) -> Result<ObjectId, Error> {
    let root_ref = doc.trailer.get(b"Root")?.as_reference()?;
    let root_dict = doc.get_object(root_ref)?.as_dict()?;
    let pages_ref = root_dict.get(b"Pages")?.as_reference()?;

    let all_pages = collect_leaf_pages(doc, pages_ref)?;
    if all_pages.is_empty() {
        return Err(Error::Other("PDF contains no pages".into()));
    }

    let idx = match page_number {
        Some(n) if n >= 1 => (n as usize).saturating_sub(1),
        _ => 0,
    };

    all_pages
        .get(idx)
        .copied()
        .ok_or_else(|| Error::Other(format!(
            "Page {} does not exist (document has {} page(s))",
            idx + 1,
            all_pages.len()
        )))
}

/// Default rectangle used when `signature_rect` is not specified.
#[cfg(test)]
fn default_signature_rect() -> Rectangle {
    Rectangle { x1: 50.0, y1: 50.0, x2: 250.0, y2: 100.0 }
}

/// Build a `V` (signature) dictionary object that contains a default `ByteRange` and an
/// empty (hexadecimal) `Contents` placeholder sized according to `signature_options`.
/// The returned value is a `lopdf::Object::Dictionary` ready to be added to the new
/// incremental document.
pub(crate) fn build_signature_v_dictionary(
    user_signature_info: &UserSignatureInfo,
    signature_options: &SignatureOptions,
) -> Object {
    // Choose subfilter based on format
    let sub_filter = match signature_options.format {
        crate::signature_options::SignatureFormat::PKCS7 => "adbe.pkcs7.detached",
        crate::signature_options::SignatureFormat::PADES => "ETSI.CAdES.detached",
    };

    // Current time in PDF date format
    let now = Utc::now();

    let v_dictionary = Dictionary::from_iter(vec![
        ("Type", Object::Name("Sig".as_bytes().to_vec())),
        (
            "Filter",
            Object::Name("Adobe.PPKLite".as_bytes().to_vec()),
        ),
        ("SubFilter", Object::Name(sub_filter.as_bytes().to_vec())),
        (
            "ByteRange",
            // Default values (will be updated before creating the CMS signature)
            Object::Array(vec![
                Object::Integer(0),
                Object::Integer(10000),
                Object::Integer(20000),
                Object::Integer(10000),
            ]),
        ),
        (
            "Contents",
            Object::String(
                vec![0u8; signature_options.signature_size / 2],
                StringFormat::Hexadecimal,
            ),
        ),
        (
            "M",
            Object::String(
                now.format("D:%Y%m%d%H%M%S+00'00'")
                    .to_string()
                    .as_bytes()
                    .to_vec(),
                StringFormat::Literal,
            ),
        ),
        (
            "Name",
            Object::String(
                user_signature_info.user_name.as_bytes().to_vec(),
                StringFormat::Literal,
            ),
        ),
        (
            "ContactInfo",
            Object::String(
                user_signature_info.user_email.as_bytes().to_vec(),
                StringFormat::Literal,
            ),
        ),
        (
            "Reason",
            Object::String(
                user_signature_info.user_id.as_bytes().to_vec(),
                StringFormat::Literal,
            ),
        ),
    ]);

    Object::Dictionary(v_dictionary)
}

/// Insert the provided `v_dictionary` into the new incremental document and set the
/// `V` entry on the signature field `signature_obj_id` to reference the new object.
/// Returns the object id of the newly inserted `V` dictionary.
#[cfg(test)]
pub(crate) fn insert_signature_v_object(
    pdf: &mut PDFSigningDocument,
    signature_obj_id: ObjectId,
    v_dictionary: Object,
) -> Result<ObjectId, Error> {
    // Ensure the signature field object is available in the new incremental document
    pdf.raw_document
        .opt_clone_object_to_new_document(signature_obj_id)?;

    // Add the V dictionary as a new object in the incremental update
    let v_ref = pdf.raw_document.new_document.add_object(v_dictionary);

    // Get mutable reference to signature field in new document and set `V` to reference
    let sign_dict = pdf
        .raw_document
        .new_document
        .get_object_mut(signature_obj_id)?
        .as_dict_mut()?;

    sign_dict.set("V", lopdf::Object::Reference(v_ref));

    Ok(v_ref)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::image_insert::InsertImage;
    use crate::user_signature_info::UserSignatureInfo;
    use cryptographic_message_syntax::SignerBuilder;
    use std::fs;
    use x509_certificate::{CapturedX509Certificate, InMemorySigningKeyPair};
    use crate::acro_form::AcroForm;
    use lopdf::Object;
    use lopdf::Object::{Array, Name, Reference};

    #[test]
    fn test_build_signature_v_dictionary_contents_and_byterange() -> Result<(), Box<dyn std::error::Error>> {
        // Load example certificate and key from repository examples
        let cert_pem = fs::read_to_string("examples/assets/keystore-local-chain.pem")?;
        let x509_certs = CapturedX509Certificate::from_pem_multiple(cert_pem)?;
        let x509_cert = &x509_certs[0];
        let private_key_data = fs::read_to_string("examples/assets/keystore-local-key.pem")?;
        let private_key = InMemorySigningKeyPair::from_pkcs8_pem(&private_key_data)?;
        let signer = SignerBuilder::new(&private_key, x509_cert.clone());

        let user_info = UserSignatureInfo {
            user_id: "test".to_owned(),
            user_name: "Charlie".to_owned(),
            user_email: "charlie@test.com".to_owned(),
            user_signature: fs::read("examples/assets/sig1.png")?,
            user_signing_keys: signer,
            user_certificate_chain: x509_certs,
        };

        let mut signature_options = SignatureOptions::default();
        // Keep test fast by reducing placeholder size
        signature_options.signature_size = 1024;

        let obj = build_signature_v_dictionary(&user_info, &signature_options);

        match obj {
            Object::Dictionary(dict) => {
                let contents = dict.get(b"Contents").expect("Contents missing");
                match contents {
                    Object::String(bytes, format) => {
                        assert_eq!(bytes.len(), signature_options.signature_size / 2);
                        assert_eq!(*format, StringFormat::Hexadecimal);
                    }
                    _ => panic!("Contents not a string"),
                }
                let br = dict.get(b"ByteRange").expect("ByteRange missing");
                match br {
                    Object::Array(arr) => assert_eq!(arr.len(), 4),
                    _ => panic!("ByteRange not array"),
                }
            }
            _ => panic!("V is not a dictionary"),
        }

        Ok(())
    }

    #[test]
    fn test_insert_signature_v_into_sample_pdf() -> Result<(), Box<dyn std::error::Error>> {
        // Read sample PDF from examples/assets
        let pdf_bytes = fs::read("examples/assets/test-small-1sig.pdf")?;
        // Use unwrap() for crate Error-returning functions so the test can keep returning Box<dyn StdError>
        let mut pdf = PDFSigningDocument::read_from(&*pdf_bytes, "test-small-1sig.pdf".to_owned()).unwrap();

        // Load AcroForm entries from previous document
        let forms = AcroForm::load_all_forms(pdf.get_prev_document_ref()).unwrap();
        let first_form = forms
            .into_iter()
            .find(|f| f.is_empty_signature())
            .ok_or("No empty signature form found in sample PDF")?;

        let form_obj_id = first_form
            .get_object_id()
            .ok_or("Form object is not an indirect reference")?;

        // Build a minimal UserSignatureInfo (only name used by builder)
        let cert_pem = fs::read_to_string("examples/assets/keystore-local-chain.pem")?;
        let x509_certs = CapturedX509Certificate::from_pem_multiple(cert_pem)?;
        let x509_cert = &x509_certs[0];
        let private_key_data = fs::read_to_string("examples/assets/keystore-local-key.pem")?;
        let private_key = InMemorySigningKeyPair::from_pkcs8_pem(&private_key_data)?;
        let signer = SignerBuilder::new(&private_key, x509_cert.clone());

        let user_info = UserSignatureInfo {
            user_id: "test".to_owned(),
            user_name: "Charlie".to_owned(),
            user_email: "charlie@test.com".to_owned(),
            user_signature: fs::read("examples/assets/sig1.png")?,
            user_signing_keys: signer,
            user_certificate_chain: x509_certs,
        };

        let mut signature_options = SignatureOptions::default();
        signature_options.signature_size = 2048; // small but realistic

        // Build V dictionary and insert it
        let v_obj = build_signature_v_dictionary(&user_info, &signature_options);
        let v_ref = insert_signature_v_object(&mut pdf, form_obj_id, v_obj).unwrap();

        // Verify the signature field in new_document has V referencing v_ref
        let sign_obj = pdf.get_new_document_ref().get_object(form_obj_id)?;
        let sign_dict = sign_obj.as_dict()?;
        // `get` returns a Result<&Object, lopdf::Error>, use expect to convert error to panic
        let v_entry_ref = sign_dict.get(b"V").expect("V entry missing from signature field");
        let v_entry = v_entry_ref.clone();
        match v_entry {
            Object::Reference(r) => assert_eq!(r, v_ref),
            _ => panic!("V entry is not a Reference"),
        }

        Ok(())
    }

    #[test]
    fn test_create_signature_field_and_insert_v_on_sample_pdf() -> Result<(), Box<dyn std::error::Error>> {
        use lopdf::{Dictionary as LoDictionary, Object as LoObject};

        // Read sample PDF that does not contain an empty signature placeholder
        let pdf_bytes = fs::read("examples/assets/sample.pdf")?;
        let mut pdf = PDFSigningDocument::read_from(&*pdf_bytes, "sample.pdf".to_owned()).unwrap();

        // Work with previous document (original) and new_document for incremental update
        let prev = pdf.get_prev_document_ref();
        let root_id = prev.trailer.get(b"Root")?.as_reference()?;

        // Extract AcroForm reference (if present) from previous document before mutating new_document.
        let acroform_opt: Option<lopdf::ObjectId> = {
            let root_prev = prev.get_object(root_id)?.as_dict()?;
            if root_prev.has(b"AcroForm") {
                Some(root_prev.get(b"AcroForm")?.as_reference()?)
            } else {
                None
            }
        };

        // Clone Root into new document so we can mutate it
        pdf.raw_document.opt_clone_object_to_new_document(root_id).unwrap();

        // Build minimal UserSignatureInfo to supply Name, etc., and encode it into the form field
        let cert_pem = fs::read_to_string("examples/assets/keystore-local-chain.pem")?;
        let x509_certs = CapturedX509Certificate::from_pem_multiple(cert_pem)?;
        let x509_cert = &x509_certs[0];
        let private_key_data = fs::read_to_string("examples/assets/keystore-local-key.pem")?;
        let private_key = InMemorySigningKeyPair::from_pkcs8_pem(&private_key_data)?;
        let signer = SignerBuilder::new(&private_key, x509_cert.clone());

        let user_info = UserSignatureInfo {
            user_id: "test".to_owned(),
            user_name: "Tester".to_owned(),
            user_email: "tester@example.com".to_owned(),
            user_signature: fs::read("examples/assets/sig1.png")?,
            user_signing_keys: signer,
            user_certificate_chain: x509_certs.clone(),
        };

        // Generate a human-readable field name with a random number
        let field_name = format!("Signature{}", rand::random::<u32>());

        // Clone Root into new document so we can mutate it
        pdf.raw_document.opt_clone_object_to_new_document(root_id).unwrap();

        // Prepare signature options — place signature on page 1 at a custom rect
        let mut signature_options = SignatureOptions::default();
        signature_options.signature_size = 40_000;
        signature_options.signature_page = Some(1);
        signature_options.signature_rect = Some(Rectangle { x1: 50., y1: 50., x2: 250., y2: 100. });

        let rect = signature_options.signature_rect
            .clone()
            .unwrap_or_else(default_signature_rect);

        let target_page_ref = {
            let prev_doc = pdf.get_prev_document_ref();
            find_page_object_id(prev_doc, signature_options.signature_page)?
        };

        // Build V (signature value) dictionary
        let v_obj = build_signature_v_dictionary(&user_info, &signature_options);
        let v_ref = pdf.raw_document.new_document.add_object(v_obj);

        // Create appearance XObject from the user's signature image
        use std::io::Cursor;
        let image_name = format!("UserSignature{}", user_info.user_id);
        let image_object_id = pdf
            .add_image_as_form_xobject(Cursor::new(&user_info.user_signature), &image_name, rect)
            .unwrap();

        // Build merged field-widget dictionary (single object = field + annotation)
        let merged_dict = lopdf::Dictionary::from_iter(vec![
            ("FT", Name("Sig".as_bytes().to_vec())),
            ("T", LoObject::String(field_name.clone().into_bytes(), StringFormat::Literal)),
            ("V", Reference(v_ref)),
            ("Type", Name("Annot".as_bytes().to_vec())),
            ("Subtype", Name("Widget".as_bytes().to_vec())),
            ("Rect", Array(vec![
                (rect.x1 as i32).into(),
                (rect.y1 as i32).into(),
                (rect.x2 as i32).into(),
                (rect.y2 as i32).into(),
            ])),
            ("P", Reference(target_page_ref)),
            ("AP", Object::Dictionary(lopdf::Dictionary::from_iter(vec![
                ("N", Reference(image_object_id)),
            ]))),
            ("F", LoObject::Integer(4)),
        ]);
        let sig_field_id = pdf.raw_document.new_document.add_object(Object::Dictionary(merged_dict));
        eprintln!("Created merged field-widget id: {:?}, target page: {:?}", sig_field_id, target_page_ref);

        // Clone target page and merge XObject into Resources
        pdf.raw_document.opt_clone_object_to_new_document(target_page_ref)?;

        let merged_resources = {
            let prev_doc = pdf.get_prev_document_ref();
            let page_dict = prev_doc.get_object(target_page_ref)?.as_dict()?;

            let mut res_dict = if page_dict.has(b"Resources") {
                match page_dict.get(b"Resources")? {
                    Object::Dictionary(d) => d.clone(),
                    Object::Reference(res_ref) => prev_doc.get_object(*res_ref)?.as_dict()?.clone(),
                    _ => lopdf::Dictionary::new(),
                }
            } else {
                lopdf::Dictionary::new()
            };

            let mut xobj_sub = if res_dict.has(b"XObject") {
                match res_dict.get(b"XObject")? {
                    Object::Dictionary(d) => d.clone(),
                    Object::Reference(xobj_ref) => prev_doc.get_object(*xobj_ref)?.as_dict()?.clone(),
                    _ => lopdf::Dictionary::new(),
                }
            } else {
                lopdf::Dictionary::new()
            };

            xobj_sub.set(image_name.as_bytes().to_vec(), Object::Reference(image_object_id));
            res_dict.set("XObject", Object::Dictionary(xobj_sub));
            Object::Dictionary(res_dict)
        };

        let page_mut = pdf.raw_document.new_document.get_object_mut(target_page_ref)?.as_dict_mut()?;
        page_mut.set("Resources", merged_resources);

        let new_annots = if page_mut.has(b"Annots") {
            let annots = page_mut.get(b"Annots")?.clone();
            match annots {
                Array(mut arr) => { arr.push(Reference(sig_field_id)); Array(arr) }
                Reference(r) => Array(vec![Reference(r), Reference(sig_field_id)]),
                _ => Array(vec![Reference(sig_field_id)]),
            }
        } else {
            Array(vec![Reference(sig_field_id)])
        };
        page_mut.set("Annots", new_annots);

        if let Ok(annots_obj) = page_mut.get(b"Annots") {
            eprintln!("Page Annots after modification: {:?}", annots_obj);
        }
        if let Ok(res_obj) = page_mut.get(b"Resources") {
            eprintln!("Page Resources after modification: {:?}", res_obj);
        }

        // Attach field to AcroForm with SigFlags = 3
        match acroform_opt {
            Some(acro_id) => {
                pdf.raw_document.opt_clone_object_to_new_document(acro_id).unwrap();
                let acro_mut = pdf.raw_document.new_document.get_object_mut(acro_id)?.as_dict_mut()?;
                if acro_mut.has(b"Fields") {
                    let mut new_fields = acro_mut.get(b"Fields")?.as_array()?.clone();
                    new_fields.push(LoObject::Reference(sig_field_id));
                    acro_mut.set("Fields", LoObject::Array(new_fields));
                } else {
                    acro_mut.set("Fields", LoObject::Array(vec![LoObject::Reference(sig_field_id)]));
                }
                acro_mut.set("SigFlags", LoObject::Integer(3));
            }
            None => {
                let new_acro = LoDictionary::from_iter(vec![
                    ("Fields", LoObject::Array(vec![LoObject::Reference(sig_field_id)])),
                    ("SigFlags", LoObject::Integer(3)),
                ]);
                let new_acro_id = pdf.raw_document.new_document.add_object(LoObject::Dictionary(new_acro));
                let root_mut = pdf.raw_document.new_document.get_object_mut(root_id)?.as_dict_mut()?;
                root_mut.set("AcroForm", LoObject::Reference(new_acro_id));
            }
        }

        // Now perform the actual cryptographic signing which fills the `Contents` and updates `ByteRange`.
        // Dump the pre-sign PDF so we can inspect the incremental update before cryptographic signing
        let mut pre_bytes: Vec<u8> = Vec::new();
        pdf.write_document(&mut pre_bytes)?;
        fs::write("examples/assets/sample-pre-sign.pdf", &pre_bytes)?;
        eprintln!("Wrote pre-sign PDF: examples/assets/sample-pre-sign.pdf ({} bytes)", pre_bytes.len());

        // Now perform the actual cryptographic signing which fills the `Contents` and updates `ByteRange`.
        let signed_pdf = pdf.digitally_sign_document(&user_info, &signature_options).unwrap();
        // Save signed PDF (overwrite earlier placeholder file so it contains the final signed output)
        fs::write("examples/assets/sample-signed.pdf", &signed_pdf)?;

        // Load signed PDF and inspect `V` dictionary to ensure `Contents` is not all zeros
        let saved_doc = lopdf::Document::load_mem(&signed_pdf)?;
        let root_id_saved = saved_doc.trailer.get(b"Root")?.as_reference()?;
        let root_dict_saved = saved_doc.get_object(root_id_saved)?.as_dict()?;
        let acro_ref_saved = root_dict_saved.get(b"AcroForm")?.as_reference()?;
        let acro_dict_saved = saved_doc.get_object(acro_ref_saved)?.as_dict()?;
        // Find our field by /T value (starts with "Signature")
        let fields = acro_dict_saved.get(b"Fields")?.as_array()?;
        let mut found_field_ref = None;
        for f in fields {
            let f_ref = f.as_reference()?;
            let f_dict = saved_doc.get_object(f_ref)?.as_dict()?;
            if f_dict.has(b"T") {
                let t_obj = f_dict.get(b"T")?;
                if let lopdf::Object::String(bytes, _) = t_obj {
                    if bytes.starts_with(b"Signature") {
                        found_field_ref = Some(f_ref);
                        break;
                    }
                }
            }
        }
        let found_field_ref = found_field_ref.ok_or("Signed PDF does not contain a Signature field")?;
        let field_dict_saved = saved_doc.get_object(found_field_ref)?.as_dict()?;
        let v_ref_saved = field_dict_saved.get(b"V")?.as_reference()?;
        let v_dict_saved = saved_doc.get_object(v_ref_saved)?.as_dict()?;
        // Inspect Contents: ensure not all zero bytes
        if let lopdf::Object::String(contents_bytes, _) = v_dict_saved.get(b"Contents")? {
            let all_zero = contents_bytes.iter().all(|b| *b == 0u8);
            assert!(!all_zero, "Contents is still all zeros after signing");
        } else {
            panic!("Contents missing or not a string in V dictionary");
        }

        Ok(())
    }
}
