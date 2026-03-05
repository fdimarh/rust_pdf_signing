mod acro_form;
mod byte_range;
mod digitally_sign;
mod error;
mod image_insert;
mod image_insert_to_page;
mod image_xobject;
mod lopdf_utils;
mod ltv;
mod pdf_object;
pub mod rectangle;
mod signature_image;
mod signature_info;
mod signature_placeholder;
pub mod signature_options;
pub mod signature_validator;
mod user_signature_info;

use acro_form::AcroForm;
use byte_range::ByteRange;
use image_insert::InsertImage;
use image_insert_to_page::InsertImageToPage;
use lopdf::{
    content::{Content, Operation},
    Document, IncrementalDocument, Object, ObjectId,
};
use pdf_object::PdfObjectDeref;
use std::collections::HashMap;
use std::{fs::File, path::Path};

pub use error::Error;
pub use lopdf;
pub use rectangle::Rectangle;
pub use signature_options::SignatureOptions;
pub use user_signature_info::{UserFormSignatureInfo, UserSignatureInfo};

/// The whole PDF document. This struct only loads part of the document on demand.
#[derive(Debug, Clone)]
pub struct PDFSigningDocument {
    raw_document: IncrementalDocument,
    file_name: String,
    /// Link between the image name saved and the objectId of the image.
    /// This is used to reduce the amount of copies of the images in the pdf file.
    image_signature_object_id: HashMap<String, ObjectId>,

    acro_form: Option<Vec<AcroForm>>,
}

impl PDFSigningDocument {
    fn new(raw_document: IncrementalDocument, file_name: String) -> Self {
        PDFSigningDocument {
            raw_document,
            file_name,
            image_signature_object_id: HashMap::new(),
            acro_form: None,
        }
    }

    pub fn copy_from(&mut self, other: Self) {
        self.raw_document = other.raw_document;
        self.file_name = other.file_name;
        // Do not replace `image_signature_object_id`
        // We want to keep this so we can do optimization.
        self.acro_form = other.acro_form;
    }

    pub fn read_from<R: std::io::Read>(reader: R, file_name: String) -> Result<Self, Error> {
        let raw_doc = IncrementalDocument::load_from(reader)?;
        Ok(Self::new(raw_doc, file_name))
    }

    pub fn read<P: AsRef<Path>>(path: P, file_name: String) -> Result<Self, Error> {
        let raw_doc = IncrementalDocument::load(path)?;
        Ok(Self::new(raw_doc, file_name))
    }

    pub fn load_all(&mut self) -> Result<(), Error> {
        self.load_acro_form()
    }

    pub fn load_acro_form(&mut self) -> Result<(), Error> {
        if self.acro_form.is_none() {
            self.acro_form = Some(AcroForm::load_all_forms(
                self.raw_document.get_prev_documents(),
            )?);
        } else {
            log::info!("Already Loaded Acro Form.");
        }
        Ok(())
    }

    /// Save document to file
    pub fn save_document<P: AsRef<Path>>(&self, path: P) -> Result<File, Error> {
        // Create clone so we can compress the clone, not the original.
        let mut raw_document = self.raw_document.clone();
        raw_document.new_document.compress();
        Ok(raw_document.save(path)?)
    }

    /// Write document to Writer or buffer
    pub fn write_document<W: std::io::Write>(&self, target: &mut W) -> Result<(), Error> {
        // Create clone so we can compress the clone, not the original.
        let mut raw_document = self.raw_document.clone();
        raw_document.new_document.compress();
        raw_document.save_to(target)?;
        Ok(())
    }

    pub fn get_incr_document_ref(&self) -> &IncrementalDocument {
        &self.raw_document
    }

    pub fn get_prev_document_ref(&self) -> &Document {
        self.raw_document.get_prev_documents()
    }

    pub fn get_new_document_ref(&self) -> &Document {
        &self.raw_document.new_document
    }

    pub fn sign_document(
        &mut self,
        users_signature_info: Vec<UserSignatureInfo>,
        signature_options: &SignatureOptions,
    ) -> Result<Vec<u8>, Error> {
        self.load_all()?;
        // Set PDF version, version 1.5 is the minimum version required.
        self.raw_document.new_document.version = "1.5".parse().unwrap();

        // loop over AcroForm elements
        let mut acro_forms = self.acro_form.clone();
        let mut last_binary_pdf = None;

        // Take the first form field (if there is any)
        let mut form_field_current = acro_forms.as_ref().and_then(|list| list.first().cloned());
        let mut form_field_index = 0;

        // Covert `Vec<UserSignatureInfo>` to `HashMap<String, UserSignatureInfo>`
        let users_signature_info_map: HashMap<String, UserSignatureInfo> = users_signature_info
            .iter()
            .map(|info| (info.user_id.clone(), info.clone()))
            .collect();

        // Make sure we never end up in an infinite loop, should not happen.
        // But better safe than sorry.
        let mut loop_counter: u16 = 0;
        // Loop over all the form fields and sign them one by one.
        while let Some(form_field) = form_field_current {
            loop_counter += 1;
            if loop_counter >= 10000 {
                log::error!(
                    "Infinite loop detected and prevented. Please check file: `{}`.",
                    self.file_name
                );
                break;
            }
            // Check if it is a signature and it is already signed.
            if !form_field.is_empty_signature() {
                // Go to next form field if pdf did not change
                form_field_index += 1;
                form_field_current = acro_forms
                    .as_ref()
                    .and_then(|list| list.get(form_field_index).cloned());
                // Go back to start of while loop
                continue;
            }

            // TODO: Debug code, can be removed
            // if form_field_index == 1 {
            //     form_field_index += 1;
            //     form_field_current = acro_forms
            //         .as_ref()
            //         .and_then(|list| list.get(form_field_index).cloned());
            //     continue;
            // }

            // Update pdf (when nothing else is incorrect)
            // Insert signature images into pdf itself.
            let pdf_document_user_info_opt = self.add_signature_images(
                form_field,
                &users_signature_info_map,
                signature_options,
            )?;

            // PDF has been updated, now we need to digitally sign it.
            if let Some((pdf_document_image, user_form_info)) = pdf_document_user_info_opt {
                // Digitally sign the document using a cert.
                let user_info = users_signature_info_map
                    .get(&user_form_info.user_id)
                    .ok_or_else(|| Error::Other("User was not found".to_owned()))?;

                let new_binary_pdf =
                    pdf_document_image.digitally_sign_document(user_info, signature_options)?;
                // Reload file
                self.copy_from(Self::read_from(
                    &*new_binary_pdf,
                    pdf_document_image.file_name,
                )?);
                self.load_all()?;
                acro_forms = self.acro_form.clone();
                // Set as return value
                last_binary_pdf = Some(new_binary_pdf);
                // Reset form field index
                form_field_index = 0;
            } else {
                // Go to next form field because pdf did not change
                form_field_index += 1;
            }

            // Load next form field (or set to `0` depending on index.)
            form_field_current = acro_forms
                .as_ref()
                .and_then(|list| list.get(form_field_index).cloned());
        }

        match last_binary_pdf {
            Some(last_binary_pdf) => Ok(last_binary_pdf),
            None => {
                // No signing done, so just return initial document.
                Ok(self.raw_document.get_prev_documents_bytes().to_vec())
            }
        }
    }

    /// Digitally sign a PDF that does **not** contain a pre-existing empty signature
    /// placeholder.  A new signature field, widget annotation, and visible signature
    /// image are created from scratch and placed on the page selected by
    /// `signature_options.signature_page` (defaults to page 1).
    ///
    /// The position / size of the visible signature is controlled by
    /// `signature_options.signature_rect`.
    pub fn sign_document_no_placeholder(
        &mut self,
        user_info: &UserSignatureInfo,
        signature_options: &SignatureOptions,
    ) -> Result<Vec<u8>, Error> {
        use crate::signature_placeholder::{
            build_signature_v_dictionary, find_page_object_id,
        };
        use lopdf::Object::{Array, Name, Reference};
        use lopdf::StringFormat;
        use std::io::Cursor;

        self.raw_document.new_document.version = "1.5".parse().unwrap();

        let prev = self.get_prev_document_ref();
        let root_id = prev.trailer.get(b"Root")?.as_reference()?;

        // Check whether AcroForm already exists
        let acroform_opt: Option<ObjectId> = {
            let root_prev = prev.get_object(root_id)?.as_dict()?;
            if root_prev.has(b"AcroForm") {
                Some(root_prev.get(b"AcroForm")?.as_reference()?)
            } else {
                None
            }
        };

        // Clone Root into new incremental update
        self.raw_document.opt_clone_object_to_new_document(root_id)?;

        // Generate a human-readable field name with a random number
        let field_name = format!("Signature{}", rand::random::<u32>());

        // --- Create signature field (FT=Sig) ---
        let sig_field_dict = lopdf::Dictionary::from_iter(vec![
            ("FT", Object::Name(b"Sig".to_vec())),
            ("T", Object::String(field_name.into_bytes(), StringFormat::Literal)),
        ]);
        let sig_field_id = self.raw_document.new_document.add_object(
            Object::Dictionary(sig_field_dict),
        );

        // --- Attach field to AcroForm ---
        match acroform_opt {
            Some(acro_id) => {
                self.raw_document.opt_clone_object_to_new_document(acro_id)?;
                let acro_mut = self.raw_document.new_document
                    .get_object_mut(acro_id)?.as_dict_mut()?;
                if acro_mut.has(b"Fields") {
                    let mut new_fields = acro_mut.get(b"Fields")?.as_array()?.clone();
                    new_fields.push(Reference(sig_field_id));
                    acro_mut.set("Fields", Object::Array(new_fields));
                } else {
                    acro_mut.set("Fields", Array(vec![Reference(sig_field_id)]));
                }
            }
            None => {
                let new_acro = lopdf::Dictionary::from_iter(vec![
                    ("Fields", Array(vec![Reference(sig_field_id)])),
                ]);
                let new_acro_id = self.raw_document.new_document.add_object(
                    Object::Dictionary(new_acro),
                );
                let root_mut = self.raw_document.new_document
                    .get_object_mut(root_id)?.as_dict_mut()?;
                root_mut.set("AcroForm", Reference(new_acro_id));
            }
        }

        // --- Resolve target page and rectangle ---
        let rect = signature_options.signature_rect
            .unwrap_or(rectangle::Rectangle { x1: 50.0, y1: 50.0, x2: 250.0, y2: 100.0 });

        let target_page_ref = {
            let prev_doc = self.get_prev_document_ref();
            find_page_object_id(prev_doc, signature_options.signature_page)?
        };

        // --- Create appearance XObject from signature image ---
        let image_name = format!("UserSignature{}", user_info.user_id);
        let image_object_id = self.add_image_as_form_xobject(
            Cursor::new(&user_info.user_signature),
            &image_name,
            rect,
        )?;

        // --- Create widget annotation ---
        let widget_dict = lopdf::Dictionary::from_iter(vec![
            ("Type", Name("Annot".as_bytes().to_vec())),
            ("Subtype", Name("Widget".as_bytes().to_vec())),
            ("Rect", Array(vec![
                (rect.x1 as i32).into(),
                (rect.y1 as i32).into(),
                (rect.x2 as i32).into(),
                (rect.y2 as i32).into(),
            ])),
            ("AP", Object::Dictionary(lopdf::Dictionary::from_iter(vec![
                ("N", Reference(image_object_id)),
            ]))),
        ]);
        let widget_id = self.raw_document.new_document.add_object(
            Object::Dictionary(widget_dict),
        );

        // --- Clone target page and merge Resources ---
        self.raw_document.opt_clone_object_to_new_document(target_page_ref)?;

        let merged_resources = {
            let prev_doc = self.get_prev_document_ref();
            let page_dict = prev_doc.get_object(target_page_ref)?.as_dict()?;

            let mut res_dict = if page_dict.has(b"Resources") {
                match page_dict.get(b"Resources")? {
                    Object::Dictionary(d) => d.clone(),
                    Object::Reference(r) => prev_doc.get_object(*r)?.as_dict()?.clone(),
                    _ => lopdf::Dictionary::new(),
                }
            } else {
                lopdf::Dictionary::new()
            };

            let mut xobj_sub = if res_dict.has(b"XObject") {
                match res_dict.get(b"XObject")? {
                    Object::Dictionary(d) => d.clone(),
                    Object::Reference(r) => prev_doc.get_object(*r)?.as_dict()?.clone(),
                    _ => lopdf::Dictionary::new(),
                }
            } else {
                lopdf::Dictionary::new()
            };

            xobj_sub.set(image_name.as_bytes().to_vec(), Reference(image_object_id));
            res_dict.set("XObject", Object::Dictionary(xobj_sub));
            Object::Dictionary(res_dict)
        };

        // Set Resources and Annots on the target page
        let page_mut = self.raw_document.new_document
            .get_object_mut(target_page_ref)?.as_dict_mut()?;
        page_mut.set("Resources", merged_resources);

        let new_annots = if page_mut.has(b"Annots") {
            let mut arr = page_mut.get(b"Annots")?.as_array()?.clone();
            arr.push(Reference(widget_id));
            Array(arr)
        } else {
            Array(vec![Reference(widget_id)])
        };
        page_mut.set("Annots", new_annots);

        // --- Create and attach V dictionary ---
        let v_obj = build_signature_v_dictionary(user_info, signature_options);
        let v_ref = self.raw_document.new_document.add_object(v_obj);

        {
            let field_mut = self.raw_document.new_document
                .get_object_mut(sig_field_id)?.as_dict_mut()?;
            field_mut.set("Kids", Array(vec![Reference(widget_id)]));
            field_mut.set("V", Reference(v_ref));
        }
        {
            let widget_mut = self.raw_document.new_document
                .get_object_mut(widget_id)?.as_dict_mut()?;
            widget_mut.set("P", Reference(target_page_ref));
            widget_mut.set("Parent", Reference(sig_field_id));
        }

        // --- Perform cryptographic signing ---
        let signed_pdf = self.digitally_sign_document(user_info, signature_options)?;

        Ok(signed_pdf)
    }

    // pub fn add_signature_to_form<R: Read>(
    //     &mut self,
    //     image_reader: R,
    //     image_name: &str,
    //     page_id: ObjectId,
    //     form_id: ObjectId,
    // ) -> Result<ObjectId, Error> {
    //     let rect = Rectangle::get_rectangle_from_signature(form_id, &self.raw_document)?;
    //     let image_object_id_opt = self.image_signature_object_id.get(image_name).cloned();
    //     Ok(if let Some(image_object_id) = image_object_id_opt {
    //         // Image was already added so we can reuse it.
    //         self.add_image_to_page_only(image_object_id, image_name, page_id, rect)?
    //     } else {
    //         // Image was not added already so we need to add it in full
    //         let image_object_id = self.add_image(image_reader, image_name, page_id, rect)?;
    //         // Add signature to map
    //         self.image_signature_object_id
    //             .insert(image_name.to_owned(), image_object_id);
    //         image_object_id
    //     })
    // }
}

impl InsertImage for PDFSigningDocument {
    fn add_object<T: Into<Object>>(&mut self, object: T) -> ObjectId {
        self.raw_document.new_document.add_object(object)
    }
}

impl InsertImageToPage for PDFSigningDocument {
    fn add_xobject<N: Into<Vec<u8>>>(
        &mut self,
        page_id: ObjectId,
        xobject_name: N,
        xobject_id: ObjectId,
    ) -> Result<(), Error> {
        Ok(self
            .raw_document
            .add_xobject(page_id, xobject_name, xobject_id)?)
    }

    fn opt_clone_object_to_new_document(&mut self, object_id: ObjectId) -> Result<(), Error> {
        Ok(self
            .raw_document
            .opt_clone_object_to_new_document(object_id)?)
    }

    fn add_to_page_content(
        &mut self,
        page_id: ObjectId,
        content: Content<Vec<Operation>>,
    ) -> Result<(), Error> {
        Ok(self
            .raw_document
            .new_document
            .add_to_page_content(page_id, content)?)
    }
}
