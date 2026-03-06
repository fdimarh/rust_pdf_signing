use crate::error::Error;
use crate::ltv::{append_dss_dictionary, build_adbe_revocation_attribute, build_adbe_revocation_unsigned_der, inject_unsigned_attribute_into_cms};
use crate::signature_options::{PadesLevel, SignatureFormat, SignatureOptions};
use crate::{ByteRange, PDFSigningDocument, UserSignatureInfo};
use bcder::Mode::Der;
use bcder::{encode::Values, Captured, OctetString};
use cryptographic_message_syntax::{Bytes, Oid, SignedDataBuilder};
use lopdf::ObjectId;
use sha2::{Digest, Sha256};
use std::io::Write;
use x509_certificate::rfc5652::AttributeValue;

impl PDFSigningDocument {
    fn compute_cert_hash(cert: Vec<u8>) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(&cert);
        hasher.finalize().to_vec()
    }

    fn build_signing_certificate_v2_attribute_value(cert_hash: Vec<u8>) -> Captured {
        let certificate_hash_octet_string = OctetString::new(Bytes::from(cert_hash));

        let ess_cert_id_v2 = bcder::encode::sequence(certificate_hash_octet_string.encode());

        let signing_certificate_v2 = bcder::encode::sequence(ess_cert_id_v2);

        let signing_certificate_attr_value = bcder::encode::sequence(signing_certificate_v2);

        signing_certificate_attr_value.to_captured(Der)
    }

    /// Digitally signs the document using a cryptographically secure algorithm.
    /// Note that using this function will prevent you from changing anything else about the document.
    /// Changing the document in any other way will invalidate the cryptographic check.
    pub(crate) fn digitally_sign_document(
        &self,
        user_info: &UserSignatureInfo,
        signature_options: &SignatureOptions,
    ) -> Result<Vec<u8>, Error> {
        // TODO: Code should be enabled in the future, do not remove.
        // Decompose `pdf_document` into it parts.
        // let acro_forms = self.acro_form.clone();
        // Add data to file before signing
        // Get first signature
        // let first_signature_id = if let Some(Some(first_signature)) =
        //     acro_forms.as_ref().map(|forms| forms.first().cloned())
        // {
        //     first_signature.get_object_id()
        // } else {
        //     None
        // };
        // // first_signature_id
        // if let Some(first_signature_id) = first_signature_id {
        //     pdf_signing_document.add_digital_signature_data(first_signature_id)?;
        // } else {
        //     return Err(InternalError::new(
        //         "Could not find first signature in PDF, can not sign document.",
        //         ApiErrorKind::ServerError,
        //         InternalErrorCodes::Default,
        //     ));
        // }

        // Convert pdf document to binary data.
        let mut pdf_file_data: Vec<u8> = Vec::new();
        self.write_document(&mut pdf_file_data)?;

        let (byte_range, pdf_file_data) =
            Self::set_next_byte_range(pdf_file_data, signature_options);

        let first_part = &pdf_file_data[byte_range.get_range(0)];
        let second_part = &pdf_file_data[byte_range.get_range(1)];

        // Used for debugging
        // log::trace!(
        //     "End of first part: {}",
        //     String::from_utf8_lossy(&first_part[(byte_range.0[1] - 15)..])
        // );
        // log::trace!(
        //     "Start of second part: {}...{}",
        //     String::from_utf8_lossy(&second_part[0..10]),
        //     String::from_utf8_lossy(&second_part[(second_part.len() - 5)..])
        // );

        let user_certificate_chain = user_info.user_certificate_chain.clone();
        let user_certificate = user_certificate_chain[0].clone();
        // 1.2.840.113549.1.9.16.2.47
        let signing_certificate_v2_oid = Oid(Bytes::copy_from_slice(&[
            42, 134, 72, 134, 247, 13, 1, 9, 16, 2, 47,
        ]));
        let cert_hash = Self::compute_cert_hash(user_certificate.encode_der().unwrap());
        let signing_certificate_v2_value =
            Self::build_signing_certificate_v2_attribute_value(cert_hash);

        // Add signing_certificate_v2 attribute to the signer
        let mut signer = user_info.user_signing_keys.clone();
        signer = signer.signed_attribute(
            signing_certificate_v2_oid,
            vec![AttributeValue::new(signing_certificate_v2_value)],
        );

        // Determine whether to include CMS-embedded revocation data and
        // signature timestamp based on the signature format and PAdES level.
        let is_pades = signature_options.format == SignatureFormat::PADES;
        let include_cms_revocation;
        let include_timestamp;
        let include_dss;

        if is_pades {
            match &signature_options.pades_level {
                PadesLevel::B_B => {
                    // Basic: no timestamp, no revocation data, no DSS
                    include_cms_revocation = false;
                    include_timestamp = false;
                    include_dss = false;
                }
                PadesLevel::B_T => {
                    // Timestamp: add signature timestamp, optionally CMS revocation
                    include_cms_revocation = signature_options.signed_attribute_include_crl
                        || signature_options.signed_attribute_include_ocsp;
                    include_timestamp = true;
                    include_dss = false;
                }
                PadesLevel::B_LT => {
                    // Long-Term: timestamp + CMS revocation + DSS dictionary
                    include_cms_revocation = true;
                    include_timestamp = true;
                    include_dss = true;
                }
                PadesLevel::B_LTA => {
                    // Long-Term Archival: same as B-LT + document timestamp
                    include_cms_revocation = true;
                    include_timestamp = true;
                    include_dss = true;
                }
            }
        } else {
            // PKCS7: For Adobe/Foxit LTV, revocation data must be in CMS
            // **unsigned attributes**, not signed attributes.  We skip it
            // here and inject after signing via inject_unsigned_attribute_into_cms().
            include_cms_revocation = false;
            include_timestamp = signature_options.timestamp_url.is_some();
            include_dss = signature_options.include_dss;
        }

        // Add adbe-revocationInfoArchival signed attribute (CRL/OCSP in CMS)
        if include_cms_revocation {
            let crl_flag = if is_pades {
                // For PAdES B-LT/B-LTA always fetch both; for B-T use user prefs
                matches!(signature_options.pades_level, PadesLevel::B_LT | PadesLevel::B_LTA)
                    || signature_options.signed_attribute_include_crl
            } else {
                signature_options.signed_attribute_include_crl
            };
            let ocsp_flag = if is_pades {
                matches!(signature_options.pades_level, PadesLevel::B_LT | PadesLevel::B_LTA)
                    || signature_options.signed_attribute_include_ocsp
            } else {
                signature_options.signed_attribute_include_ocsp
            };

            let adbe_revocation_data = build_adbe_revocation_attribute(
                &user_certificate_chain,
                crl_flag,
                ocsp_flag,
            );
            if let Some((oid, values)) = adbe_revocation_data {
                signer = signer.signed_attribute(oid, values);
            }
        }

        // Signature timestamp (TSA)
        if include_timestamp {
            if let Some(tsa_url) = &signature_options.timestamp_url {
                signer = signer.time_stamp_url(tsa_url).unwrap()
            }
        }

        // create new vec without the content part
        let mut vec = Vec::with_capacity(byte_range.get_capacity_inclusive());
        vec.extend_from_slice(first_part);
        vec.extend_from_slice(second_part);

        // Calculate file hash and sign it using the users key
        let mut builder = SignedDataBuilder::default()
            .content_external(vec)
            .content_type(Oid(Bytes::copy_from_slice(
                cryptographic_message_syntax::asn1::rfc5652::OID_ID_DATA.as_ref(),
            )))
            .signer(signer.clone());
        for i in 0..user_certificate_chain.len() {
            builder = builder.certificate(user_certificate_chain[i].clone());
        }

        let mut signature = builder.build_der().unwrap();

        // For PKCS7: inject adbe-revocationInfoArchival into CMS unsigned
        // attributes (alongside the timestamp token).  Adobe/Foxit require
        // revocation data in unsigned attrs for LTV recognition.
        if !is_pades
            && (signature_options.signed_attribute_include_crl
                || signature_options.signed_attribute_include_ocsp)
        {
            if let Some(attr_der) = build_adbe_revocation_unsigned_der(
                &user_certificate_chain,
                signature_options.signed_attribute_include_crl,
                signature_options.signed_attribute_include_ocsp,
            ) {
                signature = inject_unsigned_attribute_into_cms(&signature, &attr_der)?;
            }
        }

        #[cfg(feature = "debug")]
        {
            let mut file = std::fs::File::create("./signature.der").unwrap();
            file.write_all(&signature).unwrap();
        }

        // Write signature to file
        let mut pdf_file_data = Self::set_content(pdf_file_data, signature, signature_options);

        // Append DSS dictionary for B-LT and B-LTA levels (or when explicitly requested)
        if include_dss {
            pdf_file_data = append_dss_dictionary(pdf_file_data, user_certificate_chain.clone())?;
        }

        // For B-LTA: add a document-level timestamp via an incremental update.
        // This creates a second signature that timestamps the entire document
        // (including the DSS) to protect against future algorithm compromise.
        if is_pades && signature_options.pades_level == PadesLevel::B_LTA {
            if let Some(tsa_url) = &signature_options.timestamp_url {
                pdf_file_data = Self::append_document_timestamp(
                    pdf_file_data,
                    tsa_url,
                    signature_options.signature_size,
                )?;
            }
        }

        Ok(pdf_file_data)
    }

    /// Append a document-level timestamp signature (PAdES B-LTA).
    ///
    /// This creates a new incremental update containing a `/Type /DocTimeStamp`
    /// signature field.  The timestamp covers the entire document (including the
    /// DSS dictionary appended in the B-LT step), protecting it against future
    /// algorithm compromise.
    ///
    /// The timestamp is obtained from the RFC 3161 TSA at `tsa_url`.
    fn append_document_timestamp(
        pdf_bytes: Vec<u8>,
        tsa_url: &str,
        sig_size: usize,
    ) -> Result<Vec<u8>, Error> {
        use crate::ltv::fetch_timestamp_token;
        use crate::signature_placeholder::find_page_object_id;
        use lopdf::{Dictionary, IncrementalDocument, Object, StringFormat};

        let mut doc = IncrementalDocument::load_from(pdf_bytes.as_slice())?;
        doc.new_document.version = "2.0".parse().unwrap();

        let placeholder_size = sig_size;

        // Resolve page 1 for the /P entry
        let page_ref = find_page_object_id(doc.get_prev_documents(), Some(1))?;

        // ── Build the signature value (V) dictionary ──
        //
        // This contains /Type /DocTimeStamp plus /Filter, /SubFilter,
        // /ByteRange, and /Contents — the cryptographic payload.
        let v_dict = Dictionary::from_iter(vec![
            ("Type", Object::Name(b"Sig".to_vec())),
            ("Filter", Object::Name(b"Adobe.PPKLite".to_vec())),
            ("SubFilter", Object::Name(b"ETSI.RFC3161".to_vec())),
            (
                "ByteRange",
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
                    vec![0u8; placeholder_size / 2],
                    StringFormat::Hexadecimal,
                ),
            ),
        ]);
        let v_ref = doc.new_document.add_object(Object::Dictionary(v_dict));

        // ── Build the field + widget annotation dictionary ──
        //
        // This is a merged field-widget that references the V dictionary.
        // Adobe requires /V to point to the signature value dict so that
        // it recognises the field as "signed" (not "unsigned placeholder").
        let ts_field_name = format!("DocTimestamp{}", rand::random::<u32>());
        let field_dict = Dictionary::from_iter(vec![
            ("FT", Object::Name(b"Sig".to_vec())),
            (
                "T",
                Object::String(ts_field_name.into_bytes(), StringFormat::Literal),
            ),
            ("V", Object::Reference(v_ref)),
            ("Subtype", Object::Name(b"Widget".to_vec())),
            (
                "Rect",
                Object::Array(vec![
                    0i32.into(),
                    0i32.into(),
                    0i32.into(),
                    0i32.into(),
                ]),
            ),
            ("P", Object::Reference(page_ref)),
            ("F", Object::Integer(6)), // Hidden + Print
        ]);
        let ts_field_ref = doc.new_document.add_object(Object::Dictionary(field_dict));

        // Add to page Annots array
        doc.opt_clone_object_to_new_document(page_ref)?;
        let page_mut = doc
            .new_document
            .get_object_mut(page_ref)?
            .as_dict_mut()?;
        let new_annots = if page_mut.has(b"Annots") {
            let mut arr = page_mut.get(b"Annots")?.as_array()?.clone();
            arr.push(Object::Reference(ts_field_ref));
            Object::Array(arr)
        } else {
            Object::Array(vec![Object::Reference(ts_field_ref)])
        };
        page_mut.set("Annots", new_annots);

        // Add to AcroForm.Fields and set SigFlags
        let root_id = doc
            .get_prev_documents()
            .trailer
            .get(b"Root")?
            .as_reference()?;
        doc.opt_clone_object_to_new_document(root_id)?;

        let root_dict = doc
            .new_document
            .get_object_mut(root_id)?
            .as_dict_mut()?;

        // Get or create AcroForm
        let acro_ref = if root_dict.has(b"AcroForm") {
            root_dict.get(b"AcroForm")?.as_reference()?
        } else {
            let acro = Dictionary::from_iter(vec![
                ("Fields", Object::Array(vec![])),
                ("SigFlags", Object::Integer(3)),
            ]);
            let r = doc.new_document.add_object(Object::Dictionary(acro));
            let root_dict2 = doc.new_document.get_object_mut(root_id)?.as_dict_mut()?;
            root_dict2.set("AcroForm", Object::Reference(r));
            r
        };

        doc.opt_clone_object_to_new_document(acro_ref)?;
        let acro_mut = doc
            .new_document
            .get_object_mut(acro_ref)?
            .as_dict_mut()?;
        if acro_mut.has(b"Fields") {
            let mut fields = acro_mut.get(b"Fields")?.as_array()?.clone();
            fields.push(Object::Reference(ts_field_ref));
            acro_mut.set("Fields", Object::Array(fields));
        } else {
            acro_mut.set(
                "Fields",
                Object::Array(vec![Object::Reference(ts_field_ref)]),
            );
        }
        acro_mut.set("SigFlags", Object::Integer(3));

        // Write the incremental update (with placeholder Contents)
        let mut pdf_file_data = Vec::new();
        doc.save_to(&mut pdf_file_data)?;

        // Now compute ByteRange and fill in the timestamp token
        let sig_opts = SignatureOptions {
            signature_size: placeholder_size,
            ..Default::default()
        };
        let (byte_range, pdf_file_data) = Self::set_next_byte_range(pdf_file_data, &sig_opts);

        let first_part = &pdf_file_data[byte_range.get_range(0)];
        let second_part = &pdf_file_data[byte_range.get_range(1)];

        // Hash the file data outside the Contents placeholder
        let mut hasher = Sha256::new();
        hasher.update(first_part);
        hasher.update(second_part);
        let file_hash = hasher.finalize().to_vec();

        // Request a timestamp token from the TSA
        let ts_token = fetch_timestamp_token(tsa_url, &file_hash)?;

        // Write the timestamp token into Contents
        let pdf_file_data = Self::set_content(pdf_file_data, ts_token, &sig_opts);

        Ok(pdf_file_data)
    }

    // TODO: Not used, see start of `digitally_sign_document()`
    #[allow(dead_code)]
    pub(crate) fn add_digital_signature_data(
        &mut self,
        first_signature_id: ObjectId,
    ) -> Result<(), Error> {
        use lopdf::Object::*;
        // Get root ID
        let root_obj_id = self
            .raw_document
            .get_prev_documents()
            .trailer
            .get(b"Root")?
            .as_reference()?;
        // Clone object
        self.raw_document
            .opt_clone_object_to_new_document(root_obj_id)?;
        // Get Root in new document
        let root = self
            .raw_document
            .new_document
            .get_object_mut(root_obj_id)?
            .as_dict_mut()?;
        log::debug!("Root: {:?}", root);

        if root.has(b"Perms") {
            log::info!("Document already has `Perms` field.");
            let perms = root.get_mut(b"Perms")?.as_dict_mut()?;
            log::debug!("Perms: {:?}", perms);
            // Add `DocMDP` reference to existing dict
            perms.set("DocMDP", Reference(first_signature_id));
        } else {
            // Add `Perms` field with `DocMDP` reference
            root.set(
                "Perms",
                lopdf::Dictionary::from_iter(vec![("DocMDP", Reference(first_signature_id))]),
            );
        }

        Ok(())
    }

    // Find and set the `Content` field in the signature
    fn set_content(
        mut pdf_file_data: Vec<u8>,
        content: Vec<u8>,
        signature_options: &SignatureOptions,
    ) -> Vec<u8> {
        // Determine the byte ranged
        // Find the `Content` part of the file
        let pattern_prefix = b"/Contents<";
        let pattern_content = vec![48u8; signature_options.signature_size]; // 48 = 0x30 = `0`

        if content.len() > pattern_content.len() {
            panic!(
                "Length of content is to long. Available: {}, Needed: {}",
                pattern_content.len(),
                content.len()
            );
        }
        let mut pattern = pattern_prefix.to_vec();
        pattern.extend_from_slice(&pattern_content[..=50]); // Just add the first part, rest will be okay

        // Find the pattern in the PDF file binary
        let found_at = Self::find_binary_pattern(&pdf_file_data, &pattern);

        match found_at {
            Some(found_at) => {
                // Construct new Contents and insert it into file
                let new_contents_vec = format!(
                    "/Contents<{}",
                    content
                        .iter()
                        .map(|num| format!("{:02x}", num))
                        .collect::<Vec<String>>()
                        .join("")
                )
                .as_bytes()
                .to_vec();

                pdf_file_data.splice(
                    found_at..(found_at + new_contents_vec.len()),
                    new_contents_vec,
                );

                pdf_file_data
            }
            None => {
                // Pattern was not found, add debug info
                #[cfg(debug_assertions)]
                {
                    let crashed_file = "./pdf_missing_pattern.pdf";
                    let mut file = std::fs::File::create(crashed_file).unwrap();
                    file.write_all(&pdf_file_data).unwrap();
                    log::error!(
                        "Pattern not found `{}`. Saved file to: `{}`.",
                        String::from_utf8_lossy(&pattern),
                        crashed_file
                    );
                }
                panic!(
                    "Pattern not found `{}`. PDF Signing bug in the code.",
                    String::from_utf8_lossy(&pattern),
                );
            }
        }
    }

    /// Set the next found byte `ByteRange` that still has the default values.
    fn set_next_byte_range(
        mut pdf_file_data: Vec<u8>,
        signature_options: &SignatureOptions,
    ) -> (ByteRange, Vec<u8>) {
        // Determine the byte ranged
        // Find the `Content` part of the file
        let pattern_prefix = b"/ByteRange[0 10000 20000 10000]/Contents<";
        let pattern_content = vec![48u8; signature_options.signature_size]; // 48 = 0x30 = `0`
        let mut pattern = pattern_prefix.to_vec();
        pattern.extend_from_slice(&pattern_content[..=50]); // Just add the first part, rest will be okay

        // Search for `ByteRange` tag with default values
        let found_at = Self::find_binary_pattern(&pdf_file_data, &pattern).unwrap();

        // Calculate `ByteRange`
        let fixed_byte_range_width = 25;
        let pattern_prefix_len = b"/ByteRange[]/Contents<".len() + fixed_byte_range_width;
        let content_len =
            pattern_content.len() + b"0 10000 20000 10000".len() - fixed_byte_range_width;
        let content_offset = found_at + pattern_prefix_len - 1;
        let byte_range = ByteRange(vec![
            0,
            content_offset,
            content_offset + content_len + 2,
            pdf_file_data.len() - 2 - (content_offset + content_len),
        ]);

        // Code for debugging
        // dbg!(&byte_range
        //     .0
        //     .iter()
        //     .map(|x| format!("0x{:02x}", x))
        //     .collect::<Vec<String>>());

        // Change binary file

        // The `Contents` field after the `ByteRange` always need to have an even number of `0`s
        // because otherwise it will have invalid byte pattern.

        // Construct new ByteRange and insert it into file
        // Note: Notice the `0`s after `Contents<` this is to make sure that if the `ByteRange`
        // is shorter than the pattern that any other chars are overwritten.
        // Have at least "0 10000 20000 10000".len() + "{}".len() `0`s. (and even number)
        let mut new_byte_range_string = format!(
            "/ByteRange[{}]/Contents<0000000000000000000000",
            byte_range.to_list(fixed_byte_range_width).unwrap()
        );

        // The `Contents<...>` always need to be an even number of chars
        if pattern_prefix.len() % 2 != new_byte_range_string.len() % 2 {
            log::trace!("Added space to `ByteRange`");
            // Add space to make equal
            new_byte_range_string = format!(
                "/ByteRange[{} ]/Contents<0000000000000000000000",
                byte_range.to_list(fixed_byte_range_width).unwrap()
            );
        }
        let new_byte_range_string = new_byte_range_string.as_bytes().to_vec();

        pdf_file_data.splice(
            found_at..(found_at + new_byte_range_string.len()),
            new_byte_range_string,
        );

        (byte_range, pdf_file_data)
    }

    /// Finds the first instance matching the pattern.
    ///
    /// Note: This function can not deal well with repeating patterns inside the pattern.
    /// But this should not matter in our cases.
    ///
    /// Result is `byte_offset_where_pattern_starts`
    ///
    fn find_binary_pattern(bytes: &[u8], pattern: &[u8]) -> Option<usize> {
        if bytes.is_empty() || pattern.is_empty() {
            return None;
        }

        let first_pat_byte = pattern.first().expect("At least 1 byte expected.");
        let mut next_pat_byte = first_pat_byte;
        let mut pattern_index = 0;
        let mut start_index = 0;

        for (index, byte) in bytes.iter().enumerate() {
            if next_pat_byte == byte {
                // Save `start_index` for later
                if pattern_index == 0 {
                    start_index = index;
                }
                // Go to next byte of pattern
                pattern_index += 1;
                next_pat_byte = match pattern.get(pattern_index) {
                    Some(byte) => byte,
                    None => return Some(start_index),
                };
            } else {
                // If pattern breaks or does not match
                pattern_index = 0;
                next_pat_byte = first_pat_byte;
            }
        }

        None
    }
}
