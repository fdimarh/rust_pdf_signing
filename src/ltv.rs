use crate::Error;
use bcder::encode::Values;
use bcder::Mode::Der;
use bcder::{encode::PrimitiveContent, Captured, Integer, Mode, OctetString, Oid, Tag};
use cryptographic_message_syntax::Bytes;
use lopdf::Object::Reference;
use lopdf::{Dictionary, IncrementalDocument, Object, Stream};
use rasn::ber::encode;
use rasn::types::ObjectIdentifier;
use rasn_ocsp::{CertId, Request, TbsRequest};
use reqwest::blocking::Client;
use std::borrow::Cow;
use std::io::Write;
use x509_certificate::rfc5652::AttributeValue;
use x509_certificate::CapturedX509Certificate;
use x509_parser::extensions::DistributionPointName::FullName;
use x509_parser::extensions::ParsedExtension::AuthorityInfoAccess;
use x509_parser::num_bigint::{BigInt, Sign};
use x509_parser::prelude::ParsedExtension::CRLDistributionPoints;
use x509_parser::prelude::*;

pub(crate) fn get_ocsp_crl_url(
    captured_cert: &CapturedX509Certificate,
) -> (Option<String>, Option<String>) {
    let binding = captured_cert.encode_der().unwrap();
    let x509_certificate = X509Certificate::from_der(&*binding);
    let cert = x509_certificate.unwrap().1;
    let mut crl_url = None;
    let mut ocsp_url = None;
    for extension in cert.extensions() {
        let parsed = extension.parsed_extension();
        if let AuthorityInfoAccess(aia) = parsed {
            for access_desc in &aia.accessdescs {
                if "1.3.6.1.5.5.7.48.1".eq(&access_desc.access_method.to_string()) {
                    if let GeneralName::URI(ocsp) = &access_desc.access_location {
                        ocsp_url = Some(ocsp.to_string());
                    }
                }
            }
        } else if let CRLDistributionPoints(crl_dp) = parsed {
            for dist_point in &crl_dp.points {
                if let Some(point) = &dist_point.distribution_point {
                    if let FullName(names_list) = &point {
                        if names_list.len() > 0 {
                            let name = &names_list[0];
                            if let GeneralName::URI(crl) = name {
                                crl_url = Some(crl.to_string());
                            }
                        }
                    }
                }
            }
        }
    }

    return (ocsp_url, crl_url);
}

pub(crate) fn fetch_ocsp_response(
    captured_cert: &CapturedX509Certificate,
    ocsp_url: String,
) -> Result<Option<Vec<u8>>, Box<dyn std::error::Error>> {
    let binding = captured_cert.encode_der().unwrap();
    let cert = X509Certificate::from_der(&*binding).unwrap().1;

    let ocsp_req = create_ocsp_request(&cert)?;

    let client = Client::new();
    let response = client
        .post(&ocsp_url)
        .header("Content-Type", "application/ocsp-request")
        .body(ocsp_req)
        .send()?;

    return if response.status().is_success() {
        let ocsp_resp = response.bytes()?;
        Ok(Some(ocsp_resp.to_vec()))
    } else {
        eprintln!("OCSP request failed with status: {}", response.status());
        Ok(None)
    };
}

pub(crate) fn create_ocsp_request(
    cert: &X509Certificate,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let sha1_oid = ObjectIdentifier::new_unchecked(Cow::from(vec![1, 3, 14, 3, 2, 26]));

    let sha1 = rasn_pkix::AlgorithmIdentifier {
        algorithm: sha1_oid,
        parameters: None,
    };

    let request = Request {
        req_cert: CertId {
            hash_algorithm: sha1,
            // TODO
            issuer_name_hash: Default::default(),
            // TODO
            issuer_key_hash: Default::default(),
            serial_number: BigInt::from_bytes_le(Sign::Plus, cert.raw_serial()).into(),
        },
        single_request_extensions: None,
    };

    let tbs_request = TbsRequest {
        version: Default::default(),
        requestor_name: None,
        request_list: vec![request],
        request_extensions: None,
    };

    let ocsp_req = rasn_ocsp::OcspRequest {
        tbs_request,
        optional_signature: None,
    };

    Ok(encode(&ocsp_req).unwrap())
}

pub(crate) fn fetch_crl_response(
    crl_url: String,
) -> Result<Option<Vec<u8>>, Box<dyn std::error::Error>> {
    let client = Client::new();
    //println!("{}", crl_url);
    let response = client.get(&crl_url).send().unwrap();

    if response.status().is_success() {
        let crl_resp = response.bytes()?;
        //print!("{:?}", crl_resp);
        return Ok(Some(crl_resp.to_vec()));
    } else {
        eprintln!("CRL request failed with status: {}", response.status());
        return Ok(None);
    }
}

pub struct CrlReponse {
    pub bytes: Bytes,
}

impl Values for CrlReponse {
    fn encoded_len(&self, _: Mode) -> usize {
        self.bytes.len()
    }

    fn write_encoded<W: Write>(&self, _: Mode, target: &mut W) -> Result<(), std::io::Error> {
        target.write_all(&*self.bytes)
    }
}

/// Helper to emit pre-encoded DER bytes as-is (no extra wrapping).
struct RawDerBytes(Vec<u8>);

impl Values for RawDerBytes {
    fn encoded_len(&self, _: Mode) -> usize {
        self.0.len()
    }

    fn write_encoded<W: Write>(&self, _: Mode, target: &mut W) -> Result<(), std::io::Error> {
        target.write_all(&self.0)
    }
}

pub(crate) fn encode_revocation_info_archival<'a>(
    crls_bytes: Vec<Vec<u8>>,
    ocsps_bytes: Vec<Vec<u8>>,
) -> Option<Captured> {
    let mut revocation_vector = Vec::new();

    if crls_bytes.len() > 0 {
        let mut crl_responses = Vec::new();

        for crl_bytes in crls_bytes {
            let crl_response = CrlReponse {
                bytes: Bytes::copy_from_slice(crl_bytes.as_slice()),
            };
            crl_responses.push(crl_response);
        }

        let crl_responses = bcder::encode::sequence(crl_responses);

        let crl_tagged = bcder::encode::sequence_as(Tag::CTX_0, crl_responses);

        // crl [0] EXPLICIT SEQUENCE of CRLs, OPTIONAL
        revocation_vector.push(crl_tagged.to_captured(Der));
    }

    if ocsps_bytes.len() > 0 {
        let mut ocsp_responses = Vec::new();
        for ocsp_bytes in ocsps_bytes {
            let ocsp_encoded = OctetString::new(Bytes::from(ocsp_bytes.clone()));
            // 1.3.6.1.5.5.7.48.1.1 - id_pkix_ocsp_basic
            let pkix_ocsp_basic_oid = Oid(Bytes::copy_from_slice(&[43, 6, 1, 5, 5, 7, 48, 1, 1]));
            let basic_ocsp_response =
                bcder::encode::sequence((pkix_ocsp_basic_oid.encode(), ocsp_encoded.encode()));

            let tagged_basic_ocsp_response =
                bcder::encode::sequence_as(Tag::CTX_0, basic_ocsp_response);
            let tagged_seq = Integer::from(0u8)
                .encode_as(Tag::ENUMERATED)
                .to_captured(Der);
            let ocsp_response = bcder::encode::sequence((tagged_seq, tagged_basic_ocsp_response));
            ocsp_responses.push(ocsp_response);
        }

        let ocsp_responses = bcder::encode::sequence(ocsp_responses);

        let ocsp_tagged = bcder::encode::sequence_as(Tag::CTX_1, ocsp_responses);

        // ocsp [1] EXPLICIT SEQUENCE of OCSP Responses, OPTIONAL
        revocation_vector.push(ocsp_tagged.to_captured(Der));
    }

    if revocation_vector.len() > 0 {
        Some(bcder::encode::sequence(revocation_vector).to_captured(Der))
    } else {
        None
    }
}

pub(crate) fn fetch_revocation_data(
    user_certificate_chain: &Vec<CapturedX509Certificate>,
    include_crl: bool,
    include_ocsp: bool,
) -> (Vec<Vec<u8>>, Vec<Vec<u8>>) {
    let mut crl_data = Vec::new();
    let mut ocsp_data = Vec::new();
    for cert in user_certificate_chain {
        let (ocsp_url, crl_url) = get_ocsp_crl_url(&cert);

        if include_ocsp {
            if let Some(ocsp) = ocsp_url {
                let cert_ocsp_data = fetch_ocsp_response(cert, ocsp);
                if cert_ocsp_data.is_ok() {
                    ocsp_data.push(cert_ocsp_data.unwrap().unwrap());
                }
            }
        }
        if include_crl {
            if let Some(crl) = crl_url {
                let cert_crl_data = fetch_crl_response(crl).unwrap();
                if cert_crl_data.is_some() {
                    crl_data.push(cert_crl_data.unwrap());
                }
            }
        }
    }

    return (crl_data, ocsp_data);
}

pub(crate) fn build_adbe_revocation_attribute(
    user_certificate_chain: &Vec<CapturedX509Certificate>,
    include_crl: bool,
    include_ocsp: bool,
) -> Option<(Oid, Vec<AttributeValue>)> {
    let (crl_data, ocsp_data) =
        fetch_revocation_data(user_certificate_chain, include_crl, include_ocsp);

    let encoded_revocation_info = encode_revocation_info_archival(crl_data, ocsp_data);
    if encoded_revocation_info.is_some() {
        let adbe_revocation_oid = Oid(Bytes::copy_from_slice(&[
            42, 134, 72, 134, 247, 47, 1, 1, 8,
        ]));

        return Some((
            adbe_revocation_oid,
            vec![AttributeValue::new(encoded_revocation_info.unwrap())],
        ));
    }

    return None;
}

/// Build the `adbe-revocationInfoArchival` attribute as a complete DER-encoded
/// ASN.1 `Attribute` suitable for injection into CMS `unsignedAttrs`.
///
/// Returns `None` if no revocation data could be fetched.
///
/// The structure is:
/// ```asn1
/// Attribute ::= SEQUENCE {
///   attrType   OBJECT IDENTIFIER,   -- 1.2.840.113583.1.1.8
///   attrValues SET OF AttributeValue
/// }
/// ```
pub(crate) fn build_adbe_revocation_unsigned_der(
    user_certificate_chain: &Vec<CapturedX509Certificate>,
    include_crl: bool,
    include_ocsp: bool,
) -> Option<Vec<u8>> {
    let (crl_data, ocsp_data) =
        fetch_revocation_data(user_certificate_chain, include_crl, include_ocsp);

    let encoded_revocation_info = encode_revocation_info_archival(crl_data, ocsp_data)?;

    // OID 1.2.840.113583.1.1.8 = adbe-revocationInfoArchival
    let adbe_revocation_oid = Oid(Bytes::copy_from_slice(&[
        42, 134, 72, 134, 247, 47, 1, 1, 8,
    ]));

    // The Captured contains the raw DER of RevocationInfoArchival SEQUENCE.
    // We must embed the raw bytes directly into the SET, NOT use .encode()
    // which would wrap them in an OCTET STRING.
    let rev_info_bytes = encoded_revocation_info.as_slice();
    let rev_info_raw = RawDerBytes(rev_info_bytes.to_vec());

    // Attribute ::= SEQUENCE { attrType OID, attrValues SET OF ANY }
    let attr = bcder::encode::sequence((
        adbe_revocation_oid.encode(),
        bcder::encode::set(rev_info_raw),
    ));

    Some(attr.to_captured(Der).as_slice().to_vec())
}

/// Inject an unsigned attribute into an already-signed CMS `SignedData` DER blob.
///
/// Adobe/Foxit require `adbe-revocationInfoArchival` to be in the CMS
/// **unsigned attributes** (not signed attributes) for LTV recognition
/// with `adbe.pkcs7.detached`.
///
/// This function:
/// 1. Locates the `SignerInfo` inside the CMS `SignedData`.
/// 2. Appends the given attribute DER to the existing `unsignedAttrs`
///    (or creates the `[1] IMPLICIT SET OF` wrapper if absent).
/// 3. Re-encodes the outer lengths so the CMS blob remains valid DER.
///
/// The CMS structure (simplified):
/// ```text
/// ContentInfo ::= SEQUENCE {
///   contentType OID,
///   content [0] EXPLICIT SignedData
/// }
/// SignedData ::= SEQUENCE {
///   version, digestAlgorithms, encapContentInfo, [0] certificates,
///   signerInfos SET OF SignerInfo
/// }
/// SignerInfo ::= SEQUENCE {
///   version, sid, digestAlgorithm, [0] signedAttrs,
///   signatureAlgorithm, signature,
///   [1] unsignedAttrs OPTIONAL
/// }
/// ```
pub(crate) fn inject_unsigned_attribute_into_cms(
    cms_der: &[u8],
    attr_der: &[u8],
) -> Result<Vec<u8>, Error> {
    // Strategy: We parse just enough of the DER structure to find the
    // SignerInfo's unsignedAttrs location, then splice in the new attribute.
    //
    // Rather than a full ASN.1 rewrite (fragile), we find the end of the
    // SignerInfo SEQUENCE and either:
    //   a) If unsignedAttrs [1] already exists (timestamp was added), append
    //      our attribute to it.
    //   b) If unsignedAttrs is absent, add `[1] IMPLICIT SET OF { attr }`.

    // Helper: read a DER tag+length, returning (tag_byte, header_len, content_len)
    fn read_tl(data: &[u8], pos: usize) -> Option<(u8, usize, usize)> {
        if pos >= data.len() {
            return None;
        }
        let tag = data[pos];
        if pos + 1 >= data.len() {
            return None;
        }
        let len_byte = data[pos + 1];
        if len_byte < 0x80 {
            Some((tag, 2, len_byte as usize))
        } else {
            let num_bytes = (len_byte & 0x7f) as usize;
            if num_bytes == 0 || num_bytes > 4 || pos + 2 + num_bytes > data.len() {
                return None;
            }
            let mut length: usize = 0;
            for i in 0..num_bytes {
                length = (length << 8) | data[pos + 2 + i] as usize;
            }
            Some((tag, 2 + num_bytes, length))
        }
    }

    // Helper: skip a TLV element, returning the position after it
    fn skip_tlv(data: &[u8], pos: usize) -> Option<usize> {
        let (_, hdr, len) = read_tl(data, pos)?;
        Some(pos + hdr + len)
    }

    // Helper: encode a DER length
    fn encode_length(len: usize) -> Vec<u8> {
        if len < 0x80 {
            vec![len as u8]
        } else if len <= 0xff {
            vec![0x81, len as u8]
        } else if len <= 0xffff {
            vec![0x82, (len >> 8) as u8, (len & 0xff) as u8]
        } else if len <= 0xff_ffff {
            vec![0x83, (len >> 16) as u8, ((len >> 8) & 0xff) as u8, (len & 0xff) as u8]
        } else {
            vec![
                0x84,
                (len >> 24) as u8,
                ((len >> 16) & 0xff) as u8,
                ((len >> 8) & 0xff) as u8,
                (len & 0xff) as u8,
            ]
        }
    }

    // ── Parse the CMS structure to find insertion point ──

    // ContentInfo SEQUENCE
    let (_, ci_hdr, _ci_len) = read_tl(cms_der, 0)
        .ok_or_else(|| Error::Other("Invalid CMS: cannot read ContentInfo".into()))?;

    // contentType OID
    let oid_end = skip_tlv(cms_der, ci_hdr)
        .ok_or_else(|| Error::Other("Invalid CMS: cannot skip contentType OID".into()))?;

    // content [0] EXPLICIT
    let (_, ctx0_hdr, _ctx0_len) = read_tl(cms_der, oid_end)
        .ok_or_else(|| Error::Other("Invalid CMS: cannot read [0] EXPLICIT".into()))?;
    let signed_data_start = oid_end + ctx0_hdr;

    // SignedData SEQUENCE
    let (_, sd_hdr, _sd_len) = read_tl(cms_der, signed_data_start)
        .ok_or_else(|| Error::Other("Invalid CMS: cannot read SignedData SEQUENCE".into()))?;
    let mut pos = signed_data_start + sd_hdr;

    // version INTEGER
    pos = skip_tlv(cms_der, pos)
        .ok_or_else(|| Error::Other("Invalid CMS: cannot skip version".into()))?;
    // digestAlgorithms SET
    pos = skip_tlv(cms_der, pos)
        .ok_or_else(|| Error::Other("Invalid CMS: cannot skip digestAlgorithms".into()))?;
    // encapContentInfo SEQUENCE
    pos = skip_tlv(cms_der, pos)
        .ok_or_else(|| Error::Other("Invalid CMS: cannot skip encapContentInfo".into()))?;

    // [0] certificates (OPTIONAL, IMPLICIT)
    if pos < cms_der.len() && (cms_der[pos] & 0xe0) == 0xa0 && (cms_der[pos] & 0x1f) == 0 {
        pos = skip_tlv(cms_der, pos)
            .ok_or_else(|| Error::Other("Invalid CMS: cannot skip certificates".into()))?;
    }

    // [1] crls (OPTIONAL, IMPLICIT) — rare but possible
    if pos < cms_der.len() && cms_der[pos] == 0xa1 {
        pos = skip_tlv(cms_der, pos)
            .ok_or_else(|| Error::Other("Invalid CMS: cannot skip crls".into()))?;
    }

    // signerInfos SET OF
    let (_, si_set_hdr, _si_set_len) = read_tl(cms_der, pos)
        .ok_or_else(|| Error::Other("Invalid CMS: cannot read signerInfos SET".into()))?;
    let si_start = pos + si_set_hdr;

    // First (and usually only) SignerInfo SEQUENCE
    let (_, si_hdr, si_len) = read_tl(cms_der, si_start)
        .ok_or_else(|| Error::Other("Invalid CMS: cannot read SignerInfo SEQUENCE".into()))?;
    let si_content_start = si_start + si_hdr;
    let si_content_end = si_content_start + si_len;

    // Walk through SignerInfo fields to find unsignedAttrs
    let mut si_pos = si_content_start;

    // version INTEGER
    si_pos = skip_tlv(cms_der, si_pos)
        .ok_or_else(|| Error::Other("Invalid SignerInfo: cannot skip version".into()))?;
    // sid (IssuerAndSerialNumber SEQUENCE or [0] SubjectKeyIdentifier)
    si_pos = skip_tlv(cms_der, si_pos)
        .ok_or_else(|| Error::Other("Invalid SignerInfo: cannot skip sid".into()))?;
    // digestAlgorithm AlgorithmIdentifier
    si_pos = skip_tlv(cms_der, si_pos)
        .ok_or_else(|| Error::Other("Invalid SignerInfo: cannot skip digestAlgorithm".into()))?;
    // [0] signedAttrs (OPTIONAL)
    if si_pos < si_content_end && cms_der[si_pos] == 0xa0 {
        si_pos = skip_tlv(cms_der, si_pos)
            .ok_or_else(|| Error::Other("Invalid SignerInfo: cannot skip signedAttrs".into()))?;
    }
    // signatureAlgorithm AlgorithmIdentifier
    si_pos = skip_tlv(cms_der, si_pos)
        .ok_or_else(|| Error::Other("Invalid SignerInfo: cannot skip signatureAlgorithm".into()))?;
    // signature OCTET STRING
    si_pos = skip_tlv(cms_der, si_pos)
        .ok_or_else(|| Error::Other("Invalid SignerInfo: cannot skip signature".into()))?;

    // Now si_pos is either at unsignedAttrs [1] or at si_content_end
    let has_unsigned_attrs = si_pos < si_content_end && cms_der[si_pos] == 0xa1;

    // ── Build the new CMS with injected unsigned attribute ──

    let new_unsigned_content: Vec<u8>;

    if has_unsigned_attrs {
        // Existing [1] unsignedAttrs — append our attribute
        let (_, ua_hdr, ua_len) = read_tl(cms_der, si_pos)
            .ok_or_else(|| Error::Other("Invalid CMS: cannot read unsignedAttrs".into()))?;
        let ua_content_start = si_pos + ua_hdr;
        let ua_content_end = ua_content_start + ua_len;

        // New content = existing content + new attribute
        let mut content = cms_der[ua_content_start..ua_content_end].to_vec();
        content.extend_from_slice(attr_der);
        new_unsigned_content = content;
    } else {
        // No unsignedAttrs yet — create new
        new_unsigned_content = attr_der.to_vec();
    }

    // Encode the new [1] IMPLICIT SET OF unsignedAttrs
    let new_ua_len_bytes = encode_length(new_unsigned_content.len());

    // Rebuild from the inside out, updating all outer lengths.
    // 1. Build new SignerInfo content: everything before unsignedAttrs + new unsignedAttrs
    let si_before_ua = &cms_der[si_content_start..si_pos];
    let new_ua_size = 1 + new_ua_len_bytes.len() + new_unsigned_content.len();
    let mut new_si_content = Vec::with_capacity(si_before_ua.len() + new_ua_size);
    new_si_content.extend_from_slice(si_before_ua);
    new_si_content.push(0xa1); // [1] IMPLICIT
    new_si_content.extend_from_slice(&new_ua_len_bytes);
    new_si_content.extend_from_slice(&new_unsigned_content);

    // 2. Wrap in SignerInfo SEQUENCE
    let si_seq_len = encode_length(new_si_content.len());
    let mut new_si = Vec::with_capacity(1 + si_seq_len.len() + new_si_content.len());
    new_si.push(0x30); // SEQUENCE
    new_si.extend_from_slice(&si_seq_len);
    new_si.extend_from_slice(&new_si_content);

    // 3. Wrap in signerInfos SET OF
    let si_set_content_len = encode_length(new_si.len());
    let mut new_si_set = Vec::with_capacity(1 + si_set_content_len.len() + new_si.len());
    new_si_set.push(0x31); // SET OF
    new_si_set.extend_from_slice(&si_set_content_len);
    new_si_set.extend_from_slice(&new_si);

    // 4. Build new SignedData content: everything before signerInfos + new signerInfos
    let sd_before_si = &cms_der[signed_data_start + sd_hdr..pos];
    let mut new_sd_content = Vec::with_capacity(sd_before_si.len() + new_si_set.len());
    new_sd_content.extend_from_slice(sd_before_si);
    new_sd_content.extend_from_slice(&new_si_set);

    // 5. Wrap in SignedData SEQUENCE
    let sd_seq_len = encode_length(new_sd_content.len());
    let mut new_sd = Vec::with_capacity(1 + sd_seq_len.len() + new_sd_content.len());
    new_sd.push(0x30); // SEQUENCE
    new_sd.extend_from_slice(&sd_seq_len);
    new_sd.extend_from_slice(&new_sd_content);

    // 6. Wrap in [0] EXPLICIT context
    let ctx0_len = encode_length(new_sd.len());
    let mut new_ctx0 = Vec::with_capacity(1 + ctx0_len.len() + new_sd.len());
    new_ctx0.push(0xa0); // [0] EXPLICIT
    new_ctx0.extend_from_slice(&ctx0_len);
    new_ctx0.extend_from_slice(&new_sd);

    // 7. Build ContentInfo: OID + new [0]
    let oid_bytes = &cms_der[ci_hdr..oid_end];
    let mut new_ci_content = Vec::with_capacity(oid_bytes.len() + new_ctx0.len());
    new_ci_content.extend_from_slice(oid_bytes);
    new_ci_content.extend_from_slice(&new_ctx0);

    // 8. Wrap in ContentInfo SEQUENCE
    let ci_seq_len = encode_length(new_ci_content.len());
    let mut result = Vec::with_capacity(1 + ci_seq_len.len() + new_ci_content.len());
    result.push(0x30); // SEQUENCE
    result.extend_from_slice(&ci_seq_len);
    result.extend_from_slice(&new_ci_content);

    Ok(result)
}

pub(crate) fn append_dss_dictionary(
    pdf_bytes: Vec<u8>,
    user_certificate_chain: Vec<CapturedX509Certificate>,
) -> Result<Vec<u8>, Error> {
    //let mut file = std::fs::File::create("./signed.pdf").unwrap();
    //file.write_all(&pdf_bytes).unwrap();

    let mut doc = IncrementalDocument::load_from(pdf_bytes.as_slice())?;
    doc.new_document.version = "1.5".parse().unwrap();

    let (crl_data, ocsp_data) = fetch_revocation_data(&user_certificate_chain, true, true);

    let mut crl_streams = Vec::new();
    for crl_datum in crl_data {
        let crl_stream = Stream::new(Dictionary::new(), crl_datum);
        crl_streams.push(crl_stream);
    }

    let mut ocsp_streams = Vec::new();
    for ocsp_datum in ocsp_data {
        let ocsp_stream = Stream::new(Dictionary::new(), ocsp_datum);
        ocsp_streams.push(ocsp_stream);
    }

    let mut cert_streams = Vec::new();
    for certificate in user_certificate_chain {
        let cert = certificate.encode_der().unwrap();
        let cert_stream = Stream::new(Dictionary::new(), cert);
        cert_streams.push(cert_stream);
    }

    let crl_refs: Vec<Object> = crl_streams
        .iter()
        .map(|s| Reference(doc.new_document.add_object(s.clone())))
        .collect();
    let ocsp_refs: Vec<Object> = ocsp_streams
        .iter()
        .map(|s| Reference(doc.new_document.add_object(s.clone())))
        .collect();
    let cert_refs: Vec<Object> = cert_streams
        .iter()
        .map(|s| Reference(doc.new_document.add_object(s.clone())))
        .collect();

    let dss_dict = Dictionary::from_iter(vec![
        ("CRLs", crl_refs.into()),
        ("OCSPs", ocsp_refs.into()),
        ("Certs", cert_refs.into()),
    ]);

    let dss_ref = doc.new_document.add_object(dss_dict);

    // Get root ID
    let catalog_id = doc
        .get_prev_documents()
        .trailer
        .get(b"Root")
        .unwrap()
        .as_reference()?;
    // Clone object
    doc.opt_clone_object_to_new_document(catalog_id)?;
    // Get Root in new document
    let catalog = doc
        .new_document
        .get_object_mut(catalog_id)
        .unwrap()
        .as_dict_mut()
        .unwrap();
    catalog.set("DSS", dss_ref);

    let mut buffer = Vec::new();
    doc.save_to(&mut buffer).unwrap();

    //let mut file = std::fs::File::create("./signed+ltv.pdf").unwrap();
    //file.write_all(&buffer).unwrap();

    return Ok(buffer);
}

/// Request an RFC 3161 timestamp token from a TSA server.
///
/// The `message_digest` should be the SHA-256 hash of the data to be
/// timestamped.  Returns the DER-encoded `TimeStampToken` (a CMS
/// `ContentInfo` containing the TSA's response).
pub(crate) fn fetch_timestamp_token(
    tsa_url: &str,
    message_digest: &[u8],
) -> Result<Vec<u8>, Error> {

    // Build a minimal RFC 3161 TimeStampReq using raw DER construction.
    //
    // TimeStampReq ::= SEQUENCE {
    //   version          INTEGER  { v1(1) },
    //   messageImprint   MessageImprint,
    //   certReq          BOOLEAN  DEFAULT FALSE
    // }
    //
    // MessageImprint ::= SEQUENCE {
    //   hashAlgorithm    AlgorithmIdentifier (SHA-256),
    //   hashedMessage    OCTET STRING
    // }

    // OID for SHA-256: 2.16.840.1.101.3.4.2.1
    let sha256_oid_der: Vec<u8> = vec![
        0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
    ];

    // AlgorithmIdentifier = SEQUENCE { OID, NULL }
    let mut alg_id = Vec::new();
    let mut alg_content = Vec::new();
    alg_content.extend_from_slice(&sha256_oid_der);
    alg_content.push(0x05); // NULL tag
    alg_content.push(0x00); // NULL length
    alg_id.push(0x30); // SEQUENCE
    der_push_length(&mut alg_id, alg_content.len());
    alg_id.extend_from_slice(&alg_content);

    // hashedMessage = OCTET STRING
    let mut hashed_msg = Vec::new();
    hashed_msg.push(0x04); // OCTET STRING
    der_push_length(&mut hashed_msg, message_digest.len());
    hashed_msg.extend_from_slice(message_digest);

    // MessageImprint = SEQUENCE { AlgorithmIdentifier, OCTET STRING }
    let mut msg_imprint = Vec::new();
    let mut msg_imprint_content = Vec::new();
    msg_imprint_content.extend_from_slice(&alg_id);
    msg_imprint_content.extend_from_slice(&hashed_msg);
    msg_imprint.push(0x30); // SEQUENCE
    der_push_length(&mut msg_imprint, msg_imprint_content.len());
    msg_imprint.extend_from_slice(&msg_imprint_content);

    // version = INTEGER 1
    let version_der: Vec<u8> = vec![0x02, 0x01, 0x01];

    // certReq = BOOLEAN TRUE
    let cert_req_der: Vec<u8> = vec![0x01, 0x01, 0xff];

    // TimeStampReq = SEQUENCE { version, messageImprint, certReq }
    let mut ts_req_content = Vec::new();
    ts_req_content.extend_from_slice(&version_der);
    ts_req_content.extend_from_slice(&msg_imprint);
    ts_req_content.extend_from_slice(&cert_req_der);

    let mut ts_req = Vec::new();
    ts_req.push(0x30); // SEQUENCE
    der_push_length(&mut ts_req, ts_req_content.len());
    ts_req.extend_from_slice(&ts_req_content);

    // Send to TSA
    let client = Client::new();
    let response = client
        .post(tsa_url)
        .header("Content-Type", "application/timestamp-query")
        .body(ts_req)
        .send()
        .map_err(|e| Error::Other(format!("TSA request failed: {}", e)))?;

    if !response.status().is_success() {
        return Err(Error::Other(format!(
            "TSA returned HTTP {}", response.status()
        )));
    }

    let ts_resp = response
        .bytes()
        .map_err(|e| Error::Other(format!("Failed to read TSA response: {}", e)))?;

    // Parse the TimeStampResp to extract the TimeStampToken.
    // TimeStampResp ::= SEQUENCE {
    //   status   PKIStatusInfo,
    //   timeStampToken  TimeStampToken OPTIONAL
    // }
    //
    // We do a minimal DER walk: skip the outer SEQUENCE, skip the
    // PKIStatusInfo SEQUENCE, and the remainder is the TimeStampToken
    // (a ContentInfo).

    let data = ts_resp.to_vec();
    if data.len() < 5 || data[0] != 0x30 {
        return Err(Error::Other("Invalid TSA response: not a SEQUENCE".into()));
    }

    let (outer_content_start, _outer_len) = der_read_length(&data, 1)
        .ok_or_else(|| Error::Other("Invalid TSA response: bad length".into()))?;

    // First element: PKIStatusInfo (SEQUENCE)
    let pos = outer_content_start;
    if pos >= data.len() || data[pos] != 0x30 {
        return Err(Error::Other("Invalid TSA response: missing PKIStatusInfo".into()));
    }
    let (status_content_start, status_len) = der_read_length(&data, pos + 1)
        .ok_or_else(|| Error::Other("Invalid TSA response: bad PKIStatusInfo length".into()))?;

    // Check status value (first element of PKIStatusInfo should be INTEGER 0 = granted)
    if status_content_start < data.len() && data[status_content_start] == 0x02 {
        let (val_start, val_len) = der_read_length(&data, status_content_start + 1)
            .ok_or_else(|| Error::Other("Invalid TSA status".into()))?;
        if val_len == 1 && val_start < data.len() && data[val_start] > 2 {
            return Err(Error::Other(format!(
                "TSA returned rejection status: {}", data[val_start]
            )));
        }
    }

    // Skip past PKIStatusInfo to get to TimeStampToken
    let token_start = status_content_start + status_len;
    if token_start >= data.len() {
        return Err(Error::Other("TSA response contains no TimeStampToken".into()));
    }

    Ok(data[token_start..].to_vec())
}

/// Push a DER length encoding.
fn der_push_length(buf: &mut Vec<u8>, len: usize) {
    if len < 0x80 {
        buf.push(len as u8);
    } else if len <= 0xff {
        buf.push(0x81);
        buf.push(len as u8);
    } else if len <= 0xffff {
        buf.push(0x82);
        buf.push((len >> 8) as u8);
        buf.push(len as u8);
    } else {
        buf.push(0x83);
        buf.push((len >> 16) as u8);
        buf.push((len >> 8) as u8);
        buf.push(len as u8);
    }
}

/// Read a DER length at `offset`.  Returns `(content_start, length)`.
fn der_read_length(data: &[u8], offset: usize) -> Option<(usize, usize)> {
    if offset >= data.len() { return None; }
    let first = data[offset] as usize;
    if first < 0x80 {
        Some((offset + 1, first))
    } else if first == 0x81 {
        if offset + 1 >= data.len() { return None; }
        Some((offset + 2, data[offset + 1] as usize))
    } else if first == 0x82 {
        if offset + 2 >= data.len() { return None; }
        let len = ((data[offset + 1] as usize) << 8) | (data[offset + 2] as usize);
        Some((offset + 3, len))
    } else if first == 0x83 {
        if offset + 3 >= data.len() { return None; }
        let len = ((data[offset + 1] as usize) << 16)
            | ((data[offset + 2] as usize) << 8)
            | (data[offset + 3] as usize);
        Some((offset + 4, len))
    } else {
        None
    }
}

