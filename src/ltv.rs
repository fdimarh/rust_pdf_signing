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
            serial_number: BigInt::from_bytes_le(Sign::Plus, cert.raw_serial()),
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
