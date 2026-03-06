use crate::rectangle::Rectangle;

#[derive(Clone, Debug, PartialEq)]
pub enum SignatureFormat {
    PKCS7,
    PADES,
}

/// PAdES baseline conformance level per ETSI EN 319 142 / TS 103 172.
///
/// Each level builds on the previous one:
///
/// | Level | Description                          | Requires                             |
/// |-------|--------------------------------------|--------------------------------------|
/// | B-B   | Basic — minimum viable PAdES         | ESS-signing-certificate-v2           |
/// | B-T   | Timestamp — proves existence at time | B-B + signature timestamp (TSA)      |
/// | B-LT  | Long-Term — offline validation       | B-T + DSS dict (CRL/OCSP/Certs)      |
/// | B-LTA | Long-Term Archival                   | B-LT + document timestamp            |
#[derive(Clone, Debug, PartialEq)]
#[allow(non_camel_case_types)]
pub enum PadesLevel {
    /// PAdES-B-B: Basic level.  ESS-signing-certificate-v2 is included but
    /// no timestamp, no DSS dictionary.  Suitable when an external timestamp
    /// or validation infrastructure is available.
    B_B,
    /// PAdES-B-T: Timestamp level.  Adds a signature timestamp token from a
    /// TSA to the CMS unsigned attributes.  Proves the signature existed at
    /// the timestamp time.
    B_T,
    /// PAdES-B-LT: Long-Term level.  Adds a DSS (Document Security Store)
    /// dictionary with CRL/OCSP responses and certificates so that the
    /// signature can be validated offline long after the signing certificates
    /// expire.
    B_LT,
    /// PAdES-B-LTA: Long-Term Archival level.  Adds a document-level
    /// timestamp on top of B-LT to protect the DSS data itself against
    /// future algorithm compromise.
    B_LTA,
}

impl std::fmt::Display for PadesLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PadesLevel::B_B => write!(f, "B-B"),
            PadesLevel::B_T => write!(f, "B-T"),
            PadesLevel::B_LT => write!(f, "B-LT"),
            PadesLevel::B_LTA => write!(f, "B-LTA"),
        }
    }
}

#[derive(Clone)]
pub struct SignatureOptions {
    pub format: SignatureFormat,
    pub signature_size: usize,
    pub timestamp_url: Option<String>,

    pub include_dss: bool,

    // Pkcs7-specific
    pub signed_attribute_include_crl: bool,
    pub signed_attribute_include_ocsp: bool,

    /// 1-based page number on which the visible signature image should be placed.
    /// `None` means the signature widget is placed on the first page (default).
    pub signature_page: Option<u32>,

    /// Rectangle that defines the position and size of the visible signature
    /// image on the selected page.  `None` means a sensible default is used.
    pub signature_rect: Option<Rectangle>,

    /// When `true` (the default) the signer's image is rendered as a visible
    /// annotation on the page.  Set to `false` to create an invisible
    /// (cryptography-only) digital signature with no visual appearance.
    pub visible_signature: bool,

    /// PAdES conformance level.  Only used when `format` is `PADES`.
    /// Defaults to `B_T` (timestamp level).
    ///
    /// - `B_B`:  no timestamp, no DSS
    /// - `B_T`:  adds signature timestamp
    /// - `B_LT`: adds DSS dictionary (CRL/OCSP/Certs) after signing
    /// - `B_LTA`: adds DSS + document timestamp
    pub pades_level: PadesLevel,
}

impl Default for SignatureOptions {
    fn default() -> SignatureOptions {
        SignatureOptions {
            format: SignatureFormat::PKCS7,
            timestamp_url: Some("http://timestamp.digicert.com".parse().unwrap()),
            signature_size: 30_000,

            include_dss: false,

            signed_attribute_include_crl: true,
            signed_attribute_include_ocsp: false,

            signature_page: None,
            signature_rect: None,
            visible_signature: true,
            pades_level: PadesLevel::B_T,
        }
    }
}
