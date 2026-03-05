use crate::rectangle::Rectangle;

#[derive(Clone)]
pub enum SignatureFormat {
    PKCS7,
    PADES,
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
        }
    }
}
