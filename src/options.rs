use serde::{Deserialize, Serialize};

/// Basic signing configuration structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignOptions {
    /// Password if the input PDF is already encrypted
    pub input_password: Option<String>,
    
    /// Optional User Password to set on the resulting signed PDF
    pub apply_new_user_password: Option<String>,

    /// Reason for signing
    pub reason: String,
    
    /// Location of the signing event
    pub location: String,
    
    /// Contact info of the signer
    pub contact_info: String,
    
    /// The name of the signature field (default: "Signature1")
    pub signature_name: String,
    
    /// Apply LTV (Long Term Validation) using embedded OCSP/CRL
    pub apply_ltv: bool,
}

impl Default for SignOptions {
    fn default() -> Self {
        Self {
            input_password: None,
            apply_new_user_password: None,
            reason: String::new(),
            location: String::new(),
            contact_info: String::new(),
            signature_name: "Signature1".to_string(),
            apply_ltv: false,
        }
    }
}