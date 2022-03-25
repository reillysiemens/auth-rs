use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// Note: These structures are currently unused, but they could be used to replicate the MSAL cache format.

#[derive(Debug, Serialize, Deserialize)]
pub struct AccessToken {
    pub home_account_id: String,
    pub environment: String,
    pub client_info: String,
    pub client_id: String,
    pub secret: String,
    pub credential_type: String,
    pub realm: String,
    pub target: String,
    pub cached_at: String,
    pub expires_on: String,
    pub extended_expires_on: String,
    pub ext_expires_on: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RefreshToken {
    home_account_id: String,
    environment: String,
    client_info: String,
    client_id: String,
    secret: String,
    credential_type: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct MsalCache {
    pub access_token: HashMap<String, AccessToken>,
}
