use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};

// RSA components taken from https://login.microsoftonline.com/common/discovery/v2.0/keys.
//
// Note: It's possible that different tokens could be signed with different keys and that rather than definining this
// one as a constant we should always fetch the latest ones from login.microsoftonline.com.
//
// See https://github.com/Keats/jsonwebtoken#decoding and
// https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration for more info.
pub const MODULUS: &str = "spvQcXWqYrMcvcqQmfSMYnbUC8U03YctnXyLIBe148OzhBrgdAOmPfMfJi_tUW8L9svVGpk5qG6dN0n669cRHKqU52GnG0tlyYXmzFC1hzHVgQz9ehve4tlJ7uw936XIUOAOxx3X20zdpx7gm4zHx4j2ZBlXskAj6U3adpHQNuwUE6kmngJWR-deWlEigMpRsvUVQ2O5h0-RSq8Wr_x7ud3K6GTtrzARamz9uk2IXatKYdnj5Jrk2jLY6nWt-GtxlA_l9XwIrOl6Sqa_pOGIpS01JKdxKvpBC9VdS8oXB-7P5qLksmv7tq-SbbiOec0cvU7WP7vURv104V4FiI_qoQ";
pub const EXPONENT: &str = "AQAB";

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    aud: String,
    iss: String,
    iat: u64,
    nbf: u64,
    exp: u64,
    acr: String,
    aio: String,
    amr: Vec<String>,
    appid: String,
    appidacr: String,
    family_name: String,
    given_name: String,
    ipaddr: String,
    name: String,
    oid: String,
    onprem_sid: String,
    // puid: String, -- Not sure what this field is for. It isn't in all tokens.
    rh: String,
    scp: String,
    sub: String,
    tid: String,
    unique_name: String,
    upn: String,
    uti: String,
    ver: String,
    // wids: Vec<String>, -- Not sure what this field is for. It isn't in all tokens.
}

pub fn name(token: String) -> anyhow::Result<String> {
    let decoding_key = DecodingKey::from_rsa_components(MODULUS, EXPONENT)?;
    let validation = &Validation::new(Algorithm::RS256);
    let data = decode::<Claims>(&token, &decoding_key, &validation)?;
    let upn = data.claims.upn;
    let name = data.claims.name;

    Ok(format!("{upn} ({name})"))
}
