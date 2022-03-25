mod cache;
mod jwt;

use azure_identity::device_code_flow::{self, DeviceCodeAuthorization, DeviceCodeResponse};
use clap::Parser;
use console::style;
use futures::StreamExt;
use oauth2::ClientId;
use thiserror::Error;

#[derive(Debug, Parser)]
#[clap(version)]
struct Args {
    #[clap(long, required = true, help = "An Azure tenant ID")]
    tenant: String,
    #[clap(long, required = true, help = "An Azure client ID")]
    client: String,
    #[clap(long = "scope", required = true, help = "Azure scopes")]
    scopes: Vec<String>,
}

#[derive(Debug, Error)]
enum DeviceCodeError {
    #[error("Error starting device code flow phase one")]
    PhaseOneError(#[from] device_code_flow::DeviceCodeError),
    #[error("Device flow stream terminated early")]
    EarlyTermination,
}

async fn device_code_flow(
    http_client: &reqwest::Client,
    client: &ClientId,
    tenant: &String,
    scopes: Vec<&str>,
) -> Result<DeviceCodeAuthorization, DeviceCodeError> {
    let phase_one = device_code_flow::start(http_client, tenant, client, scopes.as_slice()).await?;

    println!("{}", phase_one.message());

    let mut responses = Box::pin(phase_one.stream());

    while let Some(response) = responses.next().await {
        let response = response?;

        if let DeviceCodeResponse::AuthorizationSucceeded(authorization_code) = response {
            return Ok(authorization_code);
        }
    }

    Err(DeviceCodeError::EarlyTermination)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    let http_client = reqwest::Client::new();
    let client = ClientId::new(args.client);
    let scopes: Vec<&str> = args.scopes.iter().map(String::as_str).collect();

    let cache = cache::EncryptedCache::new("example.cache");

    let token = match cache.get().await {
        Ok(data) => data,
        Err(_) => {
            let auth_code = device_code_flow(&http_client, &client, &args.tenant, scopes).await?;
            let access_token = auth_code.access_token().secret();
            cache.put(access_token.as_str()).await?;
            access_token.clone()
        }
    };

    // Note: This can fail if the token signature has expired. This would be an excellent place to attempt a silent
    // exchange of a refresh token for a new access token.
    let name = jwt::name(token)?;
    println!("{}", style(format!("Token cache warm for {name}")).green());

    Ok(())
}
