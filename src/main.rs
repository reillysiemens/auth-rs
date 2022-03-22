use azure_identity::device_code_flow::{
    self, DeviceCodeAuthorization, DeviceCodeErrorResponse, DeviceCodeResponse,
};
use clap::Parser;
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
    let Args {
        tenant,
        client,
        scopes,
    } = Args::parse();

    let http_client = reqwest::Client::new();
    let client = ClientId::new(client);
    let scopes: Vec<&str> = scopes.iter().map(String::as_str).collect();

    // Check for valid token in cache

    // nothing in cache - do auth
    let auth_code = device_code_flow(&http_client, &client, &tenant, scopes).await?;
    // write to cache

    println!("Access Token: {:?}", auth_code.access_token());
    println!("Good for about: {:?} minutes", auth_code.expires_in / 60);

    Ok(())
}
