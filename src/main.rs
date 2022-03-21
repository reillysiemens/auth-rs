use azure_identity::device_code_flow::{self, DeviceCodeResponse, DeviceCodeErrorResponse};
use clap::Parser;
use futures::StreamExt;
use oauth2::ClientId;

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

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let Args{ tenant, client, scopes } = Args::parse();

    let reqwest_client = reqwest::Client::new();
    let client_id = ClientId::new(client);
    let scopes: Vec<&str> = scopes.iter().map(String::as_str).collect();

    let phase_one = device_code_flow::start(&reqwest_client, tenant, &client_id, scopes.as_slice()).await?;

    println!("{}", phase_one.message());

    let mut responses = Box::pin(phase_one.stream());
    while let Some(response) = responses.next().await {
        let response = response?;
        match response {
            DeviceCodeResponse::AuthorizationSucceeded(success) => {
                let token = success.access_token();

                println!("SUCCESS!");
                println!("{token:?}");

                break;
            },
            DeviceCodeResponse::AuthorizationPending(pending) => {
                let DeviceCodeErrorResponse { error, error_description, error_uri } = pending;

                println!("PENDING...");
                println!("{error}");
                println!("{error_description}");
                println!("{error_uri}");

                continue;
            }
        }
    }

    Ok(())
}