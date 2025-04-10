// This example is implementation of login and session
// by using hyper
//
// # Run
// ## Oauth settings in cloud console 
// At first, you should set up Oauth settings in Google cloud console
// Inside setting page, set parameter like this
// - Origin JavascriptURL: http://localhost
// - RedirectURL: http://localhost/auth/callback
// 
// ## Run Redis
// Run redis container
// In ./examples/hyper directory,
// ```docker compose up```
//
// ## Run application 
// ```cargo run --example hyper```
// ## Access
// You can access http://localhost/
use std::{
    net::{Ipv4Addr, SocketAddrV4}, sync::Arc, time::Duration
};

use hyper::server::conn::http1;
use hyper_util::rt::TokioIo;
use redis::aio::ConnectionManager;
use router::Router;
use tiny_google_oidc::config::ConfigBuilder;
use tracing::{error, info};

mod protected;
mod router;
mod login_service;

static REDIS_URL: &str = "redis://localhost:6379";
static PORT: u16 = 80;
// Google OpenID Connect
// Change me according to client_secret.json that is downloaded
// auth_endpoint
static AUTH_ENDPOINT: &str = "https://accounts.google.com/o/oauth2/auth";
// client_id
// must change
static CLIENT_ID: &str = "your_client_id";
// client_secret
// must change
static CLIENT_SECRET: &str = "your_client_secret";
// redirect_url
static REDIRECT_URL: &str = "http://localhost/auth/callback";
// token endpoint
static TOKEN_ENDPOINT: &str = "https://oauth2.googleapis.com/token";

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // init log
    tracing_subscriber::fmt::init();

    // Redis connection set up
    let redis_client = redis::Client::open(REDIS_URL).expect("Failed to open redis client");
    let redis_conn = ConnectionManager::new(redis_client)
        .await
        .expect("Failed to establish redis connection");

    let addr = SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), PORT);
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .expect("Failed to bind tcp listener");

    info!("Server is running");

    // Construct Config That is warped by Arc
    let config = Arc::new(ConfigBuilder::new()
        .auth_endpoint(AUTH_ENDPOINT)
        .client_id(CLIENT_ID)
        .client_secret(CLIENT_SECRET)
        .redirect_uri(REDIRECT_URL)
        .token_endpoint(TOKEN_ENDPOINT)
        .build());

    // Routing services
    // login, rootPage, protectedPage(session)...
    let service = Router::new(config.clone(), redis_conn);

    info!("Listening on {:?}", addr);

    loop {
        let (stream, _) = listener.accept().await?;
        let io = TokioIo::new(stream);

        let service = service.clone();
        tokio::task::spawn(async move {
            let conn = http1::Builder::new().serve_connection(io, service);
            tokio::pin!(conn);

            // If it takes more than 5 seconds, it times out
            tokio::select! {
                res = conn.as_mut() => match res {
                    Ok(()) => {},
                    Err(e) => error!("error: {:?}", e),
                },
                _ = tokio::time::sleep(Duration::from_secs(5)) => {
                    conn.graceful_shutdown();
                }
            }
        });
    }
}
