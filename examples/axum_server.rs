// In Google Cloud console
// Set
// - Redirect_url: http://localhost/auth/callback
// - Host: http://localhost
// And then you will get client_secret.json file from google.
// Set .env file
// ```.env
// auth_endpoint="your_auth_endpoint"
// client_id="your_client_id"
// client_secret="your_client_secret"
// token_endpoint="your_token_endpoint"
// redirect_uri="http://localhost/auth/callback"
// ```
// finally ```cargo run --example axum_server```
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use anyhow::Context;
use axum::{
    Json, Router,
    extract::{Request, State},
    response::{IntoResponse, Redirect},
    routing::{get, post},
};
use axum_extra::extract::{CookieJar, cookie::Cookie};
use http::{StatusCode, header::HOST};
use serde::Deserialize;
use tiny_google_oidc::{
    code::{AdditionalScope, CodeRequest, UnCheckedCodeResponse},
    config::{Config, ConfigBuilder},
    csrf_token::CSRFToken,
    executer::{Executer, IDTokenExe, RefreshTokenExe, RevokeTokenExe},
    id_token::{IDToken, IDTokenRequest},
    nonce::Nonce,
    refresh_token::{RefreshToken, RefreshTokenRequest},
    revoke_token::{RevokeToken, RevokeTokenRequest},
};
use tracing::error;
use uuid::Uuid;

extern crate tiny_google_oidc;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Log settings
    tracing_subscriber::fmt::init();

    // Read environment
    let auth_endpoint = read_env("auth_endpoint")?;
    let client_id = read_env("client_id")?;
    let client_secret = read_env("client_secret")?;
    let token_endpoint = read_env("token_endpoint")?;
    let redirect_uri = read_env("redirect_uri")?;

    // Build Config
    let config = ConfigBuilder::new()
        .auth_endpoint(&auth_endpoint)
        .client_id(&client_id)
        .client_secret(&client_secret)
        .token_endpoint(&token_endpoint)
        .redirect_uri(&redirect_uri)
        .build();

    // application state that hold Config
    let app_state = AppState::new(config);
    // Binding listener
    let listener = tokio::net::TcpListener::bind("0.0.0.0:80").await.unwrap();
    // Settings Router
    // '/auth/callback': A path that is set in google console
    // '/': A path to start auth(Show login as google window)
    let app = Router::new()
        .route("/auth/callback", get(call_back))
        .route("/", get(start_auth))
        .route("/revoke", post(revoke_token))
        .route("/refresh", post(refresh_token))
        .with_state(Arc::new(app_state));

    axum::serve(listener, app).await.unwrap();
    anyhow::Ok(())
}

static COOKIE_KEY: &str = "csrf_token";

async fn start_auth(
    State(app_state): State<Arc<AppState>>,
    jar: CookieJar,
) -> Result<impl IntoResponse, StatusCode> {
    // Generate CSRF Token for each request
    let state = CSRFToken::new().map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Create Cookie that hold session of csrf_token
    // Cookie_Key -- CSRF_Token_Key
    //               CSRF_Token_Key -- CSRF_Token_Value(in memory or redis)
    let csrf_key = Uuid::new_v4().to_string();
    let cookie = Cookie::new(COOKIE_KEY, csrf_key.clone());
    // Insert CSRFToken into Memory(Redis)
    {
        app_state
            .token
            .lock()
            .unwrap()
            .insert(csrf_key, state.clone());
    }
    // Generate Nonce
    let nonce = Nonce::new();
    let scope = Some([AdditionalScope::Email, AdditionalScope::Profile].into_iter());

    // Construct CodeRequest from config, scope, csrf_token, nonce
    let req = CodeRequest::new(true, &app_state.config, scope, &state, &nonce);
    // Convert as URL
    let url = req
        .into_url()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok((jar.add(cookie), Redirect::to(&url)))
}

async fn call_back(
    State(app_state): State<Arc<AppState>>,
    jar: CookieJar,
    req: Request,
) -> Result<impl IntoResponse, StatusCode> {
    // UnCheckCodeResponse::from_url method is needed full url
    // https://localhost/...
    // So, Get HOST from Header and path
    let host = req
        .headers()
        .get(HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("localhost");
    let path = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/");
    let scheme = "http";
    let full_url = format!("{}://{}{}", scheme, host, path);

    // Construct UnCheckedCodeResponse
    let code_res = UnCheckedCodeResponse::from_url(&full_url.as_str()).map_err(|e| {
        error!("Failed to parse url: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    // Get CSRF token that insert previously
    let csrf_token: CSRFToken;
    // Get cookie
    let cookie = jar.get(COOKIE_KEY).ok_or_else(|| StatusCode::BAD_REQUEST)?;
    let csrf_key = cookie.value();
    {
        // This block for early unlock
        let lock = app_state.token.lock().unwrap();
        csrf_token = lock
            .get(csrf_key)
            .ok_or_else(|| StatusCode::BAD_REQUEST)?
            .to_owned();
    }
    // Get Code after verify CSRF token
    let code = code_res
        .exchange_with_code(csrf_token.clone())
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Construct IDTokenRequest by using Code
    let id_token_req = IDTokenRequest::new(&app_state.config, code);

    // Fetch to google for get IDToken
    let res = IDTokenExe
        .execute(&id_token_req)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    println!("{:#?}", res);
    let refresh_token = res.access_token();
    println!("{:?}", refresh_token);
    // Get IDToken that Base64URL encoded
    let id_token_row = res.id_token();
    // Decode and Get IDToken that deserialized
    let id_token = IDToken::decode_from_row(&id_token_row).unwrap();
    Ok((StatusCode::OK, Json(id_token)))
}

async fn revoke_token(Json(refresh_token): Json<Token>) -> Result<impl IntoResponse, StatusCode> {
    let token = RevokeToken::new_access_token(&refresh_token.token);
    let req = RevokeTokenRequest::new(&token);
    let res = RevokeTokenExe
        .execute(&req)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(res)
}

// Refresh token handler
async fn refresh_token(
    State(app_state): State<Arc<AppState>>,
    Json(refresh_token): Json<Token>,
) -> Result<impl IntoResponse, StatusCode> {
    // get refresh_token from json
    // this is test
    // Recommend get refresh_token from secure database in production code
    let refresh_token = RefreshToken::new(&refresh_token.token);
    let req = RefreshTokenRequest::new(&app_state.config, &refresh_token);
    let res = RefreshTokenExe
        .execute(&req)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok((StatusCode::OK, Json(res)))
}

// Get env from .env file
fn read_env(key: &str) -> anyhow::Result<String> {
    dotenvy::var(key).context("Failed to read env")
}

#[derive(Debug, Clone)]
struct AppState {
    config: Config,
    token: Arc<Mutex<HashMap<String, CSRFToken>>>,
}

impl AppState {
    fn new(config: Config) -> Self {
        Self {
            config,
            token: Arc::default(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
struct Token {
    token: String,
}
