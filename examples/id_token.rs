//! example of getting IDToken and print it.  
//!
//! # Setup
//! 1. Create OAuth2.0 Client at google-cloud-console's credentials page
//! 2. Get your AUTH_ENDPOINT, CLIENT_ID, CLIENT_SECRET, TOKEN_ENDPOINT, REDIRECT_URI
//! 3. Set step 2's value as a static value down below
//! 4. Run with the following
//! ```not_rust
//! cargo run --example id_token
//! ```
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use axum::{
    Router,
    extract::{Request, State},
    response::{IntoResponse, Redirect, Response},
    routing::get,
};
use axum_extra::extract::CookieJar;
use cookie::{
    Cookie,
    time::{Duration, OffsetDateTime},
};
use http::StatusCode;
use tiny_google_oidc::{
    code::{AccessType, AdditionalScope, Code, CodeRequest, RawCodeResponse},
    config::ConfigBuilder,
    csrf_token::CSRFToken,
    id_token::{IDToken, IDTokenRequest, send_id_token_req},
    nonce::Nonce,
};
use uuid::Uuid;

// Fix this value CLIENT_ID, CLIENT_SECRET, REDIRECT_URI
static AUTH_ENDPOINT: &str = "https://accounts.google.com/o/oauth2/auth";
static CLIENT_ID: &str = "my_client_id";
static CLIENT_SECRET: &str = "my_client_secret";
static TOKEN_ENDPOINT: &str = "https://oauth2.googleapis.com/token";
static REDIRECT_URI: &str = "http://localhost/auth/callback";

static COOKIE_KEY: &str = "token";

#[tokio::main]
async fn main() {
    // Construct Config by using your CLIENT_ID, SECRETS, etc...
    let oidc_cfg = ConfigBuilder::new()
        .auth_endpoint(AUTH_ENDPOINT)
        .client_id(CLIENT_ID)
        .client_secret(CLIENT_SECRET)
        .token_endpoint(TOKEN_ENDPOINT)
        .redirect_uri(REDIRECT_URI)
        .build();

    // Fix port number you set at google cloud console
    let listener = tokio::net::TcpListener::bind("0.0.0.0:80").await.unwrap();

    let app_state = Arc::new(AppState::new(oidc_cfg));

    let app = Router::new()
        .route("/", get(login))
        // If callback URI that you set is different, please fix
        .route("/auth/callback", get(callback))
        .with_state(app_state);

    axum::serve(listener, app).await.unwrap();
}

#[derive(Debug)]
struct AppState {
    state: Mutex<HashMap<String, String>>,
    oidc_cfg: Arc<tiny_google_oidc::config::Config>,
}

impl AppState {
    fn new(oidc_cfg: tiny_google_oidc::config::Config) -> Self {
        AppState {
            state: Mutex::default(),
            oidc_cfg: Arc::new(oidc_cfg),
        }
    }

    fn insert(&self, store_key: &str, csrf_token: &str) {
        let mut guard = self.state.lock().unwrap();
        guard.insert(store_key.to_string(), csrf_token.to_string());
    }

    fn get(&self, store_key: &str) -> Option<String> {
        let guard = self.state.lock().unwrap();
        guard.get(store_key).map(|v| v.to_string())
    }
}

async fn login(
    State(app_state): State<Arc<AppState>>,
    jar: CookieJar,
) -> Result<impl IntoResponse, AppError> {
    let csrf_token_store_key = Uuid::new_v4();
    let csrf_token = CSRFToken::new().map_err(WrapOIDCError)?;

    // Insert CSRFToken in memory.
    // Using redis is better than this implementation when production code
    app_state.insert(&csrf_token_store_key.to_string(), csrf_token.value());

    let nonce = Nonce::new();
    // Create CodeRequest to get redirect uri to google's page
    let code_req = CodeRequest::new(
        AccessType::Online,
        &app_state.oidc_cfg,
        AdditionalScope::Both,
        &csrf_token,
        &nonce,
    );

    // Create redirect uri as String to pass `axum::response::Redirect::to`
    let redirect_url = code_req.try_into_url().map_err(WrapOIDCError)?.to_string();

    // Create cookie that is holding a key which indicate csrf_token_value
    let mut cookie = Cookie::new(COOKIE_KEY, csrf_token_store_key.to_string());

    cookie.set_http_only(true);

    let mut now = OffsetDateTime::now_utc();
    now += Duration::minutes(5);
    cookie.set_expires(now);

    // Set-Cookie ant Redirect as a response
    Ok((jar.add(cookie), Redirect::to(&redirect_url)))
}

async fn callback(
    State(app_state): State<Arc<AppState>>,
    jar: CookieJar,
    req: Request,
) -> Result<impl IntoResponse, AppError> {
    // get cookie
    let cookie = jar.get(COOKIE_KEY).ok_or(AppError::CookieNotFound)?;

    // get csrf_token_key from cookie
    let csrf_token_key = cookie.value_trimmed();
    // fetch csrf_token_val by using key that you got from cookie
    let csrf_token_val = app_state
        .get(csrf_token_key)
        .ok_or(AppError::GenURL)?
        .to_owned();

    // Create RawCodeResponse that hold Response from google
    // In this case, We should only pass `http::Request `
    let code_res = RawCodeResponse::new(req).map_err(WrapOIDCError)?;

    // Verify csrf_token and get Code
    let code = Code::new_with_verify_csrf(code_res, &csrf_token_val).map_err(WrapOIDCError)?;

    // Create IDTokenRequest for getting IDToken
    let id_token_req = IDTokenRequest::new(&app_state.oidc_cfg, code);

    // Send request to google
    // This is effect
    let id_token_res = send_id_token_req(&id_token_req)
        .await
        .map_err(WrapOIDCError)?;

    // print IDTokenResponse
    // It has some value, such as refresh_token, access_token, etc...
    println!("----IDTokenResponse----");
    println!("{id_token_res:#?}");

    // encode IDToken from raw string
    let id_token = IDToken::from_id_token_raw(id_token_res.id_token()).map_err(WrapOIDCError)?;

    // print id_token
    println!("----IDToken----");
    println!("{id_token:#?}");

    Ok((StatusCode::OK, "login success"))
}

#[derive(Debug, Clone)]
enum AppError {
    CookieNotFound,
    GenURL,
    CSRFNotMatch(String),
    SendStatus((StatusCode, String)),
    Others(tiny_google_oidc::error::Error),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        match self {
            AppError::CookieNotFound => {
                { (StatusCode::BAD_REQUEST, "cookie not found to auth").into_response() }
                    .into_response()
            }
            AppError::GenURL => {
                (StatusCode::INTERNAL_SERVER_ERROR, "failed to generate url").into_response()
            }
            AppError::Others(e) => {
                (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response()
            }
            AppError::CSRFNotMatch(e) => (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
            AppError::SendStatus((status, msg)) => (status, msg).into_response(),
        }
    }
}

#[derive(Debug, Clone)]
struct WrapOIDCError(tiny_google_oidc::error::Error);

use tiny_google_oidc::error::Error;
impl From<WrapOIDCError> for AppError {
    fn from(value: WrapOIDCError) -> Self {
        match value.0 {
            Error::CSRFNotMatch => AppError::CSRFNotMatch(value.0.to_string()),
            Error::SendStatus(status) => AppError::SendStatus((status, value.0.to_string())),
            _ => AppError::Others(value.0),
        }
    }
}
