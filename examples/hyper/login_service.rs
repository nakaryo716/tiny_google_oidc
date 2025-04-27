use std::sync::Arc;

use bytes::Bytes;
use cookie::{Cookie, CookieBuilder, SameSite};
use http::{
    header::{COOKIE, HOST, LOCATION, SET_COOKIE}, HeaderValue, Request, Response, StatusCode
};
use http_body_util::{BodyExt, Empty, combinators::BoxBody};
use hyper::body::Incoming;
use redis::{aio::ConnectionManager, cmd};
use tiny_google_oidc::{
    code::{AdditionalScope, CodeRequest, UnCheckedCodeResponse},
    config::Config,
    csrf_token::CSRFToken,
    executer::{Executer, IDTokenExe},
    id_token::{IDToken, IDTokenRequest},
    nonce::Nonce,
};
use uuid::Uuid;

use crate::protected::see_location_res;

static CSRF_COOKIE_KEY: &str = "csrf_key";
pub static SESSION_COOKIE_KEY: &str = "session";

#[derive(Clone)]
pub struct LoginService {
    config: Arc<Config>,
    redis_conn: ConnectionManager,
}

impl LoginService {
    pub fn new(config: Arc<Config>, redis_conn: ConnectionManager) -> Self {
        Self { config, redis_conn }
    }

    // A service that starts login when the login button is pressed on Google
    pub async fn entry(&mut self) -> anyhow::Result<Response<BoxBody<Bytes, std::io::Error>>> {
        // gen CSRFToken
        let csrf_token = CSRFToken::new()?;
        // Create a KEY to store the CSRFToken
        let csrf_key = Uuid::new_v4().to_string();
        // Create Cookie
        let cookie = CookieBuilder::new(CSRF_COOKIE_KEY, csrf_key.clone())
            .same_site(SameSite::Lax)
            .http_only(true)
            .build();

        // Specify the OpenId Connect scope
        // Specify that the email and username should be included in the ID token
        let scope = Some([AdditionalScope::Email, AdditionalScope::Profile].into_iter());

        // Store CSRF token in Redis
        let _ = cmd("SET")
            .arg(&csrf_key)
            .arg(csrf_token.value())
            .query_async::<String>(&mut self.redis_conn)
            .await?;

        // Generate CodeRequest and make it into URL
        let url =
            CodeRequest::new(false, &self.config, scope, &csrf_token, &Nonce::new()).into_url()?;

        let res = Response::builder()
            .status(StatusCode::SEE_OTHER)
            .header(LOCATION, url)
            .header(SET_COOKIE, cookie.to_string())
            .body(Empty::new().map_err(|e| match e {}).boxed())
            .unwrap();
        Ok(res)
    }

    pub async fn callback(
        &mut self,
        req: Request<Incoming>,
    ) -> anyhow::Result<Response<BoxBody<Bytes, std::io::Error>>> {
        let cookie_header_val = match req.headers().get(COOKIE) {
            Some(v) => v,
            None => return Ok(see_location_res("/")),
        };
        let cookies = Self::parse_cookies(&cookie_header_val)?;

        // Get the CSRFToken key stored in Redis from the cookie
        let csrf_key = match cookies.iter().find(|c| c.name() == CSRF_COOKIE_KEY) {
            Some(cookie) => cookie.value(),
            None => return Ok(see_location_res("/")),
        };
        // Get CSRFToken from Redis
        let csrf_token = cmd("GET")
            .arg(&csrf_key)
            .query_async::<String>(&mut self.redis_conn)
            .await?;

        // Create Full path URL
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
        let url = format!("{}://{}{}", scheme, host, path);

        // Create UncheckedCodeResponse from url
        let code_res = UnCheckedCodeResponse::from_url(&url)?;
        // Consume the response and get the code
        // Verify that the CSRFToken matches (Error if they do not match)
        let code = code_res.exchange_with_code(&csrf_token)?;

        // Send an HTTP Request to Google to get an IDToken
        // Use the code (CSRFToken has been verified by exchange_with_code)
        let id_token_res = IDTokenExe
            .execute(&IDTokenRequest::new(&self.config, code))
            .await?;

        // It is also possible to obtain an AccessToken or RefreshToken.
        // This needs to be stored in a secure database.
        let _access_token = id_token_res.access_token();
        let _refresh_token = id_token_res.refresh_token();

        // Get IDToken(Decode)
        let id_token = IDToken::decode_from_row(id_token_res.id_token())?;

        // Create SessionID
        let session_id = Uuid::new_v4().to_string();

        // Save the SessionID and the sub of the IDToken structure (which is the identifier) ​​as the value in Redis.
        let _ = cmd("SET")
            .arg(&session_id)
            .arg(&id_token.sub)
            .query_async::<String>(&mut self.redis_conn)
            .await?;

        // Delete CSRFToken that used
        let _ = cmd("DEL")
            .arg(&csrf_key)
            .query_async::<String>(&mut self.redis_conn)
            .await?;

        // Create cookie to store SessionID
        let new_cookie = CookieBuilder::new(SESSION_COOKIE_KEY, session_id)
            .same_site(SameSite::Lax)
            .http_only(true)
            .path("/")
            .build();

        let res = Response::builder()
            .status(StatusCode::SEE_OTHER)
            .header(SET_COOKIE, new_cookie.to_string())
            .header(LOCATION, "/protected")
            .body(Empty::new().map_err(|e| match e {}).boxed())
            .unwrap();
        Ok(res)
    }

    fn parse_cookies(header_val: &HeaderValue) -> anyhow::Result<Vec<Cookie<'_>>> {
        let values = header_val.to_str()?;

        let cookies: Vec<Cookie<'_>> = values
            .split(';')
            .filter_map(|c| Cookie::parse(c.trim().to_string()).ok())
            .collect();
        Ok(cookies)
    }
}
