//! This module handles the process of requesting and verifying an authorization code
//! in the OpenID Connect authentication flow.   
//! 
//! It provides the following key functionalities:
//! - Generating an authorization request URL (`CodeRequest`).
//! - Parsing and verifying the authorization code received from Google's callback (`UnCheckedCodeResponse`).
//!
//! # Key Structures and Features
//!
//! ## `CodeRequest`
//! A structure used to generate the authorization request URL.  
//! - Includes parameters like CSRF token, scope, redirect URI, and nonce.
//!
//! ## `UnCheckedCodeResponse`
//! Represents the authorization code response received from Google.  
//! - This response must be validated using a CSRF token before it can be used.
//!
//! ## `Code`
//! Represents a verified authorization code that can be exchanged for tokens.  
//! - This is obtained after validating the `UnCheckedCodeResponse` with a CSRF token.
//!
//! # Examples
//! ## Generating an Authorization Request URL
//! ```rust,no_run
//! let config = Config::builder()
//!     .client_id("your_client_id")
//!     .redirect_uri("your_redirect_uri")
//!     .build();
//!
//! let csrf_token = CSRFToken::new().unwrap();
//! let nonce = Nonce::new();
//! let scope = Some([AdditionalScope::Email, AdditionalScope::Profile].into_iter());
//!
//! let request = CodeRequest::new(true, &config, scope, &csrf_token, &nonce);
//! let url = request.into_url().unwrap();
//! println!("Auth URL: {}", url);
//! ```
//!
//! ## Handling the Callback and Verifying the Authorization Code
//! ```rust,no_run
//! let response = UnCheckedCodeResponse::from_url("https://example.com/callback?...").unwrap();
//! // get stored CSRF token From DB(Redis, in memory ...) 
//! let csrf_token = store.get("csrf_token_key")?;
//!
//! let code = response.exchange_with_code(csrf_token).expect("CSRF token mismatch!");
//! ```
//!
//! # Flow
//! 1. Generate a CSRF token (`CSRFToken`) and include it in the authorization request.
//! 2. Redirect the user to Google's authentication page.
//! 3. After authentication, Google redirects back with an authorization code (`UnCheckedCodeResponse`).
//! 4. Validate the CSRF token in the `UnCheckedCodeResponse` using `Code::new_with_verify_csrf()` or `UnCheckedCodeResponse::exchange_with_code()`.
//! 5. If validation succeeds, a `Code` is obtained, which can be exchanged for tokens.
//!
//! # Notes
//! - Always validate the CSRF token to ensure the integrity of the authentication flow.
//! - Do not use `UnCheckedCodeResponse` directly without verification.
use itertools::Itertools;
use tracing::error;

use crate::{
    config::{AuthEndPoint, ClientID, Config, RedirectURI},
    csrf_token::{CSRFToken, UnCheckedCSRFToken},
    error::Error,
    nonce::Nonce,
};
use std::{
    collections::{HashMap, HashSet},
    iter::Iterator,
};

/// Optional Scope Parameters  
///
/// In an OpenID Connect authentication request, the `scope` parameter specifies the type of user information
/// that should be included in the ID token. By default, the `openid` scope is required for authentication.
/// This enum allows adding **optional** scopes, such as `email` or `profile`, to the request.
///
/// # Purpose
/// `AdditionalScope` is used to extend the default `scope` parameter when creating a `CodeRequest`.
/// It enables applications to request additional user information from Google.
///
/// # Variants
///
/// ## `Email`
/// - Requests the user's **email address** and **email verification status**.
/// - This is useful if the application needs to identify the user by their email address.
///
/// ## `Profile`
/// - Requests the user's **name, profile picture URL, and other basic profile information**.
/// - This is useful for displaying user details in the application.
///
/// # Usage
/// To include `email` or `profile` in the scope, add `AdditionalScope::Email` or `AdditionalScope::Profile`
/// when creating a `CodeRequest`.
///
/// # Example
/// ```rust,no_run
/// use crate::code::AdditionalScope;
///
/// let additional_scopes = Some([AdditionalScope::Email, AdditionalScope::Profile].into_iter());
/// let request = CodeRequest::new(true, &config, additional_scopes, &csrf_token, &nonce);
/// let url = request.into_url().unwrap();
/// println!("Authorization URL: {}", url);
/// ```
///
/// If **no additional scopes** are specified, the request will **only include `openid`**, which is required for authentication.
///
/// # Notes
/// - Adding `email` or `profile` scopes allows the application to access more detailed user information.
/// - Ensure that the requested scopes align with the application's privacy policy and user consent.
#[derive(Debug, Clone, PartialEq)]
pub enum AdditionalScope {
    Email,
    Profile,
}

/// Represents the value of the `code` query parameter sent by Google during the OpenID Connect flow.  
/// This structure ensures that the `code` can only be obtained after validating the associated `CSRFToken`.
///
/// # Purpose
/// The `Code` is used to construct an `IDTokenRequest`, which is required to retrieve an ID token from Google.
/// ```rust,no_run
/// let code: Code = Code::new_with_verify_csrf(res, stored_csrf_token)?;
/// let id_token_req = IDTokenRequest::new(&config, code);
/// ```
///
/// # How to Create
/// A `Code` can only be created after validating the `CSRFToken`.  
/// Use either `Code::new_with_verify_csrf` or `UnCheckedCodeResponse::exchange_with_code` to validate and create a `Code`.
///
/// # Example
/// ```rust,no_run
/// let response = UnCheckedCodeResponse::from_url("https://example.com/callback?...").unwrap();
/// let csrf_token = store.get("csrf_token_key")?;
///
/// let code = response.exchange_with_code(csrf_token).expect("CSRF token mismatch!");
/// println!("Verified Code: {:?}", code);
/// ```
///
/// # Notes
/// - Always validate the `CSRFToken` before using the `Code`.
/// - The `Code` is essential for constructing an `IDTokenRequest` to retrieve an ID token.
#[derive(Debug, Clone, PartialEq)]
pub struct Code(pub(crate) String);

impl Code {
    /// Checks if `res.state` (CSRF token from Google) matches `csrf_token` (generated by user).
    /// If valid, returns a `Code`; otherwise, returns `Error::CSRFNotMatch`.
    pub fn new_with_verify_csrf(
        res: UnCheckedCodeResponse,
        csrf_token_val: &str,
    ) -> Result<Self, Error> {
        if res.state.0 == csrf_token_val {
            Ok(res.code)
        } else {
            Err(Error::CSRFNotMatch)
        }
    }
}

impl From<String> for Code {
    fn from(value: String) -> Self {
        Self(value)
    }
}

/// Generates a URL to initiate the authorization request.
/// # Example
/// ```rust,no_run
/// let config = Config::builder()
///     .client_id("your_client_id")
///     .redirect_uri("your_redirect_uri")
///     .build();
///
/// let csrf_token = CSRFToken::new().unwrap();
/// let nonce = Nonce::new().unwrap();
///
/// let request = CodeRequest::new(true, &config, None, &csrf_token, &nonce);
/// let url = request.into_url().unwrap();
/// println!("Auth URL: {}", url);
/// ```
#[derive(Debug, Clone)]
pub struct CodeRequest<S>
where
    S: Iterator<Item = AdditionalScope>,
{
    auth_endpoint: AuthEndPoint,
    client_id: ClientID,
    response_type: String,
    scope: Option<S>,
    redirect_uri: RedirectURI,
    access_type: bool,
    state: CSRFToken,
    nonce: Nonce,
}

impl<S> CodeRequest<S>
where
    S: Iterator<Item = AdditionalScope> + Clone,
{
    /// # **Parameters**
    ///
    /// - `access_type` (`bool`):
    ///   - `true` → Requests an **offline** access token (includes a refresh token).
    ///   - `false` → Requests an **online** access token (no refresh token).
    ///
    /// - `config` (`&Config`):
    ///   - Contains necessary settings such as `client_id`, `auth_endpoint`, and `redirect_uri`.
    ///
    /// - `scope` (`Option<S>` where `S: Iterator<Item = AdditionalScope>`):
    ///   - Specifies additional scopes (`email`, `profile`) in addition to the required `openid` scope.
    ///   - If `None`, only `openid` will be requested.
    ///
    /// - `state` (`&CSRFToken`):
    ///   - A **CSRF protection token** to prevent cross-site request forgery attacks.
    ///
    /// - `nonce` (`&Nonce`):
    ///   - A **nonce value** used to mitigate replay attacks.
    pub fn new(
        access_type: bool,
        config: &Config,
        scope: Option<S>,
        state: &CSRFToken,
        nonce: &Nonce,
    ) -> Self {
        Self {
            auth_endpoint: config.auth_endpoint.to_owned(),
            client_id: config.client_id.to_owned(),
            response_type: "code".to_string(),
            scope,
            redirect_uri: config.redirect_uri.to_owned(),
            access_type,
            state: state.to_owned(),
            nonce: nonce.to_owned(),
        }
    }

    /// Constructs a URL with the required parameters for Google authentication.
    pub fn into_url(&self) -> Result<String, Error> {
        let access_type = if self.access_type {
            "offline"
        } else {
            "online"
        };

        let scope = self
            .scope
            .as_ref()
            .map(|s| {
                s.clone().map(|v| match v {
                    AdditionalScope::Email => "email",
                    AdditionalScope::Profile => "profile",
                })
            })
            .map(|v| v.collect::<HashSet<_>>().iter().sorted().join(" "));

        let scope = if let Some(mut v) = scope {
            v.insert_str(0, "openid ");
            v
        } else {
            "openid".to_string()
        };

        let url = format!(
            "{}?response_type={}&client_id={}&scope={}&access_type={}&redirect_uri={}&state={}&nonce={}",
            self.auth_endpoint.0,
            self.response_type,
            self.client_id.0,
            scope,
            access_type,
            self.redirect_uri.0,
            self.state.0,
            self.nonce.0,
        );
        Ok(url)
    }
}

/// A response from Google containing an unverified authorization code and state.  
/// Must be validated using a CSRF token before use.
/// # Example
/// ```rust,no_run
/// let response = UnCheckedCodeResponse::from_url("https://example.com/callback?...").unwrap();
/// let csrf_token = store.get("csrf_token_key")?;
///
/// let code = response.exchange_with_code(csrf_token).expect("CSRF token mismatch!");
/// ```
#[derive(Debug, Clone)]
pub struct UnCheckedCodeResponse {
    state: UnCheckedCSRFToken,
    code: Code,
}

impl UnCheckedCodeResponse {
    pub fn from_url(response_url: &str) -> Result<Self, Error> {
        let url = url::Url::try_from(response_url).map_err(|e| {
            error!("Failed to parse url from google: {}", e);
            Error::URL
        })?;
        let params: HashMap<_, _> = url.query_pairs().map(|v| (v.0, v.1)).collect();
        Ok(Self {
            state: params.get("state").ok_or(Error::URL)?.to_string().into(),
            code: params.get("code").ok_or(Error::URL)?.to_string().into(),
        })
    }

    /// Must be validated using a CSRF token before use.
    pub fn exchange_with_code(self, csrf_token_val: &str) -> Result<Code, Error> {
        if self.state.0 == csrf_token_val {
            Ok(self.code)
        } else {
            Err(Error::CSRFNotMatch)
        }
    }
}

// ==========Tests==========
#[cfg(test)]
mod tests {
    use std::iter::Empty;

    use crate::{config::ConfigBuilder, csrf_token::CSRFToken, nonce::Nonce};

    use super::{AdditionalScope, CodeRequest};

    // ==========Code methods==========

    // ==========CodeRequest methods==========
    #[test]
    fn test_code_req_new_some_scope() {
        let access_type = true;

        let auth_endpoint = "https://auth.example.com/auth";
        let client_id = "my_client_id";
        let client_secret = "my_secret";
        let token_endpoint = "https://token.example.com";
        let redirect_uri = "https://redirect.example.com";

        let config = ConfigBuilder::new()
            .auth_endpoint(auth_endpoint)
            .client_id(client_id)
            .client_secret(client_secret)
            .token_endpoint(token_endpoint)
            .redirect_uri(redirect_uri)
            .build();

        let scope = Some([AdditionalScope::Email, AdditionalScope::Profile].into_iter());
        let state = CSRFToken::new().unwrap();
        let nonce = Nonce::new();

        let code_req = CodeRequest::new(access_type, &config, scope.clone(), &state, &nonce);

        assert_eq!(code_req.access_type, access_type);
        assert_eq!(code_req.auth_endpoint.0, auth_endpoint);
        assert_eq!(code_req.client_id.0, client_id);
        assert_eq!(code_req.redirect_uri.0, redirect_uri);
        assert_eq!(code_req.state, state);
        assert_eq!(code_req.nonce, nonce);

        let expected_scope: Vec<AdditionalScope> = scope.unwrap().collect();
        let actual_scope: Vec<AdditionalScope> = code_req.scope.unwrap().collect();
        assert_eq!(actual_scope, expected_scope);
    }

    #[test]
    fn test_code_req_new_none_scope() {
        let access_type = true;

        let auth_endpoint = "https://auth.example.com/auth";
        let client_id = "my_client_id";
        let client_secret = "my_secret";
        let token_endpoint = "https://token.example.com";
        let redirect_uri = "https://redirect.example.com";

        let config = ConfigBuilder::new()
            .auth_endpoint(auth_endpoint)
            .client_id(client_id)
            .client_secret(client_secret)
            .token_endpoint(token_endpoint)
            .redirect_uri(redirect_uri)
            .build();

        let scope: Option<Empty<AdditionalScope>> = None;
        let state = CSRFToken::new().unwrap();
        let nonce = Nonce::new();

        let code_req = CodeRequest::new(access_type, &config, scope.clone(), &state, &nonce);

        assert_eq!(code_req.access_type, access_type);
        assert_eq!(code_req.auth_endpoint.0, auth_endpoint);
        assert_eq!(code_req.client_id.0, client_id);
        assert_eq!(code_req.redirect_uri.0, redirect_uri);
        assert_eq!(code_req.state, state);
        assert_eq!(code_req.nonce, nonce);
        assert!(code_req.scope.is_none())
    }

    #[test]
    fn test_code_req_into_url() {
        let access_type = true;

        let auth_endpoint = "https://auth.example.com/auth";
        let client_id = "my_client_id";
        let client_secret = "my_secret";
        let token_endpoint = "https://token.example.com";
        let redirect_url = "https://redirect.example.com";

        let config = ConfigBuilder::new()
            .auth_endpoint(auth_endpoint)
            .client_id(client_id)
            .client_secret(client_secret)
            .token_endpoint(token_endpoint)
            .redirect_uri(redirect_url)
            .build();

        let scope = Some([AdditionalScope::Email, AdditionalScope::Profile].into_iter());
        let state = CSRFToken::new().unwrap();
        let nonce = Nonce::new();

        let code_req = CodeRequest::new(access_type, &config, scope.clone(), &state, &nonce);

        let url = code_req.into_url().unwrap();
        let expected_url = format!(
            "{}?response_type={}&client_id={}&scope={}&access_type={}&redirect_uri={}&state={}&nonce={}",
            auth_endpoint,
            "code",
            client_id,
            "openid email profile",
            "offline",
            redirect_url,
            state.0,
            nonce.0,
        );
        assert_eq!(url, expected_url);
    }

    #[test]
    fn test_code_req_into_url_scope_one() {
        let access_type = true;

        let auth_endpoint = "https://auth.example.com/auth";
        let client_id = "my_client_id";
        let client_secret = "my_secret";
        let token_endpoint = "https://token.example.com";
        let redirect_url = "https://redirect.example.com";

        let config = ConfigBuilder::new()
            .auth_endpoint(auth_endpoint)
            .client_id(client_id)
            .client_secret(client_secret)
            .token_endpoint(token_endpoint)
            .redirect_uri(redirect_url)
            .build();

        let scope = Some([AdditionalScope::Email].into_iter());
        let state = CSRFToken::new().unwrap();
        let nonce = Nonce::new();

        let code_req = CodeRequest::new(access_type, &config, scope.clone(), &state, &nonce);

        let url = code_req.into_url().unwrap();
        let expected_url = format!(
            "{}?response_type={}&client_id={}&scope={}&access_type={}&redirect_uri={}&state={}&nonce={}",
            auth_endpoint,
            "code",
            client_id,
            "openid email",
            "offline",
            redirect_url,
            state.0,
            nonce.0,
        );
        assert_eq!(url, expected_url);
    }

    #[test]
    fn test_code_req_into_url_scope_none() {
        let access_type = true;

        let auth_endpoint = "https://auth.example.com/auth";
        let client_id = "my_client_id";
        let client_secret = "my_secret";
        let token_endpoint = "https://token.example.com";
        let redirect_url = "https://redirect.example.com";

        let config = ConfigBuilder::new()
            .auth_endpoint(auth_endpoint)
            .client_id(client_id)
            .client_secret(client_secret)
            .token_endpoint(token_endpoint)
            .redirect_uri(redirect_url)
            .build();

        let scope: Option<Empty<AdditionalScope>> = None;
        let state = CSRFToken::new().unwrap();
        let nonce = Nonce::new();

        let code_req = CodeRequest::new(access_type, &config, scope.clone(), &state, &nonce);

        let url = code_req.into_url().unwrap();
        let expected_url = format!(
            "{}?response_type={}&client_id={}&scope={}&access_type={}&redirect_uri={}&state={}&nonce={}",
            auth_endpoint, "code", client_id, "openid", "offline", redirect_url, state.0, nonce.0,
        );
        assert_eq!(url, expected_url);
    }

    #[test]
    fn test_code_req_into_url_scope_duplicate() {
        let access_type = true;

        let auth_endpoint = "https://auth.example.com/auth";
        let client_id = "my_client_id";
        let client_secret = "my_secret";
        let token_endpoint = "https://token.example.com";
        let redirect_url = "https://redirect.example.com";

        let config = ConfigBuilder::new()
            .auth_endpoint(auth_endpoint)
            .client_id(client_id)
            .client_secret(client_secret)
            .token_endpoint(token_endpoint)
            .redirect_uri(redirect_url)
            .build();

        let scope = Some(
            [
                AdditionalScope::Email,
                AdditionalScope::Profile,
                AdditionalScope::Email,
            ]
            .into_iter(),
        );
        let state = CSRFToken::new().unwrap();
        let nonce = Nonce::new();

        let code_req = CodeRequest::new(access_type, &config, scope.clone(), &state, &nonce);
        let url = code_req.into_url().unwrap();
        let expected_url = format!(
            "{}?response_type={}&client_id={}&scope={}&access_type={}&redirect_uri={}&state={}&nonce={}",
            auth_endpoint,
            "code",
            client_id,
            "openid email profile",
            "offline",
            redirect_url,
            state.0,
            nonce.0,
        );
        assert_eq!(url, expected_url);
    }
}
