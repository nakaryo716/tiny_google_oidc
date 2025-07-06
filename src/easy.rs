//! A module to simplify implementing the OIDC authentication flow.  
//!
//! This module provides easy-to-use helper functions that combine the public API to reduce boilerplate.  
//! It generates a CSRF token and a nonce internally, so these functions have some side effects.   
//!
//! # Examples
//! See [example/easy/id_token](https://github.com/nakaryo716/tiny_google_oidc/examples/easy/id_token.rs) for usage examples.  
use crate::{
    code::{AccessType, AdditionalScope, Code, CodeRequest, QueryExtractor, RawCodeResponse},
    config::Config,
    csrf_token::CSRFToken,
    error::Error,
    id_token::IDTokenRequest,
    nonce::Nonce,
};

/// Generates a redirect URI for obtaining an OIDC authorization code .  
///
/// Internally, this function generates a new [`CSRFToken`] and [`Nonce`],
/// then constructs a redirect URI according to the specified arguments.  
/// You should store the CSRF token and nonce as needed for later validation.  
///
/// # Arguments
/// ## config
/// The OIDC provider configuration, contains Client ID, Secrets, etc...
/// ## access_type
/// If you want to obtain refresh token, set [`AccessType::Offline`].  
/// See [google document](https://developers.google.com/identity/openid-connect/openid-connect#refresh-tokens)
/// ## scope
/// Additional scopes to request.
/// - If the [`AdditionalScope::Profile`] scope value is present, the ID token might (but is not guaranteed to)
///   include the user's default profile claims.  
/// - If the [`AdditionalScope::Email`] scope value is present, the ID token includes email and email_verified claims.
/// - If the [`AdditionalScope::Both`] scope value is present, the ID token includes
///   the user's default profile, email and email_verified claims.  
/// - If the [`AdditionalScope::None`] scope value is present, the ID token dose not include any additional claims.  
///
/// See [google documentation](https://developers.google.com/identity/openid-connect/openid-connect#scope-param)
///
/// # Returns
/// A tuple containing:
/// - 0: The generated CSRF token.
/// - 1: The generated nonce.
/// - 2: The redirect URI as a [`String`].
///
/// # Errors
/// Returns an error if token generation or URI construction fails.  
///
/// # Examples
/// ```no_run
/// let (csrf_token, nonce, uri) = generate_auth_redirect(
///     &config,
///     AccessType::Offline,
///     AdditionalScope::Both
/// )?;
/// ```
pub fn generate_auth_redirect(
    config: &Config,
    access_type: AccessType,
    scope: AdditionalScope,
) -> Result<(CSRFToken, Nonce, String), Error> {
    let csrf_token = CSRFToken::new()?;
    let nonce = Nonce::new();
    let code_req = CodeRequest::new(access_type, config, scope, &csrf_token, &nonce);
    let uri = code_req.try_into_url()?.to_string();
    Ok((csrf_token, nonce, uri))
}

/// Creates an [`IDTokenRequest`] after validating the CSRF token.  
///
/// This function validates that the provided CSRF token string (usually stored on the server)
/// matches the one returned from the Google authentication response (given as `query_src`).  
/// If the token matches, it constructs an [`IDTokenRequest`]; otherwise, it returns an error.  
///
/// # Arguments
/// ## `config`
/// The OIDC provider configuration.
/// ## `csrf_token_str`
/// The CSRF token string stored on the server.  
/// ## `query_src`
/// A type that is implementing the [`QueryExtractor`] trait.  
/// The trait method returns a URL-encoded query string that is returned from Google.  
///
/// # Returns
/// An [`IDTokenRequest`] if CSRF validation succeeds.  
///
/// # Errors
/// Returns an error if CSRF validation fails or if the query cannot be parsed.  
///
/// # Examples
/// ```no_run
/// fn callback_handler(config: &Config, stored_csrf_token: &str, req: Request) -> Result<(), Error> {
///     // http::Request is implemented QueryExtractor trait
///     let id_token_req = create_id_token_request(
///         config,
///         stored_csrf_token,
///         req
///     )?;
/// }
/// ```
pub fn create_id_token_request<'a, Q: QueryExtractor>(
    config: &'a Config,
    csrf_token_str: &'a str,
    query_src: Q,
) -> Result<IDTokenRequest<'a>, Error> {
    let raw_code = RawCodeResponse::new(query_src)?;
    let code = Code::new_with_verify_csrf(raw_code, csrf_token_str)?;
    let id_token_req = IDTokenRequest::new(config, code);
    Ok(id_token_req)
}
