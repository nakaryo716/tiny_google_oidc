//! Tiny library for Google's OpenID Connect.  
//! 
//! This library provides essential tools for handling Google's OpenID Connect flow, including
//! generating authentication URLs, verifying tokens, and managing access/refresh tokens.  
//! Implementation in server flow.
//! [google document](https://developers.google.com/identity/openid-connect/openid-connect)
//! # Feature
//! - Generate a CSRF Token
//! - Generate an authentication request URL (code) for Google
//! - Verify CSRF token and retrieve id_token
//! - Exchange code for id_token (using reqwest)
//! - Decode id_token (Base64URLDecode) to get user information
//! - Refresh access token using refresh token (using reqwest)
//! - Revoke access/refresh token (using reqwest)
//! # Caution
//! - This library is designed for direct communication with Google over HTTPS.
//! - It does **not** validate the `id_token` when converting it to a JWT. As a result, the `id_token`
//!   should not be passed to other components of your application.
//! - For more details, refer to the
//! [Google OpenID Connect documentation](https://developers.google.com/identity/openid-connect/openid-connect#obtainuserinfo).
//! # Examples
//! For example usage, see the [examples directory](https://github.com/nakaryo716/tiny_google_oidc.git).
pub mod code;
pub mod config;
pub mod csrf_token;
pub mod error;
pub mod executer;
pub mod id_token;
pub mod nonce;
pub mod refresh_token;
pub mod revoke_token;
