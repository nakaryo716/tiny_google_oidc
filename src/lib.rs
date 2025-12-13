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
//! # Examples
//! For example usage, see the [examples directory](https://github.com/nakaryo716/tiny_google_oidc.git).
pub mod code;
pub mod config;
pub mod csrf_token;
pub mod easy;
pub mod error;
pub mod id_token;
pub mod nonce;
pub mod refresh_token;

pub use easy::{create_id_token_request, generate_auth_redirect};
