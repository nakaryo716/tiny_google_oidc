//! provides functionality for handling refresh tokens.  
//!
//! This module includes:
//! - RefreshToken: A structure representing the refresh token.
//! - RefreshTokenRequest: A structure for sending a request to Google's OAuth 2.0 token endpoint.
//! - RefreshTokenResponse: A structure for parsing the response from the refresh token request.

use serde::Deserialize;

/// Represents an OAuth 2.0 refresh token, which is used to obtain a new access token without user interaction.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct RefreshToken(pub(crate) String);

impl RefreshToken {
    /// Creates a new refresh token from a string.
    pub fn new(value: &str) -> Self {
        Self(value.to_string())
    }
    /// Returns the refresh token as a String.
    pub fn value(&self) -> String {
        self.0.to_owned()
    }
    /// Returns the refresh token as a String.
    pub fn value_as_str(&self) -> &str {
        &self.0
    }
}
