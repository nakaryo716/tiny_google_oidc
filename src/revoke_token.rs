//! provides functionality for revoking OAuth 2.0 tokens.
//! In OAuth 2.0, tokens can be explicitly revoked by the client to ensure they are no longer valid.
//! This module includes:
//! - RevokeToken: An enum representing either an access token or a refresh token for revocation.
//! - RevokeTokenRequest: A structure for sending a revocation request to Google's OAuth 2.0 token revocation endpoint.
//! # Token Revocation Flow
//! 1. Choose the token type
//!     - Use an access token to revoke only the current session.
//!     - Use a refresh token to revoke all sessions related to the token.
//! 2. Send a revocation request
//!     - Create a RevokeTokenRequest and send it to Google's revocation endpoint.
//! 3. Handle the response
//!     - If successful, the token is invalidated and cannot be used anymore.
//! # Security Considerations
//! - Use refresh tokens for full revocation
//!     - Revoking an access token only terminates the current session, while revoking a refresh token invalidates all associated access tokens.
//! - Ensure token safety
//!     - Revocation should be performed securely (e.g., through a backend server) to prevent malicious attacks.
use crate::{id_token::AccessToken, refresh_token::RefreshToken};

/// Represents a token that can be revoked, which can be either an access token or a refresh token.
#[derive(Debug, Clone, PartialEq)]
pub enum RevokeToken {
    AccessToken(AccessToken),
    RefreshToken(RefreshToken),
}

impl RevokeToken {
    /// Creates a RevokeToken instance for an access token.
    pub fn new_access_token(token: &str) -> Self {
        Self::AccessToken(AccessToken(token.to_string()))
    }
    /// Creates a RevokeToken instance for a refresh token.
    pub fn new_refresh_token(token: &str) -> Self {
        Self::RefreshToken(RefreshToken(token.to_string()))
    }
}

/// Represents a request to revoke a token by sending it to Google's revocation endpoint.
#[derive(Debug, Clone, PartialEq)]
pub struct RevokeTokenRequest {
    pub(crate) end_point: String,
    pub(crate) token: RevokeToken,
}

impl RevokeTokenRequest {
    /// Creates a new RevokeTokenRequest with the token to be revoked and the Google revocation endpoint (<https://oauth2.googleapis.com/revoke>).
    pub fn new(token: &RevokeToken) -> Self {
        Self {
            end_point: "https://oauth2.googleapis.com/revoke".to_string(),
            token: token.clone(),
        }
    }
    /// Returns the revocation endpoint URL.
    pub fn end_point(&self) -> &str {
        &self.end_point
    }
    /// Extracts the token string from the RevokeToken enum, whether it's an access token or a refresh token.
    pub fn inner_value(&self) -> &str {
        match &self.token {
            RevokeToken::AccessToken(v) => &v.0,
            RevokeToken::RefreshToken(v) => &v.0,
        }
    }
}

// ==========Tests==========
#[cfg(test)]
mod tests {
    use crate::id_token::AccessToken;

    use super::{RevokeToken, RevokeTokenRequest};

    #[test]
    fn test_revoke_req_new() {
        let token = RevokeToken::AccessToken(AccessToken("my_access_token".to_string()));
        let req = RevokeTokenRequest::new(&token);
        assert_eq!(req.token, token)
    }

    #[test]
    fn test_revoke_req() {
        let token = AccessToken("my_access_token".to_string());
        let access_token = RevokeToken::AccessToken(token.clone());
        let req = RevokeTokenRequest::new(&access_token);
        assert_eq!(req.token, access_token);
    }
}
