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
use crate::{error::Error, id_token::AccessToken, refresh_token::RefreshToken};

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

    pub fn access_token(&self) -> Option<&AccessToken> {
        if let RevokeToken::AccessToken(value) = self {
            Some(value)
        } else {
            None
        }
    }

    pub fn refresh_token(&self) -> Option<&RefreshToken> {
        if let RevokeToken::RefreshToken(value) = self {
            Some(value)
        } else {
            None
        }
    }
}

/// Represents a request to revoke a token by sending it to Google's revocation endpoint.
#[derive(Debug, Clone, PartialEq)]
pub struct RevokeTokenRequest<'a> {
    pub(crate) end_point: &'a str,
    pub(crate) token: &'a RevokeToken,
}

impl<'a> RevokeTokenRequest<'a> {
    /// Creates a new RevokeTokenRequest with the token to be revoked and the Google revocation endpoint (<https://oauth2.googleapis.com/revoke>).
    pub fn new(token: &'a RevokeToken) -> Self {
        Self {
            end_point: "https://oauth2.googleapis.com/revoke",
            token,
        }
    }
    /// Returns the revocation endpoint URL.
    pub fn end_point(&self) -> &str {
        self.end_point
    }

    pub fn token(&self) -> &RevokeToken {
        self.token
    }

    /// Extracts the token string from the RevokeToken enum, whether it's an access token or a refresh token.
    pub fn inner_value(&self) -> &str {
        match &self.token {
            RevokeToken::AccessToken(v) => &v.0,
            RevokeToken::RefreshToken(v) => &v.0,
        }
    }
}

///  A function that sends an HTTP request to revoke a token (such as an access token or refresh token) using the OAuth2 standard revocation endpoint.  
///
/// It takes a `RevokeTokenRequest` struct as input and returns `Ok(())` on success, or an `Error` if the revocation fails.  
/// The implementation uses the [reqwest](https://docs.rs/reqwest/) crate internally for HTTP communication.
pub async fn send_revoke_token_req(req: &RevokeTokenRequest<'_>) -> Result<(), Error> {
    use reqwest::Client;
    use std::collections::HashMap;
    use tracing::error;

    let end_point = req.end_point();

    let mut param = HashMap::new();
    param.insert("token", req.inner_value());

    let client = Client::new();
    let status_code = client
        .post(end_point)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .form(&param)
        .send()
        .await
        .map_err(|e| {
            error!("Failed to end request: {:?}", e);
            Error::Send
        })?
        .status();

    if status_code.is_success() {
        Ok(())
    } else {
        Err(Error::SendStatus(status_code))
    }
}

#[cfg(test)]
mod tests {
    use crate::id_token::AccessToken;

    use super::{RevokeToken, RevokeTokenRequest};

    #[test]
    fn test_revoke_req_new() {
        let token = RevokeToken::AccessToken(AccessToken("my_access_token".to_string()));
        let req = RevokeTokenRequest::new(&token);
        assert_eq!(req.token(), &token)
    }

    #[test]
    fn test_revoke_req() {
        let token = AccessToken("my_access_token".to_string());
        let access_token = RevokeToken::AccessToken(token.clone());
        let req = RevokeTokenRequest::new(&access_token);
        assert_eq!(req.token(), &access_token);
    }
}
