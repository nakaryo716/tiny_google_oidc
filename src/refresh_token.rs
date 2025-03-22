//! provides functionality for handling refresh tokens.  
//! 
//! This module includes:
//! - RefreshToken: A structure representing the refresh token.
//! - RefreshTokenRequest: A structure for sending a request to Google's OAuth 2.0 token endpoint.
//! - RefreshTokenResponse: A structure for parsing the response from the refresh token request.

use serde::{Deserialize, Serialize};

use crate::{
    config::{ClientID, ClientSecret, Config},
    id_token::AccessToken,
};

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

/// Represents a request to exchange a refresh token for a new access token.
#[derive(Debug, Clone)]
pub struct RefreshTokenRequest {
    pub(crate) refresh_token_endpoint: String,
    pub(crate) client_id: ClientID,
    pub(crate) client_secret: ClientSecret,
    pub(crate) refresh_token: RefreshToken,
    pub(crate) grant_type: String,
}

impl RefreshTokenRequest {
    /// Creates a new RefreshTokenRequest with the necessary parameters:
    pub fn new(config: &Config, refresh_token: &RefreshToken) -> Self {
        Self {
            refresh_token_endpoint: "https://oauth2.googleapis.com/token".to_string(),
            client_id: config.client_id.to_owned(),
            client_secret: config.client_secret.to_owned(),
            refresh_token: refresh_token.to_owned(),
            grant_type: "refresh_token".to_string(),
        }
    }
}

/// Represents the response from Google's OAuth 2.0 token endpoint when exchanging a refresh token for a new access token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefreshTokenResponse {
    access_token: AccessToken,
    expires_in: u32,
    scope: String,
    token_type: String,
}

impl RefreshTokenResponse {
    /// Retrieves the newly issued access token.
    pub fn access_token(&self) -> &str {
        &self.access_token.0
    }
    /// Returns the expiration time (in seconds) of the access token.
    pub fn expires_in(&self) -> u32 {
        self.expires_in
    }
    /// Retrieves the scope of the new access token.
    pub fn scope(&self) -> &str {
        &self.scope
    }
    /// Retrieves the token type (typically "Bearer").
    pub fn token_type(&self) -> &str {
        &self.token_type
    }
}

// ==========Tests==========
#[cfg(test)]
mod tests {
    use crate::{config::ConfigBuilder, id_token::AccessToken, refresh_token::RefreshToken};

    use super::{RefreshTokenRequest, RefreshTokenResponse};

    #[test]
    fn test_refresh_token_methods() {
        let refresh_token = RefreshToken("refresh_token_value".to_string());

        assert_eq!(refresh_token.value(), "refresh_token_value");
        assert_eq!(refresh_token.value_as_str(), "refresh_token_value");
    }

    #[test]
    fn test_refresh_token_req_into_url() {
        let auth_endpoint = "https://auth.example.com/auth";
        let client_id = "my_client_id";
        let client_secret = "my_secret";
        let token_endpoint = "https://token.example.com/token";
        let redirect_uri = "https://redirect.example.com";

        let config = ConfigBuilder::new()
            .auth_endpoint(auth_endpoint)
            .client_id(client_id)
            .client_secret(client_secret)
            .token_endpoint(token_endpoint)
            .redirect_uri(redirect_uri)
            .build();

        let refresh_token = RefreshToken("my_refresh_token".to_string());

        let req = RefreshTokenRequest::new(&config, &refresh_token);
        assert_eq!(req.client_id, config.client_id);
        assert_eq!(
            req.refresh_token_endpoint,
            "https://oauth2.googleapis.com/token"
        );
        assert_eq!(req.client_secret, config.client_secret);
        assert_eq!(req.refresh_token, refresh_token);
        assert_eq!(req.grant_type, "refresh_token");
    }

    #[test]
    fn test_refresh_token_res() {
        let access_token = "my_access_token".to_string();
        let expires_in = 5000;
        let scope = "my_scope".to_string();
        let token_type = "my_token_type".to_string();
        let res = RefreshTokenResponse {
            access_token: AccessToken(access_token.clone()),
            expires_in,
            scope: scope.clone(),
            token_type: token_type.clone(),
        };
        assert_eq!(res.access_token(), access_token);
        assert_eq!(res.expires_in(), expires_in);
        assert_eq!(res.scope(), &scope);
        assert_eq!(res.token_type(), &token_type);
    }
}
