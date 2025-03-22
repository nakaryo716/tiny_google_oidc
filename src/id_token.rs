//! Provides the process of requesting and decode IDToken. 
//! 
//! This module:
//! IDTokenRequest: A data structure for sending requests to the token endpoint.
//! IDTokenResponse: A data structure for parsing the response from the token endpoint.
//! IDToken: A data structure representing the decoded payload of an ID token.
//! AccessToken: A structure representing an access token used to call Google APIs.
//! IDTokenRow: A structure representing an encoded ID token before decoding.

use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use tracing::error;

use crate::{
    code::Code,
    config::{ClientID, ClientSecret, Config, RedirectURI, TokenEndPoint},
    error::Error,
    nonce::Nonce,
    refresh_token::RefreshToken,
};

/// Represents an OAuth 2.0 access token.  
/// This token is used to access Google APIs.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AccessToken(pub(crate) String);

impl AccessToken {
    /// Retrieves the access token as a string.
    pub fn value(&self) -> String {
        self.0.clone()
    }
}

/// Represents a decoded ID token payload in OpenID Connect.  
/// An ID token contains user authentication and profile information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IDToken {
    pub iss: String,  // Issuer (e.g., "https://accounts.google.com")
    pub aud: String,  // Client ID
    pub sub: String,  // User ID (Unique identifier for Google accounts)
    pub azp: Option<String>,  // Authorized party (Optional)
    pub email: Option<String>,  // User's email address
    pub email_verified: Option<bool>,  // Whether the email is verified
    pub given_name: Option<String>,  // Given name
    pub family_name: Option<String>,  // Family name
    pub name: Option<String>,  // Full name
    pub picture: Option<String>,  // Profile picture URL
    pub at_hash: Option<String>,  // Access token hash
    pub iat: u32,  // Issued-at timestamp (UNIX time)
    pub exp: u32,  // Expiration timestamp (UNIX time)
    pub nonce: Option<Nonce>,  // Nonce for security validation
}

impl IDToken {
    /// Decodes an IDTokenRow (encoded ID token) into an IDToken.
    pub fn decode_from_row(id_token: &IDTokenRow) -> Result<Self, Error> {
        let split: Vec<_> = id_token.0.split(".").collect();
        if split.len() != 3 {
            return Err(Error::Decode);
        }
        // Caution!!!!
        // id_token is cloned here for decode.
        // However the cost of clone is big.
        let bytes = BASE64_URL_SAFE_NO_PAD.decode(split[1]).map_err(|e| {
            error!("Failed to decode IDToken: {}", e);
            Error::Decode
        })?;

        // Deserialize from bytes::Byte
        let id_token = serde_json::from_slice::<IDToken>(&bytes).map_err(|e| {
            error!("Failed to deserialize IDToken: {}", e);
            Error::Deserialize
        })?;
        Ok(id_token)
    }
}

/// A structure used to send an ID token request to Google's token endpoint.
#[derive(Debug, Clone)]
pub struct IDTokenRequest {
    token_endpoint: TokenEndPoint,
    code: Code,
    client_id: ClientID,
    client_secret: ClientSecret,
    redirect_uri: RedirectURI,
    grant_type: String,
}

impl IDTokenRequest {
    /// Creates a new request using parameters from Config.
    pub fn new(config: &Config, code: Code) -> Self {
        Self {
            token_endpoint: config.token_endpoint.to_owned(),
            code,
            client_id: config.client_id.to_owned(),
            client_secret: config.client_secret.to_owned(),
            redirect_uri: config.redirect_uri.to_owned(),
            grant_type: "authorization_code".to_string(),
        }
    }

    pub fn token_endpoint(&self) -> &str {
        &self.token_endpoint.0
    }

    pub fn code(&self) -> &str {
        &self.code.0
    }

    pub fn client_id(&self) -> &str {
        &self.client_id.0
    }

    pub fn client_secret(&self) -> &str {
        &self.client_secret.0
    }
    pub fn redirect_uri(&self) -> &str {
        &self.redirect_uri.0
    }

    pub fn grant_type(&self) -> &str {
        &self.grant_type
    }
}

/// Represents the response from Google's token endpoint, which includes both an access token and an ID token.
#[derive(Debug, Clone, Deserialize)]
pub struct IDTokenResponse {
    access_token: AccessToken,
    expires_in: u32,
    id_token: IDTokenRow,
    scope: String,
    token_type: String,
    refresh_token: Option<RefreshToken>,
}

impl IDTokenResponse {
    pub fn access_token(&self) -> &AccessToken {
        &self.access_token
    }

    pub fn expires_in(&self) -> u32 {
        self.expires_in
    }

    pub fn id_token(&self) -> &IDTokenRow {
        &self.id_token
    }

    pub fn scope(&self) -> &str {
        &self.scope
    }

    pub fn token_type(&self) -> &str {
        &self.token_type
    }

    pub fn refresh_token(&self) -> &Option<RefreshToken> {
        &self.refresh_token
    }
}

/// Represents an encoded ID token, which must be decoded before use.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct IDTokenRow(String);

// ==========Tests==========
#[cfg(test)]
mod tests {
    use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};

    use crate::{
        code::Code,
        config::ConfigBuilder,
        error::Error,
        id_token::{AccessToken, IDToken, IDTokenRequest, IDTokenResponse, IDTokenRow},
        refresh_token::RefreshToken,
    };

    #[test]
    fn test_access_token_value() {
        let token = AccessToken("test_token".to_string());
        assert_eq!(token.value(), "test_token");
    }

    #[test]
    fn test_id_token_decode_success() {
        let id_token_json = r#"{
            "iss": "https://accounts.google.com",
            "aud": "my_aud",
            "sub": "my_sub",
            "azp": "my_azp",
            "email": "email@gmail.com",
            "email_verified": true,
            "given_name": "my_given_name",
            "family_name": "my_family_name",
            "name": "my_name",
            "picture": "https://picture.example.com",
            "at_hash": "my_at_hash",
            "iat": 1742189616,
            "exp": 1742193216,
            "nonce": "my_nonce"
        }"#;
        let encoded = BASE64_URL_SAFE_NO_PAD.encode(id_token_json);

        let mut token_row = "header.".to_string();
        token_row.push_str(&encoded);
        token_row.push_str(".signature");
        let id_token_row = IDTokenRow(token_row);

        let decoded = IDToken::decode_from_row(&id_token_row);
        assert!(decoded.is_ok());
    }

    #[test]
    fn test_id_token_decode_invalid_base64() {
        let id_token_row = IDTokenRow("invalid_base64".to_string());

        let decoded = IDToken::decode_from_row(&id_token_row);
        assert!(matches!(decoded, Err(Error::Decode)));
    }

    #[test]
    fn test_id_token_decode_invalid_json() {
        let invalid_json = BASE64_URL_SAFE_NO_PAD.encode("not a valid json");
        let id_token_row = IDTokenRow(invalid_json);

        let decoded = IDToken::decode_from_row(&id_token_row);
        assert!(matches!(decoded, Err(Error::Decode)));
    }

    #[test]
    fn test_id_token_request_new() {
        let config = ConfigBuilder::new()
            .token_endpoint("https://token.example.com")
            .client_id("client_id")
            .client_secret("secret")
            .redirect_uri("https://redirect.example.com")
            .build();

        let code = Code("auth_code".to_string());
        let request = IDTokenRequest::new(&config, code.clone());

        assert_eq!(request.token_endpoint.0, "https://token.example.com");
        assert_eq!(request.client_id.0, "client_id");
        assert_eq!(request.client_secret.0, "secret");
        assert_eq!(request.redirect_uri.0, "https://redirect.example.com");
        assert_eq!(request.code, code);
    }

    #[test]
    fn test_id_token_response_getters() {
        let access_token = AccessToken("access_token_value".to_string());
        let id_token_row = IDTokenRow("id_token_value".to_string());
        let refresh_token = Some(RefreshToken("refresh_token_value".to_string()));

        let response = IDTokenResponse {
            access_token: access_token.clone(),
            expires_in: 3600,
            id_token: id_token_row.clone(),
            scope: "openid email".to_string(),
            token_type: "Bearer".to_string(),
            refresh_token: refresh_token.clone(),
        };

        assert_eq!(response.access_token(), &access_token);
        assert_eq!(response.expires_in(), 3600);
        assert_eq!(response.id_token(), &id_token_row);
        assert_eq!(response.scope(), "openid email");
        assert_eq!(response.token_type(), "Bearer");
        assert_eq!(response.refresh_token(), &refresh_token);
    }
}
