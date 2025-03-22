//! Provides structures for handling CSRF tokens in the OpenID Connect authentication flow.
use base64::{Engine, engine::general_purpose::URL_SAFE};
use rand::{TryRngCore, rngs::OsRng};
use tracing::error;

use crate::error::Error;

/// A randomly generated CSRF token created using `OsRng` and Base64URL-encoded.
/// 
/// This token is used to prevent CSRF attacks by verifying that the request originates from the client.
/// # Example
/// ```rust, no_run
/// use your_crate::csrf_token::CSRFToken;
///
/// let csrf_token = CSRFToken::new().expect("Failed to generate CSRF token");
/// println!("Generated CSRF Token: {}", csrf_token.value());
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct CSRFToken(pub(crate) String);

impl CSRFToken {
    /// Generates a new CSRF token using a secure random generator.
    /// - Uses `OsRng` for cryptographic security.
    /// - Encodes the random bytes in Base64URL format.
    /// - Returns an `Error::GenToken` if the random generation fails.
    /// # Example
    /// ```rust,no_run
    /// let token = CSRFToken::new().expect("Failed to generate CSRF token");
    /// ```
    pub fn new() -> Result<Self, Error> {
        let mut key = [0u8; 32];
        OsRng.try_fill_bytes(&mut key).map_err(|e| {
            error!("Failed to generate CSRF token: {:?}", e);
            Error::GenToken
        })?;
        Ok(Self(URL_SAFE.encode(key)))
    }
    /// Returns the CSRF token as a string reference.
    pub fn value(&self) -> &str {
        &self.0
    }
}

/// A CSRF token received from Google's authentication response.
/// 
/// This token **has not been verified yet** and should be checked against the stored `CSRFToken` before proceeding.
#[derive(Debug, Clone)]
pub struct UnCheckedCSRFToken(pub(crate) String);

impl From<String> for UnCheckedCSRFToken {
    fn from(value: String) -> Self {
        Self(value.to_string())
    }
}

// ==========Tests==========
#[cfg(test)]
mod tests {
    use super::CSRFToken;

    #[test]
    fn test_csrf_new() {
        let csrf_token = CSRFToken::new();
        assert!(!csrf_token.clone().unwrap().0.is_empty());
    }
}
