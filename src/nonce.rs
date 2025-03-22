//! Represents a cryptographic nonce for OpenID Connect authentication.
use serde::{Deserialize, Serialize};

/// A `Nonce` is a **unique, random value** used to prevent replay attacks in OpenID Connect authentication.  
/// It ensures that the authentication request and response belong to the same session.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Nonce(pub(crate) String);

/// # **Overview**
/// A `Nonce` is a **unique, random value** used to prevent replay attacks in OpenID Connect authentication.  
/// It ensures that the authentication request and response belong to the same session.
///
/// This structure automatically generates a new random nonce using `UUIDv4` when created.
///
/// # **Usage**
///
/// - The nonce is included in the authentication request (`CodeRequest`).
/// - When receiving an ID token from Google, the `Nonce` in the token should be verified
///   against the original nonce sent in the request.
///
/// # **Implementation Details**
///
/// - The `Nonce` value is a **UUIDv4 string**.
/// - It implements `Serialize` and `Deserialize` for easy integration with JSON-based flows.
///
/// # **Example**
///
/// ```rust,no_run
/// use crate::nonce::Nonce;
///
/// let nonce = Nonce::new();
/// println!("Generated Nonce: {}", nonce.0);
/// ```
/// - Always **verify the nonce** in the received ID token against the originally generated value
///   to ensure security.
/// - If the nonce values **do not match**, the authentication response should be rejected./
impl Nonce {
    /// Generates a new nonce using **UUIDv4**.
    pub fn new() -> Self {
        Self(uuid::Uuid::new_v4().to_string())
    }
}

/// Equivalent to `Nonce::new()`.
impl Default for Nonce {
    fn default() -> Self {
        Self::new()
    }
}

// ==========Test==========
#[cfg(test)]
mod test {
    use uuid::Uuid;

    use super::Nonce;

    #[test]
    fn test_nonce_new() {
        let nonce = Nonce::new();
        assert!(!nonce.0.is_empty());
        assert!((Uuid::parse_str(&nonce.0).is_ok()))
    }
}
