//! Defines structures and builders related to authentication configuration.  
//! 
//! Provides a structured way to handle credentials
//! and endpoints required for authentication and token exchange.
//!
//! ## Structures
//! - `Config`: Stores all the necessary authentication information.
//! - `ConfigBuilder`: A builder for constructing a `Config` instance.
//!
//! # Example
//! ```rust,no_run
//! use your_crate::config::Config;
//!
//! let config = Config::builder()
//!     .auth_endpoint("https://accounts.google.com/o/oauth2/auth")
//!     .client_id("your-client-id")
//!     .client_secret("your-client-secret")
//!     .token_endpoint("https://oauth2.googleapis.com/token")
//!     .redirect_uri("https://your-app.com/callback")
//!     .build();
//! ```
//!
//! This ensures a structured and safe way to manage configuration details.

#[derive(Debug, Clone, Default)]
pub(crate) struct AuthEndPoint(pub String);


/// Holds all necessary authentication information required for Google's OpenID Connect flow.  
/// 
/// It is designed to be immutable once constructed.
///
/// # Fields
/// - `auth_endpoint`: The authorization endpoint URL.
/// - `client_id`: The client ID obtained from Google Cloud Console.
/// - `client_secret`: The client secret linked to the client ID.
/// - `token_endpoint`: The token exchange endpoint URL.
/// - `redirect_uri`: The redirect URI registered in Google Cloud Console.
///
/// This struct is primarily built using the `ConfigBuilder`.
///
/// # Example
/// ```rust,no_run
/// use your_crate::config::Config;
///
/// let config = Config::builder()
///     .auth_endpoint("https://accounts.google.com/o/oauth2/auth")
///     .client_id("your-client-id")
///     .client_secret("your-client-secret")
///     .token_endpoint("https://oauth2.googleapis.com/token")
///     .redirect_uri("https://your-app.com/callback")
///     .build();
/// ```
#[derive(Debug, Clone)]
pub struct Config {
    pub(crate) auth_endpoint: AuthEndPoint,
    pub(crate) client_id: ClientID,
    pub(crate) client_secret: ClientSecret,
    pub(crate) token_endpoint: TokenEndPoint,
    pub(crate) redirect_uri: RedirectURI,
}
// ==========impl Config==========
impl Config {
    /// Returns a new `ConfigBuilder` instance to create a `Config` object.  
    /// This method provides a convenient way to start building a `Config` instance.
    pub fn builder() -> ConfigBuilder {
        ConfigBuilder::default()
    }
}

/// Provides a convenient way to create a `Config` instance step by step.  
/// This ensures that all required fields are set before the `Config`
/// object is constructed.
///
/// # Example
/// ```rust,no_run
/// use your_crate::config::ConfigBuilder;
///
/// let builder = ConfigBuilder::new()
///     .auth_endpoint("https://accounts.google.com/o/oauth2/auth")
///     .client_id("your-client-id")
///     .client_secret("your-client-secret")
///     .token_endpoint("https://oauth2.googleapis.com/token")
///     .redirect_uri("https://your-app.com/callback");
///
/// let config = builder.build();
/// ```
#[derive(Debug, Clone, Default)]
pub struct ConfigBuilder {
    auth_endpoint: AuthEndPoint,
    client_id: ClientID,
    client_secret: ClientSecret,
    token_endpoint: TokenEndPoint,
    redirect_uri: RedirectURI,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub(crate) struct ClientID(pub String);

#[derive(Debug, Clone, Default, PartialEq)]
pub(crate) struct ClientSecret(pub String);

#[derive(Debug, Clone, Default)]
pub(crate) struct TokenEndPoint(pub String);

#[derive(Debug, Clone, Default)]
pub(crate) struct RedirectURI(pub String);



// ==========impl ConfigBuilder==========
impl ConfigBuilder {
    /// Creates a new `ConfigBuilder` instance with default values.
    pub fn new() -> Self {
        ConfigBuilder::default()
    }

    /// Sets the authorization endpoint URL.
    pub fn auth_endpoint(mut self, auth_endpoint: &str) -> ConfigBuilder {
        self.auth_endpoint = AuthEndPoint(auth_endpoint.to_string());
        self
    }

    /// Constructs a `Config` instance with the provided values.
    pub fn build(self) -> Config {
        Config {
            auth_endpoint: self.auth_endpoint,
            client_id: self.client_id,
            client_secret: self.client_secret,
            token_endpoint: self.token_endpoint,
            redirect_uri: self.redirect_uri,
        }
    }

    /// Sets the client ID obtained from Google Cloud Console.
    pub fn client_id(mut self, client_id: &str) -> Self {
        self.client_id = ClientID(client_id.to_string());
        self
    }

    /// Sets the client secret associated with the client ID.
    pub fn client_secret(mut self, client_secret: &str) -> Self {
        self.client_secret = ClientSecret(client_secret.to_string());
        self
    }

    /// Sets the token exchange endpoint URL.
    pub fn token_endpoint(mut self, token_endpoint: &str) -> Self {
        self.token_endpoint = TokenEndPoint(token_endpoint.to_string());
        self
    }

    /// Sets the redirect URI registered in Google Cloud Console.
    pub fn redirect_uri(mut self, redirect_url: &str) -> Self {
        self.redirect_uri = RedirectURI(redirect_url.to_string());
        self
    }
}

// ==========Tests==========
#[cfg(test)]
mod tests {
    use crate::config::Config;

    use super::ConfigBuilder;

    #[test]
    fn test_config_builder() {
        let auth_endpoint = "https://auth.example.com/auth";
        let client_id = "my_client_id";
        let client_secret = "my_secret";
        let token_endpoint = "https://token.example.com";
        let redirect_uri = "https://redirect.example.com";

        let config = ConfigBuilder::new()
            .auth_endpoint(auth_endpoint)
            .client_id(client_id)
            .client_secret(client_secret)
            .token_endpoint(token_endpoint)
            .redirect_uri(redirect_uri)
            .build();

        assert_eq!(config.auth_endpoint.0, auth_endpoint);
        assert_eq!(config.client_id.0, client_id);
        assert_eq!(config.client_secret.0, client_secret);
        assert_eq!(config.token_endpoint.0, token_endpoint);
        assert_eq!(config.redirect_uri.0, redirect_uri);
    }

    #[test]
    fn test_config_builder_default() {
        let config_builder = ConfigBuilder::default();

        assert_eq!(config_builder.auth_endpoint.0, "");
        assert_eq!(config_builder.client_id.0, "");
        assert_eq!(config_builder.client_secret.0, "");
        assert_eq!(config_builder.token_endpoint.0, "");
        assert_eq!(config_builder.redirect_uri.0, "");
    }

    #[test]
    fn test_config_builder_method_chain() {
        let auth_endpoint = "https://auth.example.com/auth";
        let client_id = "my_client_id";
        let client_secret = "my_secret";
        let token_endpoint = "https://token.example.com";
        let redirect_uri = "https://redirect.example.com";

        let config = Config::builder()
            .auth_endpoint(auth_endpoint)
            .client_id(client_id)
            .client_secret(client_secret)
            .token_endpoint(token_endpoint)
            .redirect_uri(redirect_uri)
            .build();

        assert_eq!(config.auth_endpoint.0, auth_endpoint);
        assert_eq!(config.client_id.0, client_id);
        assert_eq!(config.client_secret.0, client_secret);
        assert_eq!(config.token_endpoint.0, token_endpoint);
        assert_eq!(config.redirect_uri.0, redirect_uri);
    }
}
