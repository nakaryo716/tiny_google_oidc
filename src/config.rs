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
//! ```rust
//! use tny_google_oidc::config::Config;
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
/// ```rust
/// use tiny_google_oidc::config::Config;
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

impl Config {
    /// Returns a new `ConfigBuilder` instance to create a `Config` object.  
    /// This method provides a convenient way to start building a `Config` instance.
    pub fn builder() -> ConfigBuilder {
        ConfigBuilder::default()
    }

    pub fn auth_endpoint(&self) -> &AuthEndPoint {
        &self.auth_endpoint
    }

    pub fn client_id(&self) -> &ClientID {
        &self.client_id
    }

    pub fn client_secret(&self) -> &ClientSecret {
        &self.client_secret
    }

    pub fn token_endpoint(&self) -> &TokenEndPoint {
        &self.token_endpoint
    }

    pub fn redirect_uri(&self) -> &RedirectURI {
        &self.redirect_uri
    }
}

/// Provides a convenient way to create a `Config` instance step by step.  
/// This ensures that all required fields are set before the `Config`
/// object is constructed.
///
/// # Example
/// ```rust
/// use tiny_google_oidc::config::ConfigBuilder;
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

impl ConfigBuilder {
    /// Creates a new `ConfigBuilder` instance with default values.
    pub fn new() -> Self {
        ConfigBuilder::default()
    }

    /// Sets the authorization endpoint URL.
    pub fn auth_endpoint<T: Into<AuthEndPoint>>(mut self, auth_endpoint: T) -> ConfigBuilder {
        self.auth_endpoint = auth_endpoint.into();
        self
    }

    /// Sets the client ID obtained from Google Cloud Console.
    pub fn client_id<T: Into<ClientID>>(mut self, client_id: T) -> Self {
        self.client_id = client_id.into();
        self
    }

    /// Sets the client secret associated with the client ID.
    pub fn client_secret<T: Into<ClientSecret>>(mut self, client_secret: T) -> Self {
        self.client_secret = client_secret.into();
        self
    }

    /// Sets the token exchange endpoint URL.
    pub fn token_endpoint<T: Into<TokenEndPoint>>(mut self, token_endpoint: T) -> Self {
        self.token_endpoint = token_endpoint.into();
        self
    }

    /// Sets the redirect URI registered in Google Cloud Console.
    pub fn redirect_uri<T: Into<RedirectURI>>(mut self, redirect_uri: T) -> Self {
        self.redirect_uri = redirect_uri.into();
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
}

/// Represents the authorization endpoint URL used in Google's OpenID Connect flow.
///
/// This tuple struct is a simple wrapper around a `String` and is used to specify
/// the URL where the authorization request is sent.
///
/// # Purpose
/// The `AuthEndPoint` struct is used as part of the `Config` to define the endpoint
/// for initiating the OpenID Connect authentication flow.
///
/// # Example
/// ```rust
/// use tiny_google_oidc::config::AuthEndPoint;
/// let endpoint_str = "https://accounts.google.com/o/oauth2/auth";
/// let auth_endpoint: AuthEndPoint = endpoint_str.into();
/// assert_eq!(auth_endpoint, AuthEndPoint(endpoint_str.to_string()))
/// ```
#[derive(Debug, Clone, Default, PartialEq)]
pub struct AuthEndPoint(pub(crate) String);

impl AuthEndPoint {
    pub fn new(endpoint: String) -> Self {
        AuthEndPoint(endpoint)
    }

    pub fn value(&self) -> &str {
        &self.0
    }
}

impl From<&str> for AuthEndPoint {
    fn from(value: &str) -> Self {
        AuthEndPoint(value.to_string())
    }
}

impl From<String> for AuthEndPoint {
    fn from(value: String) -> Self {
        AuthEndPoint(value)
    }
}

/// Represents the client ID used in Google's OpenID Connect flow.
///
/// This tuple struct is a simple wrapper around a `String` and is used to securely store
/// the client ID required for authentication and token exchange.
///
/// # Purpose
/// The `ClientID` struct is used as part of the `Config` to define the unique identifier
/// for your application. This ID is provided by Google Cloud Console when registering
/// your application.
///
/// # Example
/// ```rust
/// use tiny_google_oidc::config::ClientID;
///
/// let client_id_str = "your-client-id";
/// let client_id: ClientID = client_id_str.into();
/// assert_eq!(client_id, ClientID(client_id_str.to_string()));
/// ```
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ClientID(pub(crate) String);

impl ClientID {
    pub fn new(id: String) -> Self {
        ClientID(id)
    }

    pub fn value(&self) -> &str {
        &self.0
    }
}

impl From<&str> for ClientID {
    fn from(value: &str) -> Self {
        ClientID(value.to_string())
    }
}

impl From<String> for ClientID {
    fn from(value: String) -> Self {
        ClientID(value)
    }
}

/// Represents the client secret associated with the client ID in Google's OpenID Connect flow.
///
/// This tuple struct is a simple wrapper around a `String` and is used to securely store
/// the client secret required for authentication and token exchange.
///
/// # Purpose
/// The `ClientSecret` struct is used as part of the `Config` to define the secret key
/// associated with the client ID. This secret is provided by Google Cloud Console
/// when registering your application.
///
/// # Example
/// ```rust
/// use tiny_google_oidc::config::ClientSecret;
///
/// let secret_str = "your-client-secret";
/// let client_secret: ClientSecret = secret_str.into();
/// assert_eq!(client_secret, ClientSecret(secret_str.to_string()));
/// ```
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ClientSecret(pub(crate) String);

impl ClientSecret {
    pub fn new(secret: String) -> Self {
        ClientSecret(secret)
    }

    pub fn value(&self) -> &str {
        &self.0
    }
}

impl From<&str> for ClientSecret {
    fn from(value: &str) -> Self {
        ClientSecret(value.to_string())
    }
}

impl From<String> for ClientSecret {
    fn from(value: String) -> Self {
        ClientSecret(value)
    }
}

/// Represents the token endpoint URL used in Google's OpenID Connect flow.
///
/// This tuple struct is a simple wrapper around a `String` and is used to specify
/// the URL where the token exchange request is sent.
///
/// # Purpose
/// The `TokenEndPoint` struct is used as part of the `Config` to define the endpoint
/// for exchanging an authorization code for tokens (e.g., ID token, access token).
///
/// # Example
/// ```rust
/// use tiny_google_oidc::config::TokenEndPoint;
///
/// let token_endpoint_str = "https://oauth2.googleapis.com/token";
/// let token_endpoint: TokenEndPoint = token_endpoint_str.into();
/// assert_eq!(token_endpoint, TokenEndPoint(token_endpoint_str.to_string()));
/// ```
#[derive(Debug, Clone, Default, PartialEq)]
pub struct TokenEndPoint(pub(crate) String);

impl TokenEndPoint {
    pub fn new(endpoint: String) -> Self {
        TokenEndPoint(endpoint)
    }

    pub fn value(&self) -> &str {
        &self.0
    }
}

impl From<&str> for TokenEndPoint {
    fn from(value: &str) -> Self {
        TokenEndPoint(value.to_string())
    }
}

impl From<String> for TokenEndPoint {
    fn from(value: String) -> Self {
        TokenEndPoint(value)
    }
}

/// Represents the redirect URI registered in Google's OpenID Connect flow.
///
/// This tuple struct is a simple wrapper around a `String` and is used to specify
/// the URI where Google redirects the user after authentication.
///
/// # Purpose
/// The `RedirectURI` struct is used as part of the `Config` to define the URI
/// that is registered in the Google Cloud Console for your application. This URI
/// must match the one provided during the authentication request.
///
/// # Example
/// ```rust
/// use tiny_google_oidc::config::RedirectURI;
///
/// let redirect_uri_str = "https://your-app.com/callback";
/// let redirect_uri: RedirectURI = redirect_uri_str.into();
/// assert_eq!(redirect_uri, RedirectURI(redirect_uri_str.to_string()));
/// ```
#[derive(Debug, Clone, Default, PartialEq)]
pub struct RedirectURI(pub(crate) String);

impl RedirectURI {
    pub fn new(uri: String) -> Self {
        RedirectURI(uri)
    }

    pub fn value(&self) -> &str {
        &self.0
    }
}

impl From<&str> for RedirectURI {
    fn from(value: &str) -> Self {
        RedirectURI(value.to_string())
    }
}

impl From<String> for RedirectURI {
    fn from(value: String) -> Self {
        RedirectURI(value)
    }
}

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
