use thiserror::Error;

#[derive(Debug, Clone, Error)]
pub enum Error {
    #[error("Failed to Decode IDToken")]
    Decode,
    #[error("Failed to Deserialize IDToken")]
    Deserialize,
    #[error("Failed to generate CSRF token")]
    GenToken,
    #[error("CSRF token not matched")]
    CSRFNotMatch,
    #[error("Failed to parse url")]
    ScopeMismatch,
    #[error("Failed to parse url")]
    URL,
}
