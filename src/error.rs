use http::StatusCode;
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
    ParseURL,
    #[error("Failed to deserialize JSON")]
    DeserializeJson,
    #[error("Failed to send data")]
    Send,
    #[error("Send request but failed")]
    SendStatus(StatusCode),
    #[error("Parameters not found")]
    ParamsNotFound,
}
