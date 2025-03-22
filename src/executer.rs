//! Provides an asynchronous execution framework for sending HTTP requests to Google.   
//! 
//! This module:
//! - Defines the Executer trait, which provides a unified interface for making HTTP requests.
//! - Implements executers for ID token requests, refresh token requests, and token revocation requests.

use std::{collections::HashMap, error::Error, pin::Pin};

use crate::{
    id_token::{IDTokenRequest, IDTokenResponse},
    refresh_token::{RefreshTokenRequest, RefreshTokenResponse},
    revoke_token::RevokeTokenRequest,
};
use http::StatusCode;
use reqwest::{Client, Url};
use thiserror::Error;
use tracing::error;

/// generic asynchronous execution interface for sending HTTP requests.
/// Key Components:
/// - R: The request type that the executer will handle.
/// - Response: The expected response type.
/// - Error: The error type that will be returned on failure.
/// - Future: The asynchronous execution result, returning either Response or Error
pub trait Executer<'a, Req>
where
    Req: Send,
{
    type Response;
    type Error: Error;
    type Future: Future<Output = Result<Self::Response, Self::Error>> + Send + 'a;

    fn execute(&'a self, req: &'a Req) -> Self::Future;
}

/// Defines possible errors that can occur during request execution.
#[derive(Debug, Clone, Error)]
pub enum ExecuteError {
    #[error("Failed")]
    Failed,
    #[error("Failed to parse data")]
    Parse,
    #[error("Failed to send request")]
    Send,
    #[error("Failed to parse url")]
    URL,
}

/// Handles ID token requests to obtain an access token and ID token.
pub struct IDTokenExe;

/// Request Workflow
/// 1. Parse the token endpoint URL.
/// 2. Prepare the request parameters.
/// 3. Send an HTTP POST request.
/// 4. Parse and return the response as IDTokenResponse.
impl<'a> Executer<'a, IDTokenRequest> for IDTokenExe {
    type Response = IDTokenResponse;
    type Error = ExecuteError;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send + 'a>>;

    fn execute(&'a self, req: &'a IDTokenRequest) -> Self::Future {
        Box::pin(async move {
            let url = Url::parse(req.token_endpoint()).map_err(|e| {
                error!("Failed to pase url: {:?}", e);
                ExecuteError::URL
            })?;

            let mut params = HashMap::new();
            params.insert("code", req.code());
            params.insert("client_id", req.client_id());
            params.insert("client_secret", req.client_secret());
            params.insert("redirect_uri", req.redirect_uri());
            params.insert("grant_type", req.grant_type());

            let client = Client::new();
            let res = client
                .post(url)
                .header("Content-Type", "application/x-www-form-urlencoded")
                .form(&params)
                .send()
                .await
                .map_err(|e| {
                    error!("Failed to send request: {:?}", e);
                    ExecuteError::Send
                })?;
            let res_json = res.json::<IDTokenResponse>().await.map_err(|e| {
                error!("Failed to parse JSON: {:?}", e);
                ExecuteError::Parse
            })?;
            Ok(res_json)
        })
    }
}

/// Handles revocation of access tokens or refresh tokens.
pub struct RevokeTokenExe;

/// Request Workflow
/// 1. Prepare the revocation endpoint URL.
/// 2. Send the token to be revoked.
/// 3. Return the HTTP status code indicating success or failure.
impl<'a> Executer<'a, RevokeTokenRequest> for RevokeTokenExe {
    type Response = StatusCode;
    type Error = ExecuteError;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send + 'a>>;

    fn execute(&'a self, req: &'a RevokeTokenRequest) -> Self::Future {
        Box::pin(async move {
            let url = &req.end_point;

            let mut param = HashMap::new();
            param.insert("token", req.inner_value());
            let client = Client::new();
            let status_code = client
                .post(url)
                .header("Content-Type", "application/x-www-form-urlencoded")
                .form(&param)
                .send()
                .await
                .map_err(|e| {
                    error!("Failed to send request: {:?}", e);
                    ExecuteError::Send
                })?
                .status();
            Ok(status_code)
        })
    }
}

/// Handles refreshing access tokens using a refresh token.
pub struct RefreshTokenExe;

/// Request Workflow
/// 1. Prepare the request parameters.
/// 2. Send an HTTP POST request to Google's token endpoint.
/// 3. Parse and return the new RefreshTokenResponse.
impl<'a> Executer<'a, RefreshTokenRequest> for RefreshTokenExe {
    type Response = RefreshTokenResponse;
    type Error = ExecuteError;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send + 'a>>;

    fn execute(&'a self, req: &'a RefreshTokenRequest) -> Self::Future {
        Box::pin(async move {
            let mut param = HashMap::new();
            param.insert("client_id", &req.client_id.0);
            param.insert("client_secret", &req.client_secret.0);
            param.insert("refresh_token", &req.refresh_token.0);
            param.insert("grant_type", &req.grant_type);

            let client = Client::new();
            let res = client
                .post(&req.refresh_token_endpoint)
                .header("Content-Type", "application/x-www-form-urlencoded")
                .form(&param)
                .send()
                .await
                .map_err(|e| {
                    error!("Failed to send request: {:?}", e);
                    ExecuteError::Send
                })?;
            let res_json = res.json::<RefreshTokenResponse>().await.map_err(|e| {
                error!("Failed to parse JSON: {:?}", e);
                ExecuteError::Parse
            })?;
            Ok(res_json)
        })
    }
}
