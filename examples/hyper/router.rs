use std::{convert::Infallible, pin::Pin, sync::Arc};

use bytes::Bytes;
use http_body_util::{combinators::BoxBody, BodyExt, Empty, StreamBody};
use hyper::{Request, Response, StatusCode, body::Incoming, service::Service};
use redis::aio::ConnectionManager;
use tiny_google_oidc::config::Config;
use tokio::fs::File;
use tokio_util::io::ReaderStream;
use futures_util::TryStreamExt;

use crate::{protected::ProtectedService, login_service::LoginService};

#[derive(Clone)]
pub struct Router {
    config: Arc<Config>,
    redis_conn: ConnectionManager,
}

impl Router {
    pub fn new(config: Arc<Config>, redis_conn: ConnectionManager) -> Self {
        Self {
            config: config,
            redis_conn,
        }
    }

    pub fn config(&self) -> Arc<Config> {
        Arc::clone(&self.config)
    }

    pub fn redis_conn(&self) -> ConnectionManager {
        self.redis_conn.clone()
    }
}

// Routing
// - "/" return html file
// - "/auth" is open id connect auth entry point 
// - "/auth/callback" is redirect path from Google
// - "/protected" provides information about the user who has a session
impl Service<Request<Incoming>> for Router {
    type Response = Response<BoxBody<Bytes, std::io::Error>>;
    type Error = Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn call(&self, req: Request<Incoming>) -> Self::Future {
        let redis_conn = self.redis_conn();
        let config = self.config();

        Box::pin(async move {
            let default = Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Empty::new().map_err(|e| match e {}).boxed())
                .unwrap();

            match req.uri().path().to_string().as_ref() {
                "/" => {
                    let file = File::open("./examples/hyper/index.html").await.unwrap();
                    let reader_stream = ReaderStream::new(file);

                    let a = StreamBody::new(reader_stream.map_ok(hyper::body::Frame::data));
                    let box_body = BodyExt::boxed(a);

                    let res = Response::builder()
                        .status(StatusCode::OK)
                        .body(box_body)
                        .unwrap();
                    Ok(res)
                }
                "/auth" => {
                    let res = LoginService::new(config, redis_conn)
                        .entry()
                        .await
                        .unwrap_or(default);
                    Ok(res)
                }
                "/auth/callback" => {
                    let res = LoginService::new(config, redis_conn)
                        .callback(req)
                        .await
                        .unwrap_or(default);
                    Ok(res)
                }
                "/protected" => {
                    let res = ProtectedService::new(redis_conn)
                        .serve(req)
                        .await
                        .unwrap_or(default);
                    Ok(res)
                }
                _ => {
                    let res = Response::builder()
                        .status(StatusCode::NOT_FOUND)
                        .body(Empty::new().map_err(|e| match e {}).boxed())
                        .unwrap();
                    Ok(res)
                }
            }
        })
    }
}
