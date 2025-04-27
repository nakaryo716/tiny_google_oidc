use bytes::Bytes;
use cookie::Cookie;
use http::{
    header::{COOKIE, LOCATION}, HeaderValue, Request, Response, StatusCode
};
use http_body_util::{BodyExt, Empty, Full, combinators::BoxBody};
use hyper::body::Incoming;
use redis::{aio::ConnectionManager, cmd};

use crate::login_service::SESSION_COOKIE_KEY;

pub struct ProtectedService {
    redis_conn: ConnectionManager,
}

impl ProtectedService {
    pub fn new(redis_conn: ConnectionManager) -> Self {
        Self { redis_conn }
    }

    pub async fn serve(
        &mut self,
        req: Request<Incoming>,
    ) -> anyhow::Result<Response<BoxBody<Bytes, std::io::Error>>> {
        // Get Cookie Header values
        let cookie_header_val = match req.headers().get(COOKIE) {
            Some(v) => v,
            None => return Ok(see_location_res("/")),
        };
        let cookies = Self::parse_cookies(&cookie_header_val)?;


        // Find a Cookie with key "session"
        let session_id = match cookies.iter().find(|c| c.name() == SESSION_COOKIE_KEY) {
            Some(cookie) => cookie.value(),
            None => return Ok(see_location_res("/")),
        };

        // Verify session(Redis)
        match self.verify_session(&session_id).await? {
            Some(v) => {
                let txt = format!("Hi! your id is {}", v);
                let res = Response::builder()
                    .status(StatusCode::OK)
                    .body(Full::new(Bytes::from(txt)).map_err(|e| match e {}).boxed())
                    .unwrap();
                Ok(res)
            }
            None => Ok(see_location_res("/")) 
        }
    }

    fn parse_cookies(header_val: &HeaderValue) -> anyhow::Result<Vec<Cookie<'_>>> {
        let values = header_val.to_str()?;

        let cookies: Vec<Cookie<'_>> = values
            .split(';')
            .filter_map(|c| Cookie::parse(c.trim().to_string()).ok())
            .collect();
        Ok(cookies)
    }

    async fn verify_session(&mut self, session_id: &str) -> anyhow::Result<Option<String>> {
        let session = cmd("GET")
            .arg(session_id)
            .query_async::<Option<String>>(&mut self.redis_conn)
            .await?;
        Ok(session)
    }
}

pub fn see_location_res(url: &str) -> Response<BoxBody<Bytes, std::io::Error>> {
    Response::builder()
        .status(StatusCode::SEE_OTHER)
        .header(LOCATION, url)
        .body(Empty::new().map_err(|e| match e {}).boxed())
        .unwrap()
}
