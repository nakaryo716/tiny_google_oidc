# tiny_google_oidc
[![crates.io](https://img.shields.io/crates/v/tiny_google_oidc.svg)](https://crates.io/crates/tiny_google_oidc)
[![docs.rs](https://img.shields.io/docsrs/tiny_google_oidc/latest)](https://docs.rs/tiny_google_oidc)
![CI](https://github.com/nakaryo716/tiny_google_oidc/workflows/CI/badge.svg) 
![GitHub License](https://img.shields.io/github/license/nakaryo716/tiny_google_oidc)

Tiny library for Google's OpenID Connect.  
Implementation in server flow  
[google document](https://developers.google.com/identity/openid-connect/openid-connect)
## Feature
- Generate a CSRF Token
- Generate an authentication request URL (code) for Google
- Verify CSRF token and retrieve id_token
- Exchange code for id_token (using reqwest)
- Decode id_token (Base64URLDecode) to get user information
- Refresh access token using refresh token (using reqwest)
- Revoke access/refresh token (using reqwest)
## Caution
This library is designed for direct communication with Google over HTTPS.  
It does not validate the id_token when converting it to a JWT,  
so the id_token cannot be passed to other components of your app.
[See document](https://developers.google.com/identity/openid-connect/openid-connect#obtainuserinfo)
## Example
Here's hou you can use this library with the axum framework.
### 1. Create Config
First, We create `Config` struct the is including Client ID, Secrets, etc...
```rust
let oidc_cfg = ConfigBuilder::new()
    .auth_endpoint("https://accounts.google.com/o/oauth2/auth")
    .client_id("my_client_id")
    .client_secret("my_client_secret")
    .token_endpoint("https://oauth2.googleapis.com/token")
    .redirect_uri("http://localhost/auth/callback")
    .build();
```
## 2. Login Handler
Here's an example handler to start the login flow.
```rust
async fn login(
    State(app_state): State<Arc<AppState>>,
    jar: CookieJar,
) -> Result<impl IntoResponse, AppError> {
    // 1. generate redirect information for the OIDC authentication flow
    let (csrf_token, _nonce, redirect_uri) = generate_auth_redirect(
        &app_state.oidc_cfg,
        AccessType::Online,
        AdditionalScope::Both,
    )
    .map_err(WrapOIDCError)?;

    // 2. Generate a key to store the csrf_token in Redis or memory,
    //    and store it
    // 3. Create and set a cookie
    // ...(please implement these part as appropirate for your application)

    // 4. Set the Cookie ant redirect to the authorization server
    Ok((jar.add(cookie), Redirect::to(&redirect_uri)))
}
```
### 3. Callback Handler
Here’s an example of a callback handler for when the provider (like Google) redirects back.
```rust
async fn callback(
    State(app_state): State<Arc<AppState>>,
    jar: CookieJar,
    req: Request,
) -> Result<impl IntoResponse, AppError> {
    // 1. Retrieve the csrf_token key from the cookie, then fetch the stored csrf_token

    // 2. Verify the CSRF token & build the IDToken request
    let id_token_req = create_id_token_request(&app_state.oidc_cfg, &csrf_token_val, req)
        .map_err(WrapOIDCError)?;

    // 3. Send request to Google
    let id_token_res = send_id_token_req(&id_token_req)
        .await
        .map_err(WrapOIDCError)?;

    // 4. Encode the IDToken from the raw string
    let id_token = IDToken::from_id_token_raw(id_token_res.id_token()).map_err(WrapOIDCError)?;

    // print id_token
    println!("----IDToken----");
    println!("{id_token:#?}");

    Ok((StatusCode::OK, "login success"))
}
```

Of course, you can use this library with other framework as well!

See [example](examples/easy/id_token.rs) for more detailes.

## Contributing
We are currently working on the official contribution guidelines.

However, we **welcome bug reports, feature requests, and questions via [GitHub Issues](https://github.com/nakaryo716/tiny_google_oidc/issues)**!

Your feedback is very much appreciated and will help make this library better for everyone.  
Thank you for your interest and support!

## License
tiny_google_oidc is provided under the MIT license.See [LICENSE](LICENSE)
