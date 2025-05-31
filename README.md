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

## Contributing
We are currently working on the official contribution guidelines.

However, we **welcome bug reports, feature requests, and questions via [GitHub Issues](https://github.com/nakaryo716/tiny_google_oidc/issues)**!

Your feedback is very much appreciated and will help make this library better for everyone.  
Thank you for your interest and support!

## License
tiny_google_oidc is provided under the MIT license.See [LICENSE](LICENSE)
