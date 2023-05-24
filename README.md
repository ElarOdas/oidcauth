# OIDC-Auth

## What is oidc-auth

oidc auth is a go-chi middleware for verification and authentication of a Open ID Connect token. Results are send down the request context.

## How does it work

OIDC-Auth utilizes [OIDC Discovery](https://openid.net/specs/openid-connect-discovery-1_0.html#WellKnownRegistry),specifically the Well-Known Registry, to gather required information for Verification.

Currently only offline verification is fully implemented. Online verification is still in progress of being implemented
Multiple issuers are supported.

Of note: This package is heavily inspired by the [jwtauth Middleware](https://github.com/go-chi/jwtauth) and [jwx](https://github.com/lestrrat-go/jwx/).

## Usage

For now the intended user is only me.

## How to

### Develop

Feel free to fork the project!

### Use

Right now oidc-auth is under development and should therefore never be used in a production environment.
The package consists of four elements

-   Offline
    -   Takes issuerUrl & audience
    -   Supplies keyset of the issuer via jwks_uri endpoint of issuer
    -   Regularly updates via jwk.Cache
    -   Errors according to [RFC6750](https://www.rfc-editor.org/rfc/rfc6750#section-3.1)
-   Online (not implemented)

    -   Takes issuerUrl,clientId & clientSecret
    -   Supplies introspection endpoint of issuer
    -   Only Basic Auth supported at the moment.

-   Verifier( Offline | Online) Middleware

    -   Go chi compatible middleware
    -   Verifies the token from the header, cookie or path query
    -   Can also handle multiple issuers with Offline/Online Slices

-   Authenticator Middleware
    -   Takes token & verification errors from Verifier
    -   Handles reaction to valid & invalid tokens
    -   Can be replaced by custom authenticator

### Test

Right now there is no testing.

## Plans

-   Testing
-   More extensive documentation
-   Online verification
