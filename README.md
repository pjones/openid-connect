OpenID Connect 1.0 in Haskell
=============================

An OpenID Connect 1.0 compliant library written in Haskell.

The primary goals of this package are security and usability.

Client Features
---------------

This library mostly focuses on the client side of the OpenID Connect
protocol.

Supported flows:

  * [x] Authorization Code (see `OpenID.Connect.Client.Flow.AuthorizationCode`) (§3.1)
  * [ ] Implicit (partial implementation, patches welcome) (§3.2)
  * [ ] Hybrid (partial implementation, patches welcome) (§3.3)

Significant features:

  * ID Token validation via the [jose][] library (§2)
  * Additional OIDC claim validation (e.g., `nonce`, `azp`, etc.) (§2)
  * Full support for all defined forms of client authentication (§9)
  * Handles session cookie generation and validation (§3.1.2.1, §15.5.2)

Provider Features
-----------------

Some utility types and functions are available to assist in the
writing of an OIDC Provider:

  * Discovery document (OpenID Connect Discovery 1.0 §3)
  * Key generation (simple wrapper around [jose][])

[jose]: https://hackage.haskell.org/package/jose
