[![tests](https://github.com/sthenauth/openid-connect/actions/workflows/tests.yml/badge.svg)](https://github.com/sthenauth/openid-connect/actions/workflows/tests.yml)

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
  * Dynamic Client Registration 1.0.

Provider Features
-----------------

Some utility types and functions are available to assist in the
writing of an OIDC Provider:

  * Discovery document (OpenID Connect Discovery 1.0 §3)
  * Key generation (simple wrapper around [jose][])

[jose]: https://hackage.haskell.org/package/jose

Certification Status
--------------------

We plan on fully [certifying][cert] this implementation using the
following profiles:

  * [ ] Basic Relying Party
  * [ ] Implicit Relying Party
  * [ ] Hybrid Relying Party
  * [ ] Relying Party Using Configuration Information
  * [ ] Dynamic Relying Party
  * [ ] Form Post Relying Party

[cert]: https://openid.net/certification/instructions/

Specifications and RFCs
-----------------------

  * [OpenID Connect Core](http://openid.net/specs/openid-connect-core-1_0.html)
  * [OpenID Connect Discovery](http://openid.net/specs/openid-connect-discovery-1_0.html)
  * [The OAuth 2.0 Authorization Framework (RFC6749)](https://tools.ietf.org/html/rfc6749)
  * [JSON Web Token (RFC7519)](https://tools.ietf.org/html/rfc7519)
  * [JSON Web Signature (RFC7515)](https://tools.ietf.org/html/rfc7515)
  * [JSON Web Key (RFC7517)](https://www.rfc-editor.org/rfc/rfc7517.htmlhttps://www.rfc-editor.org/rfc/rfc7517.html)
