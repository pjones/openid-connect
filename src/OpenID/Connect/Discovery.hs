{-|

Copyright:

  This file is part of the package openid-connect.  It is subject to
  the license terms in the LICENSE file found in the top-level
  directory of this distribution and at:

    https://code.devalot.com/open/openid-connect

  No part of this package, including this file, may be copied,
  modified, propagated, or distributed except according to the terms
  contained in the LICENSE file.

License: BSD-2-Clause

-}
module OpenID.Connect.Discovery
  ( Discovery(..)
  , ProviderDiscoveryURI
  ) where

--------------------------------------------------------------------------------
-- Imports:
import Crypto.JOSE.JWA.JWS
import Data.List.NonEmpty (NonEmpty)
import Data.Text (Text)
import GHC.Generics (Generic)
import qualified Network.URI as Network
import OpenID.Connect.Authentication
import OpenID.Connect.JSON
import OpenID.Connect.Scope

--------------------------------------------------------------------------------
-- | URI pointing to an OpenID Connect provider's discovery document.
--
-- If necessary, the /well-known/ discovery path will be added
-- automatically.
--
-- A list of certified OpenID Connect providers can be found here:
-- <https://openid.net/certification/>
--
-- @since 0.1.0.0
type ProviderDiscoveryURI = Network.URI

--------------------------------------------------------------------------------
-- | The provider discovery document as specified in
-- /OpenID Connect Discovery 1.0/ §3.
--
-- @since 0.1.0.0
data Discovery = Discovery
  { issuer :: URI
    -- ^ URL using the https scheme with no query or fragment
    -- component that the OP asserts as its Issuer Identifier.

  , authorizationEndpoint :: URI
    -- ^ URL of the OP's OAuth 2.0 Authorization Endpoint.

  , tokenEndpoint :: Maybe URI
    -- ^ URL of the OP's OAuth 2.0 Token Endpoint.  Not provided when
    -- using the implicit flow.

  , userinfoEndpoint :: Maybe URI
    -- ^ URL of the OP's UserInfo Endpoint.

  , jwksUri :: URI
    -- ^ URL of the OP's JSON Web Key Set document.

  , registrationEndpoint :: Maybe URI
    -- ^ URL of the OP's Dynamic Client Registration Endpoint.

  , scopesSupported :: Maybe Scope
    -- ^ List of OAuth 2.0 scope values that this server supports.

  , responseTypesSupported :: NonEmpty Text
    -- ^ Array containing a list of the OAuth 2.0 @response_type@
    -- values that this OP supports.

  , responseModesSupported :: Maybe (NonEmpty Text)
    -- ^ JSON array containing a list of the OAuth 2.0 response_mode
    -- values that this OP supports.

  , grantTypesSupported :: Maybe (NonEmpty Text)
    -- ^ JSON array containing a list of the OAuth 2.0 Grant Type
    -- values that this OP supports.

  , acrValuesSupported :: Maybe (NonEmpty Text)
    -- ^ JSON array containing a list of the Authentication Context
    -- Class References that this OP supports.

  , subjectTypesSupported :: NonEmpty Text
    -- ^ JSON array containing a list of the Subject Identifier types
    -- that this OP supports.

  , idTokenSigningAlgValuesSupported :: NonEmpty Alg
    -- ^ JSON array containing a list of the JWS signing algorithms
    -- (alg values) supported by the OP for the ID Token to encode the
    -- Claims in a JWT.

  , idTokenEncryptionAlgValuesSupported :: Maybe (NonEmpty Text)
    -- ^ JSON array containing a list of the JWE encryption algorithms
    -- (alg values) supported by the OP for the ID Token to encode the
    -- Claims in a JWT.

  , idTokenEncryptionEncValuesSupported :: Maybe (NonEmpty Text)
    -- ^ JSON array containing a list of the JWE encryption algorithms
    -- (enc values) supported by the OP for the ID Token to encode the
    -- Claims in a JWT.

  , userinfoSigningAlgValuesSupported :: Maybe (NonEmpty Alg)
    -- ^ JSON array containing a list of the JWS signing algorithms
    -- (alg values).

  , userinfoEncryptionAlgValuesSupported :: Maybe (NonEmpty Text)
    -- ^ JSON array containing a list of the JWE encryption algorithms
    -- (alg values).

  , userinfoEncryptionEncValuesSupported :: Maybe (NonEmpty Text)
    -- ^ JSON array containing a list of the JWE encryption algorithms
    -- (enc values).

  , requestObjectSigningAlgValuesSupported :: Maybe (NonEmpty Alg)
    -- ^ JSON array containing a list of the JWS signing algorithms
    -- (alg values) supported by the OP for Request Objects, which are
    -- described in Section 6.1 of OpenID Connect Core 1.0.

  , requestObjectEncryptionAlgValuesSupported :: Maybe (NonEmpty Text)
    -- ^ JSON array containing a list of the JWE encryption algorithms
    -- (alg values) supported by the OP for Request Objects. These
    -- algorithms are used both when the Request Object is passed by
    -- value and when it is passed by reference.

  , requestObjectEncryptionEncValuesSupported :: Maybe (NonEmpty Text)
    -- ^ JSON array containing a list of the JWE encryption algorithms
    -- (enc values) supported by the OP for Request Objects. These
    -- algorithms are used both when the Request Object is passed by
    -- value and when it is passed by reference.

  , tokenEndpointAuthMethodsSupported :: Maybe (NonEmpty ClientAuthentication)
    -- ^ JSON array containing a list of Client Authentication methods
    -- supported by this Token Endpoint.

  , tokenEndpointAuthSigningAlgValuesSupported :: Maybe (NonEmpty Alg)
    -- ^ JSON array containing a list of the JWS signing algorithms
    -- (alg values) supported by the Token Endpoint for the signature
    -- on the JWT used to authenticate the Client at the Token
    -- Endpoint for the private_key_jwt and client_secret_jwt
    -- authentication methods.

  , displayValuesSupported :: Maybe (NonEmpty Text)
    -- ^ JSON array containing a list of the display parameter values
    -- that the OpenID Provider supports. These values are described
    -- in Section 3.1.2.1 of OpenID Connect Core 1.0.

  , claimTypesSupported :: Maybe (NonEmpty Text)
    -- ^ JSON array containing a list of the Claim Types
    -- that the OpenID Provider supports. These Claim Types are
    -- described in Section 5.6 of OpenID Connect Core 1.0.

  , claimsSupported :: Maybe (NonEmpty Text)
    -- ^ JSON array containing a list of the Claim Names of the Claims
    -- that the OpenID Provider MAY be able to supply values for. Note
    -- that for privacy or other reasons, this might not be an
    -- exhaustive list.

  , serviceDocumentation :: Maybe Text
    -- ^ URL of a page containing human-readable information that
    -- developers might want or need to know when using the OpenID
    -- Provider. In particular, if the OpenID Provider does not
    -- support Dynamic Client Registration, then information on how to
    -- register Clients needs to be provided in this documentation.

  , claimsLocalesSupported :: Maybe (NonEmpty Text)
    -- ^ Languages and scripts supported for values in Claims being
    -- returned, represented as a JSON array of language tag
    -- values. Not all languages and scripts are necessarily supported
    -- for all Claim values.

  , claimsParameterSupported :: Maybe Bool
    -- ^ Boolean value specifying whether the OP supports use of the
    -- claims parameter, with true indicating support. If omitted, the
    -- default value is false.

  , requestParameterSupported :: Maybe Bool
    -- ^ Boolean value specifying whether the OP supports use of the
    -- request parameter, with true indicating support. If omitted,
    -- the default value is false.

  , requestUriParameterSupported :: Maybe Bool
    -- ^ Boolean value specifying whether the OP supports use of the
    -- request_uri parameter, with true indicating support. If
    -- omitted, the default value is true.

  , requireRequestUriRegistration :: Maybe Bool
    -- ^ Boolean value specifying whether the OP requires any
    -- request_uri values used to be pre-registered using the
    -- request_uris registration parameter. Pre-registration is
    -- REQUIRED when the value is true. If omitted, the default value
    -- is false.

  , opPolicyUri :: Maybe URI
    -- ^ URL that the OpenID Provider provides to the person
    -- registering the Client to read about the OP's requirements on
    -- how the Relying Party can use the data provided by the OP. The
    -- registration process SHOULD display this URL to the person
    -- registering the Client if it is given.

  , opTosUri :: Maybe URI
    -- ^ URL that the OpenID Provider provides to the person
    -- registering the Client to read about OpenID Provider's terms of
    -- service. The registration process SHOULD display this URL to
    -- the person registering the Client if it is given.

  , endSessionEndpoint :: Maybe URI
    -- ^ URL at the OP to which an RP can perform a redirect to
    -- request that the End-User be logged out at the OP. This URL MUST
    -- use the https scheme and MAY contain port, path, and query
    -- parameter components.
    --
    -- @since 0.2.0
  }
  deriving stock (Generic, Show)
  deriving (ToJSON, FromJSON) via GenericJSON Discovery
