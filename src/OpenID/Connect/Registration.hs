{-|

Copyright:

  This file is part of the package openid-connect.  It is subject to
  the license terms in the LICENSE file found in the top-level
  directory of this distribution and at:

    https://code.devalot.com/sthenauth/openid-connect

  No part of this package, including this file, may be copied,
  modified, propagated, or distributed except according to the terms
  contained in the LICENSE file.

License: BSD-2-Clause

OpenID Connect Dynamic Client Registration 1.0.

-}
module OpenID.Connect.Registration
  ( Registration(..)
  , defaultRegistration
  , ClientMetadata
  , BasicRegistration(..)
  , clientMetadata
  , RegistrationResponse(..)
  , ClientMetadataResponse
  , clientSecretsFromResponse
  , additionalMetadataFromResponse
  , registrationFromResponse
  , (:*:)
  , URI(..)
  ) where

--------------------------------------------------------------------------------
-- Imports:
import Crypto.JOSE (JWKSet)
import qualified Crypto.JOSE.JWA.JWE.Alg as JWE
import qualified Crypto.JOSE.JWA.JWS as JWS
import Crypto.JWT (NumericDate)
import qualified Data.Aeson as Aeson
import Data.List.NonEmpty (NonEmpty(..))
import Data.Text (Text)
import GHC.Generics (Generic)
import qualified Network.URI as Network
import OpenID.Connect.Authentication
import OpenID.Connect.JSON

--------------------------------------------------------------------------------
-- | Client registration metadata.
--
-- OpenID Connect Dynamic Client Registration 1.0 §2.
--
-- Use the 'defaultRegistration' function to easily create a value of
-- this type.
data Registration = Registration
  { redirectUris :: NonEmpty URI
    -- ^ Array of Redirection URI values used by the Client.

  , responseTypes :: Maybe (NonEmpty Text)
    -- ^ JSON array containing a list of the OAuth 2.0 response_type
    -- values that the Client is declaring that it will restrict
    -- itself to using.

  , grantTypes :: Maybe (NonEmpty Text)
    -- ^ JSON array containing a list of the OAuth 2.0 Grant Types
    -- that the Client is declaring that it will restrict itself to
    -- using.

  , applicationType :: Maybe Text
    -- ^ Kind of the application. The default, if omitted, is web. The
    -- defined values are native or web.

  , contacts :: Maybe (NonEmpty Text)
    -- ^ Array of e-mail addresses of people responsible for this Client.

  , clientName :: Maybe Text
    -- ^ Name of the Client to be presented to the End-User.

  , logoUri :: Maybe URI
    -- ^ URL that references a logo for the Client application.

  , clientUri :: Maybe URI
    -- ^ URL of the home page of the Client.

  , policyUri :: Maybe URI
    -- ^ URL that the Relying Party Client provides to the End-User to
    -- read about the how the profile data will be used.

  , tosUri :: Maybe URI
    -- ^ URL that the Relying Party Client provides to the End-User to
    -- read about the Relying Party's terms of service.

  , jwksUri :: Maybe URI
    -- ^ URL for the Client's JSON Web Key Set document.

  , jwks :: Maybe JWKSet
    -- ^ Client's JSON Web Key Set [JWK] document, passed by value.

  , sectorIdentifierUri :: Maybe URI
    -- ^ URL using the https scheme to be used in calculating
    -- Pseudonymous Identifiers by the OP.

  , subjectType :: Maybe Text
    -- ^ @subject_type@ requested for responses to this Client.

  , idTokenSignedResponseAlg :: Maybe JWS.Alg
    -- ^ JWS alg algorithm required for signing the ID Token issued to
    -- this Client.

  , idTokenEncryptedResponseAlg :: Maybe JWE.Alg
    -- ^ JWE alg algorithm required for encrypting the ID Token issued
    -- to this Client.

  , idTokenEncryptedResponseEnc :: Maybe JWE.Alg
    -- ^ JWE enc algorithm required for encrypting the ID Token issued
    -- to this Client.

  , userinfoSignedResponseAlg :: Maybe JWS.Alg
    -- ^ JWS alg algorithm [JWA] REQUIRED for signing UserInfo
    -- Responses.

  , userinfoEncryptedResponseAlg :: Maybe JWE.Alg
    -- ^ JWE alg algorithm required for encrypting UserInfo Responses.

  , userinfoEncryptedResponseEnc :: Maybe JWE.Alg
    -- ^ JWE enc algorithm required for encrypting UserInfo Responses.

  , requestObjectSigningAlg :: Maybe JWS.Alg
    -- ^ JWS alg algorithm that must be used for signing Request
    -- Objects sent to the OP.

  , requestObjectEncryptionAlg :: Maybe JWE.Alg
    -- ^ JWE alg algorithm the RP is declaring that it may use for
    -- encrypting Request Objects sent to the OP.  This parameter
    -- SHOULD be included when symmetric encryption will be used,
    -- since this signals to the OP that a @client_secret@ value needs
    -- to be returned from which the symmetric key will be derived,
    -- that might not otherwise be returned. The RP MAY still use
    -- other supported encryption algorithms or send unencrypted
    -- Request Objects, even when this parameter is present. If both
    -- signing and encryption are requested, the Request Object will
    -- be signed then encrypted, with the result being a Nested JWT,
    -- as defined in JWT. The default, if omitted, is that the RP is
    -- not declaring whether it might encrypt any Request Objects.

  , requestObjectEncryptionEnc :: Maybe JWE.Alg
    -- ^ JWE enc algorithm the RP is declaring that it may use for
    -- encrypting Request Objects sent to the OP.  If
    -- @request_object_encryption_alg@ is specified, the default for
    -- this value is @A128CBC-HS256@. When
    -- @request_object_encryption_enc@ is included,
    -- @request_object_encryption_alg@ MUST also be provided.

  , tokenEndpointAuthMethod :: ClientAuthentication
    -- ^ Requested Client Authentication method for the Token
    -- Endpoint.

  , tokenEndpointAuthSigningAlg :: Maybe JWS.Alg
    -- ^ JWS alg algorithm that must be used for signing the JWT used
    -- to authenticate the Client at the Token Endpoint for the
    -- private_key_jwt and client_secret_jwt authentication methods.

  , defaultMaxAge :: Maybe Int
    -- ^ Default Maximum Authentication Age. Specifies that the
    -- End-User MUST be actively authenticated if the End-User was
    -- authenticated longer ago than the specified number of seconds.

  , requireAuthTime :: Maybe Bool
    -- ^ Boolean value specifying whether the auth_time Claim in the
    -- ID Token is REQUIRED. It is REQUIRED when the value is
    -- true. (If this is false, the auth_time Claim can still be
    -- dynamically requested as an individual Claim for the ID Token
    -- using the claims request parameter described in Section 5.5.1
    -- of OpenID Connect Core 1.0.) If omitted, the default value is
    -- false.

  , defaultAcrValues :: Maybe (NonEmpty Text)
    -- ^ Default requested Authentication Context Class Reference
    -- values. Array of strings that specifies the default acr values
    -- that the OP is being requested to use for processing requests
    -- from this Client, with the values appearing in order of
    -- preference.

  , initiateLoginUri :: Maybe URI
    -- ^ URI using the https scheme that a third party can use to
    -- initiate a login by the RP, as specified in Section 4 of OpenID
    -- Connect Core 1.0. The URI MUST accept requests via both GET and
    -- POST. The Client MUST understand the login_hint and iss
    -- parameters and SHOULD support the target_link_uri parameter.

  , requestUris :: Maybe (NonEmpty URI)
    -- ^ Array of request_uri values that are pre-registered by the RP
    -- for use at the OP. Servers MAY cache the contents of the files
    -- referenced by these URIs and not retrieve them at the time they
    -- are used in a request. OPs can require that request_uri values
    -- used be pre-registered with the
    -- require_request_uri_registration discovery parameter.
  }
  deriving stock (Generic, Show)
  deriving (ToJSON, FromJSON) via GenericJSON Registration

--------------------------------------------------------------------------------
-- | The default 'Registration' value.
defaultRegistration :: Network.URI -> Registration
defaultRegistration redir =
  Registration
    { redirectUris                 = URI redir :| []
    , responseTypes                = Nothing
    , grantTypes                   = Nothing
    , applicationType              = Nothing
    , contacts                     = Nothing
    , clientName                   = Nothing
    , logoUri                      = Nothing
    , clientUri                    = Nothing
    , policyUri                    = Nothing
    , tosUri                       = Nothing
    , jwksUri                      = Nothing
    , jwks                         = Nothing
    , sectorIdentifierUri          = Nothing
    , subjectType                  = Nothing
    , idTokenSignedResponseAlg     = Nothing
    , idTokenEncryptedResponseAlg  = Nothing
    , idTokenEncryptedResponseEnc  = Nothing
    , userinfoSignedResponseAlg    = Nothing
    , userinfoEncryptedResponseAlg = Nothing
    , userinfoEncryptedResponseEnc = Nothing
    , requestObjectSigningAlg      = Nothing
    , requestObjectEncryptionAlg   = Nothing
    , requestObjectEncryptionEnc   = Nothing
    , tokenEndpointAuthMethod      = ClientSecretBasic
    , tokenEndpointAuthSigningAlg  = Nothing
    , defaultMaxAge                = Nothing
    , requireAuthTime              = Nothing
    , defaultAcrValues             = Nothing
    , initiateLoginUri             = Nothing
    , requestUris                  = Nothing
  }

--------------------------------------------------------------------------------
-- | Tag the 'ClientMetadata' and 'ClientMetadataResponse' types as
-- having no additional metadata parameters.
data BasicRegistration = BasicRegistration

instance ToJSON BasicRegistration where
  toJSON _ = Aeson.object [ ]

instance FromJSON BasicRegistration where
  parseJSON _ = pure BasicRegistration

--------------------------------------------------------------------------------
-- | Registration fields with any additional fields that are
-- necessary.  If no additional fields are needed, use
-- 'BasicRegistration' to fill the type variable.
type ClientMetadata a = Registration :*: a

--------------------------------------------------------------------------------
-- | Create a complete 'ClientMetadata' record from an existing
-- 'Registration' value and any additional client metadata parameters
-- that are needed.
--
-- If you don't need to specify additional client metadata parameters
-- you can use 'BasicRegistration' as the @a@ type.  In that case, the
-- type signature would be:
--
-- @
-- clientMetadata
--   :: Registration
--   -> BasicRegistration
--   -> ClientMetadata BasicRegistration
-- @
clientMetadata :: Registration -> a -> ClientMetadata a
clientMetadata r a = Join (r, a)

--------------------------------------------------------------------------------
-- | Client Registration Response.
--
-- OpenID Connect Dynamic Client Registration 1.0 §3.2.
data RegistrationResponse = RegistrationResponse
  { clientId :: Text
    -- ^ Unique Client Identifier.

  , clientSecret :: Maybe Text
    -- ^ Client Secret.  This value is used by Confidential Clients to
    -- authenticate to the Token Endpoint, as described in Section
    -- 2.3.1 of OAuth 2.0, and for the derivation of symmetric
    -- encryption key values.

  , registrationAccessToken :: Maybe Text
    -- ^ Registration Access Token that can be used at the Client
    -- Configuration Endpoint to perform subsequent operations upon
    -- the Client registration.

  , registrationClientUri :: Maybe URI
    -- ^ Location of the Client Configuration Endpoint where the
    -- Registration Access Token can be used to perform subsequent
    -- operations upon the resulting Client
    -- registration. Implementations MUST either return both a Client
    -- Configuration Endpoint and a Registration Access Token or
    -- neither of them.

  , clientIdIssuedAt :: Maybe NumericDate
    -- ^ Time at which the Client Identifier was issued.

  , clientSecretExpiresAt :: Maybe NumericDate
    -- ^ If @client_secret@ is issued. Time at which the client_secret
    -- will expire or 0 if it will not expire.
  }
  deriving stock (Generic, Show)
  deriving (ToJSON, FromJSON) via GenericJSON RegistrationResponse

--------------------------------------------------------------------------------
-- | Like 'ClientMetadata' but includes the registration response.
type ClientMetadataResponse a = Registration :*: RegistrationResponse :*: a

--------------------------------------------------------------------------------
-- | Extract the registration value from a full registration response.
registrationFromResponse :: ClientMetadataResponse a -> Registration
registrationFromResponse (Join (Join (r, _), _)) = r

--------------------------------------------------------------------------------
-- | Extract the additional metadata fields from a full registration response.
additionalMetadataFromResponse :: ClientMetadataResponse a -> a
additionalMetadataFromResponse (Join (_, a)) = a

--------------------------------------------------------------------------------
-- | Extract the client details from a registration response.
clientSecretsFromResponse :: ClientMetadataResponse a -> RegistrationResponse
clientSecretsFromResponse (Join (Join (_, r), _)) = r
