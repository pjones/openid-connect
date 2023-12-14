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
module OpenID.Connect.Authentication
  ( ClientAuthentication(..)
  , ClientSecret(..)
  , Credentials(..)
  , ClientID
  , ClientRedirectURI
  , AuthenticationRequest(..)
  , clientSecretAsJWK
  ) where

--------------------------------------------------------------------------------
-- Imports:
import Control.Applicative ((<|>))
import Crypto.JOSE.JWK (JWK)
import qualified Crypto.JOSE.JWK as JWK
import qualified Data.Aeson as Aeson
import qualified Data.Aeson.Types as Aeson
import Data.ByteString (ByteString)
import Data.Text (Text)
import qualified Data.Text.Encoding as Text
import GHC.Generics (Generic)
import Network.HTTP.Types (QueryItem)
import qualified Network.URI as Network
import OpenID.Connect.JSON (FromJSON, ToJSON, aesonOptions)
import OpenID.Connect.Scope

--------------------------------------------------------------------------------
-- | Private values needed by the client in order to authenticate with
-- the provider.
--
-- The method of authentication is established when the client
-- registers with the provider.
--
-- @since 0.1.0.0
data ClientSecret
  = AssignedSecretText Text
    -- ^ A @client_secret@ created by the provider and given to the
    -- client to use during authentication.
    --
    -- This is the most common way to authenticate with a provider.

  | AssignedAssertionText Text
    -- ^ A @client_secret@ created by the provider and given to the
    -- client.  The client must create a JWT and use the
    -- @client_secret@ to calculate a message authentication code for
    -- the JWT.

  | AssertionPrivateKey JWK
    -- ^ A private key that is solely in the client's possession.  The
    -- provider holds the public key portion of the given key.
    --
    -- The client creates and signs a JWT in order to authenticate.

--------------------------------------------------------------------------------
-- | A @client_id@ assigned by the provider.
--
-- @since 0.1.0.0
type ClientID = Text

--------------------------------------------------------------------------------
-- | Get credentials as a JWK, if applicable
clientSecretAsJWK :: ClientSecret -> Maybe JWK
clientSecretAsJWK (AssertionPrivateKey jwk) =
  Just jwk
-- Use the @client_secret@ as a /key/ to sign a JWT.
clientSecretAsJWK (AssignedAssertionText keyBytes) =
  Just $ JWK.fromOctets $ Text.encodeUtf8 keyBytes
clientSecretAsJWK _ = Nothing

--------------------------------------------------------------------------------
-- | The client (relying party) redirection URL previously registered
-- with the OpenID Provider (i.e. a URL to an endpoint on your web
-- site that receives authentication details from the provider via the
-- end-user's browser).
--
-- After the provider has authenticated the end-user, they will be
-- redirected to this URL to continue the flow.
--
-- NOTE: This URL must match exactly with the one registered with the
-- provider.  If they don't match the provider will not redirect the
-- end-user back to your site.
--
-- @since 0.1.0.0
type ClientRedirectURI = Network.URI

--------------------------------------------------------------------------------
-- | A complete set of credentials used by the client to authenticate
-- with the provider.
--
-- @since 0.1.0.0
data Credentials = Credentials
  { assignedClientId :: ClientID
    -- ^ The provider-assigned @client_id@.

  , clientSecret :: ClientSecret
    -- ^ The @client_secret@ or other means of authenticating.

  , clientRedirectUri :: ClientRedirectURI
    -- ^ The @redirect_uri@ shared between the client and provider.
    -- This URI must be registered with the provider.
  }

--------------------------------------------------------------------------------
-- | §3.1.2.1.  Authentication Request.
--
-- The fields of this record are send to the provider by way of a URI
-- given to the end-user.
--
-- Clients can use the
-- 'OpenID.Connect.Client.Flow.AuthorizationCode.defaultAuthenticationRequest'
-- function to easily create a value of this type.
--
-- @since 0.1.0.0
data AuthenticationRequest = AuthenticationRequest
  { authRequestRedirectURI :: ClientRedirectURI
    -- ^ Where to redirect the end-user to after authentication.

  , authRequestClientId :: Text
    -- ^ The @client_id@ assigned by the provider.

  , authRequestScope :: Scope
    -- ^ The @scope@ to request.  The @openid@ scope is always part of
    -- this list.

  , authRequestResponseType :: ByteString
    -- ^ The @response_type@ parameter.

  , authRequestDisplay :: Maybe ByteString
    -- ^ The @display@ parameter.

  , authRequestPrompt :: Maybe ByteString
    -- ^ The @prompt@ parameter.

  , authRequestMaxAge :: Maybe Int
    -- ^ The @max_age@ parameter.

  , authRequestUiLocales :: Maybe Words
    -- ^ The @ui_locales@ parameter.

  , authRequestIdTokenHint :: Maybe ByteString
    -- ^ The @id_token_hint@ parameter.

  , authRequestLoginHint :: Maybe Text
    -- ^ The @login_hint@ parameter.

  , authRequestAcrValues :: Maybe Words
    -- ^ The @acr_values@ parameter.

  , authRequestOtherParams :: [QueryItem]
    -- ^ Any additional query parameters you wish to send to the
    -- provider.
  }

--------------------------------------------------------------------------------
-- | Methods that a client can use to authenticate with a provider.
--
-- Defined in OpenID Connect Core 1.0 §9.
--
-- @since 0.1.0.0
data ClientAuthentication
  = ClientSecretBasic
    -- ^ Send credentials using HTTP Basic Authentication.

  | ClientSecretPost
    -- ^ Send the credentials in the body of an HTTP POST.

  | ClientSecretJwt
    -- ^ Create a JWT and calculate a message authentication code
    -- using a shared secret.  The JWT confirms that the client is in
    -- possession of the shared secret.

  | PrivateKeyJwt
    -- ^ Create and sign a JWT using a private key.  The provider must
    -- already have access to the public key corresponding to the
    -- private key.

  | None
    -- ^ The Client does not authenticate itself at the Token
    -- Endpoint, either because it uses only the Implicit Flow (and so
    -- does not use the Token Endpoint) or because it is a Public
    -- Client with no Client Secret or other authentication mechanism.

  | UnsupportedAuthentication Text
    -- ^ Other unsupported possible ways to autenticate the client.
    --
    -- @since 0.2.0

  deriving stock (Generic, Eq, Show)

clientAuthAesonOptions :: Aeson.Options
clientAuthAesonOptions = aesonOptions{ Aeson.sumEncoding = Aeson.UntaggedValue }

instance ToJSON ClientAuthentication where
  toJSON (UnsupportedAuthentication txt) = Aeson.String txt
  toJSON a = Aeson.genericToJSON clientAuthAesonOptions a

instance FromJSON ClientAuthentication where
  parseJSON v@(Aeson.String txt) =
    Aeson.genericParseJSON clientAuthAesonOptions v
      <|> pure (UnsupportedAuthentication txt)
  parseJSON v =
    Aeson.prependFailure "parsing ClientAuthentication failed, " (Aeson.typeMismatch "String" v)
