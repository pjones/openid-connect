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

-}
module OpenID.Connect.Client.Flow.AuthorizationCode
  ( Request(..)
  , Response(..)
  , step
  , ClientURI
  , Secrets
  , generateRandomSecrets
  , generateRandomSecretsIO

  , AuthenticationRequest
  , defaultAuthenticationRequest
  , authRequestDisplay
  , authRequestPrompt
  , authRequestMaxAge
  , authRequestUiLocales
  , authRequestIdTokenHint
  , authRequestLoginHint
  , authRequestAcrValues
  , authRequestOtherParams

  , UserReturnFromRedirect(..)

  , FlowError(..)
  , ResumeFinish

  , module OpenID.Connect.Client.Scope
  , module OpenID.Connect.Client.Provider
  , module OpenID.Connect.Client.Authentication
  ) where

--------------------------------------------------------------------------------
-- Imports:
import Control.Category ((>>>))
import Control.Lens ((^?))
import Control.Monad.Except
import qualified Crypto.Hash as Hash
import qualified Crypto.JOSE.Error as JOSE
import Crypto.JOSE.JWK (JWKSet)
import Crypto.JWT (SignedJWT, ClaimsSet, JWTError)
import qualified Crypto.JWT as JWT
import Crypto.Random (MonadRandom(..))
import Data.Bifunctor (bimap, first)
import Data.ByteArray.Encoding
import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import qualified Data.ByteString.Char8 as Char8
import Data.Function ((&))
import Data.Functor ((<&>))
import Data.List.NonEmpty (NonEmpty)
import qualified Data.List.NonEmpty as NonEmpty
import Data.Maybe (isJust)
import Data.Text (Text)
import qualified Data.Text as Text
import qualified Data.Text.Encoding as Text
import Data.Time.Clock (UTCTime)
import qualified Network.HTTP.Client as HTTP
import Network.HTTP.Types (QueryItem, renderQuery)
import Network.URI (URI(..), parseURI, uriToString)
import OpenID.Connect.Client.Authentication
import OpenID.Connect.Client.HTTP
import OpenID.Connect.Client.Provider
import OpenID.Connect.Client.Scope
import Web.Cookie (SetCookie)
import qualified Web.Cookie as Cookie

import OpenID.Connect.Client.TokenResponse
  ( TokenResponse
  , decodeIdentityToken
  , verifyIdentityTokenClaims
  )

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
type ClientURI = URI

--------------------------------------------------------------------------------
data Secrets = Secrets
  { requestForgeryProtectionToken :: ByteString
  , replayProtectionNonce :: ByteString
  , valueForHttpOnlyCookie :: ByteString
  }

--------------------------------------------------------------------------------
generateRandomSecrets :: forall m. MonadRandom m => m Secrets
generateRandomSecrets = do
  bytes <- getRandomBytes 64 :: m ByteString
  let hash1 = Hash.hash (ByteString.take 32 bytes) :: Hash.Digest Hash.SHA256
      hash2 = Hash.hash (ByteString.drop 32 bytes) :: Hash.Digest Hash.SHA256

  pure Secrets
    { requestForgeryProtectionToken = convertToBase Base64URLUnpadded hash2
    , replayProtectionNonce         = convertToBase Base64URLUnpadded hash1
    , valueForHttpOnlyCookie        = convertToBase Base64URLUnpadded bytes
    }

--------------------------------------------------------------------------------
generateRandomSecretsIO :: IO Secrets
generateRandomSecretsIO = generateRandomSecrets

--------------------------------------------------------------------------------
expectedStateParam :: ByteString -> Either FlowError ByteString
expectedStateParam cookie
  = extractTokenFromSessionCookie cookie (ByteString.drop 32)
  & first (const InvalidStateParameterError)

--------------------------------------------------------------------------------
extractTokenFromSessionCookie
  :: ByteString                 -- ^ The session cookie
  -> (ByteString -> ByteString) -- ^ Function to extract token bytes
  -> Either String ByteString   -- ^ Error or token.
extractTokenFromSessionCookie cookie f =
    convertFromBase Base64URLUnpadded cookie <&> rehash . f
  where
    rehash :: ByteString -> ByteString
    rehash bs = let hash = Hash.hash bs :: Hash.Digest Hash.SHA256
                in convertToBase Base64URLUnpadded hash

--------------------------------------------------------------------------------
-- 3.1.2.1.  Authentication Request
data AuthenticationRequest = AuthenticationRequest
  { authRequestRedirectURI  :: ClientURI
  , authRequestScope        :: Scope
  , authRequestResponseType :: ByteString
  , authRequestClientId     :: Text
  , authRequestState        :: ByteString
  , authRequestNonce        :: ByteString
  , authRequestCookie       :: ByteString
  , authRequestDisplay      :: Maybe ByteString
  , authRequestPrompt       :: Maybe ByteString
  , authRequestMaxAge       :: Maybe Int
  , authRequestUiLocales    :: Maybe (NonEmpty Text)
  , authRequestIdTokenHint  :: Maybe ByteString
  , authRequestLoginHint    :: Maybe Text
  , authRequestAcrValues    :: Maybe (NonEmpty Text)
  , authRequestOtherParams  :: [QueryItem]
  }

--------------------------------------------------------------------------------
defaultAuthenticationRequest
  :: ClientURI
  -> Scope
  -> Credentials
  -> Secrets
  -> AuthenticationRequest
defaultAuthenticationRequest redir scope creds secrets =
  AuthenticationRequest
    { authRequestRedirectURI  = redir
    , authRequestScope        = scope
    , authRequestResponseType = "code"
    , authRequestClientId     = assignedClientId creds
    , authRequestState        = requestForgeryProtectionToken secrets
    , authRequestNonce        = replayProtectionNonce secrets
    , authRequestCookie       = valueForHttpOnlyCookie secrets
    , authRequestDisplay      = Nothing
    , authRequestPrompt       = Nothing
    , authRequestMaxAge       = Nothing
    , authRequestUiLocales    = Nothing
    , authRequestIdTokenHint  = Nothing
    , authRequestLoginHint    = Nothing
    , authRequestAcrValues    = Nothing
    , authRequestOtherParams  = []
    }

--------------------------------------------------------------------------------
data UserReturnFromRedirect = UserReturnFromRedirect
  { afterRedirectSessionCookie :: ByteString
  , afterRedirectCodeParam     :: ByteString
  , afterRedirectStateParam    :: ByteString
  }

--------------------------------------------------------------------------------
type ResumeFinish
  = JWKSet -> UTCTime -> Either FlowError (TokenResponse ClaimsSet)

--------------------------------------------------------------------------------
data FlowError
  = ProviderDiscoveryError DiscoveryError

  | InvalidStateParameterError

  | InvalidNonceFromProviderError

  | ProviderMissingTokenEndpointError
    -- ^ This provider does not support the Authorization Code flow.

  | InvalidProviderTokenEndpointError Text
    -- ^ The provider's discovery document includes a @token_endpoint@
    -- which is not a valid URL.

  | NoAuthenticationMethodsAvailableError
    -- ^ The provided 'Credentials' do not include any authentication
    -- secrets that match what the provider accepts in the
    -- 'tokenEndpointAuthMethodsSupported' field.  Therefore we can't
    -- make a token exchange request with this provider without using
    -- a different set of 'Credentials'.

  | InvalidProviderTokenResponseError
    -- ^ The provider responded with a token that we could not parse.

  | TokenDecodingError JOSE.Error

  | MalformedClientIdError
    -- ^ The assigned @client_id@ cannot be translated to a JSON string.

  | IdentityTokenValidationFailed JWTError ResumeFinish

--------------------------------------------------------------------------------
data Request
  = Initial ProviderDiscoveryURI
  | Authenticate Discovery AuthenticationRequest
  | Finish Discovery JWKSet Credentials ClientURI UserReturnFromRedirect UTCTime

--------------------------------------------------------------------------------
data Response
  = ProviderFound Provider (Maybe UTCTime)
    -- ^ A provider that you can use with the 'Authenticate' request.

  | RedirectTo URI (ByteString -> SetCookie)
    -- ^ Send the end-user to this URI.

  | Success (TokenResponse ClaimsSet)
    -- ^ Successful authentication.

  | Failed FlowError
    -- ^ Failed authentication.

--------------------------------------------------------------------------------
step :: MonadRandom m => HTTPS m -> Request -> m Response
step https = \case
  Initial url -> discoveryAndKeys url https >>= \case
    Left e -> pure (Failed (ProviderDiscoveryError e))
    Right (p, c) -> pure (ProviderFound p c)

  Authenticate disco req ->
    makeRedirectURI disco req
      & either Failed (`RedirectTo` makeSessionCookie req)
      & pure

  Finish disco keys creds redir user now -> do
    r <- runExceptT $ do
      _ <- ExceptT (pure (verifyPostRedirectRequest user))
      token <- ExceptT (exchangeCodeForIdentityToken https now disco creds redir user)
      ExceptT (pure (extractClaimsSetFromTokenResponse disco creds token keys now))
    pure (either Failed Success r)

--------------------------------------------------------------------------------
makeRedirectURI
  :: Discovery
  -> AuthenticationRequest
  -> Either FlowError URI
makeRedirectURI disco AuthenticationRequest{..} =
  let uriText = authorizationEndpoint disco
  in case forceHTTPS <$> parseURI (Text.unpack uriText) of
    Nothing -> Left (ProviderDiscoveryError (InvalidUrlError uriText))
    Just uri -> Right $ uri
      { uriQuery = Char8.unpack
          (renderQuery False (params <> authRequestOtherParams))
      }

  where
    params :: [QueryItem]
    params = filter (isJust . snd)
      [ ("response_type", Just authRequestResponseType)
      , ("client_id",     Just (Text.encodeUtf8 authRequestClientId))
      , ("redirect_uri",  Just redir)
      , ("nonce",         Just authRequestNonce)
      , ("state",         Just authRequestState)
      , ("display",       authRequestDisplay)
      , ("prompt",        authRequestPrompt)
      , ("max_age",       Char8.pack . show <$> authRequestMaxAge)
      , ("ui_locales",    toWords <$> authRequestUiLocales)
      , ("id_token_hint", authRequestIdTokenHint)
      , ("login_hint",    Text.encodeUtf8 <$> authRequestLoginHint)
      , ("acr_values",    toWords <$> authRequestAcrValues)
      , scopeQueryItem    authRequestScope
      ]

    redir :: ByteString
    redir = Char8.pack (uriToString id authRequestRedirectURI [])

    toWords :: NonEmpty Text -> ByteString
    toWords = Text.encodeUtf8 . Text.unwords . NonEmpty.toList

--------------------------------------------------------------------------------
makeSessionCookie :: AuthenticationRequest -> ByteString -> SetCookie
makeSessionCookie AuthenticationRequest{..} name =
  Cookie.defaultSetCookie
    { Cookie.setCookieName     = name
    , Cookie.setCookieValue    = authRequestCookie
    , Cookie.setCookiePath     = Just (Char8.pack (uriPath authRequestRedirectURI))
    , Cookie.setCookieHttpOnly = True
    , Cookie.setCookieSecure   = True
    , Cookie.setCookieSameSite = Just Cookie.sameSiteStrict
    }

--------------------------------------------------------------------------------
verifyPostRedirectRequest :: UserReturnFromRedirect -> Either FlowError ()
verifyPostRedirectRequest UserReturnFromRedirect{..} = do
  expectState <- expectedStateParam afterRedirectSessionCookie
  if afterRedirectStateParam == expectState
    then Right ()
    else Left InvalidStateParameterError

--------------------------------------------------------------------------------
-- | Use HTTP to exchange an access token for an identity token.
exchangeCodeForIdentityToken
  :: forall m. MonadRandom m
  => HTTPS m
  -> UTCTime
  -> Discovery
  -> Credentials
  -> ClientURI
  -> UserReturnFromRedirect
  -> m (Either FlowError (TokenResponse SignedJWT))
exchangeCodeForIdentityToken https now disco creds redir user =
    -- Is this line terrible?  It composes a monadic action that
    -- results in an Either with a pure function that produces an
    -- Either.
    performRequest <&> (>>= processResponse)
  where
    performRequest :: m (Either FlowError (HTTP.Response LByteString))
    performRequest = runExceptT $ do
      uri <- maybe
        (throwError ProviderMissingTokenEndpointError) pure
        (tokenEndpoint disco)
      req <- maybe
        (throwError (InvalidProviderTokenEndpointError uri)) pure
        (HTTP.parseUrlThrow (Text.unpack uri))
      applyRequestAuthentication creds
        (tokenEndpointAuthMethodsSupported disco)
          uri now body req >>= \case
            Nothing -> throwError NoAuthenticationMethodsAvailableError
            Just r  -> lift (https r)

    processResponse
      :: HTTP.Response LByteString
      -> Either FlowError (TokenResponse SignedJWT)
    processResponse res =
      parseResponse res
      & bimap (const InvalidProviderTokenResponseError) fst
      >>= (decodeIdentityToken >>> first TokenDecodingError)

    body :: [ (ByteString, ByteString) ]
    body  = [ ("grant_type", "authorization_code")
            , ("code", afterRedirectCodeParam user)
            , ("redirect_uri", Char8.pack (uriToString id redir []))
            , ("client_id", Text.encodeUtf8 (assignedClientId creds))
            ]

--------------------------------------------------------------------------------
-- | Verify an identity token and then expose the claims it holds.
extractClaimsSetFromTokenResponse
  :: Discovery
  -> Credentials
  -> TokenResponse SignedJWT
  -> JWKSet
  -> UTCTime
  -> Either FlowError (TokenResponse ClaimsSet)
extractClaimsSetFromTokenResponse disco creds token keys time =
  case assignedClientId creds ^? JWT.stringOrUri of
    Nothing -> Left MalformedClientIdError
    Just sOrU ->
      let aud  = JWT.Audience [sOrU]
          self = extractClaimsSetFromTokenResponse disco creds token
          fin  = verifyIdentityTokenClaims disco aud time keys token
      in fin & first (`IdentityTokenValidationFailed` self)
