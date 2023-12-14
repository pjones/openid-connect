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

The /Authorization Code/ Flow as defined in OpenID Connect 1.0.

Flow outline:

  1. Perform (and optionally cache) the provider's discovery document
     and keys.  This is done with a combination of
     'OpenID.Connect.Client.Provider.discovery' and
     'OpenID.Connect.Client.Provider.keysFromDiscovery'.

  2. Send the end-user to the provider for authentication by applying
     the 'authenticationRedirect' function.  It will generate a
     'RedirectTo' response with a URI and cookie.

  3. The provider will redirect the end-user back to your site with
     some query parameters.  Bundle those up and apply the
     'authenticationSuccess' function.  It will respond with a
     validated identity token if everything checks out.
-}
module OpenID.Connect.Client.Flow.AuthorizationCode
  (
    -- * Flow
    authenticationRedirect
  , authenticationSuccess
  , authenticationSuccessWithJwt
  , RedirectTo(..)

    -- * Authentication settings
  , defaultAuthenticationRequest

    -- * End-user provided details
  , UserReturnFromRedirect(..)

    -- * Errors that can occur
  , FlowError(..)

    -- * Ancillary types and re-exports
  , HTTPS
  , ErrorResponse(..)
  , module OpenID.Connect.Authentication
  , module OpenID.Connect.Client.Provider
  , module OpenID.Connect.Scope
  ) where

--------------------------------------------------------------------------------
-- Imports:
import Control.Category ((>>>))
import Control.Exception (Exception)
import Control.Monad.Except
import qualified Crypto.Hash as Hash
import qualified Crypto.JOSE.Error as JOSE
import Crypto.JOSE.JWK (JWKSet)
import Crypto.JWT (SignedJWT, ClaimsSet, JWTError)
import Crypto.Random (MonadRandom(..))
import Data.Bifunctor (bimap, first, second)
import Data.ByteArray.Encoding
import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import qualified Data.ByteString.Char8 as Char8
import qualified Data.ByteString.Lazy as LByteString
import Data.Function ((&))
import Data.Functor ((<&>))
import qualified Data.List.NonEmpty as NonEmpty
import Data.Maybe (isJust)
import Data.Text (Text)
import qualified Data.Text.Encoding as Text
import Data.Time.Clock (UTCTime)
import qualified Network.HTTP.Client as HTTP
import Network.HTTP.Types (QueryItem, renderQuery)
import qualified Network.URI as Network
import OpenID.Connect.Authentication
import OpenID.Connect.Client.Authentication
import OpenID.Connect.Client.HTTP
import OpenID.Connect.Client.Provider
import OpenID.Connect.JSON
import OpenID.Connect.Scope
import OpenID.Connect.TokenResponse (TokenResponse (idToken))
import Web.Cookie (SetCookie)
import qualified Web.Cookie as Cookie

import OpenID.Connect.Client.TokenResponse
  ( decodeIdentityToken
  , verifyIdentityTokenClaims
  )

--------------------------------------------------------------------------------
-- | Internal type for calculating secrets.
data Secrets = Secrets
  { requestForgeryProtectionToken :: ByteString
  , replayProtectionNonce         :: ByteString
  , valueForHttpOnlyCookie        :: ByteString
  }

--------------------------------------------------------------------------------
-- | Generate a new set of secrets.
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
-- | Extract the expected state value from the session cookie.
expectedStateParam :: ByteString -> Either FlowError ByteString
expectedStateParam cookie
  = extractTokenFromSessionCookie cookie (ByteString.drop 32)
  & first (const InvalidStateParameterError)

--------------------------------------------------------------------------------
-- | Given the session cookie, return the expected nonce value.
expectedNonce :: ByteString -> Either FlowError Text
expectedNonce cookie
  = extractTokenFromSessionCookie cookie (ByteString.take 32)
  & bimap (const InvalidNonceFromProviderError) Text.decodeUtf8

--------------------------------------------------------------------------------
-- | Higher-order function of extracting bytes from a session cookie.
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
-- | Create an 'AuthenticationRequest' value for the authorization
-- code flow.
--
-- @since 0.1.0.0
defaultAuthenticationRequest
  :: Scope                 -- ^ Requested scope.
  -> Credentials           -- ^ Provider assigned credentials.
  -> AuthenticationRequest -- ^ An 'AuthenticationRequest'.
defaultAuthenticationRequest scope creds =
  AuthenticationRequest
    { authRequestRedirectURI  = clientRedirectUri creds
    , authRequestScope        = scope
    , authRequestResponseType = "code"
    , authRequestClientId     = assignedClientId creds
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
-- | Values to collect from the end-user after they return from
-- provider authentication as per §3.1.2.5.
--
-- When the end-user is sent to the 'ClientRedirectURI' they /must/
-- provide the following values.  If any of these fields are not
-- provided by the end-user you should assume the authentication
-- failed.
--
-- If the @state@ and/or @code@ parameters are missing in the HTTP
-- request you should look for an @error@ query parameter as specified
-- in §3.1.2.6.
--
-- @since 0.1.0.0
data UserReturnFromRedirect = UserReturnFromRedirect
  { afterRedirectSessionCookie :: ByteString
    -- ^ The end-user /must/ provide a cookie value set by the
    -- 'RedirectTo' response.  This is needed to validate the @state@
    -- parameter and the @nonce@ claim in the identity token.

  , afterRedirectCodeParam :: ByteString
    -- ^ The @code@ parameter which contains the authorization code.

  , afterRedirectStateParam :: ByteString
    -- ^ The @state@ parameter which is used to prevent request
    -- forgery.
  }

--------------------------------------------------------------------------------
-- | Errors that may occur during the authentication code flow.
--
-- @since 0.1.0.0
data FlowError
  = ProviderDiscoveryError DiscoveryError
    -- ^ Something is wrong with the discovery document.

  | InvalidStateParameterError
    -- ^ The @state@ query parameter provided by the end-user doesn't
    -- match their session cookie.  It's possible that the current
    -- request was forged and therefore didn't originate from an
    -- actual end-user.

  | InvalidNonceFromProviderError
    -- ^ The @nonce@ claim in the identity token doesn't match the
    -- value in the end-user's session cookie.  It's possible that the
    -- response from the provider is a replay of a previous response.

  | ProviderMissingTokenEndpointError
    -- ^ The provider does not support the Authorization Code flow.
    -- To work with this provider you must use another flow type
    -- (i.e. implicit or hybrid).

  | InvalidProviderTokenEndpointError Text
    -- ^ The provider's discovery document includes a @token_endpoint@
    -- which is not a valid URL.  The invalid URL is provided for
    -- reference.

  | NoAuthenticationMethodsAvailableError
    -- ^ The provided 'Credentials' do not include any authentication
    -- secrets that match what the provider accepts in the
    -- 'tokenEndpointAuthMethodsSupported' field.  Therefore we can't
    -- make a token exchange request with this provider without using
    -- a different set of 'Credentials'.

  | InvalidProviderTokenResponseError ErrorResponse
    -- ^ While exchanging an authorization code for an identity token
    -- the provider responded in a way that we couldn't parse.  A
    -- decoding error message is provided for debugging.

  | TokenDecodingError JOSE.Error
    -- ^ The 'TokenResponse' from the provider failed to decode or
    -- validate.  More information is provided by the @jose@ error.

  | IdentityTokenValidationFailed JWTError
    -- ^ The identity token from the provider is invalid (i.e. one of
    -- the claims is incorrect) or the digital signature on the token
    -- doesn't match any of the keys in the provided key set.

  deriving (Show, Exception)

--------------------------------------------------------------------------------
-- | Send the end-user to this URI after setting a cookie.
--
-- The function for generating a cookie accepts the name of the
-- cookie.  This allows you to give the cookie any name you
-- choose.  Just be sure to retrieve the same cookie from the
-- end-user when creating the 'UserReturnFromRedirect' value.
--
-- The returned cookie has all of its security-related features
-- enabled.  Depending on your hosting requirements you may need
-- to use the @cookie@ package to loosen these restrictions.
--
-- Setting (and retrieving) the given cookie is mandatory.  It is
-- used to cryptographically derive the @state@ and @nonce@ values
-- for request forgery protection and replay protection.
data RedirectTo = RedirectTo Network.URI (ByteString -> SetCookie)

--------------------------------------------------------------------------------
-- | __Step 1: Send the end-user to the provider.__
--
-- This request will create a URI pointing to the provider's
-- authorization end point and a session cookie that must be set
-- in the end-user's browser.
--
-- To create a 'Discovery' value, use the
-- 'OpenID.Connect.Client.Provider.discovery' function.
--
-- To create an 'AuthenticationRequest' value use the
-- 'defaultAuthenticationRequest' function.
authenticationRedirect
  :: MonadRandom m
  => Discovery
  -> AuthenticationRequest
  -> m (Either FlowError RedirectTo)
authenticationRedirect disco req = do
  let uri = authRequestRedirectURI req
  secrets <- generateRandomSecrets
  makeRedirectURI secrets disco req
    & second (`RedirectTo` makeSessionCookie secrets uri)
    & pure

--------------------------------------------------------------------------------
-- | __Step 2. Turn the end-user's authorization token into an identity token.__
--
-- When the end-user returns from the provider they will make a
-- request to your site with some query parameters and a session
-- cookie.  With those values in hand, this function represents
-- a request to receive and validate an identity token from the
-- provider.
--
-- In order to create this function you'll need a few records:
--
--   * The current time given as a 'UTCTime'
--   * A 'Provider' record (discovery document and key set)
--   * Your client 'Credentials'
--   * The request details from the end-user in 'UserReturnFromRedirect'
authenticationSuccess
  :: MonadRandom m
  => HTTPS m
  -> UTCTime
  -> Provider
  -> Credentials
  -> UserReturnFromRedirect
  -> m (Either FlowError (TokenResponse ClaimsSet))
authenticationSuccess https time provider creds user =
  fmap (fmap fst) <$> authenticationSuccessWithJwt https time provider creds user

-- | Same as 'authenticationSuccess' but return also the original id_token as SignedJWT.
--
-- Some endpoints (e.g. the end_session_endpoint) may require the original
-- id_token; this functions allows an application to save it for later use.
--
-- @since 0.2.0
authenticationSuccessWithJwt
  :: MonadRandom m
  => HTTPS m
  -> UTCTime
  -> Provider
  -> Credentials
  -> UserReturnFromRedirect
  -> m (Either FlowError (TokenResponse (ClaimsSet, SignedJWT)))
authenticationSuccessWithJwt https time (Provider disco keys) creds user = runExceptT $ do
  _ <- ExceptT (pure (verifyPostRedirectRequest user))
  token <- ExceptT (exchangeCodeForIdentityToken https time disco creds user)
  ExceptT (pure (fmap (, idToken token) <$> extractClaimsSetFromTokenResponse disco creds token keys time user))

--------------------------------------------------------------------------------
-- | Create the provider authorization redirect URI for the end-user.
makeRedirectURI
  :: Secrets
  -> Discovery
  -> AuthenticationRequest
  -> Either FlowError Network.URI
makeRedirectURI secrets disco AuthenticationRequest{..} =
  let uri = getURI (authorizationEndpoint disco)
  in Right $ uri
       { Network.uriQuery = Char8.unpack
           (renderQuery True (params <> authRequestOtherParams))
       }

  where
    params :: [QueryItem]
    params = filter (isJust . snd)
      [ ("response_type", Just authRequestResponseType)
      , ("client_id",     Just (Text.encodeUtf8 authRequestClientId))
      , ("redirect_uri",  Just redir)
      , ("nonce",         Just (replayProtectionNonce secrets))
      , ("state",         Just (requestForgeryProtectionToken secrets))
      , ("display",       authRequestDisplay)
      , ("prompt",        authRequestPrompt)
      , ("max_age",       Char8.pack . show <$> authRequestMaxAge)
      , ("ui_locales",    Text.encodeUtf8 . fromWords <$> authRequestUiLocales)
      , ("id_token_hint", authRequestIdTokenHint)
      , ("login_hint",    Text.encodeUtf8 <$> authRequestLoginHint)
      , ("acr_values",    Text.encodeUtf8 . fromWords <$> authRequestAcrValues)
      , scopeQueryItem    authRequestScope
      ]

    redir :: ByteString
    redir = Char8.pack (Network.uriToString id authRequestRedirectURI [])

--------------------------------------------------------------------------------
-- | Create a session cookie for the end-user.
makeSessionCookie :: Secrets -> ClientRedirectURI -> ByteString -> SetCookie
makeSessionCookie Secrets{valueForHttpOnlyCookie} uri name =
  Cookie.defaultSetCookie
    { Cookie.setCookieName     = name
    , Cookie.setCookieValue    = valueForHttpOnlyCookie
    , Cookie.setCookiePath     = Just (Char8.pack (Network.uriPath uri))
    , Cookie.setCookieHttpOnly = True
    , Cookie.setCookieSecure   = True
    , Cookie.setCookieSameSite = Just Cookie.sameSiteLax
    }

--------------------------------------------------------------------------------
-- | Validate the @state@ parameter from the end-user.
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
  -> UserReturnFromRedirect
  -> m (Either FlowError (TokenResponse SignedJWT))
exchangeCodeForIdentityToken https now disco creds user = do
    res <- performRequest
    pure (processResponse =<< res)
  where
    performRequest :: m (Either FlowError (HTTP.Response LByteString.ByteString))
    performRequest = runExceptT $ do
      uri <- maybe
        (throwError ProviderMissingTokenEndpointError) pure
        (tokenEndpoint disco)
      req <- maybe
        (throwError (InvalidProviderTokenEndpointError (uriToText (getURI uri)))) pure
        (requestFromURI (Right (getURI uri)))
      lift (applyRequestAuthentication creds authMethods uri now body req) >>= \case
        Nothing -> throwError NoAuthenticationMethodsAvailableError
        Just r  -> lift (https r)

    processResponse
      :: HTTP.Response LByteString.ByteString
      -> Either FlowError (TokenResponse SignedJWT)
    processResponse res =
      parseResponse res
      & bimap InvalidProviderTokenResponseError fst
      >>= (decodeIdentityToken creds >>> first TokenDecodingError)

    authMethods :: [ClientAuthentication]
    authMethods = maybe [ClientSecretPost] NonEmpty.toList
      (tokenEndpointAuthMethodsSupported disco)

    body :: [ (ByteString, ByteString) ]
    body  = [ ("grant_type", "authorization_code")
            , ("code", afterRedirectCodeParam user)
            , ("redirect_uri", Char8.pack (Network.uriToString id (clientRedirectUri creds) []))
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
  -> UserReturnFromRedirect
  -> Either FlowError (TokenResponse ClaimsSet)
extractClaimsSetFromTokenResponse disco creds token keys time user = do
  nonce <- expectedNonce (afterRedirectSessionCookie user)
  verifyIdentityTokenClaims disco (assignedClientId creds) time keys nonce token
   & first IdentityTokenValidationFailed
