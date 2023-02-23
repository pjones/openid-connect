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
module Site (API, handlers) where

--------------------------------------------------------------------------------
-- Imports:
import Control.Monad.Except
import Crypto.JWT hiding (uri)
import qualified Data.ByteString.Lazy.Char8 as LChar8
import Data.Text (Text)
import qualified Data.Text as Text
import Data.Text.Encoding (encodeUtf8)
import Data.Time.Clock (getCurrentTime)
import OpenID.Connect.Client.Flow.AuthorizationCode
import Network.HTTP.Client
import Network.HTTP.Types.Status (statusIsSuccessful)
import Servant.API
import Servant.HTML.Blaze
import Servant.Server
import Text.Blaze.Html
import qualified Text.Blaze.Html5 as H

--------------------------------------------------------------------------------
-- | An example of what a server using OpenID Connect for
-- authorization could look like, using JWT Bearer Tokens.
--
-- One form of authentication used by servers is Bearer Tokens.  From
-- a client's perspective, it's an opaque text string that is passed
-- by using the Authorization HTTP header and it always starts with
-- the string "Bearer ", followed by the token.  Its use is defined in
-- RFC 6750.
--
-- With OpenID Connect, the access token given by a provider is a JWT
-- string, which is authenticated by the provider's private key.  It
-- can be used as a Bearer Token by itself.  While using one is
-- outside of the scope of the flows defined in OpenID Connect, it
-- provides all the keys and endpoints required to make it work.
--
-- Using JWT Bearer Tokens, a server implementation needs to keep no
-- state regarding authorization and it relies on provider's keys and
-- end points to manage that for it.
--
-- JWT Bearer Tokens are defined in RFC 9068.  It's recommended that
-- any clients still don't rely on the Bearer Token to contain any
-- data and you'll have to decide if the payload in JWT is something
-- you don't want the client to see in your application.

--------------------------------------------------------------------------------
-- | A dummy application.  All parameters it'd have are omitted.  A
-- client side implementation of how to pass the Authorization header
-- is also omitted from this example, but you can take the access
-- token printed out by the authentication example's success endpoint
-- and use it like "Authorization: Bearer <token>".
--
-- In this example the authentication flow is implemented on the same
-- server as this application, but they could well be placed on
-- different hosts and it'd still work as long as they share the same
-- OpenID Connect settings.
type ListArticles = "list"
  :> Header' '[Required] "Authorization" Text
  :> Get '[HTML] Html

type EditArticle = "edit"
  :> Header' '[Required] "Authorization" Text
  :> Get '[HTML] Html

type API = "site" :> SiteAPI

type SiteAPI = ListArticles :<|> EditArticle

handlers :: Manager -> Provider -> Server API
handlers mgr provider =
    listArticles :<|> editArticle
  where
    validationError :: ServerError
    validationError = err401 { errHeaders = [ ("WWW-Authenticate", "Bearer") ] }

    ----------------------------------------------------------------------------
    -- Validate a JWT Bearer Token, using the provider's public key.
    -- Your HTTP server library (Servant included) is likely to have
    -- its own implementation of authorization header handling and
    -- you'd likely be better off using it in production, but this is
    -- doing all of it directly for demonstration's sake.
    validateAuthorization authorization = do
      -- Check that it looks like a Bearer Token.
      let (initial, token) = encodeUtf8 <$> Text.splitAt 7 authorization
      when (Text.toLower initial /= "bearer ") $ throwError validationError

      -- Validating a JWT token requires 3 things: A public key, a
      -- time stamp and matching the audience field with your
      -- application's data.  The last part is required since
      -- otherwise any JWT token acquired from the provider would give
      -- access to this application.  It's provider specific how
      -- that's set up so we're just skipping that part.
      let validator = defaultJWTValidationSettings $ const True
      now <- liftIO getCurrentTime

      -- Decode and validate the JWT.
      validated :: Either JWTError a <- runExceptT $
        decodeCompact (LChar8.fromStrict token) >>=
        verifyClaimsAt validator (providerKeys provider) now
      case validated of
        Left e -> throwError $ validationError { errBody = LChar8.pack (show e) }
        Right claims -> pure (token, claims)

    ----------------------------------------------------------------------------
    -- It's up to your application to determine how strict
    -- requirements you have for authorization.  First an example of a
    -- more permissive end point.
    listArticles :: Server ListArticles
    listArticles authorization = do
      _ <- validateAuthorization authorization
      -- One option with using JWT Bearer Tokens is to only validate
      -- them with the provider's public key.  It's not even necessary
      -- to access the provider if your application doesn't need
      -- strict control about logging out with the provider or need
      -- the latest data.
      --
      -- Many providers give provider specific extra data in the JWT
      -- data, like scopes and roles defined with it.  JOSE library
      -- allows accessing such data.  See Crypto.JWT for examples.
      pure . H.docTypeHtml $ do
        H.title "List of articles"
        H.h1 "Articles"

    ----------------------------------------------------------------------------
    -- An example of a more strictly controlled end point.
    editArticle :: Server EditArticle
    editArticle authorization = do
      -- Again, validate with the public key first.  Accessing the
      -- provider for verification would fail regardless if this
      -- didn't pass.
      (token, _) <- validateAuthorization authorization

      -- For this endpoint, we're requiring that the user is still
      -- logged in with the provider.  To do that, we're accessing the
      -- token endpoint.  "scope" is also a supported parameter.  See
      -- RFC 6749 section 4.4.2.
      endpoint <- case tokenEndpoint (providerDiscovery provider) of
        Nothing -> throwError err500
        Just endpoint -> pure $ getURI endpoint

      request <- liftIO $ applyBearerAuth token
        . setQueryString [("grant_type", Just "client_credentials")]
        <$> requestFromURI endpoint
      response <- liftIO $ httpNoBody request mgr

      when (not $ statusIsSuccessful $ responseStatus response) $
        throwError validationError

      pure . H.docTypeHtml $ do
        H.title "Article editor"
        H.h1 "Article editor"
