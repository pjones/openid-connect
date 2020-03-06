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
module Auth (app) where

--------------------------------------------------------------------------------
-- Imports:
import Control.Monad.Except
import Control.Monad.IO.Class (liftIO)
import Data.ByteString (ByteString)
import Data.ByteString.Builder (toLazyByteString)
import qualified Data.ByteString.Char8 as Char8
import qualified Data.ByteString.Lazy.Char8 as LChar8
import Data.Proxy
import Data.Text (Text)
import Data.Text.Encoding as Text
import Data.Time.Clock (getCurrentTime)
import Network.HTTP.Client (Manager)
import Network.URI (uriToString)
import OpenID.Connect.Client.Flow.AuthorizationCode
import Servant.API
import Servant.HTML.Blaze
import Servant.Server
import Text.Blaze.Html
import qualified Text.Blaze.Html5 as H
import qualified Text.Blaze.Html5.Attributes as A
import Util
import Web.Cookie

--------------------------------------------------------------------------------
type Index = "index"
  :> Get '[HTML] Html

--------------------------------------------------------------------------------
type Login = "login" :> Get '[HTML] Html

--------------------------------------------------------------------------------
type Success = "return"
  :> QueryParam "code"  Text
  :> QueryParam "state" Text
  :> Header "cookie" SessionCookie
  :> Get '[HTML] Html

--------------------------------------------------------------------------------
type Failed = "return"
  :> QueryParam "error" Text
  :> QueryParam "state" Text
  :> Header "cookie" SessionCookie
  :> Get '[HTML] Html

--------------------------------------------------------------------------------
-- | Complete API.
type API = Index :<|> Login :<|> Success :<|> Failed

--------------------------------------------------------------------------------
-- | A type for getting the session cookie out of the request.
newtype SessionCookie = SessionCookie
  { getSessionCookie :: ByteString
  }

instance FromHttpApiData SessionCookie where
  parseUrlPiece = parseHeader . Text.encodeUtf8
  parseHeader bs =
    case lookup "session" (parseCookies bs) of
      Nothing -> Left "session cookie missing"
      Just val -> Right (SessionCookie val)

--------------------------------------------------------------------------------
api :: Proxy API
api = Proxy

--------------------------------------------------------------------------------
app :: Manager -> Provider -> Credentials -> Application
app mgr provider creds = serve api (handlers mgr provider creds)

--------------------------------------------------------------------------------
handlers :: Manager -> Provider -> Credentials -> Server API
handlers mgr provider creds =
    index :<|> login :<|> success :<|> failed
  where
    ----------------------------------------------------------------------------
    -- Return the login HTML.
    index :: Server Index
    index = pure . H.docTypeHtml $ do
      H.title "OpenID Connect Login"
      H.p (H.a H.! A.href "/login" $ "Login")

    ----------------------------------------------------------------------------
    -- Redirect the user to the provider.
    login :: Server Login
    login = do
      let req = defaultAuthenticationRequest openid creds
      r <- liftIO (authenticationRedirect (providerDiscovery provider) req)
      case r of
        Left e -> throwError (err403 { errBody = LChar8.pack (show e) })
        Right (RedirectTo uri cookie) ->
          throwError (err302
            { errHeaders =
                [ ("Location", Char8.pack (uriToString id uri []))
                , ("Set-Cookie", LChar8.toStrict
                    (toLazyByteString (renderSetCookie (cookie "session"))))
                ]
            })

    ----------------------------------------------------------------------------
    -- User returned from provider with a successful authentication.
    success :: Server Success
    success (Just code) (Just state) (Just cookie) = do
      let browser = UserReturnFromRedirect
            { afterRedirectCodeParam     = Text.encodeUtf8 code
            , afterRedirectStateParam    = Text.encodeUtf8 state
            , afterRedirectSessionCookie = getSessionCookie cookie
            }

      now <- liftIO getCurrentTime
      r <- liftIO (authenticationSuccess (https mgr) now provider creds browser)
      case r of
        Left e -> throwError (err403 { errBody = LChar8.pack (show e) })
        Right _token -> pure . H.docTypeHtml $ do
          H.title "Success!"
          H.h1 "Successful Authentication"

    ----------------------------------------------------------------------------
    -- Should have been a success, but one or more params are missing.
    success _ _ _ = failed (Just "missing params") Nothing Nothing

    ----------------------------------------------------------------------------
    -- User returned from provider with an authentication failure.
    failed :: Server Failed
    failed err _ _ = throwError $
      err400 { errBody = maybe "WTF?" (LChar8.fromStrict . Text.encodeUtf8) err
             }
