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
module Auth (app) where

--------------------------------------------------------------------------------
-- Imports:
import Control.Monad.Except
import Crypto.JWT hiding (uri)
import Data.ByteString (ByteString)
import Data.ByteString.Builder (toLazyByteString)
import qualified Data.ByteString.Char8 as Char8
import qualified Data.ByteString.Lazy.Char8 as LChar8
import Data.Proxy
import Data.Text as Text (Text, pack, splitAt, toLower)
import Data.Text.Encoding as Text
import Data.Time.Clock (getCurrentTime)
import Network.HTTP.Client (Manager)
import Network.URI (uriToString)
import OpenID.Connect.Client.Flow.AuthorizationCode
import OpenID.Connect.TokenResponse (accessToken)
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
  :> QueryParam' '[Required] "code"  Text
  :> QueryParam' '[Required] "state" Text
  :> Header' '[Required] "cookie" SessionCookie
  :> Get '[HTML] Html

--------------------------------------------------------------------------------
type Failed = "return"
  :> QueryParam "error" Text
  :> QueryParam "state" Text
  :> Header "cookie" SessionCookie
  :> Get '[HTML] Html

-------------------------------------------------------------------------------
type Protected = "protected"
  :> Header' '[Required] "Authorization" Text
  :> Get '[HTML] Html

--------------------------------------------------------------------------------
-- | Complete API.
type API = Index :<|> Login :<|> Success :<|> Failed :<|> Protected

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
    index :<|> login :<|> success :<|> failed :<|> protected
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
    success code state cookie = do
      let browser = UserReturnFromRedirect
            { afterRedirectCodeParam     = Text.encodeUtf8 code
            , afterRedirectStateParam    = Text.encodeUtf8 state
            , afterRedirectSessionCookie = getSessionCookie cookie
            }

      now <- liftIO getCurrentTime
      r <- liftIO (authenticationSuccess (https mgr) now provider creds browser)
      case r of
        Left e -> throwError (err403 { errBody = LChar8.pack (show e) })
        Right token -> pure . H.docTypeHtml $ do
          H.title "Success!"
          H.h1 "Successful Authentication"
          H.p $ H.text $ "Your access token: " <> accessToken token

    ----------------------------------------------------------------------------
    -- User returned from provider with an authentication failure.
    failed :: Server Failed
    failed err _ _ = throwError $
      err400 { errBody = maybe "WTF?" (LChar8.fromStrict . Text.encodeUtf8) err
             }

    ----------------------------------------------------------------------------
    -- User tries to access content protected by authentication.
    protected :: Server Protected
    protected bearer = do
      let (initial, token) = Text.splitAt 7 bearer
          validator = defaultJWTValidationSettings (== "account")
      when (Text.toLower initial /= "bearer ") $ throwError err400
      now <- liftIO getCurrentTime
      validated :: Either JWTError a <- runExceptT $
        decodeCompact (LChar8.fromStrict (Text.encodeUtf8 token)) >>=
        verifyClaimsAt validator (providerKeys provider) now
      case validated of
        Left e -> throwError (err403 { errBody = LChar8.pack (show e) })
        Right claims -> pure . H.docTypeHtml $ do
          H.title "Accessing protected resource"
          H.h1 "Successful authentication with Bearer token"
          H.p $ H.text $ "Your claims: " <> Text.pack (show claims)
