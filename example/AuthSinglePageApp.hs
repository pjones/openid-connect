{-# LANGUAGE OverloadedStrings #-}

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
module AuthSinglePageApp (app, initialServerState) where

--------------------------------------------------------------------------------
-- Imports:
import Control.Monad.Except
import Data.ByteString (ByteString, toStrict)
import Data.ByteString.Builder (toLazyByteString)
import qualified Data.ByteString.Char8 as Char8
import qualified Data.ByteString.Lazy.Char8 as LChar8
import Data.Proxy
import qualified Data.Map.Strict as Map
import Data.Text (Text, append)
import qualified Data.Text.IO as TextIO
import Data.Text.Encoding as Text
import Data.Time.Clock (getCurrentTime)
import Network.HTTP.Client (Manager)
import Network.URI (uriToString)
import OpenID.Connect.Client.Flow.AuthorizationCode
import OpenID.Connect.TokenResponse (TokenResponse, idToken)
import Crypto.JWT (ClaimsSet)
import Servant.API
import Servant.HTML.Blaze
import Servant.Server
import Text.Blaze.Html
import qualified Text.Blaze.Html5 as H
import qualified Text.Blaze.Html5.Attributes as A
import Util
import Web.Cookie
import Servant.API.WebSocket (WebSocket)
import qualified Network.WebSockets as WS
import qualified Network.WebSockets.Connection as WSC
import Control.Concurrent (MVar, newEmptyMVar, modifyMVar_, readMVar, takeMVar, putMVar)
import Crypto.Random.Types (getRandomBytes)
import Data.Function ((&))
import Data.ByteArray.Encoding (convertToBase, Base (Base64URLUnpadded))
import qualified Data.Aeson as Aeson
import Servant (serveDirectoryWebApp)

--------------------------------------------------------------------------------
-- | An example of a single-page app in which clicking the login link opens a
-- separate tab. The user logs in within the separate tab while the original tab
-- remains on the same page. When the user has successfully logged in, a
-- WebSocket connection informs the original tab which updates to display the
-- logged-in state, and the login tab closes itself.
--
-- This app is a slightly more complicated variant of the simple example app in
-- the Auth module. (Code from that module is duplicated here for the sake
-- of keeping the examples self-contained.)
--
-- If the --single-page-app argument is specified on the command line, the app
-- from this module is run. Otherwise, the app from the Auth module is run.


type SocketID = Text

-- The server state is a pool of WebSocket connections.
-- * Key: A randomly generated ID for the connection, known by both server and
--   client.
-- * Values: A WebSocket connection, and an exit signal.
type ServerState = Map.Map SocketID (WS.Connection, MVar ())

initialServerState :: ServerState
initialServerState = Map.empty

--------------------------------------------------------------------------------
type Index = "index"
  :> Get '[HTML] Html

--------------------------------------------------------------------------------
type Login = "login"
  :> Get '[HTML] Html

--------------------------------------------------------------------------------
type Success = "return"
  :> QueryParam "code"  Text
  :> QueryParam "state" Text
  :> Header "cookie" SessionCookie
  :> Header "cookie" SocketIDCookie
  :> Get '[HTML] Html

--------------------------------------------------------------------------------
type Failed = "return"
  :> QueryParam "error" Text
  :> QueryParam "state" Text
  :> Header "cookie" SessionCookie
  :> Get '[HTML] Html

--------------------------------------------------------------------------------
type LoginSocket = "wait_for_login" :> WebSocket

--------------------------------------------------------------------------------
type Static = "static" :> Raw

--------------------------------------------------------------------------------
-- | Complete API.
type API = Index :<|> Login :<|> Success :<|> Failed :<|> LoginSocket :<|> Static

--------------------------------------------------------------------------------
-- | A type for getting the session cookie out of the request.
newtype SessionCookie = SessionCookie
  { getSessionCookie :: ByteString
  } deriving (Show, Eq)

newtype SocketIDCookie = SocketIDCookie
  { getSocketIDCookie :: ByteString
  } deriving (Show, Eq)

instance FromHttpApiData SessionCookie where
  parseUrlPiece = parseHeader . Text.encodeUtf8
  parseHeader =
    cookieHeaderParser "session" "session cookie missing" SessionCookie

instance FromHttpApiData SocketIDCookie where
  parseUrlPiece = parseHeader . Text.encodeUtf8
  parseHeader =
    cookieHeaderParser "socketID" "socketID cookie missing" SocketIDCookie

cookieHeaderParser :: ByteString -> Text -> (ByteString -> cookie) ->
  ByteString -> Either Text cookie
cookieHeaderParser desiredKey errorMsgIfMissing cookieConstructor bs =
  case lookup desiredKey (parseCookies bs) of
      Nothing -> Left errorMsgIfMissing
      Just val -> Right (cookieConstructor val)

--------------------------------------------------------------------------------
api :: Proxy API
api = Proxy

--------------------------------------------------------------------------------
app :: MVar ServerState -> Manager -> Provider -> Credentials -> Application
app mvar_serverstate mgr provider creds =
  serve api (handlers mvar_serverstate mgr provider creds)

--------------------------------------------------------------------------------
handlers :: MVar ServerState -> Manager -> Provider -> Credentials -> Server API
handlers mvar_serverstate mgr provider creds =
    index :<|> login :<|> success :<|> failed :<|> waitForLogin :<|> static
  where
    ----------------------------------------------------------------------------
    -- Return the login HTML.
    index :: Server Index
    index = pure . H.docTypeHtml $ do
      H.title "OpenID Connect Login"
      H.p H.! A.id "pic" $ ""
      H.p H.! A.id "login" $ H.a H.! A.href "/login" H.! A.target "_blank" $ "Login"
      H.p H.! A.id "tokens" $ ""
      H.script H.! A.src "static/single_page_app.js" $ ""

    ----------------------------------------------------------------------------
    -- Redirect the user to the provider.
    login :: Server Login
    login = do
      -- If available, request "profile" scope so that we can show user's name
      -- on the page.
      let has_profile = case provider & providerDiscovery & scopesSupported of {
        Nothing -> False;
        Just scope -> hasScope scope "profile" }
      let scope = if has_profile then openid <> profile else openid
      let req = defaultAuthenticationRequest scope creds
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
    success (Just code) (Just state) (Just sessionCookie) (Just socketIDCookie) = do
      let browser = UserReturnFromRedirect
            { afterRedirectCodeParam     = Text.encodeUtf8 code
            , afterRedirectStateParam    = Text.encodeUtf8 state
            , afterRedirectSessionCookie = getSessionCookie sessionCookie
            }
      now <- liftIO getCurrentTime
      r <- liftIO (authenticationSuccess (https mgr) now provider creds browser)
      case r of
        Left e -> throwError (err403 { errBody = LChar8.pack (show e) })
        Right _token -> do

          -- * Send login info to the WebSocket whose ID matches the ID in the
          --   cookie.
          -- * Send exit signal to close the connection.
          let socketID = decodeUtf8 $ getSocketIDCookie socketIDCookie
          serverstate <- liftIO $ readMVar mvar_serverstate
          liftIO $ case Map.lookup socketID serverstate of
            Nothing -> TextIO.putStrLn $
              "No connection for socketID " `append` socketID
            Just (conn, exitSignal) -> do
              WS.sendTextData conn $ afterLoginMessage _token
              putMVar exitSignal ()
              -- Remove this connection from server state.
              modifyMVar_ mvar_serverstate (return . Map.delete socketID)

          pure . H.docTypeHtml $ do
            H.title "Success!"
            H.h1 "Successful Authentication. Returning to main page."
            H.script $ H.preEscapedText
              "setTimeout(function() {window.close();}, 1000);"
      where
        afterLoginMessage :: TokenResponse ClaimsSet -> Text
        afterLoginMessage tr = the_dict & Aeson.encode & toStrict & decodeUtf8
          where
            access_tokens = Aeson.toJSON $
              (const Nothing <$> tr :: TokenResponse (Maybe Text))
            id_token = Aeson.toJSON $ idToken tr
            the_dict = Map.fromList [
              ("access_tokens", access_tokens),
              ("id_token", id_token)] :: Map.Map Text Aeson.Value

    ----------------------------------------------------------------------------
    -- Should have been a success, but one or more params are missing.
    success _ _ _ _ = failed (Just "missing params") Nothing Nothing

    ----------------------------------------------------------------------------
    -- User returned from provider with an authentication failure.
    failed :: Server Failed
    failed err _ _ = throwError $
      err400 { errBody = maybe "WTF?" (LChar8.fromStrict . Text.encodeUtf8) err
             }
    ----------------------------------------------------------------------------
    -- WebSocket that will notify client once login is complete.
    waitForLogin :: Server LoginSocket
    waitForLogin = streamData
      where
        streamData :: MonadIO m => WS.Connection -> m ()
        streamData conn = do
          -- * Generate and send socket ID to client (to be stored in a cookie).
          -- * Spin off a ping thread that keeps the connection alive.
          -- * Then block until we receive the exit signal from another thread.
          -- Another thread sends the actual login notification to the client.
          -- The connection is automatically closed once this IO action
          -- finishes, which is why a signal must be used to keep it from
          -- finishing prematurely.
          socketID <- liftIO $ decodeUtf8 . convertToBase Base64URLUnpadded <$>
            (getRandomBytes 32 :: IO ByteString)
          exitSignal <- liftIO (newEmptyMVar :: IO (MVar ()))
          liftIO $ modifyMVar_ mvar_serverstate $ \ss ->
            return $ Map.insert socketID (conn, exitSignal) ss
          liftIO $ WS.sendTextData conn (socketIDMessage socketID)
          liftIO $ WSC.withPingThread conn 30 (return ()) $ do
            takeMVar exitSignal

        socketIDMessage :: Text -> Text
        socketIDMessage socketID = the_dict & Aeson.encode & toStrict & decodeUtf8
          where
            the_dict = Map.fromList [("socketID", socketID)] :: Map.Map Text Text

    static :: Server Static
    static = serveDirectoryWebApp "static"