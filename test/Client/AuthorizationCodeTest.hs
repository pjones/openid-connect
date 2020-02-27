{-# LANGUAGE QuasiQuotes #-}

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
module Client.AuthorizationCodeTest
  ( test
  ) where

--------------------------------------------------------------------------------
-- Imports:
import Control.Lens ((&), (?~), (#), (.~), (^?))
import Control.Monad.Except
import Crypto.JOSE (JWK, JWKSet(..))
import Crypto.JOSE.Compact
import Crypto.JWT (ClaimsSet)
import qualified Crypto.JWT as JWT
import qualified Data.Aeson as Aeson
import qualified Data.ByteString.Char8 as Char8
import qualified Data.ByteString.Lazy.Char8 as LChar8
import Data.Text (Text)
import qualified Data.Text as Text
import qualified Data.Text.Encoding as Text
import Data.Time.Clock (UTCTime, getCurrentTime, addUTCTime)
import HttpHelper
import qualified Network.HTTP.Client as HTTP
import Network.HTTP.Types
import Network.URI (URI(..), uriToString)
import qualified Network.URI.Static as URI
import OpenID.Connect.Client.Flow.AuthorizationCode
import OpenID.Connect.Provider.Key
import OpenID.Connect.TokenResponse
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit
import Web.Cookie (SetCookie, setCookieValue)

--------------------------------------------------------------------------------
test :: TestTree
test = testGroup "Authorization Code Flow"
  [ testCase "auth code" testAuthCodeRedir
  , testCase "token exchange" testTokenExchange
  ]

--------------------------------------------------------------------------------
credentials :: Credentials
credentials =
  Credentials
    { assignedClientId = "phiKei4uZeeGhaizaiph"
    , clientSecret = AssignedSecretText "oxei7ohsh0hoo7buoSui"
    , clientRedirectUri = [URI.uri|https://example.com/redir|]
    }

--------------------------------------------------------------------------------
authRequest :: AuthenticationRequest
authRequest = defaultAuthenticationRequest openid credentials

--------------------------------------------------------------------------------
redirUriAndCookie :: Discovery -> IO (URI, SetCookie)
redirUriAndCookie disco =
  step httpNoOp (Authenticate disco authRequest) >>= \case
    Success _             -> assertFailure "did not expect Success"
    Failed _              -> assertFailure "did not expect Failed"
    RedirectTo uri cookie -> pure (uri, cookie "foo")

--------------------------------------------------------------------------------
providerTestKeys :: IO (JWK, JWKSet)
providerTestKeys = do
  Just (JWKSet others) <- Aeson.decodeFileStrict "test/data/certs.txt"
  key <- newSigningJWK
  pure (key, JWKSet (others <> [key]))

--------------------------------------------------------------------------------
testClaims :: UTCTime -> Discovery -> Text -> ClaimsSet
testClaims now disco nonce
  = JWT.emptyClaimsSet
  & JWT.claimIss .~ (issuer disco ^? JWT.stringOrUri)
  & JWT.claimAud ?~ JWT.Audience [JWT.string # assignedClientId credentials]
  & JWT.claimIat ?~ JWT.NumericDate (addUTCTime (-30) now)
  & JWT.claimExp ?~ JWT.NumericDate (addUTCTime 300 now)
  & JWT.addClaim "nonce" (Aeson.toJSON nonce)

--------------------------------------------------------------------------------
testAuthCodeRedir :: Assertion
testAuthCodeRedir = do
    Just disco <- Aeson.decodeFileStrict "test/data/discovery.txt"
    (uri, cookie) <- redirUriAndCookie disco

    uriPath  uri @?= "/o/oauth2/v2/auth"
    uriStart uri @?= (authorizationEndpoint disco <> "?")
    assertBool "cookie value" (cookieBytes cookie > 0)

  where
    -- The URI up to and including the ?
    uriStart :: URI -> Text
    uriStart u = Text.dropWhileEnd (/= '?') (Text.pack (uriToString id u []))

    cookieBytes :: SetCookie -> Int
    cookieBytes = Char8.length . setCookieValue

--------------------------------------------------------------------------------
extractQueryParam :: URI -> Char8.ByteString -> IO Char8.ByteString
extractQueryParam uri name =
  case join (lookup name (parseQuery (Char8.pack (uriQuery uri)))) of
    Nothing -> assertFailure ("missing query param: " <> show name)
    Just p  -> pure p

--------------------------------------------------------------------------------
userReturn :: URI -> SetCookie -> IO UserReturnFromRedirect
userReturn uri cookie = do
  stateParam <- extractQueryParam uri "state"
  pure UserReturnFromRedirect
    { afterRedirectSessionCookie = setCookieValue cookie
    , afterRedirectCodeParam     = "aezoh0fahzu5iekeeX3u"
    , afterRedirectStateParam    = stateParam
    }

--------------------------------------------------------------------------------
testTokenExchange :: Assertion
testTokenExchange = do
    Just disco <- Aeson.decodeFileStrict "test/data/discovery.txt"
    (uri, cookie) <- redirUriAndCookie disco
    (key, keyset) <- providerTestKeys
    now <- getCurrentTime
    browser <- userReturn uri cookie
    nonce <- extractQueryParam uri "nonce"

    let makeRequest = makeRequest_ now disco key
        claims = testClaims now disco (Text.decodeUtf8 nonce)

    -- Happy path:
    makeRequest claims keyset browser
      >>= validateRequest
      >>= assertResponseSuccess

    -- Wrong cookie:
    makeRequest claims keyset
      (browser { afterRedirectSessionCookie = "foo"
               }) >>= assertNoRequestMade
                  >>= assertResponseFailed

    -- Wrong state field:
    makeRequest claims keyset
      (browser { afterRedirectStateParam = "foo"
               }) >>= assertNoRequestMade
                  >>= assertResponseFailed

    -- Multiple audience entries without an AZP:
    let dupAud = JWT.Audience
          [ JWT.string # assignedClientId credentials
          , JWT.string # assignedClientId credentials
          ]
    makeRequest (claims & JWT.claimAud ?~ dupAud)
      keyset browser >>= validateRequest
                     >>= assertResponseFailed

    -- Multiple audience entries with an AZP:
    let withAzp = JWT.addClaim "azp" (Aeson.String (assignedClientId credentials))
    makeRequest (claims & JWT.claimAud ?~ dupAud & withAzp)
      keyset browser >>= validateRequest
                     >>= assertResponseSuccess

    -- Wrong nonce:
    let wrongNonce = "foo" :: Text
    makeRequest (claims & JWT.addClaim "nonce" (Aeson.toJSON wrongNonce))
      keyset browser >>= validateRequest
                     >>= assertResponseFailed

    -- Wrong audience:
    makeRequest (claims & JWT.claimAud ?~ JWT.Audience [JWT.string # "foo"])
      keyset browser >>= validateRequest
                     >>= assertResponseFailed

    -- Wrong issuer:
    let wrongIssuer = "foo" :: Text
    makeRequest (claims & JWT.claimIss .~ wrongIssuer ^? JWT.stringOrUri)
      keyset browser >>= validateRequest
                     >>= assertResponseFailed

    -- Expired claims:
    makeRequest (claims & JWT.claimExp ?~ JWT.NumericDate (addUTCTime (-300) now))
      keyset browser >>= validateRequest
                     >>= assertResponseFailed

    -- Wrong Keys:
    Just wrongKeys <- Aeson.decodeFileStrict "test/data/certs.txt"
    makeRequest claims wrongKeys browser
      >>= validateRequest
      >>= assertResponseFailed

  where
    makeRequest_
      :: UTCTime
      -> Discovery
      -> JWK
      -> ClaimsSet
      -> JWKSet
      -> UserReturnFromRedirect
      -> IO (Response, HTTP.Request)
    makeRequest_ time disco key claims keyset browser = do
      claims' <- runExceptT
        (do algo <- JWT.bestJWSAlg key
            JWT.signClaims key (JWT.newJWSHeader ((), algo)) claims)
        >>= \case
          Left (e :: JWT.JWTError) -> fail (show e)
          Right a -> pure a

      let token = TokenResponse
            { accessToken = "Iegoe0sheeSeo3veesoo"
            , tokenType   = "Bearer"
            , expiresIn   = Just 3600
            , refreshToken = Nothing
            , scope = Nothing
            , idToken = Text.decodeUtf8 (LChar8.toStrict (encodeCompact claims'))
            }

      let https = fakeHttpsFromByteString (Aeson.encode token) & mkHTTPS
          provider = Provider disco keyset
      runHTTPS (step https (Finish time provider credentials browser))

    validateRequest :: (a, HTTP.Request) -> IO a
    validateRequest (x, req) = do
      HTTP.method req @?= "POST"
      uriScheme (HTTP.getUri req) @?= "https:"
      assertBool "should be a secure connection" (HTTP.secure req)
      pure x

    assertNoRequestMade :: (a, HTTP.Request) -> IO a
    assertNoRequestMade (x, req) = do
      HTTP.method req @?= "NONE" -- See HttpHelper.hs
      pure x

    assertResponseSuccess :: Response -> Assertion
    assertResponseSuccess = \case
      RedirectTo _ _ -> assertFailure "didn't expect RedirectTo"
      Failed e       -> assertFailure ("didn't expect Failed: " <> show e)
      Success _      -> pure ()

    assertResponseFailed :: Response -> Assertion
    assertResponseFailed = \case
      RedirectTo _ _ -> assertFailure "didn't expect RedirectTo"
      Success _      -> assertFailure "didn't expect Success"
      Failed _       -> pure ()
