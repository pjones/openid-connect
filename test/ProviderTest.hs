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
module ProviderTest
  ( test
  ) where

--------------------------------------------------------------------------------
import Crypto.JOSE.JWK (JWKSet(..))
import qualified Data.Aeson as Aeson
import qualified Data.ByteString.Lazy.Char8 as LChar8
import HTTP
import qualified Network.HTTP.Client.Internal as HTTP
import qualified Network.HTTP.Types.Header as HTTP
import Network.URI (parseURI)
import OpenID.Connect.Client.Provider
import OpenID.Connect.Scope
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit

--------------------------------------------------------------------------------
test :: TestTree
test = testGroup "Provider"
  [ testCase "discovery" testDiscoveryParsing
  , testCase "JWK Set" testKeyParsing
  ]

--------------------------------------------------------------------------------
testDiscoveryParsing :: Assertion
testDiscoveryParsing = do
  let fake = defaultFakeHTTPS "test/data/discovery.txt"
      https = mkHTTPS fake
  url <- maybe (fail "WTF?") pure (parseURI "https://accounts.google.com/")
  (res, req) <- runHTTPS (discovery url https)

  HTTP.path req   @?= "/.well-known/openid-configuration"
  HTTP.method req @?= "GET"
  HTTP.secure req @?= True

  case res of
    Left e -> fail (show e)
    Right (Discovery{..}, cache) -> do
      issuer @?= "https://accounts.google.com"
      authorizationEndpoint @?= "https://accounts.google.com/o/oauth2/v2/auth"
      jwksUri @?= "https://www.googleapis.com/oauth2/v3/certs"

      fmap (`hasScope` "openid") scopesSupported  @?= Just True
      fmap (`hasScope` "email") scopesSupported   @?= Just True
      fmap (`hasScope` "profile") scopesSupported @?= Just True
      fmap show cache                             @?= Just "2020-02-20 20:40:21 UTC"

--------------------------------------------------------------------------------
testKeyParsing :: Assertion
testKeyParsing = do
  let fake = (defaultFakeHTTPS "test/data/certs.txt")
        { fakeHeaders =
            [ (HTTP.hDate, "Thu, 20 Feb 2020 22:26:11 GMT")
            , (HTTP.hExpires, "Fri, 21 Feb 2020 03:59:07 GMT")
            , (HTTP.hCacheControl, "public, max-age=19976, must-revalidate, no-transform")
            ]
        }

      https = mkHTTPS fake

  Just disco <- Aeson.decode <$> LChar8.readFile "test/data/discovery.txt"
  (res, req) <- runHTTPS (keysFromDiscovery disco https)

  HTTP.path req   @?= "/oauth2/v3/certs"
  HTTP.method req @?= "GET"
  HTTP.secure req @?= True

  case res of
    Left e -> fail (show e)
    Right (JWKSet jwks, cache) -> do
      length jwks @?= 2
      fmap show cache @?= Just "2020-02-21 03:59:07 UTC"
