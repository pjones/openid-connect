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
module Discover
  ( getProvider
  , getCredentials
  ) where

--------------------------------------------------------------------------------
-- Imports:
import Control.Lens ((^.))
import Crypto.JOSE (JWK, JWKSet(..), asPublicKey)
import qualified Data.Aeson as Aeson
import qualified Data.ByteString.Lazy.Char8 as Char8
import Data.List.NonEmpty (NonEmpty(..))
import Data.Text (Text)
import Network.HTTP.Client (Manager)
import OpenID.Connect.Authentication
import OpenID.Connect.Client.DynamicRegistration as R
import OpenID.Connect.Client.Provider
import OpenID.Connect.Provider.Key
import Options
import Util

--------------------------------------------------------------------------------
-- | Fetch the provider's discovery document and signing keys.
getProvider :: Options -> Manager -> IO Provider
getProvider opts mgr =
  discoveryAndKeys (https mgr) (optionsProviderUri opts) >>= \case
    Left err     -> fail (show err)
    Right (x, _) -> pure (x { providerDiscovery =
                              updateDisco (providerDiscovery x) })

  where
    updateDisco :: Discovery -> Discovery
    updateDisco d =
      case optionsForceAuthMode opts of
        ForceSecretPost ->
          d {tokenEndpointAuthMethodsSupported =
             Just (ClientSecretPost :| [])}
        ForceSecretJWT ->
          d {tokenEndpointAuthMethodsSupported =
             Just (ClientSecretJwt :| [])}
        ForcePrivateJWT ->
          d {tokenEndpointAuthMethodsSupported =
             Just (PrivateKeyJwt :| [])}
        NoForcedAuth ->
          d

--------------------------------------------------------------------------------
-- | Construct client credentials.
getCredentials
  :: Options
  -> Manager
  -> Provider
  -> IO Credentials
getCredentials opts mgr provider =
  case optionsClientDetails opts of
    Direct cid csec -> pure (build csec cid)
    Register email -> register email

  where
    register :: Text -> IO Credentials
    register email = do
      key <- newSigningJWK
      let metadata = clientMetadata (regReq email key) BasicRegistration
      putStrLn "Performing dynamic client registration:"
      Char8.putStrLn (Aeson.encode metadata)

      registerClient (https mgr) (providerDiscovery provider) metadata >>= \case
        Left e -> fail (show e)
        Right x -> do
          let res = clientSecretsFromResponse x
          putStrLn "Registration successful:" >> print res
          pure (build (R.clientId res) (toClientSecret key (R.clientSecret res)))

    regReq :: Text -> JWK -> Registration
    regReq email key =
      let reg = defaultRegistration (optionsClientUri opts)
      in  reg { R.contacts = Just (email :| [])
              , R.tokenEndpointAuthMethod = defaultAuthMethod
              , R.jwks = JWKSet . pure <$> (key ^. asPublicKey)
              }

    defaultAuthMethod :: ClientAuthentication
    defaultAuthMethod = case optionsForceAuthMode opts of
      ForceSecretPost -> ClientSecretPost
      ForceSecretJWT  -> ClientSecretJwt
      ForcePrivateJWT -> PrivateKeyJwt
      NoForcedAuth    -> ClientSecretBasic

    toClientSecret :: JWK -> Maybe Text -> ClientSecret
    toClientSecret key = \case
      Nothing ->
        case optionsForceAuthMode opts of
          ForceSecretPost -> AssignedSecretText "should fail"
          ForceSecretJWT  -> AssignedAssertionText "should fail"
          ForcePrivateJWT -> AssertionPrivateKey key
          NoForcedAuth    -> AssignedSecretText "should fail"
      Just sec ->
        case optionsForceAuthMode opts of
          ForceSecretPost -> AssignedSecretText sec
          ForceSecretJWT  -> AssignedAssertionText sec
          ForcePrivateJWT -> AssertionPrivateKey key
          NoForcedAuth    -> AssignedSecretText sec

    build :: Text -> ClientSecret -> Credentials
    build cid csec =
      Credentials
        { assignedClientId  = cid
        , clientSecret      = csec
        , clientRedirectUri = optionsClientUri opts
        }
