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
module OpenID.Connect.Client.Provider
  ( Discovery(..)
  , Provider(..)
  , ProviderDiscoveryURI
  , DiscoveryError(..)
  , discovery
  , keysFromDiscovery
  , discoveryAndKeys

    -- * Re-exports
  , HTTPS
  , LByteString
  ) where

--------------------------------------------------------------------------------
-- Imports:
import Control.Monad.Except (ExceptT(..), runExceptT)
import Crypto.JOSE.JWK (JWKSet)
import Data.Bifunctor (first)
import Data.Functor ((<&>))
import Data.List.NonEmpty (NonEmpty)
import Data.Text (Text)
import qualified Data.Text as Text
import Data.Time.Clock (UTCTime)
import GHC.Generics (Generic)
import Network.HTTP.Client (requestFromURI_)
import Network.URI (URI(..), parseURI)
import OpenID.Connect.Client.Authentication
import OpenID.Connect.Client.HTTP
import OpenID.Connect.Client.Scope
import OpenID.Connect.JSON

--------------------------------------------------------------------------------
type ProviderDiscoveryURI = URI

--------------------------------------------------------------------------------
data DiscoveryError
  = JsonDecodingError String
  | InvalidUrlError Text
  deriving Show

--------------------------------------------------------------------------------
data Discovery = Discovery
  { issuer                            :: Text
  , authorizationEndpoint             :: Text
  , tokenEndpoint                     :: Maybe Text
  , userinfoEndpoint                  :: Maybe Text
  , jwksUri                           :: Text
  , scopesSupported                   :: Maybe Scope
  , responseTypesSupported            :: NonEmpty Text
  , tokenEndpointAuthMethodsSupported :: [ClientAuthentication]
  }
  deriving stock (Generic, Show)
  deriving (ToJSON, FromJSON) via GenericJSON Discovery

--------------------------------------------------------------------------------
data Provider = Provider
  { providerDiscovery :: Discovery  -- ^ Details from the discovery URI.
  , providerKeys      :: JWKSet     -- ^ Keys from the @jwksUri@.
  }

--------------------------------------------------------------------------------
discovery
  :: Functor m
  => ProviderDiscoveryURI
  -> HTTPS m
  -> m (Either DiscoveryError (Discovery, Maybe UTCTime))
discovery uri https =
  https (requestFromURI_ . setPath . forceHTTPS $ uri)
    <&> parseResponse
    <&> first JsonDecodingError
  where
    setPath :: URI -> URI
    setPath u@URI{uriPath} =
      if null uriPath || uriPath == "/"
        then u {uriPath = "/.well-known/openid-configuration"}
        else u

--------------------------------------------------------------------------------
keysFromDiscovery
  :: Applicative m
  => Discovery
  -> HTTPS m
  -> m (Either DiscoveryError (JWKSet, Maybe UTCTime))
keysFromDiscovery Discovery{jwksUri} https =
  case parseURI (Text.unpack jwksUri) of
    Nothing -> pure (Left (InvalidUrlError jwksUri))
    Just uri ->
      https (requestFromURI_ . forceHTTPS $ uri)
        <&> parseResponse
        <&> first JsonDecodingError

--------------------------------------------------------------------------------
discoveryAndKeys
  :: Monad m
  => ProviderDiscoveryURI
  -> HTTPS m
  -> m (Either DiscoveryError (Provider, Maybe UTCTime))
discoveryAndKeys uri https = runExceptT $ do
  (d, t1) <- ExceptT (discovery uri https)
  (k, t2) <- ExceptT (keysFromDiscovery d https)
  pure (Provider d k, min <$> t1 <*> t2)
