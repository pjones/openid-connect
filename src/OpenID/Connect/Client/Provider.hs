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

Provider details needed by clients.

-}
module OpenID.Connect.Client.Provider
  (
    -- * Provider discovery
    ProviderDiscoveryURI
  , discovery

    -- * Provider key sets
  , keysFromDiscovery

    -- * Provider convenience record
  , Provider(..)
  , discoveryAndKeys

    -- * Error handling
  , DiscoveryError(..)

    -- * Discovery document
  , Discovery(..)
  ) where

--------------------------------------------------------------------------------
-- Imports:
import Control.Monad.Except (ExceptT(..), runExceptT)
import Crypto.JOSE.JWK (JWKSet)
import Data.Bifunctor (first)
import Data.Functor ((<&>))
import Data.Text (Text)
import Data.Time.Clock (UTCTime)
import Network.URI (URI(..))
import OpenID.Connect.Client.HTTP
import OpenID.Connect.Discovery

--------------------------------------------------------------------------------
-- | Errors that may occur during provider discovery.
--
-- @since 0.1.0.0
data DiscoveryError
  = JsonDecodingError String
    -- ^ Failed to decode JSON from the provider.

  | InvalidUriError Text
    -- ^ A provider's URI is invalid.  The URI is provided as 'Text'
    -- for debugging purposes.

  deriving Show

--------------------------------------------------------------------------------
-- | A provider record is made up of their discovery document and keys.
--
-- @since 0.1.0.0
data Provider = Provider
  { providerDiscovery :: Discovery  -- ^ Details from the discovery URI.
  , providerKeys      :: JWKSet     -- ^ Keys from the @jwksUri@.
  }

--------------------------------------------------------------------------------
-- | Fetch the provider's discovery document.
--
-- Included with the discovery document is a 'UTCTime' value
-- indicating the time at which the content will expire and should be
-- expunged from your cache.  Obviously 'Nothing' indicates that the
-- value cannot be cached.
--
-- If the given 'ProviderDiscoveryURI' is missing its @path@
-- component, or the @path@ component is @/@ it will be rewritten to
-- the /well-known/ discovery path.
--
-- @since 0.1.0.0
discovery
  :: Applicative f
  => HTTPS f                    -- ^ A function that can make HTTPS requests.
  -> ProviderDiscoveryURI       -- ^ The provider's discovery URI.
  -> f (Either DiscoveryError (Discovery, Maybe UTCTime))
discovery https uri =
  case requestFromURI (Right (setPath uri)) of
    Nothing  -> pure (Left (InvalidUriError (uriToText uri)))
    Just req -> https req <&> parseResponse <&> first JsonDecodingError
  where
    setPath :: URI -> URI
    setPath u@URI{uriPath} =
      if null uriPath || uriPath == "/"
        then u {uriPath = "/.well-known/openid-configuration"}
        else u

--------------------------------------------------------------------------------
-- | Fetch the provider's key set.
--
-- Included with the key set is a 'UTCTime' value indicating the time
-- at which the content will expire and should be expunged from your
-- cache.
--
-- @since 0.1.0.0
keysFromDiscovery
  :: Applicative f
  => HTTPS f                    -- ^ A function that can make HTTPS requests.
  -> Discovery                  -- ^ The provider's discovery document.
  -> f (Either DiscoveryError (JWKSet, Maybe UTCTime))
keysFromDiscovery https Discovery{jwksUri} =
  case requestFromURI (Left jwksUri) of
    Nothing  -> pure (Left (InvalidUriError jwksUri))
    Just req -> https req <&> parseResponse <&> first JsonDecodingError

--------------------------------------------------------------------------------
-- | Fetch a provider's discovery document and key set.
--
-- This is a convenience function that simply calls 'discovery' and
-- 'keysFromDiscovery', wrapping them in a 'Provider'.
--
-- If you are caching the results of these functions you probably want
-- to call them individually since they might have very different
-- cache expiration times.
--
-- The expiration time returned from this function is the lesser of
-- the two constituents.
--
-- @since 0.1.0.0
discoveryAndKeys
  :: Monad m
  => HTTPS m                    -- ^ A function that can make HTTPS requests.
  -> ProviderDiscoveryURI       -- ^ The provider's discovery URI.
  -> m (Either DiscoveryError (Provider, Maybe UTCTime))
discoveryAndKeys https uri = runExceptT $ do
  (d, t1) <- ExceptT (discovery https uri )
  (k, t2) <- ExceptT (keysFromDiscovery https d)
  pure (Provider d k, min <$> t1 <*> t2)
