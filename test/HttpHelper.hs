{-# LANGUAGE CPP #-}
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
module HttpHelper
  ( FakeHTTPS(..)
  , defaultFakeHTTPS
  , fakeHttpsFromByteString
  , mkHTTPS
  , runHTTPS
  ) where

--------------------------------------------------------------------------------
import Control.Monad.State.Strict
import Crypto.JWT (MonadRandom(..))
import GHC.Generics (Generic)
import qualified Data.ByteString.Lazy.Char8 as LChar8
import qualified Network.HTTP.Client.Internal as HTTP
import qualified Network.HTTP.Types as HTTP
import qualified Network.HTTP.Types.Header as HTTP

--------------------------------------------------------------------------------
data FakeHTTPS = FakeHTTPS
  { fakeStatus   :: HTTP.Status
  , fakeVersion  :: HTTP.HttpVersion
  , fakeHeaders  :: HTTP.ResponseHeaders
  , fakeData     :: IO LChar8.ByteString
  }

--------------------------------------------------------------------------------
defaultFakeHTTPS :: FilePath -> FakeHTTPS
defaultFakeHTTPS = defaultFakeHTTPS' . LChar8.readFile

--------------------------------------------------------------------------------
fakeHttpsFromByteString :: LChar8.ByteString -> FakeHTTPS
fakeHttpsFromByteString = defaultFakeHTTPS' . pure

--------------------------------------------------------------------------------
defaultFakeHTTPS' :: IO LChar8.ByteString -> FakeHTTPS
defaultFakeHTTPS' rdata =
  FakeHTTPS
    { fakeStatus = HTTP.status200
    , fakeVersion = HTTP.http20
    , fakeHeaders = headers
    , fakeData    = rdata
    }
  where
    headers :: HTTP.ResponseHeaders
    headers =
      [ (HTTP.hDate,         "Thu, 20 Feb 2020 19:40:21 GMT")
      , (HTTP.hExpires,      "Thu, 20 Feb 2020 21:40:21 GMT")
      , (HTTP.hCacheControl, "public, max-age=3600")
      , (HTTP.hContentType,  "application/json")
      ]

--------------------------------------------------------------------------------
newtype HttpSt m a = HttpSt
  { _unHttpSt :: StateT HTTP.Request m a }
  deriving stock (Generic)
  deriving newtype (Functor, Applicative, Monad, MonadTrans)

instance MonadRandom m => MonadRandom (HttpSt m) where
  getRandomBytes = lift . getRandomBytes

--------------------------------------------------------------------------------
mkHTTPS
  :: MonadIO m
  => FakeHTTPS
  -> HTTP.Request
  -> HttpSt m (HTTP.Response LChar8.ByteString)
mkHTTPS FakeHTTPS{..} request = HttpSt $ do
  put request
  body <- liftIO fakeData

  pure $
    HTTP.Response
     fakeStatus
     fakeVersion
     fakeHeaders
     body
     mempty
     (HTTP.ResponseClose (pure ()))
#if MIN_VERSION_http_client(0,7,8)
     request
#endif

--------------------------------------------------------------------------------
runHTTPS
  :: HttpSt m a
  -> m (a, HTTP.Request)
runHTTPS (HttpSt s) = runStateT s (HTTP.defaultRequest { HTTP.method = "NONE" })
