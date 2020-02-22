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
module OpenID.Connect.Client.HTTP
  ( HTTPS
  , LByteString
  , forceHTTPS
  , cacheUntil
  , parseResponse
  ) where

--------------------------------------------------------------------------------
-- Imports:
import Control.Applicative
import Data.Aeson (FromJSON, eitherDecode)
import Data.ByteString (ByteString)
import qualified Data.ByteString.Char8 as Char8
import qualified Data.ByteString.Lazy as LByteString
import Data.Char (isDigit)
import Data.Functor ((<&>))
import Data.Time.Clock (UTCTime, addUTCTime)
import Data.Time.Format (parseTimeM, defaultTimeLocale)
import qualified Network.HTTP.Client as HTTP
import qualified Network.HTTP.Types.Header as HTTP
import Network.URI (URI(..))

--------------------------------------------------------------------------------
type LByteString = LByteString.ByteString

--------------------------------------------------------------------------------
-- | A function that can make HTTPS requests.
type HTTPS m = HTTP.Request -> m (HTTP.Response LByteString)

--------------------------------------------------------------------------------
forceHTTPS :: URI -> URI
forceHTTPS uri = uri { uriScheme = "https:" }

--------------------------------------------------------------------------------
cacheUntil :: HTTP.Response a -> Maybe UTCTime
cacheUntil res = maxAge <|> expires
  where
    parseTime :: ByteString -> Maybe UTCTime
    parseTime = parseTimeM True defaultTimeLocale rfc1123 . Char8.unpack

    rfc1123 :: String
    rfc1123 = "%a, %d %b %Y %X %Z"

    date :: Maybe UTCTime
    date = lookup HTTP.hDate (HTTP.responseHeaders res) >>= parseTime

    expires :: Maybe UTCTime
    expires = lookup HTTP.hExpires (HTTP.responseHeaders res) >>= parseTime

    maxAge :: Maybe UTCTime
    maxAge = do
      dt <- date
      bs <- lookup HTTP.hCacheControl (HTTP.responseHeaders res)
      ma <- nullM (snd (Char8.breakSubstring "max-age" bs))
      bn <- nullM (snd (Char8.break isDigit ma))
      addUTCTime . fromIntegral . fst
        <$> Char8.readInt (Char8.take 6 bn) -- Limit input to readInt
        <*> pure dt

    nullM :: ByteString -> Maybe ByteString
    nullM bs = if Char8.null bs then Nothing else Just bs

--------------------------------------------------------------------------------
parseResponse
  :: FromJSON a
  => HTTP.Response LByteString
  -> Either String (a, Maybe UTCTime)
parseResponse response =
  eitherDecode (HTTP.responseBody response)
    <&> (,cacheUntil response)
