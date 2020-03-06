{-# LANGUAGE UndecidableInstances #-}

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
module OpenID.Connect.JSON
  ( GenericJSON(..)
  , ErrorResponse(..)
  , (:*:)(..)
  , Words(..)
  , fromWords
  , toWords
  , URI(..)
  , Aeson.ToJSON
  , Aeson.FromJSON
  ) where

--------------------------------------------------------------------------------
import Control.Category ((>>>))
import Control.Monad (MonadPlus(..))
import Data.Aeson as Aeson
import Data.Aeson.Encoding as Aeson
import Data.Bifunctor (bimap)
import Data.List.NonEmpty (NonEmpty)
import qualified Data.List.NonEmpty as NonEmpty
import Data.Text (Text)
import qualified Data.Text as Text
import GHC.Generics (Generic, Rep)
import qualified Network.URI as Network

--------------------------------------------------------------------------------
-- | Type wrapper for automatic JSON deriving.
newtype GenericJSON a = GenericJSON
  { genericJSON :: a }

--------------------------------------------------------------------------------
-- | Default JSON decoding/encoding options.
aesonOptions :: Aeson.Options
aesonOptions = Aeson.defaultOptions
    { Aeson.fieldLabelModifier     = snakeCase
    , Aeson.constructorTagModifier = snakeCase
    , Aeson.allNullaryToStringTag  = True
    , Aeson.omitNothingFields      = True
    }
  where
    snakeCase = Aeson.camelTo2 '_' . dropWhile (== '_')

instance ( Generic a
         , Aeson.GToJSON Aeson.Zero (Rep a)
         , Aeson.GToEncoding Aeson.Zero (Rep a)
         ) =>
  ToJSON (GenericJSON a) where
    toJSON     = Aeson.genericToJSON aesonOptions     . genericJSON
    toEncoding = Aeson.genericToEncoding aesonOptions . genericJSON

instance ( Generic a
         , Aeson.GFromJSON Aeson.Zero (Rep a)
         ) =>
  FromJSON (GenericJSON a) where
    parseJSON = fmap GenericJSON . Aeson.genericParseJSON aesonOptions

--------------------------------------------------------------------------------
-- | A provider response that indicates an error as described in OAuth
-- 2.0 Bearer Token Usage (RFC 6750).
data ErrorResponse = ErrorResponse
  { errorCode        :: Text
  , errorDescription :: Maybe Text
  }
  deriving stock Show

instance ToJSON ErrorResponse where
  toJSON ErrorResponse{..} = Aeson.object
    [ "error" .= errorCode
    , "error_description" .= errorDescription
    ]
  toEncoding ErrorResponse{..} = Aeson.pairs
    ( "error" .= errorCode <> "error_description" .= errorDescription)

instance FromJSON ErrorResponse where
  parseJSON = Aeson.withObject "Error Response" $ \v ->
    ErrorResponse
      <$> v .:  "error"
      <*> v .:? "error_description"

--------------------------------------------------------------------------------
-- | Join two types together so they work with the same JSON document.
newtype (:*:) a b = Join
  { getProduct :: (a, b) }

instance (ToJSON a, ToJSON b) => ToJSON (a :*: b) where
  toJSON prod =
    case bimap toJSON toJSON (getProduct prod) of
      (Aeson.Object x, Aeson.Object y) -> Aeson.Object (x <> y)
      (x, _)                           -> x

instance (FromJSON a, FromJSON b) => FromJSON (a :*: b) where
  parseJSON v = fmap Join ((,) <$> parseJSON v <*> parseJSON v)

--------------------------------------------------------------------------------
-- | Space separated list of words.
newtype Words = Words
  { toWordList :: NonEmpty Text
  }
  deriving stock (Generic, Show)
  deriving newtype Semigroup

instance ToJSON Words where
  toJSON = fromWords >>> toJSON
  toEncoding = fromWords >>> toEncoding

instance FromJSON Words where
  parseJSON = Aeson.withText "Space separated words" toWords

--------------------------------------------------------------------------------
-- | Encode a list of words into 'Text'.
fromWords :: Words -> Text
fromWords = toWordList
        >>> NonEmpty.nub
        >>> NonEmpty.toList
        >>> Text.unwords

--------------------------------------------------------------------------------
-- | Decode a list of words from 'Text'.
toWords :: MonadPlus m => Text -> m Words
toWords = Text.words >>> \case
  [] -> mzero
  xs -> pure (Words $ NonEmpty.fromList xs)

--------------------------------------------------------------------------------
-- | A wrapper around the "Network.URI" type that supports 'ToJSON'
-- and 'FromJSON'.
newtype URI = URI
  { getURI :: Network.URI }
  deriving newtype (Show, Eq)

instance ToJSON URI where
  toJSON u = toJSON (Network.uriToString id (getURI u) [])
  toEncoding u = Aeson.string (Network.uriToString id (getURI u) [])

instance FromJSON URI where
  parseJSON = Aeson.withText "URI" go
    where
      go = maybe mzero (pure . URI) .
             Network.parseURI .
               Text.unpack
