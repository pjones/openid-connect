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
  , Aeson.ToJSON
  , Aeson.FromJSON
  , Words(..)
  , fromWords
  , toWords
  ) where

--------------------------------------------------------------------------------
import Control.Category ((>>>))
import Control.Monad (MonadPlus(..))
import Data.Aeson as Aeson
import Data.List.NonEmpty (NonEmpty)
import qualified Data.List.NonEmpty as NonEmpty
import Data.Text (Text)
import qualified Data.Text as Text
import GHC.Generics (Generic, Rep)

--------------------------------------------------------------------------------
newtype GenericJSON a = GenericJSON
  { genericJSON :: a }

--------------------------------------------------------------------------------
aesonOptions :: Aeson.Options
aesonOptions = Aeson.defaultOptions
  { Aeson.fieldLabelModifier = Aeson.camelTo2 '_' . dropWhile (== '_')
  }

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
fromWords :: Words -> Text
fromWords = toWordList
        >>> NonEmpty.nub
        >>> NonEmpty.toList
        >>> Text.unwords

--------------------------------------------------------------------------------
toWords :: MonadPlus m => Text -> m Words
toWords = Text.words >>> \case
  [] -> mzero
  xs -> pure (Words $ NonEmpty.fromList xs)
