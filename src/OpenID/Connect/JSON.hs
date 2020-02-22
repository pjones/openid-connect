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
  ) where

--------------------------------------------------------------------------------
import Data.Aeson as Aeson
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
