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
module OpenID.Connect.Client.Scope
  ( Scope
  , openid
  , email
  , profile
  , auth
  , hasScope
  , scopeQueryItem
  ) where

--------------------------------------------------------------------------------
import Data.Aeson (ToJSON, FromJSON)
import Data.ByteString (ByteString)
import Data.Function ((&))
import Data.List.NonEmpty (NonEmpty)
import qualified Data.List.NonEmpty as NonEmpty
import Data.String
import Data.Text (Text)
import qualified Data.Text as Text
import qualified Data.Text.Encoding as Text
import GHC.Generics (Generic)
import Network.HTTP.Types (QueryItem)

--------------------------------------------------------------------------------
newtype Scope = Scope
  { unScope :: NonEmpty Text
  }
  deriving stock (Generic, Show)
  deriving newtype Semigroup
  deriving (ToJSON, FromJSON) via (NonEmpty Text)

--------------------------------------------------------------------------------
instance IsString Scope where
  fromString = Scope . pure . Text.pack

--------------------------------------------------------------------------------
-- | The @openid@ scope.
--
-- Redundant since the @openid@ scope is always added to requests.
openid :: Scope
openid = "openid"

--------------------------------------------------------------------------------
-- | The @email@ scope.
email :: Scope
email = "email"

--------------------------------------------------------------------------------
-- | The @profile@ scope.
profile :: Scope
profile = "profile"

--------------------------------------------------------------------------------
-- | Authentication request scope.
--
-- Equivalent to @openid <> email@.
auth :: Scope
auth = openid <> email

--------------------------------------------------------------------------------
hasScope :: Scope -> Text -> Bool
hasScope s t= (t `elem`) . NonEmpty.toList . unScope $ s

--------------------------------------------------------------------------------
scopeQueryItem :: Scope -> QueryItem
scopeQueryItem scope = ("scope", Just scopes)
  where
    scopes :: ByteString
    scopes = (scope <> openid)
           & unScope
           & NonEmpty.nub
           & NonEmpty.toList
           & Text.unwords
           & Text.encodeUtf8
