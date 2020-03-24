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

Scope values, defined in OAuth 2.0, as used in OpenID Connect 1.0.

-}
module OpenID.Connect.Scope
  ( Scope
  , openid
  , email
  , profile
  , auth
  , hasScope
  , scopeFromWords
  , scopeQueryItem

    -- * Re-exports
  , Words(..)
  , toWords
  , fromWords
  ) where

--------------------------------------------------------------------------------
-- Imports:
import Data.ByteString (ByteString)
import Data.Function ((&))
import Data.List.NonEmpty (NonEmpty(..))
import qualified Data.List.NonEmpty as NonEmpty
import Data.String
import Data.Text (Text)
import qualified Data.Text as Text
import qualified Data.Text.Encoding as Text
import GHC.Generics (Generic)
import Network.HTTP.Types (QueryItem)
import OpenID.Connect.JSON

--------------------------------------------------------------------------------
-- | A list of @scope@ values.
--
-- To create a scope value use the 'IsString' instance or one of the
-- helper functions such as 'openid' or 'email'.
--
-- @since 0.1.0.0
newtype Scope = Scope
  { unScope :: Words
  }
  deriving stock (Generic, Show)
  deriving newtype Semigroup
  deriving (ToJSON, FromJSON) via (NonEmpty Text)

--------------------------------------------------------------------------------
instance IsString Scope where
  fromString s =
    let t = Text.pack s
    in case toWords t of
         Nothing -> Scope (Words (t :| []))
         Just w  -> Scope w


--------------------------------------------------------------------------------
-- | The @openid@ scope.
--
-- Redundant since the @openid@ scope is always added to requests.
--
-- @since 0.1.0.0
openid :: Scope
openid = "openid"

--------------------------------------------------------------------------------
-- | The @email@ scope.
--
-- @since 0.1.0.0
email :: Scope
email = "email"

--------------------------------------------------------------------------------
-- | The @profile@ scope.
--
-- @since 0.1.0.0
profile :: Scope
profile = "profile"

--------------------------------------------------------------------------------
-- | Authentication request scope.
--
-- Equivalent to @openid <> email@.
--
-- @since 0.1.0.0
auth :: Scope
auth = openid <> email

--------------------------------------------------------------------------------
-- | Test to see if the given scope includes a specific scope value.
--
-- @since 0.1.0.0
hasScope :: Scope -> Text -> Bool
hasScope s t= (t `elem`) . NonEmpty.toList . toWordList . unScope $ s

--------------------------------------------------------------------------------
-- | Convert a (non-empty) list of words into a 'Scope'.
--
-- @since 0.1.0.0
scopeFromWords :: Words -> Scope
scopeFromWords = Scope

--------------------------------------------------------------------------------
-- | Encode a 'Scope' into a query string item.
--
-- @since 0.1.0.0
scopeQueryItem :: Scope -> QueryItem
scopeQueryItem scope = ("scope", Just scopes)
  where
    scopes :: ByteString
    scopes = (scope <> openid)
           & unScope
           & fromWords
           & Text.encodeUtf8
