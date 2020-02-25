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
module OpenID.Connect.Discovery
  ( Discovery(..)
  ) where

--------------------------------------------------------------------------------
-- Imports:
import Data.List.NonEmpty (NonEmpty)
import Data.Text (Text)
import GHC.Generics (Generic)
import OpenID.Connect.Authentication
import OpenID.Connect.JSON
import OpenID.Connect.Scope

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
