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
module OpenID.Connect.Authentication
  ( ClientAuthentication(..)
  , ClientSecret(..)
  , Credentials(..)
  ) where

--------------------------------------------------------------------------------
-- Imports:
import Crypto.JOSE.JWK (JWK)
import Data.Aeson (ToJSON(..), FromJSON(..))
import qualified Data.Aeson as Aeson
import Data.Text (Text)

--------------------------------------------------------------------------------
data ClientAuthentication
  = ClientSecretBasic
  | ClientSecretPost
  | ClientSecretJwt
  | PrivateKeyJwt
  | None
  deriving stock (Eq, Ord, Show, Read)

instance FromJSON ClientAuthentication where
  parseJSON = Aeson.withText "Client Authentication" $ \case
    "client_secret_basic" -> pure ClientSecretBasic
    "client_secret_post"  -> pure ClientSecretPost
    "client_secret_jwt"   -> pure ClientSecretJwt
    "private_key_jwt"     -> pure PrivateKeyJwt
    _                     -> pure None

instance ToJSON ClientAuthentication where
  toJSON = Aeson.String . \case
    ClientSecretBasic -> "client_secret_basic"
    ClientSecretPost  -> "client_secret_post"
    ClientSecretJwt   -> "client_secret_jwt"
    PrivateKeyJwt     -> "private_key_jwt"
    None              -> "none"

--------------------------------------------------------------------------------
data ClientSecret
  = AssignedSecretText Text
  | AssignedAssertionText Int Text
  | AssertionPrivateKey Int JWK

--------------------------------------------------------------------------------
data Credentials = Credentials
  { assignedClientId :: Text
  , clientSecret     :: ClientSecret
  }
