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
module OpenID.Connect.TokenResponse
  (
    -- * Token Response
    TokenResponse(..)

    -- * Re-exports
  , Words(..)
  , toWords
  , fromWords
  ) where

--------------------------------------------------------------------------------
-- Imports:
import Data.Text (Text)
import GHC.Generics (Generic)
import OpenID.Connect.JSON

--------------------------------------------------------------------------------
-- | Authentication access token response.
--
-- RFC 6749 section 5.1. with an additional field specified in OpenID
-- Connect Core 1.0 section 3.1.3.3.
data TokenResponse a = TokeResponse
  { accessToken :: Text
    -- ^ The access token issued by the authorization server.

  , tokenType :: Text
    -- ^ The type of the token issued as described in Section 7.1.
    -- Value is case insensitive.

  , expiresIn :: Maybe Int
    -- ^ The lifetime in seconds of the access token.

  , refreshToken :: Maybe Text
    -- ^ The refresh token, which can be used to obtain new access
    -- tokens using the same authorization grant as described in
    -- Section 6.

  , scope :: Maybe Words
    -- ^ The scope of the access token as described by Section 3.3.

  , idToken :: a
    -- ^ ID Token value associated with the authenticated session.
  }
  deriving stock (Generic, Functor)

deriving via (GenericJSON (TokenResponse Text)) instance ToJSON   (TokenResponse Text)
deriving via (GenericJSON (TokenResponse Text)) instance FromJSON (TokenResponse Text)
deriving via (GenericJSON (TokenResponse (Maybe Text))) instance ToJSON   (TokenResponse (Maybe Text))
deriving via (GenericJSON (TokenResponse (Maybe Text))) instance FromJSON (TokenResponse (Maybe Text))
