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
module OpenID.Connect.Client.TokenResponse
  ( TokenResponse(..)
  , decodeIdentityToken
  , verifyIdentityTokenClaims
  ) where

--------------------------------------------------------------------------------
-- Imports:
import Control.Lens ((.~), (^?))
import Control.Monad.Except
import qualified Crypto.JOSE.Compact as JOSE
import qualified Crypto.JOSE.Error as JOSE
import Crypto.JOSE.JWK (JWKSet)
import Crypto.JWT (SignedJWT, ClaimsSet, JWTError)
import Crypto.JWT as JWT
import qualified Data.ByteString.Lazy.Char8 as LChar8
import Data.Function ((&))
import Data.Functor.Identity (runIdentity)
import Data.Text (Text)
import qualified Data.Text.Encoding as Text
import Data.Time.Clock (UTCTime)
import GHC.Generics (Generic)
import OpenID.Connect.Client.Provider
import OpenID.Connect.JSON

--------------------------------------------------------------------------------
data TokenResponse a = TokeResponse
  { accessToken  :: Text
  , expiresIn    :: Int
  , idToken      :: a
  , scope        :: Text
  , tokenType    :: Text
  , refreshToken :: Text
  }
  deriving stock (Generic, Functor)

deriving via (GenericJSON (TokenResponse Text)) instance ToJSON   (TokenResponse Text)
deriving via (GenericJSON (TokenResponse Text)) instance FromJSON (TokenResponse Text)

--------------------------------------------------------------------------------
decodeIdentityToken
  :: TokenResponse Text
  -> Either JOSE.Error (TokenResponse SignedJWT)
decodeIdentityToken token
  = JOSE.decodeCompact (LChar8.fromStrict (Text.encodeUtf8 (idToken token)))
  & runExceptT
  & runIdentity
  & fmap (<$ token)

--------------------------------------------------------------------------------
verifyIdentityTokenClaims
  :: Discovery                -- ^ Provider discovery document.
  -> JWT.Audience             -- ^ Intended audience.
  -> UTCTime                  -- ^ Current time.
  -> JWKSet                   -- ^ Available keys to try.
  -> TokenResponse SignedJWT  -- ^ Signed identity token.
  -> Either JWTError (TokenResponse ClaimsSet)
verifyIdentityTokenClaims disco audience now keys token =
    let JWKSet jwks = keys
    in foldr (\k -> either (const (verifyWithKey k)) Right)
             (Left (JWT.JWSError JOSE.NoUsableKeys)) jwks
  where
    verifyWithKey :: JWK -> Either JWTError (TokenResponse ClaimsSet)
    verifyWithKey key =
      let settings = JWT.defaultJWTValidationSettings verifyAudience
                   & allowedSkew     .~ 120
                   & issuerPredicate .~ verifyIssuer
                   & checkIssuedAt   .~ True
      in JWT.verifyClaimsAt settings key now (idToken token)
         & runExceptT
         & runIdentity
         & fmap (<$ token)

    verifyAudience :: JWT.StringOrURI -> Bool
    verifyAudience = let JWT.Audience aud = audience in (`elem` aud)

    verifyIssuer :: JWT.StringOrURI -> Bool
    verifyIssuer = case issuer disco ^? JWT.stringOrUri of
      Nothing  -> const False
      Just iss -> (== iss)
