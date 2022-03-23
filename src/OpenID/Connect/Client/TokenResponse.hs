{-# LANGUAGE CPP #-}

{-|

Copyright:

  This file is part of the package openid-connect.  It is subject to
  the license terms in the LICENSE file found in the top-level
  directory of this distribution and at:

    https://code.devalot.com/open/openid-connect

  No part of this package, including this file, may be copied,
  modified, propagated, or distributed except according to the terms
  contained in the LICENSE file.

License: BSD-2-Clause

-}
module OpenID.Connect.Client.TokenResponse
  ( decodeIdentityToken
  , verifyIdentityTokenClaims
  ) where

--------------------------------------------------------------------------------
-- Imports:
import Control.Lens ((^.), (.~), (^?), (#))
import Control.Monad.Except
import Control.Monad.Reader
import qualified Crypto.JOSE.Compact as JOSE
import qualified Crypto.JOSE.Error as JOSE
import Crypto.JWT as JWT
import qualified Data.Aeson as Aeson
import qualified Data.ByteString.Lazy.Char8 as LChar8
import Data.Function ((&))
import Data.Functor.Identity
import Data.Maybe (isJust)
import Data.Text (Text)
import qualified Data.Text.Encoding as Text
import Data.Time.Clock (UTCTime)
import OpenID.Connect.Authentication (ClientID)
import OpenID.Connect.Client.Provider
import OpenID.Connect.TokenResponse

#if MIN_VERSION_aeson(2, 0, 0)
import qualified Data.Map.Strict as Map
#else
import qualified Data.HashMap.Strict as Map
#endif

--------------------------------------------------------------------------------
-- | Decode the compacted identity token into a 'SignedJWT'.
decodeIdentityToken
  :: TokenResponse Text
  -> Either JOSE.Error (TokenResponse SignedJWT)
decodeIdentityToken token
  = JOSE.decodeCompact (LChar8.fromStrict (Text.encodeUtf8 (idToken token)))
  & runExceptT
  & runIdentity
  & fmap (<$ token)

--------------------------------------------------------------------------------
-- | Identity token verification and claim validation.
verifyIdentityTokenClaims
  :: Discovery                -- ^ Provider discovery document.
  -> ClientID                 -- ^ Intended audience.
  -> UTCTime                  -- ^ Current time.
  -> JWKSet                   -- ^ Available keys to try.
  -> Text                     -- ^ Nonce.
  -> TokenResponse SignedJWT  -- ^ Signed identity token.
  -> Either JWTError (TokenResponse ClaimsSet)
verifyIdentityTokenClaims disco clientId now keys nonce token =
    let JWKSet jwks = keys
    in foldr (\k -> either (const (verifyWithKey k)) Right)
             (Left (JWT.JWSError JOSE.NoUsableKeys)) jwks
  where
    verifyWithKey :: JWK -> Either JWTError (TokenResponse ClaimsSet)
    verifyWithKey key =
      let settings = JWT.defaultJWTValidationSettings (const True)
                   & allowedSkew     .~ 120
                   & issuerPredicate .~ verifyIssuer
                   & checkIssuedAt   .~ True
      in JWT.verifyClaimsAt settings key now (idToken token)
         & runExceptT
         & runIdentity >>= additionalValidation clientId nonce
         & fmap (<$ token)

    verifyIssuer :: JWT.StringOrURI -> Bool
    verifyIssuer = (== (JWT.uri # getURI (issuer disco)))

-- FIXME: validate the at_hash
-- FIXME: rp-id_token-bad-sig-hs256 (Request an ID token and verify
-- its signature using the 'client_secret' as MAC key.)

--------------------------------------------------------------------------------
type Validate a = ExceptT JWTError (ReaderT ClaimsSet Identity) a

--------------------------------------------------------------------------------
orFailWith :: (ClaimsSet -> Bool) -> JWTError -> Validate ()
orFailWith f e = do
  claims <- ask
  if f claims then pure () else throwError e

--------------------------------------------------------------------------------
claimEq :: Text -> Aeson.Value -> ClaimsSet -> Bool
claimEq key val claims =
  case Map.lookup key (claims ^. JWT.unregisteredClaims) of
    Nothing   -> False
    Just val' -> val == val'

--------------------------------------------------------------------------------
additionalValidation :: ClientID -> Text -> ClaimsSet -> Either JWTError ClaimsSet
additionalValidation clientId nonce = go
  where
    go :: ClaimsSet -> Either JWTError ClaimsSet
    go claims = checks
              & runExceptT
              & flip runReaderT claims
              & runIdentity
              & (claims <$)

    checks :: Validate ()
    checks = do
      verifyNonce `orFailWith` JWT.JWTClaimsSetDecodeError "invalid nonce"
      verifyIat   `orFailWith` JWT.JWTIssuedAtFuture
      verifySub   `orFailWith` JWT.JWTClaimsSetDecodeError "missing subject"
      (\c -> verifyAudience c ||
             verifyAzp c) `orFailWith` JWT.JWTNotInAudience

    verifyNonce :: ClaimsSet -> Bool
    verifyNonce = claimEq "nonce" (Aeson.String nonce)

    verifyAudience :: ClaimsSet -> Bool
    verifyAudience claims =
      case claims ^. claimAud of
        Just (JWT.Audience [aud]) ->
          Just aud == clientId ^? JWT.stringOrUri
        _ -> False

    verifyAzp :: ClaimsSet -> Bool
    verifyAzp = claimEq "azp" (Aeson.String clientId)

    verifySub :: ClaimsSet -> Bool
    verifySub = isJust . (^. claimSub)

    -- JOSE verifies the iat claim if it exists but does not reject if
    -- the iat is missing.  OpenID Connect requires a rejection when
    -- iat is missing.
    verifyIat :: ClaimsSet -> Bool
    verifyIat = isJust . (^. claimIat)
