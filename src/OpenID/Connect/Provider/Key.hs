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
module OpenID.Connect.Provider.Key
  (
    -- * Generating Keys
    newJWK
  , newSigningJWK
  , newEncryptionJWK
  ) where

--------------------------------------------------------------------------------
-- Imports:
import Control.Lens ((^.), (?~), re)
import Crypto.Hash (Digest, SHA256)
import Crypto.JOSE (JWK, KeyUse(..))
import qualified Crypto.JOSE as JOSE
import qualified Crypto.JOSE.JWA.JWE.Alg as JOSE
import Crypto.Random (MonadRandom)
import Data.Function ((&))
import Data.Text (Text)
import Data.Text.Strict.Lens (utf8)

--------------------------------------------------------------------------------
-- | An opinionated way of creating a 'JWK'.  For more control over
-- how the key is crated use 'JOSE.genJWK' instead.
--
-- Returns the new key and the key's ID.
--
-- @since 0.1.0.0
newJWK :: MonadRandom m => KeyUse -> m (JWK, Text)
newJWK keyuse = do
    jwk <- JOSE.genJWK (JOSE.RSAGenParam (4096 `div` 8))

    let h     = jwk ^. JOSE.thumbprint :: Digest SHA256
        kid   = h ^. (re (JOSE.base64url . JOSE.digest) . utf8)
        final = jwk
              & JOSE.jwkKid ?~ kid
              & JOSE.jwkUse ?~ keyuse
              & JOSE.jwkAlg ?~ alg keyuse

    pure (final, kid)

  where
    alg :: KeyUse -> JOSE.JWKAlg
    alg = \case
      Sig -> JOSE.JWSAlg JOSE.RS256
      Enc -> JOSE.JWEAlg JOSE.A256KW

--------------------------------------------------------------------------------
-- | Created a new signing key.
--
-- @since 0.1.0.0
newSigningJWK :: MonadRandom m => m JWK
newSigningJWK = fst <$> newJWK Sig

--------------------------------------------------------------------------------
-- | Create a new encryption key.
--
-- @since 0.1.0.0
newEncryptionJWK :: MonadRandom m => m JWK
newEncryptionJWK = fst <$> newJWK Enc
