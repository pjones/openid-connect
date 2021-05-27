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

Client authentication.

-}
module OpenID.Connect.Client.Authentication
  ( applyRequestAuthentication
  ) where

--------------------------------------------------------------------------------
-- Imports:
import Control.Lens ((&), (?~), (.~), (^?), (#))
import Control.Monad.Except
import qualified Crypto.JOSE.Compact as JOSE
import qualified Crypto.JOSE.Error as JOSE
import Crypto.JOSE.JWK (JWK)
import qualified Crypto.JOSE.JWK as JWK
import Crypto.JWT (ClaimsSet)
import qualified Crypto.JWT as JWT
import Crypto.Random (MonadRandom(..))
import Data.ByteArray.Encoding
import Data.ByteString (ByteString)
import qualified Data.ByteString.Char8 as Char8
import qualified Data.ByteString.Lazy.Char8 as LChar8
import Data.Functor ((<&>))
import Data.Text (Text)
import qualified Data.Text.Encoding as Text
import Data.Time.Clock (UTCTime, addUTCTime)
import qualified Network.HTTP.Client as HTTP
import OpenID.Connect.Authentication
import OpenID.Connect.JSON

--------------------------------------------------------------------------------
-- | Modify a request so that it uses the proper authentication method.
applyRequestAuthentication
  :: forall m. MonadRandom m
  => Credentials                -- ^ Client credentials.
  -> [ClientAuthentication]  -- ^ Available authentication methods.
  -> URI                        -- ^ Token Endpoint URI
  -> UTCTime                    -- ^ The current time.
  -> [(ByteString, ByteString)] -- ^ Headers to include in the post.
  -> HTTP.Request               -- ^ The request to modify.
  -> m (Maybe HTTP.Request)     -- ^ The final request.
applyRequestAuthentication creds methods uri now body =
  case clientSecret creds of
    AssignedSecretText secret
      | ClientSecretBasic `elem` methods -> pure . Just . useBasic secret
      | ClientSecretPost  `elem` methods -> pure . Just . useBody secret
      | None              `elem` methods -> pure . Just . pass body
      | otherwise                           -> pure . const Nothing
    AssignedAssertionText key
      | ClientSecretJwt `elem` methods   -> hmacWithKey key
      | None            `elem` methods   -> pure . Just . pass body
      | otherwise                           -> pure . const Nothing
    AssertionPrivateKey key
      | PrivateKeyJwt `elem` methods     -> signWithKey key
      | None          `elem` methods     -> pure . Just . pass body
      | otherwise                           -> pure . const Nothing

  where
    pass :: [(ByteString, ByteString)] -> HTTP.Request -> HTTP.Request
    pass = HTTP.urlEncodedBody

    useBody :: Text -> HTTP.Request -> HTTP.Request
    useBody secret = pass
      (body <> [ ("client_secret", Text.encodeUtf8 secret)
               ])

    useBasic :: Text -> HTTP.Request -> HTTP.Request
    useBasic secret =
      HTTP.applyBasicAuth
        (Text.encodeUtf8 (assignedClientId creds))
        (Text.encodeUtf8 secret) . pass body

    -- Use the @client_secret@ as a /key/ to sign a JWT.
    hmacWithKey :: Text -> HTTP.Request -> m (Maybe HTTP.Request)
    hmacWithKey keyBytes =
      signWithKey (JWK.fromOctets (Text.encodeUtf8 keyBytes))

    -- Use the given key to /sign/ a JWT.  May create an actual
    -- digital signature or in the case of 'hmacWithKey', create an
    -- HMAC for the header.
    signWithKey :: JWK -> HTTP.Request -> m (Maybe HTTP.Request)
    signWithKey key req = do
      claims <- makeClaims <$> makeJti
      res <- runExceptT $ do
        alg <- JWK.bestJWSAlg key
        JWT.signClaims key (JWT.newJWSHeader ((), alg)) claims
      case res of
        Left (_ :: JOSE.Error) -> pure Nothing
        Right jwt -> pure . Just $ HTTP.urlEncodedBody
          (body <> [ ( "client_assertion_type"
                     , "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
                     )
                   , ( "client_assertion"
                     , LChar8.toStrict (JOSE.encodeCompact jwt)
                     )
                   ]) req

    -- Claims required by OpenID Connect Core §9.
    makeClaims :: Text -> ClaimsSet
    makeClaims jti
      = JWT.emptyClaimsSet
      & JWT.claimIss .~ assignedClientId creds ^? JWT.stringOrUri
      & JWT.claimSub .~ assignedClientId creds ^? JWT.stringOrUri
      & JWT.claimAud ?~ JWT.Audience (pure (JWT.uri # getURI uri))
      & JWT.claimJti ?~ jti
      & JWT.claimExp ?~ JWT.NumericDate (addUTCTime 60 now)
      & JWT.claimIat ?~ JWT.NumericDate now

    -- JWT ID.  From the standard: A unique identifier for the token,
    -- which can be used to prevent reuse of the token.
    makeJti :: m Text
    makeJti = (getRandomBytes 64 :: m ByteString)
                <&> (<> Char8.pack (show now))
                <&> convertToBase Base64URLUnpadded
                <&> Text.decodeUtf8
