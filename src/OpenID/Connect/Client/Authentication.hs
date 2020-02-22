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
module OpenID.Connect.Client.Authentication
  ( ClientAuthentication(..)
  , ClientSecret(..)
  , Credentials(..)
  , applyRequestAuthentication
  ) where

--------------------------------------------------------------------------------
-- Imports:
import Control.Lens ((&), (?~), (#))
import Control.Monad.Except
import qualified Crypto.JOSE.Compact as JOSE
import qualified Crypto.JOSE.Error as JOSE
import Crypto.JOSE.JWK (JWK)
import qualified Crypto.JOSE.JWK as JWK
import Crypto.JWT (ClaimsSet)
import qualified Crypto.JWT as JWT
import Crypto.Random (MonadRandom(..))
import Data.Aeson (ToJSON(..), FromJSON(..))
import qualified Data.Aeson as Aeson
import Data.ByteArray.Encoding
import Data.ByteString (ByteString)
import qualified Data.ByteString.Char8 as Char8
import qualified Data.ByteString.Lazy.Char8 as LChar8
import Data.Functor ((<&>))
import Data.Text (Text)
import qualified Data.Text.Encoding as Text
import Data.Time.Clock (UTCTime, addUTCTime)
import qualified Network.HTTP.Client as HTTP

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
  | AssignedSecretKey Int Text
  | PrivateKey Int JWK

--------------------------------------------------------------------------------
data Credentials = Credentials
  { assignedClientId :: Text
  , clientSecret     :: ClientSecret
  }

--------------------------------------------------------------------------------
applyRequestAuthentication
  :: forall m. MonadRandom m
  => Credentials                -- ^ Client credentials.
  -> [ClientAuthentication]     -- ^ Available authentication methods.
  -> Text                       -- ^ Token Endpoint URI
  -> UTCTime                    -- ^ The current time.
  -> [(ByteString, ByteString)] -- ^ Headers to include in the post.
  -> HTTP.Request               -- ^ The request to modify.
  -> m (Maybe HTTP.Request)     -- ^ The final request.
applyRequestAuthentication creds methods uri now body =
  case clientSecret creds of
    AssignedSecretText secret
      | ClientSecretPost  `elem` methods -> pure . Just . useBody secret
      | ClientSecretBasic `elem` methods -> pure . Just . useBasic secret
      | otherwise                        -> pure . const Nothing
    AssignedSecretKey sec key
      | ClientSecretJwt `elem` methods   -> hmacWithKey sec key
      | otherwise                        -> pure . const Nothing
    PrivateKey sec key
      | PrivateKeyJwt `elem` methods     -> signWithKey sec key
      | otherwise                        -> pure . const Nothing

  where
    useBody :: Text -> HTTP.Request -> HTTP.Request
    useBody secret = HTTP.urlEncodedBody
      (body <> [ ("client_secret", Text.encodeUtf8 secret)
               ])

    useBasic :: Text -> HTTP.Request -> HTTP.Request
    useBasic secret =
      HTTP.applyBasicAuth
        (Text.encodeUtf8 (assignedClientId creds))
        (Text.encodeUtf8 secret) .
      HTTP.urlEncodedBody body

    hmacWithKey :: Int -> Text -> HTTP.Request -> m (Maybe HTTP.Request)
    hmacWithKey sec keyBytes =
      signWithKey sec (JWK.fromOctets (Text.encodeUtf8 keyBytes))

    signWithKey :: Int -> JWK -> HTTP.Request -> m (Maybe HTTP.Request)
    signWithKey sec key req = do
      claims <- makeClaims <$> makeJti <*> pure sec
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

    makeClaims :: Text -> Int -> ClaimsSet
    makeClaims jti sec
      = JWT.emptyClaimsSet
      & JWT.claimIss ?~ (JWT.string # assignedClientId creds)
      & JWT.claimSub ?~ (JWT.string # assignedClientId creds)
      & JWT.claimAud ?~ JWT.Audience [JWT.string # uri]
      & JWT.claimJti ?~ jti
      & JWT.claimExp ?~ JWT.NumericDate (addUTCTime (fromIntegral sec) now)
      & JWT.claimIat ?~ JWT.NumericDate now

    makeJti :: m Text
    makeJti = (getRandomBytes 64 :: m ByteString)
                <&> (<> Char8.pack (show now))
                <&> convertToBase Base64URLUnpadded
                <&> Text.decodeUtf8
