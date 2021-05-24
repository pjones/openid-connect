{-# LANGUAGE QuasiQuotes #-}

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
module Options
  ( Options(..)
  , ClientDetails(..)
  , ForceAuthMethod(..)
  , parseOptions
  ) where

--------------------------------------------------------------------------------
-- Imports:
import Control.Applicative
import Data.Text (Text)
import Network.URI (URI(..), URIAuth(..), parseURI)
import Network.URI.Static (uri)
import OpenID.Connect.Client.Flow.AuthorizationCode (ClientSecret(..))
import qualified Options.Applicative as O

--------------------------------------------------------------------------------
-- | How to get client info.
data ClientDetails
  = Direct
      { optionsClientSecret  :: ClientSecret
      , optionsClientId      :: Text
      }
  | Register
      { optionsClientContact :: Text
      }

--------------------------------------------------------------------------------
-- | Flags to force a certain client authentication method.
data ForceAuthMethod
  = ForceSecretPost
  | ForceSecretJWT
  | ForcePrivateJWT
  | NoForcedAuth

--------------------------------------------------------------------------------
-- | Command line options.
data Options = Options
  { optionsPort            :: Int
  , optionsCert            :: FilePath
  , optionsKey             :: FilePath
  , optionsForceAuthMode   :: ForceAuthMethod
  , optionsProviderUri     :: URI
  , optionsClientUri       :: URI
  , optionsClientDetails   :: ClientDetails
  }

--------------------------------------------------------------------------------
readUri :: O.ReadM URI
readUri = O.eitherReader $ \s ->
  case parseURI s of
    Nothing -> Left "failed to parse URI"
    Just u  -> Right u

--------------------------------------------------------------------------------
clientDetails :: O.Parser ClientDetails
clientDetails = register <|> details
  where
    register =
      Register
        <$> O.strOption (mconcat
              [ O.long "register"
              , O.short 'r'
              , O.metavar "EMAIL"
              , O.help "Use dynamic client registration"
              ])

    details =
      Direct
        <$> clientSecretOption
        <*> O.strOption (mconcat
              [ O.long "client-id"
              , O.short 'i'
              , O.metavar "ID"
              , O.help "Provider-assigned client ID"
              ])

    clientSecretOption :: O.Parser ClientSecret
    clientSecretOption =
      AssignedSecretText
        <$> O.strOption (mconcat
              [ O.long "client-secret"
              , O.short 's'
              , O.metavar "STR"
              , O.help "Provider-assigned secret"
              ])

--------------------------------------------------------------------------------
-- | Parse the 'ForceAuthMethod' type from the command line.
forceAuthMode :: O.Parser ForceAuthMethod
forceAuthMode = forceSecretPost
            <|> forceSecretJWT
            <|> forcePrivateJWT
            <|> pure NoForcedAuth
  where
    forceSecretPost =
      O.flag' ForceSecretPost (mconcat
          [ O.long "force-secret-post"
          , O.help "Authenticate via client_secret_post"
          ])

    forceSecretJWT =
      O.flag' ForceSecretJWT (mconcat
          [ O.long "force-secret-jwt"
          , O.help "Authenticate via client_secret_jwt"
          ])

    forcePrivateJWT =
      O.flag' ForcePrivateJWT (mconcat
          [ O.long "force-private-jwt"
          , O.help "Authenticate via private_key_jwt"
          ])

--------------------------------------------------------------------------------
-- | Command line parser.
options :: O.Parser Options
options =
  Options
    <$> O.option O.auto (mconcat
          [ O.long "port"
          , O.metavar "NUM"
          , O.value 3000
          , O.help "Port number for the sever"
          ])

    <*> O.strOption (mconcat
          [ O.long "cert"
          , O.metavar "FILE"
          , O.value "example/cert.pem"
          , O.help "TLS certificate file"
          ])

    <*> O.strOption (mconcat
          [ O.long "key"
          , O.metavar "FILE"
          , O.value "example/key.pem"
          , O.help "TLS private key file"
          ])

    <*> forceAuthMode

    <*> O.option readUri (mconcat
          [ O.long "provider"
          , O.short 'p'
          , O.metavar "URI"
          , O.help "Provider discovery URI"
          ])

    <*> O.option readUri (mconcat
          [ O.long "client-uri"
          , O.short 'c'
          , O.metavar "URI"
          , O.value [uri|https://localhost:0/return|]
          , O.help "The URI for this server, including /return"
          ])

    <*> clientDetails

--------------------------------------------------------------------------------
-- | Parse the command line.
parseOptions :: IO Options
parseOptions = do
    opts <- O.execParser (O.info
      (options O.<**> O.helper)
      (mconcat [ O.fullDesc
              , O.progDesc "OpenID Connect client example"
              ]))

    pure (fixRedirUri opts)
  where
    -- Update the default client URI so the port number matches the server.
    fixRedirUri :: Options -> Options
    fixRedirUri opts =
      case uriAuthority (optionsClientUri opts) of
        Nothing -> opts
        Just auth ->
          if uriRegName auth == "localhost" && uriPort auth == ":0"
            then opts { optionsClientUri = (optionsClientUri opts)
                          { uriAuthority = Just auth
                              { uriPort = ":" <> show (optionsPort opts)
                              }
                          }
                      }
            else opts
