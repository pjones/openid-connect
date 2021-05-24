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
module Main (main) where

--------------------------------------------------------------------------------
-- Imports:
import Auth
import Data.Function ((&))
import Discover
import Network.HTTP.Client.TLS (newTlsManager)
import qualified Network.Wai.Handler.Warp as Warp
import qualified Network.Wai.Handler.WarpTLS as Warp
import Options

--------------------------------------------------------------------------------
-- | Start the web server.
main :: IO ()
main = do
  opts <- parseOptions

  let settings = Warp.defaultSettings & Warp.setPort (optionsPort opts)
      tls = Warp.tlsSettings (optionsCert opts) (optionsKey opts)

  mgr <- newTlsManager
  provider <- getProvider opts mgr
  creds <- getCredentials opts mgr provider

  putStrLn "Starting web server"
  Warp.runTLS tls settings (app mgr provider creds)
