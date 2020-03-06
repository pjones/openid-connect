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
module Util
  ( https
  , httpsSimple
  , httpsDebug
  ) where

--------------------------------------------------------------------------------
-- Imports:
import Network.HTTP.Client (Manager, httpLbs)
import qualified Network.HTTP.Client as HTTP
import OpenID.Connect.Client.Flow.AuthorizationCode (HTTPS)
import System.IO

--------------------------------------------------------------------------------
-- | This is the 'HTTPS' function that the openid-connect library
-- needs in order to make HTTP requests.
--
-- Ideally you'd want to handle exceptions here.
httpsSimple :: Manager -> HTTPS IO
httpsSimple mgr = (`httpLbs` mgr)

--------------------------------------------------------------------------------
-- | A function that can make HTTP requests and dump debugging
-- information to STDERR.
httpsDebug :: Manager -> HTTPS IO
httpsDebug mgr request = do
  hPutStrLn stderr "making direct request to the provider:"
  hPrint stderr request

  case HTTP.requestBody request of
    HTTP.RequestBodyLBS bs -> hPrint stderr bs
    HTTP.RequestBodyBS  bs -> hPrint stderr bs
    _                      -> hPutStrLn stderr "<<body>>"

  res <- httpLbs request mgr
  hPrint stderr res
  hFlush stderr
  pure res

--------------------------------------------------------------------------------
https :: Manager -> HTTPS IO
https = httpsDebug
