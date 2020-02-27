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
module Client
  ( test
  ) where

--------------------------------------------------------------------------------
import Test.Tasty (TestTree, testGroup)
import qualified Client.ProviderTest
import qualified Client.AuthorizationCodeTest

--------------------------------------------------------------------------------
test :: TestTree
test = testGroup "Client"
  [ Client.ProviderTest.test
  , Client.AuthorizationCodeTest.test
  ]
