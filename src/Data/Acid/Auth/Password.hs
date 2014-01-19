-- This file is part of acid-auth-password - acidic password store
-- Copyright (C) 2013  Fraser Tweedale
--
-- acid-auth-password is free software: you can redistribute it and/or modify
-- it under the terms of the GNU Affero General Public License as published by
-- the Free Software Foundation, either version 3 of the License, or
-- (at your option) any later version.
--
-- This program is distributed in the hope that it will be useful,
-- but WITHOUT ANY WARRANTY; without even the implied warranty of
-- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
-- GNU Affero General Public License for more details.
--
-- You should have received a copy of the GNU Affero General Public License
-- along with this program.  If not, see <http://www.gnu.org/licenses/>.

-- |
--
-- @
--import Data.Acid
--import Data.Acid.Auth.Password
--
--main :: IO ()
--main = do
--  db <- openLocalState emptyCredentialsDB
--  checkCredentials db "bob@example.com" (Pass "secret") >>= print
--  salt <- newSalt
--  updateCredentials db salt "bob@example.com" (Pass "secret")
--  checkCredentials db "bob@example.com" (Pass "secret") >>= print
--  checkCredentials db "bob@example.com" (Pass "wrong") >>= print
--  checkCredentials db "not bob" (Pass "secret") >>= print
--  deleteCredentials db "bob@example.com"
--  createCheckpoint db
--  closeAcidState db
-- @

{-# LANGUAGE DeriveDataTypeable #-}
{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE TypeFamilies #-}

module Data.Acid.Auth.Password
  (
    emptyCredentialsDB
  , updateCredentials
  , deleteCredentials
  , checkCredentials
  ) where

import Data.Typeable

import Control.Applicative
import Control.Monad.Reader
import Control.Monad.State

import Crypto.Scrypt
import Data.Acid
import qualified Data.ByteString as B
import qualified Data.Map as M
import Data.SafeCopy


newtype CredentialsDB = CredentialsDB
  { allCredentials :: M.Map String B.ByteString }
  deriving (Show, Typeable)

emptyCredentialsDB :: CredentialsDB
emptyCredentialsDB = CredentialsDB M.empty


updateCrypt :: String -> B.ByteString -> Update CredentialsDB ()
updateCrypt user crypt =
  modify (CredentialsDB . M.insert user crypt . allCredentials)

deleteCrypt :: String -> Update CredentialsDB ()
deleteCrypt user = modify (CredentialsDB . M.delete user . allCredentials)

lookupCrypt :: String -> Query CredentialsDB (Maybe B.ByteString)
lookupCrypt user = M.lookup user . allCredentials <$> ask


$(deriveSafeCopy 0 'base ''CredentialsDB)
$(makeAcidic ''CredentialsDB ['updateCrypt, 'deleteCrypt, 'lookupCrypt])


updateCredentials :: AcidState (EventState UpdateCrypt) -> Salt -> String -> Pass -> IO ()
updateCredentials db salt user pass =
  update db (UpdateCrypt user $ getEncryptedPass $ encryptPass' salt pass)

deleteCredentials :: AcidState (EventState DeleteCrypt) -> String -> IO ()
deleteCredentials db user = update db (DeleteCrypt user)

checkCredentials :: AcidState (EventState LookupCrypt) -> String -> Pass -> IO Bool
checkCredentials db user pass =
  let verify crypt = verifyPass' pass (EncryptedPass crypt)
  in fmap (maybe False verify) (query db (LookupCrypt user))
