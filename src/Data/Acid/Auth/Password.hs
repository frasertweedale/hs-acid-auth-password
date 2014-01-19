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

{-# LANGUAGE DeriveDataTypeable #-}
{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE TypeFamilies #-}

module Data.Acid.Auth.Password where

import Data.Typeable

import Control.Applicative
import Control.Monad.Reader
import Control.Monad.State

import Crypto.Scrypt
import Data.Acid
import qualified Data.Map as M
import Data.SafeCopy

newtype SafeSalt = SafeSalt Salt

instance SafeCopy SafeSalt where
  putCopy (SafeSalt (Salt s)) = putCopy s
  getCopy = contain $ fmap (SafeSalt . Salt) safeGet


newtype SafePass = SafePass Pass

instance SafeCopy SafePass where
  putCopy (SafePass (Pass p)) = putCopy p
  getCopy = contain $ fmap (SafePass . Pass) safeGet


newtype SafeEncryptedPass = SafeEncryptedPass EncryptedPass
  deriving (Show)

instance SafeCopy SafeEncryptedPass where
  putCopy (SafeEncryptedPass (EncryptedPass s)) = putCopy s
  getCopy = contain $ fmap (SafeEncryptedPass . EncryptedPass) safeGet


type Credentials = (String, SafePass)  -- username, password

newtype CredentialsDB = CredentialsDB
  { allCredentials :: M.Map String SafeEncryptedPass }
  deriving (Show, Typeable)

emptyCredentialsDB :: CredentialsDB
emptyCredentialsDB = CredentialsDB M.empty


addCredentials :: SafeSalt -> Credentials -> Update CredentialsDB ()
addCredentials (SafeSalt salt) (user, SafePass pass) =
  let hash = SafeEncryptedPass $ encryptPass' salt pass
  in modify (CredentialsDB . M.insert user hash . allCredentials)

checkCredentials :: Credentials -> Query CredentialsDB Bool
checkCredentials (user, pass) =
  let verify (SafePass p) (SafeEncryptedPass h) = verifyPass' p h
  in maybe False (verify pass) . M.lookup user . allCredentials <$> ask


$(deriveSafeCopy 0 'base ''CredentialsDB)
$(makeAcidic ''CredentialsDB ['addCredentials, 'checkCredentials])
