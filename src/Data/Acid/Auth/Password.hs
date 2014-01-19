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

import Data.Acid
import qualified Data.Map as M
import Data.SafeCopy

type Credentials = (String, String)  -- username, password

newtype CredentialsDB = CredentialsDB { allCredentials :: M.Map String String }
  deriving (Show, Typeable)

emptyCredentialsDB :: CredentialsDB
emptyCredentialsDB = CredentialsDB M.empty

addCredentials :: Credentials -> Update CredentialsDB ()
addCredentials (k, v) = modify (CredentialsDB . M.insert k v . allCredentials)

checkCredentials :: Credentials -> Query CredentialsDB Bool
checkCredentials (k, v) =
  maybe False (== v) . M.lookup k . allCredentials <$> ask

$(deriveSafeCopy 0 'base ''CredentialsDB)
$(makeAcidic ''CredentialsDB ['addCredentials, 'checkCredentials])
