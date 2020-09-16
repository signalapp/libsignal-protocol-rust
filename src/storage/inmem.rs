//
// Copyright (C) 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: GPL-3.0-only
//

use crate::error::{Result, SignalProtocolError};
use crate::state::{PreKeyId, PreKeyRecord, SessionRecord, SignedPreKeyId, SignedPreKeyRecord};
use crate::storage::traits;
use crate::storage::Context;
use crate::{IdentityKey, IdentityKeyPair, ProtocolAddress, SenderKeyName, SenderKeyRecord};

use std::collections::HashMap;

#[derive(Clone)]
pub struct InMemIdentityKeyStore {
    key_pair: IdentityKeyPair,
    id: u32,
    known_keys: HashMap<ProtocolAddress, IdentityKey>,
}

impl InMemIdentityKeyStore {
    pub fn new(key_pair: IdentityKeyPair, id: u32) -> Self {
        Self {
            key_pair,
            id,
            known_keys: HashMap::new(),
        }
    }
}

impl traits::IdentityKeyStore for InMemIdentityKeyStore {
    fn get_identity_key_pair(&self, _ctx: Context) -> Result<IdentityKeyPair> {
        Ok(self.key_pair)
    }

    fn get_local_registration_id(&self, _ctx: Context) -> Result<u32> {
        Ok(self.id)
    }

    fn save_identity(
        &mut self,
        address: &ProtocolAddress,
        identity: &IdentityKey,
        _ctx: Context,
    ) -> Result<bool> {
        match self.known_keys.get(address) {
            None => {
                self.known_keys.insert(address.clone(), *identity);
                Ok(false) // new key
            }
            Some(k) if k == identity => {
                Ok(false) // same key
            }
            Some(_k) => {
                self.known_keys.insert(address.clone(), *identity);
                Ok(true) // overwrite
            }
        }
    }

    fn is_trusted_identity(
        &self,
        address: &ProtocolAddress,
        identity: &IdentityKey,
        _direction: traits::Direction,
        _ctx: Context,
    ) -> Result<bool> {
        match self.known_keys.get(address) {
            None => {
                Ok(true) // first use
            }
            Some(k) => Ok(k == identity),
        }
    }

    fn get_identity(
        &self,
        address: &ProtocolAddress,
        _ctx: Context,
    ) -> Result<Option<IdentityKey>> {
        match self.known_keys.get(address) {
            None => Ok(None),
            Some(k) => Ok(Some(k.to_owned())),
        }
    }
}

#[derive(Clone)]
pub struct InMemPreKeyStore {
    pre_keys: HashMap<PreKeyId, PreKeyRecord>,
}

impl InMemPreKeyStore {
    pub fn new() -> Self {
        Self {
            pre_keys: HashMap::new(),
        }
    }
}

impl Default for InMemPreKeyStore {
    fn default() -> Self {
        Self::new()
    }
}

impl traits::PreKeyStore for InMemPreKeyStore {
    fn get_pre_key(&self, id: PreKeyId, _ctx: Context) -> Result<PreKeyRecord> {
        Ok(self
            .pre_keys
            .get(&id)
            .ok_or(SignalProtocolError::InvalidPreKeyId)?
            .clone())
    }

    fn save_pre_key(&mut self, id: PreKeyId, record: &PreKeyRecord, _ctx: Context) -> Result<()> {
        // This overwrites old values, which matches Java behavior, but is it correct?
        self.pre_keys.insert(id, record.to_owned());
        Ok(())
    }

    fn remove_pre_key(&mut self, id: PreKeyId, _ctx: Context) -> Result<()> {
        // If id does not exist this silently does nothing
        self.pre_keys.remove(&id);
        Ok(())
    }
}

#[derive(Clone)]
pub struct InMemSignedPreKeyStore {
    signed_pre_keys: HashMap<SignedPreKeyId, SignedPreKeyRecord>,
}

impl InMemSignedPreKeyStore {
    pub fn new() -> Self {
        Self {
            signed_pre_keys: HashMap::new(),
        }
    }
}

impl Default for InMemSignedPreKeyStore {
    fn default() -> Self {
        Self::new()
    }
}

impl traits::SignedPreKeyStore for InMemSignedPreKeyStore {
    fn get_signed_pre_key(&self, id: SignedPreKeyId, _ctx: Context) -> Result<SignedPreKeyRecord> {
        Ok(self
            .signed_pre_keys
            .get(&id)
            .ok_or(SignalProtocolError::InvalidSignedPreKeyId)?
            .clone())
    }

    fn save_signed_pre_key(
        &mut self,
        id: SignedPreKeyId,
        record: &SignedPreKeyRecord,
        _ctx: Context,
    ) -> Result<()> {
        // This overwrites old values, which matches Java behavior, but is it correct?
        self.signed_pre_keys.insert(id, record.to_owned());
        Ok(())
    }
}

#[derive(Clone)]
pub struct InMemSessionStore {
    sessions: HashMap<ProtocolAddress, SessionRecord>,
}

impl InMemSessionStore {
    pub fn new() -> Self {
        Self {
            sessions: HashMap::new(),
        }
    }
}

impl Default for InMemSessionStore {
    fn default() -> Self {
        Self::new()
    }
}

impl traits::SessionStore for InMemSessionStore {
    fn load_session(
        &self,
        address: &ProtocolAddress,
        _ctx: Context,
    ) -> Result<Option<SessionRecord>> {
        match self.sessions.get(address) {
            None => Ok(None),
            Some(s) => Ok(Some(s.clone())),
        }
    }

    fn store_session(
        &mut self,
        address: &ProtocolAddress,
        record: &SessionRecord,
        _ctx: Context,
    ) -> Result<()> {
        self.sessions.insert(address.clone(), record.clone());
        Ok(())
    }
}

#[derive(Clone)]
pub struct InMemSenderKeyStore {
    keys: HashMap<SenderKeyName, SenderKeyRecord>,
}

impl InMemSenderKeyStore {
    pub fn new() -> Self {
        Self {
            keys: HashMap::new(),
        }
    }
}

impl Default for InMemSenderKeyStore {
    fn default() -> Self {
        Self::new()
    }
}

impl traits::SenderKeyStore for InMemSenderKeyStore {
    fn store_sender_key(
        &mut self,
        sender_key_name: &SenderKeyName,
        record: &SenderKeyRecord,
        _ctx: Context,
    ) -> Result<()> {
        self.keys.insert(sender_key_name.clone(), record.clone());
        Ok(())
    }

    fn load_sender_key(
        &mut self,
        sender_key_name: &SenderKeyName,
        _ctx: Context,
    ) -> Result<Option<SenderKeyRecord>> {
        Ok(self.keys.get(&sender_key_name).cloned())
    }
}

#[derive(Clone)]
pub struct InMemSignalProtocolStore {
    pub session_store: InMemSessionStore,
    pub pre_key_store: InMemPreKeyStore,
    pub signed_pre_key_store: InMemSignedPreKeyStore,
    pub identity_store: InMemIdentityKeyStore,
    pub sender_key_store: InMemSenderKeyStore,
}

impl InMemSignalProtocolStore {
    pub fn new(key_pair: IdentityKeyPair, registration_id: u32) -> Result<Self> {
        Ok(Self {
            session_store: InMemSessionStore::new(),
            pre_key_store: InMemPreKeyStore::new(),
            signed_pre_key_store: InMemSignedPreKeyStore::new(),
            identity_store: InMemIdentityKeyStore::new(key_pair, registration_id),
            sender_key_store: InMemSenderKeyStore::new(),
        })
    }
}

impl traits::IdentityKeyStore for InMemSignalProtocolStore {
    fn get_identity_key_pair(&self, ctx: Context) -> Result<IdentityKeyPair> {
        self.identity_store.get_identity_key_pair(ctx)
    }

    fn get_local_registration_id(&self, ctx: Context) -> Result<u32> {
        self.identity_store.get_local_registration_id(ctx)
    }

    fn save_identity(
        &mut self,
        address: &ProtocolAddress,
        identity: &IdentityKey,
        ctx: Context,
    ) -> Result<bool> {
        self.identity_store.save_identity(address, identity, ctx)
    }

    fn is_trusted_identity(
        &self,
        address: &ProtocolAddress,
        identity: &IdentityKey,
        direction: traits::Direction,
        ctx: Context,
    ) -> Result<bool> {
        self.identity_store
            .is_trusted_identity(address, identity, direction, ctx)
    }

    fn get_identity(&self, address: &ProtocolAddress, ctx: Context) -> Result<Option<IdentityKey>> {
        self.identity_store.get_identity(address, ctx)
    }
}

impl traits::PreKeyStore for InMemSignalProtocolStore {
    fn get_pre_key(&self, id: PreKeyId, ctx: Context) -> Result<PreKeyRecord> {
        self.pre_key_store.get_pre_key(id, ctx)
    }

    fn save_pre_key(&mut self, id: PreKeyId, record: &PreKeyRecord, ctx: Context) -> Result<()> {
        self.pre_key_store.save_pre_key(id, record, ctx)
    }

    fn remove_pre_key(&mut self, id: PreKeyId, ctx: Context) -> Result<()> {
        self.pre_key_store.remove_pre_key(id, ctx)
    }
}

impl traits::SignedPreKeyStore for InMemSignalProtocolStore {
    fn get_signed_pre_key(&self, id: SignedPreKeyId, ctx: Context) -> Result<SignedPreKeyRecord> {
        self.signed_pre_key_store.get_signed_pre_key(id, ctx)
    }

    fn save_signed_pre_key(
        &mut self,
        id: SignedPreKeyId,
        record: &SignedPreKeyRecord,
        ctx: Context,
    ) -> Result<()> {
        self.signed_pre_key_store
            .save_signed_pre_key(id, record, ctx)
    }
}

impl traits::SessionStore for InMemSignalProtocolStore {
    fn load_session(
        &self,
        address: &ProtocolAddress,
        ctx: Context,
    ) -> Result<Option<SessionRecord>> {
        self.session_store.load_session(address, ctx)
    }

    fn store_session(
        &mut self,
        address: &ProtocolAddress,
        record: &SessionRecord,
        ctx: Context,
    ) -> Result<()> {
        self.session_store.store_session(address, record, ctx)
    }
}

impl traits::SenderKeyStore for InMemSignalProtocolStore {
    fn store_sender_key(
        &mut self,
        sender_key_name: &SenderKeyName,
        record: &SenderKeyRecord,
        ctx: Context,
    ) -> Result<()> {
        self.sender_key_store
            .store_sender_key(sender_key_name, record, ctx)
    }

    fn load_sender_key(
        &mut self,
        sender_key_name: &SenderKeyName,
        ctx: Context,
    ) -> Result<Option<SenderKeyRecord>> {
        self.sender_key_store.load_sender_key(sender_key_name, ctx)
    }
}

impl traits::ProtocolStore for InMemSignalProtocolStore {}
