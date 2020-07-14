use crate::error::{Result, SignalProtocolError};
use crate::state::{PreKeyId, PreKeyRecord, SessionRecord, SignedPreKeyId, SignedPreKeyRecord};
use crate::storage::traits;
use crate::{IdentityKey, IdentityKeyPair, ProtocolAddress};

use std::collections::HashMap;

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
    fn get_identity_key_pair(&self) -> Result<IdentityKeyPair> {
        Ok(self.key_pair.clone())
    }

    fn get_local_registration_id(&self) -> Result<u32> {
        Ok(self.id)
    }

    fn save_identity(&mut self, address: &ProtocolAddress, identity: &IdentityKey) -> Result<bool> {
        match self.known_keys.get(address) {
            None => {
                self.known_keys.insert(address.clone(), identity.clone());
                Ok(false) // new key
            }
            Some(k) if k == identity => {
                Ok(false) // same key
            }
            Some(_k) => {
                self.known_keys.insert(address.clone(), identity.clone());
                Ok(true) // overwrite
            }
        }
    }

    fn is_trusted_identity(
        &self,
        address: &ProtocolAddress,
        identity: &IdentityKey,
        _direction: traits::Direction,
    ) -> Result<bool> {
        match self.known_keys.get(address) {
            None => {
                Ok(true) // first use
            }
            Some(k) => Ok(k == identity),
        }
    }

    fn get_identity(&self, address: &ProtocolAddress) -> Result<Option<IdentityKey>> {
        match self.known_keys.get(address) {
            None => Ok(None),
            Some(k) => Ok(Some(k.to_owned())),
        }
    }
}

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

impl traits::PreKeyStore for InMemPreKeyStore {
    fn get_pre_key(&self, id: PreKeyId) -> Result<PreKeyRecord> {
        Ok(self
            .pre_keys
            .get(&id)
            .ok_or(SignalProtocolError::InvalidPreKeyId)?
            .clone())
    }

    fn save_pre_key(&mut self, id: PreKeyId, record: &PreKeyRecord) -> Result<()> {
        // This overwrites old values, which matches Java behavior, but is it correct?
        self.pre_keys.insert(id, record.to_owned());
        Ok(())
    }

    fn has_pre_key(&self, id: PreKeyId) -> Result<bool> {
        Ok(self.pre_keys.get(&id).is_some())
    }

    fn remove_pre_key(&mut self, id: PreKeyId) -> Result<()> {
        // If id does not exist this silently does nothing
        self.pre_keys.remove(&id);
        Ok(())
    }
}

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

impl traits::SignedPreKeyStore for InMemSignedPreKeyStore {
    fn get_signed_pre_key(&self, id: SignedPreKeyId) -> Result<SignedPreKeyRecord> {
        Ok(self
            .signed_pre_keys
            .get(&id)
            .ok_or(SignalProtocolError::InvalidSignedPreKeyId)?
            .clone())
    }

    fn get_all_signed_prekeys(&self) -> Result<Vec<SignedPreKeyRecord>> {
        let mut result = Vec::with_capacity(self.signed_pre_keys.len());
        for v in self.signed_pre_keys.values() {
            result.push(v.clone());
        }
        Ok(result)
    }

    fn save_signed_pre_key(
        &mut self,
        id: SignedPreKeyId,
        record: &SignedPreKeyRecord,
    ) -> Result<()> {
        // This overwrites old values, which matches Java behavior, but is it correct?
        self.signed_pre_keys.insert(id, record.to_owned());
        Ok(())
    }

    fn has_signed_pre_key(&self, id: SignedPreKeyId) -> Result<bool> {
        Ok(self.signed_pre_keys.get(&id).is_some())
    }

    fn remove_pre_key(&mut self, id: SignedPreKeyId) -> Result<()> {
        // If id does not exist this silently does nothing
        self.signed_pre_keys.remove(&id);
        Ok(())
    }
}

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

impl traits::SessionStore for InMemSessionStore {
    fn load_session(&self, address: &ProtocolAddress) -> Result<Option<SessionRecord>> {
        match self.sessions.get(address) {
            None => Ok(None),
            Some(s) => Ok(Some(s.clone())),
        }
    }

    fn get_sub_device_sessions(&self, name: &str) -> Result<Vec<u32>> {
        let mut result = vec![];

        for address in self.sessions.keys() {
            if address.name() == name && address.device_id() != 1 {
                result.push(address.device_id());
            }
        }

        Ok(result)
    }

    fn store_session(&mut self, address: &ProtocolAddress, record: &SessionRecord) -> Result<()> {
        self.sessions.insert(address.clone(), record.clone());
        Ok(())
    }

    fn contains_session(&self, address: &ProtocolAddress) -> Result<bool> {
        Ok(self.sessions.get(address).is_some())
    }

    fn delete_session(&mut self, address: &ProtocolAddress) -> Result<()> {
        self.sessions.remove(address);
        Ok(())
    }

    fn delete_all_sessions(&mut self, name: &str) -> Result<()> {
        self.sessions.retain(|a, _| a.name() != name);
        Ok(())
    }
}
