use crate::{IdentityKey, IdentityKeyPair};
use crate::error::{Result, SignalProtocolError};
use crate::ratchet::{RootKey, ChainKey, MessageKeys};

use crate::proto::storage::SessionStructure;
use crate::proto::storage::session_structure;
use crate::kdf;
use crate::curve;
use prost::Message;

#[derive(Debug)]
struct UnacknowledgedPreKeyMessageItems {
    pre_key_id: Option<u32>,
    signed_pre_key_id: u32,
    base_key: curve::PublicKey,
}

impl UnacknowledgedPreKeyMessageItems {
    fn new(pre_key_id: Option<u32>, signed_pre_key_id: u32, base_key: curve::PublicKey) -> Self {
        Self { pre_key_id, signed_pre_key_id, base_key }
    }

    pub fn pre_key_id(&self) -> Result<Option<u32>> {
        Ok(self.pre_key_id)
    }

    pub fn signed_pre_key_id(&self) -> Result<u32> {
        Ok(self.signed_pre_key_id)
    }

    pub fn base_key(&self) -> Result<&curve::PublicKey> {
        Ok(&self.base_key)
    }

}

#[derive(Clone, Debug)]
pub struct SessionState {
    session: SessionStructure,
}

const MAX_MESSAGE_KEYS: usize = 2000;
const MAX_RECEIVER_CHAINS: usize = 5;

impl SessionState {

    pub fn deserialize(bytes: &[u8]) -> Result<Self> {
        let session = SessionStructure::decode(bytes)?;
        Ok(Self { session })
    }

    pub fn alice_base_key(&self) -> Result<Vec<u8>> {
        // Check the length before returning?
        Ok(self.session.alice_base_key.clone())
    }

    pub fn session_version(&self) -> Result<u32> {
        match self.session.session_version {
            0 => Ok(2),
            v => Ok(v)
        }
    }

    pub fn remote_identity_key(&self) -> Result<Option<IdentityKey>> {
        match self.session.remote_identity_public.len() {
            0 => Ok(None),
            _ => Ok(Some(IdentityKey::decode(&self.session.remote_identity_public)?)),
        }
    }

    pub fn local_identity_key(&self) -> Result<IdentityKey> {
        IdentityKey::decode(&self.session.local_identity_public)
    }

    pub fn previous_counter(&self) -> Result<u32> {
        Ok(self.session.previous_counter)
    }

    pub fn root_key(&self) -> Result<RootKey> {
        if self.session.root_key.len() != 32 {
            return Err(SignalProtocolError::InvalidProtobufEncoding);
        }
        let hkdf = kdf::HKDF::new(self.session_version()?)?;
        RootKey::new(hkdf, &self.session.root_key)
    }

    pub fn sender_ratchet_key(&self) -> Result<curve::PublicKey> {
        match self.session.sender_chain {
            None => Err(SignalProtocolError::InvalidProtobufEncoding),
            Some(ref c) => {
                curve::decode_point(&c.sender_ratchet_key)
            }
        }
    }

    pub fn sender_ratchet_private_key(&self) -> Result<curve::PrivateKey> {
        match self.session.sender_chain {
            None => Err(SignalProtocolError::InvalidProtobufEncoding),
            Some(ref c) => {
                Ok(curve::decode_private_point(&c.sender_ratchet_key_private)?)
            }
        }
    }

    pub fn has_receiver_chain(&self, sender: &curve::PublicKey) -> Result<bool> {
        Ok(self.get_receiver_chain(sender)?.is_some())
    }

    pub fn has_sender_chain(&self) -> Result<bool> {
        Ok(self.session.sender_chain.is_some())
    }

    pub fn get_receiver_chain(&self, sender: &curve::PublicKey) -> Result<Option<(session_structure::Chain, usize)>> {
        let sender_bytes = sender.serialize();

        for (idx,chain) in self.session.receiver_chains.iter().enumerate() {
            /*
            If we compared bytes directly without a deserialize + serialize pair it would
            be faster, but may miss non-canonical points. It's unclear if supporting such
            points is desirable.
            */
            let this_point = curve::decode_point(&chain.sender_ratchet_key)?.serialize();

            if this_point == sender_bytes {
                return Ok(Some((chain.clone(), idx)));
            }
        }

        Ok(None)
    }

    pub fn get_receiver_chain_key(&self, sender: &curve::PublicKey) -> Result<Option<ChainKey>> {
        match self.get_receiver_chain(sender)? {
            None => Ok(None),
            Some((chain,_)) => {
                match chain.chain_key {
                    None => Err(SignalProtocolError::InvalidProtobufEncoding),
                    Some(c) => {
                        if c.key.len() != 32 {
                            return Err(SignalProtocolError::InvalidProtobufEncoding);
                        }
                        let hkdf = kdf::HKDF::new(self.session_version()?)?;
                        Ok(Some(ChainKey::new(hkdf, &c.key, c.index)?))
                    }
                }
            }
        }
    }

    pub fn add_receiver_chain(&mut self, sender: &curve::PublicKey, chain_key: &ChainKey) -> Result<()> {
        let chain_key = session_structure::chain::ChainKey {
            index: chain_key.index(),
            key: chain_key.key().to_vec()
        };

        let chain = session_structure::Chain {
            sender_ratchet_key: sender.serialize().to_vec(),
            sender_ratchet_key_private: vec![],
            chain_key: Some(chain_key),
            message_keys: vec![],
        };

        self.session.receiver_chains.push(chain);

        if self.session.receiver_chains.len() > MAX_RECEIVER_CHAINS {
            self.session.receiver_chains.remove(0);
        }

        Ok(())
    }

    pub fn set_sender_chain(&mut self, sender: &curve::KeyPair, next_chain_key: &ChainKey) -> Result<()> {
        let chain_key = session_structure::chain::ChainKey {
            index: next_chain_key.index(),
            key: next_chain_key.key().to_vec()
        };

        let new_chain = session_structure::Chain {
            sender_ratchet_key: sender.public_key.serialize().to_vec(),
            sender_ratchet_key_private: sender.private_key.serialize().to_vec(),
            chain_key: Some(chain_key),
            message_keys: vec![],
        };

        self.session.sender_chain = Some(new_chain);

        Ok(())
    }

    pub fn get_sender_chain_key(&self) -> Result<ChainKey> {
        let sender_chain = self.session.sender_chain.as_ref().
            ok_or(SignalProtocolError::InvalidState("get_sender_chain_key", "No chain".to_owned()))?;

        let chain_key = sender_chain.chain_key.as_ref().
            ok_or(SignalProtocolError::InvalidState("get_sender_chain_key", "No chain key".to_owned()))?;

        let hkdf = kdf::HKDF::new(self.session_version()?)?;
        ChainKey::new(hkdf, &chain_key.key, chain_key.index)
    }

    pub fn set_sender_chain_key(&mut self, next_chain_key: &ChainKey) -> Result<()> {
        let chain_key = session_structure::chain::ChainKey {
            index: next_chain_key.index(),
            key: next_chain_key.key().to_vec()
        };

        // Is it actually valid to call this function with sender_chain == None?

        let new_chain = match self.session.sender_chain.take() {
            None => session_structure::Chain {
                sender_ratchet_key: vec![],
                sender_ratchet_key_private: vec![],
                chain_key: Some(chain_key),
                message_keys: vec![],
            },
            Some(mut c) => {
                c.chain_key = Some(chain_key);
                c
            }
        };

        self.session.sender_chain = Some(new_chain);

        Ok(())
    }

    pub fn has_message_keys(&self, sender: &curve::PublicKey, counter: u32) -> Result<bool> {
        if let Some(chain_and_index) = self.get_receiver_chain(sender)? {
            for message_key in chain_and_index.0.message_keys {
                if message_key.index == counter {
                    return Ok(true);
                }
            }
        }

        Ok(false)
    }

    pub fn remove_message_keys(&mut self, sender: &curve::PublicKey, counter: u32) -> Result<Option<MessageKeys>> {
        if let Some(mut chain_and_index) = self.get_receiver_chain(sender)? {
            let message_key_idx = chain_and_index.0.message_keys.iter().position(|m| m.index == counter);
            if let Some(position) = message_key_idx {
                let message_key = chain_and_index.0.message_keys.remove(position);

                let keys = MessageKeys::new(&message_key.cipher_key,
                                            &message_key.mac_key,
                                            &message_key.iv,
                                            counter)?;

                // Update with message key removed
                self.session.receiver_chains[chain_and_index.1] = chain_and_index.0;
                return Ok(Some(keys));
            }
        }

        Ok(None)
    }

    pub fn set_message_keys(&mut self, sender: &curve::PublicKey, message_keys: &MessageKeys) -> Result<bool> {
        let new_keys = session_structure::chain::MessageKey {
            cipher_key: message_keys.cipher_key().to_vec(),
            mac_key: message_keys.mac_key().to_vec(),
            iv: message_keys.iv().to_vec(),
            index: message_keys.counter(),
        };

        if let Some(mut chain_and_index) = self.get_receiver_chain(sender)? {
            let mut updated_chain = chain_and_index.0;
            updated_chain.message_keys.push(new_keys);

            if updated_chain.message_keys.len() > MAX_MESSAGE_KEYS {
                updated_chain.message_keys.pop();
            }

            self.session.receiver_chains[chain_and_index.1] = updated_chain;
        }

        Err(SignalProtocolError::InvalidState("set_message_keys", "No receiver".to_string()))
    }

    pub fn set_receiver_chain_key(&mut self, sender: &curve::PublicKey, chain_key: &ChainKey) -> Result<()> {
        if let Some(mut chain_and_index) = self.get_receiver_chain(sender)? {
            let mut updated_chain = chain_and_index.0;
            updated_chain.chain_key = Some(session_structure::chain::ChainKey {
                index: chain_key.index(),
                key: chain_key.key().to_vec()
            });

            self.session.receiver_chains[chain_and_index.1] = updated_chain;
        }

        Err(SignalProtocolError::InvalidState("set_message_keys", "No receiver".to_string()))
    }

    pub fn set_pending_key_exchange(&mut self,
                                    sequence: u32,
                                    base_key: &curve::KeyPair,
                                    ephemeral_key: &curve::KeyPair,
                                    identity_key: &IdentityKeyPair) -> Result<()> {

        self.session.pending_key_exchange = Some(session_structure::PendingKeyExchange {
            sequence,
            local_base_key: base_key.public_key.serialize().to_vec(),
            local_base_key_private: base_key.private_key.serialize().to_vec(),
            local_ratchet_key: ephemeral_key.public_key.serialize().to_vec(),
            local_ratchet_key_private: ephemeral_key.private_key.serialize().to_vec(),
            local_identity_key: identity_key.identity_key().serialize().to_vec(),
            local_identity_key_private: identity_key.private_key().serialize().to_vec(),
        });

        Ok(())
    }

    pub fn pending_key_exchange_sequence(&self) -> Result<u32> {
        match &self.session.pending_key_exchange {
            Some(pke) => Ok(pke.sequence),
            None => {
                Err(SignalProtocolError::InvalidState("pending_key_exchange_sequence",
                                                      "No pending key exchange".to_owned()))
            }
        }
    }

    pub fn pending_key_exchange_base_key(&self) -> Result<curve::KeyPair> {
        match &self.session.pending_key_exchange {
            Some(pke) => {
                curve::KeyPair::from_public_and_private(&pke.local_base_key, &pke.local_base_key_private)
            }
            None => {
                Err(SignalProtocolError::InvalidState("pending_key_exchange_sequence",
                                                      "No pending key exchange".to_owned()))
            }
        }
    }

    pub fn pending_key_exchange_ratchet_key(&self) -> Result<curve::KeyPair> {
        match &self.session.pending_key_exchange {
            Some(pke) => {
                curve::KeyPair::from_public_and_private(&pke.local_ratchet_key, &pke.local_ratchet_key_private)
            }
            None => {
                Err(SignalProtocolError::InvalidState("pending_key_exchange_sequence",
                                                      "No pending key exchange".to_owned()))
            }
        }
    }

    pub fn pending_key_exchange_identity_key(&self) -> Result<IdentityKeyPair> {
        let kp = match &self.session.pending_key_exchange {
            Some(pke) => {
                curve::KeyPair::from_public_and_private(&pke.local_identity_key, &pke.local_identity_key_private)
            }
            None => {
                Err(SignalProtocolError::InvalidState("pending_key_exchange_sequence",
                                                      "No pending key exchange".to_owned()))
            }
        }?;

        Ok(kp.into())
    }

    pub fn has_pending_key_exchange(&self) -> Result<bool> {
        Ok(self.session.pending_key_exchange.is_some())
    }

    pub fn set_unacknowledged_pre_key_message(&mut self,
                                              pre_key_id: Option<u32>,
                                              signed_pre_key_id: u32,
                                              base_key: &curve::PublicKey) -> Result<()> {
        let pending = session_structure::PendingPreKey {
            pre_key_id: pre_key_id.unwrap_or(0),
            signed_pre_key_id: signed_pre_key_id as i32,
            base_key: base_key.serialize().to_vec()
        };
        self.session.pending_pre_key = Some(pending);
        Ok(())
    }

    pub fn has_unacknowledged_pre_key_message(&self) -> Result<bool> {
        Ok(self.session.pending_pre_key.is_some())
    }

    pub fn get_unacknowledged_pre_key_message_items(&self) -> Result<Option<UnacknowledgedPreKeyMessageItems>> {
        if let Some(ref pending_pre_key) = self.session.pending_pre_key {
            Ok(Some(UnacknowledgedPreKeyMessageItems {
                pre_key_id: match pending_pre_key.pre_key_id { 0 => None, v => Some(v) },
                signed_pre_key_id: pending_pre_key.signed_pre_key_id as u32,
                base_key: curve::decode_point(&pending_pre_key.base_key)?,
            }))
        } else {
            Ok(None)
        }
    }

    pub fn clear_unacknowledged_pre_key_message(&mut self) -> Result<()> {
        self.session.pending_pre_key = None;
        Ok(())
    }

    pub fn set_remote_registration_id(&mut self, registration_id: u32) -> Result<()> {
        self.session.remote_registration_id = registration_id;
        Ok(())
    }

    pub fn get_remote_registration_id(&self) -> Result<u32> {
        Ok(self.session.remote_registration_id)
    }

    pub fn set_local_registration_id(&mut self, registration_id: u32) -> Result<()> {
        self.session.local_registration_id = registration_id;
        Ok(())
    }

    pub fn get_local_registration_id(&self) -> Result<u32> {
        Ok(self.session.local_registration_id)
    }

    pub fn serialize(&self) -> Result<Vec<u8>> {
        let mut buf = vec![];
        self.session.encode(&mut buf)?;
        Ok(buf)
    }
}


#[derive(Clone, Debug)]
pub struct SessionRecord {

}

/*
impl SessionRecord {
    fn new_fresh() -> Self {

    }

    fn deserialize(bytes: &[u8]) -> Result<Self> {

    }

    fn serialize(&self) -> Result<Vec<u8>> {

    }

}
*/
