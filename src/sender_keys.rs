use crate::crypto::hmac_sha256;
use crate::curve;
use crate::error::{Result, SignalProtocolError};
use crate::kdf::HKDF;
use crate::proto::storage as storage_proto;
use crate::ProtocolAddress;

use prost::Message;
use std::collections::VecDeque;

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct SenderKeyName {
    group_id: String,
    sender: ProtocolAddress,
}

impl SenderKeyName {
    pub fn new(group_id: String, sender: ProtocolAddress) -> Result<Self> {
        Ok(Self { group_id, sender })
    }

    pub fn group_id(&self) -> Result<String> {
        Ok(self.group_id.clone())
    }

    pub fn sender(&self) -> Result<ProtocolAddress> {
        Ok(self.sender.clone())
    }
}

#[derive(Debug)]
pub struct SenderMessageKey {
    iteration: u32,
    iv: Vec<u8>,
    cipher_key: Vec<u8>,
    seed: Vec<u8>,
}

impl SenderMessageKey {
    pub fn new(iteration: u32, seed: &[u8]) -> Result<Self> {
        let hkdf = HKDF::new(3)?;
        let derived = hkdf.derive_secrets(seed, "WhisperGroup".as_bytes(), 48)?;
        Ok(Self {
            iteration,
            seed: seed.to_vec(),
            iv: derived[0..16].to_vec(),
            cipher_key: derived[16..48].to_vec(),
        })
    }

    pub fn from_protobuf(
        smk: storage_proto::sender_key_state_structure::SenderMessageKey,
    ) -> Result<Self> {
        Self::new(smk.iteration, &smk.seed)
    }

    pub fn iteration(&self) -> Result<u32> {
        Ok(self.iteration)
    }

    pub fn iv(&self) -> Result<Vec<u8>> {
        Ok(self.iv.clone())
    }

    pub fn cipher_key(&self) -> Result<Vec<u8>> {
        Ok(self.cipher_key.clone())
    }

    pub fn seed(&self) -> Result<Vec<u8>> {
        Ok(self.seed.clone())
    }

    pub fn as_protobuf(
        &self,
    ) -> Result<storage_proto::sender_key_state_structure::SenderMessageKey> {
        Ok(
            storage_proto::sender_key_state_structure::SenderMessageKey {
                iteration: self.iteration,
                seed: self.seed.clone(),
            },
        )
    }
}

#[derive(Debug, Clone)]
pub struct SenderChainKey {
    iteration: u32,
    chain_key: Vec<u8>,
}

impl SenderChainKey {
    const MESSAGE_KEY_SEED: u8 = 0x01;
    const CHAIN_KEY_SEED: u8 = 0x02;

    pub fn new(iteration: u32, chain_key: Vec<u8>) -> Result<Self> {
        Ok(Self {
            iteration,
            chain_key: chain_key,
        })
    }

    pub fn iteration(&self) -> Result<u32> {
        Ok(self.iteration)
    }

    pub fn seed(&self) -> Result<Vec<u8>> {
        Ok(self.chain_key.clone())
    }

    pub fn next(&self) -> Result<SenderChainKey> {
        Ok(SenderChainKey::new(
            self.iteration + 1,
            self.get_derivative(Self::CHAIN_KEY_SEED)?,
        )?)
    }

    pub fn sender_message_key(&self) -> Result<SenderMessageKey> {
        Ok(SenderMessageKey::new(
            self.iteration,
            &self.get_derivative(Self::MESSAGE_KEY_SEED)?,
        )?)
    }

    fn get_derivative(&self, label: u8) -> Result<Vec<u8>> {
        let label = [label];
        Ok(hmac_sha256(&self.chain_key, &label)?.to_vec())
    }

    pub fn as_protobuf(&self) -> Result<storage_proto::sender_key_state_structure::SenderChainKey> {
        Ok(storage_proto::sender_key_state_structure::SenderChainKey {
            iteration: self.iteration,
            seed: self.chain_key.clone(),
        })
    }
}

#[derive(Debug, Clone)]
pub struct SenderKeyState {
    state: storage_proto::SenderKeyStateStructure,
}

impl SenderKeyState {
    const MAX_MESSAGE_KEYS: usize = 2000;

    pub fn new(
        id: u32,
        iteration: u32,
        chain_key: &[u8],
        signature_key: curve::PublicKey,
        signature_private_key: Option<curve::PrivateKey>,
    ) -> Result<SenderKeyState> {
        let state = storage_proto::SenderKeyStateStructure {
            sender_key_id: id,
            sender_chain_key: Some(
                SenderChainKey::new(iteration, chain_key.to_vec())?.as_protobuf()?,
            ),
            sender_signing_key: Some(
                storage_proto::sender_key_state_structure::SenderSigningKey {
                    public: signature_key.serialize().to_vec(),
                    private: match signature_private_key {
                        None => vec![],
                        Some(k) => k.serialize().to_vec(),
                    },
                },
            ),
            sender_message_keys: vec![],
        };

        Ok(Self { state })
    }

    pub fn from_protobuf(state: storage_proto::SenderKeyStateStructure) -> Self {
        Self { state }
    }

    pub fn sender_key_id(&self) -> Result<u32> {
        Ok(self.state.sender_key_id)
    }

    pub fn sender_chain_key(&self) -> Result<SenderChainKey> {
        let sender_chain = self
            .state
            .sender_chain_key
            .as_ref()
            .ok_or(SignalProtocolError::InvalidProtobufEncoding)?;
        SenderChainKey::new(sender_chain.iteration, sender_chain.seed.clone())
    }

    pub fn set_sender_chain_key(&mut self, chain_key: SenderChainKey) -> Result<()> {
        self.state.sender_chain_key = Some(chain_key.as_protobuf()?);
        Ok(())
    }

    pub fn signing_key_public(&self) -> Result<curve::PublicKey> {
        if let Some(ref signing_key) = self.state.sender_signing_key {
            Ok(curve::PublicKey::deserialize(&signing_key.public)?)
        } else {
            Err(SignalProtocolError::SignaturePubkeyMissing)
        }
    }

    pub fn signing_key_private(&self) -> Result<Option<curve::PrivateKey>> {
        if let Some(ref signing_key) = self.state.sender_signing_key {
            Ok(Some(curve::PrivateKey::deserialize(&signing_key.private)?))
        } else {
            Ok(None)
        }
    }

    pub fn has_sender_key_message(&self, iteration: u32) -> Result<bool> {
        for sender_message_key in &self.state.sender_message_keys {
            if sender_message_key.iteration == iteration {
                return Ok(true);
            }
        }
        Ok(false)
    }

    pub fn as_protobuf(&self) -> Result<storage_proto::SenderKeyStateStructure> {
        Ok(self.state.clone())
    }

    pub fn add_sender_message_key(&mut self, sender_message_key: &SenderMessageKey) -> Result<()> {
        self.state
            .sender_message_keys
            .push(sender_message_key.as_protobuf()?);
        while self.state.sender_message_keys.len() > Self::MAX_MESSAGE_KEYS {
            self.state.sender_message_keys.remove(0);
        }
        Ok(())
    }

    pub fn remove_sender_message_key(
        &mut self,
        iteration: u32,
    ) -> Result<Option<SenderMessageKey>> {
        if let Some(index) = self
            .state
            .sender_message_keys
            .iter()
            .position(|x| x.iteration == iteration)
        {
            let smk = self.state.sender_message_keys.remove(index);
            Ok(Some(SenderMessageKey::from_protobuf(smk)?))
        } else {
            Ok(None)
        }
    }
}

#[derive(Debug, Clone)]
pub struct SenderKeyRecord {
    states: VecDeque<SenderKeyState>,
}

impl SenderKeyRecord {
    const MAX_STATES: usize = 5;

    pub fn new_empty() -> Self {
        Self {
            states: VecDeque::new(),
        }
    }

    pub fn deserialize(buf: &[u8]) -> Result<SenderKeyRecord> {
        let skr = storage_proto::SenderKeyRecordStructure::decode(buf)?;

        let mut states = VecDeque::with_capacity(skr.sender_key_states.len());
        for state in skr.sender_key_states {
            states.push_back(SenderKeyState::from_protobuf(state))
        }
        Ok(Self { states })
    }

    pub fn empty(&self) -> Result<bool> {
        Ok(self.states.len() == 0)
    }

    pub fn sender_key_state(&mut self) -> Result<&mut SenderKeyState> {
        if self.states.len() > 0 {
            return Ok(&mut self.states[0]);
        }
        Err(SignalProtocolError::NoSenderKeyState)
    }

    pub fn sender_key_state_for_keyid(&mut self, key_id: u32) -> Result<&mut SenderKeyState> {
        for i in 0..self.states.len() {
            if self.states[i].sender_key_id()? == key_id {
                return Ok(&mut self.states[i]);
            }
        }
        Err(SignalProtocolError::NoSenderKeyState)
    }

    pub fn add_sender_key_state(
        &mut self,
        id: u32,
        iteration: u32,
        chain_key: &[u8],
        signature_key: curve::PublicKey,
        signature_private_key: Option<curve::PrivateKey>,
    ) -> Result<()> {
        self.states.push_front(SenderKeyState::new(
            id,
            iteration,
            chain_key,
            signature_key,
            signature_private_key,
        )?);

        while self.states.len() > Self::MAX_STATES {
            self.states.pop_back();
        }
        Ok(())
    }

    pub fn set_sender_key_state(
        &mut self,
        id: u32,
        iteration: u32,
        chain_key: &[u8],
        signature_key: curve::PublicKey,
        signature_private_key: Option<curve::PrivateKey>,
    ) -> Result<()> {
        self.states.clear();
        self.add_sender_key_state(
            id,
            iteration,
            chain_key,
            signature_key,
            signature_private_key,
        )
    }

    pub fn as_protobuf(&self) -> Result<storage_proto::SenderKeyRecordStructure> {
        let mut states = Vec::with_capacity(self.states.len());
        for state in &self.states {
            states.push(state.as_protobuf()?);
        }

        Ok(storage_proto::SenderKeyRecordStructure {
            sender_key_states: states,
        })
    }
}
