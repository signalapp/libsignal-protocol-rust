//
// Copyright (C) 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: GPL-3.0-only
//

use crate::curve;
use crate::error::Result;
use crate::proto::storage::PreKeyRecordStructure;
use prost::Message;

pub type PreKeyId = u32;

#[derive(Debug, Clone)]
pub struct PreKeyRecord {
    pre_key: PreKeyRecordStructure,
}

impl PreKeyRecord {
    pub fn new(id: PreKeyId, key: &curve::KeyPair) -> Self {
        let public_key = key.public_key.serialize().to_vec();
        let private_key = key.private_key.serialize().to_vec();
        Self {
            pre_key: PreKeyRecordStructure {
                id,
                public_key,
                private_key,
            },
        }
    }

    pub fn deserialize(data: &[u8]) -> Result<Self> {
        Ok(Self {
            pre_key: PreKeyRecordStructure::decode(data)?,
        })
    }

    pub fn id(&self) -> Result<PreKeyId> {
        Ok(self.pre_key.id)
    }

    pub fn key_pair(&self) -> Result<curve::KeyPair> {
        curve::KeyPair::from_public_and_private(&self.pre_key.public_key, &self.pre_key.private_key)
    }

    pub fn public_key(&self) -> Result<curve::PublicKey> {
        curve::PublicKey::deserialize(&self.pre_key.public_key)
    }

    pub fn private_key(&self) -> Result<curve::PrivateKey> {
        curve::PrivateKey::deserialize(&self.pre_key.private_key)
    }

    pub fn serialize(&self) -> Result<Vec<u8>> {
        let mut buf = vec![];
        self.pre_key.encode(&mut buf)?;
        Ok(buf)
    }
}
