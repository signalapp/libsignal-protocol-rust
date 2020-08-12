mod curve25519;

use crate::error::{Result, SignalProtocolError};

use std::cmp::Ordering;
use std::convert::TryFrom;
use std::fmt;

use arrayref::array_ref;
use rand::{CryptoRng, Rng};

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum KeyType {
    Djb,
}

impl fmt::Display for KeyType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

impl KeyType {
    fn value(&self) -> u8 {
        match &self {
            KeyType::Djb => 0x05u8,
        }
    }
}

impl TryFrom<u8> for KeyType {
    type Error = SignalProtocolError;

    fn try_from(x: u8) -> Result<Self> {
        match x {
            0x05u8 => Ok(KeyType::Djb),
            t => Err(SignalProtocolError::BadKeyType(t)),
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Ord, PartialOrd)]
enum PublicKeyData {
    DjbPublicKey([u8; 32]),
}

#[derive(Clone, Copy, Eq, PartialOrd)]
pub struct PublicKey {
    key: PublicKeyData,
}

impl PublicKey {
    fn new(key: PublicKeyData) -> Self {
        Self { key }
    }

    pub fn deserialize(value: &[u8]) -> Result<Self> {
        if value.is_empty() {
            return Err(SignalProtocolError::NoKeyTypeIdentifier);
        }
        let key_type = KeyType::try_from(value[0])?;
        match key_type {
            KeyType::Djb => {
                // We allow trailing data after the public key (why?)
                if value.len() < 32 + 1 {
                    return Err(SignalProtocolError::BadKeyLength(KeyType::Djb, value.len()));
                }
                let mut key = [0u8; 32];
                key.copy_from_slice(&value[1..33]);
                Ok(PublicKey {
                    key: PublicKeyData::DjbPublicKey(key),
                })
            }
        }
    }

    pub fn serialize(&self) -> Box<[u8]> {
        let value_len = match self.key {
            PublicKeyData::DjbPublicKey(v) => v.len(),
        };
        let mut result = Vec::with_capacity(1 + value_len);
        result.push(self.key_type().value());
        match self.key {
            PublicKeyData::DjbPublicKey(v) => result.extend_from_slice(&v),
        }
        result.into_boxed_slice()
    }

    pub fn verify_signature(&self, message: &[u8], signature: &[u8]) -> Result<bool> {
        match self.key {
            PublicKeyData::DjbPublicKey(pub_key) => {
                if signature.len() != 64 {
                    return Err(SignalProtocolError::MismatchedSignatureLengthForKey(
                        KeyType::Djb,
                        signature.len(),
                    ));
                }
                Ok(curve25519::KeyPair::verify_signature(
                    &pub_key,
                    message,
                    array_ref![signature, 0, 64],
                ))
            }
        }
    }

    pub fn key_type(&self) -> KeyType {
        match self.key {
            PublicKeyData::DjbPublicKey(_) => KeyType::Djb,
        }
    }
}

impl From<PublicKeyData> for PublicKey {
    fn from(key: PublicKeyData) -> PublicKey {
        Self { key }
    }
}

impl PartialEq for PublicKey {
    fn eq(&self, other: &PublicKey) -> bool {
        self.serialize() == other.serialize()
    }
}

impl Ord for PublicKey {
    fn cmp(&self, other: &Self) -> Ordering {
        let our_bytes = self.serialize();
        let their_bytes = other.serialize();
        our_bytes.cmp(&their_bytes)
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "PublicKey {{ key_type={}, serialize={:?} }}",
            self.key_type(),
            self.serialize()
        )
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum PrivateKeyData {
    DjbPrivateKey([u8; 32]),
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct PrivateKey {
    key: PrivateKeyData,
}

impl PrivateKey {
    pub fn deserialize(value: &[u8]) -> Result<Self> {
        if value.len() != 32 {
            Err(SignalProtocolError::BadKeyLength(KeyType::Djb, value.len()))
        } else {
            let mut key = [0u8; 32];
            key.copy_from_slice(&value[..32]);
            Ok(Self {
                key: PrivateKeyData::DjbPrivateKey(key),
            })
        }
    }

    pub fn serialize(&self) -> Vec<u8> {
        match self.key {
            PrivateKeyData::DjbPrivateKey(v) => v.to_vec(),
        }
    }

    pub fn public_key(&self) -> Result<PublicKey> {
        match self.key {
            PrivateKeyData::DjbPrivateKey(private_key) => {
                let public_key = curve25519::derive_public_key(&private_key);
                Ok(PublicKey::new(PublicKeyData::DjbPublicKey(public_key)))
            }
        }
    }

    pub fn key_type(&self) -> KeyType {
        match self.key {
            PrivateKeyData::DjbPrivateKey(_) => KeyType::Djb,
        }
    }

    pub fn calculate_signature<R: CryptoRng + Rng>(
        &self,
        message: &[u8],
        csprng: &mut R,
    ) -> Result<Box<[u8]>> {
        match self.key {
            PrivateKeyData::DjbPrivateKey(k) => {
                let kp = curve25519::KeyPair::from(k);
                Ok(Box::new(kp.calculate_signature(csprng, message)))
            }
        }
    }

    pub fn calculate_agreement(&self, their_key: &PublicKey) -> Result<Box<[u8]>> {
        match (self.key, their_key.key) {
            (PrivateKeyData::DjbPrivateKey(priv_key), PublicKeyData::DjbPublicKey(pub_key)) => {
                let kp = curve25519::KeyPair::from(priv_key);
                Ok(Box::new(kp.calculate_agreement(&pub_key)))
            }
        }
    }
}

impl From<PrivateKeyData> for PrivateKey {
    fn from(key: PrivateKeyData) -> PrivateKey {
        Self { key }
    }
}

#[derive(Copy, Clone)]
pub struct KeyPair {
    pub public_key: PublicKey,
    pub private_key: PrivateKey,
}

impl KeyPair {
    pub fn generate<R: Rng + CryptoRng>(csprng: &mut R) -> Self {
        let keypair = curve25519::KeyPair::new(csprng);

        let public_key = PublicKey::from(PublicKeyData::DjbPublicKey(*keypair.public_key()));
        let private_key = PrivateKey::from(PrivateKeyData::DjbPrivateKey(*keypair.private_key()));

        Self {
            public_key,
            private_key,
        }
    }

    pub fn new(public_key: PublicKey, private_key: PrivateKey) -> Self {
        Self {
            public_key,
            private_key,
        }
    }

    pub fn from_public_and_private(public_key: &[u8], private_key: &[u8]) -> Result<Self> {
        let public_key = decode_point(public_key)?;
        let private_key = decode_private_point(private_key)?;
        Ok(Self {
            public_key,
            private_key,
        })
    }

    pub fn calculate_signature<R: CryptoRng + Rng>(
        &self,
        message: &[u8],
        csprng: &mut R,
    ) -> Result<Box<[u8]>> {
        self.private_key.calculate_signature(message, csprng)
    }

    pub fn calculate_agreement(&self, their_key: &PublicKey) -> Result<Box<[u8]>> {
        self.private_key.calculate_agreement(their_key)
    }
}

pub fn verify_signature(public_key: &PublicKey, message: &[u8], signature: &[u8]) -> Result<bool> {
    public_key.verify_signature(message, signature)
}

pub fn calculate_signature<R: CryptoRng + Rng>(
    csprng: &mut R,
    private_key: &PrivateKey,
    message: &[u8],
) -> Result<Box<[u8]>> {
    private_key.calculate_signature(message, csprng)
}

pub fn calculate_agreement(public_key: &PublicKey, private_key: &PrivateKey) -> Result<Box<[u8]>> {
    private_key.calculate_agreement(public_key)
}

pub fn decode_private_point(value: &[u8]) -> Result<PrivateKey> {
    PrivateKey::deserialize(value)
}

pub fn decode_point(v: &[u8]) -> Result<PublicKey> {
    PublicKey::deserialize(v)
}

#[cfg(test)]
mod tests {
    use rand::rngs::OsRng;

    use super::*;

    #[test]
    fn test_large_signatures() {
        let mut csprng = OsRng;
        let key_pair = KeyPair::generate(&mut csprng);
        let mut message = [0u8; 1024 * 1024];
        let signature = calculate_signature(&mut csprng, &key_pair.private_key, &message).unwrap();

        assert!(verify_signature(&key_pair.public_key, &message, &signature).unwrap());
        message[0] ^= 0x01u8;
        assert!(!verify_signature(&key_pair.public_key, &message, &signature).unwrap());
        message[0] ^= 0x01u8;
        let public_key = key_pair.private_key.public_key().unwrap();
        assert!(verify_signature(&public_key, &message, &signature).unwrap());
    }

    #[test]
    fn test_decode_size() {
        let mut csprng = OsRng;
        let key_pair = KeyPair::generate(&mut csprng);
        let serialized_public = key_pair.public_key.serialize();

        assert_eq!(serialized_public, key_pair.private_key.public_key().unwrap().serialize());
        let empty: [u8; 0] = [];

        let just_right = decode_point(&serialized_public[..]);

        assert!(just_right.is_ok());
        assert!(decode_point(&serialized_public[1..]).is_err());
        assert!(decode_point(&empty[..]).is_err());

        let mut bad_key_type = [0u8; 33];
        bad_key_type[..].copy_from_slice(&serialized_public[..]);
        bad_key_type[0] = 0x01u8;
        assert!(decode_point(&bad_key_type).is_err());

        let mut extra_space = [0u8; 34];
        extra_space[..33].copy_from_slice(&serialized_public[..]);
        let extra_space_decode = decode_point(&extra_space);
        assert!(extra_space_decode.is_ok());

        assert_eq!(&serialized_public[..], &just_right.unwrap().serialize()[..]);
        assert_eq!(
            &serialized_public[..],
            &extra_space_decode.unwrap().serialize()[..]
        );
    }
}
