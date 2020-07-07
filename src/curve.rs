mod curve25519;

use crate::error::{SignalProtocolError, Result};

use std::cmp::Ordering;
use std::convert::TryFrom;
use std::error;
use std::fmt;

use arrayref::array_ref;
use rand::{CryptoRng, Rng};

#[derive(Debug, Clone, PartialEq, Eq)]
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

pub trait PublicKey {
    fn serialize(&self) -> Box<[u8]>;
    fn key_type(&self) -> KeyType;
}

impl PartialEq for dyn PublicKey {
    fn eq(&self, other: &dyn PublicKey) -> bool {
        self.serialize() == other.serialize()
    }
}

impl Eq for dyn PublicKey {}

impl Ord for dyn PublicKey {
    fn cmp(&self, other: &Self) -> Ordering {
        let our_bytes = self.serialize();
        let their_bytes = other.serialize();
        our_bytes.cmp(&their_bytes)
    }
}

impl PartialOrd for dyn PublicKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl fmt::Debug for dyn PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "PublicKey {{ key_type={:?}, serialize={:?} }}",
            self.key_type(),
            self.serialize()
        )
    }
}

pub trait PrivateKey {
    fn serialize(&self) -> Box<[u8]>;
    fn key_type(&self) -> KeyType;
}

pub struct KeyPair {
    pub public_key: Box<dyn PublicKey>,
    pub private_key: Box<dyn PrivateKey>,
}

impl KeyPair {
    pub fn new<R>(csprng: &mut R) -> Self
    where
        R: CryptoRng + Rng,
    {
        curve25519::KeyPair::new(csprng).into()
    }
}

pub fn calculate_agreement(
    public_key: &dyn PublicKey,
    private_key: &dyn PrivateKey,
) -> Result<Box<[u8]>> {
    if public_key.key_type() != private_key.key_type() {
        return Err(SignalProtocolError::MismatchedKeyTypes(
            public_key.key_type(),
            private_key.key_type(),
        ));
    }

    match public_key.key_type() {
        KeyType::Djb => {
            let djb_priv_key = DjbPrivateKey::try_from(&private_key.serialize()[..])?;
            let kp = curve25519::KeyPair::from(djb_priv_key);
            let djb_pub_key = decode_point_internal(&public_key.serialize()[..])?;
            Ok(Box::new(kp.calculate_agreement(&djb_pub_key.0)))
        }
    }
}

pub fn verify_signature(
    public_key: &dyn PublicKey,
    message: &[u8],
    signature: &[u8],
) -> Result<bool> {
    match public_key.key_type() {
        KeyType::Djb => {
            if signature.len() != 64 {
                return Err(SignalProtocolError::MismatchedSignatureLengthForKey(
                    KeyType::Djb,
                    signature.len(),
                ));
            }
            let djb_pub_key = decode_point_internal(&public_key.serialize()[..])?;
            Ok(curve25519::KeyPair::verify_signature(
                &djb_pub_key.0,
                message,
                array_ref![signature, 0, 64],
            ))
        }
    }
}

pub fn calculate_signature<R: CryptoRng + Rng>(
    csprng: &mut R,
    private_key: &dyn PrivateKey,
    message: &[u8]) -> Result<Box<[u8]>>
{
    match private_key.key_type() {
        KeyType::Djb => {
            let djb_priv_key = DjbPrivateKey::try_from(&private_key.serialize()[..])?;
            let kp = curve25519::KeyPair::from(djb_priv_key);
            Ok(Box::new(kp.calculate_signature(csprng, message)))
        }
    }
}

pub fn decode_point(value: &[u8]) -> Result<Box<dyn PublicKey>> {
    decode_point_internal(value).map(|x| Box::new(x) as Box<dyn PublicKey>)
}

fn decode_point_internal(value: &[u8]) -> Result<DjbPublicKey> {
    if value.is_empty() {
        return Err(SignalProtocolError::NoKeyTypeIdentifier);
    }
    let key_type = KeyType::try_from(value[0])?;
    match key_type {
        KeyType::Djb => Ok(DjbPublicKey::try_from(&value[1..])?),
    }
}

pub fn decode_private_point(value: &[u8]) -> Result<Box<dyn PrivateKey>> {
    Ok(Box::new(DjbPrivateKey::try_from(value)?))
}

#[derive(Debug)]
struct DjbPublicKey([u8; 32]);

impl PublicKey for DjbPublicKey {
    fn serialize(&self) -> Box<[u8]> {
        let mut result = Vec::with_capacity(1 + self.0.len());
        result.push(self.key_type().value());
        result.extend_from_slice(&self.0);
        result.into_boxed_slice()
    }

    fn key_type(&self) -> KeyType {
        KeyType::Djb
    }
}

impl TryFrom<&[u8]> for DjbPublicKey {
    type Error = SignalProtocolError;

    fn try_from(value: &[u8]) -> Result<Self> {
        if value.len() < 32 {
            Err(SignalProtocolError::BadKeyLength(KeyType::Djb, value.len()))
        } else {
            let mut result = DjbPublicKey([0u8; 32]);
            result.0.copy_from_slice(&value[..32]);
            Ok(result)
        }
    }
}

#[derive(Debug)]
struct DjbPrivateKey([u8; 32]);

impl PrivateKey for DjbPrivateKey {
    fn serialize(&self) -> Box<[u8]> {
        Box::from(&self.0[..])
    }

    fn key_type(&self) -> KeyType {
        KeyType::Djb
    }
}

impl TryFrom<&[u8]> for DjbPrivateKey {
    type Error = SignalProtocolError;

    fn try_from(value: &[u8]) -> Result<Self> {
        if value.len() != 32 {
            Err(SignalProtocolError::BadKeyLength(KeyType::Djb, value.len()))
        } else {
            let mut result = DjbPrivateKey([0u8; 32]);
            result.0.copy_from_slice(value);
            Ok(result)
        }
    }
}

#[cfg(test)]
mod tests {
    use rand::rngs::OsRng;

    use super::*;

    #[test]
    fn test_large_signatures() {
        let mut csprng = OsRng;
        let key_pair = KeyPair::new(&mut csprng);
        let mut message = [0u8; 1024 * 1024];
        let signature = calculate_signature(&mut csprng, &*key_pair.private_key, &message).unwrap();

        assert!(verify_signature(&*key_pair.public_key, &message, &*signature).unwrap());
        message[0] ^= 0x01u8;
        assert!(!verify_signature(&*key_pair.public_key, &message, &*signature).unwrap());
    }

    #[test]
    fn test_decode_size() {
        let mut csprng = OsRng;
        let key_pair = KeyPair::new(&mut csprng);
        let serialized_public = key_pair.public_key.serialize();
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
