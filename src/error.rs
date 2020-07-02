use crate::curve::KeyType;

use std::error::Error;
use std::fmt;

pub type Result<T> = std::result::Result<T, SignalError>;

#[derive(Debug, Clone)]
pub enum SignalError {
    InvalidArgument(String),

    ProtobufDecodingError(prost::DecodeError),
    ProtobufEncodingError(prost::EncodeError),
    InvalidProtobufEncoding,

    CiphertextMessageTooShort(usize),
    LegacyCiphertextVersion(u8),
    UnrecognizedCiphertextVersion(u8),
    UnrecognizedMessageVersion(u32),

    FingerprintIdentifierMismatch,
    FingerprintVersionMismatch,

    NoKeyTypeIdentifier,
    BadKeyType(u8),
    BadKeyLength(KeyType, usize),
    MismatchedKeyTypes(KeyType, KeyType),
    MismatchedSignatureLengthForKey(KeyType, usize),
}

impl Error for SignalError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            SignalError::ProtobufEncodingError(ref e) => Some(e),
            SignalError::ProtobufDecodingError(ref e) => Some(e),
            _ => None,
        }
    }
}

impl From<prost::DecodeError> for SignalError {
    fn from(value: prost::DecodeError) -> SignalError {
        SignalError::ProtobufDecodingError(value)
    }
}

impl From<prost::EncodeError> for SignalError {
    fn from(value: prost::EncodeError) -> SignalError {
        SignalError::ProtobufEncodingError(value)
    }
}

impl fmt::Display for SignalError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {

        match self {
            SignalError::ProtobufDecodingError(ref e) => {
                write!(f, "failed to decode protobuf: {}", e)
            }
            SignalError::ProtobufEncodingError(ref e) => {
                write!(f, "failed to encode protobuf: {}", e)
            }
            SignalError::InvalidProtobufEncoding => {
                write!(f, "protobuf encoding was invalid")
            }
            SignalError::InvalidArgument(ref s) => {
                write!(f, "invalid argument: {}", s)
            }
            SignalError::CiphertextMessageTooShort(size) => {
                write!(f, "ciphertext serialized bytes were too short <{}>", size)
            }
            SignalError::LegacyCiphertextVersion(version) => {
                write!(f, "ciphertext version was too old <{}>", version)
            }
            SignalError::UnrecognizedCiphertextVersion(version) => {
                write!(f, "ciphertext version was unrecognized <{}>", version)
            }
            SignalError::UnrecognizedMessageVersion(message_version) => {
                write!(f, "unrecognized message version <{}>", message_version)
            }
            SignalError::FingerprintIdentifierMismatch => {
                write!(f, "fingerprint identifiers do not match")
            }
            SignalError::FingerprintVersionMismatch => {
                write!(f, "fingerprint version numbers do not match")
            }
            SignalError::NoKeyTypeIdentifier => {
                write!(f, "no key type identifier")
            }
            SignalError::BadKeyType(t) => {
                write!(f, "bad key type <{:#04x}>", t)
            }
            SignalError::BadKeyLength(t, l) => {
                write!(f, "bad key length <{}> for key with type <{}>", l, t)
            }
            SignalError::MismatchedKeyTypes(a, b) => {
                write!(f, "key types <{}> and <{}> do not match", a, b)
            }
            SignalError::MismatchedSignatureLengthForKey(t, l) => {
                write!(f, "signature length <{}> does not match expected for key with type <{}>", l, t)
            }
        }
    }
}
