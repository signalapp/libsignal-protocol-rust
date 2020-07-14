mod keys;
mod params;

pub use self::keys::{ChainKey, MessageKeys, RootKey};
pub use self::params::{AliceSignalProtocolParameters, BobSignalProtocolParameters};
use crate::curve;
use crate::error::Result;
use crate::proto::storage::SessionStructure;
use crate::protocol::CIPHERTEXT_MESSAGE_CURRENT_VERSION;
use crate::state::SessionState;
use rand::{CryptoRng, Rng};

fn derive_keys(secret_input: &[u8]) -> Result<(RootKey, ChainKey)> {
    let kdf = crate::kdf::HKDF::new(3)?;

    let secrets = kdf.derive_secrets(secret_input, "WhisperText".as_bytes(), 64);

    let root_key = RootKey::new(kdf, &secrets[0..32])?;
    let chain_key = ChainKey::new(kdf, &secrets[32..64], 0)?;

    Ok((root_key, chain_key))
}

pub fn initialize_alice_session<R: Rng + CryptoRng>(
    parameters: &AliceSignalProtocolParameters,
    mut csprng: &mut R,
) -> Result<SessionState> {
    let local_identity = parameters.our_identity_key_pair().identity_key();

    let sending_ratchet_key = curve::KeyPair::new(&mut csprng);

    let mut secrets = Vec::with_capacity(32 * 5);

    secrets.extend_from_slice(&[0xFFu8; 32]); // "discontinuity bytes"

    let our_base_private_key = parameters.our_base_key_pair().private_key;

    secrets.extend_from_slice(&curve::calculate_agreement(
        parameters.their_signed_pre_key(),
        parameters.our_identity_key_pair().private_key(),
    )?);

    secrets.extend_from_slice(&curve::calculate_agreement(
        parameters.their_identity_key().public_key(),
        &our_base_private_key,
    )?);

    secrets.extend_from_slice(&curve::calculate_agreement(
        parameters.their_signed_pre_key(),
        &our_base_private_key,
    )?);

    if let Some(their_one_time_prekey) = parameters.their_one_time_pre_key() {
        secrets.extend_from_slice(&curve::calculate_agreement(
            their_one_time_prekey,
            &our_base_private_key,
        )?);
    }

    let (root_key, chain_key) = derive_keys(&secrets)?;

    let (sending_chain_root_key, sending_chain_chain_key) = root_key.create_chain(
        parameters.their_ratchet_key(),
        &sending_ratchet_key.private_key,
    )?;

    let session = SessionStructure {
        session_version: CIPHERTEXT_MESSAGE_CURRENT_VERSION as u32,
        local_identity_public: local_identity.public_key().serialize().to_vec(),
        remote_identity_public: parameters.their_identity_key().serialize().to_vec(),
        root_key: sending_chain_root_key.key().to_vec(),
        previous_counter: 0,
        sender_chain: None,
        receiver_chains: vec![],
        pending_key_exchange: None,
        pending_pre_key: None,
        remote_registration_id: 0,
        local_registration_id: 0,
        needs_refresh: false,
        alice_base_key: vec![],
    };

    let mut session = SessionState::new(session);

    session.add_receiver_chain(parameters.their_ratchet_key(), &chain_key)?;
    session.set_sender_chain(&sending_ratchet_key, &sending_chain_chain_key)?;

    Ok(session)
}

pub fn initialize_bob_session(parameters: &BobSignalProtocolParameters) -> Result<SessionState> {
    let local_identity = parameters.our_identity_key_pair().identity_key();

    let mut secrets = Vec::with_capacity(32 * 5);

    secrets.extend_from_slice(&[0xFFu8; 32]); // "discontinuity bytes"

    secrets.extend_from_slice(&curve::calculate_agreement(
        parameters.their_identity_key().public_key(),
        &parameters.our_signed_pre_key_pair().private_key,
    )?);

    secrets.extend_from_slice(&curve::calculate_agreement(
        parameters.their_base_key(),
        parameters.our_identity_key_pair().private_key(),
    )?);

    secrets.extend_from_slice(&curve::calculate_agreement(
        parameters.their_base_key(),
        &parameters.our_signed_pre_key_pair().private_key,
    )?);

    if let Some(our_one_time_pre_key_pair) = parameters.our_one_time_pre_key_pair() {
        secrets.extend_from_slice(&curve::calculate_agreement(
            parameters.their_base_key(),
            &our_one_time_pre_key_pair.private_key,
        )?);
    }

    let (root_key, chain_key) = derive_keys(&secrets)?;

    let session = SessionStructure {
        session_version: CIPHERTEXT_MESSAGE_CURRENT_VERSION as u32,
        local_identity_public: local_identity.public_key().serialize().to_vec(),
        remote_identity_public: parameters.their_identity_key().serialize().to_vec(),
        root_key: root_key.key().to_vec(),
        previous_counter: 0,
        sender_chain: None,
        receiver_chains: vec![],
        pending_key_exchange: None,
        pending_pre_key: None,
        remote_registration_id: 0,
        local_registration_id: 0,
        needs_refresh: false,
        alice_base_key: vec![],
    };

    let mut session = SessionState::new(session);

    session.set_sender_chain(&parameters.our_ratchet_key_pair(), &chain_key)?;

    Ok(session)
}

pub fn are_we_alice(our_key: &curve::PublicKey, their_key: &curve::PublicKey) -> bool {
    our_key.serialize() < their_key.serialize()
}
