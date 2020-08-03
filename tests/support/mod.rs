use libsignal_protocol_rust::*;
use rand::{rngs::OsRng, CryptoRng, Rng};

pub fn test_in_memory_protocol_store() -> InMemSignalProtocolStore {
    let mut csprng = OsRng;
    let identity_key = IdentityKeyPair::generate(&mut csprng);
    let registration_id = 5; // fixme randomly generate this

    InMemSignalProtocolStore::new(identity_key, registration_id).unwrap()
}

#[allow(dead_code)]
pub fn encrypt(
    store: &mut InMemSignalProtocolStore,
    remote_address: &ProtocolAddress,
    msg: &str,
) -> Result<CiphertextMessage, SignalProtocolError> {
    let mut session_cipher = SessionCipher::new(
        remote_address.clone(),
        &mut store.session_store,
        &mut store.identity_store,
        &mut store.signed_pre_key_store,
        &mut store.pre_key_store,
    );
    session_cipher.encrypt(msg.as_bytes())
}

#[allow(dead_code)]
pub fn decrypt(
    store: &mut InMemSignalProtocolStore,
    remote_address: &ProtocolAddress,
    msg: &CiphertextMessage,
) -> Result<Vec<u8>, SignalProtocolError> {
    let mut session_cipher = SessionCipher::new(
        remote_address.clone(),
        &mut store.session_store,
        &mut store.identity_store,
        &mut store.signed_pre_key_store,
        &mut store.pre_key_store,
    );
    let mut csprng = OsRng;
    session_cipher.decrypt(msg, &mut csprng)
}

#[allow(dead_code)]
pub fn create_pre_key_bundle<R: Rng + CryptoRng>(
    store: &mut dyn ProtocolStore,
    mut csprng: &mut R,
) -> Result<PreKeyBundle, SignalProtocolError> {
    let pre_key_pair = KeyPair::new(&mut csprng);
    let signed_pre_key_pair = KeyPair::new(&mut csprng);

    let signed_pre_key_public = signed_pre_key_pair.public_key.serialize();
    let signed_pre_key_signature = store
        .get_identity_key_pair()?
        .private_key()
        .calculate_signature(&signed_pre_key_public, &mut csprng)?;

    let device_id: u32 = csprng.gen();
    let pre_key_id: u32 = csprng.gen();
    let signed_pre_key_id: u32 = csprng.gen();

    let pre_key_bundle = PreKeyBundle::new(
        store.get_local_registration_id()?,
        device_id,
        Some(pre_key_id),
        Some(pre_key_pair.public_key),
        signed_pre_key_id,
        signed_pre_key_pair.public_key,
        signed_pre_key_signature.to_vec(),
        *store.get_identity_key_pair()?.identity_key(),
    )?;

    store.save_pre_key(pre_key_id, &PreKeyRecord::new(pre_key_id, &pre_key_pair))?;

    let timestamp = csprng.gen();

    store.save_signed_pre_key(
        signed_pre_key_id,
        &SignedPreKeyRecord::new(
            signed_pre_key_id,
            timestamp,
            &signed_pre_key_pair,
            &signed_pre_key_signature,
        ),
    )?;

    Ok(pre_key_bundle)
}

#[allow(dead_code)]
pub fn initialize_sessions_v3() -> Result<(SessionState, SessionState), SignalProtocolError> {
    let mut csprng = OsRng;
    let alice_identity = IdentityKeyPair::generate(&mut csprng);
    let bob_identity = IdentityKeyPair::generate(&mut csprng);

    let alice_base_key = KeyPair::new(&mut csprng);

    let bob_base_key = KeyPair::new(&mut csprng);
    let bob_ephemeral_key = bob_base_key;

    let alice_params = AliceSignalProtocolParameters::new(
        alice_identity,
        alice_base_key,
        *bob_identity.identity_key(),
        bob_base_key.public_key,
        None,
        bob_ephemeral_key.public_key,
    );

    let alice_session = initialize_alice_session(&alice_params, &mut csprng)?;

    let bob_params = BobSignalProtocolParameters::new(
        bob_identity,
        bob_base_key,
        None,
        bob_ephemeral_key,
        *alice_identity.identity_key(),
        alice_base_key.public_key,
    );

    let bob_session = initialize_bob_session(&bob_params)?;

    Ok((alice_session, bob_session))
}
