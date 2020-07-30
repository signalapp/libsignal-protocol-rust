use libsignal_protocol_rust::*;

#[test]
fn test_ratcheting_session_as_bob() -> Result<(), SignalProtocolError> {
    let bob_ephemeral_public =
        hex::decode("052cb49776b8770205745a3a6e24f579cdb4ba7a89041005928ebbadc9c05ad458").unwrap();

    let bob_ephemeral_private =
        hex::decode("a1cab48f7c893fafa9880a28c3b4999d28d6329562d27a4ea4e22e9ff1bdd65a").unwrap();

    let bob_identity_public =
        hex::decode("05f1f43874f6966956c2dd473f8fa15adeb71d1cb991b2341692324cefb1c5e626").unwrap();

    let bob_identity_private =
        hex::decode("4875cc69ddf8ea0719ec947d61081135868d5fd801f02c0225e516df2156605e").unwrap();

    let alice_base_public =
        hex::decode("05472d1fb1a9862c3af6beaca8920277e2b26f4a79213ec7c906aeb35e03cf8950").unwrap();

    let alice_identity_public =
        hex::decode("05b4a8455660ada65b401007f615e654041746432e3339c6875149bceefcb42b4a").unwrap();

    let bob_signed_prekey_public =
        hex::decode("05ac248a8f263be6863576eb0362e28c828f0107a3379d34bab1586bf8c770cd67").unwrap();

    let bob_signed_prekey_private =
        hex::decode("583900131fb727998b7803fe6ac22cc591f342e4e42a8c8d5d78194209b8d253").unwrap();

    let expected_sender_chain = "9797caca53c989bbe229a40ca7727010eb2604fc14945d77958a0aeda088b44d";

    let bob_identity_key_public = IdentityKey::decode(&bob_identity_public)?;

    let bob_identity_key_private = PrivateKey::deserialize(&bob_identity_private)?;

    let bob_identity_key_pair =
        IdentityKeyPair::new(bob_identity_key_public, bob_identity_key_private);

    let bob_ephemeral_pair =
        KeyPair::from_public_and_private(&bob_ephemeral_public, &bob_ephemeral_private)?;

    let bob_signed_prekey_pair =
        KeyPair::from_public_and_private(&bob_signed_prekey_public, &bob_signed_prekey_private)?;

    let alice_base_public_key = PublicKey::deserialize(&alice_base_public)?;

    let alice_identity_public = IdentityKey::decode(&alice_identity_public)?;

    let bob_parameters = BobSignalProtocolParameters::new(
        bob_identity_key_pair,
        bob_signed_prekey_pair,
        None, // one time pre key pair
        bob_ephemeral_pair,
        alice_identity_public,
        alice_base_public_key,
    );

    let bob_session = initialize_bob_session(&bob_parameters)?;

    assert_eq!(
        bob_session.local_identity_key()?,
        *bob_identity_key_pair.identity_key()
    );
    assert_eq!(
        bob_session.remote_identity_key()?.unwrap(),
        alice_identity_public
    );
    assert_eq!(
        hex::encode(bob_session.get_sender_chain_key()?.key()),
        expected_sender_chain
    );

    Ok(())
}

#[test]
fn test_ratcheting_session_as_alice() -> Result<(), SignalProtocolError> {
    let bob_ephemeral_public =
        hex::decode("052cb49776b8770205745a3a6e24f579cdb4ba7a89041005928ebbadc9c05ad458").unwrap();

    let bob_identity_public =
        hex::decode("05f1f43874f6966956c2dd473f8fa15adeb71d1cb991b2341692324cefb1c5e626").unwrap();

    let alice_base_public =
        hex::decode("05472d1fb1a9862c3af6beaca8920277e2b26f4a79213ec7c906aeb35e03cf8950").unwrap();

    let alice_base_private =
        hex::decode("11ae7c64d1e61cd596b76a0db5012673391cae66edbfcf073b4da80516a47449").unwrap();

    let bob_signed_prekey_public =
        hex::decode("05ac248a8f263be6863576eb0362e28c828f0107a3379d34bab1586bf8c770cd67").unwrap();

    let alice_identity_public =
        hex::decode("05b4a8455660ada65b401007f615e654041746432e3339c6875149bceefcb42b4a").unwrap();

    let alice_identity_private =
        hex::decode("9040f0d4e09cf38f6dc7c13779c908c015a1da4fa78737a080eb0a6f4f5f8f58").unwrap();

    // This differs from the Java test and needs investigation
    let expected_receiver_chain =
        "ab9be50e5cb22a925446ab90ee5670545f4fd32902459ec274b6ad0ae5d6031a";

    let alice_identity_key_public = IdentityKey::decode(&alice_identity_public)?;

    let bob_ephemeral_public = PublicKey::deserialize(&bob_ephemeral_public)?;

    let alice_identity_key_private = PrivateKey::deserialize(&alice_identity_private)?;

    let bob_signed_prekey_public = PublicKey::deserialize(&bob_signed_prekey_public)?;

    let alice_identity_key_pair =
        IdentityKeyPair::new(alice_identity_key_public, alice_identity_key_private);

    let bob_identity_public = IdentityKey::decode(&bob_identity_public)?;

    let alice_base_key = KeyPair::from_public_and_private(&alice_base_public, &alice_base_private)?;

    let alice_parameters = AliceSignalProtocolParameters::new(
        alice_identity_key_pair,
        alice_base_key,
        bob_identity_public,
        bob_signed_prekey_public,
        None, // one-time prekey
        bob_ephemeral_public,
    );

    let mut csprng = rand::rngs::OsRng;
    let alice_session = initialize_alice_session(&alice_parameters, &mut csprng)?;

    assert_eq!(
        alice_session.local_identity_key()?,
        *alice_identity_key_pair.identity_key()
    );
    assert_eq!(
        alice_session.remote_identity_key()?.unwrap(),
        bob_identity_public
    );

    assert_eq!(
        hex::encode(
            alice_session
                .get_receiver_chain(&bob_ephemeral_public)?
                .unwrap()
                .0
                .chain_key
                .unwrap()
                .key
        ),
        expected_receiver_chain
    );

    Ok(())
}
