use crate::error::{Result, SignalProtocolError};
use crate::proto;
use crate::IdentityKey;
use prost::Message;
use sha2::{digest::Digest, Sha512};
use std::fmt;
use subtle::ConstantTimeEq;

#[derive(Debug)]
pub struct DisplayableFingerprint {
    local: String,
    remote: String,
}

impl fmt::Display for DisplayableFingerprint {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if self.local < self.remote {
            write!(f, "{}{}", self.local, self.remote)
        } else {
            write!(f, "{}{}", self.remote, self.local)
        }
    }
}

fn get_encoded_string(fprint: &[u8]) -> Result<String> {
    if fprint.len() < 30 {
        return Err(SignalProtocolError::InvalidArgument(
            "DisplayableFingerprint created with short encoding".to_string(),
        ));
    }

    fn read5_mod_100k(fprint: &[u8]) -> u64 {
        assert_eq!(fprint.len(), 5);
        let x = fprint.iter().fold(0u64, |acc, &x| acc * 256 + (x as u64));
        x % 100000
    }

    // todo use iterators
    let s = format!(
        "{:05}{:05}{:05}{:05}{:05}{:05}",
        read5_mod_100k(&fprint[0..5]),
        read5_mod_100k(&fprint[5..10]),
        read5_mod_100k(&fprint[10..15]),
        read5_mod_100k(&fprint[15..20]),
        read5_mod_100k(&fprint[20..25]),
        read5_mod_100k(&fprint[25..30])
    );

    Ok(s)
}

impl DisplayableFingerprint {
    pub fn new(local: &[u8], remote: &[u8]) -> Result<Self> {
        Ok(Self {
            local: get_encoded_string(local)?,
            remote: get_encoded_string(remote)?,
        })
    }
}

#[derive(Debug)]
pub struct ScannableFingerprint {
    version: u32,
    local_fingerprint: Vec<u8>,
    remote_fingerprint: Vec<u8>,
}

impl ScannableFingerprint {
    fn new(version: u32, local_fprint: &[u8], remote_fprint: &[u8]) -> Self {
        Self {
            version,
            local_fingerprint: local_fprint[..32].to_vec(),
            remote_fingerprint: remote_fprint[..32].to_vec(),
        }
    }

    pub fn deserialize(protobuf: &[u8]) -> Result<Self> {
        let fingerprint = proto::fingerprint::CombinedFingerprints::decode(protobuf)?;

        Ok(Self {
            version: fingerprint.version,
            local_fingerprint: fingerprint.local_fingerprint.ok_or(SignalProtocolError::InvalidProtobufEncoding)?.content,
            remote_fingerprint: fingerprint.remote_fingerprint.ok_or(SignalProtocolError::InvalidProtobufEncoding)?.content,
        })
    }

    pub fn serialize(&self) -> Result<Vec<u8>> {
        let combined_fingerprints = proto::fingerprint::CombinedFingerprints {
            version: self.version,
            local_fingerprint: Some(proto::fingerprint::LogicalFingerprint {
                content: self.local_fingerprint.to_owned(),
            }),
            remote_fingerprint: Some(proto::fingerprint::LogicalFingerprint {
                content: self.remote_fingerprint.to_owned(),
            }),
        };

        let mut buf = Vec::new();
        combined_fingerprints.encode(&mut buf)?;
        Ok(buf)
    }

    pub fn compare(&self, combined: &[u8]) -> Result<bool> {
        let combined = proto::fingerprint::CombinedFingerprints::decode(combined)?;

        if combined.version != self.version {
            return Err(SignalProtocolError::FingerprintVersionMismatch);
        }

        // This follows the Java logic but seems misleading - use InvalidProtobufEncoding instead?
        if combined.local_fingerprint.is_none() || combined.remote_fingerprint.is_none() {
            return Err(SignalProtocolError::FingerprintVersionMismatch);
        }

        let same1 = combined
            .local_fingerprint
            .as_ref()
            .unwrap()
            .content
            .ct_eq(&self.remote_fingerprint);
        let same2 = combined
            .remote_fingerprint
            .as_ref()
            .unwrap()
            .content
            .ct_eq(&self.local_fingerprint);

        Ok(same1.into() && same2.into())
    }
}

#[derive(Debug)]
pub struct Fingerprint {
    pub display: DisplayableFingerprint,
    pub scannable: ScannableFingerprint,
}

impl Fingerprint {
    fn get_fingerprint(
        iterations: u32,
        local_id: &[u8],
        local_key: &IdentityKey,
    ) -> Result<Vec<u8>> {
        if iterations <= 1 || iterations > 1000000 {
            return Err(SignalProtocolError::InvalidArgument(format!(
                "Invalid fingerprint iterations {}",
                iterations
            )));
        }

        let fingerprint_version = [0u8, 0u8]; // 0x0000
        let key_bytes = local_key.serialize();

        let mut sha512 = Sha512::new();

        // iteration=0
        sha512.input(&fingerprint_version);
        sha512.input(&key_bytes);
        sha512.input(local_id);
        sha512.input(&key_bytes);
        let mut buf = sha512.result();

        for _i in 1..iterations {
            let mut sha512 = Sha512::new();
            sha512.input(&buf);
            sha512.input(&key_bytes);
            buf = sha512.result();
        }

        Ok(buf.to_vec())
    }

    pub fn new(
        version: u32,
        iterations: u32,
        local_id: &[u8],
        local_key: &IdentityKey,
        remote_id: &[u8],
        remote_key: &IdentityKey,
    ) -> Result<Fingerprint> {
        let local_fingerprint = Fingerprint::get_fingerprint(iterations, local_id, local_key)?;
        let remote_fingerprint = Fingerprint::get_fingerprint(iterations, remote_id, remote_key)?;

        Ok(Fingerprint {
            display: DisplayableFingerprint::new(&local_fingerprint, &remote_fingerprint)?,
            scannable: ScannableFingerprint::new(version, &local_fingerprint, &remote_fingerprint),
        })
    }
}

#[cfg(test)]
mod test {
    use super::*;

    const ALICE_IDENTITY: &str =
        "0506863bc66d02b40d27b8d49ca7c09e9239236f9d7d25d6fcca5ce13c7064d868";
    const BOB_IDENTITY: &str = "05f781b6fb32fed9ba1cf2de978d4d5da28dc34046ae814402b5c0dbd96fda907b";

    const DISPLAYABLE_FINGERPRINT_V1: &str =
        "300354477692869396892869876765458257569162576843440918079131";
    const ALICE_SCANNABLE_FINGERPRINT_V1 : &str = "080112220a201e301a0353dce3dbe7684cb8336e85136cdc0ee96219494ada305d62a7bd61df1a220a20d62cbf73a11592015b6b9f1682ac306fea3aaf3885b84d12bca631e9d4fb3a4d";
    const BOB_SCANNABLE_FINGERPRINT_V1   : &str = "080112220a20d62cbf73a11592015b6b9f1682ac306fea3aaf3885b84d12bca631e9d4fb3a4d1a220a201e301a0353dce3dbe7684cb8336e85136cdc0ee96219494ada305d62a7bd61df";

    const ALICE_SCANNABLE_FINGERPRINT_V2 : &str = "080212220a201e301a0353dce3dbe7684cb8336e85136cdc0ee96219494ada305d62a7bd61df1a220a20d62cbf73a11592015b6b9f1682ac306fea3aaf3885b84d12bca631e9d4fb3a4d";
    const BOB_SCANNABLE_FINGERPRINT_V2   : & str = "080212220a20d62cbf73a11592015b6b9f1682ac306fea3aaf3885b84d12bca631e9d4fb3a4d1a220a201e301a0353dce3dbe7684cb8336e85136cdc0ee96219494ada305d62a7bd61df";

    const ALICE_STABLE_ID: &str = "+14152222222";
    const BOB_STABLE_ID: &str = "+14153333333";

    #[test]
    fn fingerprint_test_v1() {
        // testVectorsVersion1 in Java

        let a_key = IdentityKey::decode(&hex::decode(ALICE_IDENTITY).unwrap()).unwrap();
        let b_key = IdentityKey::decode(&hex::decode(BOB_IDENTITY).unwrap()).unwrap();

        let version = 1;
        let iterations = 5200;

        let a_fprint = Fingerprint::new(
            version,
            iterations,
            ALICE_STABLE_ID.as_bytes(),
            &a_key,
            BOB_STABLE_ID.as_bytes(),
            &b_key,
        )
        .unwrap();

        let b_fprint = Fingerprint::new(
            version,
            iterations,
            BOB_STABLE_ID.as_bytes(),
            &b_key,
            ALICE_STABLE_ID.as_bytes(),
            &a_key,
        )
        .unwrap();

        assert_eq!(
            hex::encode(a_fprint.scannable.serialize().unwrap()),
            ALICE_SCANNABLE_FINGERPRINT_V1
        );
        assert_eq!(
            hex::encode(b_fprint.scannable.serialize().unwrap()),
            BOB_SCANNABLE_FINGERPRINT_V1
        );

        assert_eq!(format!("{}", a_fprint.display), DISPLAYABLE_FINGERPRINT_V1);
        assert_eq!(format!("{}", b_fprint.display), DISPLAYABLE_FINGERPRINT_V1);

        assert_eq!(
            hex::encode(a_fprint.scannable.serialize().unwrap()),
            ALICE_SCANNABLE_FINGERPRINT_V1
        );
        assert_eq!(
            hex::encode(b_fprint.scannable.serialize().unwrap()),
            BOB_SCANNABLE_FINGERPRINT_V1
        );
    }

    #[test]
    fn fingerprint_test_v2() {
        // testVectorsVersion2 in Java

        let a_key = IdentityKey::decode(&hex::decode(ALICE_IDENTITY).unwrap()).unwrap();
        let b_key = IdentityKey::decode(&hex::decode(BOB_IDENTITY).unwrap()).unwrap();

        let version = 2;
        let iterations = 5200;

        let a_fprint = Fingerprint::new(
            version,
            iterations,
            ALICE_STABLE_ID.as_bytes(),
            &a_key,
            BOB_STABLE_ID.as_bytes(),
            &b_key,
        )
        .unwrap();

        let b_fprint = Fingerprint::new(
            version,
            iterations,
            BOB_STABLE_ID.as_bytes(),
            &b_key,
            ALICE_STABLE_ID.as_bytes(),
            &a_key,
        )
        .unwrap();

        assert_eq!(
            hex::encode(a_fprint.scannable.serialize().unwrap()),
            ALICE_SCANNABLE_FINGERPRINT_V2
        );
        assert_eq!(
            hex::encode(b_fprint.scannable.serialize().unwrap()),
            BOB_SCANNABLE_FINGERPRINT_V2
        );

        // unchanged vs v1
        assert_eq!(format!("{}", a_fprint.display), DISPLAYABLE_FINGERPRINT_V1);
        assert_eq!(format!("{}", b_fprint.display), DISPLAYABLE_FINGERPRINT_V1);

        assert_eq!(
            hex::encode(a_fprint.scannable.serialize().unwrap()),
            ALICE_SCANNABLE_FINGERPRINT_V2
        );
        assert_eq!(
            hex::encode(b_fprint.scannable.serialize().unwrap()),
            BOB_SCANNABLE_FINGERPRINT_V2
        );
    }

    #[test]
    fn fingerprint_matching_identifiers() {
        // testMatchingFingerprints

        use crate::IdentityKeyPair;
        use rand::rngs::OsRng;

        let a_key_pair = IdentityKeyPair::generate(&mut OsRng);
        let b_key_pair = IdentityKeyPair::generate(&mut OsRng);

        let a_key = a_key_pair.identity_key();
        let b_key = b_key_pair.identity_key();

        let version = 1;
        let iterations = 1024;

        let a_fprint = Fingerprint::new(
            version,
            iterations,
            ALICE_STABLE_ID.as_bytes(),
            &a_key,
            BOB_STABLE_ID.as_bytes(),
            &b_key,
        )
        .unwrap();

        let b_fprint = Fingerprint::new(
            version,
            iterations,
            BOB_STABLE_ID.as_bytes(),
            &b_key,
            ALICE_STABLE_ID.as_bytes(),
            &a_key,
        )
        .unwrap();

        assert_eq!(
            format!("{}", a_fprint.display),
            format!("{}", b_fprint.display)
        );
        assert_eq!(format!("{}", a_fprint.display).len(), 60);

        assert_eq!(
            a_fprint
                .scannable
                .compare(&b_fprint.scannable.serialize().unwrap())
                .unwrap(),
            true
        );
        assert_eq!(
            b_fprint
                .scannable
                .compare(&a_fprint.scannable.serialize().unwrap())
                .unwrap(),
            true
        );

        // Java is missing this test
        assert_eq!(
            a_fprint
                .scannable
                .compare(&a_fprint.scannable.serialize().unwrap())
                .unwrap(),
            false
        );
        assert_eq!(
            b_fprint
                .scannable
                .compare(&b_fprint.scannable.serialize().unwrap())
                .unwrap(),
            false
        );
    }

    #[test]
    fn fingerprint_mismatching_fingerprints() {
        use crate::IdentityKeyPair;
        use rand::rngs::OsRng;

        let a_key_pair = IdentityKeyPair::generate(&mut OsRng);
        let b_key_pair = IdentityKeyPair::generate(&mut OsRng);
        let m_key_pair = IdentityKeyPair::generate(&mut OsRng); // mitm

        let a_key = a_key_pair.identity_key();
        let b_key = b_key_pair.identity_key();
        let m_key = m_key_pair.identity_key();

        let version = 1;
        let iterations = 1024;

        let a_fprint = Fingerprint::new(
            version,
            iterations,
            ALICE_STABLE_ID.as_bytes(),
            &a_key,
            BOB_STABLE_ID.as_bytes(),
            &m_key,
        )
        .unwrap();

        let b_fprint = Fingerprint::new(
            version,
            iterations,
            BOB_STABLE_ID.as_bytes(),
            &b_key,
            ALICE_STABLE_ID.as_bytes(),
            &a_key,
        )
        .unwrap();

        assert_ne!(
            format!("{}", a_fprint.display),
            format!("{}", b_fprint.display)
        );

        assert_eq!(
            a_fprint
                .scannable
                .compare(&b_fprint.scannable.serialize().unwrap())
                .unwrap(),
            false
        );
        assert_eq!(
            b_fprint
                .scannable
                .compare(&a_fprint.scannable.serialize().unwrap())
                .unwrap(),
            false
        );
    }

    #[test]
    fn fingerprint_mismatching_identifiers() {
        use crate::IdentityKeyPair;
        use rand::rngs::OsRng;

        let a_key_pair = IdentityKeyPair::generate(&mut OsRng);
        let b_key_pair = IdentityKeyPair::generate(&mut OsRng);

        let a_key = a_key_pair.identity_key();
        let b_key = b_key_pair.identity_key();

        let version = 1;
        let iterations = 1024;

        let a_fprint = Fingerprint::new(
            version,
            iterations,
            "+141512222222".as_bytes(),
            &a_key,
            BOB_STABLE_ID.as_bytes(),
            &b_key,
        )
        .unwrap();

        let b_fprint = Fingerprint::new(
            version,
            iterations,
            BOB_STABLE_ID.as_bytes(),
            &b_key,
            ALICE_STABLE_ID.as_bytes(),
            &a_key,
        )
        .unwrap();

        assert_ne!(
            format!("{}", a_fprint.display),
            format!("{}", b_fprint.display)
        );

        assert_eq!(
            a_fprint
                .scannable
                .compare(&b_fprint.scannable.serialize().unwrap())
                .unwrap(),
            false
        );
        assert_eq!(
            b_fprint
                .scannable
                .compare(&a_fprint.scannable.serialize().unwrap())
                .unwrap(),
            false
        );
    }

    #[test]
    fn fingerprint_mismatching_versions() {
        let a_key = IdentityKey::decode(&hex::decode(ALICE_IDENTITY).unwrap()).unwrap();
        let b_key = IdentityKey::decode(&hex::decode(BOB_IDENTITY).unwrap()).unwrap();

        let iterations = 5200;

        let a_fprint_v1 = Fingerprint::new(
            1,
            iterations,
            ALICE_STABLE_ID.as_bytes(),
            &a_key,
            BOB_STABLE_ID.as_bytes(),
            &b_key,
        )
        .unwrap();

        let a_fprint_v2 = Fingerprint::new(
            2,
            iterations,
            BOB_STABLE_ID.as_bytes(),
            &b_key,
            ALICE_STABLE_ID.as_bytes(),
            &a_key,
        )
        .unwrap();

        // Display fingerprint doesn't change
        assert_eq!(
            format!("{}", a_fprint_v1.display),
            format!("{}", a_fprint_v2.display)
        );

        // Scannable fingerprint does
        assert_ne!(
            hex::encode(a_fprint_v1.scannable.serialize().unwrap()),
            hex::encode(a_fprint_v2.scannable.serialize().unwrap())
        );
    }
}
