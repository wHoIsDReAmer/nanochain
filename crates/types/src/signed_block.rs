use crate::{Block, Error};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

/// A block with its proposer's Ed25519 signature over `block.hash()`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedBlock {
    pub block: Block,
    #[serde(with = "sig_bytes")]
    pub signature: [u8; 64],
}

impl SignedBlock {
    /// Sign with `signer`; `block.header.proposer` must match `signer`'s public key.
    pub fn sign(block: Block, signer: &SigningKey) -> Result<Self, Error> {
        let signer_pub = signer.verifying_key().to_bytes();
        if block.header.proposer != signer_pub {
            return Err(Error::InvalidBlock(
                "proposer field does not match signer's public key".into(),
            ));
        }
        let sig: Signature = signer.sign(&block.hash().0);
        Ok(SignedBlock {
            block,
            signature: sig.to_bytes(),
        })
    }

    /// Verify the Ed25519 signature against `block.header.proposer`.
    pub fn verify(&self) -> Result<(), Error> {
        let pubkey = VerifyingKey::from_bytes(&self.block.header.proposer)
            .map_err(|e| Error::InvalidBlock(format!("bad proposer key: {e}")))?;
        let sig = Signature::from_bytes(&self.signature);
        pubkey
            .verify(&self.block.hash().0, &sig)
            .map_err(|e| Error::InvalidBlock(format!("block signature: {e}")))
    }

    pub fn proposer(&self) -> [u8; 32] {
        self.block.header.proposer
    }
}

/// Bridges `[u8; 64]` through `Vec<u8>` cuz of serde lacks built-in
/// Deserialize for arrays past 32 elements. Length checked on read.
mod sig_bytes {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(sig: &[u8; 64], s: S) -> Result<S::Ok, S::Error> {
        sig.as_slice().serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 64], D::Error> {
        let v: Vec<u8> = Vec::deserialize(d)?;
        if v.len() != 64 {
            return Err(serde::de::Error::custom(format!(
                "expected 64 bytes, got {}",
                v.len()
            )));
        }
        let mut arr = [0u8; 64];
        arr.copy_from_slice(&v);
        Ok(arr)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Hash;
    use rand_core::OsRng;

    fn keypair() -> SigningKey {
        SigningKey::generate(&mut OsRng)
    }

    fn block_for(signer: &SigningKey) -> Block {
        Block::new(
            1,
            Hash::zero(),
            0,
            signer.verifying_key().to_bytes(),
            vec![],
        )
    }

    #[test]
    fn sign_then_verify_roundtrip() {
        let key = keypair();
        let sb = SignedBlock::sign(block_for(&key), &key).unwrap();
        assert!(sb.verify().is_ok());
    }

    #[test]
    fn proposer_mismatch_refuses_to_sign() {
        let key = keypair();
        let mut block = block_for(&key);
        block.header.proposer = [0xff; 32]; // forge proposer
        let err = SignedBlock::sign(block, &key).unwrap_err();
        assert!(matches!(err, Error::InvalidBlock(_)));
    }

    #[test]
    fn tampered_block_fails_verify() {
        let key = keypair();
        let mut sb = SignedBlock::sign(block_for(&key), &key).unwrap();
        sb.block.header.height = 9999;
        assert!(sb.verify().is_err());
    }

    #[test]
    fn wrong_proposer_fails_verify() {
        let alice = keypair();
        let bob = keypair();
        let mut sb = SignedBlock::sign(block_for(&alice), &alice).unwrap();
        sb.block.header.proposer = bob.verifying_key().to_bytes();
        assert!(sb.verify().is_err());
    }

    #[test]
    fn garbage_signature_fails_verify() {
        let key = keypair();
        let mut sb = SignedBlock::sign(block_for(&key), &key).unwrap();
        sb.signature = [0xff; 64];
        assert!(sb.verify().is_err());
    }
}
