use crate::{Error, Hash};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

/// Ed25519 signature size in bytes.
pub const SIGNATURE_LEN: usize = 64;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Transaction {
    /// Sender's Ed25519 public key, doubles as their address.
    pub from: [u8; 32],
    /// Recipient's public key / address.
    pub to: [u8; 32],
    pub amount: u64,
    pub nonce: u64,
    /// Ed25519 signature over `pure_payload()`. `None` means the transaction
    /// is unsigned and will be rejected by `verify_signature()`.
    #[serde(with = "option_sig_bytes")]
    pub signature: Option<[u8; SIGNATURE_LEN]>,
}

/// Bridges `Option<[u8; 64]>` through `Option<Vec<u8>>` because serde lacks
/// built-in Deserialize for arrays past 32 elements. Length checked on read.
mod option_sig_bytes {
    use super::SIGNATURE_LEN;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(
        sig: &Option<[u8; SIGNATURE_LEN]>,
        s: S,
    ) -> Result<S::Ok, S::Error> {
        sig.as_ref().map(|arr| arr.as_slice()).serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        d: D,
    ) -> Result<Option<[u8; SIGNATURE_LEN]>, D::Error> {
        let opt: Option<Vec<u8>> = Option::deserialize(d)?;
        opt.map(|v| {
            if v.len() != SIGNATURE_LEN {
                Err(serde::de::Error::custom(format!(
                    "signature must be exactly {SIGNATURE_LEN} bytes, got {}",
                    v.len()
                )))
            } else {
                let mut arr = [0u8; SIGNATURE_LEN];
                arr.copy_from_slice(&v);
                Ok(arr)
            }
        })
        .transpose()
    }
}

impl Transaction {
    /// Bytes that the sender signs over. Includes every field except `signature`.
    pub fn pure_payload(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(32 + 32 + 8 + 8);
        buf.extend_from_slice(&self.from);
        buf.extend_from_slice(&self.to);
        buf.extend_from_slice(&self.amount.to_le_bytes());
        buf.extend_from_slice(&self.nonce.to_le_bytes());
        buf
    }

    /// Deterministic encoding; `signature` is length-prefixed for safe parsing.
    /// TODO: swap for commonware-utils.
    pub fn to_bytes(&self) -> Vec<u8> {
        let sig_len = self.signature.as_ref().map_or(0, |s| s.len());
        let mut buf = Vec::with_capacity(32 + 32 + 8 + 8 + 8 + sig_len);
        buf.extend_from_slice(&self.from);
        buf.extend_from_slice(&self.to);
        buf.extend_from_slice(&self.amount.to_le_bytes());
        buf.extend_from_slice(&self.nonce.to_le_bytes());
        buf.extend_from_slice(&(sig_len as u64).to_le_bytes());
        if let Some(sig) = &self.signature {
            buf.extend_from_slice(sig);
        }
        buf
    }

    pub fn hash(&self) -> Hash {
        Hash::digest(&self.to_bytes())
    }

    /// Build and sign in one step; `from` is set to `signer`'s public key.
    pub fn signed(signer: &SigningKey, to: [u8; 32], amount: u64, nonce: u64) -> Self {
        let from = signer.verifying_key().to_bytes();
        let mut tx = Transaction {
            from,
            to,
            amount,
            nonce,
            signature: None,
        };
        let sig: Signature = signer.sign(&tx.pure_payload());
        tx.signature = Some(sig.to_bytes());
        tx
    }

    /// Verify the Ed25519 signature against `from`'s public key.
    pub fn verify_signature(&self) -> Result<(), Error> {
        let sig_bytes = self
            .signature
            .as_ref()
            .ok_or_else(|| Error::InvalidSignature("transaction is unsigned".to_string()))?;
        let pubkey = VerifyingKey::from_bytes(&self.from)
            .map_err(|e| Error::InvalidSignature(format!("bad public key: {e}")))?;
        let sig = Signature::from_bytes(sig_bytes);
        pubkey
            .verify(&self.pure_payload(), &sig)
            .map_err(|e| Error::InvalidSignature(format!("verification failed: {e}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

    fn keypair() -> SigningKey {
        SigningKey::generate(&mut OsRng)
    }

    #[test]
    fn sign_then_verify_roundtrip() {
        let key = keypair();
        let tx = Transaction::signed(&key, [9u8; 32], 100, 0);
        assert!(tx.verify_signature().is_ok());
    }

    #[test]
    fn tampering_after_sign_fails_verify() {
        let key = keypair();
        let mut tx = Transaction::signed(&key, [9u8; 32], 100, 0);
        tx.amount = 999_999; // tamper post-sign
        assert!(tx.verify_signature().is_err());
    }

    #[test]
    fn signature_from_wrong_key_fails() {
        // Sign with `attacker`, but pretend the tx is from `victim`.
        let victim = keypair();
        let attacker = keypair();
        let mut tx = Transaction::signed(&attacker, [9u8; 32], 100, 0);
        tx.from = victim.verifying_key().to_bytes();
        assert!(tx.verify_signature().is_err());
    }

    #[test]
    fn garbage_signature_bytes_fail_verify() {
        // Right length but bogus content — must be rejected.
        let key = keypair();
        let mut tx = Transaction::signed(&key, [9u8; 32], 100, 0);
        tx.signature = Some([0xff; SIGNATURE_LEN]);
        assert!(tx.verify_signature().is_err());
    }

    #[test]
    fn unsigned_tx_is_rejected() {
        let key = keypair();
        let tx = Transaction {
            from: key.verifying_key().to_bytes(),
            to: [9u8; 32],
            amount: 1,
            nonce: 0,
            signature: None,
        };
        match tx.verify_signature() {
            Err(Error::InvalidSignature(_)) => {}
            other => panic!("expected InvalidSignature error, got {other:?}"),
        }
    }

    #[test]
    fn pure_payload_excludes_signature_field() {
        // Two txs identical except for signature bytes must share pure_payload.
        let key = keypair();
        let tx1 = Transaction::signed(&key, [9u8; 32], 100, 0);
        let mut tx2 = tx1.clone();
        tx2.signature = Some([0xff; SIGNATURE_LEN]); // different sig, same fields
        assert_eq!(tx1.pure_payload(), tx2.pure_payload());
    }
}
