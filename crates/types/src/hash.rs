pub use commonware_cryptography::sha256::Digest as Hash;
use commonware_cryptography::{Hasher, Sha256};

pub fn sha256(bytes: &[u8]) -> Hash {
    Sha256::hash(bytes)
}

pub const fn zero() -> Hash {
    Hash([0u8; 32])
}

/// commonware's `Digest` has no serde derives; bridge through `Vec<u8>`.
pub mod hash_serde {
    use super::Hash;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(h: &Hash, s: S) -> Result<S::Ok, S::Error> {
        h.0.as_slice().serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Hash, D::Error> {
        let v: Vec<u8> = Vec::deserialize(d)?;
        if v.len() != 32 {
            return Err(serde::de::Error::custom(format!(
                "Hash must be 32 bytes, got {}",
                v.len()
            )));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&v);
        Ok(Hash(arr))
    }
}
