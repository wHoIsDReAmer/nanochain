use crate::hash::{hash_serde, sha256, zero};
use crate::{Hash, Transaction};
use bytes::{Buf, BufMut};
use commonware_codec::{
    Encode, EncodeSize, Error as CodecError, FixedSize, RangeCfg, Read, ReadExt as _, Write,
};
use commonware_consensus::{types::Height, Block as ConsensusBlock, Heightable};
use commonware_cryptography::Digestible;
use serde::{Deserialize, Serialize};

/// Hard ceiling on tx-per-block applied when decoding from the network; DoS guard.
const MAX_TXS_PER_BLOCK: usize = 16_384;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockHeader {
    pub height: u64,
    #[serde(with = "hash_serde")]
    pub parent_hash: Hash,
    #[serde(with = "hash_serde")]
    pub tx_root: Hash,
    pub timestamp: u64,
    pub proposer: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Block {
    pub header: BlockHeader,
    pub transactions: Vec<Transaction>,
}

impl Block {
    pub fn compute_tx_root(txs: &[Transaction]) -> Hash {
        if txs.is_empty() {
            return zero();
        }

        let mut layer: Vec<Hash> = txs.iter().map(|tx| tx.hash()).collect();

        while layer.len() > 1 {
            if layer.len() % 2 == 1 {
                layer.push(*layer.last().unwrap());
            }
            layer = layer
                .chunks(2)
                .map(|pair| {
                    let mut buf = [0u8; 64];
                    buf[..32].copy_from_slice(&pair[0].0);
                    buf[32..].copy_from_slice(&pair[1].0);
                    sha256(&buf)
                })
                .collect();
        }

        layer.into_iter().next().unwrap()
    }

    pub fn hash(&self) -> Hash {
        sha256(&self.header.encode())
    }

    pub fn genesis() -> Self {
        Block {
            header: BlockHeader {
                height: 0,
                parent_hash: zero(),
                tx_root: zero(),
                timestamp: 0,
                proposer: [0u8; 32],
            },
            transactions: vec![],
        }
    }

    pub fn new(
        height: u64,
        parent_hash: Hash,
        timestamp: u64,
        proposer: [u8; 32],
        transactions: Vec<Transaction>,
    ) -> Self {
        let tx_root = Self::compute_tx_root(&transactions);
        Block {
            header: BlockHeader {
                height,
                parent_hash,
                tx_root,
                timestamp,
                proposer,
            },
            transactions,
        }
    }
}

impl Write for BlockHeader {
    fn write(&self, buf: &mut impl BufMut) {
        self.height.write(buf);
        self.parent_hash.write(buf);
        self.tx_root.write(buf);
        self.timestamp.write(buf);
        self.proposer.write(buf);
    }
}

impl Read for BlockHeader {
    type Cfg = ();
    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        Ok(Self {
            height: u64::read(buf)?,
            parent_hash: Hash::read(buf)?,
            tx_root: Hash::read(buf)?,
            timestamp: u64::read(buf)?,
            proposer: <[u8; 32]>::read(buf)?,
        })
    }
}

impl FixedSize for BlockHeader {
    const SIZE: usize = 8 + 32 + 32 + 8 + 32;
}

impl Write for Block {
    fn write(&self, buf: &mut impl BufMut) {
        self.header.write(buf);
        self.transactions.write(buf);
    }
}

impl Read for Block {
    type Cfg = ();
    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let header = BlockHeader::read(buf)?;
        let cfg: (RangeCfg<usize>, ()) = ((..=MAX_TXS_PER_BLOCK).into(), ());
        let transactions = Vec::<Transaction>::read_cfg(buf, &cfg)?;
        Ok(Self {
            header,
            transactions,
        })
    }
}

impl EncodeSize for Block {
    fn encode_size(&self) -> usize {
        self.header.encode_size() + self.transactions.encode_size()
    }
}

impl Digestible for Block {
    type Digest = Hash;
    fn digest(&self) -> Hash {
        self.hash()
    }
}

impl Heightable for Block {
    fn height(&self) -> Height {
        Height::new(self.header.height)
    }
}

impl ConsensusBlock for Block {
    fn parent(&self) -> Hash {
        self.header.parent_hash
    }
}

/// Compile-time assertion that `Block` satisfies commonware's consensus `Block`.
const _: fn() = || {
    fn assert_block<B: ConsensusBlock>() {}
    assert_block::<Block>();
};

#[cfg(test)]
mod tests {
    use super::*;

    fn tx(amount: u64, nonce: u64) -> Transaction {
        Transaction {
            from: [1u8; 32],
            to: [2u8; 32],
            amount,
            nonce,
            signature: None,
        }
    }

    #[test]
    fn empty_root_is_zero() {
        assert_eq!(Block::compute_tx_root(&[]), zero());
    }

    #[test]
    fn single_tx_root_is_tx_hash() {
        let t = tx(10, 0);
        let h = t.hash();
        assert_eq!(Block::compute_tx_root(&[t]), h);
    }

    #[test]
    fn modifying_one_tx_changes_root() {
        let a = vec![tx(10, 0), tx(20, 1), tx(30, 2)];
        let mut b = a.clone();
        b[1].amount = 999;
        assert_ne!(Block::compute_tx_root(&a), Block::compute_tx_root(&b));
    }

    #[test]
    fn reordering_changes_root() {
        let a = tx(10, 0);
        let b = tx(20, 1);
        assert_ne!(
            Block::compute_tx_root(&[a.clone(), b.clone()]),
            Block::compute_tx_root(&[b, a]),
        );
    }

    #[test]
    fn block_hash_reacts_to_tx_change() {
        let b1 = Block::new(1, zero(), 0, [0u8; 32], vec![tx(10, 0)]);
        let b2 = Block::new(1, zero(), 0, [0u8; 32], vec![tx(99, 0)]);
        assert_ne!(b1.hash(), b2.hash());
    }

    #[test]
    fn odd_layer_handled() {
        let txs = vec![tx(1, 0), tx(2, 1), tx(3, 2)];
        let _ = Block::compute_tx_root(&txs);
    }

    #[test]
    fn block_codec_roundtrip() {
        use commonware_codec::{DecodeExt as _, Encode as _};
        let b = Block::new(7, zero(), 42, [3u8; 32], vec![tx(10, 0), tx(20, 1)]);
        let encoded = b.encode();
        let decoded = Block::decode(encoded).expect("decode");
        assert_eq!(b.header.height, decoded.header.height);
        assert_eq!(b.header.parent_hash, decoded.header.parent_hash);
        assert_eq!(b.header.tx_root, decoded.header.tx_root);
        assert_eq!(b.header.timestamp, decoded.header.timestamp);
        assert_eq!(b.header.proposer, decoded.header.proposer);
        assert_eq!(b.transactions.len(), decoded.transactions.len());
        assert_eq!(b.hash(), decoded.hash());
    }

    #[test]
    fn header_is_fixed_112_bytes() {
        assert_eq!(BlockHeader::SIZE, 112);
    }
}
