use nanochain_types::{Block, Hash};
use std::collections::HashMap;

pub struct BlockStore {
    blocks: HashMap<Hash, Block>,
    height_index: HashMap<u64, Hash>,
}

impl BlockStore {
    pub fn new() -> Self {
        BlockStore {
            blocks: HashMap::new(),
            height_index: HashMap::new(),
        }
    }

    pub fn insert(&mut self, block: Block) {
        let hash = block.hash();
        self.height_index.insert(block.header.height, hash);
        self.blocks.insert(hash, block);
    }

    pub fn get_by_hash(&self, hash: &Hash) -> Option<&Block> {
        self.blocks.get(hash)
    }

    pub fn get_by_height(&self, height: u64) -> Option<&Block> {
        self.height_index
            .get(&height)
            .and_then(|h| self.blocks.get(h))
    }

    pub fn tip(&self) -> Option<&Block> {
        let max_height = self.height_index.keys().max()?;
        self.get_by_height(*max_height)
    }
}

impl Default for BlockStore {
    fn default() -> Self {
        Self::new()
    }
}
