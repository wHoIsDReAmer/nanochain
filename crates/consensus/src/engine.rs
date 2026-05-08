use nanochain_types::Block;

pub struct ConsensusEngine {
    // Simplex consensus integration will go here
}

impl ConsensusEngine {
    pub fn new() -> Self {
        ConsensusEngine {}
    }

    pub fn propose(&self, block: Block) {
        tracing::info!(height = block.header.height, "proposing block");
    }
}

impl Default for ConsensusEngine {
    fn default() -> Self {
        Self::new()
    }
}
