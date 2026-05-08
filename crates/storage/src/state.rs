use std::collections::HashMap;

pub struct StateStore {
    // account -> balance
    balances: HashMap<[u8; 32], u64>,
}

impl StateStore {
    pub fn new() -> Self {
        StateStore {
            balances: HashMap::new(),
        }
    }

    pub fn get_balance(&self, account: &[u8; 32]) -> u64 {
        *self.balances.get(account).unwrap_or(&0)
    }

    pub fn set_balance(&mut self, account: [u8; 32], amount: u64) {
        self.balances.insert(account, amount);
    }
}

impl Default for StateStore {
    fn default() -> Self {
        Self::new()
    }
}
