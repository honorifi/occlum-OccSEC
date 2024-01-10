use super::*;

use comm::ecdsa::EcdsaPublicBytes;
use std::collections::HashMap;

pub struct CertContain {
    container: HashMap<usize, EcdsaPublicBytes>,
    gc: Vec<usize>,
    max_tag: usize,
}

impl CertContain {
    pub fn new() -> Self {
        Self {
            container: HashMap::new(),
            gc: Vec::new(),
            max_tag: 0,
        }
    }

    pub fn find(&self, val: &EcdsaPublicBytes) -> Result<usize, ()> {
        for (k, v) in &self.container {
            if val.equal(v) {return Ok(*k);}
        }

        Err(())
    }

    pub fn regist(&mut self, raw_val: &[u8]) -> usize {
        let val = EcdsaPublicBytes::from_be_bytes(raw_val);

        let key = match self.find(&val) {
            Ok(k) => k,
            Err(()) => {
                match self.gc.pop() {
                    Some(k) => k,
                    None => {
                        let ret = self.max_tag;
                        self.max_tag += 1;
                        ret
                    },
                }
            },
        };

        self.container.insert(key, val);
        key
    }

    pub fn unregist(&mut self, key: usize) {
        if !self.gc.contains(&key) {
            self.gc.push(key);
            self.container.remove(&key);
        }
    }
}