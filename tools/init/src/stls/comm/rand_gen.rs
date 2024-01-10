use std::os::unix::thread;

use rand::thread_rng;
// use rand::rngs::ThreadRng;
use num_bigint::BigUint;
use num_bigint::RandBigInt;

pub struct Generator {
}

impl Generator {
    pub fn new() -> Self {
        Self{}
    }
    
    pub fn gen_biguint(bit_size: usize) -> BigUint {
        let mut rng = thread_rng();
        rng.gen_biguint(bit_size as u64)
    }
}