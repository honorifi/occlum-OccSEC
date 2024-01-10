use sgx_rand::{thread_rng, Rng};
// use rand::rngs::ThreadRng;
use num_bigint::BigUint;
// use num_bigint::RandBigInt;

pub struct Generator {
}

impl Generator {
    pub fn new() -> Self {
        Self{}
    }
    
    pub fn gen_biguint(bit_size: usize) -> BigUint {
        let mut rng = thread_rng();
        // rng.gen_biguint(bit_size as u64)

        let mut rd_bytes = vec![0u8; bit_size/8];
        rng.fill_bytes(&mut rd_bytes);
        BigUint::from_bytes_be(&rd_bytes)
    }
}