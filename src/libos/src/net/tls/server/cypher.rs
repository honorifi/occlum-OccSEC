use super::*;

use num_bigint::BigUint;
use comm::rand_gen::Generator;
use std::sync::Arc;
use client::cypher::DhParams;

pub struct ServerCypher {
    dh_pub_para: (BigUint, BigUint),
    dh_private_key: BigUint,
    dh_public_key: BigUint,
    dh_symmetric_key: BigUint,
}

impl ServerCypher {
    pub fn new(dh_pub_para: Arc<(BigUint, BigUint)>) -> Self{
        let p = dh_pub_para.0.clone();
        let g = dh_pub_para.1.clone();
        let q = Generator::gen_biguint(DhParams::Q.get_len_bit());
        
        let b = g.modpow(&q, &p);

        Self{
            dh_pub_para: (p, g),
            dh_private_key: q,
            dh_public_key: b,
            dh_symmetric_key: BigUint::from_bytes_be(b"0"),
        }
    }

    pub fn calc_symmetric_key(&mut self, peer_dh_pub_key: Arc<BigUint>){
        self.dh_symmetric_key = peer_dh_pub_key.modpow(
            &self.dh_private_key, &self.dh_pub_para.0
        );
    }

    pub fn get_dh_pub_key(&self) -> Arc<BigUint> {
        Arc::new(self.dh_public_key.clone())
    }

    pub fn get_dh_symmetric_key(&self) -> Result<Arc<BigUint>> {
        let zero = BigUint::from_bytes_be(b"0");
        if self.dh_symmetric_key == zero {
            return_errno!(ECONNREFUSED, "could not find peer_dh_pub_key, try calc_symmetric_key first\n");
        }
        
        Ok(Arc::new(self.dh_symmetric_key.clone()))
    }
}

impl Clone for ServerCypher {
    fn clone(&self) -> ServerCypher {
        ServerCypher {
            dh_pub_para: self.dh_pub_para.clone(),
            dh_private_key: self.dh_private_key.clone(),
            dh_public_key: self.dh_public_key.clone(),
            dh_symmetric_key: self.dh_symmetric_key.clone(),
        }
    }
}