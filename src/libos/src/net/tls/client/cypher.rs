//use openssl::bn::BigNum;
use super::*;
use num_bigint::BigUint;
use comm::rand_gen::Generator;
use std::sync::Arc;

pub enum DhParams {
    P,
    G,
    Q,
    PubKey,
    SymKey,
}

impl DhParams {
    pub fn get_len_bit(&self) -> usize {
        match self {
            DhParams::P => 1024,    // don't change length of p, because it is declared from a constant in the process of Dh param generation
            DhParams::G => 1024,
            DhParams::Q => 160,
            DhParams::PubKey => DhParams::P.get_len_bit(),
            DhParams::SymKey => DhParams::P.get_len_bit(),
            _ => 0,
        }
    }

    pub fn get_len_byte(&self) -> usize {
        match self {
            DhParams::P => DhParams::P.get_len_bit()/8,
            DhParams::G => DhParams::G.get_len_bit()/8,
            DhParams::Q => DhParams::Q.get_len_bit()/8,
            DhParams::PubKey => DhParams::PubKey.get_len_bit()/8,
            DhParams::SymKey => DhParams::SymKey.get_len_bit()/8,
        }
    }
}

pub struct ClientCypher {
    dh_pub_para: (BigUint, BigUint),
    dh_private_key: BigUint,
    dh_public_key: BigUint,
    dh_symmetric_key: BigUint,
}

impl ClientCypher {
    pub fn new() -> Self{
        // let p = num_primes::BigUint::from_bytes_be(
        //     &BigNum::get_rfc2409_prime_1024().unwrap().to_vec()
        // );
        let p = BigUint::parse_bytes(b"179769313486231590770839156793787453197860296048756011706444423684197180216158519368947833795864925541502180565485980503646440548199239100050792877003355816639229553136239076508735759914822574862575007425302077447712589550957937778424442426617334727629299387668709205606050270810842907692932019128194467627007", 10).unwrap();
        let g = Generator::gen_biguint(DhParams::G.get_len_bit());
        let q = Generator::gen_biguint(DhParams::Q.get_len_bit());

        let a = g.modpow(&q, &p);

        Self {
            dh_pub_para: (p, g),
            dh_private_key: q,
            dh_public_key: a,
            dh_symmetric_key: BigUint::from_bytes_be(b"0"),
        }
    }

    pub fn calc_symmetric_key(&mut self, peer_dh_pub_key: Arc<BigUint>){
        self.dh_symmetric_key = peer_dh_pub_key.modpow(
            &self.dh_private_key, &self.dh_pub_para.0
        );
    }

    pub fn get_dh_pub_para(&self) -> Arc<(BigUint, BigUint)> {
        Arc::new(self.dh_pub_para.clone())
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
