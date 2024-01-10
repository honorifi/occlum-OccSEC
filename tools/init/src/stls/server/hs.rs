use super::*;
use cypher::ServerCypher;
use client::msg::read_usize_be;
// use openssl::rsa::{Rsa, Padding};
// use openssl::pkey::Private;
use comm::ecdsa::{EcdsaHandle, EcdsaPublic, ECDSA_SIGN_MSG_SIZE};
use num_bigint::BigUint;
use std::sync::Arc;
use comm::ca_manager;

pub struct ServerHs {
    cypher: Option<ServerCypher>,
    dh_pub_key: Option<BigUint>,
    // rsa_private_key: Rsa<Private>,
    // rsa_peer_pub_key: Rsa<Private>,
    ec_priv_key: EcdsaHandle,
    ec_peer_pub_key: EcdsaPublic,
}

impl ServerHs {
    pub fn new() -> Self {
        Self {
            cypher: None,
            dh_pub_key: None,
            // rsa_private_key: ca_manager::get_peer_rsa(),
            // rsa_peer_pub_key: ca_manager::get_my_rsa(),
            ec_priv_key: ca_manager::get_ec(1),
            ec_peer_pub_key: ca_manager::get_ec_pub(0),
        }
    }

    pub fn recv_clienthello_and_decrypt(&mut self, data: &[u8]) {
        // let decrypted_data = self.veri_with_rsa(data);
        let decrypted_data = self.veri_with_ecdsa(data).unwrap();
    
        let raw_data = &mut (&decrypted_data as &[u8]);
    
        let p_len = read_usize_be(raw_data);

        // println!("p_len: {}", p_len);
    
        let (p_bytes, rest) = raw_data.split_at(p_len as usize);
        *raw_data = rest;
        let p = BigUint::from_bytes_be(p_bytes);
    
        let g_len = read_usize_be(raw_data);

        // println!("g_len: {}", g_len);
    
        let (g_bytes, rest) = raw_data.split_at(g_len as usize);
        *raw_data = rest;
        let g = BigUint::from_bytes_be(g_bytes);
    
        let pubkey_len = read_usize_be(raw_data);

        // println!("pubkey_len: {}", pubkey_len);
    
        let (pubkey_bytes, rest) = raw_data.split_at(pubkey_len as usize);
        *raw_data = rest;
        self.dh_pub_key = Some(BigUint::from_bytes_be(pubkey_bytes));
    
        let dh_pub_para = Arc::new((p, g));
        self.cypher = Some(ServerCypher::new(dh_pub_para));

    }

    pub fn reply_to_client(&self) -> Vec<u8> {
        let pub_key = match self.cypher.clone() {
            Some(k) => (*k.get_dh_pub_key()).clone(),
            None => panic!("not yet recv client msg"),
        };
        // let server_hello = msg::ServerHelloMessage::new(pub_key, self.rsa_private_key.clone());
        let server_hello = msg::ServerHelloMessage::new(pub_key, self.ec_priv_key.clone());
        server_hello.pack_msg_and_sign()
    }

    pub fn get_nego_key(&mut self) -> BigUint {
        let pub_key = match self.dh_pub_key.clone() {
            Some(k) => k,
            None => panic!("not yet recv client msg"),
        };

        let cypher = match &mut self.cypher {
            Some(t) => t,
            None => panic!("No cypher found in ServerHs, try and check handshake first"),
        };

        match cypher.get_dh_symmetric_key() {
            Err(err) => {
                cypher.calc_symmetric_key(Arc::new(pub_key));
                (*cypher.get_dh_symmetric_key().unwrap()).clone()
            },
            Ok(ok) => (*ok).clone(),
        }
    }

    // fn veri_with_rsa(&self, data: &[u8]) -> Vec<u8> {
    //     let len = data.len();
    //     let rsa_mod_len = self.rsa_peer_pub_key.size() as usize;
    //     let mut ret = vec![0 as u8; len];

    //     let mut cur_pos = 0;
    //     while cur_pos < len - rsa_mod_len {
    //         self.rsa_peer_pub_key.public_decrypt(
    //             &data[cur_pos..(cur_pos+rsa_mod_len)],
    //             &mut ret[cur_pos..(cur_pos+rsa_mod_len)],
    //             Padding::NONE,
    //         ).unwrap();
    //         cur_pos += rsa_mod_len;
    //     };
    //     self.rsa_peer_pub_key.public_decrypt(
    //         &data[cur_pos..],
    //         &mut ret[cur_pos..],
    //         Padding::PKCS1,
    //     ).unwrap();

    //     ret
    // }

    fn veri_with_ecdsa(&self, data: &[u8]) -> Result<Vec<u8>, &str> {
        let sign_msg_bytes = data[..ECDSA_SIGN_MSG_SIZE].to_vec();
        let raw_data = data[ECDSA_SIGN_MSG_SIZE..].to_vec();
        let veri_result = self.ec_peer_pub_key.veri_msg_with_bytes(
            &raw_data, &sign_msg_bytes);
        
        match veri_result {
            true => Ok(raw_data),
            false => Err("ecdsa verification failed!"),
        }
    }
}