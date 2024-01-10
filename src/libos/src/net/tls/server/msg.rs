use super::*;

use client::cypher::DhParams;
// use openssl::rsa::{Rsa, Padding};
// use openssl::pkey:: Private;
use comm::ecdsa::EcdsaHandle;
use num_bigint::BigUint;
use core::cmp;


const LENGH_WIDTH: usize = std::mem::size_of::<usize>();

pub struct ServerHelloMessage {
    dh_public_key: BigUint,
    // rsa_private_key: Rsa<Private>,
    ec_priv_key: EcdsaHandle,
    ec_hash_tag: Option<usize>,
}

impl ServerHelloMessage {
    pub fn new(pubkey:BigUint, ec_priv_key: EcdsaHandle) -> Self {
        Self {
            dh_public_key: pubkey,
            // rsa_private_key: rsa,
            ec_priv_key,
            ec_hash_tag: None,
        }
    }

    pub fn new_with_echash(pubkey:BigUint, ec_priv_key: EcdsaHandle, ec_hash: usize) -> Self {
        Self {
            dh_public_key: pubkey,
            // rsa_private_key: rsa,
            ec_priv_key,
            ec_hash_tag: Some(ec_hash),
        }
    }

    pub fn pack_msg_and_sign(&self) -> Vec<u8> {
        let mut dh_pub_key_data = self.dh_public_key.clone().to_bytes_be();
        let mut dh_pub_key_len = 
            cmp::min(dh_pub_key_data.len(), DhParams::PubKey.get_len_byte())
            .to_be_bytes()
            .to_vec();
        dh_pub_key_len.resize(LENGH_WIDTH, 0);

        let mut data = Vec::new();
        data.append(&mut dh_pub_key_len);
        data.append(&mut dh_pub_key_data);

        // self.sign_with_rsa(&data)
        let mut ret = self.sign_with_ecdsa(&data);

        match self.ec_hash_tag {
            Some(ec_hash) => {
                // println!("[sign]: ident tag: {}\npubkey: {}", ec_hash, self.ec_priv_key.to_pub_handle().to_bytes_str());
                let mut ec_hash_vec = ec_hash.to_be_bytes().to_vec();
                let mut msg_with_len = (ec_hash_vec.len()+ret.len()).to_be_bytes().to_vec();
                msg_with_len.append(&mut ec_hash_vec);
                msg_with_len.append(&mut ret);
                msg_with_len
            },
            None => {ret},
        }
    }

    // fn sign_with_rsa(&self, data: &[u8]) -> Vec<u8> {
    //     let rsa_mod_len = self.rsa_private_key.size() as usize;
    //     let encrypt_msg_pad_len = (data.len()/rsa_mod_len + 1) * rsa_mod_len;
    //     let mut ret = vec![0 as u8; encrypt_msg_pad_len];

    //     let mut cur_pos = 0;
    //     while cur_pos < encrypt_msg_pad_len - rsa_mod_len {
    //         self.rsa_private_key.private_encrypt(
    //             &data[cur_pos..(cur_pos+rsa_mod_len)],
    //             &mut ret[cur_pos..(cur_pos+rsa_mod_len)],
    //             Padding::NONE,
    //         ).unwrap();
    //         cur_pos += rsa_mod_len;
    //     };
    //     self.rsa_private_key.private_encrypt(
    //         &data[cur_pos..],
    //         &mut ret[cur_pos..],
    //         Padding::PKCS1,
    //     ).unwrap();

    //     ret
    // }

    fn sign_with_ecdsa(&self, data: &[u8]) -> Vec<u8> {
        let mut ret = self.ec_priv_key.sign_msg_with_bytes(data);
        // println!("signature: {}\nraw_data: {}", base64::encode(&ret), base64::encode(data));
        let mut data = data.to_vec();
        ret.append(&mut data);
        ret
    }
}