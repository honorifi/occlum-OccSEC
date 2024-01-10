use super::*;
use cypher::DhParams;
// use openssl::rsa::{Rsa, Padding};
// use openssl::pkey:: Private;
use comm::ecdsa::EcdsaHandle;
use num_bigint::BigUint;
use core::cmp;
use std::sync::Arc;

const LENGH_WIDTH: usize = std::mem::size_of::<usize>();

pub fn read_usize_be(raw_data: &mut &[u8]) -> usize {
    let (int_bytes, rest) = raw_data.split_at(LENGH_WIDTH);
    *raw_data = rest;
    usize::from_be_bytes(int_bytes.try_into().unwrap())
}

pub struct ClientHelloMessage {
    dh_pub_para: (BigUint, BigUint),
    dh_public_key: BigUint,
    //rsa_private_key: Rsa<Private>,
    ec_priv_key: EcdsaHandle,
}

impl ClientHelloMessage {
    pub fn new(p:BigUint, g:BigUint, pubkey:BigUint, ec_priv_key:EcdsaHandle) -> Self {
        Self {
            dh_pub_para: (p, g),
            dh_public_key: pubkey,
            //rsa_private_key: rsa,
            ec_priv_key,
        }
    }
    
    // signed the dh_pub_key with rsa private key
    pub fn pack_msg_and_sign(&self) -> Vec<u8> {
        let mut dh_pub_para_0_data = self.dh_pub_para.0.clone().to_bytes_be();
        let mut dh_pub_para_1_data = self.dh_pub_para.1.clone().to_bytes_be();
        let mut dh_pub_key_data = self.dh_public_key.clone().to_bytes_be();
        let mut dh_pub_para_0_len = 
            cmp::min(dh_pub_para_0_data.len(), DhParams::P.get_len_byte())
            .to_be_bytes()
            .to_vec();
        dh_pub_para_0_len.resize(LENGH_WIDTH, 0);
        let mut dh_pub_para_1_len = 
            cmp::min(dh_pub_para_1_data.len(), DhParams::G.get_len_byte())
            .to_be_bytes()
            .to_vec();
        dh_pub_para_1_len.resize(LENGH_WIDTH, 0);
        let mut dh_pub_key_len = 
            cmp::min(dh_pub_key_data.len(), DhParams::PubKey.get_len_byte())
            .to_be_bytes()
            .to_vec();
        dh_pub_key_len.resize(LENGH_WIDTH, 0);

        let mut data = Vec::new();
        data.append(&mut dh_pub_para_0_len);
        data.append(&mut dh_pub_para_0_data);
        data.append(&mut dh_pub_para_1_len);
        data.append(&mut dh_pub_para_1_data);
        data.append(&mut dh_pub_key_len);
        data.append(&mut dh_pub_key_data);

        //self.sign_with_rsa(&data)
        self.sign_with_ecdsa(&data)
    }

    // fn sign_with_rsa(&self, data: &mut [u8]) -> Vec<u8> {
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
        let mut data = data.to_vec();
        ret.append(&mut data);
        ret
    }
}