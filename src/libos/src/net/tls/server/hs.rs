use super::*;
use cypher::ServerCypher;
use client::msg::read_u32_be;
// use openssl::rsa::{Rsa, Padding};
// use openssl::pkey::Private;
use comm::ecdsa::{EcdsaHandle, EcdsaPublic, ECDSA_SIGN_MSG_SIZE};
use num_bigint::BigUint;
use std::sync::Arc;
use comm::ca_manager;
const USIZE_LENGH: usize = std::mem::size_of::<usize>();

// please modify these two variable simutaneously for accurate err msg display
const MAX_RETRY: usize = 1000;
const HANDSHAKE_FAIL_ERR: &str = "handshake failed after 1000 times retry";
// please modify these two variable simutaneously


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
    
        let p_len = read_u32_be(raw_data);

        // println!("p_len: {}", p_len);
    
        let (p_bytes, rest) = raw_data.split_at(p_len as usize);
        *raw_data = rest;
        let p = BigUint::from_bytes_be(p_bytes);
    
        let g_len = read_u32_be(raw_data);

        // println!("g_len: {}", g_len);
    
        let (g_bytes, rest) = raw_data.split_at(g_len as usize);
        *raw_data = rest;
        let g = BigUint::from_bytes_be(g_bytes);
    
        let pubkey_len = read_u32_be(raw_data);

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

    fn veri_with_ecdsa(&self, data: &[u8]) -> Result<Vec<u8>> {
        let sign_msg_bytes = data[..ECDSA_SIGN_MSG_SIZE].to_vec();
        let raw_data = data[ECDSA_SIGN_MSG_SIZE..].to_vec();
        let veri_result = self.ec_peer_pub_key.veri_msg_with_bytes(
            &raw_data, &sign_msg_bytes);
        
        if veri_result == false {
            return_errno!(ECONNREFUSED, "ecdsa verification failed!");
        }

        Ok(raw_data)
    }
}

pub struct ServerHsRmAt {
    cypher: Option<ServerCypher>,
    dh_pub_key: Option<BigUint>,
    // rsa_private_key: Rsa<Private>,
    // rsa_peer_pub_key: Rsa<Private>,
    ec_priv_key: EcdsaHandle,
}

impl ServerHsRmAt {
    pub fn new() -> Self {
        Self {
            cypher: None,
            dh_pub_key: None,
            // rsa_private_key: ca_manager::get_peer_rsa(),
            // rsa_peer_pub_key: ca_manager::get_my_rsa(),
            ec_priv_key: ca_manager::get_ec_fromfile("/host/myEC_key"),
        }
    }

    fn parse_clienthello(&mut self, data: &[u8]) {
        // let decrypted_data = self.veri_with_rsa(data);
        let decrypted_data = self.veri_with_ecdsa(data).unwrap();
    
        let raw_data = &mut (&decrypted_data as &[u8]);
    
        let p_len = read_u32_be(raw_data);

        // println!("p_len: {}", p_len);
    
        let (p_bytes, rest) = raw_data.split_at(p_len as usize);
        *raw_data = rest;
        let p = BigUint::from_bytes_be(p_bytes);
    
        let g_len = read_u32_be(raw_data);

        // println!("g_len: {}", g_len);
    
        let (g_bytes, rest) = raw_data.split_at(g_len as usize);
        *raw_data = rest;
        let g = BigUint::from_bytes_be(g_bytes);
    
        let pubkey_len = read_u32_be(raw_data);

        // println!("pubkey_len: {}", pubkey_len);
    
        let (pubkey_bytes, rest) = raw_data.split_at(pubkey_len as usize);
        *raw_data = rest;
        self.dh_pub_key = Some(BigUint::from_bytes_be(pubkey_bytes));
    
        let dh_pub_para = Arc::new((p, g));
        self.cypher = Some(ServerCypher::new(dh_pub_para));

    }

    pub fn recv_clienthello_and_parse(&mut self, conn: &HostSocket) -> Result<()> {
        let rflag = RecvFlags::from_bits(0).unwrap();

        let mut len_buf = [0u8; USIZE_LENGH];
        // let mut retry = 0;
        // while let Err(err) = conn.recvfrom(&mut len_buf, /*rflag*/ RecvFlags::MSG_DONTWAIT) {
        //     if err.errno() != EAGAIN || retry >= MAX_RETRY {
        //         // println!("recv severhello err: {:?}", err);
        //         return Err(err);
        //     }
        //     retry += 1;
        //     // msg_len = usize::from_be_bytes(len_buf);
        //     // if msg_len != 0 {break;}
        //     std::thread::park_timeout(std::time::Duration::from_millis(1));
        // }
        if let Err(err) = conn.recvfrom(&mut len_buf, rflag){
            return Err(err);
        }

        let msg_len = usize::from_be_bytes(len_buf);
        if msg_len == 0 || msg_len >= 512 {
            return Err(errno!(EINVAL, "not clienthello msg"));
        }
        println!("clienthello len: {}", msg_len);
        let mut data = vec![0u8; msg_len];
        if let Err(err) = conn.recvfrom(&mut data, rflag){
            return Err(err);
        }

        self.parse_clienthello(&data);

        Ok(())
    }

    pub fn reply_to_client(&self) -> Vec<u8> {
        let ec_hash = ca_manager::get_echash_fromfile("/host/hash_tag");

        let pub_key = match self.cypher.clone() {
            Some(k) => (*k.get_dh_pub_key()).clone(),
            None => panic!("not yet recv client msg"),
        };
        // let server_hello = msg::ServerHelloMessage::new(pub_key, self.rsa_private_key.clone());
        let server_hello = msg::ServerHelloMessage::new_with_echash(pub_key, self.ec_priv_key.clone(), ec_hash);
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

    fn veri_with_ecdsa(&self, data: &[u8]) -> Result<Vec<u8>> {
        let PREFIX_LENGH = USIZE_LENGH+ECDSA_SIGN_MSG_SIZE;

        let ec_hash_tag = usize::from_be_bytes(data[..USIZE_LENGH].try_into().unwrap());
        let ec_peer_pub_key = test_client::request_peer_pubkey(ec_hash_tag);
        let sign_msg_bytes = data[USIZE_LENGH..PREFIX_LENGH].to_vec();
        // println!("[veri]: ident tag: {}\npubkey: {}", ec_hash_tag, ec_peer_pub_key.to_bytes_str());
        let raw_data = data[PREFIX_LENGH..].to_vec();
        // println!("signature: {}\nraw_data: {}", base64::encode(&sign_msg_bytes), base64::encode(&raw_data));
        let veri_result = ec_peer_pub_key.veri_msg_with_bytes(
            &raw_data, &sign_msg_bytes);
        
        if veri_result == false {
            return_errno!(ECONNREFUSED, "ecdsa verification failed!");
        }

        Ok(raw_data)
    }
}