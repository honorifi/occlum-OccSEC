use super::*;
use cypher::ClientCypher;
use msg::{ClientHelloMessage, read_u32_be};
use comm::ca_manager;
use num_bigint::BigUint;
use comm::ecdsa::{EcdsaHandle, EcdsaPublic, ECDSA_SIGN_MSG_SIZE};
use std::sync::Arc;
use comm::aes_comm::Aes128CtrCipher;
use sgx_tstd::net::TcpStream;
use sgx_tstd::io::{Write, Read};
const USIZE_LENGH: usize = std::mem::size_of::<usize>();

// please modify these two variable simutaneously for accurate err msg display
const MAX_RETRY: usize = 1000;
const HANDSHAKE_FAIL_ERR: &str = "handshake failed after 1000 times retry";
// please modify these two variable simutaneously

pub struct ClientHs {
    cypher: ClientCypher,
    dh_pub_key: Option<BigUint>,
    // rsa_private_key: Rsa<Private>,
    // rsa_peer_pub_key: Rsa<Private>,
    ec_priv_key: EcdsaHandle,
    ec_peer_pub_key: EcdsaPublic,
}

impl ClientHs {
    pub fn new() -> Self {
        Self {
            cypher: ClientCypher::new(),
            dh_pub_key: None,
            // rsa_private_key: ca_manager::get_my_rsa(),
            // rsa_peer_pub_key: ca_manager::get_peer_rsa(),
            ec_priv_key: ca_manager::get_ec(0),
            ec_peer_pub_key: ca_manager::get_ec_pub(1),
        }
    }

    pub fn start_handshake(&self) -> Vec<u8> {
        let client_cypher = &self.cypher;
        let dh_pub_para = client_cypher.get_dh_pub_para();
        let p = dh_pub_para.0.clone();
        let g = dh_pub_para.1.clone();
        let dh_pub_key = (*client_cypher.get_dh_pub_key()).clone();
    
        //let auth_key = self.rsa_private_key.clone();
        let auth_key = self.ec_priv_key.clone();
    
        let client_hello = ClientHelloMessage::new(
            p,
            g,
            dh_pub_key,
            auth_key,
        );
    
        client_hello.pack_msg_and_sign()
    }
    
    pub fn recv_serverhello_and_decrypt(&mut self, data: &[u8]) {
        // let decrypted_data = self.veri_with_rsa(data);
        let decrypted_data = self.veri_with_ecdsa(data).unwrap();
    
        let raw_data = &mut (&decrypted_data as &[u8]);
    
        let pubkey_len = read_u32_be(raw_data);

        //println!("pubkey_len: {}", pubkey_len);
    
        let (pubkey_bytes, rest) = raw_data.split_at(pubkey_len);
        *raw_data = rest;
        let pubkey = BigUint::from_bytes_be(pubkey_bytes);
        //println!("server_pubkey: {}", pubkey);

        self.dh_pub_key = Some(pubkey.clone());
        self.cypher.calc_symmetric_key(Arc::new(pubkey));
    }

    pub fn get_nego_key(&mut self) -> BigUint {
        let pub_key = match self.dh_pub_key.clone() {
            Some(k) => k,
            None => panic!("not yet recv client msg"),
        };

        let cypher = &mut self.cypher;

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


pub fn CertMG_tls_handshake(mut conn: &TcpStream) -> Aes128CtrCipher {
    let mut client_hs = client::hs::ClientHs::new();

    let client_hello = client_hs.start_handshake();
    let msg_len = conn.write(&client_hello).unwrap();
    // println!("send {} bytes", msg_len);

    let mut server_hello = [0u8; 512];
    let msg_len = conn.read(&mut server_hello).unwrap();

    if msg_len != 0 {
        let server_hello = &server_hello[0..msg_len];
        // println!("recv msg_len: {}", msg_len);
        client_hs.recv_serverhello_and_decrypt(server_hello);
    
        let client_nego_key = client_hs.get_nego_key();
        
        // println!("nego_key: {}", client_nego_key);

        Aes128CtrCipher::new(&client_nego_key.to_bytes_be()).unwrap()
    }
    else{
        Aes128CtrCipher::empty_new()
    }
}

pub struct ClientHsRmAt {
    cypher: ClientCypher,
    dh_pub_key: Option<BigUint>,
    // rsa_private_key: Rsa<Private>,
    // rsa_peer_pub_key: Rsa<Private>,
    ec_priv_key: EcdsaHandle,
}

impl ClientHsRmAt {
    pub fn new() -> Self {
        Self {
            cypher: ClientCypher::new(),
            dh_pub_key: None,
            // rsa_private_key: ca_manager::get_my_rsa(),
            // rsa_peer_pub_key: ca_manager::get_peer_rsa(),
            ec_priv_key: ca_manager::get_ec_fromfile("/host/myEC_key"),
        }
    }

    pub fn start_handshake(&self) -> Vec<u8> {
        let ec_hash = ca_manager::get_echash_fromfile("/host/hash_tag");

        let client_cypher = &self.cypher;
        let dh_pub_para = client_cypher.get_dh_pub_para();
        let p = dh_pub_para.0.clone();
        let g = dh_pub_para.1.clone();
        let dh_pub_key = (*client_cypher.get_dh_pub_key()).clone();
    
        //let auth_key = self.rsa_private_key.clone();
        let auth_key = self.ec_priv_key.clone();
    
        let client_hello = ClientHelloMessage::new_with_echash(
            p,
            g,
            dh_pub_key,
            auth_key,
            ec_hash,
        );
    
        client_hello.pack_msg_and_sign()
    }
    
    fn parse_serverhello(&mut self, data: &[u8]) {
        // let decrypted_data = self.veri_with_rsa(data);
        let decrypted_data = self.veri_with_ecdsa(data).unwrap();
    
        let raw_data = &mut (&decrypted_data as &[u8]);
    
        let pubkey_len = read_u32_be(raw_data);

        //println!("pubkey_len: {}", pubkey_len);
    
        let (pubkey_bytes, rest) = raw_data.split_at(pubkey_len);
        *raw_data = rest;
        let pubkey = BigUint::from_bytes_be(pubkey_bytes);
        //println!("server_pubkey: {}", pubkey);

        self.dh_pub_key = Some(pubkey.clone());
        self.cypher.calc_symmetric_key(Arc::new(pubkey));
    }

    pub fn recv_serverhello_and_parse(&mut self, conn: &HostSocket) -> Result<()> {
        let rflag = RecvFlags::from_bits(0).unwrap();

        let mut len_buf = [0u8; USIZE_LENGH];
        let mut retry = 0;
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

        if let Err(err) = conn.recvfrom(&mut len_buf, rflag) {
            return Err(err);
        }

        let msg_len = usize::from_be_bytes(len_buf);
        if msg_len == 0 || msg_len >= 512 {
            return Err(errno!(EINVAL, "not serverhello msg"));
        }
        println!("serverhello len: {}", msg_len);
        let mut data = vec![0u8; msg_len];
        if let Err(err) = conn.recvfrom(&mut data, rflag) {
            return Err(err);
        }

        self.parse_serverhello(&data);

        Ok(())
    }

    pub fn get_nego_key(&mut self) -> BigUint {
        let pub_key = match self.dh_pub_key.clone() {
            Some(k) => k,
            None => panic!("not yet recv client msg"),
        };

        let cypher = &mut self.cypher;

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