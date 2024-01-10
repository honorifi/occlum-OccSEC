use super::*;
use std::net::TcpStream;
use client::hs::client_tls_handshake;
use conn::msg_handle::PackHandle;
use std::fs::File;
use std::io::{Write, Read};
use comm::aes_comm::Aes128CtrCipher;
use std::time::{Duration, Instant};

const LENGH_WIDTH: usize = std::mem::size_of::<usize>();

pub fn msg_sender(repeat: usize) {
    let mut conn = TcpStream::connect("127.0.0.1:10011").unwrap();
    let packhandle = PackHandle::new(&conn);

    for i in 0..repeat {
        let mut send_buf = String::new();
        let len = std::io::stdin().read_line(&mut send_buf).unwrap();

        packhandle.send_msg(send_buf.as_bytes(), len);
    }
    let send_buf = "close".as_bytes();
    packhandle.send_msg(&send_buf, send_buf.len());
}

// fn send_msg(mut conn: &TcpStream, msg: &[u8], len: usize) {
//     let mut msg_send = Vec::from(len.to_be_bytes());
//     msg_send.append(&mut Vec::from(msg));
//     // println!("{:?}", msg_send);
//     conn.write(&msg_send).unwrap();
// }

pub fn safe_msg_sender(repeat: usize) {
    let mut conn = TcpStream::connect("127.0.0.1:10011").unwrap();
    let packhandle = PackHandle::new(&conn);
    let aes_cipher = client_tls_handshake(&conn);

    for i in 0..repeat {
        let mut input_buf = String::new();
        let length = std::io::stdin().read_line(&mut input_buf).unwrap();
        let send_buf = aes_cipher.encrypt(input_buf.as_bytes());

        packhandle.send_msg(&send_buf, send_buf.len());
    }

    let send_buf = aes_cipher.encrypt("close".as_bytes());
    packhandle.send_msg(&send_buf, send_buf.len());
}

pub fn safe_msg_static_sender(repeat: usize) {
    let mut conn = TcpStream::connect("127.0.0.1:10011").unwrap();
    let packhandle = PackHandle::new(&conn);
    let aes_cipher = client_tls_handshake(&conn);

    for i in 0..repeat {
        let msg = i.to_string();
        // println!("send: {}", msg);
        let send_buf = aes_cipher.encrypt(msg.as_bytes());
        packhandle.send_msg(&send_buf, send_buf.len());
    }
    
    let send_buf = aes_cipher.encrypt("close".as_bytes());
    packhandle.send_msg(&send_buf, send_buf.len());
}

pub fn safe_regist() {
    let mut conn = TcpStream::connect("127.0.0.1:10011").unwrap();
    let mut packhandle = PackHandle::new(&conn);
    let aes_cipher = client::hs::client_tls_handshake(&conn);

    let (priv_key, pub_key) = comm::ca_manager::generate_ec_key_pair();

    let req_type = aes_cipher.encrypt("regist".as_bytes());
    let pub_key_enc = aes_cipher.encrypt(&pub_key);
    packhandle.send_msg(&req_type, req_type.len());
    packhandle.send_msg(&pub_key_enc, pub_key_enc.len());

    let hash_key_enc = packhandle.recv_msg().unwrap();
    let hash_key_dec = aes_cipher.decrypt(&hash_key_enc);
    let hash_key = usize::from_be_bytes(hash_key_dec[..LENGH_WIDTH].try_into().unwrap());
    
    let close_req = aes_cipher.encrypt("close".as_bytes());
    packhandle.send_msg(&close_req, close_req.len());

    println!("hash_key: {}", hash_key);
}

pub fn safe_unregist(hash_key: usize) {
    let mut conn = TcpStream::connect("127.0.0.1:10011").unwrap();
    let mut packhandle = PackHandle::new(&conn);
    let aes_cipher = client::hs::client_tls_handshake(&conn);

    let req_type = aes_cipher.encrypt("unregist".as_bytes());
    let hash_key_enc = aes_cipher.encrypt(&hash_key.to_be_bytes());
    packhandle.send_msg(&req_type, req_type.len());
    packhandle.send_msg(&hash_key_enc, hash_key_enc.len());

    let close_req = aes_cipher.encrypt("close".as_bytes());
    packhandle.send_msg(&close_req, close_req.len());
}

pub fn generate_and_regist_pubkey(kssp_mode: usize) {
    // println!("generate and regist my ECkey");
    let hash_tag = request_shared_aes_and_store(kssp_mode == 2);

    // if kssp is off, then do not continue to regist
    // without hash_tag registed, the socket disable handshake and aes-encryption
    // previous operation ensure the hash_tag left by previous occlum run will reflush
    if kssp_mode == 0 {
        return;
    }

    let mut conn = match TcpStream::connect("127.0.0.1:10011") {
        Ok(ret) => ret,
        Err(err) => {
            println!("\x1b[33m[Warning:] CertMG unreachable, KSSP unavailable the msg will be transmitted in plaintext!\x1b[0m");
            return ;
        }
    };

    let begin_time =Instant::now();

    let mut packhandle = PackHandle::new(&conn);
    let aes_cipher = client::hs::client_tls_handshake(&conn);

    comm::ca_manager::generate_ec_file("/host/myEC_key");
    let ec_handle = comm::ca_manager::get_ec_fromfile("/host/myEC_key");
    let pub_key = ec_handle.to_pub_handle().to_be_bytes();

    if hash_tag != 0 {
        let req_type = aes_cipher.encrypt("unregist".as_bytes());
        let hash_tag_enc = aes_cipher.encrypt(&hash_tag.to_be_bytes());
        packhandle.send_msg(&req_type, req_type.len());
        packhandle.send_msg(&hash_tag_enc, hash_tag_enc.len());
    }

    let req_type = aes_cipher.encrypt("regist".as_bytes());
    let pub_key_enc = aes_cipher.encrypt(&pub_key);
    packhandle.send_msg(&req_type, req_type.len());
    packhandle.send_msg(&pub_key_enc, pub_key_enc.len());

    let hash_tag_enc = packhandle.recv_msg().unwrap();
    let hash_tag_dec = aes_cipher.decrypt(&hash_tag_enc);
    let hash_tag = usize::from_be_bytes(hash_tag_dec[..LENGH_WIDTH].try_into().unwrap());
    
    let close_req = aes_cipher.encrypt("close".as_bytes());
    packhandle.send_msg(&close_req, close_req.len());

    println!("Identity Proof: {} ms", begin_time.elapsed().as_millis());

    let kssp_mode_str = match kssp_mode {
        0 => "off",
        1 => "on",
        2 => "shared_aes",
        _ => "off",
    };
    println!("\x1b[32mkssp_mode {}, my hash_tag: {}\x1b[0m", kssp_mode_str, hash_tag);

    let mut hash_tag_file = std::fs::File::create("/host/hash_tag").unwrap();
    hash_tag_file.write(&hash_tag.to_be_bytes());
}

pub fn request_shared_aes_and_store(shared_aes_mode: bool) -> usize {
    // delete history
    if std::fs::metadata("/host/shared_aes").is_ok() {
        std::fs::remove_file("/host/shared_aes").unwrap();
    }

    // delete and unregist previous hash_tag
    let pre_hash_tag = match std::fs::metadata("/host/hash_tag").is_ok() {
        true => {
            let mut file = File::open("/host/hash_tag").unwrap();
            let mut buf = [0 as u8; LENGH_WIDTH];
            file.read(&mut buf).unwrap();
            std::fs::remove_file("/host/hash_tag").unwrap();
            
            usize::from_be_bytes(buf)
        }, 
        false => 0,
    };

    if shared_aes_mode == false {
        return pre_hash_tag;
    }

    // connect to CertMG
    let mut conn = match TcpStream::connect("127.0.0.1:10011") {
        Ok(ret) => ret,
        Err(err) => {
            println!("\x1b[33m[Warning:] CertMG unreachable, Shared_Aes unavailable the msg will be transmitted in plaintext!\x1b[0m");
            return pre_hash_tag;
        }
    };
    let mut packhandle = PackHandle::new(&conn);
    let aes_cipher = client::hs::client_tls_handshake(&conn);

    // request the shared_aes
    let req_type = aes_cipher.encrypt("req_shared_aes".as_bytes());
    packhandle.send_msg(&req_type, req_type.len());

    let shared_aes_enc = packhandle.recv_msg().unwrap();
    let shared_aes_dec = aes_cipher.decrypt(&shared_aes_enc);
    let close_req = aes_cipher.encrypt("close".as_bytes());
    packhandle.send_msg(&close_req, close_req.len());

    // get the shared_aes and store
    // println!("\x1b[32mshared_aes_mode on\x1b[0m");
    let mut shared_aes_file = std::fs::File::create("/host/shared_aes").unwrap();
    shared_aes_file.write(&shared_aes_dec);

    pre_hash_tag
}