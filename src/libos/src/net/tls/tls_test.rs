use super::*;
use client::cypher::ClientCypher;
use comm::ca_manager;
use comm::aes_comm;
use server::cypher::ServerCypher;
// use openssl::symm;

pub fn test_dh_handshake() {
    let mut alice = ClientCypher::new();
    let dh_pub_para = alice.get_dh_pub_para();
    let mut bob = ServerCypher::new(dh_pub_para);

    let a_key = alice.get_dh_pub_key();
    let b_key = bob.get_dh_pub_key();

    println!("pub_key_A: {}", a_key);
    println!("pub_key_B: {}", b_key);

    alice.calc_symmetric_key(b_key);
    bob.calc_symmetric_key(a_key);

    let sym_key_a = alice.get_dh_symmetric_key().unwrap();
    let sym_key_b = bob.get_dh_symmetric_key().unwrap();

    println!("sym_key_A: {}", sym_key_a);
    println!("sym_key_B: {}", sym_key_b);
    assert_eq!(sym_key_a, sym_key_b);
}

pub fn test_dh_rsa_handshake() {
    // ca_manager::generate_rsa_group_file();

    let mut client_hs = client::hs::ClientHs::new();
    let mut server_hs = server::hs::ServerHs::new();

    let client_hello = client_hs.start_handshake();
    server_hs.recv_clienthello_and_decrypt(&client_hello);

    let server_hello = server_hs.reply_to_client();
    client_hs.recv_serverhello_and_decrypt(&server_hello);

    let client_nego_key = client_hs.get_nego_key();
    let server_nego_key = server_hs.get_nego_key();

    println!("client_nego_key:\n{}", client_nego_key);
    println!("server_nego_key:\n{}", server_nego_key);
}

// pub fn test_symm_encrypt(){
//     let raw_data = b"hello, this is a aes256 encrypted communication test";

//     let cipher = symm::Cipher::aes_128_cbc();
//     let key = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F";
//     let iv = b"\x00\x01\x02\x03\x04\x05\x06\x07\x00\x01\x02\x03\x04\x05\x06\x07";
    
//     let enc_cipher = symm::Cipher::aes_128_cbc();
//     let enc_text = symm::encrypt(
//         enc_cipher,
//         key,
//         Some(iv),
//         raw_data
//     ).unwrap();
    
//     let ciphertext = symm::decrypt(
//         cipher,
//         key,
//         Some(iv),
//         &enc_text
//     ).unwrap();

//     assert_eq!(
//         raw_data,
//         &ciphertext[..]);
// }

pub fn test_handshake_and_aes256_comm() {
    let mut client_hs = client::hs::ClientHs::new();
    let mut server_hs = server::hs::ServerHs::new();

    let client_hello = client_hs.start_handshake();
    server_hs.recv_clienthello_and_decrypt(&client_hello);

    let server_hello = server_hs.reply_to_client();
    client_hs.recv_serverhello_and_decrypt(&server_hello);

    let client_nego_key = client_hs.get_nego_key().to_bytes_be();
    let server_nego_key = server_hs.get_nego_key().to_bytes_be();

    let msg = b"hello, this is a aes256 encrypted communication test";

    // let enc_key = &client_nego_key[0..32];
    // let enc_iv = &client_nego_key[32..48];
    // let enc_cipher = symm::Cipher::aes_256_ctr();
    // let ciphertext = symm::encrypt(
    //     enc_cipher,
    //     enc_key,
    //     Some(enc_iv),
    //     msg
    // ).unwrap();
    
    // let dec_key = &server_nego_key[0..32];
    // let dec_iv = &server_nego_key[32..48];
    // let dec_cipher = symm::Cipher::aes_256_ctr();
    // let dec_text = symm::decrypt(
    //     dec_cipher,
    //     dec_key,
    //     Some(dec_iv),
    //     &ciphertext
    // ).unwrap();

    let enc_cipher = aes_comm::Aes128CtrCipher::new(&client_nego_key).unwrap();
    let enc_text = enc_cipher.encrypt(msg);

    let dec_cipher = aes_comm::Aes128CtrCipher::new(&server_nego_key).unwrap();
    let dec_text = dec_cipher.decrypt(&enc_text);

    println!("{}", std::str::from_utf8(&dec_text).unwrap());
}
