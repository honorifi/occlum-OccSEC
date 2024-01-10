use super::*;
use ecdsa::{EcdsaHandle, EcdsaPublic};
use aes_comm::Aes128CtrCipher;
use rc4_comm::RC4Cipher;
use sgx_types::{uint8_t, SGX_ECP256_KEY_SIZE, uint32_t,
    SGX_NISTP_ECP256_KEY_SIZE, sgx_ec256_private_t, sgx_ec256_public_t};
use std::sync::{SgxMutex as Mutex, SgxMutexGuard as MutexGuard};
use fs::{FileMode, AccessMode, CreationFlags, StatusFlags};
const USIZE_LENGH: usize = std::mem::size_of::<usize>();
// use openssl::rsa::{Rsa, Padding};
// use openssl::pkey::Private;

// pub fn generate_rsa_group_file(){
//     let mut file1 = File::create("rsa_key0").unwrap();
//     let rsa0 = Rsa::generate(2048).unwrap();
//     file1.write(&rsa0.private_key_to_pem().unwrap());


//     let mut file1 = File::create("rsa_key1").unwrap();
//     let rsa1 = Rsa::generate(2048).unwrap();
//     file1.write(&rsa1.private_key_to_pem().unwrap());
// }

// pub fn get_my_rsa() -> Rsa<Private> {
//     let mut file = File::open("rsa_key0").unwrap();
//     let mut buf = vec![0 as u8; 2048];
//     file.read(&mut buf).unwrap();
//     Rsa::private_key_from_pem(&buf).unwrap()
// }

// pub fn get_peer_rsa() -> Rsa<Private> {
//     let mut file = File::open("rsa_key1").unwrap();
//     let mut buf = vec![0 as u8; 2048];
//     file.read(&mut buf).unwrap();
//     Rsa::private_key_from_pem(&buf).unwrap()
// }

pub struct FileWriter {
    host_fs: Arc<dyn File>,
}

impl FileWriter {
    pub fn create(path: &str) -> Result<Self> {
        let flags =
        AccessMode::O_WRONLY as u32 | (CreationFlags::O_CREAT | CreationFlags::O_TRUNC).bits();// | StatusFlags::O_APPEND.bits();
        let current = current!();
        let host_fs = current.fs().read().unwrap();
        let fd = match host_fs.open_file(path, flags, FileMode::all()) {
            Ok(fd) => fd,
            Err(error) => panic!("open File failed {:?}", error),
        };
        fd.sync_all();

        Ok(Self{
            host_fs: fd,
        })
    }

    pub fn write(&self, data: &[u8]) -> Result<usize> {
        let ret = self.host_fs.write(data);
        self.host_fs.sync_data();
        ret
    }
}

struct FileReader {
    host_fs: Arc<dyn File>,
}

impl FileReader {
    pub fn open(path: &str) -> Result<Self> {
        let flags =
        AccessMode::O_RDONLY as u32;    // | (CreationFlags::O_CREAT | CreationFlags::O_TRUNC).bits();// | StatusFlags::O_APPEND.bits();
        let current = current!();
        let host_fs = current.fs().read().unwrap();
        let fd = match host_fs.open_file(path, flags, FileMode::all()) {
            Ok(fd) => fd,
            Err(error) => return_errno!(error.errno(), "open File failed"),
        };

        Ok(Self{
            host_fs: fd,
        })
    }

    pub fn read(&self, buf: &mut [u8]) -> Result<usize> {
        self.host_fs.read(buf)
    }

    pub fn is_exist(path: &str) -> bool {
        let ret = FileReader::open(path);
        match ret {
            Ok(f) => true,
            Err(err) => {
                // println!("is_exist err: {}", err);
                false
            },
        }
    }
}

pub fn generate_ec_key_pair() -> (Vec<u8>, Vec<u8>) {
    let ec = ecdsa::EcdsaHandle::new();
    let priv_key = ec.to_be_bytes();
    let pub_key = ec.to_pub_handle().to_be_bytes();
    (priv_key, pub_key)
}

pub fn generate_ec_file(filename: &str) {
    let file_exist = FileReader::is_exist(filename);
    if file_exist {return;}

    let ec = ecdsa::EcdsaHandle::new();
    let priv_key = ec.to_be_bytes();

    let mut file = FileWriter::create(filename).unwrap();
    file.write(&priv_key);
}

pub fn get_echash_fromfile(filename: &str) -> usize {
    let file_exist = FileReader::is_exist(filename);
    if !file_exist {
        // test_client::generate_and_regist_pubkey();
        return 0;
    }

    let mut file = FileReader::open(filename).unwrap();
    let mut buf = [0 as uint8_t; USIZE_LENGH];
    file.read(&mut buf).unwrap();

    usize::from_be_bytes(buf)
}

pub fn get_ec_fromfile(filename: &str) -> EcdsaHandle {
    let file_exist = FileReader::is_exist(filename);
    if !file_exist {panic!("get_ec_file: no such file exist");}

    let mut file = FileReader::open(filename).unwrap();
    let mut buf = [0 as uint8_t; SGX_ECP256_KEY_SIZE * 3];
    file.read(&mut buf).unwrap();

    EcdsaHandle::from_be_bytes(&buf)
}

pub fn get_shared_aes_fromfile(filename: &str) -> Option<Aes128CtrCipher> {
    let file_exist = FileReader::is_exist(filename);
    if !file_exist {
        // test_client::generate_and_regist_pubkey();
        return None;
    }

    let mut file = FileReader::open(filename).unwrap();
    let mut buf = vec![0u8; 512];
    file.read(&mut buf).unwrap();

    Some(Aes128CtrCipher::new(&buf).unwrap())
}

pub fn get_shared_rc4_fromfile(filename: &str) -> Option<RC4Cipher> {
    let file_exist = FileReader::is_exist(filename);
    if !file_exist {
        // test_client::generate_and_regist_pubkey();
        return None;
    }

    let mut file = FileReader::open(filename).unwrap();
    let mut buf = vec![0u8; 512];
    file.read(&mut buf).unwrap();

    Some(RC4Cipher::new(&buf))
}

pub fn generate_ec_group_file() {
    let file1 = FileWriter::create("/host/ec_key0").unwrap();
    let ec0 = ecdsa::EcdsaHandle::new();
    file1.write(ec0.to_bytes_str().as_bytes()).unwrap();

    let file1 = FileWriter::create("/host/ec_pub_key0").unwrap();
    let ec_pub0 = ec0.to_pub_handle();
    file1.write(ec_pub0.to_bytes_str().as_bytes()).unwrap();


    let file2 = FileWriter::create("/host/ec_key1").unwrap();
    let ec1 = ecdsa::EcdsaHandle::new();
    file2.write(ec1.to_bytes_str().as_bytes()).unwrap();

    let file2 = FileWriter::create("/host/ec_pub_key1").unwrap();
    let ec_pub1 = ec1.to_pub_handle();
    file2.write(ec_pub1.to_bytes_str().as_bytes()).unwrap();
}

pub fn get_ec(id: u32) -> EcdsaHandle {
    let path = match id {
        0 => "/host/ec_key0",
        _ => "/host/ec_key1",
    };
    let file = FileReader::open(path).unwrap();
    let mut buf = [0 as uint8_t; SGX_ECP256_KEY_SIZE * 4];
    let msg_len = file.read(&mut buf).unwrap();
    let buf_cont = String::from_utf8(buf[..msg_len].to_vec()).unwrap().replace("\n", "");
    let ret = EcdsaHandle::from_bytes_str(buf_cont);

    // println!("get_ec_{}_to_pub: {:?}", id, ret.to_pub_handle().to_be_bytes());

    ret
}

pub fn get_ec_pub(id: u32) -> EcdsaPublic {
    let path = match id {
        0 => "/host/ec_pub_key0",
        _ => "/host/ec_pub_key1",
    };
    let file = FileReader::open(path).unwrap();
    let mut buf = [0 as uint8_t; SGX_ECP256_KEY_SIZE * 3];
    let msg_len = file.read(&mut buf).unwrap();
    let buf_cont = String::from_utf8(buf[..msg_len].to_vec()).unwrap().replace("\n", "");

    // println!("get_ec_pub_{}: {:?}", id, buf);

    EcdsaPublic::from_bytes_str(buf_cont)
}


// pub fn rsa_sign_veri_test() {
//     let rsa0 = get_my_rsa();
//     println!("got rsa key");

//     let mut msg = b"hello world".to_vec();
//     println!("msg: {}", std::str::from_utf8(&msg).unwrap());

//     let mut packed_msg = msg.len().to_be_bytes().to_vec();
//     packed_msg.append(&mut msg);

//     let mut signed_msg = vec![0 as u8; rsa0.size() as usize];
//     let mut verifi_msg = vec![0 as u8; rsa0.size() as usize];

//     rsa0.private_encrypt(&packed_msg, &mut signed_msg, Padding::PKCS1).unwrap();
//     //println!("signed_msg: {}", std::str::from_utf8(&signed_msg).unwrap());

//     rsa0.public_decrypt(&signed_msg, &mut verifi_msg, Padding::PKCS1).unwrap();
    
//     let (msg_len_bytes, rest) = verifi_msg.split_at(8);

//     let msg_len = usize::from_be_bytes(msg_len_bytes.try_into().unwrap());

//     println!("msg_len: {}", msg_len);
    
//     println!("verifi_msg: {}", std::str::from_utf8(&rest).unwrap());

// }

pub fn test_ecdsa_sign_veri() {
    // generate_ec_group_file();

    let msg = b"this is a ecdsa sign test";

    // let handle = sgx_ucrypto::SgxEccHandle::new();
    // handle.open();

    // let (priv_key, pub_key) = handle.create_key_pair().unwrap();

    // let sign_msg = handle.ecdsa_sign_msg(msg, &priv_key).unwrap();

    // let veri_result = handle.ecdsa_verify_msg(msg, &pub_key, &sign_msg).unwrap();

    // println!("veri_result: {}", veri_result);

    let handle = get_ec(1);

    let pub_handle = get_ec_pub(1);

    let sign_msg = handle.sign_msg_with_bytes(msg);

    let veri_result = pub_handle.veri_msg_with_bytes(msg, &sign_msg);

    println!("veri_result: {}", veri_result);
}