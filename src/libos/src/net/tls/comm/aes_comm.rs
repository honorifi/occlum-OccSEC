use super::*;
use sgx_tcrypto;
pub const LENGH_WIDTH: usize = std::mem::size_of::<usize>();
pub const MAX_MSG_LEN: usize = 65472;


#[derive(Debug)]
pub struct Aes128CtrCipher {
    key: [u8; 16],
    ctr: [u8; 16],
    ctr_inc: u32,
}

impl Aes128CtrCipher {
    pub fn new(init_bytes: &[u8]) -> Result<Self>{
        let init_bytes_len = init_bytes.len();

        if init_bytes_len < 32 {
            return_errno!(EINVAL, "init_bytes too short, 32 bytes at least expected");
        }

        Ok(Self{
            key: init_bytes[0..16].try_into().unwrap(),
            ctr: init_bytes[16..32].try_into().unwrap(),
            ctr_inc: 128,
        })
    }

    // warning! this method will not create aes_128 key, thus not avilable for 
    // en/decrypt, if you want to en/decrypt function, call set_key first instead.
    pub fn empty_new() -> Self {
        Self{
            key: [0u8; 16],
            ctr: [0u8; 16],
            ctr_inc: 0,
        }
    }

    pub fn set_key(&mut self, init_bytes: &[u8]) -> Result<()> {
        let init_bytes_len = init_bytes.len();

        if init_bytes_len < 32 {
            return_errno!(EINVAL, "init_bytes too short, 32 bytes at least expected");
        }

        for i in 0..16 {
            self.key[i] = init_bytes[i];
            self.ctr[i] = init_bytes[i+16];
        }
        self.ctr_inc = 128;

        Ok(())
    }

    pub fn show_key(&self) {
        for i in 0..16 {
            print!("{}", self.key[i]);
        }
        println!(" -- aes key");
    }

    pub fn key_valid(&self) -> bool {
        self.ctr_inc != 0
    }

    pub fn encrypt(&self, src: &[u8]) -> Vec<u8> {
        let mut ret = vec![0u8; src.len()];
        let mut ctr_copy = self.ctr_copy();
        // println!("{:?}", ctr_copy);
        sgx_tcrypto::rsgx_aes_ctr_encrypt(
            &self.key,
            src,
            &mut ctr_copy,
            self.ctr_inc,
            &mut ret,
        ).unwrap();
        // println!("{:?}", ret);
        ret
    }

    // pub fn encrypt_mark_len(&self, src: &[u8]) -> Vec<u8> {
    //     let src_len = src.len();
    //     let mut ret = src_len.to_be_bytes().to_vec();
    //     let mut enc_msg = vec![0u8; src_len];
    //     let mut ctr_copy = self.ctr_copy();
    //     sgx_tcrypto::rsgx_aes_ctr_encrypt(
    //         &self.key,
    //         src,
    //         &mut ctr_copy,
    //         self.ctr_inc,
    //         &mut enc_msg,
    //     ).unwrap();
    //     ret.append(&mut enc_msg);
    //     ret
    // }

    // split: max msg len = 4KB
    pub fn encrypt_mark_len(&self, src: &[u8]) -> Vec<u8> {
        let mut ret = Vec::new();

        let src_len = src.len();
        let mut pack_len = 0;
        while pack_len + MAX_MSG_LEN < src_len {
            let mut tmp_len = MAX_MSG_LEN.to_be_bytes().to_vec();
            let mut enc_msg = vec![0u8; MAX_MSG_LEN];
            let mut ctr_copy = self.ctr_copy();
            sgx_tcrypto::rsgx_aes_ctr_encrypt(
                &self.key,
                &src[pack_len..(pack_len+MAX_MSG_LEN)],
                &mut ctr_copy,
                self.ctr_inc,
                &mut enc_msg,
            ).unwrap();
            ret.append(&mut tmp_len);
            ret.append(&mut enc_msg);
            pack_len += MAX_MSG_LEN;
        }
        let mut tmp_len = (src_len - pack_len).to_be_bytes().to_vec();
        let mut enc_msg = vec![0u8; src_len - pack_len];
        let mut ctr_copy = self.ctr_copy();
        sgx_tcrypto::rsgx_aes_ctr_encrypt(
            &self.key,
            &src[pack_len..src_len],
            &mut ctr_copy,
            self.ctr_inc,
            &mut enc_msg,
        ).unwrap();
        ret.append(&mut tmp_len);
        ret.append(&mut enc_msg);
        ret
    }

    // the first is the len_buf, second is the enc_msg
    pub fn encrypt_with_len(&self, src: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let len = src.len();
        // println!("origin len: {}", len);
        let mut enc_msg = vec![0u8; len];
        let mut ctr_copy = self.ctr_copy();
        // println!("{:?}", ctr_copy);
        sgx_tcrypto::rsgx_aes_ctr_encrypt(
            &self.key,
            src,
            &mut ctr_copy,
            self.ctr_inc,
            &mut enc_msg,
        ).unwrap();
        (len.to_be_bytes().to_vec(), enc_msg)
    }

    pub fn decrypt(&self, src: &[u8]) -> Vec<u8> {
        let mut ret = vec![0u8; src.len()];
        let mut ctr_copy = self.ctr_copy();
        // println!("{:?}", ctr_copy);
        sgx_tcrypto::rsgx_aes_ctr_decrypt(
            &self.key,
            src,
            &mut ctr_copy,
            self.ctr_inc,
            &mut ret,
        ).unwrap();
        ret
    }

    // please make sure des.len() equals to src.len(), else may encounter unexpected error
    pub fn decrypt_to(&self, des: &mut [u8], src: &[u8]) {
        let mut ctr_copy = self.ctr_copy();
        let src_len = src.len();
        sgx_tcrypto::rsgx_aes_ctr_decrypt(
            &self.key,
            src,
            &mut ctr_copy,
            self.ctr_inc,
            des,
        ).unwrap();
    }

    fn ctr_copy(&self) -> [u8; 16] {
        let mut ret = [0u8; 16];
        for i in 0..16 {
            ret[i] = self.ctr[i];
        }
        ret
    }

    pub fn clone(&self) -> Self {
        let key = self.key;
        let ctr = self.ctr;
        let ctr_inc = self.ctr_inc;
        Self{
            key,
            ctr,
            ctr_inc,
        }
    }

    pub fn to_be_bytes(&self) -> Vec<u8> {
        let mut ret = Vec::from(self.key.clone());
        let mut ctr = Vec::from(self.ctr.clone());
        ret.append(&mut ctr);
        ret
    }
}

pub fn test_aes_comm(){
    let init_str = b"1937410592709672487620397232847923534235";

    let aes_cipher = Aes128CtrCipher::new(init_str).unwrap();

    let plaintext = b"Hello world!";
    
    let enc_msg = aes_cipher.encrypt(plaintext);

    let dec_msg = aes_cipher.decrypt(&enc_msg);

    println!("dec: {}", std::str::from_utf8(&dec_msg).unwrap());
}
