use sgx_ucrypto;

pub struct Aes128CtrCipher {
    key: [u8; 16],
    ctr: [u8; 16],
    ctr_inc: u32,
}

impl Aes128CtrCipher {
    pub fn new(init_bytes: &[u8]) -> Result<Self, String>{
        let init_bytes_len = init_bytes.len();

        if init_bytes_len < 32 {
            let mut err_msg = String::from("init_bytes too short, 32 bytes at least expected, ");
            err_msg += &init_bytes_len.to_string();
            err_msg += " bytes found";
            return Err(err_msg);
        }

        Ok(Self{
            key: init_bytes[0..16].try_into().unwrap(),
            ctr: init_bytes[16..32].try_into().unwrap(),
            ctr_inc: 128,
        })
    }

    pub fn empty_new() -> Self {
        Self{
            key: [0u8; 16],
            ctr: [0u8; 16],
            ctr_inc: 0,
        }
    }
    
    pub fn key_valid(&self) -> bool {
        self.ctr_inc != 0
    }

    pub fn set_key(&mut self, init_bytes: &[u8]) -> Result<(), &'static str> {
        let init_bytes_len = init_bytes.len();

        if init_bytes_len < 32 {
            return Err("init_bytes too short, 32 bytes at least expected");
        }

        for i in 0..16 {
            self.key[i] = init_bytes[i];
            self.ctr[i] = init_bytes[i+16];
        }
        self.ctr_inc = 128;

        Ok(())
    }

    pub fn encrypt(&self, src: &[u8]) -> Vec<u8> {
        let mut ret = vec![0u8; src.len()];
        let mut ctr_copy = self.ctr_copy();
        // println!("encrypt: src_len {}, des_len {}", src.len(), ret.len());
        sgx_ucrypto::rsgx_aes_ctr_encrypt(
            &self.key,
            src,
            &mut ctr_copy,
            self.ctr_inc,
            &mut ret,
        ).unwrap();
        // println!("{:?}", ret);
        ret
    }

    pub fn decrypt(&self, src: &[u8]) -> Vec<u8> {
        let mut ret = vec![0u8; src.len()];
        let mut ctr_copy = self.ctr_copy();
        // println!("{:?}", ctr_copy);
        sgx_ucrypto::rsgx_aes_ctr_decrypt(
            &self.key,
            src,
            &mut ctr_copy,
            self.ctr_inc,
            &mut ret,
        ).unwrap();
        ret
    }

    fn ctr_copy(&self) -> [u8; 16] {
        let mut ret = [0u8; 16];
        for i in 0..16 {
            ret[i] = self.ctr[i];
        }
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
