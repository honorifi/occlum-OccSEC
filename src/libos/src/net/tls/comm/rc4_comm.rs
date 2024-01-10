use super::*;
use std::sync::{SgxMutex as Mutex};

#[derive(Debug)]
struct RC4inner {
    seed: [u8; 256],
    ptr_i: usize,
    ptr_j: usize,
}

impl RC4inner {
    pub fn new(init_bytes: &[u8]) -> Self{
        let init_bytes_len = init_bytes.len();

        let mut seed = [0u8; 256];
        let mut tmp = [0u8; 256];
        for i in 0..256 {
            seed[i] = i as u8;
            tmp[i] = init_bytes[i%init_bytes_len];
        }

        let mut j: usize = 0;
        for i in 0..256 {
            j = (j+seed[i] as usize+tmp[i] as usize) % 256;
            let mid = seed[i];
            seed[i] = seed[j];
            seed[j] = mid;
        }
        
        Self{
            seed,
            ptr_i: 0,
            ptr_j: 0,
        }
    }

    pub fn empty_new() -> Self {
        Self{
            seed: [0u8; 256],
            ptr_i: 0,
            ptr_j: 0,
        }
    }

    pub fn set_key(&mut self, init_bytes: &[u8]) {
        let init_bytes_len = init_bytes.len();

        let mut seed = [0u8; 256];
        let mut tmp = [0u8; 256];
        for i in 0..256 {
            seed[i] = i as u8;
            tmp[i] = init_bytes[i%init_bytes_len];
        }

        let mut j: usize = 0;
        for i in 0..256 {
            j = (j+seed[i] as usize+tmp[i] as usize) % 256;
            let mid = seed[i];
            seed[i] = seed[j];
            seed[j] = mid;
        }

        self.seed = seed;
        self.ptr_i = 0;
        self.ptr_j = 0;
    }

    pub fn encrypt(&mut self, buf: &[u8]) -> Vec<u8> {
        let mut i: usize = self.ptr_i;
        let mut j: usize = self.ptr_j;

        let len = buf.len();
        let mut ret = vec![0u8; len];
        let mut mid = 0u8;
        let mut t = 0;
        for iter in 0..len {
            i = (i+1) % 256;
            mid = self.seed[i];
            t = (mid as usize+self.seed[j] as usize) % 256;
            j = (j+mid as usize) % 256;
            self.seed[i] = self.seed[j];
            self.seed[j] = mid;

            ret[iter] = buf[iter] ^ self.seed[t];
        }
        self.ptr_i = i;
        self.ptr_j = j;

        ret
    }

    pub fn decrypt(&mut self, buf: &[u8]) -> Vec<u8> {
        let mut i: usize = self.ptr_i;
        let mut j: usize = self.ptr_j;

        let len = buf.len();
        let mut ret = vec![0u8; len];
        let mut mid = 0u8;
        let mut t = 0;
        for iter in 0..len {
            i = (i+1) % 256;
            mid = self.seed[i];
            t = (mid as usize+self.seed[j] as usize) % 256;
            j = (j+mid as usize) % 256;
            self.seed[i] = self.seed[j];
            self.seed[j] = mid;

            ret[iter] = buf[iter] ^ self.seed[t];
        }
        self.ptr_i = i;
        self.ptr_j = j;

        ret
    }

    pub fn decrypt_to(&mut self, des: &mut [u8], buf: &[u8]) {
        let mut i: usize = self.ptr_i;
        let mut j: usize = self.ptr_j;

        let len = buf.len();
        let mut mid = 0u8;
        let mut t = 0usize;
        for iter in 0..len {
            i = (i+1) % 256;
            mid = self.seed[i];
            t = (mid as usize + self.seed[j] as usize) % 256;
            j = (j+mid as usize) % 256;
            self.seed[i] = self.seed[j];
            self.seed[j] = mid;

            des[iter] = buf[iter] ^ self.seed[t];
        }
        self.ptr_i = i;
        self.ptr_j = j;
    }

    pub fn decrypt_self(&mut self, buf: &mut [u8]) {
        let mut i: usize = self.ptr_i;
        let mut j: usize = self.ptr_j;

        let len = buf.len();
        let mut mid = 0u8;
        let mut t = 0usize;
        for iter in 0..len {
            i = (i+1) % 256;
            mid = self.seed[i];
            t = (mid as usize + self.seed[j] as usize) % 256;
            j = (j+mid as usize) % 256;
            self.seed[i] = self.seed[j];
            self.seed[j] = mid;

            buf[iter] ^= self.seed[t];
        }
        self.ptr_i = i;
        self.ptr_j = j;
    }

    pub fn clone(&self) -> RC4inner {
        RC4inner{
            seed: self.seed.clone(),
            ptr_i: self.ptr_i,
            ptr_j: self.ptr_j,
        }
    }

    pub fn look_back(&mut self, backup: &RC4inner) {
        self.seed = backup.seed;
        self.ptr_i = backup.ptr_i;
        self.ptr_j = backup.ptr_j;
    }
}

#[derive(Debug)]
pub struct RC4Cipher {
    sender: Mutex<RC4inner>,
    // sender_backup: RC4inner,
    recver: Mutex<RC4inner>,
    // key_valid: bool,
}

impl RC4Cipher {
    pub fn new(init_bytes: &[u8]) -> Self{
        let sender = Mutex::new(RC4inner::new(init_bytes));
        // let sender_backup = RC4inner::empty_new();
        let recver = Mutex::new(RC4inner::new(init_bytes));
        
        Self{
            sender,
            // sender_backup,
            recver,
            // key_valid: true,
        }
    }

    pub fn empty_new() -> Self {
        let sender = Mutex::new(RC4inner::empty_new());
        // let sender_backup = RC4inner::empty_new();
        let recver = Mutex::new(RC4inner::empty_new());
        
        Self{
            sender,
            // sender_backup,
            recver,
            // key_valid: false,
        }
    }

    pub fn set_key(&self, init_bytes: &[u8]) -> Result<()> {
        self.sender.lock().unwrap().set_key(init_bytes);
        // self.sender_backup = RC4inner::empty_new();
        self.recver.lock().unwrap().set_key(init_bytes);

        // self.key_valid = true;

        Ok(())
    }

    pub fn encrypt(&self, buf: &[u8]) -> Vec<u8> {
        // backup, look back when send fail
        // self.sender_backup = self.sender.clone();
        
        self.sender.lock().unwrap().encrypt(buf)
    }

    pub fn decrypt(&self, buf: &[u8]) -> Vec<u8> {
        self.recver.lock().unwrap().decrypt(buf)
    }

    pub fn decrypt_to(&self, des: &mut [u8], buf: &[u8]) {
        self.recver.lock().unwrap().decrypt_to(des, buf)
    }

    pub fn decrypt_self(&self, buf: &mut [u8]) {
        self.recver.lock().unwrap().decrypt_self(buf)
    }

    // pub fn look_back(&mut self) {
    //     self.sender.look_back(&self.sender_backup);
    // }
}