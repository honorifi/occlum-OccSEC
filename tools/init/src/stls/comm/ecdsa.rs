use sgx_ucrypto;
use sgx_types::{uint8_t, SGX_ECP256_KEY_SIZE, uint32_t,
    SGX_NISTP_ECP256_KEY_SIZE, sgx_ec256_private_t, sgx_ec256_public_t};
use std::mem::size_of;

pub const ECDSA_SIGN_MSG_SIZE: usize = size_of::<uint32_t>()/size_of::<u8>() * 2 * SGX_NISTP_ECP256_KEY_SIZE;
pub struct EcdsaHandle {
    handle: sgx_ucrypto::SgxEccHandle,
    priv_key: sgx_ec256_private_t,
    pub_key: sgx_ec256_public_t,
}

impl EcdsaHandle {
    pub fn new() -> Self {
        let handle = sgx_ucrypto::SgxEccHandle::new();
        handle.open();
        let (priv_key, pub_key) = handle.create_key_pair().unwrap();

        Self {
            handle,
            priv_key,
            pub_key,
        }
    }

    pub fn to_be_bytes(&self) -> Vec<u8> {
        let mut ret = Vec::new();

        for i in 0 .. SGX_ECP256_KEY_SIZE {
            ret.push(self.priv_key.r[i]);
            ret.push(self.pub_key.gx[i]);
            ret.push(self.pub_key.gy[i]);
        };

        ret
    }

    pub fn to_pub_handle(&self) -> EcdsaPublic {
        let handle = sgx_ucrypto::SgxEccHandle::new();
        handle.open();
        EcdsaPublic {
            handle,
            pub_key: self.pub_key,
        }
    }

    pub fn from_be_bytes(bytes: &[u8]) -> Self {
        let mut r = [0 as uint8_t; SGX_ECP256_KEY_SIZE];
        let mut gx = [0 as uint8_t; SGX_ECP256_KEY_SIZE];
        let mut gy = [0 as uint8_t; SGX_ECP256_KEY_SIZE];

        for i in 0 .. SGX_ECP256_KEY_SIZE {
            r[i] = bytes[i*3];
            gx[i] = bytes[i*3+1];
            gy[i] = bytes[i*3+2];
        };

        let handle = sgx_ucrypto::SgxEccHandle::new();
        handle.open();
        Self {
            handle,
            priv_key: sgx_ec256_private_t { r },
            pub_key: sgx_ec256_public_t { gx, gy },
        }
    }

    pub fn to_bytes_str(&self) -> String {
        let bytes_str = base64::encode(&self.to_be_bytes());
        bytes_str.to_string()
    }

    pub fn from_bytes_str(b64_str: String) -> Self {
        let bytes_buf = &base64::decode(&b64_str).unwrap()[..];

        Self::from_be_bytes(bytes_buf)
    }
     
    pub fn sign_msg_with_bytes(&self, data: &[u8]) -> Vec<u8> {
        let sign_msg = self.handle.ecdsa_sign_slice(data, &self.priv_key).unwrap();
        let mut ret = Vec::new();

        let block = size_of::<uint32_t>()/size_of::<u8>();
        for i in 0 .. SGX_NISTP_ECP256_KEY_SIZE {
            let x_slice = sign_msg.x[i].to_be_bytes();
            let y_slice = sign_msg.y[i].to_be_bytes();
            for j in 0..block {
                ret.push(x_slice[j]);
                ret.push(y_slice[j]);
            }
        };

        ret
    }

    pub fn veri_msg_with_bytes(&self, data: &[u8], sign_msg: &[u8]) -> bool {
        let mut sign_t = sgx_types::sgx_ec256_signature_t {
            x: [0 as uint32_t; SGX_NISTP_ECP256_KEY_SIZE],
            y: [0 as uint32_t; SGX_NISTP_ECP256_KEY_SIZE],
        };

        let block = size_of::<uint32_t>()/size_of::<u8>() * 2;
        for i in 0..SGX_NISTP_ECP256_KEY_SIZE {
            let ib = i*block;
            sign_t.x[i] = uint32_t::from_be_bytes(
                [sign_msg[ib], sign_msg[ib+2], 
                sign_msg[ib+4], sign_msg[ib+6]]
            );
            sign_t.y[i] = uint32_t::from_be_bytes(
                [sign_msg[ib+1], sign_msg[ib+3], 
                sign_msg[ib+5], sign_msg[ib+7]]
            );
        };

        self.handle.ecdsa_verify_slice(data, &self.pub_key, &sign_t).unwrap()
    }
}

pub struct EcdsaPublic {
    handle: sgx_ucrypto::SgxEccHandle,
    pub_key: sgx_ec256_public_t,
}

impl EcdsaPublic {
    pub fn to_be_bytes(&self) -> Vec<u8> {
        let mut ret = Vec::new();

        for i in 0 .. SGX_ECP256_KEY_SIZE {
            ret.push(self.pub_key.gx[i]);
            ret.push(self.pub_key.gy[i]);
        };

        ret
    }

    pub fn from_be_bytes(bytes: &[u8]) -> Self {
        let mut gx = [0 as uint8_t; SGX_ECP256_KEY_SIZE];
        let mut gy = [0 as uint8_t; SGX_ECP256_KEY_SIZE];

        for i in 0 .. SGX_ECP256_KEY_SIZE {
            gx[i] = bytes[i*2];
            gy[i] = bytes[i*2+1];
        };

        let handle = sgx_ucrypto::SgxEccHandle::new();
        handle.open();
        Self {
            handle,
            pub_key: sgx_ec256_public_t { gx, gy },
        }
    }

    pub fn to_bytes_str(&self) -> String {
        let bytes_str = base64::encode(&self.to_be_bytes());
        bytes_str.to_string()
    }

    pub fn from_bytes_str(b64_str: String) -> Self {
        let bytes_buf = &base64::decode(&b64_str).unwrap()[..];

        Self::from_be_bytes(bytes_buf)
    }

    pub fn veri_msg_with_bytes(&self, data: &[u8], sign_msg: &[u8]) -> bool {
        let data = data.try_into().unwrap();
        let mut sign_t = sgx_types::sgx_ec256_signature_t {
            x: [0 as uint32_t; SGX_NISTP_ECP256_KEY_SIZE],
            y: [0 as uint32_t; SGX_NISTP_ECP256_KEY_SIZE],
        };

        let block = size_of::<uint32_t>()/size_of::<u8>() * 2;
        for i in 0..SGX_NISTP_ECP256_KEY_SIZE {
            let ib = i*block;
            sign_t.x[i] = uint32_t::from_be_bytes(
                [sign_msg[ib], sign_msg[ib+2], 
                sign_msg[ib+4], sign_msg[ib+6]]
            );
            sign_t.y[i] = uint32_t::from_be_bytes(
                [sign_msg[ib+1], sign_msg[ib+3], 
                sign_msg[ib+5], sign_msg[ib+7]]
            );
        };

        self.handle.ecdsa_verify_slice(data, &self.pub_key, &sign_t).unwrap()
    }
}

pub struct EcdsaPublicBytes {
    pub_key: sgx_ec256_public_t,
}

impl EcdsaPublicBytes {
    pub fn to_be_bytes(&self) -> Vec<u8> {
        let mut ret = Vec::new();

        for i in 0 .. SGX_ECP256_KEY_SIZE {
            ret.push(self.pub_key.gx[i]);
            ret.push(self.pub_key.gy[i]);
        };

        ret
    }

    pub fn from_be_bytes(bytes: &[u8]) -> Self {
        let mut gx = [0 as uint8_t; SGX_ECP256_KEY_SIZE];
        let mut gy = [0 as uint8_t; SGX_ECP256_KEY_SIZE];

        for i in 0 .. SGX_ECP256_KEY_SIZE {
            gx[i] = bytes[i*2];
            gy[i] = bytes[i*2+1];
        };

        Self {
            pub_key: sgx_ec256_public_t { gx, gy },
        }
    }

    pub fn equal(&self, x: &EcdsaPublicBytes) -> bool {
        self.pub_key.gx == x.pub_key.gx && self.pub_key.gy == x.pub_key.gy
    }
}

impl Clone for EcdsaHandle {
    fn clone(&self) -> Self {
        let handle = sgx_ucrypto::SgxEccHandle::new();
        handle.open();
        Self{
            handle,
            priv_key: self.priv_key.clone(),
            pub_key: self.pub_key.clone(),
        }
    }
}

impl Clone for EcdsaPublic {
    fn clone(&self) -> Self {
        let handle = sgx_ucrypto::SgxEccHandle::new();
        handle.open();
        Self{
            handle,
            pub_key: self.pub_key.clone(),
        }
    }
}
