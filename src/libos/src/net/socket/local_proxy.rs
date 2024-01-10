use super::*;
use fs::{FsView, FileMode, AccessMode, CreationFlags, StatusFlags, INodeFile, AsINodeFile};
// use std::thread::JoinHandle;

macro_rules! echo_buf {
    ($buf: ident) => {
        let length = $buf.len();
        for i in 0..length {
            print!("{}", $buf[i] as char);
        }
        println!("");
    };
}

// #[derive(Debug)]
// pub struct EncryptLocalProxy {
//     nfv_fd: Arc<dyn File>,
// }

// #[derive(Debug)]
// pub struct RunningELP {
//     elp: Arc<EncryptLocalProxy>,
//     join_handle: JoinHandle<()>,
// }

#[derive(Debug)]
pub struct EncryptMsg;

// impl EncryptLocalProxy {
//     pub fn new(nfv_fd: Arc<dyn File>) -> Self {
//         Self{
//             nfv_fd,
//         }
//     }

//     pub fn start(self) -> RunningELP {
//         let elp = Arc::new(self);
//         let join_handle = {
//             let elp = elp.clone();
//             std::thread::spawn(move || elp.run())
//         };

//         RunningELP {
//             elp,
//             join_handle,
//         }
//     }

//     fn run(&self) {
//         println!("elp running");
//         let eof_str = "".as_bytes();
//         let close_str = "close".as_bytes();
//         let mut bufread: [u8; 256] = [0; 256];
//         let mut flag: bool = true;

//         loop {
//             flag = true;
//             let len = self.nfv_fd.read_at(0, &mut bufread).unwrap();
//             if len == 0 {                    
//                 std::thread::yield_now();
//                 continue;
//             }
//             for i in 0..5 {
//                 if bufread[i] != close_str[i] {flag = false; break;}
//             }
//             if flag == true {break;}

//             self.nfv_fd.read_at(0, &mut bufread);
//             println!("elp_echo:");
//             echo_buf!(bufread);
//             self.nfv_fd.write_at(0, &eof_str);
//         }

//         println!("elp terminated");
//     }

//     pub fn stop(&self) {
//         let close_str = "close".as_bytes();
//         self.nfv_fd.write_at(0, close_str);
//     }
// }

// impl RunningELP {
//     pub fn stop(&self) {
//         self.elp.stop();
//         println!("wait elp_subthread stop");
//         // self.join_handle.join();
//         println!("elp_subthread stop");
//     }
// }

impl EncryptMsg {
    pub fn msg_len(buf: &[u8]) -> usize {
        let mut i: usize = buf.len() - 1;
        while i != 0 {
            if buf[i] != 0 {i = i+1; break;}
            i = i-1;
        }
        i
    }

    pub fn buf_copy(des: &mut [u8], src: &[u8]) -> usize {
        let mut i: usize = src.len() - 1;
        while i != 0 {
            if src[i] != 0 {break;}
            i = i-1;
        }
        let ret = i+1;
        while i != 0 {
            des[i] = src[i];
            i = i-1;
        }
        des[i] = src[i];
        ret
    }

    pub fn msg_encrypt(buf: &mut [u8], key: u32) {
        let len = EncryptMsg::msg_len(buf);
        let mut offset = 0;
        for i in 0..len {
            buf[i] = buf[i] ^ ((key >> offset) as u8);
            offset = (offset + 8) % 32;
        }
    }

    pub fn msg_decrypt(buf: &mut [u8], key: u32) {
        let len = EncryptMsg::msg_len(buf);
        let mut offset = 0;
        for i in 0..len {
            buf[i] = buf[i] ^ ((key >> offset) as u8);
            offset = (offset + 8) % 32;
        }
    }
}
