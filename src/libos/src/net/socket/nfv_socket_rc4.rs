//this file is edit by kxc
use super::*;
use std::any::Any;
use fs::{FsView, FileMode, AccessMode, CreationFlags, StatusFlags, INodeFile, AsINodeFile};
use self::local_proxy::EncryptMsg;
use tls::comm::aes_comm::{Aes128CtrCipher, LENGH_WIDTH, MAX_MSG_LEN};
use tls::comm::rc4_comm::RC4Cipher;
use tls::comm::ca_manager::{get_echash_fromfile, get_shared_aes_fromfile};
use std::sync::{SgxMutex as Mutex, SgxMutexGuard as MutexGuard, SgxRwLock as RwLock};

macro_rules! try_libc {
    ($ret: expr) => {{
        let ret = unsafe { $ret };
        if ret < 0 {
            let errno = unsafe { libc::errno() };
            return_errno!(Errno::from(errno as u32), "libc error");
        }
        ret
    }};
}

macro_rules! echo_buf {
    ($buf: ident) => {
        let length = EncryptMsg::msg_len($buf);
        for i in 0..length {
            print!("{:X}", $buf[i] as u8);
        }
        println!("");
    };
    ($buf: expr) => {
        let length = EncryptMsg::msg_len({$buf});
        for i in 0..length {
            print!("{:X}", $buf[i] as u8);
        }
        println!("");
    };
}

#[derive(Debug)]
enum NfvSocketState {
    NEW,            // could not send anything
    BARE,           // UDP socket, allow plaintext msg
    CONNECTED,      // could only use sendto to send plaintext msg to other socket except peer
    CHELLOSEND,    // already send client hello
    HANDSHAKED,     // could send encrypted msg to peer
}

#[derive(Debug)]
pub struct NfvSocket {
    // pub nfv_fd: Arc<dyn File>,
    pub host_sc: HostSocket,                // host socket
    pub aes_cipher: RwLock<Aes128CtrCipher>,
    pub rc4_cipher: RC4Cipher,
    pub pub_key_hash_tag: usize,            // 0 means did not registed yet.
    sock_state: RwLock<NfvSocketState>,
    aes_msg_buf: Mutex<Vec<u8>>,           // aes padding require whole msg recv, but the app may tunic the msg, this buff is used to cache the remain data
    //pub key: Some(BigUint),
    //pub elp_service: RunningELP,
}

impl NfvSocket {
    pub fn new(
        domain: AddressFamily,
        socket_type: SocketType,
        file_flags: FileFlags,
        protocol: i32,
    ) -> Result<Self> {
        let pub_key_hash_tag = get_echash_fromfile("/host/hash_tag");
        let host_sc = HostSocket::new(domain, socket_type, file_flags, protocol)?;

        let mut raw_aes_cipher = if pub_key_hash_tag == 0 {
            Aes128CtrCipher::empty_new()
        }else if let Some(shared_aes) = get_shared_aes_fromfile("/host/shared_aes") {
            shared_aes
        }else {
            Aes128CtrCipher::empty_new()
        };

        println!("socket_type: {:?}", socket_type);
        let sock_state = RwLock::new(match socket_type {
            SocketType::STREAM =>  match raw_aes_cipher.key_valid () {
                true => NfvSocketState::HANDSHAKED,
                false => NfvSocketState::NEW,
            },
            _ => NfvSocketState::BARE,
        });

        let rc4_cipher = match raw_aes_cipher.key_valid() {
            true => RC4Cipher::new(&raw_aes_cipher.to_be_bytes()),
            false => RC4Cipher::empty_new(),
        };
        let aes_cipher = RwLock::new(raw_aes_cipher);

        //let elp_service = EncryptLocalProxy::new(fd.clone()).start();

        Ok(Self {
            // nfv_fd: fd, 
            host_sc,
            aes_cipher,
            pub_key_hash_tag,
            sock_state,
            aes_msg_buf: Mutex::new(Vec::new()),
            rc4_cipher,
            //elp_service,
        })
    }

    fn from_host_sc(host_sc: HostSocket) -> NfvSocket {
        let pub_key_hash_tag = tls::comm::ca_manager::get_echash_fromfile("/host/hash_tag");

        let mut raw_aes_cipher = if pub_key_hash_tag == 0 {
            Aes128CtrCipher::empty_new()
        }else if let Some(shared_aes) = get_shared_aes_fromfile("/host/shared_aes") {
            shared_aes
        }else {
            Aes128CtrCipher::empty_new()
        };

        let sock_state = RwLock::new(
            // server_tls_handshake is block-method, if it fail, then fail all the time
            match raw_aes_cipher.key_valid() {
                true => NfvSocketState::HANDSHAKED,
                false => NfvSocketState::BARE,
            }
        );

        let rc4_cipher = match raw_aes_cipher.key_valid() {
            true => RC4Cipher::new(&raw_aes_cipher.to_be_bytes()),
            false => RC4Cipher::empty_new(),
        };
        let aes_cipher = RwLock::new(raw_aes_cipher);

        Self {
            // nfv_fd: fd, 
            host_sc,
            aes_cipher,
            pub_key_hash_tag,
            sock_state,
            aes_msg_buf: Mutex::new(Vec::new()),
            rc4_cipher,
            // elp_service,
        }
    }

    fn from_hsc_cipher(host_sc: HostSocket, cipher:Aes128CtrCipher) -> NfvSocket {
        let pub_key_hash_tag = tls::comm::ca_manager::get_echash_fromfile("/host/hash_tag");
        let rc4_cipher = RC4Cipher::new(&cipher.to_be_bytes());

        Self {
            host_sc,
            aes_cipher: RwLock::new(cipher),
            pub_key_hash_tag, 
            sock_state: RwLock::new(NfvSocketState::HANDSHAKED),
            aes_msg_buf: Mutex::new(Vec::new()),
            rc4_cipher,
        }
    }

    pub fn bind(&self, addr: &SockAddr) -> Result<()> {
        self.host_sc.bind(addr)
    }

    pub fn listen(&self, backlog: i32) -> Result<()> {
        self.host_sc.listen(backlog)
    }

    pub fn accept(&self, flags: FileFlags) -> Result<(NfvSocket, Option<SockAddr>)> {
        println!("call accept");
        let (host_sc, addr_option) = match self.host_sc.accept(flags) {
            Ok(ret) => ret,
            Err(err) => {
                println!("accept Err: {:?}", err);
                return Err(err);
            },
        };

        // kssp mode off
        let aes_cipher = self.aes_cipher.read().unwrap();
        if self.pub_key_hash_tag == 0 || aes_cipher.key_valid() {
            return Ok((NfvSocket::from_host_sc(host_sc), addr_option));
        }
        drop(aes_cipher);

        // println!("accept server_tls_handshake");
        match self.server_tls_handshake(&host_sc) {
            Ok(cipher) => {
                Ok((NfvSocket::from_hsc_cipher(host_sc, cipher), addr_option))
            },
            Err(err) => {
                println!("\x1b[33m[Warning:handshake faild] {}\x1b[0m", err);
                Ok((NfvSocket::from_host_sc(host_sc), addr_option))
            },
        }
    }

    fn server_tls_handshake(&self, host_sc: &HostSocket) -> Result<Aes128CtrCipher> {
        let sflag = SendFlags::from_bits(0).unwrap();
        let mut server_hs = server::hs::ServerHsRmAt::new();

        if let Err(err) = server_hs.recv_clienthello_and_parse(&host_sc) {
            println!("clienthello parse fail");
            // std::thread::park_timeout(std::time::Duration::from_secs(0));
            return Err(err);
        }

        let server_hello = server_hs.reply_to_client();

        if let Err(err) = host_sc.sendto(&server_hello, sflag, &None) {
            println!("server handshake send fail: {:?}", err);
            // std::thread::park_timeout(std::time::Duration::from_secs(0));
            return Err(err);
        }
        
        let server_nego_key = server_hs.get_nego_key();

        // println!("nego_key: {}", server_nego_key);

        println!("\x1b[32mhandshake success\x1b[0m");
        Ok(Aes128CtrCipher::new(&server_nego_key.to_bytes_be()).unwrap())
    }

    pub fn connect(&self, addr: &Option<SockAddr>) -> Result<()> {
        println!("call connect");
        let aes_cipher = self.aes_cipher.read().unwrap();
        if self.pub_key_hash_tag == 0 || aes_cipher.key_valid() {
            return self.host_sc.connect(addr);
        }
        drop(aes_cipher);

        let sock_state = self.sock_state.read().unwrap();
        match *sock_state {
            NfvSocketState::BARE => {
                self.host_sc.connect(addr)
            },
            _ => {
                drop(sock_state);

                // let ret = match self.host_sc.connect(addr) {
                //     Ok(x) => Ok(x),
                //     Err(err) => {
                //         println!("connect Err: {:?}", err);
                //         let mut sock_state = self.sock_state.write().unwrap();
                //         *sock_state = NfvSocketState::CONNECTED;
                //         return Err(err);
                //     },
                // };
                let ret = self.host_sc.connect(addr);

                self.client_tls_handshake();

                ret
            },
        }
    }

    fn client_tls_handshake(&self) -> Result<()> {
        let mut client_hs = client::hs::ClientHsRmAt::new();
        let sflag = SendFlags::from_bits(0).unwrap();
        let client_hello = client_hs.start_handshake();

        if let Err(err) = self.host_sc.sendto(&client_hello, sflag, &None) {
            println!("client handshake send fail: {:?}", err);
            // std::thread::park_timeout(std::time::Duration::from_secs(0));
            return Err(err);
        }
        // println!("client hello send");
        let mut sock_state = self.sock_state.write().unwrap();
        *sock_state = NfvSocketState::CHELLOSEND;

        if let Err(err) = client_hs.recv_serverhello_and_parse(&self.host_sc) {
            // if err.errno() == EINVAL {
            //     *sock_state = NfvSocketState::BARE;
            // }
            // println!("serverhello parse fail");
            return Err(err);
        }

        let client_nego_key = client_hs.get_nego_key();
        let mut aes_cipher = self.aes_cipher.write().unwrap();
        aes_cipher.set_key(&client_nego_key.to_bytes_be());
        self.rc4_cipher.set_key(&aes_cipher.to_be_bytes());
        *sock_state = NfvSocketState::HANDSHAKED;
        println!("\x1b[32mhandshake success\x1b[0m");

        Ok(())
    }

    fn recv_server_hello_again(&self) -> Result<()> {
        let mut client_hs = client::hs::ClientHsRmAt::new();
        if let Err(err) = client_hs.recv_serverhello_and_parse(&self.host_sc) {
            println!("recv serverhello fail agian, set the socket to BARE");
            *self.sock_state.write().unwrap() = NfvSocketState::BARE;
            // println!("got write lock");
            return Err(errno!(EINVAL, "handshake failed"));
            // std::thread::park_timeout(std::time::Duration::from_millis(1));
        }

        let client_nego_key = client_hs.get_nego_key();
        self.aes_cipher.write().unwrap().set_key(&client_nego_key.to_bytes_be());
        *self.sock_state.write().unwrap() = NfvSocketState::HANDSHAKED;
        println!("\x1b[32mhandshake success\x1b[0m");
        
        Ok(())
    }

    pub fn check_handshake_before_comm(&self) -> Result<()> {
        let sock_state = self.sock_state.read().unwrap();
        match *sock_state {
            NfvSocketState::CONNECTED => {
                drop(sock_state);
                // non-block connect where client_tls_handshake not happened
                // println!("check state: CONNECTED");
                if let Err(err) = self.client_tls_handshake() {
                    self.recv_server_hello_again()
                }else {
                    Ok(())
                }
            },
            NfvSocketState::CHELLOSEND => {
                drop(sock_state);
                // already send clienthello during connect
                // println!("check state: CHELLOSEND");
                self.recv_server_hello_again()
            },
            NfvSocketState::HANDSHAKED => {
                // println!("check state: HANDSHAKED");
                Ok(())
            },
            NfvSocketState::NEW => {
                // println!("check state: NEW");
                Err(errno!(EINVAL, "bare socket"))
            },
            NfvSocketState::BARE => {
                // println!("check state: BARE");
                Err(errno!(EINVAL, "bare socket"))
            },
        }
    }

    pub fn sendto(
        &self,
        buf: &[u8],
        flags: SendFlags,
        addr_option: &Option<SockAddr>,
    ) -> Result<usize> {
        // println!("call sendto flags: {}, buf_size: {}", flags.bits(), buf.len());
        // kssp mode on
        if self.pub_key_hash_tag != 0 {
            // there's already a connection
            if let None = addr_option {
                // if let Err(err) = self.check_handshake_before_comm() {
                //     return self.host_sc.sendto(buf, flags, &None);
                // }
                // println!("msg_len:{}, msg:{}", buf.len(), base64::encode(buf));
                // let enc_msg = self.aes_cipher.read().unwrap().encrypt_mark_len(buf);
                // let enc_msg = self.aes_cipher.read().unwrap().encrypt(buf);
                let enc_msg = self.rc4_cipher.encrypt(buf);
                match self.host_sc.sendto(&enc_msg, flags, &None) {
                    Ok(x) => {
                        // println!("sendto {} bytes successfully", x);
                        // Ok(buf.len())
                        Ok(x)
                    },
                    Err(err) => {
                        println!("sendto err: {}", err);
                        // rc4_cipher.look_back();
                        Err(err)
                    },
                }
            }
            // UDP sendto
            else {
                println!("\x1b[33m[Warning:] plaintext UDP sendto {:?}\x1b[0m", addr_option.unwrap());
                self.host_sc.sendto(buf, flags, addr_option)
            }
        }
        // kssp mode off
        else {
            self.host_sc.sendto(buf, flags, addr_option)
        }
    }

    // recv a whole encrypted msg to aes_msg_buf
    pub fn recv_msg_to_amb(&self, flags: RecvFlags, expect_volumn: usize, amb: &mut MutexGuard<Vec<u8>>) -> Result<usize> {
        let amb_len = amb.len();

        if amb_len >= expect_volumn {
            return Ok(0);
        }

        let mut len_buf = [0u8; LENGH_WIDTH];

        let rflag = match amb_len {
            0 => flags,
            _ => (flags | RecvFlags::MSG_DONTWAIT),
        };

        // println!("peek len buf: {}", base64::encode(len_buf));
        if let Err(err) = self.host_sc.recvfrom(&mut len_buf, rflag) {
            if err.errno() == EAGAIN || amb_len != 0 {
                return Ok(0);
            }
            println!("recvfrom err: {}", err);
            return Err(err);
        }
        let msg_len = usize::from_be_bytes(len_buf);
        println!("parse len: {}", msg_len);
        if msg_len == 0 {
            // peer close the socket
            return Ok(0);
        }
        let mut data_buf = vec![0u8; msg_len];
        let mut recv_ptr = 0;
        while recv_ptr < msg_len {
            let (recv_len, addr_option) = self.host_sc.recvfrom(&mut data_buf[recv_ptr..], flags).unwrap();
            println!("recv len: {}", recv_len);
            recv_ptr+=recv_len;
        }
        // println!("recvfrom: {}", base64::encode(&data_buf));
        amb.resize(amb_len+msg_len, 0u8);
        self.aes_cipher.read().unwrap().decrypt_to(&mut amb[amb_len..], &data_buf);

        Ok(msg_len)
    }

    // asynchronous I/O
    pub fn fetch_msg_from_amb(&self, des: &mut [u8], flags: RecvFlags) -> Result<usize> {
        let mut amb = self.aes_msg_buf.lock().unwrap();

        let expect_volumn = des.len();
        while match self.recv_msg_to_amb(flags, expect_volumn, &mut amb) {
            Ok(x) => {
                match x {
                    0 => false,
                    _ => true,
                }
            },
            Err(err) => {
                return Err(err);
            }
        }{;}

        let amb_len = amb.len();
        if amb_len <= expect_volumn {
            for i in 0..amb_len{
                des[i] = amb[i];
            }
            amb.resize(0, 0u8);
            Ok(amb_len)
        }
        else{
            for i in 0..expect_volumn{
                des[i] = amb[i];
            }
            *amb = amb.split_off(expect_volumn);
            Ok(expect_volumn)
        }
    }

    // synchronous I/O
    pub fn fetch_msg(&self, des: &mut [u8], flags: RecvFlags) -> Result<usize> {
        let mut amb = self.aes_msg_buf.lock().unwrap();
        let amb_len = amb.len();// usize::from_be_bytes(amb[..LENGH_WIDTH].try_into().unwrap());
        let expect_volumn = des.len();

        // split if too bigger
        let expand_len = if expect_volumn > MAX_MSG_LEN + amb_len {
            MAX_MSG_LEN + LENGH_WIDTH
        }else if expect_volumn + LENGH_WIDTH > amb_len {
            expect_volumn + LENGH_WIDTH - amb_len
        }else{
            // println!("expected_volum: {}, amb_len:{}", expect_volumn, amb_len);
            0
        };
        let data_buf: &mut [u8] =  {
            amb.resize(amb_len + expand_len, 0u8);
            &mut amb[amb_len..]
        };

        // synchronously recv msg
        let data_buf_len = amb_len + match self.host_sc.recvfrom(data_buf, flags) {
            Ok((x, y)) => x,
            Err(err) => {
                // println!("recvfrom err: {}", err);
                return Err(err);
                0
            },
        };
        // println!("expect_volumn: {}, recv_len: {}", expect_volumn, recv_len);

        // parse recved_msg
        let mut parse_ptr = 0;
        let mut ret_len = 0;
        let parse_buf = &amb;
        let aes_cipher = self.aes_cipher.read().unwrap();
        while parse_ptr < data_buf_len {
            if parse_ptr+LENGH_WIDTH > data_buf_len{
                break;
            }
            let msg_len = usize::from_be_bytes(parse_buf[parse_ptr..(parse_ptr+LENGH_WIDTH)].try_into().unwrap());
            // println!("parse len: {}", msg_len);
            parse_ptr+=LENGH_WIDTH;
            if parse_ptr+msg_len > data_buf_len{
                // println!("parsed_len: {}, req_len: {}, rest_len:{}", ret_len, msg_len, data_buf_len-parse_ptr);
                parse_ptr-=LENGH_WIDTH;
                break;
            }
            else if msg_len != 0 {
                aes_cipher.decrypt_to(&mut des[ret_len..ret_len+msg_len], &parse_buf[parse_ptr..parse_ptr+msg_len]);
                ret_len += msg_len;
            }
            else {
                // empty msg
                let rest_len = amb.len() - parse_ptr;
                aes_cipher.decrypt_to(&mut des[ret_len..ret_len+rest_len], &parse_buf[parse_ptr..]);
                parse_ptr += rest_len;
                ret_len += rest_len;
                break;
            }
            parse_ptr+=msg_len;
        }
        *amb = amb.split_off(parse_ptr);
        Ok(ret_len)
        // let msg_len = usize::from_be_bytes(data_buf[..LENGH_WIDTH].try_into().unwrap());
        // println!("parse len: {}", msg_len);
        // amb.append(&mut aes_cipher.decrypt(&data_buf[LENGH_WIDTH..]));
        // aes_cipher.decrypt_to(des, &data_buf[LENGH_WIDTH..]);
        // drop(aes_cipher);
        // Ok(data_buf.len()-LENGH_WIDTH)

        // let amb_len = amb.len();
        // if amb_len <= expect_volumn {
        //     for i in 0..amb_len {
        //         des[i] = amb[i];
        //     }
        //     amb.resize(0, 0u8);
        //     Ok(amb_len)
        // }
        // else{
        //     for i in 0..expect_volumn {
        //         des[i] = amb[i];
        //     }
        //     *amb = amb.split_off(expect_volumn);
        //     Ok(expect_volumn)
        // }
    }

    pub fn recvfrom(&self, buf: &mut [u8], flags: RecvFlags) -> Result<(usize, Option<SockAddr>)> {
        // println!("call recvfrom, flag: {}, buf_size: {}", flags.bits(), buf.len());
        // kssp mode on
        if self.pub_key_hash_tag != 0 {
            // if let Err(err) = self.check_handshake_before_comm() {
            //     return self.host_sc.recvfrom(buf, flags);
            // }

            // match self.fetch_msg_from_amb(buf, flags) {
            //     Ok(len) => Ok((len, None)),
            //     Err(err) => Err(err),
            // }
            // match self.fetch_msg(buf, flags) {
            //     Ok(len) => Ok((len, None)),
            //     Err(err) => Err(err),
            // }

            // let mut enc_msg = vec![0u8; buf.len()];
            // let ret = self.host_sc.recvfrom(&mut enc_msg, flags);
            // if let Ok((msg_len, addr_option)) = ret {
            //     self.aes_cipher.read().unwrap().decrypt_to(&mut buf[..msg_len], &enc_msg[..msg_len]);
            // }
            // ret
            // let mut enc_msg = vec![0u8; buf.len()];
            let ret = self.host_sc.recvfrom(buf, flags);
            if let Ok((msg_len, addr_option)) = ret {
                if let None = addr_option {
                    self.rc4_cipher.decrypt_self(&mut buf[..msg_len]);
                }
                else {
                    println!("\x1b[33m[Warning:] plaintext UDP recvfrom {:?}\x1b[0m", addr_option.unwrap());
                }
            }
            ret

            // match ret {
            //     Ok((msg_len, addr_option)) => {
            //         // there's already a connection
            //         if let None = addr_option {
            //             let aes_cipher = self.aes_cipher.read().unwrap();
            //             let enc_msg = aes_cipher.decrypt_to(&mut buf[..msg_len], &enc_msg[..msg_len]);
            //             drop(aes_cipher);
            //         }
            //         // UDP recvfrom
            //         // one can only know whether it is a TCP/UDP after parsing the result of the hostsocket.recvfrom()
            //         // but the data can not be writen into buf directly, in case that aes_cipher is not ready.
            //         // As a backward, when it is UDP, the data need to be transfered from enc_msg to buf
            //         else {
            //             println!("\x1b[33m[Warning:] plaintext UDP recvfrom {:?}\x1b[0m", addr_option.unwrap());
            //             for i in 0..msg_len {
            //                 buf[i] = enc_msg[i];
            //             }
            //         }
            //         ret
            //     },
            //     Err(err) => Err(err),
            // }
        }
        // kssp mode off
        else{
            self.host_sc.recvfrom(buf, flags)
        }
    }

    pub fn raw_host_fd(&self) -> FileDesc {
        self.host_sc.raw_host_fd()
    }

    pub fn shutdown(&self, how: HowToShut) -> Result<()> {
        // println!("call nfv shutdown");
        //self.elp_service.stop();
        self.host_sc.shutdown(how)
    }
}

pub trait NfvSocketType {
    fn as_host_socket(&self) -> Result<&NfvSocket>;
}

use backtrace::Backtrace;
impl NfvSocketType for FileRef {
    fn as_host_socket(&self) -> Result<&NfvSocket> {
        self.as_any()
            .downcast_ref::<NfvSocket>()
            .ok_or_else(|| errno!(EBADF, "not a host socket"))
    }
}