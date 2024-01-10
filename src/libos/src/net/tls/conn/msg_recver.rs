use super::*;

use client::msg::read_u32_be;
use core::fmt;
use sgx_tstd::net::TcpStream;
use std::io::Read;


const LENGH_WIDTH: usize = std::mem::size_of::<usize>();


#[derive(Debug)]
pub enum ConnErr {
    NoEnoughMsg,
    SendFail,
    Unkown,
}

impl fmt::Display for ConnErr{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let err = match self{
            ConnErr::NoEnoughMsg => "No enough msg in recver buf",
            ConnErr::SendFail => "fail while sending msg",
            ConnErr::Unkown => "Unknown err",
        };
        write!(f, "{}", err)
    }
}

pub struct TcpPackParser {
    buf: Vec<u8>,
    conn: Option<TcpStream>,
}

impl TcpPackParser {
    pub fn new() -> Self {
        Self { 
            buf: Vec::new(), 
            conn: None,
        }
    }

    pub fn from_conn(conn: &TcpStream) -> Self {
        Self { 
            buf: Vec::new(), 
            conn: Some((*conn).try_clone().unwrap()),
        }
    }

    pub fn set_conn(&mut self, conn: &TcpStream) {
        self.conn = Some((*conn).try_clone().unwrap());
    }

    pub fn recv_msg(&mut self, mut conn: &TcpStream) -> usize {
        let mut buf = [0u8; 2048];
        let len = conn.read(&mut buf).unwrap();
        self.buf.append(&mut buf[..len].to_vec());
        len
    }

    fn recv_msg_selfconn(&mut self) -> usize {
        let mut buf = [0u8; 2048];
        let mut conn = self.conn.as_ref().unwrap();
        let len = conn.read(&mut buf).unwrap();
        self.buf.append(&mut buf[..len].to_vec());
        len
    }

    pub fn parse_one_data(&mut self) -> Result<Vec<u8>> {
        if self.buf.len() < LENGH_WIDTH {
            return Err(errno!(EINVAL, "No enough msg in recver buf!"));
        }

        // parse data_len to avoid tcp pack sticking
        let raw_data = &mut (&self.buf as &[u8]);
        let data_len = read_u32_be(raw_data);

        if (*raw_data).len() < data_len {
            return Err(errno!(EINVAL, "No enough msg in recver buf!"));
        }

        let (data, rest) = raw_data.split_at(data_len);
        let ret = Vec::from(data);
        self.buf = Vec::from(rest);

        Ok(ret)
    }

    pub fn empty(&self) -> bool {
        self.buf.is_empty()
    }

    pub fn fetch_one_data(&mut self) -> Vec<u8> {
        loop {  // avoid Tcp pack truncation
            match self.parse_one_data() {
                Ok(ret) => {return ret;},
                Err(err) => {
                    match err.errno() {
                        EINVAL => {self.recv_msg_selfconn();},
                        _ => {panic!("parse_data err: {}", err);},
                    }
                },
            }
        }
    }
}