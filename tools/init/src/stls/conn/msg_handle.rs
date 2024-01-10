pub use super::*;

use msg_sender;
use msg_recver::{TcpPackParser, ConnErr};
use std::net::TcpStream;

pub struct PackHandle {
    conn: TcpStream,
    packparser: TcpPackParser,
}

impl PackHandle {
    pub fn new(conn: &TcpStream) -> Self {
        Self {
            conn: (*conn).try_clone().unwrap(),
            packparser: TcpPackParser::new(),
        }
    }

    pub fn send_msg(&self, msg: &[u8], len: usize) -> Result<usize, ConnErr> {
        match msg_sender::send_msg(&self.conn, msg, len) {
            Ok(len) => Ok(len),
            Err(err) => Err(ConnErr::SendFail),
        }
    }

    pub fn recv_msg(&mut self) -> Result<Vec<u8>, ConnErr> {
        loop {  // avoid Tcp pack truncation
            match self.packparser.parse_one_data() {
                Ok(ret) => {return Ok(ret);},
                Err(err) => {
                    match err {
                        ConnErr::NoEnoughMsg => {self.packparser.recv_msg(&self.conn);},
                        _ => {panic!("parse_data err: {}", err);},
                    }
                },
            }
        }
    } 
}
