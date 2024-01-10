use super::*;
use std::io::Write;
use std::net::TcpStream;
use msg_recver::ConnErr;

pub fn send_msg(mut conn: &TcpStream, msg: &[u8], len: usize) -> Result<usize, ConnErr> {
    let mut msg_send = Vec::from(len.to_be_bytes());
    msg_send.append(&mut Vec::from(msg));
    // println!("{:?}", msg_send);
    match conn.write(&msg_send) {
        Ok(len) => Ok(len),
        Err(err) => Err(ConnErr::SendFail),
    }
}