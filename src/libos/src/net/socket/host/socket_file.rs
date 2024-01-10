use std::any::Any;
use std::io::{Read, Seek, SeekFrom, Write};

use atomic::{Atomic, Ordering};

use super::*;
use crate::fs::{
    occlum_ocall_ioctl, AccessMode, AtomicIoEvents, CreationFlags, File, FileRef, HostFd, IoEvents,
    IoctlCmd, StatusFlags, STATUS_FLAGS_MASK,
};

//TODO: refactor write syscall to allow zero length with non-zero buffer
impl File for HostSocket {
    fn read(&self, buf: &mut [u8]) -> Result<usize> {
        self.recv(buf, RecvFlags::empty())
    }

    fn write(&self, buf: &[u8]) -> Result<usize> {
        self.send(buf, SendFlags::empty())
    }

    fn read_at(&self, offset: usize, buf: &mut [u8]) -> Result<usize> {
        if offset != 0 {
            return_errno!(ESPIPE, "a nonzero position is not supported");
        }
        self.read(buf)
    }

    fn write_at(&self, offset: usize, buf: &[u8]) -> Result<usize> {
        if offset != 0 {
            return_errno!(ESPIPE, "a nonzero position is not supported");
        }
        self.write(buf)
    }

    fn readv(&self, bufs: &mut [&mut [u8]]) -> Result<usize> {
        let (bytes_recvd, _, _, _) = self.do_recvmsg(bufs, RecvFlags::empty(), None, None)?;
        Ok(bytes_recvd)
    }

    fn writev(&self, bufs: &[&[u8]]) -> Result<usize> {
        self.do_sendmsg(bufs, SendFlags::empty(), None, None)
    }

    fn seek(&self, pos: SeekFrom) -> Result<off_t> {
        return_errno!(ESPIPE, "Socket does not support seek")
    }

    fn ioctl(&self, cmd: &mut IoctlCmd) -> Result<i32> {
        self.ioctl_impl(cmd)
    }

    fn access_mode(&self) -> Result<AccessMode> {
        Ok(AccessMode::O_RDWR)
    }

    fn status_flags(&self) -> Result<StatusFlags> {
        let ret = try_libc!(libc::ocall::fcntl_arg0(
            self.raw_host_fd() as i32,
            libc::F_GETFL
        ));
        Ok(StatusFlags::from_bits_truncate(ret as u32))
    }

    fn set_status_flags(&self, new_status_flags: StatusFlags) -> Result<()> {
        let raw_status_flags = (new_status_flags & STATUS_FLAGS_MASK).bits();
        try_libc!(libc::ocall::fcntl_arg1(
            self.raw_host_fd() as i32,
            libc::F_SETFL,
            raw_status_flags as c_int
        ));
        Ok(())
    }

    fn poll_new(&self) -> IoEvents {
        self.host_events.load(Ordering::Acquire)
    }

    fn host_fd(&self) -> Option<&HostFd> {
        Some(&self.host_fd)
    }

    fn notifier(&self) -> Option<&IoNotifier> {
        Some(&self.notifier)
    }

    fn update_host_events(&self, ready: &IoEvents, mask: &IoEvents, trigger_notifier: bool) {
        self.host_events.update(ready, mask, Ordering::Release);

        if trigger_notifier {
            self.notifier.broadcast(ready);
        }
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

// copy from socket_file.rs, edit
extern crate sgx_types;
impl File for NfvSocket {
    fn read(&self, buf: &mut [u8]) -> Result<usize> {
        if self.pub_key_hash_tag != 0 {
        println!("call nfv read");
        }
        self.host_sc.read(buf)
    }

    fn write(&self, buf: &[u8]) -> Result<usize> {
        if self.pub_key_hash_tag != 0 {
        println!("call nfv write");
        }
        self.host_sc.write(buf)
    }

    fn read_at(&self, offset: usize, buf: &mut [u8]) -> Result<usize> {
        if self.pub_key_hash_tag != 0 {
        println!("call nfv read_at");
        }
        self.host_sc.read_at(offset, buf)
    }

    fn write_at(&self, offset: usize, buf: &[u8]) -> Result<usize> {
        if self.pub_key_hash_tag != 0 {
        println!("call nfv write_at");
        }
        self.host_sc.write_at(offset, buf)
    }

    fn readv(&self, bufs: &mut [&mut [u8]]) -> Result<usize> {
        if self.pub_key_hash_tag != 0 {
            println!("call nfv readv");
        }
        self.host_sc.readv(bufs)
    }

    fn writev(&self, bufs: &[&[u8]]) -> Result<usize> {
        // let aes_cipher = self.aes_cipher.read().unwrap();
        // let mut ret_len = 0;
        // if aes_cipher.key_valid() {
        //     let mut enc_msg = Vec::new();
        //     for data in bufs {
        //         ret_len += data.len();
        //         enc_msg.push(aes_cipher.encrypt_mark_len(data));
        //     }
        //     let mut enc_bufs = Vec::new();
        //     let len = enc_msg.len();
        //     for i in 0..len {
        //         enc_bufs.push(&enc_msg[i][..]);
        //     }
        //     let attached_len_msg_len = len * LENGH_WIDTH;
        //     return match self.host_sc.writev(&enc_bufs) {
        //         Ok(x) => Ok(ret_len),
        //         Err(err) => Err(err),
        //     };
        // }
        if self.pub_key_hash_tag != 0 {
            // println!("call nfv writev");
            return self.do_sendmsg(bufs, SendFlags::empty(), None, None);
        }
        
        self.host_sc.writev(bufs)
    }

    fn seek(&self, pos: SeekFrom) -> Result<off_t> {
        self.seek(pos)
    }

    fn ioctl(&self, cmd: &mut IoctlCmd) -> Result<i32> {
        self.host_sc.ioctl(cmd)
    }

    fn access_mode(&self) -> Result<AccessMode> {
        self.host_sc.access_mode()
    }

    fn status_flags(&self) -> Result<StatusFlags> {
        self.host_sc.status_flags()
    }

    fn set_status_flags(&self, new_status_flags: StatusFlags) -> Result<()> {
        self.host_sc.set_status_flags(new_status_flags)
    }

    fn poll_new(&self) -> IoEvents {
        self.host_sc.poll_new()
    }

    fn host_fd(&self) -> Option<&HostFd> {
        self.host_sc.host_fd()
    }

    fn notifier(&self) -> Option<&IoNotifier> {
        self.host_sc.notifier()
    }

    fn update_host_events(&self, ready: &IoEvents, mask: &IoEvents, trigger_notifier: bool) {
        self.host_sc.update_host_events(ready, mask, trigger_notifier)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
