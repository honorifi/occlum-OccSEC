use super::*;
use std;
use untrusted::{SliceAsMutPtrAndLen, SliceAsPtrAndLen, UntrustedSlice, UntrustedSliceAlloc};

pub use self::io_multiplexing::{
    clear_notifier_status, notify_thread, wait_for_notification, EpollEvent, IoEvent, PollEvent,
    PollEventFlags, PollFd, THREAD_NOTIFIERS,
};
pub use self::socket::{
    mmsghdr, msghdr, msghdr_mut, socketpair, unix_socket, AddressFamily, AsUnixSocket, FileFlags,
    HostSocket, /*HostSocketType, edit by kxc ->*/ NfvSocket, NfvSocketType,/*<-edit by kxc*/ HowToShut, Iovs, IovsMut, MsgHdr, MsgHdrFlags, MsgHdrMut,
    RecvFlags, SendFlags, SliceAsLibcIovec, SockAddr, SocketType, UnixAddr,
};
pub use self::tls::{client, comm, server, tls_test};
pub use self::syscalls::*;

mod io_multiplexing;
mod socket;
mod tls;
mod syscalls;
