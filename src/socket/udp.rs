use core::{fmt, net::SocketAddr, num::NonZero};

use crate::{
    iface::NetTx,
    route::Router,
    stack::dispatch,
    storage::{Buf, Storage},
    time::Instant,
    wire::*,
    TxResult,
};

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum BindError {
    AlreadyBound,
    Unaddressable,
}

impl fmt::Display for BindError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BindError::AlreadyBound => write!(f, "already bound"),
            BindError::Unaddressable => write!(f, "unaddressable"),
        }
    }
}

impl core::error::Error for BindError {}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum SendErrorKind {
    Unaddressable,
    BufferTooSmall,
    BufferExceedsMtu(usize),
    Unbound,
    NotConnected,
}

impl fmt::Display for SendErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SendErrorKind::Unaddressable => write!(f, "unaddressable"),
            SendErrorKind::BufferTooSmall => write!(f, "buffer too small"),
            SendErrorKind::BufferExceedsMtu(mtu) => write!(f, "buffer exceeds MTU: {}", mtu),
            SendErrorKind::Unbound => write!(f, "unbound"),
            SendErrorKind::NotConnected => write!(f, "not connected"),
        }
    }
}
crate::error::make_error!(SendErrorKind => pub SendError);

/// Error returned by [`Socket::recv`]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum RecvError {
    Exhausted,
    Truncated,
}

impl fmt::Display for RecvError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RecvError::Exhausted => write!(f, "exhausted"),
            RecvError::Truncated => write!(f, "truncated"),
        }
    }
}

impl core::error::Error for RecvError {}

pub struct Socket {
    addr: Option<SocketAddr>,
    peer: Option<SocketAddr>,
    hop_limit: u8,
}

impl Socket {
    pub const fn new() -> Self {
        Self {
            addr: None,
            peer: None,
            hop_limit: 64,
        }
    }

    pub fn hop_limit(&self) -> u8 {
        self.hop_limit
    }

    pub fn set_hop_limit(&mut self, hop_limit: Option<NonZero<u8>>) {
        self.hop_limit = match hop_limit {
            Some(hop_limit) => hop_limit.get(),
            None => 64,
        };
    }

    pub fn bind(&mut self, bind: SocketAddr) -> Result<(), BindError> {
        if bind.port() == 0 {
            return Err(BindError::Unaddressable);
        }
        if self.is_open() {
            return Err(BindError::AlreadyBound);
        }

        self.addr = Some(bind);

        Ok(())
    }

    pub fn is_open(&self) -> bool {
        self.addr.is_some()
    }

    pub fn send<S, R>(
        &mut self,
        now: Instant,
        router: R,
        data: Buf<S>,
    ) -> Result<TxResult, SendError<Buf<S>>>
    where
        S: Storage,
        R: Router<S>,
    {
        match self.peer {
            Some(dst) => self.send_to(now, router, dst, data),
            None => Err(SendErrorKind::NotConnected.with(data)),
        }
    }

    pub fn send_with<S, R>(
        &mut self,
        now: Instant,
        router: R,
        data: impl FnOnce(&R::Tx<'_>) -> Buf<S>,
    ) -> Result<TxResult, SendError<Option<Buf<S>>>>
    where
        S: Storage,
        R: Router<S>,
    {
        match self.peer {
            Some(dst) => self.send_to_with(now, router, dst, data),
            None => Err(SendErrorKind::NotConnected.with(None)),
        }
    }

    pub fn send_to<S, R>(
        &mut self,
        now: Instant,
        router: R,
        dst: SocketAddr,
        data: Buf<S>,
    ) -> Result<TxResult, SendError<Buf<S>>>
    where
        S: Storage,
        R: Router<S>,
    {
        let mut slot = Some(data);
        match self.send_to_with(now, router, dst, |_| slot.take().unwrap()) {
            Ok(res) => Ok(res),
            Err(err) => match err.data {
                Some(data) => Err(err.kind.with(data)),
                None => Err(err.kind.with(slot.take().unwrap())),
            },
        }
    }

    pub fn send_to_with<S, R>(
        &mut self,
        now: Instant,
        router: R,
        dst: SocketAddr,
        data: impl FnOnce(&R::Tx<'_>) -> Buf<S>,
    ) -> Result<TxResult, SendError<Option<Buf<S>>>>
    where
        S: Storage,
        R: Router<S>,
    {
        let Some(src) = self.addr else {
            return Err(SendErrorKind::Unbound.with(None));
        };

        if dst.ip().is_unspecified() || dst.port() == 0 {
            return Err(SendErrorKind::Unaddressable.with(None));
        }

        if src.is_ipv4() ^ dst.is_ipv4() {
            return Err(SendErrorKind::Unaddressable.with(None));
        }

        let ip = Ends { src, dst }.map(|s| s.ip());

        dispatch(now, router, ip, IpProtocol::Udp, |tx| {
            let data = data(tx);

            let buffer_len = data.len()
                + UDP_HEADER_LEN
                + match dst {
                    SocketAddr::V4(_) => IPV4_HEADER_LEN,
                    SocketAddr::V6(_) => IPV6_HEADER_LEN,
                };

            if buffer_len > data.capacity() {
                return Err(SendErrorKind::BufferTooSmall.with(Some(data)));
            }

            let mtu = tx.device_caps().ip_mtu;
            if buffer_len > mtu {
                return Err(SendErrorKind::BufferExceedsMtu(mtu).with(Some(data)));
            }

            let payload = |data| {
                uncheck_build!(UdpPacket {
                    port: Ends { src: src.port(), dst: dst.port() },
                    payload: data,
                }
                .build(&(tx.device_caps().tx_checksums, ip)))
            };

            let packet = match (src, dst) {
                (SocketAddr::V4(src), SocketAddr::V4(dst)) => IpPacket::V4(Ipv4Packet {
                    addr: Ends { src: *src.ip(), dst: *dst.ip() },
                    next_header: IpProtocol::Udp,
                    hop_limit: self.hop_limit,
                    frag_info: None,
                    payload: payload(data),
                }),
                (SocketAddr::V6(src), SocketAddr::V6(dst)) => IpPacket::V6(Ipv6Packet {
                    addr: Ends { src: *src.ip(), dst: *dst.ip() },
                    next_header: IpProtocol::Udp,
                    hop_limit: self.hop_limit,
                    payload: payload(data),
                }),
                _ => unreachable!(),
            };

            Ok((packet, ()))
        })
    }
}

impl Default for Socket {
    fn default() -> Self {
        Self::new()
    }
}