use core::{fmt, net::SocketAddr, num::NonZero};

use crate::{
    iface::NetTx,
    phy::DeviceCaps,
    route::Router,
    stack::{DispatchError, StackTx},
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
    PacketExceedsMtu(usize),
    Unbound,
    NotConnected,
    Dispatch(DispatchError),
}

impl fmt::Display for SendErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SendErrorKind::Unaddressable => write!(f, "unaddressable"),
            SendErrorKind::BufferTooSmall => write!(f, "buffer too small"),
            SendErrorKind::PacketExceedsMtu(mtu) => write!(f, "packet exceeds MTU: {}", mtu),
            SendErrorKind::Unbound => write!(f, "unbound"),
            SendErrorKind::NotConnected => write!(f, "not connected"),
            SendErrorKind::Dispatch(e) => write!(f, "dispatch error: {e:?}"),
        }
    }
}
crate::error::make_error!(SendErrorKind => pub SendError);

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

#[derive(Debug)]
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
}

impl Default for Socket {
    fn default() -> Self {
        Self::new()
    }
}

impl Socket {
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
}

impl Socket {
    pub fn send_data<P, R>(
        &self,
        now: Instant,
        router: &mut R,
        data: P,
    ) -> Result<TxResult, SendError<P>>
    where
        P: PayloadBuild,
        R: Router<P>,
    {
        match self.send(now, router) {
            Ok(tx) => tx.consume(now, data),
            Err(err) => Err(err.map(|_| data)),
        }
    }

    pub fn send<'router, P, R>(
        &self,
        now: Instant,
        router: &'router mut R,
    ) -> Result<SocketSend<P, R::Tx<'router>>, SendError>
    where
        P: PayloadBuild,
        R: Router<P>,
    {
        match self.peer {
            Some(dst) => self.send_to(now, router, dst),
            None => Err(SendErrorKind::NotConnected.into()),
        }
    }

    pub fn send_data_to<P, R>(
        &self,
        now: Instant,
        router: &mut R,
        dst: SocketAddr,
        data: P,
    ) -> Result<TxResult, SendError<P>>
    where
        P: PayloadBuild,
        R: Router<P>,
    {
        match self.send_to(now, router, dst) {
            Ok(tx) => tx.consume(now, data),
            Err(err) => Err(err.map(|_| data)),
        }
    }

    pub fn send_to<'router, P, R>(
        &self,
        now: Instant,
        router: &'router mut R,
        dst: SocketAddr,
    ) -> Result<SocketSend<P, R::Tx<'router>>, SendError>
    where
        P: PayloadBuild,
        R: Router<P>,
    {
        let Some(src) = self.addr else {
            return Err(SendErrorKind::Unbound.into());
        };

        if dst.ip().is_unspecified() || dst.port() == 0 {
            return Err(SendErrorKind::Unaddressable.into());
        }

        if src.is_ipv4() ^ dst.is_ipv4() {
            return Err(SendErrorKind::Unaddressable.into());
        }

        let ip = Ends { src, dst }.map(|s| s.ip());

        let tx = crate::stack::dispatch(router, now, ip, IpProtocol::Udp)
            .map_err(SendErrorKind::Dispatch)?;

        Ok(SocketSend {
            endpoint: Ends { src, dst },
            hop_limit: self.hop_limit,
            tx,
        })
    }
}

#[derive(Debug, Clone)]
pub struct SocketSend<P, Tx> {
    endpoint: Ends<SocketAddr>,
    hop_limit: u8,
    tx: StackTx<P, Tx>,
}

impl<P: PayloadBuild, Tx: NetTx<P>> SocketSend<P, Tx> {
    pub fn device_caps(&self) -> DeviceCaps {
        self.tx.device_caps()
    }

    pub fn consume(self, now: Instant, data: P) -> Result<TxResult, SendError<P>> {
        let Ends { src, dst } = self.endpoint;
        let ip = self.endpoint.map(|s| s.ip());

        let buffer_len = data.len()
            + UDP_HEADER_LEN
            + match dst {
                SocketAddr::V4(_) => IPV4_HEADER_LEN,
                SocketAddr::V6(_) => IPV6_HEADER_LEN,
            }
            + self.tx.device_caps().header_len;

        if buffer_len > data.capacity() {
            return Err(SendErrorKind::BufferTooSmall.with(data));
        }

        let mtu = self.tx.device_caps().mtu;
        if buffer_len > mtu {
            return Err(SendErrorKind::PacketExceedsMtu(mtu).with(data));
        }

        let payload = |data| {
            uncheck_build!(UdpPacket {
                port: Ends { src, dst }.map(|s| s.port()),
                payload: data,
            }
            .build(&(self.tx.device_caps().tx_checksums, ip)))
        };

        let packet = match (src, dst) {
            (SocketAddr::V4(src), SocketAddr::V4(dst)) => IpPacket::V4(Ipv4Packet {
                addr: Ends { src, dst }.map(|s| *s.ip()),
                next_header: IpProtocol::Udp,
                hop_limit: self.hop_limit,
                frag_info: None,
                payload: payload(data),
            }),
            (SocketAddr::V6(src), SocketAddr::V6(dst)) => IpPacket::V6(Ipv6Packet {
                addr: Ends { src, dst }.map(|s| *s.ip()),
                next_header: IpProtocol::Udp,
                hop_limit: self.hop_limit,
                payload: payload(data),
            }),
            _ => unreachable!(),
        };

        Ok(self.tx.comsume(now, packet))
    }
}
