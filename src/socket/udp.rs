use core::{
    fmt,
    net::{IpAddr, SocketAddr},
    num::NonZero,
};

use super::SocketRx;
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
pub enum SendErrorKind {
    Unaddressable,
    BufferTooSmall,
    PacketExceedsMtu(usize),
    NotConnected,
    Dispatch(DispatchError),
}

impl fmt::Display for SendErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SendErrorKind::Unaddressable => write!(f, "unaddressable"),
            SendErrorKind::BufferTooSmall => write!(f, "buffer too small"),
            SendErrorKind::PacketExceedsMtu(mtu) => write!(f, "packet exceeds MTU: {}", mtu),
            SendErrorKind::NotConnected => write!(f, "not connected"),
            SendErrorKind::Dispatch(e) => write!(f, "dispatch error: {e:?}"),
        }
    }
}
crate::error::make_error!(SendErrorKind => pub SendError);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecvErrorKind {
    Disconnected,
    NotAccepted,
}
crate::error::make_error!(RecvErrorKind => pub RecvError);

impl fmt::Display for RecvErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RecvErrorKind::Disconnected => write!(f, "disconnected"),
            RecvErrorKind::NotAccepted => write!(f, "not accepted"),
        }
    }
}

#[derive(Debug)]
pub struct Socket {
    addr: SocketAddr,
    peer: Option<SocketAddr>,
    hop_limit: u8,
}

impl Socket {
    pub fn bind<P, Rx>(bind: SocketAddr, rx: Rx) -> Option<(Self, SocketRecv<P, Rx>)>
    where
        P: Payload,
        Rx: SocketRx<Item = P>,
    {
        (bind.port() != 0).then(|| {
            (
                Socket {
                    addr: bind,
                    peer: None,
                    hop_limit: 64,
                },
                SocketRecv { addr: bind, peer: None, rx },
            )
        })
    }
}

impl Socket {
    pub const fn local(&self) -> SocketAddr {
        self.addr
    }

    pub const fn peer(&self) -> Option<SocketAddr> {
        self.peer
    }

    pub const fn hop_limit(&self) -> u8 {
        self.hop_limit
    }

    pub fn set_hop_limit(&mut self, hop_limit: Option<NonZero<u8>>) {
        self.hop_limit = match hop_limit {
            Some(hop_limit) => hop_limit.get(),
            None => 64,
        };
    }

    pub fn connect<P: Payload, Rx: SocketRx<Item = P>>(
        &mut self,
        peer: SocketAddr,
        rx: Rx,
    ) -> Option<SocketRecv<P, Rx>> {
        (peer.port() != 0).then(|| {
            self.peer = Some(peer);

            SocketRecv {
                addr: self.addr,
                peer: self.peer,
                rx,
            }
        })
    }

    pub const fn is_connected(&self) -> bool {
        self.peer.is_some()
    }
}

impl Socket {
    pub fn send_data<P: PayloadBuild, R: Router<P>>(
        &self,
        now: Instant,
        router: &mut R,
        data: P,
    ) -> Result<TxResult, SendError<P>> {
        match self.send(now, router) {
            Ok(tx) => tx.consume(now, data),
            Err(err) => Err(err.map(|_| data)),
        }
    }

    pub fn send<'router, P: PayloadBuild, R: Router<P>>(
        &self,
        now: Instant,
        router: &'router mut R,
    ) -> Result<SocketSend<P, R::Tx<'router>>, SendError> {
        match self.peer {
            Some(dst) => self.send_to(now, router, dst),
            None => Err(SendErrorKind::NotConnected.into()),
        }
    }

    pub fn send_data_to<P: PayloadBuild, R: Router<P>>(
        &self,
        now: Instant,
        router: &mut R,
        dst: SocketAddr,
        data: P,
    ) -> Result<TxResult, SendError<P>> {
        match self.send_to(now, router, dst) {
            Ok(tx) => tx.consume(now, data),
            Err(err) => Err(err.map(|_| data)),
        }
    }

    pub fn send_to<'router, P: PayloadBuild, R: Router<P>>(
        &self,
        now: Instant,
        router: &'router mut R,
        dst: SocketAddr,
    ) -> Result<SocketSend<P, R::Tx<'router>>, SendError> {
        let src = self.addr;

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

#[derive(Debug)]
pub struct SocketRecv<P, Rx>
where
    P: Payload,
    Rx: SocketRx<Item = P> + ?Sized,
{
    addr: SocketAddr,
    peer: Option<SocketAddr>,
    rx: Rx,
}

impl<P, Rx> SocketRecv<P, Rx>
where
    P: Payload,
    Rx: SocketRx<Item = P> + ?Sized,
{
    pub const fn local(&self) -> SocketAddr {
        self.addr
    }

    pub const fn peer(&self) -> Option<SocketAddr> {
        self.peer
    }

    pub fn is_connected(&self) -> bool {
        self.rx.is_connected()
    }

    pub fn accepts(&self, addr: Ends<SocketAddr>) -> bool {
        if self.addr.port() != addr.dst.port() {
            return false;
        }

        if addr.dst.ip().is_unicast() && addr.dst.ip() != self.addr.ip() {
            return false;
        }

        if self.peer.is_some_and(|peer| peer != addr.src) {
            return false;
        }

        true
    }

    pub fn process(
        &mut self,
        now: Instant,
        ip: Ends<IpAddr>,
        mut packet: UdpPacket<P>,
    ) -> Result<(), RecvError<UdpPacket<P>>> {
        if !self.rx.is_connected() {
            return Err(RecvErrorKind::Disconnected.with(packet));
        }

        if !self.accepts(ip.zip_map(packet.port, SocketAddr::new)) {
            return Err(RecvErrorKind::NotAccepted.with(packet));
        }

        match self.rx.receive(now, ip.src, packet.payload) {
            Ok(()) => Ok(()),
            Err(payload) => {
                packet.payload = payload;
                Err(RecvErrorKind::Disconnected.with(packet))
            }
        }
    }
}
