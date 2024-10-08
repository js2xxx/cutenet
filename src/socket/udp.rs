use core::{
    fmt,
    net::{IpAddr, SocketAddr},
    num::NonZero,
};

use super::{RxError, RxErrorKind, SocketRx};
use crate::{
    iface::NetTx,
    phy::DeviceCaps,
    route::Router,
    stack::{DispatchError, StackTx},
    storage::*,
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
pub struct UdpSocket {
    addr: SocketAddr,
    peer: Option<SocketAddr>,
    hop_limit: u8,
}

impl UdpSocket {
    pub fn bind<P, Rx>(bind: SocketAddr, rx: Rx) -> Option<(Self, UdpRecv<P, Rx>)>
    where
        P: Payload,
        Rx: SocketRx<Item = P>,
    {
        (bind.port() != 0).then(|| {
            (
                UdpSocket {
                    addr: bind,
                    peer: None,
                    hop_limit: 64,
                },
                UdpRecv { addr: bind, peer: None, rx },
            )
        })
    }
}

impl UdpSocket {
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
    ) -> Option<UdpRecv<P, Rx>> {
        (peer.port() != 0).then(|| {
            self.peer = Some(peer);

            UdpRecv {
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

impl UdpSocket {
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
    ) -> Result<UdpSend<P, R::Tx<'router>>, SendError> {
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
    ) -> Result<UdpSend<P, R::Tx<'router>>, SendError> {
        let src = self.addr;

        if dst.ip().is_unspecified() || dst.port() == 0 {
            return Err(SendErrorKind::Unaddressable.into());
        }

        if src.ip().version() != dst.ip().version() {
            return Err(SendErrorKind::Unaddressable.into());
        }

        let ip = Ends { src, dst }.map(|s| s.ip());

        let tx = crate::stack::dispatch(router, now, ip, IpProtocol::Udp)
            .map_err(SendErrorKind::Dispatch)?;

        Ok(UdpSend {
            endpoint: Ends { src, dst },
            hop_limit: self.hop_limit,
            tx,
        })
    }
}

#[derive(Debug, Clone)]
pub struct UdpSend<P, Tx> {
    endpoint: Ends<SocketAddr>,
    hop_limit: u8,
    tx: StackTx<P, Tx>,
}

impl<P: PayloadBuild, Tx: NetTx<P>> UdpSend<P, Tx> {
    pub fn device_caps(&self) -> DeviceCaps {
        self.tx.device_caps()
    }

    pub fn consume(self, now: Instant, payload: P) -> Result<TxResult, SendError<P>> {
        let ip = self.endpoint.map(|s| s.ip());
        let port = self.endpoint.map(|s| s.port());

        let device_caps = self.tx.device_caps();

        let buffer_len = payload.len() + device_caps.header_len(self.endpoint, UDP_HEADER_LEN);
        if buffer_len > payload.capacity() {
            return Err(SendErrorKind::BufferTooSmall.with(payload));
        }

        let mtu = device_caps.mtu;
        if buffer_len > mtu {
            return Err(SendErrorKind::PacketExceedsMtu(mtu).with(payload));
        }

        let cx = &(device_caps.tx_checksums, ip);
        let payload = uncheck_build!(UdpPacket { port, payload }.build(cx));

        let packet = IpPacket::new(ip, IpProtocol::Udp, self.hop_limit, payload);
        Ok(self.tx.comsume(now, packet))
    }
}

#[derive(Debug)]
pub struct UdpRecv<P, Rx>
where
    P: Payload,
    Rx: SocketRx<Item = P> + ?Sized,
{
    addr: SocketAddr,
    peer: Option<SocketAddr>,
    rx: Rx,
}

impl<P, Rx> UdpRecv<P, Rx>
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

        if self.rx.is_full() {
            return Ok(());
        }

        if !self.accepts(ip.zip_map(packet.port, SocketAddr::new)) {
            return Err(RecvErrorKind::NotAccepted.with(packet));
        }

        match self.rx.receive(now, ip.src, packet.payload) {
            Ok(()) | Err(RxError { kind: RxErrorKind::Full, .. }) => Ok(()),
            Err(RxError {
                kind: RxErrorKind::Disconnected,
                data,
            }) => {
                packet.payload = data;
                Err(RecvErrorKind::Disconnected.with(packet))
            }
        }
    }
}
