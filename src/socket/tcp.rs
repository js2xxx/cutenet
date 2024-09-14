use core::{
    fmt,
    hash::BuildHasher,
    net::{IpAddr, SocketAddr},
};

use super::SocketRx;
use crate::{route::Router, time::Instant, wire::*};

mod seq_number;

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

#[cfg(feature = "alloc")]
type Deque<T> = alloc::collections::VecDeque<T>;
#[cfg(not(feature = "alloc"))]
type Deque<T> = heapless::Deque<T, crate::config::STATIC_TCP_BUFFER_CAPACITY>;

#[derive(Debug, Default)]
pub struct TcpState {}

pub trait WithTcpState: Clone {
    fn with<T, F>(&mut self, f: F) -> T
    where
        F: FnOnce(&mut TcpState) -> T;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpConfig<W, P, R>
where
    W: WithTcpState,
    P: Payload,
    R: SocketRx<Item = P>,
{
    pub state: W,
    pub packet_rx: R,
}

#[derive(Debug)]
pub struct TcpListener<Rx, H: BuildHasher> {
    addr: SocketAddr,
    hop_limit: u8,

    sack_enabled: bool,
    timestamp_gen: Option<TcpTimestampGenerator>,

    seq_hasher: H,
    rx: Rx,
}

impl<Rx, H: BuildHasher> TcpListener<Rx, H> {
    pub const fn local(&self) -> SocketAddr {
        self.addr
    }

    pub fn accepts(&self, addr: Ends<SocketAddr>) -> bool {
        if self.addr.port() != addr.dst.port() {
            return false;
        }

        if addr.dst.ip().is_unicast() && addr.dst.ip() != self.addr.ip() {
            return false;
        }

        true
    }
}

pub type ProcessResult<P, Rx, W> = Result<Option<TcpRx<P, Rx, W>>, RecvError<TcpPacket<P>>>
where
    P: PayloadBuild,
    Rx: SocketRx<Item = P>,
    W: WithTcpState;

impl<Rx, H: BuildHasher> TcpListener<Rx, H> {
    pub fn process<P, R, Rx2, W>(
        &mut self,
        now: Instant,
        router: &mut R,
        ip: Ends<IpAddr>,
        packet: TcpPacket<P>,
        config: impl FnOnce() -> TcpConfig<W, P, Rx2>,
    ) -> ProcessResult<P, Rx2, W>
    where
        P: PayloadBuild,
        Rx: SocketRx<Item = TcpStream<P, W>>,
        R: Router<P>,
        Rx2: SocketRx<Item = P>,
        W: WithTcpState,
    {
        if !self.rx.is_connected() {
            return Err(RecvErrorKind::Disconnected.with(packet));
        }

        if !self.accepts(ip.zip_map(packet.port, SocketAddr::new)) {
            return Err(RecvErrorKind::NotAccepted.with(packet));
        }

        self.sack_enabled = packet.sack_permitted;

        match packet.control {
            TcpControl::Syn => self.reply_synack(now, router, ip, packet),
            TcpControl::None | TcpControl::Psh => return self.establish(now, ip, packet, config),
            TcpControl::Fin | TcpControl::Rst => {
                return Err(RecvErrorKind::NotAccepted.with(packet))
            }
        }
        Ok(None)
    }

    fn reply_synack<P, R>(
        &mut self,
        now: Instant,
        router: &mut R,
        ip: Ends<IpAddr>,
        packet: TcpPacket<P>,
    ) where
        P: PayloadBuild,
        R: Router<P>,
    {
        let reply_ip = ip.reverse();
        let Ok(tx) = crate::stack::dispatch(router, now, reply_ip, IpProtocol::Tcp) else {
            return;
        };
        let device_caps = tx.device_caps();

        let header_len = TCP_HEADER_LEN
            + match reply_ip.dst {
                IpAddr::V4(_) => IPV4_HEADER_LEN,
                IpAddr::V6(_) => IPV6_HEADER_LEN,
            }
            + device_caps.header_len;

        let mss = device_caps.mtu - header_len;

        let payload = uncheck_build!(TcpPacket {
            port: packet.port.reverse(),
            control: TcpControl::Syn,
            seq_number: self.seq_number(now, ip, &packet),
            ack_number: Some(packet.seq_number + 1),
            window_len: 0,
            window_scale: None,
            max_seg_size: Some(mss as u16),
            sack_permitted: self.sack_enabled,
            sack_ranges: [None; 3],
            timestamp: (packet.timestamp).and_then(|t| t.generate_reply(self.timestamp_gen)),
            payload: packet.payload,
        }
        .build(&(reply_ip, device_caps.tx_checksums)));

        let reply = IpPacket::new(reply_ip, IpProtocol::Tcp, self.hop_limit, payload);
        let _res = tx.comsume(now, reply);
    }

    fn establish<P, Rx2, W>(
        &mut self,
        now: Instant,
        ip: Ends<IpAddr>,
        packet: TcpPacket<P>,
        config: impl FnOnce() -> TcpConfig<W, P, Rx2>,
    ) -> ProcessResult<P, Rx2, W>
    where
        P: PayloadBuild,
        Rx: SocketRx<Item = TcpStream<P, W>>,
        Rx2: SocketRx<Item = P>,
        W: WithTcpState,
    {
        #[allow(unused)]
        let Some(mss) = self.check_seq_number(now, ip, &packet) else {
            return Err(RecvErrorKind::NotAccepted.with(packet));
        };

        if !self.rx.is_connected() {
            return Err(RecvErrorKind::Disconnected.with(packet));
        }

        let config = config();
        let state = config.state;

        let conn = TcpStream {
            send_queue: Deque::new(),
            state: state.clone(),
        };

        Ok(match self.rx.receive(now, ip.dst, conn) {
            Ok(()) => Some(TcpRx {
                recv_queue: Deque::new(),
                rx: config.packet_rx,
                state,
            }),
            Err(_) => None,
        })
    }
}

#[allow(unused)]
pub struct TcpStream<P: Payload, W: WithTcpState> {
    send_queue: Deque<P>,
    state: W,
}

#[allow(unused)]
pub struct TcpRx<P: Payload, Rx: SocketRx<Item = P>, W: WithTcpState> {
    recv_queue: Deque<P>,
    rx: Rx,
    state: W,
}
