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

#[derive(Debug)]
pub struct TcpListener<P, Rx, H>
where
    P: Payload,
    Rx: SocketRx<Item = TcpStream<P>>,
    H: BuildHasher,
{
    addr: SocketAddr,
    hop_limit: u8,

    sack_enabled: bool,
    timestamp_gen: Option<TcpTimestampGenerator>,

    seq_hasher: H,
    rx: Rx,
}

impl<P, Rx, H> TcpListener<P, Rx, H>
where
    P: Payload,
    Rx: SocketRx<Item = TcpStream<P>>,
    H: BuildHasher,
{
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

impl<P, Rx, H> TcpListener<P, Rx, H>
where
    P: PayloadBuild,
    Rx: SocketRx<Item = TcpStream<P>>,
    H: BuildHasher,
{
    pub fn process<R: Router<P>, Rx2: SocketRx<Item = P>>(
        &mut self,
        now: Instant,
        router: &mut R,
        ip: Ends<IpAddr>,
        packet: TcpPacket<P>,
        new_rx: impl FnOnce() -> Rx2,
    ) -> Result<Option<TcpRx<P, Rx2>>, RecvError<TcpPacket<P>>> {
        if !self.rx.is_connected() {
            return Err(RecvErrorKind::Disconnected.with(packet));
        }

        if !self.accepts(ip.zip_map(packet.port, SocketAddr::new)) {
            return Err(RecvErrorKind::NotAccepted.with(packet));
        }

        self.sack_enabled = packet.sack_permitted;

        match packet.control {
            TcpControl::Syn => {
                let reply_ip = ip.reverse();
                let Ok(tx) = crate::stack::dispatch(router, now, reply_ip, IpProtocol::Tcp) else {
                    return Ok(None);
                };
                let device_caps = tx.device_caps();

                let header_len = TCP_HEADER_LEN
                    + match reply_ip.dst {
                        IpAddr::V4(_) => IPV4_HEADER_LEN,
                        IpAddr::V6(_) => IPV6_HEADER_LEN,
                    }
                    + device_caps.header_len;

                let mss = device_caps.mtu - header_len;

                let reply = TcpPacket {
                    port: packet.port.reverse(),
                    control: TcpControl::Syn,
                    seq_number: self.seq_number(now, ip, &packet),
                    ack_number: Some(packet.seq_number + 1),
                    window_len: 0,
                    window_scale: None,
                    max_seg_size: Some(mss as u16),
                    sack_permitted: self.sack_enabled,
                    sack_ranges: [None; 3],
                    timestamp: (packet.timestamp)
                        .and_then(|t| t.generate_reply(self.timestamp_gen)),
                    payload: packet.payload,
                };

                let reply = match (reply_ip.src, reply_ip.dst) {
                    (IpAddr::V4(src), IpAddr::V4(dst)) => IpPacket::V4(Ipv4Packet {
                        addr: Ends { src, dst },
                        next_header: IpProtocol::Tcp,
                        hop_limit: self.hop_limit,
                        frag_info: None,
                        payload: uncheck_build!(reply.build(&(reply_ip, device_caps))),
                    }),
                    (IpAddr::V6(src), IpAddr::V6(dst)) => IpPacket::V6(Ipv6Packet {
                        addr: Ends { src, dst },
                        next_header: IpProtocol::Tcp,
                        hop_limit: self.hop_limit,
                        payload: uncheck_build!(reply.build(&(reply_ip, device_caps))),
                    }),
                    _ => unreachable!(),
                };

                let _res = tx.comsume(now, reply);
            }
            TcpControl::None | TcpControl::Psh => {
                #[allow(unused)]
                let Some(mss) = self.check_seq_number(now, ip, &packet) else {
                    return Err(RecvErrorKind::NotAccepted.with(packet));
                };

                if !self.rx.is_connected() {
                    return Err(RecvErrorKind::Disconnected.with(packet));
                }

                let conn = TcpStream { send_queue: Deque::new() };

                if let Ok(()) = self.rx.receive(now, ip.dst, conn) {
                    return Ok(Some(TcpRx {
                        recv_queue: Deque::new(),
                        rx: new_rx(),
                    }));
                }
            }
            TcpControl::Fin | TcpControl::Rst => {
                return Err(RecvErrorKind::NotAccepted.with(packet))
            }
        }

        Ok(None)
    }
}

#[allow(unused)]
pub struct TcpStream<P: Payload> {
    send_queue: Deque<P>,
}

#[allow(unused)]
pub struct TcpRx<P: Payload, Rx: SocketRx<Item = P>> {
    recv_queue: Deque<P>,
    rx: Rx,
}
