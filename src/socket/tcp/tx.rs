use core::{
    fmt,
    marker::PhantomData,
    net::{IpAddr, SocketAddr},
};

use super::WithTcpState;
use crate::{
    iface::NetTx,
    route::Router,
    stack::{DispatchError, StackTx},
    storage::*,
    time::Instant,
    wire::*,
};

#[derive(Debug)]
pub enum SendErrorKind {
    BufferTooSmall,
    QueueFull,
    Dispatch(DispatchError),
}

impl fmt::Display for SendErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BufferTooSmall => write!(f, "buffer too small"),
            Self::QueueFull => write!(f, "queue full"),
            Self::Dispatch(e) => write!(f, "dispatch error: {e:?}"),
        }
    }
}

crate::error::make_error!(SendErrorKind => pub SendError);

#[derive(Debug)]
pub struct TcpStream<P: Payload, W: WithTcpState<P>> {
    endpoint: Ends<SocketAddr>,

    state: W,
    marker: PhantomData<P>,
}

impl<P: Payload, W: WithTcpState<P>> TcpStream<P, W> {
    pub(super) const fn new(endpoint: Ends<SocketAddr>, state: W) -> Self {
        Self {
            endpoint,
            state,
            marker: PhantomData,
        }
    }
}

impl<P: PayloadBuild, W: WithTcpState<P>> TcpStream<P, W> {
    pub fn send<'a, R: Router<P>>(
        &'a self,
        now: Instant,
        router: &'a mut R,
    ) -> Result<TcpSend<'a, P, W, R::Tx<'a>>, SendError> {
        let ip = self.endpoint.map(|s| s.ip());

        let tx = crate::stack::dispatch(router, now, ip, IpProtocol::Tcp)
            .map_err(SendErrorKind::Dispatch)?;

        Ok(TcpSend { stream: self, tx })
    }
}

#[derive(Debug)]
pub struct TcpSend<'a, P: Payload, W: WithTcpState<P>, N: NetTx<P>> {
    stream: &'a TcpStream<P, W>,
    tx: StackTx<P, N>,
}

impl<'a, P: PayloadBuild + PayloadSplit + Clone, W: WithTcpState<P>, N: NetTx<P>>
    TcpSend<'a, P, W, N>
{
    pub fn consume(self, now: Instant, payload: P) -> Result<Option<P>, SendError<P>> {
        let ip = self.stream.endpoint.map(|s| s.ip());
        let port = self.stream.endpoint.map(|s| s.port());
        let device_caps = self.tx.device_caps();

        let (packet, rest, hop_limit) = self.stream.state.with(|state| {
            let mut packet = TcpPacket {
                port,
                control: TcpControl::None,
                seq_number: state.send.next,
                ack_number: Some(state.recv.next),
                window_len: state.recv.window as u16,
                window_scale: None,
                max_seg_size: None,
                sack_permitted: true,
                sack_ranges: if state.send.can_sack {
                    state.recv.ooo_sack_ranges()
                } else {
                    [None; 3]
                },
                timestamp: TcpTimestamp::generate_reply_with_tsval(
                    state.timestamp_gen,
                    state.last_timestamp,
                ),
                payload,
            };

            let buffer_len = packet.buffer_len()
                + match ip.dst {
                    IpAddr::V4(_) => IPV4_HEADER_LEN,
                    IpAddr::V6(_) => IPV6_HEADER_LEN,
                }
                + device_caps.header_len;

            if buffer_len > packet.payload.capacity() {
                return Err(SendErrorKind::BufferTooSmall.with(packet.payload));
            }

            let mtu = device_caps.mtu;
            let mtu_mss = mtu + buffer_len - packet.payload_len();

            let max_len = mtu_mss.min(state.send.mss());
            let rest = packet.payload.split_off(max_len);

            let retx = packet.payload.clone();
            (state.send.advance(retx)).map_err(|p| SendErrorKind::QueueFull.with(p))?;

            Ok((packet, rest, state.hop_limit))
        })?;

        let payload = uncheck_build!(packet.build(&(device_caps.tx_checksums, ip)));
        let packet = IpPacket::new(ip, IpProtocol::Tcp, hop_limit, payload);
        let _ = self.tx.comsume(now, packet);

        Ok(rest)
    }
}
