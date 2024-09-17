use core::{
    fmt,
    marker::PhantomData,
    net::{IpAddr, SocketAddr},
};

use super::{TcpConfig, TcpRecv, WithTcpState};
use crate::{
    iface::NetTx,
    route::Router,
    socket::{tcp::CongestionController, SocketRx},
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
pub struct TcpStream<W: WithTcpState> {
    endpoint: Ends<SocketAddr>,

    state: W,
}

impl<W: WithTcpState> TcpStream<W> {
    pub(super) const fn new(endpoint: Ends<SocketAddr>, state: W) -> Self {
        Self { endpoint, state }
    }
}

impl<P, W> TcpStream<W>
where
    W: WithTcpState<Payload = P>,
    P: PayloadBuild,
{
    pub fn connect<R, Rx>(
        now: Instant,
        router: &mut R,
        endpoint: Ends<SocketAddr>,
        buf: P::NoPayload,
        init_seq: TcpSeqNumber,
        config: impl FnOnce() -> TcpConfig<P, W::Congestion, Rx>,
    ) -> Result<(Self, TcpRecv<Rx, W>), SendError<P>>
    where
        R: Router<P>,
        Rx: SocketRx<Item = P>,
    {
        let ip = endpoint.map(|s| s.ip());
        let port = endpoint.map(|s| s.port());

        let tx = match crate::stack::dispatch(router, now, ip, IpProtocol::Tcp) {
            Ok(tx) => tx,
            Err(e) => return Err(SendErrorKind::Dispatch(e).with(buf.init())),
        };
        let device_caps = tx.device_caps();

        let config = config();

        let packet = TcpPacket {
            port,
            control: TcpControl::Syn,
            seq_number: init_seq,
            ack_number: None,
            window_len: config.congestion.window(),
            max_seg_size: Some(device_caps.mss(ip, TCP_HEADER_LEN)),
            sack_permitted: true,
            sack_ranges: [None; 3],
            timestamp: TcpTimestamp::generate_reply_with_tsval(config.timestamp_gen, 0),
            payload: buf.init(),
        };
        todo!()
    }

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
pub struct TcpSend<'a, P: Payload, W: WithTcpState<Payload = P>, N: NetTx<P>> {
    stream: &'a TcpStream<W>,
    tx: StackTx<P, N>,
}

impl<'a, P, W, N> TcpSend<'a, P, W, N>
where
    P: PayloadBuild + PayloadSplit + Clone,
    W: WithTcpState<Payload = P>,
    N: NetTx<P>,
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
                window_len: state.recv.window,
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

            let buffer_len = packet.payload_len() + device_caps.header_len(ip, packet.header_len());
            if buffer_len > packet.payload.capacity() {
                return Err(SendErrorKind::BufferTooSmall.with(packet.payload));
            }

            let mtu_mss = usize::from(device_caps.mss(ip, packet.header_len()));

            let max_len = mtu_mss.min(state.send.mss());
            let rest = packet.payload.split_off(max_len);

            let retx = packet.payload.clone();
            (state.send.advance(retx)).map_err(|p| SendErrorKind::QueueFull.with(p))?;
            state.timer.set_for_retx(now, state.rtte.retx_timeout());

            state.rtte.packet_sent(now, state.send.next);
            Ok((packet, rest, state.hop_limit))
        })?;

        let payload = uncheck_build!(packet.build(&(device_caps.tx_checksums, ip)));
        let packet = IpPacket::new(ip, IpProtocol::Tcp, hop_limit, payload);
        let _ = self.tx.comsume(now, packet);

        Ok(rest)
    }
}
