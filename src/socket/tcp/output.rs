use core::{fmt, net::SocketAddr, time::Duration};

use super::{
    CongestionController, RecvState, SendState, Tcb, TcpConfig, TcpRecv, TcpState, WithTcb,
};
use crate::{
    iface::NetTx,
    route::Router,
    socket::SocketRx,
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
pub struct TcpStream<W: WithTcb> {
    endpoint: Ends<SocketAddr>,
    tcb: W,
}

impl<W: WithTcb> TcpStream<W> {
    pub(super) const fn new(endpoint: Ends<SocketAddr>, tcb: W) -> Self {
        Self { endpoint, tcb }
    }

    pub fn ack_delay(&self) -> Option<Duration> {
        self.tcb.with(|tcb| tcb.ack_delay_timer.delay())
    }

    pub fn set_ack_delay(&mut self, delay: Option<Duration>) {
        self.tcb.with(|tcb| tcb.ack_delay_timer.set_delay(delay))
    }

    pub fn keep_alive(&self) -> Option<Duration> {
        self.tcb.with(|tcb| tcb.keep_alive)
    }

    pub fn set_keep_alive(&mut self, delay: Option<Duration>) {
        self.tcb.with(|tcb| {
            tcb.keep_alive = delay;
            if delay.is_some() {
                tcb.timer.set_keep_alive();
            }
        })
    }
}

impl<P, W> TcpStream<W>
where
    W: WithTcb<Payload = P>,
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
        P: PayloadSplit + Clone,
        R: Router<P>,
        Rx: SocketRx<Item = (P, TcpControl)>,
    {
        let ip = endpoint.map(|s| s.ip());
        let tx = match crate::stack::dispatch(router, now, ip, IpProtocol::Tcp) {
            Ok(tx) => tx,
            Err(e) => return Err(SendErrorKind::Dispatch(e).with(buf.init())),
        };
        let device_caps = tx.device_caps();

        let config = config();

        let tcb = W::new(Tcb {
            state: TcpState::SynSent,
            send: SendState {
                initial: init_seq,
                fin: TcpSeqNumber(u32::MAX),
                unacked: init_seq,
                next: init_seq + 1,
                window: config.congestion.window(),
                seq_lw: TcpSeqNumber(0),
                ack_lw: init_seq,
                dup_acks: 0,
                retx: Default::default(),
                remote_mss: usize::MAX,
                can_sack: false,
            },
            recv: RecvState {
                next: TcpSeqNumber(0),
                window: config.congestion.window(),
                ooo: Default::default(),
            },
            hop_limit: config.hop_limit,
            congestion: config.congestion,
            rtte: Default::default(),
            keep_alive: None,
            timer: Default::default(),
            ack_delay_timer: Default::default(),
            timestamp_gen: config.timestamp_gen,
            last_timestamp: 0,
        });

        let stream = TcpStream::new(endpoint, tcb.clone());
        let recv = TcpRecv::new(endpoint, config.packet_rx, tcb);

        TcpSend { stream: &stream, tx }.consume_packet(now, |port, tcb| {
            Some(TcpPacket {
                port,
                control: TcpControl::Syn,
                seq_number: init_seq,
                ack_number: None,
                window_len: tcb.congestion.window(),
                max_seg_size: Some(device_caps.mss(ip, TCP_HEADER_LEN)),
                sack_permitted: true,
                sack_ranges: [None; 3],
                timestamp: TcpTimestamp::generate_reply_with_tsval(config.timestamp_gen, 0),
                payload: buf.init(),
            })
        })?;

        Ok((stream, recv))
    }

    pub fn send_data<R>(
        &self,
        now: Instant,
        router: &mut R,
        push: bool,
        data: P,
    ) -> Result<Option<P>, SendError<P>>
    where
        P: PayloadSplit + Clone,
        R: Router<P>,
    {
        match self.send(now, router) {
            Ok(tx) => tx.consume(now, push, data),
            Err(e) => Err(e.kind.with(data)),
        }
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

    pub fn close<R: Router<P>>(
        &self,
        now: Instant,
        router: &mut R,
        buf: P::NoPayload,
    ) -> Result<(), SendError<P>>
    where
        P: PayloadSplit + Clone,
    {
        match self.send(now, router) {
            Ok(tx) => (tx.consume_packet(now, |port, tcb| {
                match tcb.state {
                    TcpState::SynSent => {
                        tcb.state = TcpState::Closed;
                        return None;
                    }
                    TcpState::Established => tcb.state = TcpState::FinWait1,
                    TcpState::CloseWait => tcb.state = TcpState::LastAck,
                    TcpState::FinWait1
                    | TcpState::FinWait2
                    | TcpState::Closing
                    | TcpState::LastAck
                    | TcpState::TimeWait
                    | TcpState::Closed => return None,
                }

                Some(TcpPacket {
                    port,
                    control: TcpControl::Fin,
                    seq_number: tcb.send.next,
                    ack_number: Some(tcb.recv.next),
                    window_len: tcb.recv.window,
                    max_seg_size: None,
                    sack_permitted: true,
                    sack_ranges: if tcb.send.can_sack {
                        tcb.recv.sack_ranges()
                    } else {
                        [None; 3]
                    },
                    timestamp: TcpTimestamp::generate_reply_with_tsval(
                        tcb.timestamp_gen,
                        tcb.last_timestamp,
                    ),
                    payload: buf.init(),
                })
            }))
            .map(drop),
            Err(err) => Err(err.kind.with(buf.init())),
        }
    }
}

#[derive(Debug)]
pub struct TcpSend<'a, P: Payload, W: WithTcb<Payload = P>, N: NetTx<P>> {
    stream: &'a TcpStream<W>,
    tx: StackTx<P, N>,
}

impl<'a, P, W, N> TcpSend<'a, P, W, N>
where
    P: PayloadBuild + PayloadSplit + Clone,
    W: WithTcb<Payload = P>,
    N: NetTx<P>,
{
    pub fn consume(self, now: Instant, push: bool, payload: P) -> Result<Option<P>, SendError<P>> {
        self.consume_packet(now, |port, tcb| {
            Some(TcpPacket {
                port,
                control: if push {
                    TcpControl::Psh
                } else {
                    TcpControl::None
                },
                seq_number: tcb.send.next,
                ack_number: Some(tcb.recv.next),
                window_len: tcb.recv.window,
                max_seg_size: None,
                sack_permitted: true,
                sack_ranges: if tcb.send.can_sack {
                    tcb.recv.sack_ranges()
                } else {
                    [None; 3]
                },
                timestamp: TcpTimestamp::generate_reply_with_tsval(
                    tcb.timestamp_gen,
                    tcb.last_timestamp,
                ),
                payload,
            })
        })
    }

    fn consume_packet(
        self,
        now: Instant,
        packet: impl FnOnce(Ends<u16>, &mut Tcb<P, W::Congestion>) -> Option<TcpPacket<P>>,
    ) -> Result<Option<P>, SendError<P>> {
        let ip = self.stream.endpoint.map(|s| s.ip());
        let port = self.stream.endpoint.map(|s| s.port());

        let device_caps = self.tx.device_caps();

        if let Some((packet, rest, hop_limit)) = self.stream.tcb.with(|tcb| {
            let Some(mut packet) = packet(port, tcb) else {
                return Ok(None);
            };
            let control = packet.control;

            tcb.congestion.pre_transmit(now);

            let buffer_len = packet.payload_len() + device_caps.header_len(ip, packet.header_len());
            if buffer_len > packet.payload.capacity() {
                return Err(SendErrorKind::BufferTooSmall.with(packet.payload));
            }

            let mtu_mss = usize::from(device_caps.mss(ip, packet.header_len()));

            let max_len = mtu_mss.min(tcb.send.mss()).min(tcb.congestion.window());
            let rest = packet.payload.split_off(max_len);

            let retx = packet.payload.clone();
            (tcb.send.advance(retx, control)).map_err(|p| SendErrorKind::QueueFull.with(p))?;
            tcb.timer.set_for_retx(now, tcb.rtte.retx_timeout());

            tcb.congestion.post_transmit(now, packet.payload_len());
            tcb.rtte.packet_sent(now, tcb.send.next);
            tcb.timer.rewind_keep_alive(now, tcb.keep_alive);
            tcb.ack_delay_timer.reset();

            Ok(Some((packet, rest, tcb.hop_limit)))
        })? {
            let payload = uncheck_build!(packet.build(&(device_caps.tx_checksums, ip)));
            let packet = IpPacket::new(ip, IpProtocol::Tcp, hop_limit, payload);
            let _ = self.tx.comsume(now, packet);

            return Ok(rest);
        }
        Ok(None)
    }
}
