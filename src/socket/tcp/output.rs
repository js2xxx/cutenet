use core::ops::DerefMut;

use super::{
    payload::Tagged, CongestionController, SendError, SendErrorKind, SendState, Tcb, TcpState,
};
use crate::{
    iface::NetTx, phy::DeviceCaps, route::Router, stack::StackTx, storage::*, time::Instant,
    wire::*, TxResult,
};

impl<P: PayloadSplit> SendState<P> {
    fn mss(&self) -> usize {
        let window_mss = self.unacked + self.window - self.next;
        self.remote_mss.min(window_mss)
    }

    fn advance(&mut self, p: P, c: TcpControl) -> Result<(), P> {
        let tagged = Tagged::new(p, c);
        let len = tagged.len();
        self.retx.push(self.next, tagged).map_err(|t| t.payload)?;
        if c == TcpControl::Fin {
            self.fin = self.next;
        }
        self.next += len;
        Ok(())
    }
}

pub trait TcpStream<P, C>: DerefMut<Target = Tcb<P, C>> + Sized {
    fn send_data<R: Router<P>>(
        self,
        now: Instant,
        router: &mut R,
        push: bool,
        data: P,
    ) -> Result<(TxResult, Option<P>), SendError<P>>
    where
        P: PayloadSplit + PayloadMerge + PayloadBuild + Clone,
        C: CongestionController,
    {
        match self.send(now, router) {
            Ok(tx) => tx.consume_data(now, push, data),
            Err(err) => Err(err.kind.with(data)),
        }
    }

    fn send<R: Router<P>>(
        self,
        now: Instant,
        router: &mut R,
    ) -> Result<TcpSend<Self, P, R::Tx<'_>>, SendError>
    where
        P: PayloadSplit + PayloadMerge + PayloadBuild + Clone,
        C: CongestionController,
    {
        if !self.may_send() {
            return Err(SendErrorKind::InvalidState(self.state).into());
        }
        let ip = self.endpoint.map(|s| s.ip());

        let tx = crate::stack::dispatch(router, now, ip, IpProtocol::Tcp)
            .map_err(SendErrorKind::Dispatch)?;

        Ok(TcpSend::new(self, tx))
    }

    fn close<R: Router<P>>(
        mut self,
        now: Instant,
        router: &mut R,
        buf: P::NoPayload,
    ) -> Result<(), SendError<P>>
    where
        P: PayloadSplit + PayloadMerge + PayloadBuild + Clone,
        C: CongestionController,
    {
        match self.state {
            TcpState::SynSent => {
                self.state = TcpState::Closed;
                return Ok(());
            }
            TcpState::Established => self.state = TcpState::FinWait1,
            TcpState::CloseWait => self.state = TcpState::LastAck,
            TcpState::FinWait1
            | TcpState::FinWait2
            | TcpState::Closing
            | TcpState::LastAck
            | TcpState::TimeWait
            | TcpState::Closed => return Ok(()),
        }

        match self.send(now, router) {
            Ok(tx) => {
                let packet = TcpPacket {
                    port: tx.obj.endpoint.map(|s| s.port()),
                    control: TcpControl::Fin,
                    seq_number: tx.obj.send.next,
                    ack_number: Some(tx.obj.recv.next),
                    window_len: tx.obj.recv.window,
                    max_seg_size: None,
                    sack_permitted: true,
                    sack_ranges: if tx.obj.send.can_sack {
                        tx.obj.recv.sack_ranges()
                    } else {
                        [None; 3]
                    },
                    timestamp: TcpTimestamp::generate_reply_with_tsval(
                        tx.obj.timestamp_gen,
                        tx.obj.last_timestamp,
                    ),
                    payload: buf.init(),
                };
                let _ = tx.packet(now, packet)?.consume(now);
                Ok(())
            }
            Err(err) => Err(err.kind.with(buf.init())),
        }
    }
}

impl<W: DerefMut<Target = Tcb<P, C>>, P, C> TcpStream<P, C> for W {}

#[derive(Debug)]
pub struct TcpSend<T, P, Tx> {
    obj: T,
    tx: StackTx<P, Tx>,
}

pub type TcpSendPacket<P, Tx> = TcpSend<(IpPacket<TcpPacket<P>>, Option<P>), P, Tx>;

impl<P, C> Tcb<P, C>
where
    P: PayloadSplit + PayloadMerge + PayloadBuild + Clone,
    C: CongestionController,
{
    fn packet(&self, push: bool, payload: P) -> TcpPacket<P> {
        TcpPacket {
            port: self.endpoint.map(|s| s.port()),
            control: if push {
                TcpControl::Psh
            } else {
                TcpControl::None
            },
            seq_number: self.send.next,
            ack_number: Some(self.recv.next),
            window_len: self.recv.window,
            max_seg_size: None,
            sack_permitted: true,
            sack_ranges: if self.send.can_sack {
                self.recv.sack_ranges()
            } else {
                [None; 3]
            },
            timestamp: TcpTimestamp::generate_reply_with_tsval(
                self.timestamp_gen,
                self.last_timestamp,
            ),
            payload,
        }
    }

    fn prepare_send(
        &mut self,
        now: Instant,
        device_caps: &DeviceCaps,
        packet: &mut TcpPacket<P>,
    ) -> Result<Option<P>, SendError> {
        let control = packet.control;
        let ip = self.endpoint.map(|s| s.ip());

        self.congestion.pre_transmit(now);

        let buffer_len = packet.payload_len() + device_caps.header_len(ip, packet.header_len());
        if buffer_len > packet.payload.capacity() {
            return Err(SendErrorKind::BufferTooSmall.into());
        }

        let mtu_mss = usize::from(device_caps.mss(ip, packet.header_len()));

        let max_len = mtu_mss.min(self.send.mss()).min(self.congestion.window());
        let rest = packet.payload.split_off(max_len);

        let retx = packet.payload.clone();
        (self.send.advance(retx, control)).map_err(|_| SendErrorKind::QueueFull)?;
        self.timer.set_for_retx(now, self.rtte.retx_timeout());

        self.congestion.post_transmit(now, packet.payload_len());
        self.rtte.packet_sent(now, self.send.next);
        self.timer.rewind_keep_alive(now, self.keep_alive);
        self.ack_delay_timer.reset();

        Ok(rest)
    }
}

impl<T, P, Tx> TcpSend<T, P, Tx> {
    pub(super) fn new(obj: T, tx: StackTx<P, Tx>) -> Self {
        Self { obj, tx }
    }
}

impl<W, P, C, Tx> TcpSend<W, P, Tx>
where
    W: DerefMut<Target = Tcb<P, C>>,
    P: PayloadSplit + PayloadMerge + PayloadBuild + Clone,
    C: CongestionController,
    Tx: NetTx<P>,
{
    pub(super) fn packet(
        self,
        now: Instant,
        mut packet: TcpPacket<P>,
    ) -> Result<TcpSendPacket<P, Tx>, SendError<P>> {
        let TcpSend { obj: mut tcb, tx } = self;
        let device_caps = tx.device_caps();

        match tcb.prepare_send(now, &device_caps, &mut packet) {
            Ok(rest) => {
                let packet = IpPacket::new(
                    tcb.endpoint.map(|s| s.ip()),
                    IpProtocol::Tcp,
                    tcb.hop_limit,
                    packet,
                );
                Ok(TcpSend { obj: (packet, rest), tx })
            }
            Err(e) => Err(e.kind.with(packet.payload)),
        }
    }

    pub fn data(
        self,
        now: Instant,
        push: bool,
        payload: P,
    ) -> Result<TcpSendPacket<P, Tx>, SendError<P>> {
        let packet = self.obj.packet(push, payload);
        self.packet(now, packet)
    }

    pub fn consume_data(
        self,
        now: Instant,
        push: bool,
        payload: P,
    ) -> Result<(TxResult, Option<P>), SendError<P>> {
        let t = self.data(now, push, payload)?;
        Ok(t.consume(now))
    }
}

impl<P, Tx> TcpSendPacket<P, Tx>
where
    P: PayloadBuild,
    Tx: NetTx<P>,
{
    pub fn rest(&mut self) -> Option<P> {
        self.obj.1.take()
    }

    pub fn consume(self, now: Instant) -> (TxResult, Option<P>) {
        let TcpSend { obj: (packet, rest), tx } = self;
        let device_caps = tx.device_caps();

        let packet =
            packet.map_wire(|tcp, ip| uncheck_build!(tcp.build(&(device_caps.tx_checksums, ip))));
        let res = tx.comsume(now, packet);
        (res, rest)
    }
}
