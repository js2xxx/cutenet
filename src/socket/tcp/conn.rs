use core::{
    hash::BuildHasher,
    net::{IpAddr, SocketAddr},
};

use super::{
    CongestionController, RecvError, RecvErrorKind, RecvState, SendError, SendErrorKind, SendState,
    Tcb, TcpConfig, TcpSend, TcpState,
};
use crate::{route::Router, socket::SocketRx, storage::*, time::Instant, wire::*};

#[derive(Debug)]
pub struct TcpListener<H: BuildHasher> {
    addr: SocketAddr,
    hop_limit: u8,

    sack_enabled: bool,
    timestamp_gen: Option<TcpTimestampGenerator>,

    pub(super) seq_hasher: H,
}

impl<H: BuildHasher> TcpListener<H> {
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

impl<H: BuildHasher> TcpListener<H> {
    pub fn process<P, R, C>(
        &mut self,
        now: Instant,
        router: &mut R,
        ip: Ends<IpAddr>,
        packet: TcpPacket<P>,
        config: impl FnOnce() -> TcpConfig<C>,
    ) -> Result<Option<Tcb<P, C>>, RecvError<TcpPacket<P>>>
    where
        P: PayloadBuild,
        C: CongestionController,
        R: Router<P>,
    {
        if !self.accepts(ip.zip_map(packet.port, SocketAddr::new)) {
            return Err(RecvErrorKind::NotAccepted.with(packet));
        }

        self.sack_enabled = packet.sack_permitted;

        // 1. https://datatracker.ietf.org/doc/html/rfc9293#name-listen-state
        // 2. https://datatracker.ietf.org/doc/html/rfc9293#name-other-states, for
        //    SYN-RECEIVED state.
        match packet.control {
            // 1-1. Check for a RST.
            TcpControl::Rst => return Err(RecvErrorKind::NotAccepted.with(packet)),

            // 1-2. Check for an ACK.
            //
            // - If ACK & !SYN, it might be an establishment packet, so we don't handle at this
            //   branch;
            // - If ACK & SYN, we don't reply RST here because there might be other established
            //   connections.
            TcpControl::Syn if packet.ack_number.is_some() => {
                return Err(RecvErrorKind::NotAccepted.with(packet))
            }

            // 1-3. Check for a SYN.
            TcpControl::Syn => self.reply_synack(now, router, ip, packet),

            // 2. Establishment packets.
            TcpControl::Fin | TcpControl::None | TcpControl::Psh => {
                return self.establish(now, ip, packet, config)
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

        let payload = uncheck_build!(TcpPacket {
            port: packet.port.reverse(),
            control: TcpControl::Syn,
            seq_number: self.seq_number(now, ip, &packet),
            ack_number: Some(packet.seq_number + 1),
            window_len: 0,
            max_seg_size: Some(device_caps.mss(reply_ip, TCP_HEADER_LEN)),
            sack_permitted: self.sack_enabled,
            sack_ranges: [None; 3],
            timestamp: (packet.timestamp).and_then(|t| t.generate_reply(self.timestamp_gen)),
            payload: packet.payload,
        }
        .build(&(reply_ip, device_caps.tx_checksums)));

        let reply = IpPacket::new(reply_ip, IpProtocol::Tcp, self.hop_limit, payload);
        let _res = tx.comsume(now, reply);
    }

    fn establish<P, C>(
        &mut self,
        now: Instant,
        ip: Ends<IpAddr>,
        packet: TcpPacket<P>,
        config: impl FnOnce() -> TcpConfig<C>,
    ) -> Result<Option<Tcb<P, C>>, RecvError<TcpPacket<P>>>
    where
        P: PayloadBuild,
        C: CongestionController,
    {
        let Some((mss, can_sack)) = self.check_seq_number(now, ip, &packet) else {
            return Err(RecvErrorKind::NotAccepted.with(packet));
        };

        let endpoint = ip.zip_map(packet.port, SocketAddr::new).reverse();

        let mut config = config();
        config.congestion.set_mss(usize::from(mss));

        Ok(Some(Tcb::establish(
            endpoint, &packet, config, mss, can_sack,
        )))
    }
}

impl<P, C> Tcb<P, C>
where
    P: Payload,
    C: CongestionController,
{
    fn establish(
        endpoint: Ends<SocketAddr>,
        packet: &TcpPacket<P>,
        config: TcpConfig<C>,
        mss: u16,
        can_sack: bool,
    ) -> Tcb<P, C>
    where
        C: CongestionController,
    {
        Tcb {
            endpoint,
            state: TcpState::Established,
            send: SendState {
                initial: packet.ack_number.unwrap(),
                fin: TcpSeqNumber(u32::MAX),
                unacked: packet.ack_number.unwrap(),
                next: packet.ack_number.unwrap(),
                window: config.congestion.window(),
                seq_lw: packet.seq_number,
                ack_lw: packet.ack_number.unwrap(),
                dup_acks: 0,
                retx: Default::default(),
                remote_mss: usize::from(mss),
                can_sack,
            },
            recv: RecvState {
                next: packet.seq_number,
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
            last_timestamp: packet.timestamp.map_or(0, |t| t.tsval),
        }
    }
}

impl<P, C> Tcb<P, C>
where
    P: PayloadSplit + PayloadMerge + PayloadBuild + Clone,
    C: CongestionController,
{
    pub fn connect<R, Rx>(
        now: Instant,
        router: &mut R,
        endpoint: Ends<SocketAddr>,
        buf: P::NoPayload,
        init_seq: TcpSeqNumber,
        config: impl FnOnce() -> TcpConfig<C>,
    ) -> Result<Self, SendError<P>>
    where
        R: Router<P>,
        Rx: SocketRx<Item = (P, TcpControl)>,
    {
        let ip = endpoint.map(|s| s.ip());
        let port = endpoint.map(|s| s.port());

        let tx = match crate::stack::dispatch(router, now, ip, IpProtocol::Tcp) {
            Ok(tx) => tx,
            Err(e) => return Err(SendErrorKind::Dispatch(e).with(buf.init())),
        };
        let device_caps = tx.device_caps();

        let config = config();

        let mut tcb = Tcb {
            endpoint,
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
        };

        let syn = TcpPacket {
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
        };
        let _ = TcpSend::new(&mut tcb, tx).packet(now, syn)?.consume(now);

        Ok(tcb)
    }
}
