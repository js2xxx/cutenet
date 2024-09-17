use core::{
    hash::BuildHasher,
    net::{IpAddr, SocketAddr},
};

use super::{
    CongestionController, RecvError, RecvErrorKind, RecvState, SendState, Tcb, TcpConfig, TcpRecv,
    TcpState, TcpStream, WithTcb,
};
use crate::{route::Router, socket::SocketRx, storage::*, time::Instant, wire::*};

pub type ConnResult<P, Rx, W> = Result<Option<TcpRecv<Rx, W>>, RecvError<TcpPacket<P>>>
where
    P: PayloadBuild,
    Rx: SocketRx<Item = P>,
    W: WithTcb<Payload = P>;

#[derive(Debug)]
pub struct TcpListener<Rx, H: BuildHasher> {
    addr: SocketAddr,
    hop_limit: u8,

    sack_enabled: bool,
    timestamp_gen: Option<TcpTimestampGenerator>,

    pub(super) seq_hasher: H,
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

impl<Rx, H: BuildHasher> TcpListener<Rx, H> {
    pub fn process<P, R, Rx2, C, W>(
        &mut self,
        now: Instant,
        router: &mut R,
        ip: Ends<IpAddr>,
        packet: TcpPacket<P>,
        config: impl FnOnce() -> TcpConfig<P, C, Rx2>,
    ) -> ConnResult<P, Rx2, W>
    where
        P: PayloadBuild,
        Rx: SocketRx<Item = TcpStream<W>>,
        C: CongestionController,
        R: Router<P>,
        Rx2: SocketRx<Item = P>,
        W: WithTcb<Payload = P, Congestion = C>,
    {
        if !self.rx.is_connected() {
            return Err(RecvErrorKind::Disconnected.with(packet));
        }

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

    fn establish<P, C, Rx2, W>(
        &mut self,
        now: Instant,
        ip: Ends<IpAddr>,
        packet: TcpPacket<P>,
        config: impl FnOnce() -> TcpConfig<P, C, Rx2>,
    ) -> ConnResult<P, Rx2, W>
    where
        P: PayloadBuild,
        C: CongestionController,
        Rx: SocketRx<Item = TcpStream<W>>,
        Rx2: SocketRx<Item = P>,
        W: WithTcb<Payload = P, Congestion = C>,
    {
        if !self.rx.is_connected() {
            return Err(RecvErrorKind::Disconnected.with(packet));
        }

        if self.rx.is_full() {
            todo!("reply RST")
        }

        let Some((mss, can_sack)) = self.check_seq_number(now, ip, &packet) else {
            return Err(RecvErrorKind::NotAccepted.with(packet));
        };

        let endpoint = ip.zip_map(packet.port, SocketAddr::new).reverse();

        let config = config();
        let tcb = W::new(Tcb {
            state: TcpState::Established,
            send: SendState {
                initial: packet.ack_number.unwrap(),
                fin: TcpSeqNumber(u32::MAX),
                unacked: packet.ack_number.unwrap(),
                next: packet.ack_number.unwrap(),
                window: config.congestion.window(),
                seq_lw: packet.seq_number,
                ack_lw: packet.ack_number.unwrap(),
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
            timer: Default::default(),
            timestamp_gen: config.timestamp_gen,
            last_timestamp: packet.timestamp.map_or(0, |t| t.tsval),
        });

        let conn = TcpStream::new(endpoint, tcb.clone());

        Ok(match self.rx.receive(now, ip.dst, conn) {
            Ok(()) => Some(TcpRecv::new(endpoint, config.packet_rx, tcb)),
            Err(_) => None,
        })
    }
}
