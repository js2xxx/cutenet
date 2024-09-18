use core::net::{IpAddr, SocketAddr};

use super::{AckResult, CongestionController, Tcb, TcpState, WithTcb};
use crate::{
    error::Error,
    route::Router,
    socket::{RxErrorKind, SocketRx},
    storage::*,
    time::{Instant, PollAt},
    wire::*,
};

#[derive(Debug, Clone)]
pub struct TcpRecv<Rx, W>
where
    Rx: SocketRx<Item = (W::Payload, TcpControl)>,
    W: WithTcb,
{
    endpoint: Ends<SocketAddr>,

    rx: Rx,
    tcb: W,
}

impl<P, Rx, W> TcpRecv<Rx, W>
where
    P: Payload,
    Rx: SocketRx<Item = (P, TcpControl)>,
    W: WithTcb<Payload = P>,
{
    pub(super) fn new(endpoint: Ends<SocketAddr>, rx: Rx, tcb: W) -> Self {
        Self { endpoint, rx, tcb }
    }
}

impl<P, Rx, W> TcpRecv<Rx, W>
where
    P: PayloadSplit + PayloadMerge,
    Rx: SocketRx<Item = (P, TcpControl)>,
    W: WithTcb<Payload = P>,
{
    pub const fn endpoints(&self) -> Ends<SocketAddr> {
        self.endpoint
    }

    pub fn accepts(&self, ip: Ends<IpAddr>, packet: TcpPacket<P>) -> bool {
        self.endpoint == ip.zip_map(packet.port, SocketAddr::new).reverse()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecvResult {
    Ok(PollAt),
    Remove,
}

impl<P, Rx, W> TcpRecv<Rx, W>
where
    P: PayloadSplit + PayloadMerge + PayloadBuild + Clone,
    Rx: SocketRx<Item = (P, TcpControl)>,
    W: WithTcb<Payload = P>,
{
    pub fn process<R: Router<P>>(
        &mut self,
        now: Instant,
        router: &mut R,
        ip: Ends<IpAddr>,
        packet: TcpPacket<P>,
        mut reply_buf: impl FnMut() -> P::NoPayload,
    ) -> RecvResult {
        let mut reply = |tcb: &Tcb<P, W::Congestion>, seq, ack, control, window, buf: Option<P>| {
            let packet = TcpPacket {
                port: self.endpoint.map(|s| s.port()),
                control,
                seq_number: seq,
                ack_number: ack,
                window_len: window,
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
                payload: PayloadHolder(0),
            };
            let buf = buf.unwrap_or_else(|| reply_buf().reserve(packet.header_len()).init());
            let packet = packet.sub_payload(|_| buf);
            (tcb.hop_limit, packet)
        };

        let (reply, res) = self.tcb.with(|tcb| {
            macro_rules! reply {
                (retx: $seq:expr, $control:expr, $buf:expr) => {{
                    reply(
                        tcb,
                        $seq,
                        Some(tcb.recv.next),
                        $control,
                        tcb.congestion.window(),
                        Some($buf)
                    )
                }};
                (challenge_ack: $($t:tt)*) => {{
                    reply(
                        tcb,
                        tcb.send.next,
                        Some(tcb.recv.next),
                        TcpControl::None,
                        $($t)*,
                        None,
                    )
                }};
                (challenge_ack) => {
                    reply!(challenge_ack: tcb.congestion.window())
                };
                (seq: $seq:expr, $control:expr $(,)?) => {{
                    reply(tcb, $seq, None, $control, tcb.congestion.window(), None)
                }};
                (seq: $seq:expr,ack: $ack:expr, $control:expr $(,)?) => {{
                    reply(tcb, $seq, Some($ack), $control, tcb.congestion.window(), None)
                }};
            }

            // (1) https://datatracker.ietf.org/doc/html/rfc9293#name-syn-sent-state, or
            // (2) https://datatracker.ietf.org/doc/html/rfc9293#name-other-states
            if tcb.timer.should_close(now) {
                tcb.state = TcpState::Closed;
            }

            if tcb.state == TcpState::Closed || !self.rx.is_connected() {
                tcb.state = TcpState::Closed;
                let reply = match packet.ack_number {
                    Some(ack) => reply!(seq: ack, TcpControl::Rst),
                    None => reply!(
                        seq: TcpSeqNumber(0),
                        ack: packet.seq_number + packet.segment_len(),
                        TcpControl::Rst,
                    ),
                };
                return (Some(reply), RecvResult::Remove);
            }

            // (2) 1. Check the sequence number.
            let Some((seq_number, mut range)) = tcb.recv.accept(
                tcb.state == TcpState::SynSent,
                packet.seq_number,
                packet.segment_len(),
            ) else {
                let reply = (packet.control != TcpControl::Rst).then(|| reply!(challenge_ack));
                return (reply, RecvResult::Ok(tcb.poll_at()));
            };
            range.end -= packet.control.len();
            let range = range;

            // (1 | 2) 2. Check for a RST.
            if packet.control == TcpControl::Rst {
                // 2-1. Check if the sequence number is out of window. Processed above.

                let reply = (seq_number != tcb.recv.next).then(|| {
                    // 2-3. Challenge ACK.
                    reply!(challenge_ack)
                });
                // 2-2. Valid RST; Reset the connection.
                tcb.state = TcpState::Closed;
                return (reply, RecvResult::Remove);
            }

            // (1 | 2) 3. Check security/compartment. TODO.

            // (1 | 2) 4. Check for a SYN.
            if packet.control == TcpControl::Syn {
                if tcb.state == TcpState::SynSent {
                    tcb.recv.next = seq_number + 1;
                    if let Some(remote_mss) = packet.max_seg_size {
                        tcb.send.remote_mss = remote_mss.into();
                        tcb.congestion.set_mss(remote_mss.into());
                    }
                } else if let Some(_timestamp) = packet.timestamp {
                    // TIME-WAIT & Timestamp enabled: Establish new connection if
                    // necessary. TODO.
                    return (None, RecvResult::Ok(tcb.poll_at()));
                } else {
                    // Challenge ACK.
                    let reply = reply!(challenge_ack);
                    tcb.state = TcpState::Closed;
                    return (Some(reply), RecvResult::Remove);
                }
            }

            // (1) 1. | (2) 5. Check for an ACK.
            let Some(ack_number) = packet.ack_number else {
                // 5-1. No ACK, drop & return.
                return (None, RecvResult::Ok(tcb.poll_at()));
            };

            // 5-2. ACK the send queue.
            match tcb.send.ack(seq_number, ack_number, packet.window_len) {
                AckResult::Ok => {
                    if !tcb.timer.is_retransmit() {
                        tcb.timer.set_for_idle(now, tcb.keep_alive);
                    }
                }
                AckResult::Duplicate(times) => {
                    tcb.congestion.on_duplicate_ack(now);
                    if times >= 3 {
                        tcb.timer.set_for_fast_retx();
                    }
                }
                AckResult::Invalid => {
                    return if tcb.state == TcpState::SynSent {
                        (
                            Some(reply!(seq: ack_number, TcpControl::Rst)),
                            RecvResult::Ok(tcb.poll_at()),
                        )
                    } else {
                        // Challenge ACK.
                        (Some(reply!(challenge_ack)), RecvResult::Ok(tcb.poll_at()))
                    };
                }
            }
            tcb.send.sack(packet.sack_ranges);
            tcb.rtte.packet_acked(now, ack_number);
            tcb.congestion.on_ack(now, packet.segment_len(), &tcb.rtte);

            let mut reply = None;

            let fin_acked = tcb.send.fin_acked();
            match (tcb.state, fin_acked) {
                // (1) 4-2. Establish the new connection.
                (TcpState::SynSent, _) => {
                    if tcb.send.unacked > tcb.send.initial {
                        tcb.state = TcpState::Established;
                        tcb.timer.set_for_idle(now, tcb.keep_alive);

                        reply = Some(reply!(challenge_ack));
                    } else {
                        // Interchanged opening (SYN-SENT => SYN-RECEIVED) not supported.
                        return (None, RecvResult::Ok(tcb.poll_at()));
                    }
                }
                // 5-3. FIN-WAIT-1 => FIN-WAIT-2.
                (TcpState::FinWait1, true) => tcb.state = TcpState::FinWait2,
                (TcpState::FinWait2, _) => {
                    // Acknowledge user's close call. TODO.
                }

                // 5-4. CLOSING => TIME-WAIT.
                (TcpState::Closing, true) => {
                    tcb.state = TcpState::TimeWait;
                    tcb.timer.set_for_close(now);
                }

                // 5-5. LAST-ACK => CLOSED.
                (TcpState::LastAck, true) => {
                    tcb.state = TcpState::Closed;
                    return (None, RecvResult::Remove);
                }
                // 5-6. TIME-WAIT: Restart the 2 MSL timeout.
                (TcpState::TimeWait, _) => tcb.timer.set_for_close(now),
                _ => {}
            }

            // 6. Check for an URG. TODO.

            // 7. Process the received payload.
            if !matches!(
                tcb.state,
                TcpState::CloseWait | TcpState::Closing | TcpState::LastAck | TcpState::TimeWait
            ) {
                if self.rx.is_full() {
                    reply = Some(reply!(challenge_ack: 0));
                } else {
                    let mut data = None;
                    let mut should_immediate_ack = false;

                    if !range.is_empty() {
                        let payload = (packet.payload.slice_into(range))
                            .unwrap_or_else(|_| unreachable!("slicing into a non-empty range"));

                        match tcb.recv.advance(seq_number, payload, packet.control) {
                            Ok((new_recv, s)) => (data, should_immediate_ack) = (new_recv, s),
                            Err(_) => reply = Some(reply!(challenge_ack: 0)),
                        }
                    }

                    if let Some(data) = data {
                        match self.rx.receive(now, ip.src, (data, packet.control)) {
                            Ok(()) => {}
                            Err(Error {
                                kind: RxErrorKind::Disconnected,
                                data: (payload, control),
                            }) => {
                                tcb.state = TcpState::Closed;
                                reply = Some(reply!(
                                    seq: TcpSeqNumber(0),
                                    ack: packet.seq_number + payload.len() + control.len(),
                                    TcpControl::Rst,
                                ))
                            }
                            Err(Error { kind: RxErrorKind::Full, .. }) => {
                                panic!("rx queue full after testing")
                            }
                        }
                    }

                    // 7-1. ACK the received data if necessary.
                    if reply.is_some() {
                        tcb.ack_delay_timer.reset();
                    } else if should_immediate_ack || tcb.ack_delay_timer.expired(now) {
                        reply = Some(reply!(challenge_ack));
                        tcb.ack_delay_timer.reset();
                    } else {
                        tcb.ack_delay_timer.activate(now);
                    }
                }
            }

            // 8. Check for a FIN.
            //
            // https://datatracker.ietf.org/doc/html/rfc9293#section-3.10.7.4-2.8.1
            if packet.control == TcpControl::Fin {
                if tcb.state == TcpState::SynSent {
                    return (reply, RecvResult::Ok(tcb.poll_at()));
                }

                match (tcb.state, fin_acked) {
                    (TcpState::Established, _) => tcb.state = TcpState::CloseWait,
                    (TcpState::FinWait1, true) => {
                        tcb.state = TcpState::TimeWait;
                        tcb.timer.set_for_close(now);
                    }
                    (TcpState::FinWait1, false) => tcb.state = TcpState::Closing,
                    (TcpState::TimeWait, _) => tcb.timer.set_for_close(now),
                    _ => {}
                }
            }

            if let Some(_delta) = tcb.timer.should_retransmit(now) {
                tcb.timer.set_for_idle(now, tcb.keep_alive);
                tcb.congestion.on_retransmit(now);

                let next = tcb.send.retx.peek(tcb.send.next).next();
                if let Some((seq, data)) = next {
                    reply = Some(reply!(retx: seq, data.control, data.payload));
                }
            }

            if reply.is_none() && tcb.timer.should_keep_alive(now) {
                reply = Some(reply!(challenge_ack));
            }

            if reply.is_some() {
                tcb.timer.rewind_keep_alive(now, tcb.keep_alive);
            }

            (reply, RecvResult::Ok(tcb.poll_at()))
        });

        let ip = ip.reverse();
        if let Some((hop_limit, reply)) = reply
            && let Ok(tx) = crate::stack::dispatch(router, now, ip, IpProtocol::Tcp)
        {
            let device_caps = tx.device_caps();

            let payload = uncheck_build!(reply.build(&(device_caps.tx_checksums, ip)));
            let packet = IpPacket::new(ip, IpProtocol::Tcp, hop_limit, payload);
            let _ = tx.comsume(now, packet);
        }

        res
    }

    pub fn poll_at(&self) -> PollAt {
        self.tcb.with(|tcb| tcb.poll_at())
    }
}
