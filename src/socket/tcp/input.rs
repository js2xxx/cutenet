use core::net::{IpAddr, SocketAddr};

use super::{CongestionController, TcpState, WithTcb};
use crate::{
    error::Error,
    route::Router,
    socket::{tcp::Tcb, RxErrorKind, SocketRx},
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

impl<P, Rx, W> TcpRecv<Rx, W>
where
    P: PayloadSplit + PayloadMerge,
    Rx: SocketRx<Item = (P, TcpControl)>,
    W: WithTcb<Payload = P>,
{
    pub fn process<R: Router<P>>(
        &mut self,
        now: Instant,
        #[allow(unused_variables)] router: &mut R,
        ip: Ends<IpAddr>,
        packet: TcpPacket<P>,
    ) {
        let reply = |tcb: &Tcb<P, W::Congestion>, seq, ack, control, window| TcpPacket {
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

        let reply = self.tcb.with(|tcb| {
            macro_rules! reply {
                (challenge_ack: $($t:tt)*) => {
                    reply(
                        tcb,
                        tcb.send.next,
                        Some(tcb.recv.next),
                        TcpControl::None,
                        $($t)*
                    )
                };
                (challenge_ack) => {
                    reply!(challenge_ack: tcb.congestion.window())
                };
                (seq: $seq:expr, $control:expr $(,)?) => {
                    reply(tcb, $seq, None, $control, tcb.congestion.window())
                };
                (seq: $seq:expr,ack: $ack:expr, $control:expr $(,)?) => {
                    reply(tcb, $seq, Some($ack), $control, tcb.congestion.window())
                };
            }

            // (1) https://datatracker.ietf.org/doc/html/rfc9293#name-syn-sent-state, or
            // (2) https://datatracker.ietf.org/doc/html/rfc9293#name-other-states

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
                return Some(reply);
            }

            // (2) 1. Check the sequence number.
            let Some((seq_number, mut range)) = tcb.recv.accept(
                tcb.state == TcpState::SynSent,
                packet.seq_number,
                packet.segment_len(),
            ) else {
                let reply = (packet.control != TcpControl::Rst).then(|| reply!(challenge_ack));
                return reply;
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
                return reply;
            }

            // (1 | 2) 3. Check security/compartment. TODO.

            // (1 | 2) 4. Check for a SYN.
            if packet.control == TcpControl::Syn {
                if tcb.state == TcpState::SynSent {
                    tcb.recv.next = seq_number + 1;
                } else if let Some(_timestamp) = packet.timestamp {
                    // TIME-WAIT & Timestamp enabled: Establish new connection if
                    // necessary. TODO.
                    return None;
                } else {
                    // Challenge ACK.
                    let reply = reply!(challenge_ack);
                    tcb.state = TcpState::Closed;
                    return Some(reply);
                }
            }

            // (1) 1. | (2) 5. Check for an ACK.
            let Some(ack_number) = packet.ack_number else {
                // 5-1. No ACK, drop & return.
                return None;
            };

            // 5-2. ACK the send queue.
            if !tcb.send.ack(seq_number, ack_number, packet.window_len) {
                return Some(if tcb.state == TcpState::SynSent {
                    reply!(seq: ack_number, TcpControl::Rst)
                } else {
                    // Challenge ACK.
                    reply!(challenge_ack)
                });
            }
            tcb.send.sack(packet.sack_ranges);
            tcb.rtte.packet_acked(now, ack_number);

            let mut reply = None;

            let fin_acked = tcb.send.fin_acked();
            match (tcb.state, fin_acked) {
                // (1) 4-2. Establish the new connection.
                (TcpState::SynSent, _) => {
                    if tcb.send.unacked > tcb.send.initial {
                        tcb.state = TcpState::Established;

                        reply = Some(reply!(challenge_ack));
                    } else {
                        // Interchanged opening (SYN-SENT => SYN-RECEIVED) not supported.
                        return None;
                    }
                }
                // 5-3. FIN-WAIT-1 => FIN-WAIT-2.
                (TcpState::FinWait1, true) => tcb.state = TcpState::FinWait2,
                (TcpState::FinWait2, _) => todo!("acknowledge user's close call"),

                // 5-4. CLOSING => TIME-WAIT.
                (TcpState::Closing, true) => {
                    tcb.timer.set_for_close(now);
                    tcb.state = TcpState::TimeWait
                }

                // 5-5. LAST-ACK => CLOSED.
                (TcpState::LastAck, true) => {
                    tcb.state = TcpState::Closed;
                    return None;
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
                    let mut should_ack = false;
                    if !range.is_empty() {
                        let payload = (packet.payload.slice_into(range))
                            .unwrap_or_else(|_| unreachable!("slicing into a non-empty range"));

                        match tcb.recv.advance(seq_number, payload, packet.control) {
                            Ok((new_recv, s)) => (data, should_ack) = (new_recv, s),
                            Err(_) => todo!("drop packet (ooo queue full)"),
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

                    if should_ack && reply.is_none() {
                        // 7-1. ACK the received data if necessary. TODO.
                    }
                }
            }

            // 8. Check for a FIN.
            //
            // https://datatracker.ietf.org/doc/html/rfc9293#section-3.10.7.4-2.8.1
            if packet.control == TcpControl::Fin {
                if tcb.state == TcpState::SynSent {
                    return reply;
                }

                match (tcb.state, fin_acked) {
                    (TcpState::Established, _) => tcb.state = TcpState::CloseWait,
                    (TcpState::FinWait1, true) => {
                        tcb.timer.set_for_close(now);
                        tcb.state = TcpState::TimeWait
                    }
                    (TcpState::FinWait1, false) => tcb.state = TcpState::Closing,
                    (TcpState::TimeWait, _) => tcb.timer.set_for_close(now),
                    _ => {}
                }
            }

            reply
        });

        todo!()
    }

    pub fn poll_at(&self) -> PollAt {
        self.tcb.with(|tcb| tcb.timer.poll_at())
    }
}
