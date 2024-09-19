use core::{
    net::{IpAddr, SocketAddr},
    ops::Range,
};

use super::{payload::Tagged, CongestionController, RecvState, SendState, Tcb, TcpState};
use crate::{
    error::Error,
    socket::{RxErrorKind, SocketRx},
    storage::*,
    time::{Instant, PollAt},
    wire::*,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecvResult {
    Ok(PollAt),
    Remove,
}

enum AckResult {
    Ok,
    Duplicate(usize),
    Invalid,
}

impl<P: PayloadSplit> SendState<P> {
    fn fin_acked(&self) -> bool {
        self.unacked > self.fin
    }

    fn ack(&mut self, seq: TcpSeqNumber, ack: TcpSeqNumber, window: usize) -> AckResult {
        let unacked = self.unacked;

        let mut is_dup = false;
        if unacked < ack && ack <= self.next {
            self.unacked = ack;
        } else if ack <= unacked {
            self.dup_acks += 1;
            is_dup = true;
        } else {
            return AckResult::Invalid;
        };

        if (unacked <= ack && ack <= self.next)
            && (self.seq_lw < seq || (self.seq_lw == seq && self.ack_lw <= ack))
        {
            self.window = window;
            self.seq_lw = seq;
            self.ack_lw = ack;
        }

        self.retx.remove(..ack);

        if is_dup {
            AckResult::Duplicate(self.dup_acks)
        } else {
            AckResult::Ok
        }
    }

    fn sack(&mut self, ranges: [Option<(TcpSeqNumber, TcpSeqNumber)>; 3]) {
        let ranges = ranges.into_iter().flatten().map(|(start, end)| start..end);
        ranges.for_each(|range| self.retx.remove(range));
    }
}

impl<P: PayloadMerge + PayloadSplit> RecvState<P> {
    fn accept(
        &self,
        is_syn_sent: bool,
        seq: TcpSeqNumber,
        segment_len: usize,
    ) -> Option<(TcpSeqNumber, Range<usize>)> {
        // NOTE: recv.next is uninit when is_syn_sent.
        if is_syn_sent {
            return Some((seq, 0..segment_len));
        }

        let seq_start = seq;
        let seq_end = seq_start + segment_len;

        let window_start = self.next;
        let window_end = self.next + self.window;

        let start = seq_start.max(window_start);
        let end = seq_end.min(window_end);

        (start <= end).then(|| {
            let segment_len = end - start;
            let offset = start - seq_start;
            (seq_start, offset..offset + segment_len)
        })
    }

    fn advance(&mut self, seq: TcpSeqNumber, p: P, c: TcpControl) -> Result<(Option<P>, bool), P> {
        if p.is_empty() {
            return Ok((None, true));
        }
        let pos = seq - self.next;

        let was_empty = self.ooo.is_empty();
        let new_recv = (self.ooo.merge(pos, Tagged::new(p, c))).map_err(|p| p.payload)?;
        let is_empty = self.ooo.is_empty();

        if let Some(ref new_recv) = new_recv {
            self.next += new_recv.len();
        }

        Ok((new_recv.map(|r| r.payload), !was_empty || !is_empty))
    }
}

impl<P, C> Tcb<P, C>
where
    P: PayloadSplit + PayloadMerge + PayloadBuild + Clone,
    C: CongestionController,
{
    pub const fn endpoints(&self) -> Ends<SocketAddr> {
        self.endpoint
    }

    pub fn accepts(&self, ip: Ends<IpAddr>, packet: TcpPacket<P>) -> bool {
        self.endpoint == ip.zip_map(packet.port, SocketAddr::new).reverse()
    }

    pub fn process(
        &mut self,
        now: Instant,
        ip: Ends<IpAddr>,
        packet: TcpPacket<P>,
        mut reply_buf: impl FnMut() -> P::NoPayload,
        rx: &mut impl SocketRx<Item = (P, TcpControl)>,
    ) -> (Option<IpPacket<TcpPacket<P>>>, RecvResult) {
        // (1) https://datatracker.ietf.org/doc/html/rfc9293#name-syn-sent-state, or
        // (2) https://datatracker.ietf.org/doc/html/rfc9293#name-other-states
        if self.timer.should_close(now) || !rx.is_connected() {
            self.state = TcpState::Closed;
        }

        if self.state == TcpState::Closed {
            let reply = match packet.ack_number {
                Some(ack) => self.rst_reply(ack, &mut reply_buf),
                None => self.rst_ack_reply(
                    TcpSeqNumber(0),
                    packet.seq_number + packet.segment_len(),
                    &mut reply_buf,
                ),
            };
            return (Some(reply), RecvResult::Remove);
        }

        // (2) 1. Check the sequence number.
        let Some((seq_number, mut range)) = self.recv.accept(
            self.state == TcpState::SynSent,
            packet.seq_number,
            packet.segment_len(),
        ) else {
            let reply =
                (packet.control != TcpControl::Rst).then(|| self.challenge_ack(&mut reply_buf));
            return (reply, RecvResult::Ok(self.poll_at()));
        };
        range.end -= packet.control.len();
        let range = range;

        // (1 | 2) 2. Check for a RST.
        if packet.control == TcpControl::Rst {
            // 2-1. Check if the sequence number is out of window. Processed above.

            let reply = (seq_number != self.recv.next).then(|| {
                // 2-3. Challenge ACK.
                self.challenge_ack(&mut reply_buf)
            });
            // 2-2. Valid RST; Reset the connection.
            self.state = TcpState::Closed;
            return (reply, RecvResult::Remove);
        }

        // (1 | 2) 3. Check security/compartment. TODO.

        // (1 | 2) 4. Check for a SYN.
        if packet.control == TcpControl::Syn {
            if self.state == TcpState::SynSent {
                self.recv.next = seq_number + 1;
                if let Some(remote_mss) = packet.max_seg_size {
                    self.send.remote_mss = remote_mss.into();
                    self.congestion.set_mss(remote_mss.into());
                }
            } else if let Some(_timestamp) = packet.timestamp {
                // TIME-WAIT & Timestamp enabled: Establish new connection if
                // necessary. TODO.
                return (None, RecvResult::Ok(self.poll_at()));
            } else {
                // Challenge ACK.
                let reply = self.challenge_ack(&mut reply_buf);
                self.state = TcpState::Closed;
                return (Some(reply), RecvResult::Remove);
            }
        }

        // (1) 1. | (2) 5. Check for an ACK.
        let Some(ack_number) = packet.ack_number else {
            // 5-1. No ACK, drop & return.
            return (None, RecvResult::Ok(self.poll_at()));
        };

        // 5-2. ACK the send queue.
        match self.send.ack(seq_number, ack_number, packet.window_len) {
            AckResult::Ok => {
                if !self.timer.is_retransmit() {
                    self.timer.set_for_idle(now, self.keep_alive);
                }
            }
            AckResult::Duplicate(times) => {
                self.congestion.on_duplicate_ack(now);
                if times >= 3 {
                    self.timer.set_for_fast_retx();
                }
            }
            AckResult::Invalid => {
                return if self.state == TcpState::SynSent {
                    (
                        Some(self.rst_reply(ack_number, &mut reply_buf)),
                        RecvResult::Ok(self.poll_at()),
                    )
                } else {
                    // Challenge ACK.
                    (
                        Some(self.challenge_ack(&mut reply_buf)),
                        RecvResult::Ok(self.poll_at()),
                    )
                };
            }
        }
        self.send.sack(packet.sack_ranges);
        self.rtte.packet_acked(now, ack_number);
        self.congestion
            .on_ack(now, packet.segment_len(), &self.rtte);

        let mut reply = None;

        let fin_acked = self.send.fin_acked();
        match (self.state, fin_acked) {
            // (1) 4-2. Establish the new connection.
            (TcpState::SynSent, _) => {
                if self.send.unacked > self.send.initial {
                    self.state = TcpState::Established;
                    self.timer.set_for_idle(now, self.keep_alive);

                    reply = Some(self.challenge_ack(&mut reply_buf));
                } else {
                    // Interchanged opening (SYN-SENT => SYN-RECEIVED) not supported.
                    return (None, RecvResult::Ok(self.poll_at()));
                }
            }
            // 5-3. FIN-WAIT-1 => FIN-WAIT-2.
            (TcpState::FinWait1, true) => self.state = TcpState::FinWait2,
            (TcpState::FinWait2, _) => {
                // Acknowledge user's close call. TODO.
            }

            // 5-4. CLOSING => TIME-WAIT.
            (TcpState::Closing, true) => {
                self.state = TcpState::TimeWait;
                self.timer.set_for_close(now);
            }

            // 5-5. LAST-ACK => CLOSED.
            (TcpState::LastAck, true) => {
                self.state = TcpState::Closed;
                return (None, RecvResult::Remove);
            }
            // 5-6. TIME-WAIT: Restart the 2 MSL timeout.
            (TcpState::TimeWait, _) => self.timer.set_for_close(now),
            _ => {}
        }

        // 6. Check for an URG. TODO.

        // 7. Process the received payload.
        if !matches!(
            self.state,
            TcpState::CloseWait | TcpState::Closing | TcpState::LastAck | TcpState::TimeWait
        ) {
            if rx.is_full() {
                reply = Some(self.challenge_ack_congested(&mut reply_buf));
            } else {
                let mut data = None;
                let mut should_immediate_ack = false;

                if !range.is_empty() {
                    let payload = (packet.payload.slice_into(range))
                        .unwrap_or_else(|_| unreachable!("slicing into a non-empty range"));

                    match self.recv.advance(seq_number, payload, packet.control) {
                        Ok((new_recv, s)) => (data, should_immediate_ack) = (new_recv, s),
                        Err(_) => reply = Some(self.challenge_ack_congested(&mut reply_buf)),
                    }
                }

                if let Some(data) = data {
                    match rx.receive(now, ip.src, (data, packet.control)) {
                        Ok(()) => {}
                        Err(Error {
                            kind: RxErrorKind::Disconnected,
                            data: (payload, control),
                        }) => {
                            self.state = TcpState::Closed;
                            reply = Some(self.rst_ack_reply(
                                TcpSeqNumber(0),
                                packet.seq_number + payload.len() + control.len(),
                                &mut reply_buf,
                            ))
                        }
                        Err(Error { kind: RxErrorKind::Full, .. }) => {
                            panic!("rx queue full after testing")
                        }
                    }
                }

                // 7-1. ACK the received data if necessary.
                if reply.is_some() {
                    self.ack_delay_timer.reset();
                } else if should_immediate_ack || self.ack_delay_timer.expired(now) {
                    reply = Some(self.challenge_ack(&mut reply_buf));
                    self.ack_delay_timer.reset();
                } else {
                    self.ack_delay_timer.activate(now);
                }
            }
        }

        // 8. Check for a FIN.
        //
        // https://datatracker.ietf.org/doc/html/rfc9293#section-3.10.7.4-2.8.1
        if packet.control == TcpControl::Fin {
            if self.state == TcpState::SynSent {
                return (reply, RecvResult::Ok(self.poll_at()));
            }

            match (self.state, fin_acked) {
                (TcpState::Established, _) => self.state = TcpState::CloseWait,
                (TcpState::FinWait1, true) => {
                    self.state = TcpState::TimeWait;
                    self.timer.set_for_close(now);
                }
                (TcpState::FinWait1, false) => self.state = TcpState::Closing,
                (TcpState::TimeWait, _) => self.timer.set_for_close(now),
                _ => {}
            }
        }

        if let Some(_delta) = self.timer.should_retransmit(now) {
            self.timer.set_for_idle(now, self.keep_alive);
            self.congestion.on_retransmit(now);

            let next = self.send.retx.peek(self.send.next).next();
            if let Some((seq, data)) = next {
                reply = Some(self.retx_reply(seq, data.control, data.payload));
            }
        }

        if reply.is_none() && self.timer.should_keep_alive(now) {
            reply = Some(self.challenge_ack(&mut reply_buf));
        }

        if reply.is_some() {
            self.timer.rewind_keep_alive(now, self.keep_alive);
        }

        (reply, RecvResult::Ok(self.poll_at()))
    }

    pub fn poll_timeout(
        &mut self,
        now: Instant,
        mut reply_buf: impl FnMut() -> P::NoPayload,
        rx: &impl SocketRx<Item = (P, TcpControl)>,
    ) -> (Option<IpPacket<TcpPacket<P>>>, RecvResult) {
        // https://datatracker.ietf.org/doc/html/rfc9293#name-timeouts

        if self.timer.should_close(now) || rx.is_connected() {
            self.state = TcpState::Closed;
            return (None, RecvResult::Remove);
        }

        let reply = (self.timer.should_retransmit(now))
            .and_then(|_| {
                self.timer.set_for_idle(now, self.keep_alive);
                self.congestion.on_retransmit(now);

                let next = self.send.retx.peek(self.send.next).next();
                next.map(|(seq, data)| self.retx_reply(seq, data.control, data.payload))
            })
            .or_else(|| {
                (self.ack_delay_timer.expired(now) || self.timer.should_keep_alive(now))
                    .then(|| self.challenge_ack(&mut reply_buf))
            });

        if reply.is_some() {
            self.ack_delay_timer.reset();
            self.timer.rewind_keep_alive(now, self.keep_alive);
        }

        (reply, RecvResult::Ok(self.poll_at()))
    }
}

impl<P, C> Tcb<P, C>
where
    P: PayloadSplit + PayloadMerge + PayloadBuild + Clone,
    C: CongestionController,
{
    fn reply(
        &self,
        seq: TcpSeqNumber,
        ack: Option<TcpSeqNumber>,
        control: TcpControl,
        window: usize,
        buf: impl FnOnce(usize) -> P,
    ) -> IpPacket<TcpPacket<P>> {
        let packet = TcpPacket {
            port: self.endpoint.map(|s| s.port()),
            control,
            seq_number: seq,
            ack_number: ack,
            window_len: window,
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
            payload: PayloadHolder(0),
        };
        let buf = buf(packet.header_len());
        let packet = packet.sub_payload(|_| buf);
        let ip = self.endpoint.map(|s| s.ip());
        IpPacket::new(ip, IpProtocol::Tcp, self.hop_limit, packet)
    }

    fn challenge_ack(&self, mut reply_buf: impl FnMut() -> P::NoPayload) -> IpPacket<TcpPacket<P>> {
        self.reply(
            self.send.next,
            Some(self.recv.next),
            TcpControl::None,
            self.congestion.window(),
            |header_len| reply_buf().reserve(header_len).init(),
        )
    }

    fn challenge_ack_congested(
        &self,
        mut reply_buf: impl FnMut() -> P::NoPayload,
    ) -> IpPacket<TcpPacket<P>> {
        self.reply(
            self.send.next,
            Some(self.recv.next),
            TcpControl::None,
            0,
            |header_len| reply_buf().reserve(header_len).init(),
        )
    }

    fn rst_reply(
        &self,
        seq: TcpSeqNumber,
        mut reply_buf: impl FnMut() -> P::NoPayload,
    ) -> IpPacket<TcpPacket<P>> {
        self.reply(
            seq,
            None,
            TcpControl::Rst,
            self.congestion.window(),
            |header_len| reply_buf().reserve(header_len).init(),
        )
    }

    fn rst_ack_reply(
        &self,
        seq: TcpSeqNumber,
        ack: TcpSeqNumber,
        mut reply_buf: impl FnMut() -> P::NoPayload,
    ) -> IpPacket<TcpPacket<P>> {
        self.reply(seq, Some(ack), TcpControl::Rst, 0, |header_len| {
            reply_buf().reserve(header_len).init()
        })
    }

    fn retx_reply(&self, seq: TcpSeqNumber, control: TcpControl, buf: P) -> IpPacket<TcpPacket<P>> {
        let window = self.congestion.window();
        self.reply(seq, Some(self.recv.next), control, window, |_| buf)
    }
}
