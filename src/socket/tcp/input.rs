use core::{
    net::{IpAddr, SocketAddr},
    ops::Range,
};

use super::{RecvState, WithTcb};
use crate::{
    route::Router,
    socket::SocketRx,
    storage::*,
    time::{Instant, PollAt},
    wire::*,
};

impl<P> RecvState<P> {
    fn accept(&self, seq: TcpSeqNumber, len: usize) -> Option<(TcpSeqNumber, Range<usize>)> {
        let seq_start = seq;
        let seq_end = seq_start + len;

        let window_start = self.next;
        let window_end = self.next + self.window;

        let start = seq_start.max(window_start);
        let end = seq_end.min(window_end);

        (start <= end).then(|| {
            let len = end - start;
            let offset = start - seq_start;
            (seq_start, offset..offset + len)
        })
    }
}

impl<P: PayloadMerge + PayloadSplit> RecvState<P> {
    fn advance(&mut self, seq: TcpSeqNumber, payload: P) -> Result<(Option<P>, bool), P> {
        let pos = seq - self.next;
        let new_recv = self.ooo.merge(pos, payload)?;

        if let Some(ref new_recv) = new_recv {
            self.next += new_recv.len();
        }

        Ok((new_recv, true))
    }
}

#[derive(Debug, Clone)]
pub struct TcpRecv<Rx, W>
where
    Rx: SocketRx<Item = W::Payload>,
    W: WithTcb,
{
    endpoint: Ends<SocketAddr>,

    rx: Rx,
    tcb: W,
}

impl<P, Rx, W> TcpRecv<Rx, W>
where
    P: Payload,
    Rx: SocketRx<Item = P>,
    W: WithTcb<Payload = P>,
{
    pub(super) fn new(endpoint: Ends<SocketAddr>, rx: Rx, tcb: W) -> Self {
        Self { endpoint, rx, tcb }
    }
}

impl<P, Rx, W> TcpRecv<Rx, W>
where
    P: PayloadSplit + PayloadMerge,
    Rx: SocketRx<Item = P>,
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
    Rx: SocketRx<Item = P>,
    W: WithTcb<Payload = P>,
{
    pub fn process<R: Router<P>>(
        &mut self,
        now: Instant,
        #[allow(unused_variables)] router: &mut R,
        ip: Ends<IpAddr>,
        packet: TcpPacket<P>,
    ) {
        // https://datatracker.ietf.org/doc/html/rfc9293#name-other-states

        let data = self.tcb.with(|tcb| {
            let mut data = None;

            // 1. Check the sequence number.
            //
            // https://datatracker.ietf.org/doc/html/rfc9293#section-3.10.7.4-2.1.1
            let Some((seq_number, range)) =
                tcb.recv.accept(packet.seq_number, packet.payload.len())
            else {
                if packet.control == TcpControl::Rst {
                    // Simply drop the RST packet and return.
                    return None;
                } else {
                    todo!("<SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>; drop & return")
                }
            };

            // 2. Check for a RST.
            //
            // https://datatracker.ietf.org/doc/html/rfc9293#section-3.10.7.4-2.2.1
            if packet.control == TcpControl::Rst {
                // 2-1. Check if the sequence number is out of window. Processed above.

                if seq_number == tcb.recv.next {
                    // 2-2. Valid RST; Reset the connection.
                    todo!("reset the connection")
                } else {
                    // 2-3. Challenge ACK.
                    todo!(
                        "<SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>;\n\
                        reset the connection"
                    )
                }
            }

            // 3. Check security/compartment. TODO.
            //
            // https://datatracker.ietf.org/doc/html/rfc9293#section-3.10.7.4-2.3.1

            // 4. Check for a SYN.
            //
            // https://datatracker.ietf.org/doc/html/rfc9293#section-3.10.7.4-2.4.1
            if packet.control == TcpControl::Syn {
                if let Some(timestamp) = packet.timestamp {
                    // TIME-WAIT & Timestamp enabled: Establish new connection if
                    // necessary.
                    todo!("TIME-WAIT & {timestamp:?} enabled")
                } else {
                    // Challenge ACK.
                    todo!(
                        "<SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>;\n\
                        reset the connection"
                    )
                }
            }

            // 5. Check for an ACK.
            //
            // https://datatracker.ietf.org/doc/html/rfc9293#section-3.10.7.4-2.5.1
            let Some(ack_number) = packet.ack_number else {
                // 5-1. No ACK, drop & return.
                return None;
            };

            // 5-2. ACK the send queue.
            if !tcb.send.ack(seq_number, ack_number, packet.window_len) {
                // Challenge ACK.
                todo!("<SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>")
            }
            tcb.send.sack(packet.sack_ranges);
            tcb.rtte.packet_acked(now, ack_number);

            // 5-3. FIN-WAIT-1 => FIN-WAIT-2. TODO.
            // 5-4. CLOSING => TIME-WAIT. TODO.
            // 5-5. LAST-ACK => CLOSED. TODO.
            // 5-6. TIME-WAIT: Restart the 2 MSL timeout. TODO.

            // 6. Check for an URG. TODO.

            // 7. Process the received payload.
            let mut should_ack = false;
            if !range.is_empty() {
                let payload = (packet.payload.slice_into(range))
                    .unwrap_or_else(|_| unreachable!("slicing into a non-empty range"));

                match tcb.recv.advance(seq_number, payload) {
                    Ok((new_recv, s)) => (data, should_ack) = (new_recv, s),
                    Err(_) => todo!("drop packet (ooo queue full)"),
                }
            }

            if should_ack {
                // 7-1. ACK the received data if necessary. TODO.
            }

            // 8. Check for a FIN.
            //
            // https://datatracker.ietf.org/doc/html/rfc9293#section-3.10.7.4-2.8.1
            if packet.control == TcpControl::Fin {
                // 8-1. ESTABLISHED => CLOSE-WAIT. TODO.
                // 8-2. FIN-WAIT-1 => CLOSING. TODO.
                // 8-3. TIME-WAIT: Restart the 2 MSL timeout. TODO.
            }
            data
        });

        if let Some(data) = data {
            let _ = self.rx.receive(now, ip.src, data);
        }

        todo!()
    }

    pub fn poll_at(&self) -> PollAt {
        self.tcb.with(|tcb| tcb.timer.poll_at())
    }
}
