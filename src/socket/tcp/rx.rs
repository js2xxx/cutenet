use core::{net::IpAddr, ops::Range};

use super::{RecvState, ReorderQueue, WithTcpState};
use crate::{
    route::Router,
    socket::SocketRx,
    storage::{PayloadMerge, PayloadSplit},
    time::Instant,
    wire::*,
};

impl RecvState {
    #[allow(unused)]
    pub(super) fn new(next: TcpSeqNumber, window: usize) -> Self {
        Self { next, window }
    }

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

    fn offset(&self, seq: TcpSeqNumber) -> usize {
        seq - self.next
    }

    fn advance(&mut self, len: usize) {
        self.next += len;
    }
}

#[derive(Debug)]
pub struct TcpRx<P, Rx, W>
where
    P: Payload,
    Rx: SocketRx<Item = P>,
    W: WithTcpState<P>,
{
    ooo: ReorderQueue<P>,

    rx: Rx,
    state: W,
}

impl<P, Rx, W> TcpRx<P, Rx, W>
where
    P: Payload,
    Rx: SocketRx<Item = P>,
    W: WithTcpState<P>,
{
    pub(super) fn new(rx: Rx, state: W) -> Self {
        Self {
            ooo: ReorderQueue::new(),
            rx,
            state,
        }
    }
}

impl<P, Rx, W> TcpRx<P, Rx, W>
where
    P: PayloadSplit + PayloadMerge,
    Rx: SocketRx<Item = P>,
    W: WithTcpState<P>,
{
    pub fn process<R: Router<P>>(
        &mut self,
        now: Instant,
        #[allow(unused_variables)] router: &mut R,
        ip: Ends<IpAddr>,
        packet: TcpPacket<P>,
    ) {
        // https://datatracker.ietf.org/doc/html/rfc9293#name-other-states

        self.state.with(|state| {
            // 1. Check the sequence number.
            //
            // https://datatracker.ietf.org/doc/html/rfc9293#section-3.10.7.4-2.1.1
            let Some((seq_number, range)) =
                state.recv.accept(packet.seq_number, packet.payload.len())
            else {
                if packet.control == TcpControl::Rst {
                    // Simply drop the RST packet and return.
                    return;
                } else {
                    todo!("<SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>; drop & return")
                }
            };

            // 2. Check for a RST.
            //
            // https://datatracker.ietf.org/doc/html/rfc9293#section-3.10.7.4-2.2.1
            if packet.control == TcpControl::Rst {
                // 2-1. Check if the sequence number is out of window. Processed above.

                if seq_number == state.recv.next {
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
                return;
            };

            // 5-2. ACK the send queue.
            if !state
                .send
                .ack(seq_number, ack_number, usize::from(packet.window_len))
            {
                // Challenge ACK.
                todo!("<SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>")
            }

            // 5-3. FIN-WAIT-1 => FIN-WAIT-2. TODO.
            // 5-4. CLOSING => TIME-WAIT. TODO.
            // 5-5. LAST-ACK => CLOSED. TODO.
            // 5-6. TIME-WAIT: Restart the 2 MSL timeout. TODO.

            // 6. Check for an URG. TODO.

            // 7. Process the received payload.
            if !range.is_empty() {
                let payload = (packet.payload.slice_into(range))
                    .unwrap_or_else(|_| unreachable!("slicing into a non-empty range"));

                let pos = state.recv.offset(seq_number);
                let new_recv = if pos != 0 {
                    match self.ooo.merge(pos, payload) {
                        Ok(merged) => merged,
                        Err(_) => todo!("drop packet (ooo queue full)"),
                    }
                } else {
                    Some(payload)
                };

                if let Some(new_recv) = new_recv {
                    let len = new_recv.len();

                    let _ = self.rx.receive(now, ip.src, new_recv);

                    state.recv.advance(len);
                }
            }
            // 7-1. ACK the received data if necessary. TODO.

            // 8. Check for a FIN.
            //
            // https://datatracker.ietf.org/doc/html/rfc9293#section-3.10.7.4-2.8.1
            if packet.control == TcpControl::Fin {
                // 8-1. ESTABLISHED => CLOSE-WAIT. TODO.
                // 8-2. FIN-WAIT-1 => CLOSING. TODO.
                // 8-3. TIME-WAIT: Restart the 2 MSL timeout. TODO.
            }
        });

        todo!()
    }
}
