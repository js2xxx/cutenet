use core::{fmt, ops::Range};

use self::timer::{RttEstimator, Timer};
use super::SocketRx;
use crate::{storage::*, wire::*};

mod congestion;
mod conn;
mod input;
mod output;
mod seq_number;
mod timer;

pub use self::{
    congestion::{cubic::Cubic, reno::Reno, CongestionController},
    conn::{ConnResult, TcpListener},
    input::TcpRecv,
    output::{TcpSend, TcpStream},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecvErrorKind {
    Disconnected,
    NotAccepted,
}
crate::error::make_error!(RecvErrorKind => pub RecvError);

impl fmt::Display for RecvErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RecvErrorKind::Disconnected => write!(f, "disconnected"),
            RecvErrorKind::NotAccepted => write!(f, "not accepted"),
        }
    }
}

#[cfg(feature = "alloc")]
type ReorderQueue<P> = crate::storage::rope::BTreeReord<P>;
#[cfg(not(feature = "alloc"))]
type ReorderQueue<P> = crate::storage::rope::StaticReord<P, crate::config::STATIC_TCP_OOO_CAPACITY>;

#[cfg(feature = "alloc")]
type RetxQueue<T, P> = crate::storage::rope::BTreeRetx<T, P>;
#[cfg(not(feature = "alloc"))]
type RetxQueue<T, P> =
    crate::storage::rope::StaticRetx<T, P, crate::config::STATIC_TCP_RETX_CAPACITY>;

/// https://datatracker.ietf.org/doc/html/rfc9293#name-send-sequence-variables
#[derive(Debug, Default)]
struct SendState<P> {
    initial: TcpSeqNumber,
    fin: TcpSeqNumber,

    unacked: TcpSeqNumber,
    next: TcpSeqNumber,
    window: usize,

    seq_lw: TcpSeqNumber,
    ack_lw: TcpSeqNumber,

    retx: RetxQueue<TcpSeqNumber, P>,
    remote_mss: usize,
    can_sack: bool,
}

/// https://datatracker.ietf.org/doc/html/rfc9293#name-receive-sequence-variables
#[derive(Debug, Default)]
struct RecvState<P> {
    next: TcpSeqNumber,
    window: usize,

    ooo: ReorderQueue<P>,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TcpState {
    SynSent,
    Established,
    FinWait1,
    FinWait2,
    CloseWait,
    Closing,
    LastAck,
    TimeWait,
    #[default]
    Closed,
}

#[derive(Debug, Default)]
pub struct Tcb<P, C> {
    state: TcpState,

    send: SendState<P>,
    recv: RecvState<P>,

    hop_limit: u8,

    congestion: C,
    rtte: RttEstimator,
    timer: Timer,

    timestamp_gen: Option<TcpTimestampGenerator>,
    last_timestamp: u32,
}

impl<P: PayloadSplit> SendState<P> {
    fn mss(&self) -> usize {
        let window_mss = self.unacked + self.window - self.next;
        self.remote_mss.min(window_mss)
    }

    fn advance(&mut self, p: P, control: TcpControl) -> Result<(), P> {
        let len = p.len();
        self.retx.push(self.next, p)?;
        if control == TcpControl::Fin {
            self.fin = self.next;
        }
        self.next += len + control.len();
        Ok(())
    }

    fn fin_acked(&self) -> bool {
        self.unacked > self.fin
    }

    fn ack(&mut self, seq: TcpSeqNumber, ack: TcpSeqNumber, window: usize) -> bool {
        let unacked = self.unacked;

        if unacked < ack && ack <= self.next {
            self.unacked = ack;
        } else if ack <= unacked {
            // Duplicate ACK. Fast retransmit (RFC 5681). TODO.
        } else {
            return false;
        };

        if (unacked <= ack && ack <= self.next)
            && (self.seq_lw < seq || (self.seq_lw == seq && self.ack_lw <= ack))
        {
            self.window = window;
            self.seq_lw = seq;
            self.ack_lw = ack;
        }

        self.retx.remove(..ack);

        true
    }

    fn sack(&mut self, ranges: [Option<(TcpSeqNumber, TcpSeqNumber)>; 3]) {
        let ranges = ranges.into_iter().flatten().map(|(start, end)| start..end);
        ranges.for_each(|range| self.retx.remove(range));
    }
}

impl<P: Payload> RecvState<P> {
    fn ooo_sack_ranges(&self) -> [Option<(TcpSeqNumber, TcpSeqNumber)>; 3] {
        let mut ranges = [None; 3];
        (self.ooo.ranges().zip(&mut ranges))
            .for_each(|(range, r)| *r = Some((self.next + range.start, self.next + range.end)));
        ranges
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

    fn advance(&mut self, seq: TcpSeqNumber, payload: P) -> Result<(Option<P>, bool), P> {
        if payload.is_empty() {
            return Ok((None, true));
        }
        let pos = seq - self.next;
        let new_recv = self.ooo.merge(pos, payload)?;

        if let Some(ref new_recv) = new_recv {
            self.next += new_recv.len();
        }

        Ok((new_recv, true))
    }
}

pub trait WithTcb: Clone {
    type Payload: Payload;
    type Congestion: CongestionController;

    fn new(state: Tcb<Self::Payload, Self::Congestion>) -> Self;

    fn with<T, F>(&self, f: F) -> T
    where
        F: FnOnce(&mut Tcb<Self::Payload, Self::Congestion>) -> T;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpConfig<P, C, R>
where
    P: Payload,
    C: CongestionController,
    R: SocketRx<Item = P>,
{
    pub hop_limit: u8,
    pub timestamp_gen: Option<TcpTimestampGenerator>,
    pub congestion: C,
    pub packet_rx: R,
}
