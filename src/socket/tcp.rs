use core::fmt;

use super::SocketRx;
use crate::{storage::*, wire::*};

mod conn;
mod rx;
mod seq_number;
mod tx;

pub use self::{
    conn::{ProcessResult, TcpListener},
    rx::TcpRecv,
    tx::TcpStream,
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

#[derive(Debug, Default)]
pub struct TcpState<P> {
    send: SendState<P>,
    recv: RecvState<P>,

    hop_limit: u8,

    timestamp_gen: Option<TcpTimestampGenerator>,
    last_timestamp: u32,
}

impl<P: PayloadSplit> SendState<P> {
    fn mss(&self) -> usize {
        let window_mss = self.unacked + self.window - self.next;
        self.remote_mss.min(window_mss)
    }

    fn advance(&mut self, p: P) -> Result<(), P> {
        let len = p.len();
        self.retx.push(self.next, p)?;
        self.next += len;
        Ok(())
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

pub trait WithTcpState<P>: Clone {
    fn with<T, F>(&self, f: F) -> T
    where
        F: FnOnce(&mut TcpState<P>) -> T;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpConfig<W, P, R>
where
    W: WithTcpState<P>,
    P: Payload,
    R: SocketRx<Item = P>,
{
    pub state: W,
    pub packet_rx: R,
}
