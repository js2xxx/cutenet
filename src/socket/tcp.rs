use core::fmt;

use super::SocketRx;
use crate::{
    storage::{PayloadMerge, PayloadSplit},
    wire::*,
};

mod conn;
mod rx;
mod seq_number;

pub use self::{
    conn::{ProcessResult, TcpListener},
    rx::TcpRx,
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
type Deque<T> = alloc::collections::VecDeque<T>;
#[cfg(not(feature = "alloc"))]
type Deque<T> = heapless::Deque<T, crate::config::STATIC_TCP_BUFFER_CAPACITY>;

#[cfg(feature = "alloc")]
type ReorderQueue<P> = crate::storage::rope::BTreeRq<P>;
#[cfg(not(feature = "alloc"))]
type ReorderQueue<P> = crate::storage::rope::StaticRq<P, crate::config::STATIC_TCP_ROPE_CAPACITY>;

/// https://datatracker.ietf.org/doc/html/rfc9293#name-send-sequence-variables
#[derive(Debug, Default)]
struct SendState<P> {
    unacked: TcpSeqNumber,
    next: TcpSeqNumber,
    window: usize,

    seq_lw: TcpSeqNumber,
    ack_lw: TcpSeqNumber,

    queue: Deque<P>,
}

/// https://datatracker.ietf.org/doc/html/rfc9293#name-receive-sequence-variables
#[derive(Debug, Default)]
struct RecvState {
    next: TcpSeqNumber,
    window: usize,
}

#[derive(Debug, Default)]
pub struct TcpState<P> {
    send: SendState<P>,
    recv: RecvState,
}

impl<P: PayloadMerge + PayloadSplit> SendState<P> {
    fn ack(&mut self, seq: TcpSeqNumber, ack: TcpSeqNumber, window: usize) -> bool {
        let unacked = self.unacked;

        let mut offset = if unacked < ack && ack <= self.next {
            self.unacked = ack;
            ack - unacked
        } else if ack < unacked {
            0
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

        while let Some(front) = self.queue.front_mut() {
            if let Some(next) = front.split_off(offset) {
                *front = next;
                break;
            }
            offset -= front.len();
            self.queue.pop_front();
        }

        true
    }
}

pub trait WithTcpState<P>: Clone {
    fn with<T, F>(&mut self, f: F) -> T
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

#[allow(unused)]
pub struct TcpStream<P: Payload, W: WithTcpState<P>> {
    data: core::marker::PhantomData<P>,
    state: W,
}
