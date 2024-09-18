use core::{fmt, net::SocketAddr, time::Duration};

use self::timer::{AckDelayTimer, RttEstimator, Timer};
use crate::{stack::DispatchError, storage::*, time::PollAt, wire::*};

mod congestion;
mod conn;
mod input;
mod output;
mod payload;
mod seq_number;
mod timer;

use self::payload::Tagged;
pub use self::{
    congestion::{cubic::Cubic, reno::Reno, CongestionController},
    conn::TcpListener,
    input::RecvResult,
    output::{TcpSend, TcpSendPacket, TcpStream},
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

#[derive(Debug)]
pub enum SendErrorKind {
    InvalidState(TcpState),
    BufferTooSmall,
    QueueFull,
    Dispatch(DispatchError),
}

impl fmt::Display for SendErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidState(s) => write!(f, "invalid state: {s:?}"),
            Self::BufferTooSmall => write!(f, "buffer too small"),
            Self::QueueFull => write!(f, "queue full"),
            Self::Dispatch(e) => write!(f, "dispatch error: {e:?}"),
        }
    }
}

crate::error::make_error!(SendErrorKind => pub SendError);

#[cfg(feature = "alloc")]
type ReorderQueue<P> = crate::storage::rope::BTreeReord<Tagged<P>>;
#[cfg(not(feature = "alloc"))]
type ReorderQueue<P> =
    crate::storage::rope::StaticReord<Tagged<P>, crate::config::STATIC_TCP_OOO_CAPACITY>;

#[cfg(feature = "alloc")]
type RetxQueue<T, P> = crate::storage::rope::BTreeRetx<T, Tagged<P>>;
#[cfg(not(feature = "alloc"))]
type RetxQueue<T, P> =
    crate::storage::rope::StaticRetx<T, Tagged<P>, crate::config::STATIC_TCP_RETX_CAPACITY>;

/// https://datatracker.ietf.org/doc/html/rfc9293#name-send-sequence-variables
#[derive(Debug)]
struct SendState<P> {
    initial: TcpSeqNumber,
    fin: TcpSeqNumber,

    unacked: TcpSeqNumber,
    next: TcpSeqNumber,
    window: usize,

    seq_lw: TcpSeqNumber,
    ack_lw: TcpSeqNumber,

    dup_acks: usize,

    retx: RetxQueue<TcpSeqNumber, P>,
    remote_mss: usize,
    can_sack: bool,
}

/// https://datatracker.ietf.org/doc/html/rfc9293#name-receive-sequence-variables
#[derive(Debug)]
struct RecvState<P> {
    next: TcpSeqNumber,
    window: usize,

    ooo: ReorderQueue<P>,
}

impl<P: Payload> RecvState<P> {
    fn sack_ranges(&self) -> [Option<(TcpSeqNumber, TcpSeqNumber)>; 3] {
        let mut ranges = [None; 3];
        (self.ooo.ranges().zip(&mut ranges))
            .for_each(|(range, r)| *r = Some((self.next + range.start, self.next + range.end)));
        ranges
    }
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpConfig<C>
where
    C: CongestionController,
{
    pub hop_limit: u8,
    pub timestamp_gen: Option<TcpTimestampGenerator>,
    pub congestion: C,
}

#[derive(Debug)]
pub struct Tcb<P, C> {
    endpoint: Ends<SocketAddr>,
    state: TcpState,

    send: SendState<P>,
    recv: RecvState<P>,

    hop_limit: u8,

    congestion: C,
    rtte: RttEstimator,

    keep_alive: Option<Duration>,
    timer: Timer,
    ack_delay_timer: AckDelayTimer,

    timestamp_gen: Option<TcpTimestampGenerator>,
    last_timestamp: u32,
}

impl<P, C> Tcb<P, C> {
    pub fn poll_at(&self) -> PollAt {
        (self.timer.poll_at()).min(self.ack_delay_timer.poll_at())
    }

    pub fn ack_delay(&self) -> Option<Duration> {
        self.ack_delay_timer.delay()
    }

    pub fn set_ack_delay(&mut self, ack_delay: Option<Duration>) {
        self.ack_delay_timer.set_delay(ack_delay);
    }

    pub fn keep_alive(&self) -> Option<Duration> {
        self.keep_alive
    }

    pub fn set_keep_alive(&mut self, keep_alive: Option<Duration>) {
        self.keep_alive = keep_alive;
        if keep_alive.is_some() {
            self.timer.set_keep_alive();
        }
    }

    pub fn is_open(&self) -> bool {
        !matches!(self.state, TcpState::Closed | TcpState::TimeWait)
    }

    pub fn is_active(&self) -> bool {
        !matches!(self.state, TcpState::Closed | TcpState::TimeWait)
    }

    pub fn may_send(&self) -> bool {
        matches!(self.state, TcpState::Established | TcpState::CloseWait)
    }

    pub fn may_recv(&self) -> bool {
        // In FIN-WAIT-1/2, we have closed our transmit half of the connection but
        // we still can receive indefinitely.
        matches!(
            self.state,
            TcpState::Established | TcpState::FinWait1 | TcpState::FinWait2
        )
    }

    pub fn abort(&mut self) {
        self.state = TcpState::Closed;
    }
}
