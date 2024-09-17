use core::time::Duration;

use crate::{
    time::{Instant, PollAt},
    wire::*,
};

const ALPHA_INV: u32 = 8; // 1 / ALPHA
const BETA_INV: u32 = 4; // 1 / BETA

const INITIAL_RTT: Duration = Duration::from_millis(300);
const MIN_TIMEOUT: Duration = Duration::from_millis(10);
const MAX_TIMEOUT: Duration = Duration::from_millis(60000);

fn timeout(srtt: Duration, rttvar: Duration) -> Duration {
    (srtt + rttvar * 4).clamp(MIN_TIMEOUT, MAX_TIMEOUT)
}

#[derive(Debug, Clone, Copy)]
struct RttData {
    srtt: Duration,
    rttvar: Duration,
    timeout: Duration,
}

impl RttData {
    fn new() -> Self {
        let rttvar = INITIAL_RTT / 2;
        RttData {
            srtt: INITIAL_RTT,
            rttvar,
            timeout: timeout(INITIAL_RTT, rttvar),
        }
    }

    fn update(&mut self, rtt: Duration) {
        self.rttvar = (self.rttvar * (BETA_INV - 1) + self.srtt.abs_diff(rtt)) / BETA_INV;
        self.srtt = (self.srtt * (ALPHA_INV - 1) + (rtt - self.srtt)) / ALPHA_INV;
        self.timeout = timeout(self.srtt, self.rttvar);
    }

    fn timeout(&self) -> Duration {
        self.timeout
    }
}

#[derive(Debug)]
pub struct RttEstimator {
    data: RttData,
    last_sent: Option<(Instant, TcpSeqNumber)>,
    retx_count: u8,
}

impl RttEstimator {
    pub fn new() -> Self {
        RttEstimator {
            data: RttData::new(),
            last_sent: None,
            retx_count: 0,
        }
    }

    pub fn retx_timeout(&self) -> Duration {
        self.data.timeout()
    }

    pub fn packet_sent(&mut self, now: Instant, end_seq: TcpSeqNumber) {
        let updated = match self.last_sent {
            Some((_, sent)) => sent < end_seq,
            None => true,
        };

        if updated {
            self.last_sent = Some((now, end_seq));
        }
    }

    pub fn packet_acked(&mut self, now: Instant, acked: TcpSeqNumber) {
        if let Some((sent_ts, sent_seq)) = self.last_sent
            && acked >= sent_seq
        {
            self.data.update(now - sent_ts);
            self.last_sent = None;
        }
    }

    pub fn packet_lost(&mut self) {
        self.last_sent = None;
        self.retx_count += 1;
        if self.retx_count >= 3 {
            self.retx_count = 0;
            self.data.srtt = MAX_TIMEOUT.min(self.data.srtt * 2);
        }
    }
}

impl Default for RttEstimator {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Timer {
    Idle {
        keep_alive_at: Option<Instant>,
    },
    Retx {
        expires_at: Instant,
        delay: Duration,
    },
    FastRetx,
    Close {
        expires_at: Instant,
    },
}

const ACK_DELAY_DEFAULT: Duration = Duration::from_millis(10);
const CLOSE_DELAY: Duration = Duration::from_millis(10_000);

impl Timer {
    pub const fn new() -> Timer {
        Timer::Idle { keep_alive_at: None }
    }

    pub fn should_keep_alive(&self, now: Instant) -> bool {
        matches!(*self, Timer::Idle {
            keep_alive_at: Some(keep_alive_at),
        } if now >= keep_alive_at)
    }

    pub fn should_retransmit(&self, now: Instant) -> Option<Duration> {
        match *self {
            Timer::Retx { expires_at, delay } if now >= expires_at => {
                Some(now - expires_at + delay)
            }
            Timer::FastRetx => Some(Duration::from_millis(0)),
            _ => None,
        }
    }

    pub fn should_close(&self, now: Instant) -> bool {
        matches!(*self, Timer::Close { expires_at } if now >= expires_at)
    }

    pub fn poll_at(&self) -> PollAt {
        match *self {
            Timer::Idle { keep_alive_at } => match keep_alive_at {
                Some(keep_alive_at) => PollAt::Instant(keep_alive_at),
                None => PollAt::Pending,
            },
            Timer::Retx { expires_at, .. } => PollAt::Instant(expires_at),
            Timer::FastRetx => PollAt::Now,
            Timer::Close { expires_at } => PollAt::Instant(expires_at),
        }
    }

    pub fn set_for_idle(&mut self, now: Instant, interval: Option<Duration>) {
        *self = Timer::Idle {
            keep_alive_at: interval.map(|interval| now + interval),
        }
    }

    pub fn set_keep_alive(&mut self) {
        if let Timer::Idle { keep_alive_at } = self {
            if keep_alive_at.is_none() {
                *keep_alive_at = Some(Instant::ZERO)
            }
        }
    }

    pub fn rewind_keep_alive(&mut self, now: Instant, interval: Option<Duration>) {
        if let Timer::Idle { keep_alive_at } = self {
            *keep_alive_at = interval.map(|interval| now + interval)
        }
    }

    pub fn set_for_retx(&mut self, now: Instant, delay: Duration) {
        match *self {
            Timer::Idle { .. } | Timer::FastRetx { .. } => {
                *self = Timer::Retx { expires_at: now + delay, delay }
            }
            Timer::Retx { expires_at, delay } if now >= expires_at => {
                *self = Timer::Retx {
                    expires_at: now + delay,
                    delay: delay * 2,
                }
            }
            Timer::Retx { .. } => {}
            Timer::Close { .. } => {}
        }
    }

    fn set_for_fast_retx(&mut self) {
        *self = Timer::FastRetx
    }

    fn set_for_close(&mut self, now: Instant) {
        *self = Timer::Close { expires_at: now + CLOSE_DELAY }
    }

    fn is_retransmit(&self) -> bool {
        matches!(*self, Timer::Retx { .. } | Timer::FastRetx)
    }
}

impl Default for Timer {
    fn default() -> Self {
        Self::new()
    }
}