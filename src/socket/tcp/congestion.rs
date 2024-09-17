use super::timer::RttEstimator;
use crate::time::Instant;

pub mod cubic;
pub mod reno;

pub trait CongestionController: Send + Sync {
    /// Returns the number of bytes that can be sent.
    fn window(&self) -> usize;

    /// Set the remote window size.
    fn set_remote_window(&mut self, remote_window: usize) {
        let _ = remote_window;
    }

    fn on_ack(&mut self, now: Instant, len: usize, rtte: &RttEstimator) {
        let _ = (now, len, rtte);
    }

    fn on_retransmit(&mut self, now: Instant) {
        let _ = now;
    }

    fn on_duplicate_ack(&mut self, now: Instant) {
        let _ = now;
    }

    fn pre_transmit(&mut self, now: Instant) {
        let _ = now;
    }

    fn post_transmit(&mut self, now: Instant, len: usize) {
        let _ = (now, len);
    }

    /// Set the maximum segment size.
    fn set_mss(&mut self, mss: usize) {
        let _ = mss;
    }
}

impl CongestionController for () {
    fn window(&self) -> usize {
        usize::MAX
    }
}
