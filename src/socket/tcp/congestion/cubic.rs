use super::CongestionController;
use crate::time::Instant;

// Constants for the Cubic congestion control algorithm.
// See RFC 8312.
const BETA_CUBIC: f64 = 0.7;
const C: f64 = 0.4;

#[derive(Debug)]
pub struct Cubic {
    cwnd: usize,     // Congestion window
    min_cwnd: usize, // The minimum size of congestion window
    w_max: usize,    // Window size just before congestion
    recovery_start: Option<Instant>,
    rwnd: usize, // Remote window
    last_update: Instant,
    ssthresh: usize,
}

impl Cubic {
    pub const fn new() -> Cubic {
        Cubic {
            cwnd: 1024 * 2,
            min_cwnd: 1024 * 2,
            w_max: 1024 * 2,
            recovery_start: None,
            rwnd: 64 * 1024,
            last_update: Instant::ZERO,
            ssthresh: usize::MAX,
        }
    }
}

impl Default for Cubic {
    fn default() -> Self {
        Self::new()
    }
}

impl CongestionController for Cubic {
    fn window(&self) -> usize {
        self.cwnd
    }

    fn on_retransmit(&mut self, now: Instant) {
        self.w_max = self.cwnd;
        self.ssthresh = self.cwnd >> 1;
        self.recovery_start = Some(now);
    }

    fn on_duplicate_ack(&mut self, now: Instant) {
        self.w_max = self.cwnd;
        self.ssthresh = self.cwnd >> 1;
        self.recovery_start = Some(now);
    }

    fn set_remote_window(&mut self, remote_window: usize) {
        if self.rwnd < remote_window {
            self.rwnd = remote_window;
        }
    }

    fn on_ack(&mut self, _now: Instant, len: usize, _rtt: &crate::socket::tcp::RttEstimator) {
        // Slow start.
        if self.cwnd < self.ssthresh {
            self.cwnd = self
                .cwnd
                .saturating_add(len)
                .min(self.rwnd)
                .max(self.min_cwnd);
        }
    }

    fn pre_transmit(&mut self, now: Instant) {
        let Some(recovery_start) = self.recovery_start else {
            self.recovery_start = Some(now);
            return;
        };

        let now_millis = now.total_millis();

        // If the last update was less than 100ms ago, don't update the congestion
        // window.
        if self.last_update > recovery_start && now_millis - self.last_update.total_millis() < 100 {
            return;
        }

        // Elapsed time since the start of the recovery phase.
        if now_millis < recovery_start.total_millis() {
            return;
        }
        let t = now_millis - recovery_start.total_millis();

        // K = (w_max * (1 - beta) / C)^(1/3)
        let k3 = ((self.w_max as f64) * (1.0 - BETA_CUBIC)) / C;
        let k = k3.cbrt();

        // cwnd = C(T - K)^3 + w_max
        let s = t as f64 / 1000.0 - k;
        let s = s * s * s;
        let cwnd = C * s + self.w_max as f64;

        self.last_update = now;

        self.cwnd = (cwnd as usize).max(self.min_cwnd).min(self.rwnd);
    }

    fn set_mss(&mut self, mss: usize) {
        self.min_cwnd = mss;
    }
}

#[cfg(test)]
mod test {
    use std::println;

    use super::*;
    use crate::{socket::tcp::RttEstimator, time::Instant};

    #[test]
    fn test_cubic() {
        let remote_window = 64 * 1024 * 1024;
        let now = Instant::ZERO;

        for i in 0..10 {
            for j in 0..9 {
                let mut cubic = Cubic::new();
                // Set remote window.
                cubic.set_remote_window(remote_window);

                cubic.set_mss(1480);

                if i & 1 == 0 {
                    cubic.on_retransmit(now);
                } else {
                    cubic.on_duplicate_ack(now);
                }

                cubic.pre_transmit(now);

                let mut n = i;
                for _ in 0..j {
                    n *= i;
                }

                let elapsed = Instant::from_millis(n);
                cubic.pre_transmit(elapsed);

                let cwnd = cubic.window();
                println!("Cubic: elapsed = {}, cwnd = {}", elapsed, cwnd);

                assert!(cwnd >= cubic.min_cwnd);
                assert!(cubic.window() <= remote_window);
            }
        }
    }

    #[test]
    fn cubic_time_inversion() {
        let mut cubic = Cubic::new();

        let t1 = Instant::ZERO;
        let t2 = Instant::from_micros(u64::MAX);

        cubic.on_retransmit(t2);
        cubic.pre_transmit(t1);

        let cwnd = cubic.window();
        println!("Cubic:time_inversion: cwnd: {}, cubic: {cubic:?}", cwnd);

        assert!(cwnd >= cubic.min_cwnd);
        assert!(cwnd <= cubic.rwnd);
    }

    #[test]
    fn cubic_long_elapsed_time() {
        let mut cubic = Cubic::new();

        let t1 = Instant::ZERO;
        let t2 = Instant::from_micros(u64::MAX);

        cubic.on_retransmit(t1);
        cubic.pre_transmit(t2);

        let cwnd = cubic.window();
        println!("Cubic:long_elapsed_time: cwnd: {}", cwnd);

        assert!(cwnd >= cubic.min_cwnd);
        assert!(cwnd <= cubic.rwnd);
    }

    #[test]
    fn cubic_last_update() {
        let mut cubic = Cubic::new();

        let t1 = Instant::ZERO;
        let t2 = Instant::from_millis(100);
        let t3 = Instant::from_millis(199);
        let t4 = Instant::from_millis(20000);

        cubic.on_retransmit(t1);

        cubic.pre_transmit(t2);
        let cwnd2 = cubic.window();

        cubic.pre_transmit(t3);
        let cwnd3 = cubic.window();

        cubic.pre_transmit(t4);
        let cwnd4 = cubic.window();

        println!(
            "Cubic:last_update: cwnd2: {}, cwnd3: {}, cwnd4: {}",
            cwnd2, cwnd3, cwnd4
        );

        assert_eq!(cwnd2, cwnd3);
        assert_ne!(cwnd2, cwnd4);
    }

    #[test]
    fn cubic_slow_start() {
        let mut cubic = Cubic::new();

        let t1 = Instant::ZERO;

        let cwnd = cubic.window();
        let ack_len = 1024;

        cubic.on_ack(t1, ack_len, &RttEstimator::default());

        assert!(cubic.window() > cwnd);

        for i in 1..1000 {
            let t2 = Instant::from_micros(i);
            cubic.on_ack(t2, ack_len * 100, &RttEstimator::default());
            assert!(cubic.window() <= cubic.rwnd);
        }

        let t3 = Instant::from_micros(2000);

        let cwnd = cubic.window();
        cubic.on_retransmit(t3);
        assert_eq!(cwnd >> 1, cubic.ssthresh);
    }

    #[test]
    fn cubic_pre_transmit() {
        let mut cubic = Cubic::new();
        cubic.pre_transmit(Instant::from_micros(2000));
    }
}
