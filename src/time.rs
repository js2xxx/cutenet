use core::{fmt, ops, time::Duration};

/// A representation of an absolute time value.
///
/// The `Instant` type is a wrapper around a `u64` value that
/// represents a number of microseconds, monotonically increasing
/// since an arbitrary moment in time, such as system startup.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Instant {
    micros: u64,
}

impl Instant {
    pub const ZERO: Instant = Instant::from_micros_const(0);

    /// Create a new `Instant` from a number of microseconds.
    pub fn from_micros<T: Into<u64>>(micros: T) -> Instant {
        Instant { micros: micros.into() }
    }

    pub const fn from_micros_const(micros: u64) -> Instant {
        Instant { micros }
    }

    /// Create a new `Instant` from a number of milliseconds.
    pub fn from_millis<T: Into<u64>>(millis: T) -> Instant {
        Instant { micros: millis.into() * 1000 }
    }

    /// Create a new `Instant` from a number of milliseconds.
    pub const fn from_millis_const(millis: u64) -> Instant {
        Instant { micros: millis * 1000 }
    }

    /// Create a new `Instant` from a number of seconds.
    pub fn from_secs<T: Into<u64>>(secs: T) -> Instant {
        Instant { micros: secs.into() * 1000000 }
    }

    /// Create a new `Instant` from the current [`std::time::SystemTime`].
    ///
    /// See [`std::time::SystemTime::now`]
    #[cfg(feature = "std")]
    pub fn now() -> Instant {
        Self::from(::std::time::SystemTime::now())
    }

    /// The fractional number of milliseconds that have passed
    /// since the beginning of time.
    pub const fn millis(&self) -> u64 {
        self.micros % 1000000 / 1000
    }

    /// The fractional number of microseconds that have passed
    /// since the beginning of time.
    pub const fn micros(&self) -> u64 {
        self.micros % 1000000
    }

    /// The number of whole seconds that have passed since the
    /// beginning of time.
    pub const fn secs(&self) -> u64 {
        self.micros / 1000000
    }

    /// The total number of milliseconds that have passed since
    /// the beginning of time.
    pub const fn total_millis(&self) -> u64 {
        self.micros / 1000
    }
    /// The total number of milliseconds that have passed since
    /// the beginning of time.
    pub const fn total_micros(&self) -> u64 {
        self.micros
    }
}

#[cfg(feature = "std")]
impl From<::std::time::SystemTime> for Instant {
    fn from(other: ::std::time::SystemTime) -> Instant {
        let n = other
            .duration_since(::std::time::UNIX_EPOCH)
            .expect("start time must not be before the unix epoch");
        Self::from_micros(n.as_secs() * 1000000 + u64::from(n.subsec_micros()))
    }
}

impl fmt::Display for Instant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{:0>3}s", self.secs(), self.millis())
    }
}

impl ops::Add<Duration> for Instant {
    type Output = Instant;

    fn add(self, rhs: Duration) -> Instant {
        Instant::from_micros(self.micros + rhs.as_micros() as u64)
    }
}

impl ops::AddAssign<Duration> for Instant {
    fn add_assign(&mut self, rhs: Duration) {
        self.micros += rhs.as_micros() as u64;
    }
}

impl ops::Sub<Duration> for Instant {
    type Output = Instant;

    fn sub(self, rhs: Duration) -> Instant {
        Instant::from_micros(self.micros - rhs.as_micros() as u64)
    }
}

impl ops::SubAssign<Duration> for Instant {
    fn sub_assign(&mut self, rhs: Duration) {
        self.micros -= rhs.as_micros() as u64;
    }
}

impl ops::Sub<Instant> for Instant {
    type Output = Duration;

    fn sub(self, rhs: Instant) -> Duration {
        Duration::from_micros(self.micros - rhs.micros)
    }
}
