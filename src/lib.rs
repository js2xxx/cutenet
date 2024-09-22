#![no_std]
#![deny(future_incompatible)]
#![deny(rust_2018_idioms)]
#![deny(rust_2024_compatibility)]
#![allow(edition_2024_expr_fragment_specifier)]
#![deny(trivial_casts)]
#![deny(trivial_numeric_casts)]
#![allow(clippy::unit_arg)]
#![allow(incomplete_features)]
#![feature(allocator_api)]
#![feature(if_let_guard)]
#![feature(ip)]
#![feature(lazy_type_alias)]
#![feature(let_chains)]
#![feature(macro_metavar_expr)]
#![feature(trait_alias)]
#![feature(trait_upcasting)]

#[cfg(any(test, feature = "std"))]
extern crate std;

#[cfg(any(feature = "std", feature = "alloc"))]
extern crate alloc;

#[macro_use]
mod macros;

pub use cutenet_config as config;
pub use cutenet_error as error;
pub use cutenet_storage as storage;
pub use cutenet_time as time;
pub use cutenet_wire as wire;

pub mod frag;
pub mod iface;
pub mod phy;
pub mod route;
pub mod socket;
pub mod stack;

#[must_use]
#[derive(Debug, PartialEq, Eq, Clone, Copy, PartialOrd, Ord, Hash)]
pub enum TxResult {
    /// Transmission successful.
    Success,
    /// Also success, but with a warning.
    CongestionAlert,
    /// Transmission failed & packet dropped.
    Dropped(TxDropReason),
}

#[derive(Debug, PartialEq, Eq, Clone, Copy, PartialOrd, Ord, Hash)]
pub enum TxDropReason {
    QueueFull,
    NoRoute,
    NeighborPending,
}
