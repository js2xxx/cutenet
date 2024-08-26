#![no_std]
#![deny(future_incompatible)]
#![deny(rust_2018_idioms)]
#![deny(rust_2024_compatibility)]
#![allow(edition_2024_expr_fragment_specifier)]
#![deny(trivial_casts)]
#![deny(trivial_numeric_casts)]
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

pub mod config;
pub mod context;
pub mod layer;
pub mod storage;
pub mod time;
pub mod wire;
