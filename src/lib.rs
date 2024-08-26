#![no_std]
#![deny(future_incompatible)]
#![deny(rust_2018_idioms)]
#![deny(rust_2024_compatibility)]
#![allow(edition_2024_expr_fragment_specifier)]
#![deny(trivial_casts)]
#![deny(trivial_numeric_casts)]
#![allow(incomplete_features)]
#![feature(ip)]
#![feature(lazy_type_alias)]
#![feature(let_chains)]

#[cfg(test)]
extern crate std;

#[macro_use]
mod macros;

pub mod storage;
pub mod wire;
pub mod phy;
