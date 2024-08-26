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
#![feature(macro_metavar_expr)]
#![feature(non_lifetime_binders)]
#![feature(type_changing_struct_update)]

#[cfg(any(test, feature = "std"))]
extern crate std;

// #[cfg(any(feature = "std", feature = "alloc"))]
// extern crate alloc;

#[macro_use]
mod macros;

pub mod provide_any;

pub mod context;
pub mod storage;
pub mod wire;
