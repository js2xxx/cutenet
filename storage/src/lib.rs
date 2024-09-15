#![no_std]
#![feature(let_chains)]
#![cfg_attr(feature = "alloc", feature(btree_cursors))]

use core::ops::DerefMut;

use stable_deref_trait::StableDeref;

mod buf;
pub use self::buf::{Buf, ReserveBuf};

mod holder;
pub use self::holder::{NoPayloadHolder, PayloadHolder};

mod payload;
pub use self::payload::{
    NoPayload, Payload, PayloadBuild, PayloadMerge, PayloadParse, PayloadSplit, PushOption,
};

pub mod rope;

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(test)]
extern crate std;

pub trait Storage: DerefMut<Target = [u8]> + StableDeref {}
impl<T: DerefMut<Target = [u8]> + StableDeref + ?Sized> Storage for T {}
