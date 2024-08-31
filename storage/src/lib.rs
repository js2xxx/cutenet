#![no_std]

use core::ops::DerefMut;

use stable_deref_trait::StableDeref;

mod buf;
pub use self::buf::{Buf, ReserveBuf};

#[cfg(test)]
extern crate std;

pub trait Storage: DerefMut<Target = [u8]> + StableDeref {}
impl<T: DerefMut<Target = [u8]> + StableDeref + ?Sized> Storage for T {}