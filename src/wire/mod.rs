use crate::storage::{Buf, Storage};

pub mod ethernet;
pub mod ip;
pub mod udp;

mod field {
    use core::ops::{Range, RangeFrom};

    pub type Field = Range<usize>;
    pub type Rest = RangeFrom<usize>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Src<T>(pub T);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Dst<T>(pub T);

pub type Ends<T> = (Src<T>, Dst<T>);

pub trait WireBuf {
    type Storage: Storage + ?Sized;

    const HEADER_LEN: usize;

    fn into_inner(self) -> Buf<Self::Storage>
    where
        Self::Storage: Sized;

    fn into_payload(self) -> Buf<Self::Storage>
    where
        Self::Storage: Sized;
}
