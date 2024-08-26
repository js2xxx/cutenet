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

    type BuildError;
    fn build_default(payload: Buf<Self::Storage>) -> Result<Self, Self::BuildError>
    where
        Self::Storage: Sized,
        Self: Sized;

    fn builder(payload: Buf<Self::Storage>) -> Result<Builder<Self>, Self::BuildError>
    where
        Self::Storage: Sized,
        Self: Sized,
    {
        Self::build_default(payload).map(Builder)
    }

    fn into_raw(self) -> Buf<Self::Storage>
    where
        Self::Storage: Sized;

    fn into_payload(self) -> Buf<Self::Storage>
    where
        Self::Storage: Sized;
}

#[derive(Debug)]
pub struct Builder<W>(W);

impl<W> Builder<W> {
    pub fn build(self) -> W {
        self.0
    }
}
