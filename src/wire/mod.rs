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

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct VerifyChecksum<T>(pub T);

pub trait WireBuf {
    type Storage: Storage + ?Sized;

    const HEADER_LEN: usize;

    fn into_raw(self) -> Buf<Self::Storage>
    where
        Self::Storage: Sized;

    fn into_payload(self) -> Buf<Self::Storage>
    where
        Self::Storage: Sized;

    type ParseError;
    type ParseArg<'a>;
    fn parse(raw: Buf<Self::Storage>, arg: Self::ParseArg<'_>) -> Result<Self, Self::ParseError>
    where
        Self::Storage: Sized,
        Self: Sized;

    type BuildError;
    fn build_default(payload: Buf<Self::Storage>) -> Result<Self, Self::BuildError>
    where
        Self::Storage: Sized,
        Self: Sized;
}

pub trait WireBufExt: WireBuf + Sized {
    fn builder(payload: Buf<Self::Storage>) -> Result<Builder<Self>, Self::BuildError>
    where
        Self::Storage: Sized,
    {
        Self::build_default(payload).map(Builder)
    }
}
impl<W: WireBuf> WireBufExt for W {}

#[derive(Debug)]
pub struct Builder<W>(W);

impl<W> Builder<W> {
    pub fn build(self) -> W {
        self.0
    }
}
