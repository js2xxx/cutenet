use core::{fmt, marker::PhantomData, ops::Range};

use crate::storage::{Buf, Storage};

pub mod arp;
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

pub struct Packet<Tag, S: Storage + ?Sized> {
    marker: PhantomData<Tag>,
    inner: Buf<S>,
}

impl<Tag, S: Storage + ?Sized> fmt::Debug for Packet<Tag, S>
where
    Buf<S>: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Packet")
            .field("marker", &core::any::type_name::<Tag>())
            .field("inner", &&self.inner)
            .finish()
    }
}

impl<Tag, S: Storage> Packet<Tag, S> {
    pub fn into_raw(self) -> Buf<S> {
        self.inner
    }
}

pub trait Wire: Sized {
    const EMPTY_PAYLOAD: bool;

    const HEAD_LEN: usize;
    const TAIL_LEN: usize;

    fn payload_range<S: Storage + ?Sized>(packet: &Packet<Self, S>) -> Range<usize> {
        Self::HEAD_LEN..(packet.inner.len() - Self::TAIL_LEN)
    }

    type ParseError;
    type ParseArg<'a>;
    fn parse<S>(packet: &Packet<Self, S>, arg: Self::ParseArg<'_>) -> Result<(), Self::ParseError>
    where
        S: Storage;

    type BuildError;
    fn build_default<S>(
        packet: &mut Packet<Self, S>,
        payload_len: usize,
    ) -> Result<(), Self::BuildError>
    where
        S: Storage;
}

impl<Tag: Wire, S: Storage> Packet<Tag, S> {
    pub fn into_payload(self) -> Buf<S> {
        let s = Tag::payload_range(&self);
        self.inner.slice_into(s)
    }

    pub fn payload(&self) -> &[u8] {
        let s = Tag::payload_range(self);
        &self.inner.data()[s]
    }

    pub fn parse(raw: Buf<S>, arg: Tag::ParseArg<'_>) -> Result<Self, Tag::ParseError> {
        let packet = Packet { marker: PhantomData, inner: raw };
        Tag::parse(&packet, arg)?;
        Ok(packet)
    }

    pub fn builder(payload: Buf<S>) -> Result<Builder<Self>, Tag::BuildError> {
        let len = payload.len();

        let mut inner = payload;
        inner.prepend(Tag::HEAD_LEN);
        inner.append(Tag::TAIL_LEN);

        let mut packet = Packet { marker: PhantomData, inner };
        Tag::build_default(&mut packet, len)?;

        Ok(Builder(packet))
    }
}

#[derive(Debug)]
pub struct Builder<W>(W);

impl<W> Builder<W> {
    pub fn build(self) -> W {
        self.0
    }
}
