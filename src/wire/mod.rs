use core::{fmt, marker::PhantomData, ops::Range};

use crate::storage::{Buf, Storage};

pub mod arpv4;
pub mod ethernet;
pub mod ieee802154;
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

    fn header_len(&self) -> usize;

    fn buffer_len(&self, payload_len: usize) -> usize;

    fn payload_range<S: Storage + ?Sized>(packet: &Packet<Self, S>) -> Range<usize>;

    type ParseArg<'a>;
    fn parse_packet<S: Storage>(
        packet: &Packet<Self, S>,
        arg: Self::ParseArg<'_>,
    ) -> Result<(), ParseErrorKind>;

    fn build_packet<S: Storage>(
        self,
        packet: &mut Packet<Self, S>,
        payload_len: usize,
    ) -> Result<(), BuildErrorKind>;
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

    pub fn parse(raw: Buf<S>, arg: Tag::ParseArg<'_>) -> Result<Self, ParseError<S>> {
        let packet = Packet { marker: PhantomData, inner: raw };
        match Tag::parse_packet(&packet, arg) {
            Ok(()) => Ok(packet),
            Err(kind) => Err(ParseError { buf: packet.inner, kind }),
        }
    }

    pub fn build(payload: Buf<S>, tag: Tag) -> Result<Self, BuildError<S>> {
        let header_len = tag.header_len();
        let payload_len = payload.len();

        if Tag::EMPTY_PAYLOAD && payload_len != 0 {
            let error = BuildError {
                kind: BuildErrorKind::PayloadNotEmpty,
                buf: payload,
            };
            return Err(error);
        }

        let mut inner = payload;
        inner.prepend(header_len);

        let mut packet = Packet { marker: PhantomData, inner };
        match tag.build_packet(&mut packet, payload_len) {
            Ok(()) => Ok(packet),
            Err(kind) => Err(BuildError {
                kind,
                buf: packet.inner.slice_into(header_len..),
            }),
        }
    }

    pub fn encap<U: Wire>(self, tag: U) -> Result<Packet<U, S>, BuildError<S>> {
        self.inner.build(tag)
    }
}

pub trait WireExt: Wire {
    fn build<S: Storage>(self, payload: Buf<S>) -> Result<Packet<Self, S>, BuildError<S>> {
        Packet::build(payload, self)
    }
}

impl<Tag: Wire> WireExt for Tag {}

#[derive(Debug)]
pub struct Error<K, S: Storage + ?Sized> {
    pub kind: K,
    pub buf: Buf<S>,
}

#[derive(Debug)]
pub enum ParseErrorKind {
    PacketTooShort,
    PacketTooLong,

    ProtocolUnknown,
    ChecksumInvalid,
    VersionInvalid,
    DstInvalid,
}
pub type ParseError<S: Storage + ?Sized> = Error<ParseErrorKind, S>;

#[derive(Debug)]
pub enum BuildErrorKind {
    PayloadTooLong,
    PayloadNotEmpty,
}
pub type BuildError<S: Storage + ?Sized> = Error<BuildErrorKind, S>;
