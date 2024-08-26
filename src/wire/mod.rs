use core::{fmt, marker::PhantomData, ops::Range};

use crate::storage::{Buf, Storage};

pub mod arpv4;
pub mod ethernet;
pub mod icmp;
pub mod ieee802154;
pub mod ip;
pub mod udp;

mod field {
    use core::ops::{Range, RangeFrom};

    pub type Field = Range<usize>;
    pub type Rest = RangeFrom<usize>;
}

pub trait Data: AsRef<[u8]> {
    fn parse<Tag: Wire>(self, arg: Tag::ParseArg<'_>) -> Result<Packet<Tag, Self>, ParseError<Self>>
    where
        Self: Sized,
    {
        Packet::parse(self, arg)
    }
}
impl<T: AsRef<[u8]> + ?Sized> Data for T {}

pub trait DataMut: Data + AsMut<[u8]> {}
impl<T: AsRef<[u8]> + AsMut<[u8]> + ?Sized> DataMut for T {}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Src<T>(pub T);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Dst<T>(pub T);

pub type Ends<T> = (Src<T>, Dst<T>);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct VerifyChecksum<T>(pub T);

#[derive(Clone, Copy)]
pub struct Packet<Tag, T: ?Sized> {
    marker: PhantomData<Tag>,
    inner: T,
}

impl<Tag, T: ?Sized + fmt::Debug> fmt::Debug for Packet<Tag, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Packet")
            .field("marker", &core::any::type_name::<Tag>())
            .field("inner", &&self.inner)
            .finish()
    }
}

impl<Tag, T> Packet<Tag, T> {
    pub fn into_raw(self) -> T {
        self.inner
    }
}

pub trait Wire: Sized {
    const EMPTY_PAYLOAD: bool;

    fn header_len(&self) -> usize;

    fn buffer_len(&self, payload_len: usize) -> usize;

    fn payload_range(packet: Packet<Self, &[u8]>) -> Range<usize>;

    type ParseArg<'a>;
    fn parse_packet(
        packet: Packet<Self, &[u8]>,
        arg: Self::ParseArg<'_>,
    ) -> Result<Self, ParseErrorKind>;

    fn build_packet(
        self,
        packet: Packet<Self, &mut [u8]>,
        payload_len: usize,
    ) -> Result<(), BuildErrorKind>;
}

impl<Tag: Wire, T: Data + ?Sized> Packet<Tag, T> {
    pub fn as_ref(&self) -> Packet<Tag, &[u8]> {
        Packet {
            marker: self.marker,
            inner: self.inner.as_ref(),
        }
    }

    pub fn payload(&self) -> &[u8] {
        let s = Tag::payload_range(self.as_ref());
        &self.inner.as_ref()[s]
    }
}

impl<Tag: Wire, T: DataMut + ?Sized> Packet<Tag, T> {
    pub fn as_mut(&mut self) -> Packet<Tag, &mut [u8]> {
        Packet {
            marker: self.marker,
            inner: self.inner.as_mut(),
        }
    }
}

impl<Tag: Wire, T: Data> Packet<Tag, T> {
    pub fn parse(raw: T, arg: Tag::ParseArg<'_>) -> Result<Self, ParseError<T>> {
        let packet = Packet { marker: PhantomData, inner: raw };
        match Tag::parse_packet(packet.as_ref(), arg) {
            Ok(_) => Ok(packet),
            Err(kind) => Err(ParseError { data: packet.inner, kind }),
        }
    }
}

impl<Tag: Wire, T: DataMut> Packet<Tag, T> {
    fn build_at(raw: T, tag: Tag, payload_len: usize) -> Result<Self, BuildErrorKind> {
        let mut packet = Packet { marker: PhantomData, inner: raw };
        match tag.build_packet(packet.as_mut(), payload_len) {
            Ok(()) => Ok(packet),
            Err(kind) => Err(kind),
        }
    }
}

impl<Tag: Wire, S: Storage> Packet<Tag, Buf<S>> {
    pub fn into_payload(self) -> Buf<S> {
        let s = Tag::payload_range(self.as_ref());
        self.inner.slice_into(s)
    }

    pub fn build(payload: Buf<S>, tag: Tag) -> Result<Self, BuildError<Buf<S>>> {
        let header_len = tag.header_len();
        let payload_len = payload.len();

        if Tag::EMPTY_PAYLOAD && payload_len != 0 {
            let error = BuildError {
                kind: BuildErrorKind::PayloadNotEmpty,
                data: payload,
            };
            return Err(error);
        }

        let mut inner = payload;
        inner.prepend(header_len);

        let mut packet = Packet { marker: PhantomData, inner };
        match tag.build_packet(packet.as_mut(), payload_len) {
            Ok(()) => Ok(packet),
            Err(kind) => Err(BuildError {
                kind,
                data: packet.inner.slice_into(header_len..),
            }),
        }
    }

    pub fn encap<U: Wire>(self, tag: U) -> Result<Packet<U, Buf<S>>, BuildError<Buf<S>>> {
        self.inner.build(tag)
    }
}

pub trait WireExt: Wire {
    fn parse<T: Data>(raw: T, arg: Self::ParseArg<'_>) -> Result<Self, ParseError<T>> {
        let packet = Packet { marker: PhantomData, inner: raw };
        match Self::parse_packet(packet.as_ref(), arg) {
            Ok(ret) => Ok(ret),
            Err(kind) => Err(ParseError { data: packet.inner, kind }),
        }
    }

    fn build<S: Storage>(
        self,
        payload: Buf<S>,
    ) -> Result<Packet<Self, Buf<S>>, BuildError<Buf<S>>> {
        Packet::build(payload, self)
    }
}

impl<Tag: Wire> WireExt for Tag {}

#[derive(Debug)]
pub struct Error<K, T: ?Sized> {
    pub kind: K,
    pub data: T,
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
pub type ParseError<T: ?Sized> = Error<ParseErrorKind, T>;

#[derive(Debug)]
pub enum BuildErrorKind {
    PayloadTooLong,
    PayloadNotEmpty,
}
pub type BuildError<T: ?Sized> = Error<BuildErrorKind, T>;
