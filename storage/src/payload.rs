use core::{marker::PhantomData, ops::Range};

use cutenet_error::Error;

pub trait Payload {
    type NoPayload: NoPayload<Init = Self>;

    fn len(&self) -> usize;

    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn truncate(self) -> Self::NoPayload;

    fn reset(self) -> Self::NoPayload;
}

pub trait NoPayload {
    type Init: Payload<NoPayload = Self>;

    fn reset(self) -> Self;

    fn reserve(self, headroom: usize) -> Self;

    fn init(self) -> Self::Init;
}

#[derive(Debug, Clone, Copy, Default)]
#[non_exhaustive]
pub struct PushOption {
    pub truncate: Option<usize>,
}

impl PushOption {
    pub const fn new() -> Self {
        Self { truncate: None }
    }

    pub const fn truncate(mut self, truncate: usize) -> Self {
        self.truncate = Some(truncate);
        self
    }
}

pub trait PayloadBuild: Payload + Sized {
    fn capacity(&self) -> usize;

    fn push<F, E>(self, size: usize, set_header: F) -> Result<Self, Error<E, Self>>
    where
        F: FnOnce(&mut [u8]) -> Result<(), E>,
    {
        self.push_with(size, &Default::default(), set_header)
    }

    fn push_with<F, E>(
        self,
        size: usize,
        opt: &PushOption,
        set_header: F,
    ) -> Result<Self, Error<E, Self>>
    where
        F: FnOnce(&mut [u8]) -> Result<(), E>;

    fn prepend(self, size: usize) -> Result<Self, Error<(), Self>> {
        self.push(size, |_| Ok(()))
    }
}

pub trait PayloadParse: Payload + Sized {
    fn header_data(&self) -> &[u8];

    fn pop(self, range: Range<usize>) -> Result<Self, Self>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ZeroSlice<'a>(PhantomData<&'a [u8]>);

impl<'a> Payload for &'a [u8] {
    type NoPayload = ZeroSlice<'a>;

    fn len(&self) -> usize {
        (**self).len()
    }

    fn truncate(self) -> Self::NoPayload {
        ZeroSlice(PhantomData)
    }

    fn reset(self) -> Self::NoPayload {
        ZeroSlice(PhantomData)
    }
}

impl<'a> NoPayload for ZeroSlice<'a> {
    type Init = &'a [u8];

    fn reset(self) -> Self {
        self
    }

    fn reserve(self, _headroom: usize) -> Self {
        self
    }

    fn init(self) -> Self::Init {
        &[]
    }
}

impl<'a> PayloadParse for &'a [u8] {
    fn header_data(&self) -> &[u8] {
        self
    }

    fn pop(self, range: Range<usize>) -> Result<Self, Self> {
        self.get(range).ok_or(self)
    }
}
