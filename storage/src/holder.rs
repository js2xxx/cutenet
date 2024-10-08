use cutenet_error::Error;

use crate::{NoPayload, Payload, PayloadBuild, PushOption};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PayloadHolder(pub usize);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NoPayloadHolder;

impl Payload for PayloadHolder {
    type NoPayload = NoPayloadHolder;

    fn len(&self) -> usize {
        self.0
    }

    type DataIter<'a> = core::iter::Empty<&'a [u8]>;

    fn data_iter(&self) -> Self::DataIter<'_> {
        core::iter::empty()
    }

    type DataIterMut<'a> = core::iter::Empty<&'a mut [u8]>;

    fn data_iter_mut(&mut self) -> Self::DataIterMut<'_> {
        core::iter::empty()
    }

    fn truncate(self) -> Self::NoPayload {
        NoPayloadHolder
    }

    fn reset(self) -> Self::NoPayload {
        NoPayloadHolder
    }
}

impl NoPayload for NoPayloadHolder {
    type Init = PayloadHolder;

    fn reset(self) -> Self {
        self
    }

    fn reserve(self, _headroom: usize) -> Self {
        self
    }

    fn init(self) -> Self::Init {
        PayloadHolder(0)
    }
}

impl PayloadBuild for PayloadHolder {
    fn capacity(&self) -> usize {
        usize::MAX
    }

    fn push_with<F, E>(
        self,
        size: usize,
        _opt: &PushOption,
        _set_header: F,
    ) -> Result<Self, Error<E, Self>>
    where
        F: FnOnce(&mut [u8], Self::DataIter<'_>) -> Result<(), E>,
    {
        Ok(PayloadHolder(self.0 + size))
    }
}
