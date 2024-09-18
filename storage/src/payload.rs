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

pub trait PayloadMerge: Payload + Sized {
    fn merge(&mut self, latter: Self);
}

pub trait PayloadSplit: Payload + Sized {
    fn split(mut self, mid: usize) -> Result<(Self, Self), Self> {
        match self.split_off(mid) {
            Some(right) => Ok((self, right)),
            None => Err(self),
        }
    }

    fn split_off(&mut self, mid: usize) -> Option<Self>;

    fn slice_into(self, range: Range<usize>) -> Result<Self, Self> {
        let (_, right) = self.split(range.start)?;
        let (mid, _) = right.split(range.end - range.start)?;
        Ok(mid)
    }
}

mod slice {
    use super::*;

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

    impl<'a> PayloadSplit for &'a [u8] {
        fn split_off(&mut self, mid: usize) -> Option<Self> {
            if self.len() > mid {
                let (left, right) = self.split_at(mid);
                *self = left;
                Some(right)
            } else {
                None
            }
        }

        fn slice_into(self, range: Range<usize>) -> Result<Self, Self> {
            self.get(range).ok_or(self)
        }
    }
}

#[cfg(feature = "alloc")]
mod vec {
    use alloc::vec::Vec;

    use super::*;

    #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
    pub struct EmptyVec<T>(Vec<T>);

    impl NoPayload for EmptyVec<u8> {
        type Init = Vec<u8>;

        fn reset(self) -> Self {
            self
        }

        fn reserve(mut self, headroom: usize) -> Self {
            self.0.reserve(headroom);
            self
        }

        fn init(self) -> Self::Init {
            self.0
        }
    }

    impl Payload for Vec<u8> {
        type NoPayload = EmptyVec<u8>;

        fn len(&self) -> usize {
            self.len()
        }

        fn truncate(mut self) -> Self::NoPayload {
            self.clear();
            EmptyVec(self)
        }

        fn reset(mut self) -> Self::NoPayload {
            self.clear();
            EmptyVec(self)
        }
    }

    impl PayloadParse for Vec<u8> {
        fn header_data(&self) -> &[u8] {
            &self[..]
        }

        fn pop(mut self, range: Range<usize>) -> Result<Self, Self> {
            if self.len() >= range.end {
                let mut data = self.split_off(range.start);
                Vec::truncate(&mut data, range.end - range.start);
                Ok(data)
            } else {
                Err(self)
            }
        }
    }

    impl PayloadBuild for Vec<u8> {
        fn capacity(&self) -> usize {
            isize::MAX as usize
        }

        fn push_with<F, E>(
            mut self,
            size: usize,
            opt: &PushOption,
            set_header: F,
        ) -> Result<Self, Error<E, Self>>
        where
            F: FnOnce(&mut [u8]) -> Result<(), E>,
        {
            let len = match opt.truncate {
                Some(truncate) => (size + self.len()).min(truncate),
                None => size + self.len(),
            };
            let header_len = size.min(len);
            let mut ret = Vec::with_capacity(len);
            ret.resize(header_len, 0);

            if let Err(err) = set_header(&mut ret[..]) {
                return Err((err, self).into());
            }

            Vec::truncate(&mut self, len - header_len);
            ret.append(&mut self);

            Ok(ret)
        }
    }

    impl PayloadMerge for Vec<u8> {
        fn merge(&mut self, latter: Self) {
            self.extend(latter);
        }
    }

    impl PayloadSplit for Vec<u8> {
        fn split_off(&mut self, mid: usize) -> Option<Self> {
            (self.len() > mid).then(|| self.split_off(mid))
        }
    }
}
