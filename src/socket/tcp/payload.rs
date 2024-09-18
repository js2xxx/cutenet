use core::marker::PhantomData;

use crate::storage::*;

#[derive(Debug, Default)]
pub(super) struct Tagged<P, Q = ()> {
    pub payload: P,
    pub extra_len: usize,
    _marker: PhantomData<Q>,
}

impl<P, Q> Tagged<P, Q> {
    pub fn new(payload: P, extra_len: usize) -> Self {
        Tagged {
            payload,
            extra_len,
            _marker: PhantomData,
        }
    }
}

impl<P: Payload> Payload for Tagged<P> {
    type NoPayload = Tagged<P::NoPayload, ((), ())>;

    fn len(&self) -> usize {
        self.extra_len + self.payload.len()
    }

    fn truncate(self) -> Self::NoPayload {
        Tagged {
            payload: self.payload.truncate(),
            extra_len: self.extra_len,
            _marker: PhantomData,
        }
    }

    fn reset(self) -> Self::NoPayload {
        Tagged {
            payload: self.payload.reset(),
            extra_len: self.extra_len,
            _marker: PhantomData,
        }
    }
}

impl<P: NoPayload> NoPayload for Tagged<P, ((), ())> {
    type Init = Tagged<P::Init>;

    fn reset(self) -> Self {
        Tagged {
            payload: self.payload.reset(),
            extra_len: self.extra_len,
            _marker: PhantomData,
        }
    }

    fn reserve(self, headroom: usize) -> Self {
        Tagged {
            payload: self.payload.reserve(headroom),
            extra_len: self.extra_len,
            _marker: PhantomData,
        }
    }

    fn init(self) -> Self::Init {
        Tagged {
            payload: self.payload.init(),
            extra_len: self.extra_len,
            _marker: PhantomData,
        }
    }
}

impl<P: PayloadMerge> PayloadMerge for Tagged<P> {
    fn merge(&mut self, latter: Self) {
        self.payload.merge(latter.payload);
        self.extra_len += latter.extra_len;
    }
}

impl<P: PayloadSplit> PayloadSplit for Tagged<P> {
    fn split_off(&mut self, mid: usize) -> Option<Self> {
        let mid = mid.checked_sub(self.extra_len)?;
        Some(Tagged::new(self.payload.split_off(mid)?, 0))
    }
}
