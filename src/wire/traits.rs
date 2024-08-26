use core::ops::Range;

use crate::{
    provide_any::Provider,
    wire::error::{BuildError, BuildErrorKind, ParseError, ParseErrorKind},
};

pub trait Payload {
    type NoPayload: NoPayload<Init = Self>;

    fn len(&self) -> usize;

    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn truncate(self) -> Self::NoPayload;
}

pub trait NoPayload {
    type Init: Payload<NoPayload = Self>;

    fn init(self) -> Self::Init;
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PayloadPush {
    Truncate(usize),
    Error(usize),
}

pub trait PayloadBuild: Payload + Sized {
    fn push<F>(self, size: usize, set: F) -> Result<Self, BuildError<Self>>
    where
        F: FnOnce(&mut [u8]) -> Result<(), BuildErrorKind>;

    fn push_with<F>(self, size: usize, opt: PayloadPush, set: F) -> Result<Self, BuildError<Self>>
    where
        F: FnOnce(&mut [u8]) -> Result<(), BuildErrorKind>;
}

pub trait PayloadParse: Payload + Sized {
    fn pop(self, range: Range<usize>) -> Result<Self, ParseError<Self>>;
}

pub trait Wire {
    type Payload: Payload;

    fn payload_len(&self) -> usize;
}

pub trait WireSubstitute<Q: Payload>: Wire + Sized {
    type Output;

    fn substitute<F, G>(self, sub_payload: F, sub_no_payload: G) -> Self::Output
    where
        F: FnOnce(Self::Payload) -> Q,
        G: FnOnce(<Self::Payload as Payload>::NoPayload) -> Q::NoPayload;

    fn sub_payload<F>(self, sub: F) -> Self::Output
    where
        F: FnOnce(Self::Payload) -> Q,
    {
        self.substitute(sub, |_| {
            unreachable!("substituting payload in a wired data with no payload")
        })
    }
}

pub trait WireSubNoPayload<N: NoPayload>: WireSubstitute<N::Init> + Sized {
    fn sub_no_payload<G>(self, sub: G) -> Self::Output
    where
        G: FnOnce(<Self::Payload as Payload>::NoPayload) -> N,
    {
        let sub_payload = |_| -> N::Init {
            unreachable!("substituting no-payload in a wired data with a payload")
        };
        self.substitute(sub_payload, sub)
    }
}
impl<N: NoPayload, W: WireSubstitute<N::Init> + Sized> WireSubNoPayload<N> for W {}

pub trait WireBuild: Wire + Sized {
    fn build(self, cx: &dyn Provider) -> Result<Self::Payload, BuildError<Self::Payload>>;
}

pub trait WireParse: Wire + Sized {
    fn parse(cx: &dyn Provider, raw: Self::Payload) -> Result<Self, ParseError<Self::Payload>>;
}

impl<T: Payload> Wire for T {
    type Payload = Self;

    fn payload_len(&self) -> usize {
        self.len()
    }
}

impl<T: Payload, U: Payload> WireSubstitute<U> for T {
    type Output = U;

    fn substitute<F, G>(self, sub_payload: F, _sub_no_payload: G) -> Self::Output
    where
        F: FnOnce(Self::Payload) -> U,
        G: FnOnce(<Self::Payload as Payload>::NoPayload) -> <U as Payload>::NoPayload,
    {
        sub_payload(self)
    }
}

impl<T: Payload + Wire<Payload = T>> WireBuild for T {
    fn build(self, _: &dyn Provider) -> Result<T, BuildError<T>> {
        Ok(self)
    }
}

impl<T: Payload + Wire<Payload = T>> WireParse for T {
    fn parse(_: &dyn Provider, raw: T) -> Result<Self, ParseError<T>> {
        Ok(raw)
    }
}

mod holder {
    use super::*;
    use crate::wire::error::ParseErrorKind;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct PayloadHolder(pub usize);

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct NoPayloadHolder;

    impl Payload for PayloadHolder {
        type NoPayload = NoPayloadHolder;

        fn len(&self) -> usize {
            self.0
        }

        fn truncate(self) -> Self::NoPayload {
            NoPayloadHolder
        }
    }

    impl NoPayload for NoPayloadHolder {
        type Init = PayloadHolder;
        fn init(self) -> Self::Init {
            PayloadHolder(0)
        }
    }

    impl PayloadBuild for PayloadHolder {
        fn push<F>(self, size: usize, _set: F) -> Result<Self, BuildError<Self>>
        where
            F: FnOnce(&mut [u8]) -> Result<(), BuildErrorKind>,
        {
            Ok(PayloadHolder(size + self.0))
        }

        fn push_with<F>(
            self,
            size: usize,
            opt: PayloadPush,
            _set: F,
        ) -> Result<Self, BuildError<Self>>
        where
            F: FnOnce(&mut [u8]) -> Result<(), BuildErrorKind>,
        {
            let len = size + self.0;
            Ok(PayloadHolder(match opt {
                PayloadPush::Truncate(mtu) => len.min(mtu),
                PayloadPush::Error(mtu) if len <= mtu => len,
                PayloadPush::Error(_) => return Err(BuildErrorKind::PayloadTooLong.with(self)),
            }))
        }
    }

    impl PayloadParse for PayloadHolder {
        fn pop(self, range: Range<usize>) -> Result<Self, ParseError<Self>> {
            if range.end <= self.0 {
                Ok(PayloadHolder(range.len()))
            } else {
                Err(ParseErrorKind::PacketTooShort.with(self))
            }
        }
    }
}
pub use self::holder::{NoPayloadHolder, PayloadHolder};

mod slice {
    use std::marker::PhantomData;

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
    }

    impl<'a> NoPayload for ZeroSlice<'a> {
        type Init = &'a [u8];

        fn init(self) -> Self::Init {
            &[]
        }
    }

    impl<'a> PayloadParse for &'a [u8] {
        fn pop(self, range: Range<usize>) -> Result<Self, ParseError<Self>> {
            self.get(range)
                .ok_or(ParseErrorKind::PacketTooShort.with(self))
        }
    }
}

mod buf {
    use super::*;
    use crate::{storage::*, wire::error::ParseErrorKind};

    impl<S: Storage> Payload for Buf<S> {
        type NoPayload = ReserveBuf<S>;

        fn len(&self) -> usize {
            self.len()
        }

        fn truncate(self) -> Self::NoPayload {
            ReserveBuf::from_buf_truncate(self)
        }
    }

    impl<S: Storage> NoPayload for ReserveBuf<S> {
        type Init = Buf<S>;
        fn init(self) -> Self::Init {
            self.build()
        }
    }

    impl<S: Storage> PayloadBuild for Buf<S> {
        fn push<F>(mut self, size: usize, set: F) -> Result<Self, BuildError<Self>>
        where
            F: FnOnce(&mut [u8]) -> Result<(), BuildErrorKind>,
        {
            let Some(_) = self.try_prepend(size) else {
                return Err(BuildErrorKind::HeadroomTooShort.with(self));
            };

            match set(self.data_mut()) {
                Ok(()) => Ok(self),
                Err(e) => {
                    self.slice_into(size..);
                    Err(e.with(self))
                }
            }
        }

        fn push_with<F>(
            mut self,
            size: usize,
            opt: PayloadPush,
            set: F,
        ) -> Result<Self, BuildError<Self>>
        where
            F: FnOnce(&mut [u8]) -> Result<(), BuildErrorKind>,
        {
            let len = size + self.len();
            let new_len = match opt {
                PayloadPush::Truncate(mtu) => len.min(mtu),
                PayloadPush::Error(mtu) if len <= mtu => len,
                PayloadPush::Error(_) => return Err(BuildErrorKind::PayloadTooLong.with(self)),
            };
            let new_payload_len = new_len - size;
            self.slice_into(..new_payload_len);

            self.push(size, set)
        }
    }

    impl<S: Storage> PayloadParse for Buf<S> {
        fn pop(mut self, range: Range<usize>) -> Result<Self, ParseError<Self>> {
            if range.end <= self.len() {
                self.slice_into(range);
                Ok(self)
            } else {
                Err(ParseErrorKind::PacketTooShort.with(self))
            }
        }
    }
}
