use cutenet_storage::{NoPayload, Payload};
use either::Either;

use crate::{
    context::WireCx,
    error::{BuildError, ParseError},
};

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

    #[allow(clippy::type_complexity)]
    fn sub_ref<F, G>(
        self,
        sub_payload: F,
        sub_no_payload: G,
    ) -> (
        Self::Output,
        Either<Self::Payload, <Self::Payload as Payload>::NoPayload>,
    )
    where
        F: FnOnce(&Self::Payload) -> Q,
        G: FnOnce(&<Self::Payload as Payload>::NoPayload) -> Q::NoPayload,
    {
        let mut payload_slot = None;
        let mut no_payload_slot = None;
        let output = self.substitute(
            |payload| {
                let sub = sub_payload(&payload);
                payload_slot = Some(payload);
                sub
            },
            |no_payload| {
                let sub = sub_no_payload(&no_payload);
                no_payload_slot = Some(no_payload);
                sub
            },
        );
        (output, match (payload_slot, no_payload_slot) {
            (Some(payload), None) => Either::Left(payload),
            (None, Some(no_payload)) => Either::Right(no_payload),
            (None, None) | (Some(_), Some(_)) => unreachable!(),
        })
    }

    fn sub_payload<F>(self, sub: F) -> Self::Output
    where
        F: FnOnce(Self::Payload) -> Q,
    {
        self.substitute(sub, |_| {
            unreachable!("substituting payload in a wired data with no payload")
        })
    }

    fn sub_payload_ref<F>(self, sub: F) -> (Self::Output, Self::Payload)
    where
        F: FnOnce(&Self::Payload) -> Q,
    {
        let mut slot = None;
        let output = self.sub_payload(|payload| {
            let sub = sub(&payload);
            slot = Some(payload);
            sub
        });
        (output, slot.unwrap())
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
    fn buffer_len(&self) -> usize;

    fn header_len(&self) -> usize {
        self.buffer_len() - self.payload_len()
    }

    fn build(self, cx: &dyn WireCx) -> Result<Self::Payload, BuildError<Self::Payload>>;
}

pub trait WireParse: Wire + Sized {
    fn parse(cx: &dyn WireCx, raw: Self::Payload) -> Result<Self, ParseError<Self::Payload>>;
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
    fn buffer_len(&self) -> usize {
        self.len()
    }

    fn build(self, _: &dyn WireCx) -> Result<T, BuildError<T>> {
        Ok(self)
    }
}

impl<T: Payload + Wire<Payload = T>> WireParse for T {
    fn parse(_: &dyn WireCx, raw: T) -> Result<Self, ParseError<T>> {
        Ok(raw)
    }
}

pub trait ReserveExt {
    fn reserve_for<T: WireBuild>(self, tag: &T) -> Self;
}

impl<S: cutenet_storage::Storage> ReserveExt for cutenet_storage::ReserveBuf<S> {
    fn reserve_for<T: WireBuild>(self, tag: &T) -> Self {
        self.add_reservation(tag.header_len())
    }
}
