use crate::storage::{Buf, Storage};

mod adapter;
pub use self::adapter::{hook, Hook};

pub trait Device<S: Storage> {
    type TxToken<'a>: TxToken<S>
    where
        Self: 'a;

    fn receive(&mut self) -> Option<(Buf<S>, Self::TxToken<'_>)>;

    fn transmit(&mut self) -> Option<Self::TxToken<'_>>;
}

pub trait TxToken<S: Storage> {
    fn consume(self, buf: Buf<S>);
}

impl<S: Storage, D: Device<S>> Device<S> for &mut D {
    type TxToken<'a> = D::TxToken<'a>
    where
        Self: 'a;

    fn receive(&mut self) -> Option<(Buf<S>, Self::TxToken<'_>)> {
        (**self).receive()
    }

    fn transmit(&mut self) -> Option<Self::TxToken<'_>> {
        (**self).transmit()
    }
}
