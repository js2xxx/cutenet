use super::Device;
use crate::storage::{Buf, Storage};

pub fn hook<S, D, R, T>(device: D, hook_tx: T, hook_rx: R) -> Hook<D, R, T>
where
    S: Storage,
    D: Device<S>,
    R: FnMut(&mut Buf<S>),
    T: FnMut(&mut Buf<S>),
{
    Hook { device, hook_tx, hook_rx }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Hook<D, R, T> {
    device: D,
    hook_rx: R,
    hook_tx: T,
}

impl<S, D, R, T> Device<S> for Hook<D, R, T>
where
    S: Storage,
    D: Device<S>,
    R: FnMut(&mut Buf<S>),
    T: FnMut(&mut Buf<S>),
{
    type TxToken<'a> = TxToken<D::TxToken<'a>, &'a mut T>
    where
        Self: 'a;

    fn receive(&mut self) -> Option<(Buf<S>, Self::TxToken<'_>)> {
        self.device.receive().map(|(mut buf, token)| {
            (self.hook_rx)(&mut buf);
            (buf, TxToken {
                token,
                hook_tx: &mut self.hook_tx,
            })
        })
    }

    fn transmit(&mut self) -> Option<Self::TxToken<'_>> {
        self.device.transmit().map(|token| TxToken {
            token,
            hook_tx: &mut self.hook_tx,
        })
    }
}

pub struct TxToken<Token, T> {
    token: Token,
    hook_tx: T,
}

impl<S, Token, T> super::TxToken<S> for TxToken<Token, T>
where
    S: Storage,
    Token: super::TxToken<S>,
    T: FnOnce(&mut Buf<S>),
{
    fn consume(self, mut buf: Buf<S>) {
        (self.hook_tx)(&mut buf);
        self.token.consume(buf);
    }
}
