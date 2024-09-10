use core::net::IpAddr;

use super::iface::NetTx;
use crate::{time::Instant, wire::*};

pub mod r#static;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Query {
    pub addr: Ends<IpAddr>,
    pub next_header: IpProtocol,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action<Tx> {
    Deliver { loopback: Tx },
    Forward { next_hop: IpAddr, tx: Tx },
    Discard,
}

impl<Tx> Action<Tx> {
    pub fn map<U>(self, map: impl FnOnce(Tx) -> U) -> Action<U> {
        match self {
            Action::Deliver { loopback } => Action::Deliver { loopback: map(loopback) },
            Action::Forward { next_hop, tx } => Action::Forward { next_hop, tx: map(tx) },
            Action::Discard => Action::Discard,
        }
    }

    pub fn map_or_discard<U>(self, map: impl FnOnce(Tx) -> Option<U>) -> Action<U> {
        match self {
            Action::Deliver { loopback } => match map(loopback) {
                Some(loopback) => Action::Deliver { loopback },
                None => Action::Discard,
            },
            Action::Forward { next_hop, tx } => match map(tx) {
                Some(tx) => Action::Forward { next_hop, tx },
                None => Action::Discard,
            },
            Action::Discard => Action::Discard,
        }
    }
}

pub trait Router<P: Payload> {
    type Tx<'a>: NetTx<P>
    where
        Self: 'a;

    fn route(&mut self, now: Instant, query: Query) -> Action<Self::Tx<'_>>;

    fn device(&mut self, now: Instant, hw: HwAddr) -> Option<Self::Tx<'_>>;
}

impl<P: Payload, R: Router<P>> Router<P> for &mut R {
    type Tx<'a> = R::Tx<'a> where Self: 'a;

    fn route(&mut self, now: Instant, query: Query) -> Action<Self::Tx<'_>> {
        R::route(self, now, query)
    }

    fn device(&mut self, now: Instant, hw: HwAddr) -> Option<Self::Tx<'_>> {
        R::device(self, now, hw)
    }
}
