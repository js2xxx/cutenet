use core::net::IpAddr;

use super::iface::NetTx;
use crate::{storage::Storage, time::Instant, wire::*};

pub mod r#static;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Query {
    pub addr: Ends<IpAddr>,
    pub next_header: IpProtocol,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action<Tx> {
    Deliver,
    Forward { next_hop: IpAddr, tx: Tx },
    Discard,
}

impl<Tx> Action<Tx> {
    pub fn map<U>(self, map: impl FnOnce(Tx) -> U) -> Action<U> {
        match self {
            Action::Deliver => Action::Deliver,
            Action::Forward { next_hop, tx } => Action::Forward { next_hop, tx: map(tx) },
            Action::Discard => Action::Discard,
        }
    }

    pub fn map_or_discard<U>(self, map: impl FnOnce(Tx) -> Option<U>) -> Action<U> {
        match self {
            Action::Deliver => Action::Deliver,
            Action::Forward { next_hop, tx } => match map(tx) {
                Some(tx) => Action::Forward { next_hop, tx },
                None => Action::Discard,
            },
            Action::Discard => Action::Discard,
        }
    }
}

pub trait Router<S: Storage> {
    type Tx<'a>: NetTx<S>
    where
        Self: 'a;

    fn loopback(&mut self, now: Instant) -> Option<Self::Tx<'_>>;

    fn route(&mut self, now: Instant, query: Query) -> Action<Self::Tx<'_>>;

    fn device(&mut self, now: Instant, hw: HwAddr) -> Option<Self::Tx<'_>>;
}
