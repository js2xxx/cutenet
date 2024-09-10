use heapless::{FnvIndexMap, Vec};

use super::{Action, Query, Router};
use crate::{config::*, iface::NetTx, time::Instant, wire::*};

#[derive(Debug, Clone, Copy)]
pub struct Route {
    pub cidr: IpCidr,
    pub action: Action<HwAddr>,
    pub expiration: Option<Instant>,
}
pub type Routes = Vec<Route, STATIC_ROUTER_ROUTE_CAPACITY>;

#[derive(Debug, Clone, Copy)]
pub struct Destination<N> {
    pub device: N,
}
pub type DstMap<N> = FnvIndexMap<HwAddr, Destination<N>, STATIC_ROUTER_DESTINATION_CAPACITY>;

pub struct StaticRouter<N> {
    routes: Routes,
    dsts: DstMap<N>,
}

impl<N> StaticRouter<N> {
    pub const fn new() -> Self {
        Self {
            routes: Vec::new(),
            dsts: FnvIndexMap::new(),
        }
    }

    pub const fn destinations(&self) -> &DstMap<N> {
        &self.dsts
    }

    pub fn update_destinations<R>(&mut self, update: impl FnOnce(&mut DstMap<N>) -> R) -> R {
        update(&mut self.dsts)
    }

    pub const fn routes(&self) -> &Routes {
        &self.routes
    }

    pub fn update_routes<R>(&mut self, update: impl FnOnce(&mut Routes) -> R) -> R {
        update(&mut self.routes)
    }
}

impl<N> Default for StaticRouter<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<P: Payload, N: NetTx<P>> Router<P> for StaticRouter<N> {
    type Tx<'a> = &'a mut N
    where
        Self: 'a;

    fn route(&mut self, now: Instant, query: Query) -> Action<Self::Tx<'_>> {
        let route = (self.routes.iter())
            .filter(|i| {
                let expired = matches!(i.expiration, Some(e) if e < now);
                !expired && i.cidr.contains_addr(&query.addr.dst)
            })
            .max_by_key(|i| i.cidr.prefix_len());

        match route {
            Some(&Route { action, .. }) => action.map_or_discard(|hw| self.device(now, hw)),
            None => Action::Discard,
        }
    }

    fn device(&mut self, _now: Instant, hw: HwAddr) -> Option<Self::Tx<'_>> {
        self.dsts.get_mut(&hw).map(|dst| &mut dst.device)
    }
}
