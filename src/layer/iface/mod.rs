use core::net::{IpAddr, Ipv6Addr};

use self::neighbor::{NeighborCacheOption, NeighborLookupError};
use super::{phy::DeviceCaps, TxResult};
use crate::{
    storage::{Buf, ReserveBuf, Storage},
    time::Instant,
    wire::*,
};

pub mod dynamic;
pub mod ethernet;
pub mod loopback;
pub mod neighbor;

pub type Payload<S: Storage> = crate::wire::EthernetPayload<Buf<S>, ReserveBuf<S>>;

pub trait NetTx<S: Storage> {
    fn hw_addr(&self) -> HwAddr;

    fn device_caps(&self) -> DeviceCaps;

    fn has_ip(&self, ip: IpAddr) -> bool;

    fn is_same_net(&self, ip: IpAddr) -> bool;

    fn is_broadcast(&self, ip: IpAddr) -> bool;

    fn has_solicited_node(&self, ip: Ipv6Addr) -> bool;

    fn fill_neighbor_cache(
        &mut self,
        now: Instant,
        entry: (IpAddr, HwAddr),
        opt: NeighborCacheOption,
    );

    fn lookup_neighbor_cache(
        &self,
        now: Instant,
        ip: IpAddr,
    ) -> Result<HwAddr, NeighborLookupError>;

    fn transmit(&mut self, now: Instant, dst: HwAddr, packet: Payload<S>) -> TxResult;
}

pub trait SyncNetTx<S: Storage>: Sync
where
    for<'a> &'a Self: NetTx<S>,
{
    fn fill_neighbor_cache(
        mut self: &Self,
        now: Instant,
        entry: (IpAddr, HwAddr),
        opt: NeighborCacheOption,
    ) {
        NetTx::fill_neighbor_cache(&mut self, now, entry, opt)
    }

    fn transmit(mut self: &Self, now: Instant, dst: HwAddr, packet: Payload<S>) -> TxResult {
        NetTx::transmit(&mut self, now, dst, packet)
    }
}

impl<S: Storage, N: Sync> SyncNetTx<S> for N where for<'a> &'a N: NetTx<S> {}

pub trait NetRx<S: Storage> {
    fn hw_addr(&self) -> HwAddr;

    fn device_caps(&self) -> DeviceCaps;

    fn receive(&mut self, now: Instant) -> Option<(HwAddr, Payload<S>)>;
}

impl<S: Storage, N: NetTx<S>> NetTx<S> for &'_ mut N {
    fn hw_addr(&self) -> HwAddr {
        (**self).hw_addr()
    }

    fn device_caps(&self) -> DeviceCaps {
        (**self).device_caps()
    }

    fn has_ip(&self, ip: IpAddr) -> bool {
        (**self).has_ip(ip)
    }

    fn is_same_net(&self, ip: IpAddr) -> bool {
        (**self).is_same_net(ip)
    }

    fn is_broadcast(&self, ip: IpAddr) -> bool {
        (**self).is_broadcast(ip)
    }

    fn has_solicited_node(&self, ip: Ipv6Addr) -> bool {
        (**self).has_solicited_node(ip)
    }

    fn fill_neighbor_cache(
        &mut self,
        now: Instant,
        entry: (IpAddr, HwAddr),
        opt: NeighborCacheOption,
    ) {
        (**self).fill_neighbor_cache(now, entry, opt)
    }

    fn lookup_neighbor_cache(
        &self,
        now: Instant,
        ip: IpAddr,
    ) -> Result<HwAddr, NeighborLookupError> {
        (**self).lookup_neighbor_cache(now, ip)
    }

    fn transmit(&mut self, now: Instant, dst: HwAddr, packet: Payload<S>) -> TxResult {
        (**self).transmit(now, dst, packet)
    }
}

impl<S: Storage, N: NetRx<S>> NetRx<S> for &'_ mut N {
    fn hw_addr(&self) -> HwAddr {
        (**self).hw_addr()
    }

    fn device_caps(&self) -> DeviceCaps {
        (**self).device_caps()
    }

    fn receive(&mut self, now: Instant) -> Option<(HwAddr, Payload<S>)> {
        (**self).receive(now)
    }
}
