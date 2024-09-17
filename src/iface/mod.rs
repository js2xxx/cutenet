use core::net::{IpAddr, Ipv6Addr};

use self::neighbor::CacheOption;
use super::{phy::DeviceCaps, TxResult};
use crate::{storage::*, time::Instant, wire::*};

pub mod dynamic;
pub mod ethernet;
pub mod loopback;
pub mod neighbor;

pub type NetPayload<P: Payload> = EthernetPayload<P, P::NoPayload>;

pub trait NetTx<P: Payload> {
    fn hw_addr(&self) -> HwAddr;

    fn device_caps(&self) -> DeviceCaps;

    fn has_ip(&self, ip: IpAddr) -> bool;

    fn is_same_net(&self, ip: IpAddr) -> bool;

    fn is_broadcast(&self, ip: IpAddr) -> bool;

    fn has_solicited_node(&self, ip: Ipv6Addr) -> bool;

    fn fill_neighbor_cache(
        &mut self,
        now: Instant,
        opt: CacheOption,
        nop: Option<P::NoPayload>,
        entry: (IpAddr, HwAddr),
    );

    fn lookup_neighbor_cache(
        &mut self,
        now: Instant,
        ip: IpAddr,
    ) -> Result<HwAddr, Option<P::NoPayload>>;

    fn transmit(&mut self, now: Instant, dst: HwAddr, packet: NetPayload<P>) -> TxResult;
}

pub trait SyncNetTx<P: Payload>: Sync
where
    for<'a> &'a Self: NetTx<P>,
{
    fn fill_neighbor_cache(
        mut self: &Self,
        now: Instant,
        opt: CacheOption,
        nop: Option<P::NoPayload>,
        entry: (IpAddr, HwAddr),
    ) {
        NetTx::fill_neighbor_cache(&mut self, now, opt, nop, entry)
    }

    fn lookup_neighbor_cache(
        mut self: &Self,
        now: Instant,
        ip: IpAddr,
    ) -> Result<HwAddr, Option<P::NoPayload>> {
        NetTx::lookup_neighbor_cache(&mut self, now, ip)
    }

    fn transmit(mut self: &Self, now: Instant, dst: HwAddr, packet: NetPayload<P>) -> TxResult {
        NetTx::transmit(&mut self, now, dst, packet)
    }
}

impl<P: Payload, N: Sync> SyncNetTx<P> for N where for<'a> &'a N: NetTx<P> {}

pub trait NetRx<P: Payload> {
    fn hw_addr(&self) -> HwAddr;

    fn device_caps(&self) -> DeviceCaps;

    fn receive(&mut self, now: Instant) -> Option<(HwAddr, NetPayload<P>)>;
}

impl<P: Payload, N: NetTx<P>> NetTx<P> for &'_ mut N {
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
        opt: CacheOption,
        nop: Option<P::NoPayload>,
        entry: (IpAddr, HwAddr),
    ) {
        (**self).fill_neighbor_cache(now, opt, nop, entry)
    }

    fn lookup_neighbor_cache(
        &mut self,
        now: Instant,
        ip: IpAddr,
    ) -> Result<HwAddr, Option<P::NoPayload>> {
        (**self).lookup_neighbor_cache(now, ip)
    }

    fn transmit(&mut self, now: Instant, dst: HwAddr, packet: NetPayload<P>) -> TxResult {
        (**self).transmit(now, dst, packet)
    }
}

impl<P: Payload, N: NetRx<P>> NetRx<P> for &'_ mut N {
    fn hw_addr(&self) -> HwAddr {
        (**self).hw_addr()
    }

    fn device_caps(&self) -> DeviceCaps {
        (**self).device_caps()
    }

    fn receive(&mut self, now: Instant) -> Option<(HwAddr, NetPayload<P>)> {
        (**self).receive(now)
    }
}
