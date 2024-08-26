use core::net::{IpAddr, Ipv6Addr};

use self::neighbor::{NeighborCacheOption, NeighborLookupError};
use super::phy::DeviceCaps;
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

    fn transmit(&mut self, now: Instant, dst: HwAddr, packet: Payload<S>);
}

pub trait NetRx<S: Storage> {
    fn hw_addr(&self) -> HwAddr;

    fn device_caps(&self) -> DeviceCaps;

    fn receive(&mut self, now: Instant) -> Option<(HwAddr, Payload<S>)>;
}
