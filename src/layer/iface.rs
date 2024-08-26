use core::net::{IpAddr, Ipv6Addr};

use crate::{
    storage::{Buf, ReserveBuf, Storage},
    time::Instant,
    wire::*,
};

pub type Payload<S: Storage> = crate::wire::EthernetPayload<Buf<S>, ReserveBuf<S>>;

#[derive(Debug, Clone, Copy)]
pub struct Checksums {
    pub ip: bool,
    pub udp: bool,
    pub tcp: bool,
    pub icmp: bool,
}

impl Checksums {
    pub const fn new() -> Self {
        Checksums {
            ip: true,
            udp: true,
            tcp: true,
            icmp: true,
        }
    }

    pub const IGNORE: Self = Checksums {
        ip: false,
        udp: false,
        tcp: false,
        icmp: false,
    };
}

impl Default for Checksums {
    fn default() -> Self {
        Checksums::new()
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct DeviceCaps {
    pub header_len: usize,
    pub ip_mtu: usize,

    pub rx_checksums: Checksums,
    pub tx_checksums: Checksums,
}

impl DeviceCaps {
    pub const fn new() -> Self {
        DeviceCaps {
            header_len: 0,
            ip_mtu: 1500,

            rx_checksums: Checksums::new(),
            tx_checksums: Checksums::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NeighborLookupError {
    pub rate_limited: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NeighborCacheOption {
    Override,
    UpdateHwAddr,
    UpdateExpiration,
}

pub trait NetTx<S: Storage> {
    fn hw_addr(&self) -> HwAddr;

    fn device_caps(&self) -> &DeviceCaps;

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

    fn device_caps(&self) -> &DeviceCaps;

    fn receive(&mut self) -> Option<(HwAddr, Payload<S>)>;
}
