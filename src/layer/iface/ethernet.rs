use core::net::{IpAddr, Ipv6Addr};

use heapless::Vec;

use super::{neighbor::StaticNeighborCache, HwAddr, NetRx, NetTx, Payload};
use crate::{
    config::*,
    context::Ends,
    layer::{DeviceCaps, NeighborCacheOption, NeighborLookupError, PhyRx, PhyTx, TxResult},
    storage::Storage,
    time::Instant,
    wire::*,
};

#[derive(Debug)]
pub struct EthernetRx<D: ?Sized> {
    device: D,
}

impl<D> EthernetRx<D> {
    pub const fn new(device: D) -> Self {
        Self { device }
    }
}

impl<S: Storage, D: PhyRx<S> + ?Sized> NetRx<S> for EthernetRx<D> {
    fn hw_addr(&self) -> HwAddr {
        self.device.hw_addr()
    }

    fn device_caps(&self) -> DeviceCaps {
        self.device.caps().add_header_len(ETHERNET_HEADER_LEN)
    }

    fn receive(&mut self, now: Instant) -> Option<(HwAddr, Payload<S>)> {
        let buf = self.device.receive(now)?;

        let packet = match EthernetFrame::parse(&(), buf) {
            Ok(packet) => packet,
            Err(err) => log_parse!(err => None),
        };

        if !packet.addr.dst.is_broadcast()
            && !packet.addr.dst.is_multicast()
            && HwAddr::Ethernet(packet.addr.dst) != self.hw_addr()
        {
            return None;
        }

        let cx = &(packet.protocol, self.device_caps().rx_checksums);
        let payload = match EthernetPayload::parse(cx, packet.payload) {
            Ok(payload) => payload,
            Err(err) => log_parse!(err => None),
        };

        Some((HwAddr::Ethernet(packet.addr.src), payload))
    }
}

#[derive(Debug)]
pub struct EthernetTx<D: ?Sized> {
    ip: Vec<IpCidr, STATIC_IFACE_IP_CAPACITY>,
    neighbor_cache: StaticNeighborCache,
    device: D,
}

impl<D> EthernetTx<D> {
    pub const fn new(device: D) -> Self {
        Self {
            ip: Vec::new(),
            neighbor_cache: StaticNeighborCache::new(),
            device,
        }
    }
}

impl<D: ?Sized> EthernetTx<D> {
    pub fn flush_cache(&mut self) {
        self.neighbor_cache.flush()
    }
}

impl<S: Storage, D: PhyTx<S> + ?Sized> NetTx<S> for EthernetTx<D> {
    fn hw_addr(&self) -> HwAddr {
        self.device.hw_addr()
    }

    fn device_caps(&self) -> DeviceCaps {
        self.device.caps().add_header_len(ETHERNET_HEADER_LEN)
    }

    fn has_ip(&self, ip: IpAddr) -> bool {
        self.ip.iter().any(|cidr| cidr.addr() == ip)
    }

    fn is_same_net(&self, ip: IpAddr) -> bool {
        self.ip.iter().any(|cidr| cidr.contains_addr(&ip))
    }

    fn is_broadcast(&self, ip: IpAddr) -> bool {
        ip.is_broadcast()
            || (self.ip.iter())
                .filter_map(|cidr| cidr.broadcast())
                .any(|b| b == ip)
    }

    fn has_solicited_node(&self, ip: Ipv6Addr) -> bool {
        self.ip.iter().any(|cidr| match cidr {
            IpCidr::V6(cidr) if cidr.addr() != Ipv6Addr::LOOPBACK => {
                cidr.addr().octets()[14..] == ip.octets()[14..]
            }
            _ => false,
        })
    }

    fn fill_neighbor_cache(
        &mut self,
        now: Instant,
        entry: (IpAddr, HwAddr),
        opt: NeighborCacheOption,
    ) {
        self.neighbor_cache.fill(now, entry, opt);
    }

    fn lookup_neighbor_cache(
        &self,
        now: Instant,
        ip: IpAddr,
    ) -> Result<HwAddr, NeighborLookupError> {
        self.neighbor_cache.lookup(now, ip)
    }

    fn transmit(&mut self, now: Instant, dst: HwAddr, packet: Payload<S>) -> TxResult {
        let addr = Ends { src: self.hw_addr(), dst };

        let packet = EthernetFrame {
            addr: addr.map(HwAddr::unwrap_ethernet),
            protocol: packet.ethernet_protocol(),
            payload: packet,
        };

        let buf = uncheck_build!(packet.build(&(self.device_caps().tx_checksums,)));
        self.device.transmit(now, buf)
    }
}
