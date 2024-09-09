use core::net::{IpAddr, Ipv6Addr};

use heapless::Vec;

use super::{neighbor::StaticNeighborCache, HwAddr, NetPayload, NetRx, NetTx};
use crate::{
    config::*,
    iface::neighbor::CacheOption,
    phy::{DeviceCaps, PhyRx, PhyTx},
    time::Instant,
    wire::*,
    TxResult,
};

pub struct EthernetRx<D: ?Sized> {
    device: D,
}

impl<D> EthernetRx<D> {
    pub const fn new(device: D) -> Self {
        Self { device }
    }
}

impl<P, D> NetRx<P> for EthernetRx<D>
where
    P: PayloadParse,
    D: PhyRx<P> + ?Sized,
{
    fn hw_addr(&self) -> HwAddr {
        self.device.hw_addr()
    }

    fn device_caps(&self) -> DeviceCaps {
        self.device.caps().add_header_len(ETHERNET_HEADER_LEN)
    }

    fn receive(&mut self, now: Instant) -> Option<(HwAddr, NetPayload<P>)> {
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
pub struct EthernetTx<P, D>
where
    P: Payload,
    D: PhyTx<P> + ?Sized,
{
    ip: Vec<IpCidr, STATIC_IFACE_IP_CAPACITY>,
    neighbor_cache: StaticNeighborCache,
    nd_payload_cache: Vec<P::NoPayload, STATIC_IFACE_ND_PAYLOAD_CAPACITY>,
    device: D,
}

impl<P, D> EthernetTx<P, D>
where
    P: Payload,
    D: PhyTx<P>,
{
    pub const fn new(device: D) -> Self {
        Self {
            ip: Vec::new(),
            neighbor_cache: StaticNeighborCache::new(),
            nd_payload_cache: Vec::new(),
            device,
        }
    }
}

impl<P, D> EthernetTx<P, D>
where
    P: Payload,
    D: PhyTx<P> + ?Sized,
{
    pub fn flush_cache(&mut self) {
        self.neighbor_cache.flush()
    }

    pub fn update_nd_payload_cache<T, F>(&mut self, f: F) -> T
    where
        F: FnOnce(&mut Vec<P::NoPayload, STATIC_IFACE_ND_PAYLOAD_CAPACITY>) -> T,
    {
        f(&mut self.nd_payload_cache)
    }
}

impl<P, D> NetTx<P> for EthernetTx<P, D>
where
    P: PayloadBuild,
    D: PhyTx<P> + ?Sized,
{
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
        opt: CacheOption,
        nop: Option<P::NoPayload>,
        entry: (IpAddr, HwAddr),
    ) {
        self.neighbor_cache.fill(now, entry, opt);
        if let Some(nop) = nop {
            let _ = self.nd_payload_cache.push(nop);
        }
    }

    fn lookup_neighbor_cache(
        &mut self,
        now: Instant,
        ip: IpAddr,
    ) -> Result<HwAddr, Option<P::NoPayload>> {
        let lookup = self.neighbor_cache.lookup(now, ip);
        lookup.map_err(|err| match err.rate_limited {
            true => None,
            false => self.nd_payload_cache.pop(),
        })
    }

    fn transmit(&mut self, now: Instant, dst: HwAddr, packet: NetPayload<P>) -> TxResult {
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
