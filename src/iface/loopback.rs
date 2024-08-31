use core::{
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use heapless::mpmc::MpMcQueue;

use super::{NetRx, NetTx, Payload};
use crate::{
    config::STATIC_LOOPBACK_CAPACITY,
    iface::neighbor::{CacheOption, LookupError},
    phy::DeviceCaps,
    storage::Storage,
    time::Instant,
    wire::*,
    TxDropReason::QueueFull,
    TxResult,
};

pub struct StaticLoopback<S: Storage> {
    q: MpMcQueue<Payload<S>, STATIC_LOOPBACK_CAPACITY>,
}

impl<S: Storage> fmt::Debug for StaticLoopback<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StaticLoopback").finish_non_exhaustive()
    }
}

impl<S: Storage> StaticLoopback<S> {
    pub const fn new() -> Self {
        Self { q: MpMcQueue::new() }
    }
}

pub const IP: [IpCidr; 2] = [
    IpCidr::V4(Ipv4Cidr::new(Ipv4Addr::LOCALHOST, 8)),
    IpCidr::V6(Ipv6Cidr::new(Ipv6Addr::LOCALHOST, 128)),
];

pub const DEVICE_CAPS: DeviceCaps = DeviceCaps {
    header_len: 0,
    ip_mtu: 65536,
    rx_checksums: Checksums::IGNORE,
    tx_checksums: Checksums::IGNORE,
};

impl<S: Storage> Default for StaticLoopback<S> {
    fn default() -> Self {
        Self::new()
    }
}

impl<S: Storage> NetRx<S> for &StaticLoopback<S> {
    fn hw_addr(&self) -> HwAddr {
        HwAddr::Ip
    }

    fn device_caps(&self) -> DeviceCaps {
        DEVICE_CAPS
    }

    fn receive(&mut self, now: Instant) -> Option<(HwAddr, Payload<S>)> {
        #[cfg(feature = "log")]
        tracing::trace!(target: "net::loopback", "receive at {now}");
        self.q.dequeue().map(|payload| (HwAddr::Ip, payload))
    }
}

impl<S: Storage> NetTx<S> for &StaticLoopback<S> {
    fn hw_addr(&self) -> HwAddr {
        HwAddr::Ip
    }

    fn device_caps(&self) -> DeviceCaps {
        DEVICE_CAPS
    }

    fn has_ip(&self, ip: IpAddr) -> bool {
        IP.iter().any(|cidr| cidr.addr() == ip)
    }

    fn is_same_net(&self, ip: IpAddr) -> bool {
        IP.iter().any(|cidr| cidr.contains_addr(&ip))
    }

    fn is_broadcast(&self, ip: IpAddr) -> bool {
        ip.is_broadcast()
            || IP
                .iter()
                .filter_map(|cidr| cidr.broadcast())
                .any(|b| b == ip)
    }

    fn has_solicited_node(&self, ip: core::net::Ipv6Addr) -> bool {
        IP.iter().any(|cidr| match cidr {
            IpCidr::V6(cidr) if cidr.addr() != Ipv6Addr::LOOPBACK => {
                cidr.addr().octets()[14..] == ip.octets()[14..]
            }
            _ => false,
        })
    }

    fn fill_neighbor_cache(&mut self, _: Instant, _: (IpAddr, HwAddr), _: CacheOption) {}

    fn lookup_neighbor_cache(&self, _: Instant, ip: IpAddr) -> Result<HwAddr, LookupError> {
        if self.is_same_net(ip) {
            Ok(HwAddr::Ip)
        } else {
            Err(LookupError { rate_limited: false })
        }
    }

    fn transmit(&mut self, now: Instant, _: HwAddr, packet: Payload<S>) -> TxResult {
        #[cfg(feature = "log")]
        tracing::trace!(target: "net::loopback", "receiving packet at {now}");
        match self.q.enqueue(packet) {
            Ok(()) => TxResult::Success,
            Err(_) => {
                #[cfg(feature = "log")]
                tracing::info!(target: "net::loopback", "queue full at {now}, dropping packet");
                TxResult::Dropped(QueueFull)
            }
        }
    }
}

#[cfg(any(feature = "std", feature = "alloc"))]
mod alloc {
    use ::alloc::sync::Arc;
    use crossbeam_queue::ArrayQueue;

    use super::*;
    use crate::storage::Storage;

    #[derive(Debug, Clone)]
    pub struct ArcLoopbackRx<S: Storage>(Arc<ArrayQueue<Payload<S>>>);

    #[derive(Debug, Clone)]
    pub struct ArcLoopbackTx<S: Storage>(Arc<ArrayQueue<Payload<S>>>);

    pub fn arc_loopback<S: Storage>(capacity: usize) -> (ArcLoopbackTx<S>, ArcLoopbackRx<S>) {
        let q = Arc::new(ArrayQueue::new(capacity));
        let tx = ArcLoopbackTx(q.clone());
        let rx = ArcLoopbackRx(q);
        (tx, rx)
    }

    impl<S: Storage> NetRx<S> for ArcLoopbackRx<S> {
        fn hw_addr(&self) -> HwAddr {
            HwAddr::Ip
        }

        fn device_caps(&self) -> DeviceCaps {
            DEVICE_CAPS
        }

        fn receive(&mut self, now: Instant) -> Option<(HwAddr, Payload<S>)> {
            #[cfg(feature = "log")]
            tracing::trace!(target: "net::loopback", "receive at {now}");
            self.0.pop().map(|p| (HwAddr::Ip, p))
        }
    }

    impl<S: Storage> NetTx<S> for ArcLoopbackTx<S> {
        fn hw_addr(&self) -> HwAddr {
            HwAddr::Ip
        }

        fn device_caps(&self) -> DeviceCaps {
            DEVICE_CAPS
        }

        fn has_ip(&self, ip: IpAddr) -> bool {
            IP.iter().any(|cidr| cidr.addr() == ip)
        }

        fn is_same_net(&self, ip: IpAddr) -> bool {
            IP.iter().any(|cidr| cidr.contains_addr(&ip))
        }

        fn is_broadcast(&self, ip: IpAddr) -> bool {
            ip.is_broadcast()
                || IP
                    .iter()
                    .filter_map(|cidr| cidr.broadcast())
                    .any(|b| b == ip)
        }

        fn has_solicited_node(&self, ip: core::net::Ipv6Addr) -> bool {
            IP.iter().any(|cidr| match cidr {
                IpCidr::V6(cidr) if cidr.addr() != Ipv6Addr::LOOPBACK => {
                    cidr.addr().octets()[14..] == ip.octets()[14..]
                }
                _ => false,
            })
        }

        fn fill_neighbor_cache(&mut self, _: Instant, _: (IpAddr, HwAddr), _: CacheOption) {}

        fn lookup_neighbor_cache(&self, _: Instant, ip: IpAddr) -> Result<HwAddr, LookupError> {
            if self.is_same_net(ip) {
                Ok(HwAddr::Ip)
            } else {
                Err(LookupError { rate_limited: false })
            }
        }

        fn transmit(&mut self, now: Instant, _: HwAddr, packet: Payload<S>) -> TxResult {
            #[cfg(feature = "log")]
            tracing::trace!(target: "net::loopback", "receiving packet at {now}");
            match self.0.push(packet) {
                Ok(()) if self.0.len() * 8 < self.0.capacity() * 7 => TxResult::Success,
                Ok(()) => TxResult::CongestionAlert,
                Err(_) => {
                    #[cfg(feature = "log")]
                    tracing::info!(target: "net::loopback", "queue full at {now}, dropping packet");
                    TxResult::Dropped(QueueFull)
                }
            }
        }
    }
}
#[cfg(any(feature = "std", feature = "alloc"))]
pub use self::alloc::{arc_loopback, ArcLoopbackRx, ArcLoopbackTx};
