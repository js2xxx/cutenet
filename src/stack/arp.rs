use core::net::IpAddr;

use crate::{
    iface::{neighbor::CacheOption, NetTx},
    route::Router,
    time::Instant,
    wire::*,
};

pub(super) fn process_arp<P, R>(
    now: Instant,
    router: &mut R,
    hw: HwAddr,
    packet: ArpPacket<P::NoPayload>,
) where
    P: Payload,
    R: Router<P>,
{
    let Ends {
        src: (src_hw, src_ip),
        dst: (_dst_hw, dst_ip),
    } = packet.addr;

    let Some(mut tx) = router.device(now, hw) else {
        return;
    };

    if !tx.has_ip(IpAddr::V4(src_ip)) {
        return;
    }

    if let ArpOperation::Unknown(unknown) = packet.operation {
        #[cfg(feature = "log")]
        tracing::debug!("unknown ARP operation {unknown}");
        return;
    }

    // Discard packets with non-unicast source addresses.
    if !src_hw.is_unicast() || !src_ip.is_unicast() {
        #[cfg(feature = "log")]
        tracing::debug!("arp: non-unicast source address {src_hw}/{src_ip}");
        return;
    }

    if !tx.is_same_net(IpAddr::V4(src_ip)) {
        return;
    }

    tx.fill_neighbor_cache(
        now,
        (IpAddr::V4(src_ip), HwAddr::Ethernet(src_hw)),
        CacheOption::Override,
    );

    if packet.operation == ArpOperation::Request {
        let mut packet = packet;
        packet.operation = ArpOperation::Reply;
        packet.addr = Ends {
            src: (hw.unwrap_ethernet(), dst_ip),
            dst: (src_hw, src_ip),
        };

        let _ = tx.transmit(now, src_hw.into(), EthernetPayload::Arp(packet));
    }
}
