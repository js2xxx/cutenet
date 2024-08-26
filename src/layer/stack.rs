use core::net::IpAddr;

use super::{
    iface::{NeighborCacheOption, NeighborLookupError, NetRx, NetTx},
    route::{Action, Query, Router},
    socket::{AllSocketSet, RawSocketSet, SocketRecv},
};
use crate::{
    context::Ends,
    storage::{Buf, Storage},
    time::Instant,
    wire::*,
};

mod arp;
mod ipv4;
mod ipv6;

pub fn process<S, Rx, R, A>(now: Instant, mut rx: Rx, mut router: R, mut sockets: A)
where
    S: Storage,
    Rx: NetRx<S>,
    R: Router<S>,
    A: AllSocketSet<S>,
{
    let Some((src_hw, payload)) = rx.receive() else {
        return;
    };
    let hw = rx.hw_addr();
    let device_caps = rx.device_caps();

    let packet = match payload {
        EthernetPayload::Arp(packet) => {
            return self::arp::process_arp(now, &mut router, hw, packet)
        }
        EthernetPayload::Ip(packet) => packet,
    };

    let addr = packet.ip_addr();
    let action = match router.route(now, Query {
        addr,
        next_header: packet.next_header(),
    }) {
        Action::Deliver => Action::Deliver,
        Action::Forward { next_hop, tx } => {
            // TODO: decrease TTL and reply an ICMP if error.
            return transmit(now, next_hop, tx, packet);
        }
        Action::Discard => Action::Discard,
    };

    if let Some(mut tx) = router.device(now, hw) {
        match action {
            Action::Deliver => tx.fill_neighbor_cache(
                now,
                (addr.src, src_hw),
                NeighborCacheOption::UpdateExpiration,
            ),
            Action::Forward { tx: (), .. } => unreachable!(),
            Action::Discard => {
                return tx.transmit(now, src_hw, match packet {
                    IpPacket::V4(packet) => ipv4::icmp_reply(
                        device_caps,
                        packet.addr.reverse(),
                        Icmpv4Packet::DstUnreachable {
                            reason: Icmpv4DstUnreachable::HostUnreachable,
                            payload: packet,
                        },
                    ),
                    IpPacket::V6(_) => todo!(),
                });
            }
        }
    }

    let raw_processed = sockets.raw().receive(now, device_caps, &packet);

    let hw = Ends { src: src_hw, dst: hw };
    let res = match packet {
        IpPacket::V4(packet) => {
            ipv4::process(now, device_caps, &mut router, &mut sockets, hw, packet)
        }
        IpPacket::V6(packet) => {
            ipv6::process(now, device_caps, &mut router, &mut sockets, hw, packet)
        }
    };

    let packet = match res {
        SocketRecv::Received { reply: () } => return,
        SocketRecv::NotReceived(_) if raw_processed => return,
        SocketRecv::NotReceived(packet) => match packet {
            IpPacket::V4(packet) => {
                let addr = packet.addr.reverse();
                let icmp = Icmpv4Packet::DstUnreachable {
                    reason: Icmpv4DstUnreachable::ProtoUnreachable,
                    payload: packet,
                };
                ipv4::icmp_reply(device_caps, addr, icmp)
            }
            IpPacket::V6(packet) => {
                let addr = packet.addr.reverse();
                let icmp = Icmpv6Packet::ParamProblem {
                    reason: Icmpv6ParamProblem::UnrecognizedNxtHdr,
                    pointer: packet.header_len() as u32,
                    header: packet,
                };
                ipv6::icmp_reply(device_caps, addr, icmp)
            }
        },
    };
    if let Some(mut tx) = router.device(now, hw.dst) {
        tx.transmit(now, src_hw, packet)
    }
}

pub fn dispatch<S, R>(now: Instant, mut router: R, packet: IpPacket<Buf<S>>)
where
    S: Storage,
    R: Router<S>,
{
    dispatch_impl(now, &mut router, packet)
}

fn dispatch_impl<S, R>(now: Instant, router: &mut R, packet: IpPacket<Buf<S>>)
where
    S: Storage,
    R: Router<S>,
{
    match router.route(now, Query {
        addr: packet.ip_addr(),
        next_header: packet.next_header(),
    }) {
        Action::Deliver => {}
        Action::Forward { next_hop, tx } => return transmit(now, next_hop, tx, packet),
        Action::Discard => return,
    }
    if let Some(mut loopback) = router.loopback(now) {
        loopback.transmit(now, HwAddr::Ip, EthernetPayload::Ip(packet))
    }
}

fn transmit<S, Tx>(now: Instant, next_hop: IpAddr, mut tx: Tx, packet: IpPacket<Buf<S>>)
where
    S: Storage,
    Tx: NetTx<S>,
{
    let ip = packet.ip_addr();

    let hw = tx.hw_addr();
    if let HwAddr::Ip = hw {
        return tx.transmit(now, hw, EthernetPayload::Ip(packet));
    }

    if tx.is_broadcast(ip.dst) {
        let dst = match hw {
            HwAddr::Ethernet(_) => HwAddr::Ethernet(EthernetAddr::BROADCAST),
            HwAddr::Ieee802154(_) => HwAddr::Ieee802154(Ieee802154Addr::BROADCAST),
            HwAddr::Ip => unreachable!(),
        };
        return tx.transmit(now, dst, EthernetPayload::Ip(packet));
    }

    if ip.dst.is_multicast() {
        let dst = match hw {
            HwAddr::Ethernet(_) => HwAddr::Ethernet(ip.dst.multicast_ethernet()),
            HwAddr::Ieee802154(_) => HwAddr::Ieee802154(Ieee802154Addr::BROADCAST),
            HwAddr::Ip => unreachable!(),
        };
        return tx.transmit(now, dst, EthernetPayload::Ip(packet));
    }

    match tx.lookup_neighbor_cache(now, next_hop) {
        Ok(dst) => {
            return tx.transmit(now, dst, EthernetPayload::Ip(packet));
        }
        Err(NeighborLookupError { rate_limited: true }) => return,
        Err(_) => {}
    }

    let (_, buf) = packet.sub_payload_ref(|p| PayloadHolder(p.len()));
    let buf = buf.reset();

    match (ip.src, ip.dst) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => {
            let packet = ArpPacket {
                operation: ArpOperation::Request,
                addr: Ends {
                    src: (tx.hw_addr().unwrap_ethernet(), src),
                    dst: (EthernetAddr::BROADCAST, dst),
                },
                payload: NoPayloadHolder,
            };

            let buf = buf.add_reservation(packet.buffer_len() + tx.device_caps().header_len);
            let packet = packet.sub_no_payload(|_| buf);

            tx.transmit(
                now,
                EthernetAddr::BROADCAST.into(),
                EthernetPayload::Arp(packet),
            )
        }
        (IpAddr::V6(src), IpAddr::V6(dst)) => {
            let dst = dst.solicited_node();

            let packet = ipv6::icmp_reply(tx.device_caps(), Ends { src, dst }, Icmpv6Packet::Nd {
                nd: Icmpv6Nd::NeighborSolicit {
                    target_addr: dst,
                    lladdr: Some(hw.into()),
                },
                payload: buf,
            });

            let hw_dst = match hw {
                HwAddr::Ethernet(_) => HwAddr::Ethernet(dst.multicast_ethernet()),
                HwAddr::Ieee802154(_) => HwAddr::Ieee802154(Ieee802154Addr::BROADCAST),
                HwAddr::Ip => unreachable!(),
            };

            tx.transmit(now, hw_dst, packet)
        }
        _ => unreachable!(),
    }
}
