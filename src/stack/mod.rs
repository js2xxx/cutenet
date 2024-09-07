use core::net::IpAddr;

use super::{
    iface::{
        neighbor::{CacheOption, LookupError},
        NetRx, NetTx,
    },
    route::{Action, Query, Router},
    socket::{AllSocketSet, RawSocketSet, SocketRecv, SocketState},
    TxDropReason, TxResult,
};
use crate::{time::Instant, wire::*};

mod arp;
mod ipv4;
mod ipv6;

pub trait RouterExt<P: Payload>: Router<P> + Sized {
    fn process<Rx, A>(&mut self, now: Instant, mut rx: Rx, mut sockets: A) -> bool
    where
        P: PayloadParse + PayloadBuild,
        Rx: NetRx<P>,
        A: AllSocketSet<P>,
    {
        let Some((src_hw, payload)) = rx.receive(now) else {
            return false;
        };
        let hw = rx.hw_addr();
        let device_caps = rx.device_caps();
        drop(rx);

        let packet = match payload {
            EthernetPayload::Arp(packet) => {
                self::arp::process_arp(now, self, hw, packet);
                return true;
            }
            EthernetPayload::Ip(packet) => packet,
        };

        let addr = packet.ip_addr();
        let action = match self.route(now, Query {
            addr,
            next_header: packet.next_header(),
        }) {
            Action::Deliver => Action::Deliver,
            Action::Forward { next_hop, mut tx } => {
                let mut packet = packet;
                // TODO: handle forwarding results.
                let _ = if packet.decrease_hop_limit() {
                    transmit(now, next_hop, tx, packet, ())
                } else {
                    tx.transmit(now, src_hw, match packet {
                        IpPacket::V4(packet) => {
                            let addr = packet.addr.reverse();
                            ipv4::icmp_reply(&tx.device_caps(), addr, Icmpv4Packet::TimeExceeded {
                                reason: Icmpv4TimeExceeded::TtlExpired,
                                payload: Lax(packet),
                            })
                        }
                        IpPacket::V6(packet) => {
                            let addr = packet.addr.reverse();
                            ipv6::icmp_reply(&tx.device_caps(), addr, Icmpv6Packet::TimeExceeded {
                                reason: Icmpv6TimeExceeded::HopLimitExceeded,
                                payload: Lax(packet),
                            })
                        }
                    })
                };
                return true;
            }
            Action::Discard => Action::Discard,
        };

        if let Some(mut tx) = self.device(now, hw) {
            match action {
                Action::Deliver => {
                    tx.fill_neighbor_cache(now, (addr.src, src_hw), CacheOption::UpdateExpiration)
                }
                Action::Forward { tx: (), .. } => unreachable!(),
                Action::Discard => {
                    let _ = tx.transmit(now, src_hw, match packet {
                        IpPacket::V4(packet) => ipv4::icmp_reply(
                            &tx.device_caps(),
                            packet.addr.reverse(),
                            Icmpv4Packet::DstUnreachable {
                                reason: Icmpv4DstUnreachable::HostUnreachable,
                                payload: Lax(packet),
                            },
                        ),
                        IpPacket::V6(packet) => ipv6::icmp_reply(
                            &tx.device_caps(),
                            packet.addr.reverse(),
                            Icmpv6Packet::DstUnreachable {
                                reason: Icmpv6DstUnreachable::NoRoute,
                                payload: Lax(packet),
                            },
                        ),
                    });
                    return true;
                }
            }
        }

        let raw_processed = sockets.raw().receive(now, &device_caps, &packet);

        let hw = Ends { src: src_hw, dst: hw };
        let res = match packet {
            IpPacket::V4(packet) => {
                ipv4::process(now, &device_caps, self, &mut sockets, hw, packet)
            }
            IpPacket::V6(packet) => {
                ipv6::process(now, &device_caps, self, &mut sockets, hw, packet)
            }
        };

        let packet = match res {
            SocketRecv::Received(()) => return true,
            SocketRecv::NotReceived(_) if raw_processed => return true,
            SocketRecv::NotReceived(packet) => packet,
        };

        if let Some(mut tx) = self.device(now, hw.dst) {
            let packet = match packet {
                IpPacket::V4(packet) => {
                    let addr = packet.addr.reverse();
                    let icmp = Icmpv4Packet::DstUnreachable {
                        reason: Icmpv4DstUnreachable::ProtoUnreachable,
                        payload: Lax(packet),
                    };
                    ipv4::icmp_reply(&tx.device_caps(), addr, icmp)
                }
                IpPacket::V6(packet) => {
                    let addr = packet.addr.reverse();
                    let icmp = Icmpv6Packet::ParamProblem {
                        reason: Icmpv6ParamProblem::UnrecognizedNxtHdr,
                        pointer: packet.header_len() as u32,
                        payload: Lax(packet),
                    };
                    ipv6::icmp_reply(&tx.device_caps(), addr, icmp)
                }
            };
            let _ = tx.transmit(now, src_hw, packet);
        }
        true
    }

    fn dispatch<Ss, E>(
        &mut self,
        now: Instant,
        addr: Ends<IpAddr>,
        next_header: IpProtocol,
        packet: impl FnOnce(&Self::Tx<'_>) -> Result<(IpPacket<P>, Ss), E>,
    ) -> Result<TxResult, E>
    where
        P: PayloadBuild,
        Ss: SocketState,
    {
        match self.route(now, Query { addr, next_header }) {
            Action::Deliver => {}
            Action::Forward { next_hop, tx } => {
                let (packet, ss) = packet(&tx)?;
                return Ok(transmit(now, next_hop, tx, packet, ss));
            }
            Action::Discard => return Ok(TxResult::Dropped(TxDropReason::NoRoute)),
        }
        match self.loopback(now) {
            Some(mut loopback) => {
                let (packet, _ss) = packet(&loopback)?;
                Ok(loopback.transmit(now, HwAddr::Ip, EthernetPayload::Ip(packet)))
            }
            None => Ok(TxResult::Dropped(TxDropReason::NoRoute)),
        }
    }
}
impl<P: Payload, R: Router<P>> RouterExt<P> for R {}

fn transmit<P, Tx, Ss>(
    now: Instant,
    next_hop: IpAddr,
    mut tx: Tx,
    packet: IpPacket<P>,
    ss: Ss,
) -> TxResult
where
    P: PayloadBuild,
    Tx: NetTx<P>,
    Ss: SocketState,
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
        Err(LookupError { rate_limited }) => {
            ss.neighbor_missing(now, next_hop);
            if rate_limited {
                return TxResult::Dropped(TxDropReason::NeighborPending);
            }
        }
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

            let buf = buf.reserve(packet.buffer_len() + tx.device_caps().header_len);
            let packet = packet.sub_no_payload(|_| buf);

            let _ = tx.transmit(
                now,
                EthernetAddr::BROADCAST.into(),
                EthernetPayload::Arp(packet),
            );
        }
        (IpAddr::V6(src), IpAddr::V6(dst)) => {
            let dst = dst.solicited_node();

            let packet = ipv6::icmp_reply(&tx.device_caps(), Ends { src, dst }, Icmpv6Packet::Nd {
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

            let _ = tx.transmit(now, hw_dst, packet);
        }
        _ => unreachable!(),
    }
    TxResult::Dropped(TxDropReason::NeighborPending)
}
