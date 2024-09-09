use super::{ipv4, ipv6};
use crate::{phy::DeviceCaps, wire::*};

pub(crate) enum Icmp<P: Payload> {
    NoRoute(IpPacket<P>),
    NoProtocol(IpPacket<P>),
    HopLimitExceeded(IpPacket<P>),
}

enum IcmpType {
    NoRoute,
    NoProtocol,
    HopLimitExceeded,
}

impl<P: PayloadBuild> Icmp<P> {
    fn split(self) -> (IcmpType, IpPacket<P>) {
        match self {
            Icmp::NoRoute(packet) => (IcmpType::NoRoute, packet),
            Icmp::NoProtocol(packet) => (IcmpType::NoProtocol, packet),
            Icmp::HopLimitExceeded(packet) => (IcmpType::HopLimitExceeded, packet),
        }
    }
}

impl<P: PayloadBuild> Icmp<P> {
    pub fn build(self, device_caps: &DeviceCaps) -> EthernetPayload<P, P::NoPayload> {
        let (icmp_type, packet) = self.split();

        match packet {
            IpPacket::V4(packet) => {
                let addr = packet.addr.reverse();
                let icmp = match icmp_type {
                    IcmpType::NoRoute => Icmpv4Packet::DstUnreachable {
                        reason: Icmpv4DstUnreachable::HostUnreachable,
                        payload: Lax(packet),
                    },
                    IcmpType::NoProtocol => Icmpv4Packet::DstUnreachable {
                        reason: Icmpv4DstUnreachable::ProtoUnreachable,
                        payload: Lax(packet),
                    },
                    IcmpType::HopLimitExceeded => Icmpv4Packet::TimeExceeded {
                        reason: Icmpv4TimeExceeded::TtlExpired,
                        payload: Lax(packet),
                    },
                };
                ipv4::icmp_reply(device_caps, addr, icmp)
            }
            IpPacket::V6(packet) => {
                let addr = packet.addr.reverse();
                let icmp = match icmp_type {
                    IcmpType::NoRoute => Icmpv6Packet::DstUnreachable {
                        reason: Icmpv6DstUnreachable::NoRoute,
                        payload: Lax(packet),
                    },
                    IcmpType::NoProtocol => Icmpv6Packet::ParamProblem {
                        reason: Icmpv6ParamProblem::UnrecognizedNxtHdr,
                        pointer: packet.header_len() as u32,
                        payload: Lax(packet),
                    },
                    IcmpType::HopLimitExceeded => Icmpv6Packet::TimeExceeded {
                        reason: Icmpv6TimeExceeded::HopLimitExceeded,
                        payload: Lax(packet),
                    },
                };
                ipv6::icmp_reply(device_caps, addr, icmp)
            }
        }
    }
}
