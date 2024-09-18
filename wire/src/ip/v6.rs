use core::net::{IpAddr, Ipv4Addr, Ipv6Addr, Ipv6MulticastScope};

use byteorder::{ByteOrder, NetworkEndian};

pub use self::cidr::Cidr;
use super::{IpAddrExt, Protocol, Version, WireCx};
use crate::{context::Ends, prelude::*};

#[path = "v6_cidr.rs"]
mod cidr;

#[path = "v6_hbh.rs"]
pub mod hbh;

#[path = "v6_opt.rs"]
pub mod option;

/// Minimum MTU required of all links supporting IPv6. See [RFC 8200 § 5].
///
/// [RFC 8200 § 5]: https://tools.ietf.org/html/rfc8200#section-5
pub const MIN_MTU: usize = 1280;

pub trait Ipv6AddrExt {
    const LINK_LOCAL_ALL_NODES: Ipv6Addr;
    const LINK_LOCAL_ALL_ROUTERS: Ipv6Addr;
    const LINK_LOCAL_ALL_MLDV2_ROUTERS: Ipv6Addr;
    const LINK_LOCAL_ALL_RPL_NODES: Ipv6Addr;
    const LOOPBACK: Ipv6Addr;

    fn is_link_local(&self) -> bool;

    fn is_global_unicast(&self) -> bool;

    fn solicited_node(&self) -> Self;

    fn unicast_scope(&self) -> Option<Ipv6MulticastScope>;

    fn from_ipv4_mapped(v4: Ipv4Addr) -> Self;
}

impl Ipv6AddrExt for Ipv6Addr {
    const LINK_LOCAL_ALL_NODES: Ipv6Addr = Ipv6Addr::new(
        0xff02, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0001,
    );

    const LINK_LOCAL_ALL_ROUTERS: Ipv6Addr = Ipv6Addr::new(
        0xff02, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0002,
    );

    const LINK_LOCAL_ALL_MLDV2_ROUTERS: Ipv6Addr = Ipv6Addr::new(
        0xff02, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0016,
    );

    const LINK_LOCAL_ALL_RPL_NODES: Ipv6Addr = Ipv6Addr::new(
        0xff02, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x001a,
    );

    const LOOPBACK: Ipv6Addr = Ipv6Addr::new(
        0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0001,
    );

    fn is_link_local(&self) -> bool {
        self.octets()[0..8] == [0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
    }

    fn is_global_unicast(&self) -> bool {
        (self.octets()[0] >> 5) == 0b001
    }

    fn solicited_node(&self) -> Self {
        assert!(self.is_unicast());

        let [.., b13, b14, b15] = self.octets();
        Ipv6Addr::from([
            0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xFF, b13, b14,
            b15,
        ])
    }

    fn unicast_scope(&self) -> Option<Ipv6MulticastScope> {
        if self.is_link_local() {
            Some(Ipv6MulticastScope::LinkLocal)
        } else if self.is_unique_local() || self.is_global_unicast() {
            // ULA are considered global scope
            // https://www.rfc-editor.org/rfc/rfc6724#section-3.1
            Some(Ipv6MulticastScope::Global)
        } else {
            None
        }
    }

    fn from_ipv4_mapped(v4: Ipv4Addr) -> Self {
        v4.to_ipv6_mapped()
    }
}

struct RawPacket<T: ?Sized>(T);

mod field {
    use crate::field::*;

    // 4-bit version number, 8-bit traffic class, and the
    // 20-bit flow label.
    pub const VER_TC_FLOW: Field = 0..4;
    // 16-bit value representing the length of the payload.
    // Note: Options are included in this length.
    pub const LENGTH: Field = 4..6;
    // 8-bit value identifying the type of header following this
    // one. Note: The same numbers are used in IPv4.
    pub const NXT_HDR: usize = 6;
    // 8-bit value decremented by each node that forwards this
    // packet. The packet is discarded when the value is 0.
    pub const HOP_LIMIT: usize = 7;
    // IPv6 address of the source node.
    pub const SRC_ADDR: Field = 8..24;
    // IPv6 address of the destination node.
    pub const DST_ADDR: Field = 24..40;
}
pub const HEADER_LEN: usize = field::DST_ADDR.end;

wire!(impl RawPacket {
    version/set_version: u8 =>
        |data| data[field::VER_TC_FLOW.start] >> 4;
        |data, value| {
            // Make sure to retain the lower order bits which contain
            // the higher order bits of the traffic class
            data[0] = (data[0] & 0x0f) | ((value & 0x0f) << 4);
        };

    /// Return the traffic class.
    #[allow(unused)]
    traffic_class/set_traffic_class: u8 =>
        |data| ((NetworkEndian::read_u16(&data[0..2]) & 0x0ff0) >> 4) as u8;
        |data, value| {
            // Put the higher order 4-bits of value in the lower order
            // 4-bits of the first byte
            data[0] = (data[0] & 0xf0) | ((value & 0xf0) >> 4);
            // Put the lower order 4-bits of value in the higher order
            // 4-bits of the second byte
            data[1] = (data[1] & 0x0f) | ((value & 0x0f) << 4);
        };

    /// Return the flow label field.
    #[allow(unused)]
    flow_label/set_flow_label: u32 =>
        |data| NetworkEndian::read_u24(&data[1..4]) & 0x000fffff;
        |data, value| {
            // Retain the lower order 4-bits of the traffic class
            let raw = (u32::from(data[1] & 0xf0) << 16) | (value & 0x0fffff);
            NetworkEndian::write_u24(&mut data[1..4], raw);
        };

    /// Return the payload length field.
    payload_len/set_payload_len: u16 =>
        |data| NetworkEndian::read_u16(&data[field::LENGTH]);
        |data, value| NetworkEndian::write_u16(&mut data[field::LENGTH], value);

    /// Return the next header field.
    next_header/set_next_header: Protocol =>
        |data| Protocol::from(data[field::NXT_HDR]);
        |data, value| data[field::NXT_HDR] = value.into();

    /// Return the hop limit field.
    hop_limit/set_hop_limit: u8 =>
        |data| data[field::HOP_LIMIT];
        |data, value| data[field::HOP_LIMIT] = value;

    /// Return the source address field.
    src_addr/set_src_addr: Ipv6Addr =>
        |data| Ipv6Addr::from_bytes(&data[field::SRC_ADDR]);
        |data, value| data[field::SRC_ADDR].copy_from_slice(&value.octets());

    /// Return the destination address field.
    dst_addr/set_dst_addr: Ipv6Addr =>
        |data| Ipv6Addr::from_bytes(&data[field::DST_ADDR]);
        |data, value| data[field::DST_ADDR].copy_from_slice(&value.octets());
});

impl<T: AsRef<[u8]> + ?Sized> RawPacket<T> {
    /// Return the payload length added to the known header length.
    pub fn total_len(&self) -> usize {
        HEADER_LEN + usize::from(self.payload_len())
    }

    pub fn addr(&self) -> Ends<Ipv6Addr> {
        Ends {
            src: self.src_addr(),
            dst: self.dst_addr(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Wire)]
#[prefix(crate)]
pub struct Packet<#[wire] T> {
    pub addr: Ends<Ipv6Addr>,
    pub next_header: Protocol,
    pub hop_limit: u8,
    #[wire]
    pub payload: T,
}

impl<P: PayloadParse, T: WireParse<Payload = P>> WireParse for Packet<T> {
    fn parse(cx: &dyn WireCx, raw: P) -> Result<Self, ParseError<P>> {
        let packet = RawPacket(raw.header_data());

        let len = packet.0.len();
        let total_len = packet.total_len();
        if len < field::DST_ADDR.end || len < total_len {
            return Err(ParseErrorKind::PacketTooShort.with(raw));
        }
        if packet.version() != 6 {
            return Err(ParseErrorKind::VersionInvalid.with(raw));
        }

        let generic_addr = packet.addr().map(IpAddr::V6);
        let next_header = packet.next_header();

        Ok(Packet {
            addr: packet.addr(),
            next_header,
            hop_limit: packet.hop_limit(),

            payload: T::parse(
                &[cx, &(generic_addr, next_header, Version::V6)],
                raw.pop(HEADER_LEN..total_len)
                    .map_err(|err| ParseErrorKind::PacketTooShort.with(err))?,
            )?,
        })
    }
}

impl<P: PayloadBuild, T: WireBuild<Payload = P>> WireBuild for Packet<T> {
    fn buffer_len(&self) -> usize {
        HEADER_LEN + self.payload_len()
    }

    fn build(self, cx: &dyn WireCx) -> Result<P, BuildError<P>> {
        let Packet {
            addr,
            next_header,
            hop_limit,
            payload,
        } = self;

        let generic_addr = addr.map(IpAddr::V6);
        let payload = payload.build(&[cx, &(generic_addr, next_header, Version::V6)])?;

        payload.push(HEADER_LEN, |buf| {
            let payload_len = u16::try_from(buf.len() - HEADER_LEN)
                .map_err(|_| BuildErrorKind::PayloadTooLong)?;

            let mut packet = RawPacket(buf);

            packet.set_version(6);
            packet.set_traffic_class(0);
            packet.set_flow_label(0);
            packet.set_payload_len(payload_len);

            packet.set_src_addr(addr.src);
            packet.set_dst_addr(addr.dst);
            packet.set_next_header(next_header);
            packet.set_hop_limit(hop_limit);

            Ok(())
        })
    }
}

impl<P: PayloadParse, T: WireParse<Payload = P>> WireParse for Lax<Packet<T>> {
    fn parse(cx: &dyn WireCx, raw: P) -> Result<Self, ParseError<P>> {
        let packet = RawPacket(raw.header_data());

        let len = packet.0.len();
        if len < field::DST_ADDR.end {
            return Err(ParseErrorKind::PacketTooShort.with(raw));
        }
        if packet.version() != 6 {
            return Err(ParseErrorKind::VersionInvalid.with(raw));
        }

        let generic_addr = packet.addr().map(IpAddr::V6);
        let next_header = packet.next_header();

        Ok(Lax(Packet {
            addr: packet.addr(),
            next_header,
            hop_limit: packet.hop_limit(),

            payload: T::parse(
                &[cx, &(generic_addr, next_header, Version::V6)],
                raw.pop(HEADER_LEN..len)
                    .map_err(|err| ParseErrorKind::PacketTooShort.with(err))?,
            )?,
        }))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Wire)]
#[prefix(crate)]
pub enum Ipv6Payload<#[wire] T, #[no_payload] U> {
    HopByHop(#[wire] crate::Ipv6HopByHopHeader<T>),
    Icmp(#[wire] crate::Icmpv6Packet<T, U>),
    Udp(#[wire] crate::UdpPacket<T>),
    Tcp(#[wire] crate::TcpPacket<T>),
}

impl<T, U> Ipv6Payload<T, U> {
    pub fn ip_protocol(&self) -> Protocol {
        match self {
            Ipv6Payload::HopByHop(_) => Protocol::HopByHop,
            Ipv6Payload::Icmp(_) => Protocol::Icmpv6,
            Ipv6Payload::Udp(_) => Protocol::Udp,
            Ipv6Payload::Tcp(_) => Protocol::Tcp,
        }
    }
}

impl<T, P, U> WireParse for Ipv6Payload<T, U>
where
    T: WireParse<Payload = P>,
    P: PayloadParse<NoPayload = U>,
    U: NoPayload<Init = P>,
{
    fn parse(cx: &dyn WireCx, raw: P) -> Result<Self, ParseError<P>> {
        Ok(match cx.ip_protocol() {
            Protocol::HopByHop => Ipv6Payload::HopByHop(crate::Ipv6HopByHopHeader::parse(cx, raw)?),
            Protocol::Icmpv6 => Ipv6Payload::Icmp(crate::Icmpv6Packet::parse(cx, raw)?),
            Protocol::Tcp => Ipv6Payload::Tcp(crate::TcpPacket::parse(cx, raw)?),
            Protocol::Udp => Ipv6Payload::Udp(crate::UdpPacket::parse(cx, raw)?),
            _ => return Err(ParseErrorKind::ProtocolUnknown.with(raw)),
        })
    }
}

impl<T, P, U> WireBuild for Ipv6Payload<T, U>
where
    T: WireBuild<Payload = P>,
    P: PayloadBuild<NoPayload = U>,
    U: NoPayload<Init = P>,
{
    fn buffer_len(&self) -> usize {
        match self {
            Ipv6Payload::HopByHop(packet) => packet.buffer_len(),
            Ipv6Payload::Icmp(packet) => packet.buffer_len(),
            Ipv6Payload::Tcp(packet) => packet.buffer_len(),
            Ipv6Payload::Udp(packet) => packet.buffer_len(),
        }
    }

    fn build(self, cx: &dyn WireCx) -> Result<P, BuildError<P>> {
        match self {
            Ipv6Payload::HopByHop(packet) => packet.build(cx),
            Ipv6Payload::Icmp(packet) => packet.build(cx),
            Ipv6Payload::Tcp(packet) => packet.build(cx),
            Ipv6Payload::Udp(packet) => packet.build(cx),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::vec;

    use cutenet_storage::{Buf, PayloadHolder};

    use super::*;

    const REPR_PACKET_BYTES: [u8; 52] = [
        0x60, 0x00, 0x00, 0x00, 0x00, 0x0c, 0x11, 0x40, 0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x02, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x02, 0x00,
        0x0c, 0x02, 0x4e, 0xff, 0xff, 0xff, 0xff,
    ];
    const REPR_PAYLOAD_BYTES: [u8; 12] = [
        0x00, 0x01, 0x00, 0x02, 0x00, 0x0c, 0x02, 0x4e, 0xff, 0xff, 0xff, 0xff,
    ];

    #[test]
    fn test_packet_deconstruction() {
        let packet: Packet<&[u8]> = Packet::parse(&(), &REPR_PACKET_BYTES[..]).unwrap();

        assert_eq!(packet.next_header, Protocol::Udp);
        assert_eq!(packet.hop_limit, 0x40);
        assert_eq!(packet.addr, Ends {
            src: Ipv6Addr::LINK_LOCAL_ALL_ROUTERS,
            dst: Ipv6Addr::LINK_LOCAL_ALL_NODES,
        });
        assert_eq!(packet.payload, &REPR_PAYLOAD_BYTES[..]);
    }

    #[test]
    fn test_packet_construction() {
        let ip = Packet {
            addr: Ends {
                src: Ipv6Addr::LINK_LOCAL_ALL_ROUTERS,
                dst: Ipv6Addr::LINK_LOCAL_ALL_NODES,
            },
            next_header: Protocol::Udp,
            hop_limit: 0x40,
            payload: PayloadHolder(REPR_PACKET_BYTES.len()),
        };
        let tag = ip;

        let bytes = vec![0xff; 52];
        let mut payload = Buf::builder(bytes).reserve_for(&tag).build();
        payload.append_slice(&REPR_PAYLOAD_BYTES);

        let packet = tag.sub_payload(|_| payload).build(&()).unwrap();
        assert_eq!(packet.data(), &REPR_PACKET_BYTES);
    }

    #[test]
    fn test_overlong() {
        let mut pb = vec![];
        pb.extend(REPR_PACKET_BYTES.into_iter().chain([0]));
        let packet: Packet<&[u8]> = Packet::parse(&(), &pb[..]).unwrap();

        assert_eq!(packet.payload.len(), REPR_PAYLOAD_BYTES.len());
    }

    #[test]
    fn test_repr_parse_smaller_than_header() {
        let mut bytes = [0; 40];
        bytes[0] = 0x09;
        assert!(Packet::<&[u8]>::parse(&(), &bytes[..]).is_err());
    }
}
