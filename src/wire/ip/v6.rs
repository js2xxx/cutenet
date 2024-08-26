#[path = "v6_cidr.rs"]
mod cidr;

use core::{
    net::{Ipv4Addr, Ipv6Addr, Ipv6MulticastScope},
    ops::Range,
};

use byteorder::{ByteOrder, NetworkEndian};

pub use self::cidr::Cidr;
use super::{IpAddrExt, Protocol};
use crate::wire::{BuildErrorKind, Data, DataMut, Dst, Ends, ParseErrorKind, Src, Wire};

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

pub type Packet<T: ?Sized> = crate::wire::Packet<Ipv6, T>;

mod field {
    use crate::wire::field::*;

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

wire!(impl Packet {
    version/set_version: u8 =>
        |data| data[field::VER_TC_FLOW.start] >> 4;
        |data, value| {
            // Make sure to retain the lower order bits which contain
            // the higher order bits of the traffic class
            data[0] = (data[0] & 0x0f) | ((value & 0x0f) << 4);
        };

    /// Return the traffic class.
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

impl<T: Data + ?Sized> Packet<T> {
    /// Return the payload length added to the known header length.
    pub fn total_len(&self) -> usize {
        HEADER_LEN + usize::from(self.payload_len())
    }

    pub fn addr(&self) -> Ends<Ipv6Addr> {
        (Src(self.src_addr()), Dst(self.dst_addr()))
    }
}

pub type Ipv6 = super::IpImpl<Ipv6Addr>;

impl Wire for Ipv6 {
    const EMPTY_PAYLOAD: bool = false;

    fn header_len(&self) -> usize {
        HEADER_LEN
    }

    fn buffer_len(&self, payload_len: usize) -> usize {
        HEADER_LEN + payload_len
    }

    fn payload_range(packet: Packet<&[u8]>) -> Range<usize> {
        HEADER_LEN..packet.total_len()
    }

    type ParseArg<'a> = ();
    fn parse_packet(packet: Packet<&[u8]>, _: ()) -> Result<Ipv6, ParseErrorKind> {
        let len = packet.inner.len();
        if len < field::DST_ADDR.end || len < packet.total_len() {
            return Err(ParseErrorKind::PacketTooShort);
        }
        if packet.version() != 6 {
            return Err(ParseErrorKind::VersionInvalid);
        }

        Ok(Ipv6 {
            addr: packet.addr(),
            next_header: packet.next_header(),
            hop_limit: packet.hop_limit(),
        })
    }

    fn build_packet(
        self,
        mut packet: Packet<&mut [u8]>,
        payload_len: usize,
    ) -> Result<(), BuildErrorKind> {
        let payload_len = u16::try_from(payload_len).map_err(|_| BuildErrorKind::PayloadTooLong)?;

        packet.set_version(6);
        packet.set_traffic_class(0);
        packet.set_flow_label(0);
        packet.set_payload_len(payload_len);
        packet.set_hop_limit(64);
        packet.set_next_header(Protocol::Unknown(0));

        let Ipv6 {
            addr: (Src(src), Dst(dst)),
            next_header,
            hop_limit,
        } = self;
        packet.set_src_addr(src);
        packet.set_dst_addr(dst);
        packet.set_next_header(next_header);
        packet.set_hop_limit(hop_limit);

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::vec;

    use super::*;
    use crate::{storage::Buf, wire::WireExt};

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
        let mut pb = REPR_PACKET_BYTES;
        let packet = Packet::parse(Buf::full(&mut pb[..]), ()).unwrap();

        assert_eq!(packet.version(), 6);
        assert_eq!(packet.traffic_class(), 0);
        assert_eq!(packet.flow_label(), 0);
        assert_eq!(packet.total_len(), 0x34);
        assert_eq!(usize::from(packet.payload_len()), REPR_PAYLOAD_BYTES.len());
        assert_eq!(packet.next_header(), Protocol::Udp);
        assert_eq!(packet.hop_limit(), 0x40);
        assert_eq!(packet.src_addr(), Ipv6Addr::LINK_LOCAL_ALL_ROUTERS);
        assert_eq!(packet.dst_addr(), Ipv6Addr::LINK_LOCAL_ALL_NODES);
        assert_eq!(packet.payload(), &REPR_PAYLOAD_BYTES[..]);
    }

    #[test]
    fn test_packet_construction() {
        let ip = Ipv6 {
            addr: (
                Src(Ipv6Addr::LINK_LOCAL_ALL_ROUTERS),
                Dst(Ipv6Addr::LINK_LOCAL_ALL_NODES),
            ),
            next_header: Protocol::Udp,
            hop_limit: 0x40,
        };
        let tag = ip;

        let bytes = vec![0xff; 52];
        let mut payload = Buf::builder(bytes).reserve_for(&tag).build();
        payload.append_slice(&REPR_PAYLOAD_BYTES);

        let packet = tag.build(payload).unwrap();
        assert_eq!(packet.into_raw().data(), &REPR_PACKET_BYTES);
    }

    #[test]
    fn test_overlong() {
        let mut pb = vec![];
        pb.extend(REPR_PACKET_BYTES);
        pb.push(0);
        let packet = Packet::parse(Buf::full(&mut pb[..]), ()).unwrap();

        assert_eq!(packet.payload().len(), REPR_PAYLOAD_BYTES.len());
    }

    #[test]
    fn test_repr_parse_valid() {
        let mut pb = REPR_PACKET_BYTES;
        let packet = Packet::parse(Buf::full(&mut pb[..]), ()).unwrap();
        assert_eq!(packet.src_addr(), Ipv6Addr::LINK_LOCAL_ALL_ROUTERS);
        assert_eq!(packet.dst_addr(), Ipv6Addr::LINK_LOCAL_ALL_NODES);
        assert_eq!(packet.next_header(), Protocol::Udp);
        assert_eq!(packet.payload_len(), 12);
        assert_eq!(packet.hop_limit(), 64);
    }

    #[test]
    fn test_repr_parse_smaller_than_header() {
        let mut bytes = [0; 40];
        bytes[0] = 0x09;
        assert!(Packet::parse(Buf::full(&mut bytes[..]), ()).is_err());
    }
}
