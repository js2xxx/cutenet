#[path = "v6_cidr.rs"]
mod cidr;

use core::{
    net::{Ipv4Addr, Ipv6Addr, Ipv6MulticastScope},
    ops::Range,
};

use byteorder::{ByteOrder, NetworkEndian};

pub use self::cidr::Cidr;
use super::{IpAddrExt, ParseError, Protocol};
use crate::{
    storage::{Buf, Storage},
    wire::{Builder, Dst, Ends, Src, WireBuf},
};

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

#[derive(Debug)]
pub struct Packet<S: Storage + ?Sized> {
    inner: Buf<S>,
}

impl<S: Storage + ?Sized> Packet<S> {
    pub const fn header_len(&self) -> usize {
        field::DST_ADDR.end
    }

    pub fn version(&self) -> u8 {
        self.inner.data()[field::VER_TC_FLOW.start] >> 4
    }

    fn set_version(&mut self, value: u8) {
        let data = self.inner.data_mut();
        // Make sure to retain the lower order bits which contain
        // the higher order bits of the traffic class
        data[0] = (data[0] & 0x0f) | ((value & 0x0f) << 4);
    }

    /// Return the traffic class.
    pub fn traffic_class(&self) -> u8 {
        ((NetworkEndian::read_u16(&self.inner.data()[0..2]) & 0x0ff0) >> 4) as u8
    }

    fn set_traffic_class(&mut self, value: u8) {
        let data = self.inner.data_mut();
        // Put the higher order 4-bits of value in the lower order
        // 4-bits of the first byte
        data[0] = (data[0] & 0xf0) | ((value & 0xf0) >> 4);
        // Put the lower order 4-bits of value in the higher order
        // 4-bits of the second byte
        data[1] = (data[1] & 0x0f) | ((value & 0x0f) << 4);
    }

    /// Return the flow label field.
    pub fn flow_label(&self) -> u32 {
        NetworkEndian::read_u24(&self.inner.data()[1..4]) & 0x000fffff
    }

    fn set_flow_label(&mut self, value: u32) {
        let data = self.inner.data_mut();
        // Retain the lower order 4-bits of the traffic class
        let raw = (u32::from(data[1] & 0xf0) << 16) | (value & 0x0fffff);
        NetworkEndian::write_u24(&mut data[1..4], raw);
    }

    /// Return the payload length field.
    pub fn payload_len(&self) -> u16 {
        NetworkEndian::read_u16(&self.inner.data()[field::LENGTH])
    }

    fn set_payload_len(&mut self, value: u16) {
        NetworkEndian::write_u16(&mut self.inner.data_mut()[field::LENGTH], value);
    }

    /// Return the payload length added to the known header length.
    pub fn total_len(&self) -> usize {
        self.header_len() + usize::from(self.payload_len())
    }

    /// Return the next header field.
    pub fn next_header(&self) -> Protocol {
        let data = self.inner.data();
        Protocol::from(data[field::NXT_HDR])
    }

    fn set_next_header(&mut self, value: Protocol) {
        self.inner.data_mut()[field::NXT_HDR] = value.into();
    }

    /// Return the hop limit field.
    pub fn hop_limit(&self) -> u8 {
        let data = self.inner.data();
        data[field::HOP_LIMIT]
    }

    fn set_hop_limit(&mut self, value: u8) {
        self.inner.data_mut()[field::HOP_LIMIT] = value;
    }

    /// Return the source address field.
    pub fn src_addr(&self) -> Ipv6Addr {
        let data = self.inner.data();
        Ipv6Addr::from_bytes(&data[field::SRC_ADDR])
    }

    fn set_src_addr(&mut self, value: Ipv6Addr) {
        let data = self.inner.data_mut();
        data[field::SRC_ADDR].copy_from_slice(&value.octets());
    }

    /// Return the destination address field.
    pub fn dst_addr(&self) -> Ipv6Addr {
        let data = self.inner.data();
        Ipv6Addr::from_bytes(&data[field::DST_ADDR])
    }

    fn set_dst_addr(&mut self, value: Ipv6Addr) {
        let data = self.inner.data_mut();
        data[field::DST_ADDR].copy_from_slice(&value.octets());
    }

    pub fn addr(&self) -> Ends<Ipv6Addr> {
        (Src(self.src_addr()), Dst(self.dst_addr()))
    }

    fn payload_range(&self) -> Range<usize> {
        self.header_len()..self.total_len()
    }

    pub fn payload(&self) -> &[u8] {
        &self.inner.data()[self.payload_range()]
    }
}

impl<S: Storage> Builder<Packet<S>> {
    pub fn addr(mut self, addr: Ends<Ipv6Addr>) -> Self {
        let (Src(src), Dst(dst)) = addr;
        self.0.set_src_addr(src);
        self.0.set_dst_addr(dst);
        self
    }

    pub fn hop_limit(mut self, hop_limit: u8) -> Self {
        self.0.set_hop_limit(hop_limit);
        self
    }

    pub fn next_header(mut self, prot: Protocol) -> Self {
        self.0.set_next_header(prot);
        self
    }
}

impl<S: Storage + ?Sized> WireBuf for Packet<S> {
    type Storage = S;

    const HEADER_LEN: usize = HEADER_LEN;

    fn into_raw(self) -> Buf<S>
    where
        S: Sized,
    {
        self.inner
    }

    fn into_payload(self) -> Buf<S>
    where
        S: Sized,
    {
        let range = self.payload_range();
        self.inner.slice_into(range)
    }

    type ParseError = ParseError;
    type ParseArg<'a> = ();

    fn parse(raw: Buf<Self::Storage>, _: ()) -> Result<Self, Self::ParseError>
    where
        Self::Storage: Sized,
        Self: Sized,
    {
        let packet = Packet { inner: raw };
        let len = packet.inner.len();
        if len < field::DST_ADDR.end || len < packet.total_len() {
            return Err(ParseError::PacketTooShort);
        }
        if packet.version() != 6 {
            return Err(ParseError::VersionInvalid);
        }
        Ok(packet)
    }

    type BuildError = BuildError;
    fn build_default(payload: Buf<Self::Storage>) -> Result<Self, Self::BuildError>
    where
        Self::Storage: Sized,
        Self: Sized,
    {
        let len = u16::try_from(payload.len()).map_err(|_| BuildError::PayloadTooLong)?;
        let mut inner = payload;
        inner.prepend_fixed::<HEADER_LEN>();
        let mut packet = Packet { inner };

        packet.set_version(6);
        packet.set_traffic_class(0);
        packet.set_flow_label(0);
        packet.set_payload_len(len);
        packet.set_hop_limit(64);
        packet.set_next_header(Protocol::Unknown(0));

        Ok(packet)
    }
}

#[derive(Debug)]
pub enum BuildError {
    PayloadTooLong,
}

#[cfg(test)]
mod tests {
    use std::vec;

    use super::*;
    use crate::wire::WireBufExt;

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
        let packet = Packet { inner: Buf::full(&mut pb[..]) };

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
        let bytes = vec![0xff; 52];
        let mut payload = Buf::builder(bytes).reserve_for::<Packet<_>>().build();
        payload.append_slice(&REPR_PAYLOAD_BYTES);

        let packet = Packet::builder(payload).unwrap();
        let packet = packet
            .next_header(Protocol::Udp)
            .hop_limit(0x40)
            .addr((
                Src(Ipv6Addr::LINK_LOCAL_ALL_ROUTERS),
                Dst(Ipv6Addr::LINK_LOCAL_ALL_NODES),
            ))
            .build();

        assert_eq!(packet.into_raw().data(), &REPR_PACKET_BYTES);
    }

    #[test]
    fn test_overlong() {
        let mut pb = vec![];
        pb.extend(REPR_PACKET_BYTES);
        pb.push(0);
        let packet = Packet { inner: Buf::full(&mut pb[..]) };

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
