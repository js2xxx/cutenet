#[path = "v4_cidr.rs"]
mod cidr;

use core::{net::Ipv4Addr, ops::Range};

use byteorder::{ByteOrder, NetworkEndian};

pub use self::cidr::Cidr;
use super::{checksum, IpAddrExt, ParseError, Protocol};
use crate::{
    storage::{Buf, Storage},
    wire::{Dst, Ends, Src, WireBuf},
};

#[derive(Debug, Eq, PartialEq, Ord, PartialOrd, Clone, Copy)]
pub struct Key {
    id: u16,
    src_addr: Ipv4Addr,
    dst_addr: Ipv4Addr,
    protocol: Protocol,
}

mod field {
    use crate::wire::field::*;

    pub const VER_IHL: usize = 0;
    pub const DSCP_ECN: usize = 1;
    pub const LENGTH: Field = 2..4;
    pub const IDENT: Field = 4..6;
    pub const FLG_OFF: Field = 6..8;
    pub const TTL: usize = 8;
    pub const PROTOCOL: usize = 9;
    pub const CHECKSUM: Field = 10..12;
    pub const SRC_ADDR: Field = 12..16;
    pub const DST_ADDR: Field = 16..20;
}
pub const HEADER_LEN: usize = field::DST_ADDR.end;

pub struct Packet<S: Storage + ?Sized> {
    inner: Buf<S>,
}

impl<S: Storage> Packet<S> {
    pub fn builder(payload: Buf<S>) -> Result<PacketBuilder<S>, BuildError> {
        PacketBuilder::new(payload)
    }

    pub fn parse(raw: Buf<S>, verify_checksum: bool) -> Result<Packet<S>, ParseError> {
        let packet = Packet { inner: raw };

        let len = packet.inner.len();
        if len < field::DST_ADDR.end
            || len < packet.header_len() as usize
            || packet.header_len() as u16 > packet.total_len()
            || len < packet.total_len() as usize
        {
            return Err(ParseError::PacketTooShort);
        }

        if packet.version() != 4 {
            return Err(ParseError::VersionInvalid);
        }

        if verify_checksum && !packet.verify_checksum() {
            return Err(ParseError::ChecksumInvalid);
        }

        Ok(packet)
    }
}

impl<S: Storage + ?Sized> WireBuf for Packet<S> {
    type Storage = S;

    const HEADER_LEN: usize = HEADER_LEN;

    fn into_inner(self) -> Buf<S>
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
}

impl<S: Storage + ?Sized> Packet<S> {
    pub fn version(&self) -> u8 {
        self.inner.data()[field::VER_IHL] >> 4
    }

    /// Return the header length, in octets.
    pub fn header_len(&self) -> u8 {
        (self.inner.data()[field::VER_IHL] & 0x0f) * 4
    }

    /// Return the Differential Services Code Point field.
    pub fn dscp(&self) -> u8 {
        self.inner.data()[field::DSCP_ECN] >> 2
    }

    /// Return the Explicit Congestion Notification field.
    pub fn ecn(&self) -> u8 {
        self.inner.data()[field::DSCP_ECN] & 0x03
    }

    /// Return the total length field.
    pub fn total_len(&self) -> u16 {
        NetworkEndian::read_u16(&self.inner.data()[field::LENGTH])
    }

    /// Return the fragment identification field.
    pub fn ident(&self) -> u16 {
        NetworkEndian::read_u16(&self.inner.data()[field::IDENT])
    }

    /// Return the "don't fragment" flag.
    pub fn dont_frag(&self) -> bool {
        NetworkEndian::read_u16(&self.inner.data()[field::FLG_OFF]) & 0x4000 != 0
    }

    /// Return the "more fragments" flag.
    pub fn more_frags(&self) -> bool {
        NetworkEndian::read_u16(&self.inner.data()[field::FLG_OFF]) & 0x2000 != 0
    }

    /// Return the fragment offset, in octets.
    pub fn frag_offset(&self) -> u16 {
        NetworkEndian::read_u16(&self.inner.data()[field::FLG_OFF]) << 3
    }

    /// Return the time to live field.
    pub fn hop_limit(&self) -> u8 {
        self.inner.data()[field::TTL]
    }

    /// Return the next_header (protocol) field.
    pub fn next_header(&self) -> Protocol {
        Protocol::from(self.inner.data()[field::PROTOCOL])
    }

    /// Return the header checksum field.
    pub fn checksum(&self) -> u16 {
        NetworkEndian::read_u16(&self.inner.data()[field::CHECKSUM])
    }

    /// Return the source address field.
    pub fn src_addr(&self) -> Ipv4Addr {
        Ipv4Addr::from_bytes(&self.inner.data()[field::SRC_ADDR])
    }

    /// Return the destination address field.
    pub fn dst_addr(&self) -> Ipv4Addr {
        Ipv4Addr::from_bytes(&self.inner.data()[field::DST_ADDR])
    }

    pub fn addr(&self) -> Ends<Ipv4Addr> {
        (Src(self.src_addr()), Dst(self.dst_addr()))
    }

    pub fn verify_checksum(&self) -> bool {
        checksum::data(&self.inner.data()[..self.header_len() as usize]) == !0
    }

    pub fn key(&self) -> Key {
        Key {
            id: self.ident(),
            src_addr: self.src_addr(),
            dst_addr: self.dst_addr(),
            protocol: self.next_header(),
        }
    }

    fn payload_range(&self) -> Range<usize> {
        self.header_len() as usize..self.total_len() as usize
    }

    pub fn payload(&self) -> &[u8] {
        &self.inner.data()[self.payload_range()]
    }
}

pub struct PacketBuilder<S: Storage + ?Sized> {
    inner: Buf<S>,
}

impl<S: Storage> PacketBuilder<S> {
    fn new(payload: Buf<S>) -> Result<Self, BuildError> {
        let len = payload.len();
        let mut inner = payload;
        inner.prepend_fixed::<HEADER_LEN>();
        let mut ret = PacketBuilder { inner };

        ret.set_version(4);
        ret.set_header_len(u8::try_from(field::DST_ADDR.end).unwrap());
        ret.set_dscp(0);
        ret.set_ecn(0);

        let total_len = usize::from(ret.header_len()) + len;
        ret.set_total_len(u16::try_from(total_len).map_err(|_| BuildError::PayloadTooLong)?);

        ret.set_ident(0);
        ret.clear_flags();
        ret.set_more_frags(false);
        ret.set_dont_frag(true);
        ret.set_frag_offset(0);
        ret.set_hop_limit(64);
        ret.set_next_header(Protocol::Unknown(0));
        ret.set_checksum(0);

        Ok(ret)
    }
}

impl<S: Storage + ?Sized> PacketBuilder<S> {
    fn set_version(&mut self, value: u8) {
        self.inner.data_mut()[field::VER_IHL] =
            (self.inner.data_mut()[field::VER_IHL] & !0xf0) | (value << 4);
    }

    fn header_len(&self) -> u8 {
        (self.inner.data()[field::VER_IHL] & 0x0f) * 4
    }

    /// Set the header length, in octets.
    fn set_header_len(&mut self, value: u8) {
        self.inner.data_mut()[field::VER_IHL] =
            (self.inner.data_mut()[field::VER_IHL] & !0x0f) | ((value / 4) & 0x0f);
    }

    /// Set the Differential Services Code Point field.
    fn set_dscp(&mut self, value: u8) {
        self.inner.data_mut()[field::DSCP_ECN] =
            (self.inner.data_mut()[field::DSCP_ECN] & !0xfc) | (value << 2)
    }

    /// Set the Explicit Congestion Notification field.
    fn set_ecn(&mut self, value: u8) {
        self.inner.data_mut()[field::DSCP_ECN] =
            (self.inner.data_mut()[field::DSCP_ECN] & !0x03) | (value & 0x03)
    }

    /// Set the total length field.
    fn set_total_len(&mut self, value: u16) {
        NetworkEndian::write_u16(&mut self.inner.data_mut()[field::LENGTH], value)
    }

    /// Set the fragment identification field.
    fn set_ident(&mut self, value: u16) {
        NetworkEndian::write_u16(&mut self.inner.data_mut()[field::IDENT], value)
    }

    /// Clear the entire flags field.
    fn clear_flags(&mut self) {
        let data = self.inner.data_mut();
        let raw = NetworkEndian::read_u16(&data[field::FLG_OFF]);
        let raw = raw & !0xe000;
        NetworkEndian::write_u16(&mut data[field::FLG_OFF], raw);
    }

    /// Set the "don't fragment" flag.
    fn set_dont_frag(&mut self, value: bool) {
        let data = self.inner.data_mut();
        let raw = NetworkEndian::read_u16(&data[field::FLG_OFF]);
        let raw = if value { raw | 0x4000 } else { raw & !0x4000 };
        NetworkEndian::write_u16(&mut data[field::FLG_OFF], raw);
    }

    /// Set the "more fragments" flag.
    fn set_more_frags(&mut self, value: bool) {
        let data = self.inner.data_mut();
        let raw = NetworkEndian::read_u16(&data[field::FLG_OFF]);
        let raw = if value { raw | 0x2000 } else { raw & !0x2000 };
        NetworkEndian::write_u16(&mut data[field::FLG_OFF], raw);
    }

    /// Set the fragment offset, in octets.
    fn set_frag_offset(&mut self, value: u16) {
        let data = self.inner.data_mut();
        let raw = NetworkEndian::read_u16(&data[field::FLG_OFF]);
        let raw = (raw & 0xe000) | (value >> 3);
        NetworkEndian::write_u16(&mut data[field::FLG_OFF], raw);
    }

    /// Set the time to live field.
    fn set_hop_limit(&mut self, value: u8) {
        self.inner.data_mut()[field::TTL] = value
    }

    /// Set the next header (protocol) field.
    fn set_next_header(&mut self, value: Protocol) {
        self.inner.data_mut()[field::PROTOCOL] = value.into()
    }

    /// Set the header checksum field.
    fn set_checksum(&mut self, value: u16) {
        NetworkEndian::write_u16(&mut self.inner.data_mut()[field::CHECKSUM], value)
    }

    /// Set the source address field.
    fn set_src_addr(&mut self, value: Ipv4Addr) {
        self.inner.data_mut()[field::SRC_ADDR].copy_from_slice(&value.octets())
    }

    /// Set the destination address field.
    fn set_dst_addr(&mut self, value: Ipv4Addr) {
        self.inner.data_mut()[field::DST_ADDR].copy_from_slice(&value.octets())
    }
}

impl<S: Storage> PacketBuilder<S> {
    pub fn addr(mut self, addr: Ends<Ipv4Addr>) -> Self {
        let (Src(src), Dst(dst)) = addr;
        self.set_src_addr(src);
        self.set_dst_addr(dst);
        self
    }

    pub fn hop_limit(mut self, hop_limit: u8) -> Self {
        self.set_hop_limit(hop_limit);
        self
    }

    pub fn next_header(mut self, prot: Protocol) -> Self {
        self.set_next_header(prot);
        self
    }

    pub fn checksum(mut self) -> Self {
        self.set_checksum(0);
        let checksum = !checksum::data(&self.inner.data()[..self.header_len() as usize]);
        self.set_checksum(checksum);
        self
    }

    pub fn build(self) -> Packet<S> {
        Packet { inner: self.inner }
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

    const INGRESS_PACKET_BYTES: [u8; 30] = [
        0x45, 0x00, 0x00, 0x1e, 0x01, 0x02, 0x62, 0x03, 0x1a, 0x01, 0xd5, 0x6e, 0x11, 0x12, 0x13,
        0x14, 0x21, 0x22, 0x23, 0x24, 0xaa, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff,
    ];

    const EGRESS_PACKET_BYTES: [u8; 30] = [
        0x45, 0x00, 0x00, 0x1e, 0x00, 0x00, 0x40, 0x00, 0x1a, 0x01, 0xf8, 0x73, 0x11, 0x12, 0x13,
        0x14, 0x21, 0x22, 0x23, 0x24, 0xaa, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff,
    ];

    const PAYLOAD_BYTES: [u8; 10] = [0xaa, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff];

    #[test]
    fn test_deconstruct() {
        let mut pb = INGRESS_PACKET_BYTES;
        let packet = Packet { inner: Buf::full(&mut pb[..]) };
        assert_eq!(packet.version(), 4);
        assert_eq!(packet.header_len(), 20);
        assert_eq!(packet.dscp(), 0);
        assert_eq!(packet.ecn(), 0);
        assert_eq!(packet.total_len(), 30);
        assert_eq!(packet.ident(), 0x102);
        assert!(packet.more_frags());
        assert!(packet.dont_frag());
        assert_eq!(packet.frag_offset(), 0x203 * 8);
        assert_eq!(packet.hop_limit(), 0x1a);
        assert_eq!(packet.next_header(), Protocol::Icmp);
        assert_eq!(packet.checksum(), 0xd56e);
        assert_eq!(packet.src_addr(), Ipv4Addr::from([0x11, 0x12, 0x13, 0x14]));
        assert_eq!(packet.dst_addr(), Ipv4Addr::from([0x21, 0x22, 0x23, 0x24]));
        assert!(packet.verify_checksum());
        assert_eq!(packet.payload(), &PAYLOAD_BYTES[..]);
    }

    #[test]
    fn test_construct() {
        let bytes = vec![0xa5; 30];
        let mut payload = Buf::builder(bytes).reserve_for::<Packet<_>>().build();
        payload.append_slice(&PAYLOAD_BYTES);

        let packet = Packet::builder(payload).unwrap();
        let packet = packet
            .hop_limit(0x1a)
            .next_header(Protocol::Icmp)
            .addr((
                Src(Ipv4Addr::from([0x11, 0x12, 0x13, 0x14])),
                Dst(Ipv4Addr::from([0x21, 0x22, 0x23, 0x24])),
            ))
            .checksum()
            .build();
        assert_eq!(packet.into_inner().data(), &EGRESS_PACKET_BYTES[..]);
    }

    #[test]
    fn test_overlong() {
        let mut pb = vec![];
        pb.extend(INGRESS_PACKET_BYTES);
        pb.push(0);
        let packet = Packet { inner: Buf::full(&mut pb[..]) };

        assert_eq!(packet.payload().len(), PAYLOAD_BYTES.len());
    }

    const REPR_PACKET_BYTES: [u8; 24] = [
        0x45, 0x00, 0x00, 0x18, 0x00, 0x00, 0x40, 0x00, 0x40, 0x01, 0xd2, 0x79, 0x11, 0x12, 0x13,
        0x14, 0x21, 0x22, 0x23, 0x24, 0xaa, 0x00, 0x00, 0xff,
    ];

    #[test]
    fn test_parse() {
        let mut pb = REPR_PACKET_BYTES;
        let packet = Packet::parse(Buf::full(&mut pb[..]), true).unwrap();

        assert_eq!(packet.src_addr(), Ipv4Addr::from([0x11, 0x12, 0x13, 0x14]));
        assert_eq!(packet.dst_addr(), Ipv4Addr::from([0x21, 0x22, 0x23, 0x24]));
        assert_eq!(packet.next_header(), Protocol::Icmp);
        assert_eq!(packet.payload().len(), 4);
        assert_eq!(packet.hop_limit(), 64);
    }

    #[test]
    fn test_parse_total_len_less_than_header_len() {
        let mut bytes = [0; 40];
        bytes[0] = 0x09;
        assert!(Packet::parse(Buf::full(&mut bytes[..]), false).is_err());
    }
}
