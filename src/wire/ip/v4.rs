#[path = "v4_cidr.rs"]
mod cidr;

use core::{net::Ipv4Addr, ops::Range};

use byteorder::{ByteOrder, NetworkEndian};

pub use self::cidr::Cidr;
use super::{checksum, IpAddrExt, Protocol};
use crate::{
    storage::Storage,
    wire::{BuildErrorKind, Dst, Ends, ParseErrorKind, Src, VerifyChecksum, Wire},
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

pub type Ipv4 = super::Ip<Ipv4Addr>;

pub type Packet<S: Storage + ?Sized> = crate::wire::Packet<Ipv4, S>;

impl<S: Storage + ?Sized> Packet<S> {
    pub fn version(&self) -> u8 {
        self.inner.data()[field::VER_IHL] >> 4
    }

    fn set_version(&mut self, value: u8) {
        self.inner.data_mut()[field::VER_IHL] =
            (self.inner.data_mut()[field::VER_IHL] & !0xf0) | (value << 4);
    }

    /// Return the header length, in octets.
    pub fn header_len(&self) -> u8 {
        (self.inner.data()[field::VER_IHL] & 0x0f) * 4
    }

    fn set_header_len(&mut self, value: u8) {
        self.inner.data_mut()[field::VER_IHL] =
            (self.inner.data_mut()[field::VER_IHL] & !0x0f) | ((value / 4) & 0x0f);
    }

    /// Return the Differential Services Code Point field.
    pub fn dscp(&self) -> u8 {
        self.inner.data()[field::DSCP_ECN] >> 2
    }

    fn set_dscp(&mut self, value: u8) {
        self.inner.data_mut()[field::DSCP_ECN] =
            (self.inner.data_mut()[field::DSCP_ECN] & !0xfc) | (value << 2)
    }

    /// Return the Explicit Congestion Notification field.
    pub fn ecn(&self) -> u8 {
        self.inner.data()[field::DSCP_ECN] & 0x03
    }

    fn set_ecn(&mut self, value: u8) {
        self.inner.data_mut()[field::DSCP_ECN] =
            (self.inner.data_mut()[field::DSCP_ECN] & !0x03) | (value & 0x03)
    }

    /// Return the total length field.
    pub fn total_len(&self) -> u16 {
        NetworkEndian::read_u16(&self.inner.data()[field::LENGTH])
    }

    fn set_total_len(&mut self, value: u16) {
        NetworkEndian::write_u16(&mut self.inner.data_mut()[field::LENGTH], value)
    }

    /// Return the fragment identification field.
    pub fn ident(&self) -> u16 {
        NetworkEndian::read_u16(&self.inner.data()[field::IDENT])
    }

    fn set_ident(&mut self, value: u16) {
        NetworkEndian::write_u16(&mut self.inner.data_mut()[field::IDENT], value)
    }

    /// Return the "don't fragment" flag.
    pub fn dont_frag(&self) -> bool {
        NetworkEndian::read_u16(&self.inner.data()[field::FLG_OFF]) & 0x4000 != 0
    }

    fn set_dont_frag(&mut self, value: bool) {
        let data = self.inner.data_mut();
        let raw = NetworkEndian::read_u16(&data[field::FLG_OFF]);
        let raw = if value { raw | 0x4000 } else { raw & !0x4000 };
        NetworkEndian::write_u16(&mut data[field::FLG_OFF], raw);
    }

    /// Return the "more fragments" flag.
    pub fn more_frags(&self) -> bool {
        NetworkEndian::read_u16(&self.inner.data()[field::FLG_OFF]) & 0x2000 != 0
    }

    fn set_more_frags(&mut self, value: bool) {
        let data = self.inner.data_mut();
        let raw = NetworkEndian::read_u16(&data[field::FLG_OFF]);
        let raw = if value { raw | 0x2000 } else { raw & !0x2000 };
        NetworkEndian::write_u16(&mut data[field::FLG_OFF], raw);
    }

    /// Return the fragment offset, in octets.
    pub fn frag_offset(&self) -> u16 {
        NetworkEndian::read_u16(&self.inner.data()[field::FLG_OFF]) << 3
    }

    fn set_frag_offset(&mut self, value: u16) {
        let data = self.inner.data_mut();
        let raw = NetworkEndian::read_u16(&data[field::FLG_OFF]);
        let raw = (raw & 0xe000) | (value >> 3);
        NetworkEndian::write_u16(&mut data[field::FLG_OFF], raw);
    }

    fn clear_flags(&mut self) {
        let data = self.inner.data_mut();
        let raw = NetworkEndian::read_u16(&data[field::FLG_OFF]);
        let raw = raw & !0xe000;
        NetworkEndian::write_u16(&mut data[field::FLG_OFF], raw);
    }

    /// Return the time to live field.
    pub fn hop_limit(&self) -> u8 {
        self.inner.data()[field::TTL]
    }

    fn set_hop_limit(&mut self, value: u8) {
        self.inner.data_mut()[field::TTL] = value
    }

    /// Return the next_header (protocol) field.
    pub fn next_header(&self) -> Protocol {
        Protocol::from(self.inner.data()[field::PROTOCOL])
    }

    fn set_next_header(&mut self, value: Protocol) {
        self.inner.data_mut()[field::PROTOCOL] = value.into()
    }

    /// Return the header checksum field.
    pub fn checksum(&self) -> u16 {
        NetworkEndian::read_u16(&self.inner.data()[field::CHECKSUM])
    }

    fn set_checksum(&mut self, value: u16) {
        NetworkEndian::write_u16(&mut self.inner.data_mut()[field::CHECKSUM], value)
    }

    /// Return the source address field.
    pub fn src_addr(&self) -> Ipv4Addr {
        Ipv4Addr::from_bytes(&self.inner.data()[field::SRC_ADDR])
    }

    fn set_src_addr(&mut self, value: Ipv4Addr) {
        self.inner.data_mut()[field::SRC_ADDR].copy_from_slice(&value.octets())
    }

    /// Return the destination address field.
    pub fn dst_addr(&self) -> Ipv4Addr {
        Ipv4Addr::from_bytes(&self.inner.data()[field::DST_ADDR])
    }

    fn set_dst_addr(&mut self, value: Ipv4Addr) {
        self.inner.data_mut()[field::DST_ADDR].copy_from_slice(&value.octets())
    }

    pub fn addr(&self) -> Ends<Ipv4Addr> {
        (Src(self.src_addr()), Dst(self.dst_addr()))
    }

    pub fn verify_checksum(&self) -> bool {
        checksum::data(&self.inner.data()[..usize::from(self.header_len())]) == !0
    }

    pub fn fill_checksum(&mut self) {
        self.set_checksum(0);
        let checksum = !checksum::data(&self.inner.data()[..usize::from(self.header_len())]);
        self.set_checksum(checksum);
    }

    pub fn key(&self) -> Key {
        Key {
            id: self.ident(),
            src_addr: self.src_addr(),
            dst_addr: self.dst_addr(),
            protocol: self.next_header(),
        }
    }
}

impl Wire for Ipv4 {
    const EMPTY_PAYLOAD: bool = false;

    fn header_len(&self) -> usize {
        HEADER_LEN
    }

    fn buffer_len(&self, payload_len: usize) -> usize {
        HEADER_LEN + payload_len
    }

    fn payload_range<S: Storage + ?Sized>(packet: &Packet<S>) -> Range<usize> {
        usize::from(packet.header_len())..usize::from(packet.total_len())
    }

    type ParseArg<'a> = VerifyChecksum<bool>;
    fn parse_packet<S: Storage>(
        packet: &Packet<S>,
        VerifyChecksum(verify_checksum): VerifyChecksum<bool>,
    ) -> Result<(), ParseErrorKind> {
        let len = packet.inner.len();
        if len < field::DST_ADDR.end
            || len < usize::from(packet.header_len())
            || u16::from(packet.header_len()) > packet.total_len()
            || len < usize::from(packet.total_len())
        {
            return Err(ParseErrorKind::PacketTooShort);
        }

        if packet.version() != 4 {
            return Err(ParseErrorKind::VersionInvalid);
        }

        if verify_checksum && !packet.verify_checksum() {
            return Err(ParseErrorKind::ChecksumInvalid);
        }

        Ok(())
    }

    fn build_packet<S: Storage>(
        self,
        packet: &mut Packet<S>,
        payload_len: usize,
    ) -> Result<(), BuildErrorKind> {
        packet.set_version(4);
        packet.set_header_len(u8::try_from(field::DST_ADDR.end).unwrap());
        packet.set_dscp(0);
        packet.set_ecn(0);

        let total_len = usize::from(packet.header_len()) + payload_len;
        packet.set_total_len(u16::try_from(total_len).map_err(|_| BuildErrorKind::PayloadTooLong)?);

        packet.set_ident(0);
        packet.clear_flags();
        packet.set_more_frags(false);
        packet.set_dont_frag(true);
        packet.set_frag_offset(0);
        packet.set_hop_limit(64);
        packet.set_next_header(Protocol::Unknown(0));
        packet.set_checksum(0);

        let Ipv4 {
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
        let packet = Packet::parse(Buf::full(&mut pb[..]), VerifyChecksum(true)).unwrap();
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
        let tag = Ipv4 {
            addr: (
                Src(Ipv4Addr::from([0x11, 0x12, 0x13, 0x14])),
                Dst(Ipv4Addr::from([0x21, 0x22, 0x23, 0x24])),
            ),
            next_header: Protocol::Icmp,
            hop_limit: 0x1a,
        };

        let bytes = vec![0xa5; 30];
        let mut payload = Buf::builder(bytes).reserve_for(&tag).build();
        payload.append_slice(&PAYLOAD_BYTES);

        let mut packet = tag.build(payload).unwrap();
        packet.fill_checksum();
        assert_eq!(packet.into_raw().data(), &EGRESS_PACKET_BYTES[..]);
    }

    #[test]
    fn test_overlong() {
        let mut pb = vec![];
        pb.extend(INGRESS_PACKET_BYTES);
        pb.push(0);
        let packet = Packet::parse(Buf::full(&mut pb[..]), VerifyChecksum(true)).unwrap();

        assert_eq!(packet.payload().len(), PAYLOAD_BYTES.len());
    }

    #[test]
    fn test_parse_total_len_less_than_header_len() {
        let mut bytes = [0; 40];
        bytes[0] = 0x09;
        assert!(Packet::parse(Buf::full(&mut bytes[..]), VerifyChecksum(false)).is_err());
    }
}
