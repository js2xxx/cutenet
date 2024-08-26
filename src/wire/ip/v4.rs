use core::{fmt, net::Ipv4Addr, ops::Range};

use byteorder::{ByteOrder, NetworkEndian};

use super::{checksum, IpAddrExt, ParseError};
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

enum_with_unknown! {
    /// IP datagram encapsulated protocol.
    pub enum Protocol(u8) {
        HopByHop  = 0x00,
        Icmp      = 0x01,
        Igmp      = 0x02,
        Tcp       = 0x06,
        Udp       = 0x11,
        Ipv6Route = 0x2b,
        Ipv6Frag  = 0x2c,
        IpSecEsp  = 0x32,
        IpSecAh   = 0x33,
        Icmpv6    = 0x3a,
        Ipv6NoNxt = 0x3b,
        Ipv6Opts  = 0x3c
    }
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Protocol::HopByHop => write!(f, "Hop-by-Hop"),
            Protocol::Icmp => write!(f, "ICMP"),
            Protocol::Igmp => write!(f, "IGMP"),
            Protocol::Tcp => write!(f, "TCP"),
            Protocol::Udp => write!(f, "UDP"),
            Protocol::Ipv6Route => write!(f, "IPv6-Route"),
            Protocol::Ipv6Frag => write!(f, "IPv6-Frag"),
            Protocol::IpSecEsp => write!(f, "IPsec-ESP"),
            Protocol::IpSecAh => write!(f, "IPsec-AH"),
            Protocol::Icmpv6 => write!(f, "ICMPv6"),
            Protocol::Ipv6NoNxt => write!(f, "IPv6-NoNxt"),
            Protocol::Ipv6Opts => write!(f, "IPv6-Opts"),
            Protocol::Unknown(id) => write!(f, "0x{id:02x}"),
        }
    }
}

#[derive(Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
pub struct Cidr {
    address: Ipv4Addr,
    prefix_len: u8,
}

impl Cidr {
    /// Create an IPv4 CIDR block from the given address and prefix length.
    ///
    /// # Panics
    /// This function panics if the prefix length is larger than 32.
    pub const fn new(address: Ipv4Addr, prefix_len: u8) -> Cidr {
        assert!(prefix_len <= 32);
        Cidr { address, prefix_len }
    }

    /// Create an IPv4 CIDR block from the given address and network mask.
    pub fn from_netmask(addr: Ipv4Addr, netmask: Ipv4Addr) -> Result<Cidr, ParseError> {
        let netmask = netmask.to_bits();
        if netmask.leading_zeros() == 0 && netmask.trailing_zeros() == netmask.count_zeros() {
            Ok(Cidr {
                address: addr,
                prefix_len: netmask.count_ones() as u8,
            })
        } else {
            Err(ParseError::NetmaskInvalid)
        }
    }

    /// Return the address of this IPv4 CIDR block.
    pub const fn address(&self) -> Ipv4Addr {
        self.address
    }

    /// Return the prefix length of this IPv4 CIDR block.
    pub const fn prefix_len(&self) -> u8 {
        self.prefix_len
    }

    /// Return the network mask of this IPv4 CIDR.
    pub const fn netmask(&self) -> Ipv4Addr {
        if self.prefix_len == 0 {
            return Ipv4Addr::new(0, 0, 0, 0);
        }

        let number = 0xffffffffu32 << (32 - self.prefix_len);
        Ipv4Addr::from_bits(number)
    }

    /// Return the broadcast address of this IPv4 CIDR.
    pub fn broadcast(&self) -> Option<Ipv4Addr> {
        let network = self.network();

        if network.prefix_len == 31 || network.prefix_len == 32 {
            return None;
        }

        let network_number = network.address.to_bits();
        let number = network_number | 0xffffffffu32 >> network.prefix_len;

        Some(Ipv4Addr::from_bits(number))
    }

    /// Return the network block of this IPv4 CIDR.
    pub const fn network(&self) -> Cidr {
        let network = self.address.to_bits() & self.netmask().to_bits();
        Cidr {
            address: Ipv4Addr::from_bits(network),
            prefix_len: self.prefix_len,
        }
    }

    /// Query whether the subnetwork described by this IPv4 CIDR block contains
    /// the given address.
    pub fn contains_addr(&self, addr: &Ipv4Addr) -> bool {
        // right shift by 32 is not legal
        if self.prefix_len == 0 {
            return true;
        }

        let shift = 32 - self.prefix_len;
        let self_prefix = self.address.to_bits() >> shift;
        let addr_prefix = addr.to_bits() >> shift;
        self_prefix == addr_prefix
    }

    /// Query whether the subnetwork described by this IPv4 CIDR block contains
    /// the subnetwork described by the given IPv4 CIDR block.
    pub fn contains_subnet(&self, subnet: &Cidr) -> bool {
        self.prefix_len <= subnet.prefix_len && self.contains_addr(&subnet.address)
    }
}

impl fmt::Display for Cidr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.address, self.prefix_len)
    }
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
            return Err(ParseError::VersionUnknown);
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
mod test_cidr {
    use super::*;

    #[test]
    fn test_unspecified() {
        assert!(Ipv4Addr::UNSPECIFIED.is_unspecified());
        assert!(!Ipv4Addr::UNSPECIFIED.is_broadcast());
        assert!(!Ipv4Addr::UNSPECIFIED.is_multicast());
        assert!(!Ipv4Addr::UNSPECIFIED.is_link_local());
        assert!(!Ipv4Addr::UNSPECIFIED.is_loopback());
    }

    #[test]
    fn test_broadcast() {
        assert!(!Ipv4Addr::BROADCAST.is_unspecified());
        assert!(Ipv4Addr::BROADCAST.is_broadcast());
        assert!(!Ipv4Addr::BROADCAST.is_multicast());
        assert!(!Ipv4Addr::BROADCAST.is_link_local());
        assert!(!Ipv4Addr::BROADCAST.is_loopback());
    }

    #[test]
    fn test_cidr() {
        let cidr = Cidr::new(Ipv4Addr::new(192, 168, 1, 10), 24);

        let inside_subnet = [
            [192, 168, 1, 0],
            [192, 168, 1, 1],
            [192, 168, 1, 2],
            [192, 168, 1, 10],
            [192, 168, 1, 127],
            [192, 168, 1, 255],
        ];

        let outside_subnet = [
            [192, 168, 0, 0],
            [127, 0, 0, 1],
            [192, 168, 2, 0],
            [192, 168, 0, 255],
            [0, 0, 0, 0],
            [255, 255, 255, 255],
        ];

        let subnets = [
            ([192, 168, 1, 0], 32),
            ([192, 168, 1, 255], 24),
            ([192, 168, 1, 10], 30),
        ];

        let not_subnets = [
            ([192, 168, 1, 10], 23),
            ([127, 0, 0, 1], 8),
            ([192, 168, 1, 0], 0),
            ([192, 168, 0, 255], 32),
        ];

        for addr in inside_subnet.into_iter().map(Ipv4Addr::from) {
            assert!(cidr.contains_addr(&addr));
        }

        for addr in outside_subnet.into_iter().map(Ipv4Addr::from) {
            assert!(!cidr.contains_addr(&addr));
        }

        for subnet in subnets
            .iter()
            .map(|&(a, p)| Cidr::new(Ipv4Addr::new(a[0], a[1], a[2], a[3]), p))
        {
            assert!(cidr.contains_subnet(&subnet));
        }

        for subnet in not_subnets
            .iter()
            .map(|&(a, p)| Cidr::new(Ipv4Addr::new(a[0], a[1], a[2], a[3]), p))
        {
            assert!(!cidr.contains_subnet(&subnet));
        }

        let cidr_without_prefix = Cidr::new(cidr.address(), 0);
        assert!(cidr_without_prefix.contains_addr(&Ipv4Addr::new(127, 0, 0, 1)));
    }

    #[test]
    fn test_cidr_from_netmask() {
        assert!(
            Cidr::from_netmask(Ipv4Addr::from([0, 0, 0, 0]), Ipv4Addr::from([1, 0, 2, 0])).is_err()
        );
        assert!(
            Cidr::from_netmask(Ipv4Addr::from([0, 0, 0, 0]), Ipv4Addr::from([0, 0, 0, 0])).is_err()
        );
        assert_eq!(
            Cidr::from_netmask(
                Ipv4Addr::from([0, 0, 0, 1]),
                Ipv4Addr::from([255, 255, 255, 0])
            )
            .unwrap(),
            Cidr::new(Ipv4Addr::from([0, 0, 0, 1]), 24)
        );
        assert_eq!(
            Cidr::from_netmask(
                Ipv4Addr::from([192, 168, 0, 1]),
                Ipv4Addr::from([255, 255, 0, 0])
            )
            .unwrap(),
            Cidr::new(Ipv4Addr::from([192, 168, 0, 1]), 16)
        );
        assert_eq!(
            Cidr::from_netmask(
                Ipv4Addr::from([172, 16, 0, 1]),
                Ipv4Addr::from([255, 240, 0, 0])
            )
            .unwrap(),
            Cidr::new(Ipv4Addr::from([172, 16, 0, 1]), 12)
        );
        assert_eq!(
            Cidr::from_netmask(
                Ipv4Addr::from([255, 255, 255, 1]),
                Ipv4Addr::from([255, 255, 255, 0])
            )
            .unwrap(),
            Cidr::new(Ipv4Addr::from([255, 255, 255, 1]), 24)
        );
        assert_eq!(
            Cidr::from_netmask(
                Ipv4Addr::from([255, 255, 255, 255]),
                Ipv4Addr::from([255, 255, 255, 255])
            )
            .unwrap(),
            Cidr::new(Ipv4Addr::from([255, 255, 255, 255]), 32)
        );
    }

    #[test]
    fn test_cidr_netmask() {
        assert_eq!(
            Cidr::new(Ipv4Addr::from([0, 0, 0, 0]), 0).netmask(),
            Ipv4Addr::from([0, 0, 0, 0])
        );
        assert_eq!(
            Cidr::new(Ipv4Addr::from([0, 0, 0, 1]), 24).netmask(),
            Ipv4Addr::from([255, 255, 255, 0])
        );
        assert_eq!(
            Cidr::new(Ipv4Addr::from([0, 0, 0, 0]), 32).netmask(),
            Ipv4Addr::from([255, 255, 255, 255])
        );
        assert_eq!(
            Cidr::new(Ipv4Addr::from([127, 0, 0, 0]), 8).netmask(),
            Ipv4Addr::from([255, 0, 0, 0])
        );
        assert_eq!(
            Cidr::new(Ipv4Addr::from([192, 168, 0, 0]), 16).netmask(),
            Ipv4Addr::from([255, 255, 0, 0])
        );
        assert_eq!(
            Cidr::new(Ipv4Addr::from([192, 168, 1, 1]), 16).netmask(),
            Ipv4Addr::from([255, 255, 0, 0])
        );
        assert_eq!(
            Cidr::new(Ipv4Addr::from([192, 168, 1, 1]), 17).netmask(),
            Ipv4Addr::from([255, 255, 128, 0])
        );
        assert_eq!(
            Cidr::new(Ipv4Addr::from([172, 16, 0, 0]), 12).netmask(),
            Ipv4Addr::from([255, 240, 0, 0])
        );
        assert_eq!(
            Cidr::new(Ipv4Addr::from([255, 255, 255, 1]), 24).netmask(),
            Ipv4Addr::from([255, 255, 255, 0])
        );
        assert_eq!(
            Cidr::new(Ipv4Addr::from([255, 255, 255, 255]), 32).netmask(),
            Ipv4Addr::from([255, 255, 255, 255])
        );
    }

    #[test]
    fn test_cidr_broadcast() {
        assert_eq!(
            Cidr::new(Ipv4Addr::from([0, 0, 0, 0]), 0)
                .broadcast()
                .unwrap(),
            Ipv4Addr::from([255, 255, 255, 255])
        );
        assert_eq!(
            Cidr::new(Ipv4Addr::from([0, 0, 0, 1]), 24)
                .broadcast()
                .unwrap(),
            Ipv4Addr::from([0, 0, 0, 255])
        );
        assert_eq!(
            Cidr::new(Ipv4Addr::from([0, 0, 0, 0]), 32).broadcast(),
            None
        );
        assert_eq!(
            Cidr::new(Ipv4Addr::from([127, 0, 0, 0]), 8)
                .broadcast()
                .unwrap(),
            Ipv4Addr::from([127, 255, 255, 255])
        );
        assert_eq!(
            Cidr::new(Ipv4Addr::from([192, 168, 0, 0]), 16)
                .broadcast()
                .unwrap(),
            Ipv4Addr::from([192, 168, 255, 255])
        );
        assert_eq!(
            Cidr::new(Ipv4Addr::from([192, 168, 1, 1]), 16)
                .broadcast()
                .unwrap(),
            Ipv4Addr::from([192, 168, 255, 255])
        );
        assert_eq!(
            Cidr::new(Ipv4Addr::from([192, 168, 1, 1]), 17)
                .broadcast()
                .unwrap(),
            Ipv4Addr::from([192, 168, 127, 255])
        );
        assert_eq!(
            Cidr::new(Ipv4Addr::from([172, 16, 0, 1]), 12)
                .broadcast()
                .unwrap(),
            Ipv4Addr::from([172, 31, 255, 255])
        );
        assert_eq!(
            Cidr::new(Ipv4Addr::from([255, 255, 255, 1]), 24)
                .broadcast()
                .unwrap(),
            Ipv4Addr::from([255, 255, 255, 255])
        );
        assert_eq!(
            Cidr::new(Ipv4Addr::from([255, 255, 255, 254]), 31).broadcast(),
            None
        );
        assert_eq!(
            Cidr::new(Ipv4Addr::from([255, 255, 255, 255]), 32).broadcast(),
            None
        );
    }

    #[test]
    fn test_cidr_network() {
        assert_eq!(
            Cidr::new(Ipv4Addr::from([0, 0, 0, 0]), 0).network(),
            Cidr::new(Ipv4Addr::from([0, 0, 0, 0]), 0)
        );
        assert_eq!(
            Cidr::new(Ipv4Addr::from([0, 0, 0, 1]), 24).network(),
            Cidr::new(Ipv4Addr::from([0, 0, 0, 0]), 24)
        );
        assert_eq!(
            Cidr::new(Ipv4Addr::from([0, 0, 0, 0]), 32).network(),
            Cidr::new(Ipv4Addr::from([0, 0, 0, 0]), 32)
        );
        assert_eq!(
            Cidr::new(Ipv4Addr::from([127, 0, 0, 0]), 8).network(),
            Cidr::new(Ipv4Addr::from([127, 0, 0, 0]), 8)
        );
        assert_eq!(
            Cidr::new(Ipv4Addr::from([192, 168, 0, 0]), 16).network(),
            Cidr::new(Ipv4Addr::from([192, 168, 0, 0]), 16)
        );
        assert_eq!(
            Cidr::new(Ipv4Addr::from([192, 168, 1, 1]), 16).network(),
            Cidr::new(Ipv4Addr::from([192, 168, 0, 0]), 16)
        );
        assert_eq!(
            Cidr::new(Ipv4Addr::from([192, 168, 1, 1]), 17).network(),
            Cidr::new(Ipv4Addr::from([192, 168, 0, 0]), 17)
        );
        assert_eq!(
            Cidr::new(Ipv4Addr::from([172, 16, 0, 1]), 12).network(),
            Cidr::new(Ipv4Addr::from([172, 16, 0, 0]), 12)
        );
        assert_eq!(
            Cidr::new(Ipv4Addr::from([255, 255, 255, 1]), 24).network(),
            Cidr::new(Ipv4Addr::from([255, 255, 255, 0]), 24)
        );
        assert_eq!(
            Cidr::new(Ipv4Addr::from([255, 255, 255, 255]), 32).network(),
            Cidr::new(Ipv4Addr::from([255, 255, 255, 255]), 32)
        );
    }
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
