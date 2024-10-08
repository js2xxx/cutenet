use core::{
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
};

use super::EthernetAddr;
use crate::{context::*, prelude::*, EthernetProtocol};

pub(super) mod checksum;
pub mod v4;
pub mod v6;

#[derive(Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
pub enum Cidr {
    V4(v4::Cidr),
    V6(v6::Cidr),
}

impl Cidr {
    /// Create a CIDR block from the given address and prefix length.
    ///
    /// # Panics
    /// This function panics if the given prefix length is invalid for the given
    /// address.
    pub fn new(addr: IpAddr, prefix_len: u8) -> Cidr {
        match addr {
            IpAddr::V4(addr) => Cidr::V4(v4::Cidr::new(addr, prefix_len)),
            IpAddr::V6(addr) => Cidr::V6(v6::Cidr::new(addr, prefix_len)),
        }
    }

    /// Return the IP address of this CIDR block.
    pub const fn addr(&self) -> IpAddr {
        match *self {
            Cidr::V4(cidr) => IpAddr::V4(cidr.addr()),
            Cidr::V6(cidr) => IpAddr::V6(cidr.addr()),
        }
    }

    /// Return the prefix length of this CIDR block.
    pub const fn prefix_len(&self) -> u8 {
        match *self {
            Cidr::V4(cidr) => cidr.prefix_len(),
            Cidr::V6(cidr) => cidr.prefix_len(),
        }
    }

    /// Query whether the subnetwork described by this CIDR block contains
    /// the given address.
    pub fn contains_addr(&self, addr: &IpAddr) -> bool {
        match (self, addr) {
            (Cidr::V4(cidr), IpAddr::V4(addr)) => cidr.contains_addr(addr),
            (Cidr::V6(cidr), IpAddr::V6(addr)) => cidr.contains_addr(addr),
            _ => false,
        }
    }

    /// Query whether the subnetwork described by this CIDR block contains
    /// the subnetwork described by the given CIDR block.
    pub fn contains_subnet(&self, subnet: &Cidr) -> bool {
        match (self, subnet) {
            (Cidr::V4(cidr), Cidr::V4(other)) => cidr.contains_subnet(other),
            (Cidr::V6(cidr), Cidr::V6(other)) => cidr.contains_subnet(other),
            _ => false,
        }
    }
}

impl From<v4::Cidr> for Cidr {
    fn from(addr: v4::Cidr) -> Self {
        Cidr::V4(addr)
    }
}

impl From<v6::Cidr> for Cidr {
    fn from(addr: v6::Cidr) -> Self {
        Cidr::V6(addr)
    }
}

impl fmt::Display for Cidr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Cidr::V4(cidr) => cidr.fmt(f),
            Cidr::V6(cidr) => cidr.fmt(f),
        }
    }
}

#[derive(Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
pub enum Version {
    V4,
    V6,
}

impl Version {
    pub const fn of_packet(data: &[u8]) -> Option<Version> {
        match data[0] >> 4 {
            4 => Some(Version::V4),
            6 => Some(Version::V6),
            _ => None,
        }
    }

    pub fn header_len(&self) -> usize {
        match *self {
            Version::V4 => v4::HEADER_LEN,
            Version::V6 => v6::HEADER_LEN,
        }
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Version::V4 => write!(f, "IPv4"),
            Version::V6 => write!(f, "IPv6"),
        }
    }
}

impl From<IpAddr> for Version {
    fn from(addr: IpAddr) -> Self {
        match addr {
            IpAddr::V4(_) => Version::V4,
            IpAddr::V6(_) => Version::V6,
        }
    }
}

impl From<SocketAddr> for Version {
    fn from(addr: SocketAddr) -> Self {
        match addr {
            SocketAddr::V4(_) => Version::V4,
            SocketAddr::V6(_) => Version::V6,
        }
    }
}

impl From<Ipv4Addr> for Version {
    fn from(_: Ipv4Addr) -> Self {
        Version::V4
    }
}

impl From<Ipv6Addr> for Version {
    fn from(_: Ipv6Addr) -> Self {
        Version::V6
    }
}

impl From<SocketAddrV4> for Version {
    fn from(_: SocketAddrV4) -> Self {
        Version::V4
    }
}

impl From<SocketAddrV6> for Version {
    fn from(_: SocketAddrV6) -> Self {
        Version::V6
    }
}

impl<T: Into<Version>> From<Ends<T>> for Version {
    fn from(value: Ends<T>) -> Self {
        let version = value.map(Into::into);
        assert_eq!(version.src, version.dst);
        version.dst
    }
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
        Ipv6Opts  = 0x3c,
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

fn prefix_len_impl(bytes: &[u8]) -> Option<u8> {
    let mut ones = true;
    let mut prefix_len = 0;
    for byte in bytes {
        let mut mask = 0x80;
        for _ in 0..8 {
            let one = *byte & mask != 0;
            if ones {
                // Expect 1s until first 0
                if one {
                    prefix_len += 1;
                } else {
                    ones = false;
                }
            } else if one {
                // 1 where 0 was expected
                return None;
            }
            mask >>= 1;
        }
    }
    Some(prefix_len)
}

fn mask_impl<const N: usize>(input: [u8; N], prefix_len: u8) -> [u8; N] {
    let mut bytes = [0u8; N];
    let idx = usize::from(prefix_len) / 8;
    let modulus = usize::from(prefix_len) % 8;
    let (first, second) = input.split_at(idx);
    bytes[0..idx].copy_from_slice(first);
    if idx < 16 {
        let part = second[0];
        bytes[idx] = part & (!(0xff >> modulus) as u8);
    }
    bytes
}

pub trait IpAddrExt: Eq + Copy + fmt::Display + fmt::Debug {
    type Cidr: IpCidrExt<Addr = Self>;

    const UNSPECIFIED: Self;

    fn version(&self) -> Version;

    fn from_bytes(bytes: &[u8]) -> Self;

    fn mask(&self, prefix_len: u8) -> Self;

    fn prefix_len(&self) -> Option<u8>;

    fn is_unicast(&self) -> bool;

    fn is_broadcast(&self) -> bool;

    fn multicast_ethernet(&self) -> EthernetAddr;

    fn unwrap_v4(self) -> Ipv4Addr;

    fn unwrap_v6(self) -> Ipv6Addr;
}

impl IpAddrExt for Ipv4Addr {
    type Cidr = v4::Cidr;

    const UNSPECIFIED: Self = Ipv4Addr::UNSPECIFIED;

    fn version(&self) -> Version {
        Version::V4
    }

    fn from_bytes(bytes: &[u8]) -> Self {
        From::<[u8; 4]>::from(bytes.try_into().unwrap())
    }

    fn mask(&self, prefix_len: u8) -> Self {
        Ipv4Addr::from(mask_impl(self.octets(), prefix_len))
    }

    fn prefix_len(&self) -> Option<u8> {
        prefix_len_impl(&self.octets())
    }

    fn is_unicast(&self) -> bool {
        !(self.is_broadcast() || self.is_multicast() || self.is_unspecified())
    }

    fn is_broadcast(&self) -> bool {
        self.is_broadcast()
    }

    fn multicast_ethernet(&self) -> EthernetAddr {
        let [_, b1, b2, b3, ..] = self.octets();
        EthernetAddr([0x01, 0x00, 0x5e, b1 & 0x7F, b2, b3])
    }

    fn unwrap_v4(self) -> Ipv4Addr {
        self
    }

    fn unwrap_v6(self) -> Ipv6Addr {
        unreachable!("IPv4 => IPv6")
    }
}

impl IpAddrExt for Ipv6Addr {
    type Cidr = v6::Cidr;

    const UNSPECIFIED: Self = Ipv6Addr::UNSPECIFIED;

    fn version(&self) -> Version {
        Version::V6
    }

    fn from_bytes(bytes: &[u8]) -> Self {
        From::<[u8; 16]>::from(bytes.try_into().unwrap())
    }

    fn mask(&self, prefix_len: u8) -> Self {
        Ipv6Addr::from(mask_impl(self.octets(), prefix_len))
    }

    fn prefix_len(&self) -> Option<u8> {
        prefix_len_impl(&self.octets())
    }

    fn is_unicast(&self) -> bool {
        self.is_unicast()
    }

    fn is_broadcast(&self) -> bool {
        false
    }

    fn multicast_ethernet(&self) -> EthernetAddr {
        let [.., b12, b13, b14, b15] = self.octets();
        EthernetAddr([0x33, 0x33, b12, b13, b14, b15])
    }

    fn unwrap_v4(self) -> Ipv4Addr {
        unreachable!("IPv6 => IPv4")
    }

    fn unwrap_v6(self) -> Ipv6Addr {
        self
    }
}

impl IpAddrExt for IpAddr {
    type Cidr = Cidr;

    const UNSPECIFIED: Self = IpAddr::V4(Ipv4Addr::UNSPECIFIED);

    fn version(&self) -> Version {
        match self {
            IpAddr::V4(_) => Version::V4,
            IpAddr::V6(_) => Version::V6,
        }
    }

    fn from_bytes(bytes: &[u8]) -> Self {
        match bytes.len() {
            4 => IpAddr::V4(Ipv4Addr::from_bytes(bytes)),
            16 => IpAddr::V6(Ipv6Addr::from_bytes(bytes)),
            _ => panic!("invalid byte length for IP addresses"),
        }
    }

    fn mask(&self, prefix_len: u8) -> Self {
        match self {
            IpAddr::V4(v4) => IpAddr::V4(v4.mask(prefix_len)),
            IpAddr::V6(v6) => IpAddr::V6(v6.mask(prefix_len)),
        }
    }

    fn prefix_len(&self) -> Option<u8> {
        match self {
            IpAddr::V4(v4) => v4.prefix_len(),
            IpAddr::V6(v6) => v6.prefix_len(),
        }
    }

    fn is_unicast(&self) -> bool {
        match self {
            IpAddr::V4(v4) => v4.is_unicast(),
            IpAddr::V6(v6) => v6.is_unicast(),
        }
    }

    fn is_broadcast(&self) -> bool {
        match self {
            IpAddr::V4(v4) => v4.is_broadcast(),
            IpAddr::V6(v6) => v6.is_broadcast(),
        }
    }

    fn multicast_ethernet(&self) -> EthernetAddr {
        match self {
            IpAddr::V4(v4) => v4.multicast_ethernet(),
            IpAddr::V6(v6) => v6.multicast_ethernet(),
        }
    }

    fn unwrap_v4(self) -> Ipv4Addr {
        match self {
            IpAddr::V4(v4) => v4.unwrap_v4(),
            IpAddr::V6(v6) => v6.unwrap_v4(),
        }
    }

    fn unwrap_v6(self) -> Ipv6Addr {
        match self {
            IpAddr::V4(v4) => v4.unwrap_v6(),
            IpAddr::V6(v6) => v6.unwrap_v6(),
        }
    }
}

pub trait IpCidrExt: Eq + Copy + fmt::Display + fmt::Debug {
    type Addr: IpAddrExt<Cidr = Self>;

    const UNSPECIFIED: Self;

    fn new(addr: Self::Addr, prefix_len: u8) -> Self;

    fn addr(&self) -> Self::Addr;

    fn broadcast(&self) -> Option<Self::Addr>;

    fn contains_addr(&self, addr: &Self::Addr) -> bool;

    fn prefix_len(&self) -> u8;
}

impl IpCidrExt for v4::Cidr {
    type Addr = Ipv4Addr;

    const UNSPECIFIED: Self = v4::Cidr::new(Ipv4Addr::UNSPECIFIED, 32);

    fn new(addr: Self::Addr, prefix_len: u8) -> Self {
        v4::Cidr::new(addr, prefix_len)
    }

    fn addr(&self) -> Self::Addr {
        self.addr()
    }

    fn broadcast(&self) -> Option<Self::Addr> {
        self.broadcast()
    }

    fn contains_addr(&self, addr: &Self::Addr) -> bool {
        self.contains_addr(addr)
    }

    fn prefix_len(&self) -> u8 {
        self.prefix_len()
    }
}

impl IpCidrExt for v6::Cidr {
    type Addr = Ipv6Addr;

    const UNSPECIFIED: Self = v6::Cidr::new(Ipv6Addr::UNSPECIFIED, 128);

    fn new(addr: Self::Addr, prefix_len: u8) -> Self {
        v6::Cidr::new(addr, prefix_len)
    }

    fn addr(&self) -> Self::Addr {
        self.addr()
    }

    fn broadcast(&self) -> Option<Self::Addr> {
        None
    }

    fn contains_addr(&self, addr: &Self::Addr) -> bool {
        self.contains_addr(addr)
    }

    fn prefix_len(&self) -> u8 {
        self.prefix_len()
    }
}

impl IpCidrExt for Cidr {
    type Addr = IpAddr;

    const UNSPECIFIED: Self = Cidr::V4(v4::Cidr::UNSPECIFIED);

    fn new(addr: Self::Addr, prefix_len: u8) -> Self {
        Cidr::new(addr, prefix_len)
    }

    fn addr(&self) -> Self::Addr {
        match self {
            Cidr::V4(cidr) => IpAddr::V4(cidr.addr()),
            Cidr::V6(cidr) => IpAddr::V6(cidr.addr()),
        }
    }

    fn broadcast(&self) -> Option<Self::Addr> {
        match self {
            Cidr::V4(cidr) => cidr.broadcast().map(IpAddr::V4),
            Cidr::V6(cidr) => cidr.broadcast().map(IpAddr::V6),
        }
    }

    fn contains_addr(&self, addr: &Self::Addr) -> bool {
        match (self, addr) {
            (Cidr::V4(cidr), IpAddr::V4(addr)) => cidr.contains_addr(addr),
            (Cidr::V6(cidr), IpAddr::V6(addr)) => cidr.contains_addr(addr),
            _ => false,
        }
    }

    fn prefix_len(&self) -> u8 {
        match self {
            Cidr::V4(cidr) => cidr.prefix_len(),
            Cidr::V6(cidr) => cidr.prefix_len(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Wire)]
#[prefix(crate)]
pub enum Packet<#[wire] T> {
    V4(#[wire] v4::Packet<T>),
    V6(#[wire] v6::Packet<T>),
}

impl<T> Packet<T> {
    pub fn ip_addr(&self) -> Ends<IpAddr> {
        match *self {
            Packet::V4(v4::Packet { addr, .. }) => addr.map(IpAddr::V4),
            Packet::V6(v6::Packet { addr, .. }) => addr.map(IpAddr::V6),
        }
    }

    pub fn next_header(&self) -> Protocol {
        match *self {
            Packet::V4(v4::Packet { next_header, .. }) => next_header,
            Packet::V6(v6::Packet { next_header, .. }) => next_header,
        }
    }

    pub fn decrease_hop_limit(&mut self) -> bool {
        let hop_limit = match self {
            Packet::V4(v4::Packet { hop_limit, .. }) => hop_limit,
            Packet::V6(v6::Packet { hop_limit, .. }) => hop_limit,
        };
        let ret = *hop_limit > 1;
        *hop_limit = hop_limit.saturating_sub(1);
        ret
    }

    pub fn new(addr: Ends<IpAddr>, next_header: Protocol, hop_limit: u8, payload: T) -> Self {
        match (addr.src, addr.dst) {
            (IpAddr::V4(src), IpAddr::V4(dst)) => Packet::V4(v4::Packet {
                addr: Ends { src, dst },
                next_header,
                hop_limit,
                frag_info: None,
                payload,
            }),
            (IpAddr::V6(src), IpAddr::V6(dst)) => Packet::V6(v6::Packet {
                addr: Ends { src, dst },
                next_header,
                hop_limit,
                payload,
            }),
            _ => unreachable!("IP address family mismatch"),
        }
    }

    pub fn map_wire<U>(self, map: impl FnOnce(T, Ends<IpAddr>) -> U) -> Packet<U> {
        match self {
            Packet::V4(v4::Packet {
                addr,
                next_header,
                hop_limit,
                frag_info,
                payload,
            }) => Packet::V4(v4::Packet {
                addr,
                next_header,
                hop_limit,
                frag_info,
                payload: map(payload, addr.map(Into::into)),
            }),
            Packet::V6(v6::Packet {
                addr,
                next_header,
                hop_limit,
                payload,
            }) => Packet::V6(v6::Packet {
                addr,
                next_header,
                hop_limit,
                payload: map(payload, addr.map(Into::into)),
            }),
        }
    }
}

impl<T, P, U> WireParse for Packet<T>
where
    T: WireParse<Payload = P>,
    P: PayloadParse<NoPayload = U>,
    U: NoPayload<Init = P>,
{
    fn parse(cx: &dyn WireCx, raw: P) -> Result<Self, ParseError<P>> {
        Ok(match cx.ethernet_protocol() {
            EthernetProtocol::Ipv4 => Packet::V4(v4::Packet::parse(cx, raw)?),
            EthernetProtocol::Ipv6 => Packet::V6(v6::Packet::parse(cx, raw)?),
            _ => return Err(ParseErrorKind::ProtocolUnknown.with(raw)),
        })
    }
}

impl<T, P, U> WireBuild for Packet<T>
where
    T: WireBuild<Payload = P>,
    P: PayloadBuild<NoPayload = U>,
    U: NoPayload<Init = P>,
{
    fn buffer_len(&self) -> usize {
        match self {
            Packet::V4(packet) => packet.buffer_len(),
            Packet::V6(packet) => packet.buffer_len(),
        }
    }

    fn build(self, cx: &dyn WireCx) -> Result<P, BuildError<P>> {
        match self {
            Packet::V4(packet) => packet.build(cx),
            Packet::V6(packet) => packet.build(cx),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Wire)]
#[prefix(crate)]
pub enum IpPayload<#[wire] T, #[no_payload] U> {
    V4(#[wire] v4::Ipv4Payload<T>),
    V6(#[wire] v6::Ipv6Payload<T, U>),
}

impl<T, U> IpPayload<T, U> {
    pub fn ip_protocol(&self) -> Protocol {
        match self {
            IpPayload::V4(payload) => payload.ip_protocol(),
            IpPayload::V6(payload) => payload.ip_protocol(),
        }
    }
}

impl<T, P, U> WireParse for IpPayload<T, U>
where
    T: WireParse<Payload = P>,
    P: PayloadParse<NoPayload = U>,
    U: NoPayload<Init = P>,
{
    fn parse(cx: &dyn WireCx, raw: Self::Payload) -> Result<Self, ParseError<Self::Payload>> {
        match cx.ip_version() {
            Version::V4 => v4::Ipv4Payload::parse(cx, raw).map(IpPayload::V4),
            Version::V6 => v6::Ipv6Payload::parse(cx, raw).map(IpPayload::V6),
        }
    }
}

impl<T, P, U> WireBuild for IpPayload<T, U>
where
    T: WireBuild<Payload = P>,
    P: PayloadBuild<NoPayload = U>,
    U: NoPayload<Init = P>,
{
    fn buffer_len(&self) -> usize {
        match self {
            IpPayload::V4(payload) => payload.buffer_len(),
            IpPayload::V6(payload) => payload.buffer_len(),
        }
    }

    fn build(self, cx: &dyn WireCx) -> Result<Self::Payload, BuildError<Self::Payload>> {
        match self {
            IpPayload::V4(payload) => payload.build(cx),
            IpPayload::V6(payload) => payload.build(cx),
        }
    }
}
