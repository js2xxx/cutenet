use core::{
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use crate as cutenet;
use crate::wire::prelude::*;

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
            Cidr::V4(cidr) => IpAddr::V4(cidr.address()),
            Cidr::V6(cidr) => IpAddr::V6(cidr.address()),
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
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Version::V4 => write!(f, "IPv4"),
            Version::V6 => write!(f, "IPv6"),
        }
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

pub trait IpAddrExt {
    fn zeroed() -> Self;

    fn from_bytes(bytes: &[u8]) -> Self;

    fn mask(&self, prefix_len: u8) -> Self;

    fn prefix_len(&self) -> Option<u8>;

    fn unwrap_v4(self) -> Ipv4Addr;

    fn unwrap_v6(self) -> Ipv6Addr;
}

impl IpAddrExt for Ipv4Addr {
    fn zeroed() -> Self {
        Ipv4Addr::from_bits(0)
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

    fn unwrap_v4(self) -> Ipv4Addr {
        self
    }

    fn unwrap_v6(self) -> Ipv6Addr {
        unreachable!("IPv4 => IPv6")
    }
}

impl IpAddrExt for Ipv6Addr {
    fn zeroed() -> Self {
        Ipv6Addr::from_bits(0)
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

    fn unwrap_v4(self) -> Ipv4Addr {
        unreachable!("IPv6 => IPv4")
    }

    fn unwrap_v6(self) -> Ipv6Addr {
        self
    }
}

impl IpAddrExt for IpAddr {
    fn zeroed() -> Self {
        IpAddr::V4(Ipv4Addr::zeroed())
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Wire)]
pub enum Packet<#[wire] T, #[no_payload] U> {
    Arp(#[wire] super::Arpv4Packet<U>),
    V4(#[wire] v4::Packet<T>),
    V6(#[wire] v6::Packet<T>),
}
