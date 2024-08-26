use core::{
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

pub(super) mod checksum;
pub mod v4;
pub mod v6;

#[derive(Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
pub enum Version {
    Ipv4,
    Ipv6,
}

impl Version {
    pub const fn of_packet(data: &[u8]) -> Result<Version, ParseError> {
        match data[0] >> 4 {
            4 => Ok(Version::Ipv4),
            6 => Ok(Version::Ipv6),
            _ => Err(ParseError::VersionInvalid),
        }
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Version::Ipv4 => write!(f, "IPv4"),
            Version::Ipv6 => write!(f, "IPv6"),
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
    fn from_bytes(bytes: &[u8]) -> Self;

    fn mask(&self, prefix_len: u8) -> Self;

    fn prefix_len(&self) -> Option<u8>;
}

impl IpAddrExt for Ipv4Addr {
    fn from_bytes(bytes: &[u8]) -> Self {
        From::<[u8; 4]>::from(bytes.try_into().unwrap())
    }

    fn mask(&self, prefix_len: u8) -> Self {
        Ipv4Addr::from(mask_impl(self.octets(), prefix_len))
    }

    fn prefix_len(&self) -> Option<u8> {
        prefix_len_impl(&self.octets())
    }
}

impl IpAddrExt for Ipv6Addr {
    fn from_bytes(bytes: &[u8]) -> Self {
        From::<[u8; 16]>::from(bytes.try_into().unwrap())
    }

    fn mask(&self, prefix_len: u8) -> Self {
        Ipv6Addr::from(mask_impl(self.octets(), prefix_len))
    }

    fn prefix_len(&self) -> Option<u8> {
        prefix_len_impl(&self.octets())
    }
}

impl IpAddrExt for IpAddr {
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
}

#[derive(Debug)]
pub enum ParseError {
    VersionInvalid,
    NetmaskInvalid,
    PacketTooShort,
    ChecksumInvalid,
}
