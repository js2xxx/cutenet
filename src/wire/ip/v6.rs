use core::{fmt, net::Ipv6Addr};

use super::IpAddrExt;

#[derive(Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
pub struct Cidr {
    address: Ipv6Addr,
    prefix_len: u8,
}

impl Cidr {
    /// The [solicited node prefix].
    ///
    /// [solicited node prefix]: https://tools.ietf.org/html/rfc4291#section-2.7.1
    pub const SOLICITED_NODE_PREFIX: Cidr = Cidr {
        address: Ipv6Addr::new(
            0xff02, 0x0000, 0x0000, 0x0000, 0x0000, 0x0001, 0xff00, 0x0000,
        ),
        prefix_len: 104,
    };

    /// Create an IPv6 CIDR block from the given address and prefix length.
    ///
    /// # Panics
    /// This function panics if the prefix length is larger than 128.
    pub const fn new(address: Ipv6Addr, prefix_len: u8) -> Cidr {
        assert!(prefix_len <= 128);
        Cidr { address, prefix_len }
    }

    /// Return the address of this IPv6 CIDR block.
    pub const fn address(&self) -> Ipv6Addr {
        self.address
    }

    /// Return the prefix length of this IPv6 CIDR block.
    pub const fn prefix_len(&self) -> u8 {
        self.prefix_len
    }

    /// Query whether the subnetwork described by this IPv6 CIDR block contains
    /// the given address.
    pub fn contains_addr(&self, addr: &Ipv6Addr) -> bool {
        // right shift by 128 is not legal
        if self.prefix_len == 0 {
            return true;
        }

        self.address.mask(self.prefix_len) == addr.mask(self.prefix_len)
    }

    /// Query whether the subnetwork described by this IPV6 CIDR block contains
    /// the subnetwork described by the given IPv6 CIDR block.
    pub fn contains_subnet(&self, subnet: &Cidr) -> bool {
        self.prefix_len <= subnet.prefix_len && self.contains_addr(&subnet.address)
    }
}

impl fmt::Display for Cidr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // https://tools.ietf.org/html/rfc4291#section-2.3
        write!(f, "{}/{}", self.address, self.prefix_len)
    }
}
