use core::{fmt, net::Ipv4Addr};

use super::ParseError;

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
