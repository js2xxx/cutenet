use core::{fmt, net::Ipv4Addr};

use crate::wire::ip::ParseError;

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
