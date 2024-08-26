use core::{
    fmt,
    net::{Ipv4Addr, Ipv6Addr, Ipv6MulticastScope},
};

use super::IpAddrExt;

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

#[cfg(test)]
pub(crate) mod test {
    use core::net::Ipv4Addr;
    use std::format;

    use super::{Cidr, Ipv6Addr};
    use crate::wire::ip::{v6::Ipv6AddrExt, IpAddrExt};

    #[allow(unused)]
    pub(crate) const MOCK_IP_ADDR_1: Ipv6Addr = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
    #[allow(unused)]
    pub(crate) const MOCK_IP_ADDR_2: Ipv6Addr = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 2);
    #[allow(unused)]
    pub(crate) const MOCK_IP_ADDR_3: Ipv6Addr = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 3);
    #[allow(unused)]
    pub(crate) const MOCK_IP_ADDR_4: Ipv6Addr = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 4);
    #[allow(unused)]
    pub(crate) const MOCK_UNSPECIFIED: Ipv6Addr = Ipv6Addr::UNSPECIFIED;

    const LINK_LOCAL_ADDR: Ipv6Addr = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
    const UNIQUE_LOCAL_ADDR: Ipv6Addr = Ipv6Addr::new(0xfd00, 0, 0, 201, 1, 1, 1, 1);
    const GLOBAL_UNICAST_ADDR: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0x3, 0, 0, 0, 0, 1);

    #[test]
    fn test_basic_multicast() {
        assert!(!Ipv6Addr::LINK_LOCAL_ALL_ROUTERS.is_unspecified());
        assert!(Ipv6Addr::LINK_LOCAL_ALL_ROUTERS.is_multicast());
        assert!(!Ipv6Addr::LINK_LOCAL_ALL_ROUTERS.is_link_local());
        assert!(!Ipv6Addr::LINK_LOCAL_ALL_ROUTERS.is_loopback());
        assert!(!Ipv6Addr::LINK_LOCAL_ALL_ROUTERS.is_unique_local());
        assert!(!Ipv6Addr::LINK_LOCAL_ALL_ROUTERS.is_global_unicast());
        assert!(!Ipv6Addr::LINK_LOCAL_ALL_NODES.is_unspecified());
        assert!(Ipv6Addr::LINK_LOCAL_ALL_NODES.is_multicast());
        assert!(!Ipv6Addr::LINK_LOCAL_ALL_NODES.is_link_local());
        assert!(!Ipv6Addr::LINK_LOCAL_ALL_NODES.is_loopback());
        assert!(!Ipv6Addr::LINK_LOCAL_ALL_NODES.is_unique_local());
        assert!(!Ipv6Addr::LINK_LOCAL_ALL_NODES.is_global_unicast());
    }

    #[test]
    fn test_basic_link_local() {
        assert!(!LINK_LOCAL_ADDR.is_unspecified());
        assert!(!LINK_LOCAL_ADDR.is_multicast());
        assert!(LINK_LOCAL_ADDR.is_link_local());
        assert!(!LINK_LOCAL_ADDR.is_loopback());
        assert!(!LINK_LOCAL_ADDR.is_unique_local());
        assert!(!LINK_LOCAL_ADDR.is_global_unicast());
    }

    #[test]
    fn test_basic_loopback() {
        assert!(!Ipv6Addr::LOOPBACK.is_unspecified());
        assert!(!Ipv6Addr::LOOPBACK.is_multicast());
        assert!(!Ipv6Addr::LOOPBACK.is_link_local());
        assert!(Ipv6Addr::LOOPBACK.is_loopback());
        assert!(!Ipv6Addr::LOOPBACK.is_unique_local());
        assert!(!Ipv6Addr::LOOPBACK.is_global_unicast());
    }

    #[test]
    fn test_unique_local() {
        assert!(!UNIQUE_LOCAL_ADDR.is_unspecified());
        assert!(!UNIQUE_LOCAL_ADDR.is_multicast());
        assert!(!UNIQUE_LOCAL_ADDR.is_link_local());
        assert!(!UNIQUE_LOCAL_ADDR.is_loopback());
        assert!(UNIQUE_LOCAL_ADDR.is_unique_local());
        assert!(!UNIQUE_LOCAL_ADDR.is_global_unicast());
    }

    #[test]
    fn test_global_unicast() {
        assert!(!GLOBAL_UNICAST_ADDR.is_unspecified());
        assert!(!GLOBAL_UNICAST_ADDR.is_multicast());
        assert!(!GLOBAL_UNICAST_ADDR.is_link_local());
        assert!(!GLOBAL_UNICAST_ADDR.is_loopback());
        assert!(!GLOBAL_UNICAST_ADDR.is_unique_local());
        assert!(GLOBAL_UNICAST_ADDR.is_global_unicast());
    }

    #[test]
    fn test_address_format() {
        assert_eq!("ff02::1", format!("{}", Ipv6Addr::LINK_LOCAL_ALL_NODES));
        assert_eq!("fe80::1", format!("{LINK_LOCAL_ADDR}"));
        assert_eq!(
            "fe80::7f00:0:1",
            format!(
                "{}",
                Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0x7f00, 0x0000, 0x0001)
            )
        );
        assert_eq!("::", format!("{}", Ipv6Addr::UNSPECIFIED));
        assert_eq!("::1", format!("{}", Ipv6Addr::LOOPBACK));

        assert_eq!(
            "::ffff:192.168.1.1",
            format!(
                "{}",
                Ipv6Addr::from_ipv4_mapped(Ipv4Addr::new(192, 168, 1, 1))
            )
        );
    }

    #[test]
    fn test_new() {
        assert_eq!(
            Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1),
            Ipv6Addr::LINK_LOCAL_ALL_NODES
        );
        assert_eq!(
            Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 2),
            Ipv6Addr::LINK_LOCAL_ALL_ROUTERS
        );
        assert_eq!(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1), Ipv6Addr::LOOPBACK);
        assert_eq!(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0), Ipv6Addr::UNSPECIFIED);
        assert_eq!(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1), LINK_LOCAL_ADDR);
    }

    #[test]
    fn test_from_parts() {
        assert_eq!(
            Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1),
            Ipv6Addr::LINK_LOCAL_ALL_NODES
        );
        assert_eq!(
            Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 2),
            Ipv6Addr::LINK_LOCAL_ALL_ROUTERS
        );
        assert_eq!(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1), Ipv6Addr::LOOPBACK);
        assert_eq!(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0), Ipv6Addr::UNSPECIFIED);
        assert_eq!(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1), LINK_LOCAL_ADDR);
    }

    #[test]
    fn test_mask() {
        let addr = Ipv6Addr::new(0x0123, 0x4567, 0x89ab, 0, 0, 0, 0, 1);
        assert_eq!(addr.mask(11).octets(), [
            0x01, 0x20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
        ]);
        assert_eq!(addr.mask(15).octets(), [
            0x01, 0x22, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
        ]);
        assert_eq!(addr.mask(26).octets(), [
            0x01, 0x23, 0x45, 0x40, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
        ]);
        assert_eq!(addr.mask(128).octets(), [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1
        ]);
        assert_eq!(addr.mask(127).octets(), [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
        ]);
    }

    #[test]
    fn test_is_ipv4_mapped() {
        assert!(!Ipv6Addr::UNSPECIFIED.is_ipv4_mapped());
        assert!(Ipv6Addr::from_ipv4_mapped(Ipv4Addr::new(192, 168, 1, 1)).is_ipv4_mapped());
    }

    #[test]
    fn test_as_ipv4() {
        assert_eq!(None, Ipv6Addr::UNSPECIFIED.to_ipv4_mapped());

        let ipv4 = Ipv4Addr::new(192, 168, 1, 1);
        assert_eq!(
            Some(ipv4),
            Ipv6Addr::from_ipv4_mapped(ipv4).to_ipv4_mapped()
        );
    }

    #[test]
    fn test_from_ipv4_address() {
        assert_eq!(
            Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, (192 << 8) + 168, (1 << 8) + 1),
            Ipv6Addr::from_ipv4_mapped(Ipv4Addr::new(192, 168, 1, 1))
        );
        assert_eq!(
            Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, (222 << 8) + 1, (41 << 8) + 90),
            Ipv6Addr::from_ipv4_mapped(Ipv4Addr::new(222, 1, 41, 90))
        );
    }

    #[test]
    fn test_cidr() {
        // fe80::1/56
        // 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00,
        // 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        let cidr = Cidr::new(LINK_LOCAL_ADDR, 56);

        let inside_subnet = [
            // fe80::2
            [
                0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x02,
            ],
            // fe80::1122:3344:5566:7788
            [
                0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
                0x77, 0x88,
            ],
            // fe80::ff00:0:0:0
            [
                0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00,
            ],
            // fe80::ff
            [
                0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0xff,
            ],
        ];

        let outside_subnet = [
            // fe80:0:0:101::1
            [
                0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x01,
            ],
            // ::1
            [
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x01,
            ],
            // ff02::1
            [
                0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x01,
            ],
            // ff02::2
            [
                0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x02,
            ],
        ];

        let subnets = [
            // fe80::ffff:ffff:ffff:ffff/65
            (
                [
                    0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff,
                    0xff, 0xff, 0xff,
                ],
                65,
            ),
            // fe80::1/128
            (
                [
                    0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x01,
                ],
                128,
            ),
            // fe80::1234:5678/96
            (
                [
                    0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x12,
                    0x34, 0x56, 0x78,
                ],
                96,
            ),
        ];

        let not_subnets = [
            // fe80::101:ffff:ffff:ffff:ffff/55
            (
                [
                    0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0xff, 0xff, 0xff, 0xff, 0xff,
                    0xff, 0xff, 0xff,
                ],
                55,
            ),
            // fe80::101:ffff:ffff:ffff:ffff/56
            (
                [
                    0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0xff, 0xff, 0xff, 0xff, 0xff,
                    0xff, 0xff, 0xff,
                ],
                56,
            ),
            // fe80::101:ffff:ffff:ffff:ffff/57
            (
                [
                    0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0xff, 0xff, 0xff, 0xff, 0xff,
                    0xff, 0xff, 0xff,
                ],
                57,
            ),
            // ::1/128
            (
                [
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x01,
                ],
                128,
            ),
        ];

        for addr in inside_subnet.into_iter().map(Ipv6Addr::from) {
            assert!(cidr.contains_addr(&addr));
        }

        for addr in outside_subnet.into_iter().map(Ipv6Addr::from) {
            assert!(!cidr.contains_addr(&addr));
        }

        for subnet in subnets
            .into_iter()
            .map(|(a, p)| Cidr::new(Ipv6Addr::from(a), p))
        {
            assert!(cidr.contains_subnet(&subnet));
        }

        for subnet in not_subnets
            .into_iter()
            .map(|(a, p)| Cidr::new(Ipv6Addr::from(a), p))
        {
            assert!(!cidr.contains_subnet(&subnet));
        }

        let cidr_without_prefix = Cidr::new(LINK_LOCAL_ADDR, 0);
        assert!(cidr_without_prefix.contains_addr(&Ipv6Addr::LOOPBACK));
    }

    #[test]
    fn test_scope() {
        use super::*;
        assert_eq!(
            Ipv6Addr::new(0xff01, 0, 0, 0, 0, 0, 0, 1).multicast_scope(),
            Some(Ipv6MulticastScope::InterfaceLocal)
        );
        assert_eq!(
            Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1).multicast_scope(),
            Some(Ipv6MulticastScope::LinkLocal)
        );
        assert_eq!(
            Ipv6Addr::new(0xff03, 0, 0, 0, 0, 0, 0, 1).multicast_scope(),
            Some(Ipv6MulticastScope::RealmLocal)
        );
        assert_eq!(
            Ipv6Addr::new(0xff04, 0, 0, 0, 0, 0, 0, 1).multicast_scope(),
            Some(Ipv6MulticastScope::AdminLocal)
        );
        assert_eq!(
            Ipv6Addr::new(0xff05, 0, 0, 0, 0, 0, 0, 1).multicast_scope(),
            Some(Ipv6MulticastScope::SiteLocal)
        );
        assert_eq!(
            Ipv6Addr::new(0xff08, 0, 0, 0, 0, 0, 0, 1).multicast_scope(),
            Some(Ipv6MulticastScope::OrganizationLocal)
        );
        assert_eq!(
            Ipv6Addr::new(0xff0e, 0, 0, 0, 0, 0, 0, 1).multicast_scope(),
            Some(Ipv6MulticastScope::Global)
        );

        assert_eq!(
            Ipv6Addr::LINK_LOCAL_ALL_NODES.multicast_scope(),
            Some(Ipv6MulticastScope::LinkLocal)
        );

        // For source address selection, unicast addresses also have a scope:
        assert_eq!(
            LINK_LOCAL_ADDR.unicast_scope(),
            Some(Ipv6MulticastScope::LinkLocal)
        );
        assert_eq!(
            GLOBAL_UNICAST_ADDR.unicast_scope(),
            Some(Ipv6MulticastScope::Global)
        );
        assert_eq!(
            UNIQUE_LOCAL_ADDR.unicast_scope(),
            Some(Ipv6MulticastScope::Global)
        );
    }
}
