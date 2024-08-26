use core::fmt;

mod traits;
pub use self::traits::{
    NoPayload, NoPayloadHolder, Payload, PayloadBuild, PayloadHolder, PayloadParse, Wire,
    WireBuild, WireParse, WireSubNoPayload, WireSubstitute,
};

mod error;
pub use self::error::{BuildError, BuildErrorKind, ParseError, ParseErrorKind};

mod arpv4;
pub use self::arpv4::{
    Hardware as ArpHardware, Operation as ArpOperation, Packet as Arpv4Packet,
    HARDWARE_LEN as ARPV4_HARDWARE_LEN, HEADER_LEN as ARPV4_HEADER_LEN,
    PROTOCOL_LEN as ARPV4_PROTOCOL_LEN,
};

mod ethernet;
pub use self::ethernet::{
    Addr as EthernetAddr, Frame as EthernetFrame, Protocol as EthernetProtocol,
    HEADER_LEN as ETHERNET_HEADER_LEN,
};

mod icmp;
pub use self::icmp::{
    v4::{
        DstUnreachable as Icmpv4DstUnreachable, Message as Icmpv4Message, Packet as Icmpv4Packet,
        ParamProblem as Icmpv4ParamProblem, Redirect as Icmpv4Redirect,
        TimeExceeded as Icmpv4TimeExceeded,
    },
    v6::{
        nd::{
            Nd as Icmpv6Nd, NeighborFlags as Icmpv6NeighborFlags, PrefixInfo as Icmpv6PrefixInfo,
            PrefixInfoFlags as Icmpv6PrefixInfoFlags, RouterFlags as Icmpv6Routerflags,
        },
        DstUnreachable as Icmpv6DstUnreachable, Message as Icmpv6Message, Packet as Icmpv6Packet,
        ParamProblem as Icmpv6ParamProblem, TimeExceeded as Icmpv6TimeExceeded,
    },
};

mod ieee802154;
pub use self::ieee802154::{
    Addr as Ieee802154Addr, AddressingMode as Ieee802154AddressingMode, Frame as Ieee802154Frame,
    FrameType as Ieee802154FrameType, FrameVersion as Ieee802154FrameVersion, Pan as Ieee802154Pan,
};

mod ip;
pub use self::ip::{
    v4::{
        Cidr as Ipv4Cidr, FragInfo as Ipv4FragInfo, Key as Ipv4Key, Packet as Ipv4Packet,
        HEADER_LEN as IPV4_HEADER_LEN,
    },
    v6::{
        Cidr as Ipv6Cidr, Ipv6AddrExt, Packet as Ipv6Packet, HEADER_LEN as IPV6_HEADER_LEN,
        MIN_MTU as IPV6_MIN_MTU,
    },
    Cidr as IpCidr, IpAddrExt, Packet as IpPacket, Protocol as IpProtocol, Version as IpVersion,
};

mod tcp;
pub use self::tcp::{
    Control as TcpControl, Packet as TcpPacket, SeqNumber as TcpSeqNumber, TcpFlags, TcpOption,
    TcpTimestamp, TcpTimestampGenerator, HEADER_LEN as TCP_HEADER_LEN,
};

mod udp;
pub use self::udp::{Packet as UdpPacket, HEADER_LEN as UDP_HEADER_LEN};

mod field {
    use core::ops::{Range, RangeFrom};

    pub type Field = Range<usize>;
    pub type Rest = RangeFrom<usize>;
}

mod prelude {
    pub use cutenet_macros::Wire;

    pub use super::{error::*, traits::*};
}

pub trait Data: AsRef<[u8]> {}
impl<T: AsRef<[u8]> + ?Sized> Data for T {}

pub trait DataMut: Data + AsMut<[u8]> {}
impl<T: Data + AsMut<[u8]> + ?Sized> DataMut for T {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HwAddr {
    Ethernet(EthernetAddr),
    Ieee802154(Ieee802154Addr),
}

impl From<Ieee802154Addr> for HwAddr {
    fn from(v: Ieee802154Addr) -> Self {
        Self::Ieee802154(v)
    }
}

impl From<EthernetAddr> for HwAddr {
    fn from(v: EthernetAddr) -> Self {
        Self::Ethernet(v)
    }
}

impl HwAddr {
    pub fn ethernet(self) -> Option<EthernetAddr> {
        match self {
            HwAddr::Ethernet(eth) => Some(eth),
            HwAddr::Ieee802154(_) => None,
        }
    }

    pub fn ieee802154(self) -> Option<Ieee802154Addr> {
        match self {
            HwAddr::Ethernet(_) => None,
            HwAddr::Ieee802154(ieee) => Some(ieee),
        }
    }
}

pub const MAX_HWADDR_LEN: usize = 8;

/// Unparsed hardware address.
///
/// Used to make NDISC parsing agnostic of the hardware medium in use.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct RawHwAddr {
    len: u8,
    data: [u8; MAX_HWADDR_LEN],
}

impl RawHwAddr {
    pub fn from_bytes(addr: &[u8]) -> Self {
        let mut data = [0u8; MAX_HWADDR_LEN];
        data[..addr.len()].copy_from_slice(addr);

        Self { len: addr.len() as u8, data }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.data[..self.len as usize]
    }

    pub const fn len(&self) -> usize {
        self.len as usize
    }

    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    // pub fn parse(&self, medium: Medium) -> Result<HardwareAddress> {
    //     match medium {
    //         #[cfg(feature = "medium-ethernet")]
    //         Medium::Ethernet => {
    //             if self.len() < 6 {
    //                 return Err(Error);
    //             }
    //             Ok(HardwareAddress::Ethernet(ethernet::Addr::from_bytes(
    //                 self.as_bytes(),
    //             )))
    //         }
    //         #[cfg(feature = "medium-ieee802154")]
    //         Medium::Ieee802154 => {
    //             if self.len() < 8 {
    //                 return Err(Error);
    //             }

    //             Ok(HardwareAddress::Ieee802154(ieee802154::Addr::from_bytes(
    //                 self.as_bytes(),
    //             )))
    //         }
    //         #[cfg(feature = "medium-ip")]
    //         Medium::Ip => unreachable!(),
    //     }
    // }
}

impl fmt::Display for RawHwAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, &b) in self.as_bytes().iter().enumerate() {
            if i != 0 {
                write!(f, ":")?;
            }
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

impl From<HwAddr> for RawHwAddr {
    fn from(value: HwAddr) -> Self {
        match value {
            HwAddr::Ethernet(eth) => eth.into(),
            HwAddr::Ieee802154(ieee) => ieee.into(),
        }
    }
}

impl From<ethernet::Addr> for RawHwAddr {
    fn from(addr: ethernet::Addr) -> Self {
        Self::from_bytes(addr.as_bytes())
    }
}

impl From<ieee802154::Addr> for RawHwAddr {
    fn from(addr: ieee802154::Addr) -> Self {
        Self::from_bytes(addr.as_bytes())
    }
}
