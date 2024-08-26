mod traits;
pub use self::traits::{
    NoPayload, NoPayloadHolder, Payload, PayloadBuild, PayloadHolder, PayloadParse, Wire,
    WireBuild, WireCx, WireParse, WireSubNoPayload, WireSubstitute,
};

mod error;
pub use self::error::{BuildError, BuildErrorKind, ParseError, ParseErrorKind};

mod hw;
pub use self::hw::{HwAddr, HwAddrExt, RawHwAddr, HWADDR_MAX_LEN};

mod arp;
pub use self::arp::{
    Operation as ArpOperation, Packet as ArpPacket, HEADER_LEN as ARPV4_HEADER_LEN,
};

mod ethernet;
pub use self::ethernet::{
    Addr as EthernetAddr, EthernetPayload, Frame as EthernetFrame, Protocol as EthernetProtocol,
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
        Cidr as Ipv4Cidr, FragInfo as Ipv4FragInfo, Ipv4Payload, Key as Ipv4Key,
        Packet as Ipv4Packet, HEADER_LEN as IPV4_HEADER_LEN,
    },
    v6::{
        Cidr as Ipv6Cidr, Ipv6AddrExt, Ipv6Payload, Packet as Ipv6Packet,
        HEADER_LEN as IPV6_HEADER_LEN, MIN_MTU as IPV6_MIN_MTU,
    },
    Cidr as IpCidr, IpAddrExt, IpCidrExt, Packet as IpPacket, Protocol as IpProtocol,
    Version as IpVersion,
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
