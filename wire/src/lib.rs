#![no_std]
#![feature(ip)]
#![feature(let_chains)]
#![feature(macro_metavar_expr)]
#![feature(trait_upcasting)]

#[cfg(test)]
extern crate std;

#[macro_use]
mod macros;

use cutenet_storage::{NoPayload, Payload, PayloadBuild};

mod context;
pub use self::context::{Ends, WireCx};

mod traits;
pub use self::traits::{ReserveExt, Wire, WireBuild, WireParse, WireSubNoPayload, WireSubstitute};

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
        hbh::Header as Ipv6HopByHopHeader,
        option::{
            FailureType as Ipv6OptFailureType, Opt as Ipv6Opt, RouterAlert as Ipv6OptRouterAlert,
            Type as Ipv6OptType,
        },
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
    pub use cutenet_storage::{NoPayload, Payload, PayloadBuild, PayloadParse};

    pub use super::{error::*, traits::*, Lax};
}

bitflags::bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
    pub struct Checksums: u8 {
        const IP = 1 << 0;
        const UDP = 1 << 1;
        const TCP = 1 << 2;
        const ICMP = 1 << 3;
    }
}

impl Checksums {
    pub const fn new() -> Self {
        Checksums::all()
    }

    pub const fn ip(&self) -> bool {
        self.contains(Checksums::IP)
    }

    pub const fn udp(&self) -> bool {
        self.contains(Checksums::UDP)
    }

    pub const fn tcp(&self) -> bool {
        self.contains(Checksums::TCP)
    }

    pub const fn icmp(&self) -> bool {
        self.contains(Checksums::ICMP)
    }

    pub const IGNORE: Self = Checksums::empty();
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, cutenet_macros::Wire)]
#[prefix(crate)]
pub struct Lax<#[wire] T>(#[wire] pub T);

impl<T: WireBuild<Payload = P>, P: PayloadBuild> WireBuild for Lax<T> {
    fn buffer_len(&self) -> usize {
        self.0.buffer_len()
    }

    fn build(self, cx: &dyn WireCx) -> Result<P, BuildError<P>> {
        self.0.build(cx)
    }
}
