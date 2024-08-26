use core::{net::Ipv6Addr, time::Duration};

use bitflags::bitflags;
use byteorder::{ByteOrder, NetworkEndian};
use option::NdOption;

use super::{field, Message, Packet};
use crate::wire::{ip::IpAddrExt, prelude::*, Data, DataMut, RawHwAddr};

#[path = "v6_ndopt.rs"]
mod option;

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct RouterFlags: u8 {
        const MANAGED = 0b10000000;
        const OTHER   = 0b01000000;
    }
}

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct NeighborFlags: u8 {
        const ROUTER    = 0b10000000;
        const SOLICITED = 0b01000000;
        const OVERRIDE  = 0b00100000;
    }
}

wire!(impl Packet {
    current_hop_limit/set_current_hop_limit: u8 =>
        |data| data[field::CUR_HOP_LIMIT];
        |data, value| data[field::CUR_HOP_LIMIT] = value;

    router_flags/set_router_flags: RouterFlags =>
        |data| RouterFlags::from_bits_truncate(data[field::ROUTER_FLAGS]);
        |data, value| data[field::ROUTER_FLAGS] = value.bits();

    router_lifetime/set_router_lifetime: Duration =>
        |data| Duration::from_secs(u64::from(NetworkEndian::read_u16(&data[field::ROUTER_LT])));
        |data, value| NetworkEndian::write_u16(&mut data[field::ROUTER_LT], value.as_secs() as u16);

    reachable_time/set_reachable_time: Duration =>
        |data| Duration::from_millis(u64::from(NetworkEndian::read_u32(&data[field::REACHABLE_TM])));
        |data, value| NetworkEndian::write_u32(&mut data[field::REACHABLE_TM], value.as_millis() as u32);

    retrans_time/set_retrans_time: Duration =>
        |data| Duration::from_millis(u64::from(NetworkEndian::read_u32(&data[field::RETRANS_TM])));
        |data, value| NetworkEndian::write_u32(&mut data[field::RETRANS_TM], value.as_millis() as u32);

    // Type-specific:

    target_addr/set_target_addr: Ipv6Addr =>
        |data| Ipv6Addr::from_bytes(&data[field::TARGET_ADDR]);
        |data, value| data[field::TARGET_ADDR].copy_from_slice(&value.octets());


    neighbor_flags/set_neighbor_flags: NeighborFlags =>
        |data| NeighborFlags::from_bits_truncate(data[field::NEIGH_FLAGS]);
        |data, value| data[field::NEIGH_FLAGS] = value.bits();

    dest_addr/set_dest_addr: Ipv6Addr =>
        |data| Ipv6Addr::from_bytes(&data[field::DEST_ADDR]);
        |data, value| data[field::DEST_ADDR].copy_from_slice(&value.octets());
});

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Nd {
    RouterSolicit {
        lladdr: Option<RawHwAddr>,
    },
    RouterAdvert {
        hop_limit: u8,
        flags: RouterFlags,
        router_lifetime: Duration,
        reachable_time: Duration,
        retrans_time: Duration,
        lladdr: Option<RawHwAddr>,
        mtu: Option<u32>,
        prefix_info: Option<option::PrefixInfo>,
    },
    NeighborSolicit {
        target_addr: Ipv6Addr,
        lladdr: Option<RawHwAddr>,
    },
    NeighborAdvert {
        flags: NeighborFlags,
        target_addr: Ipv6Addr,
        lladdr: Option<RawHwAddr>,
    },
    Redirect {
        target_addr: Ipv6Addr,
        dest_addr: Ipv6Addr,
        lladdr: Option<RawHwAddr>,
    },
}

impl Nd {
    pub(super) fn len(&self) -> usize {
        match *self {
            Nd::RouterSolicit { lladdr } => match lladdr {
                Some(addr) => field::UNUSED.end + { NdOption::SrcLLAddr(addr).len() },
                None => field::UNUSED.end,
            },
            Nd::RouterAdvert { lladdr, mtu, prefix_info, .. } => {
                let mut offset = 0;
                if let Some(lladdr) = lladdr {
                    offset += NdOption::DstLLAddr(lladdr).len();
                }
                if let Some(mtu) = mtu {
                    offset += NdOption::Mtu(mtu).len();
                }
                if let Some(prefix_info) = prefix_info {
                    offset += NdOption::PrefixInfo(prefix_info).len();
                }
                field::RETRANS_TM.end + offset
            }
            Nd::NeighborSolicit { lladdr, .. } | Nd::NeighborAdvert { lladdr, .. } => {
                let mut offset = field::TARGET_ADDR.end;
                if let Some(lladdr) = lladdr {
                    offset += NdOption::SrcLLAddr(lladdr).len();
                }
                offset
            }
            Nd::Redirect { lladdr, .. } => {
                let mut offset = field::DEST_ADDR.end;
                if let Some(lladdr) = lladdr {
                    offset += NdOption::DstLLAddr(lladdr).len();
                }
                offset
            }
        }
    }

    pub(super) fn parse(packet: Packet<&[u8]>) -> Result<Self, ParseErrorKind> {
        let (mut src_ll_addr, mut mtu, mut prefix_info, mut target_ll_addr) =
            (None, None, None, None);

        let mut options = packet.data();
        while options.len() >= option::MIN_OPT_LEN {
            let (opt, rest) = NdOption::parse(options)?;

            // If an option doesn't parse, ignore it and still parse the others.
            match opt {
                NdOption::SrcLLAddr(addr) => src_ll_addr = Some(addr),
                NdOption::DstLLAddr(addr) => target_ll_addr = Some(addr),
                NdOption::PrefixInfo(prefix) => prefix_info = Some(prefix),
                NdOption::Mtu(m) => mtu = Some(m),
                _ => {}
            }

            options = rest;
        }

        match packet.msg_type() {
            Message::RouterSolicit => Ok(Nd::RouterSolicit { lladdr: src_ll_addr }),
            Message::RouterAdvert => Ok(Nd::RouterAdvert {
                hop_limit: packet.current_hop_limit(),
                flags: packet.router_flags(),
                router_lifetime: packet.router_lifetime(),
                reachable_time: packet.reachable_time(),
                retrans_time: packet.retrans_time(),
                lladdr: src_ll_addr,
                mtu,
                prefix_info,
            }),
            Message::NeighborSolicit => Ok(Nd::NeighborSolicit {
                target_addr: packet.target_addr(),
                lladdr: src_ll_addr,
            }),
            Message::NeighborAdvert => Ok(Nd::NeighborAdvert {
                flags: packet.neighbor_flags(),
                target_addr: packet.target_addr(),
                lladdr: target_ll_addr,
            }),
            Message::Redirect => Ok(Nd::Redirect {
                target_addr: packet.target_addr(),
                dest_addr: packet.dest_addr(),
                lladdr: src_ll_addr,
            }),
            _ => Err(ParseErrorKind::ProtocolUnknown),
        }
    }

    pub(super) fn build(self, mut packet: Packet<&mut [u8]>) {
        match self {
            Nd::RouterSolicit { lladdr } => {
                packet.set_msg_type(Message::RouterSolicit);
                packet.set_msg_code(0);
                packet.clear_reserved();
                if let Some(lladdr) = lladdr {
                    NdOption::SrcLLAddr(lladdr).build(packet.data_mut());
                }
            }

            Nd::RouterAdvert {
                hop_limit,
                flags,
                router_lifetime,
                reachable_time,
                retrans_time,
                lladdr,
                mtu,
                prefix_info,
            } => {
                packet.set_msg_type(Message::RouterAdvert);
                packet.set_msg_code(0);
                packet.set_current_hop_limit(hop_limit);
                packet.set_router_flags(flags);
                packet.set_router_lifetime(router_lifetime);
                packet.set_reachable_time(reachable_time);
                packet.set_retrans_time(retrans_time);
                let mut data = packet.data_mut();
                if let Some(lladdr) = lladdr {
                    data = NdOption::SrcLLAddr(lladdr).build(data);
                }
                if let Some(mtu) = mtu {
                    data = NdOption::Mtu(mtu).build(data);
                }
                if let Some(prefix_info) = prefix_info {
                    NdOption::PrefixInfo(prefix_info).build(data);
                }
            }

            Nd::NeighborSolicit { target_addr, lladdr } => {
                packet.set_msg_type(Message::NeighborSolicit);
                packet.set_msg_code(0);
                packet.clear_reserved();
                packet.set_target_addr(target_addr);
                if let Some(lladdr) = lladdr {
                    NdOption::SrcLLAddr(lladdr).build(packet.data_mut());
                }
            }

            Nd::NeighborAdvert { flags, target_addr, lladdr } => {
                packet.set_msg_type(Message::NeighborAdvert);
                packet.set_msg_code(0);
                packet.clear_reserved();
                packet.set_neighbor_flags(flags);
                packet.set_target_addr(target_addr);
                if let Some(lladdr) = lladdr {
                    NdOption::DstLLAddr(lladdr).build(packet.data_mut());
                }
            }

            Nd::Redirect { target_addr, dest_addr, lladdr } => {
                packet.set_msg_type(Message::Redirect);
                packet.set_msg_code(0);
                packet.clear_reserved();
                packet.set_target_addr(target_addr);
                packet.set_dest_addr(dest_addr);
                if let Some(lladdr) = lladdr {
                    NdOption::DstLLAddr(lladdr).build(packet.data_mut());
                }
            }
        }
    }
}
