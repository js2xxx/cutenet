use core::{fmt, net::Ipv6Addr, time::Duration};

use bitflags::bitflags;
use byteorder::{ByteOrder, NetworkEndian};

use crate::{ip::IpAddrExt, prelude::*, Data, DataMut, RawHwAddr, HWADDR_MAX_LEN};

enum_with_unknown! {
    /// NDISC Option Type
    pub enum Type(u8) {
        /// Source Link-layer Address
        SrcLLAddr  = 0x1,
        /// Target Link-layer Address
        DstLLAddr  = 0x2,
        /// Prefix Information
        PrefixInfo = 0x3,
        // /// Redirected Header
        // RedirectedHeader    = 0x4,
        /// MTU
        Mtu        = 0x5
    }
}

impl fmt::Display for Type {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Type::SrcLLAddr => write!(f, "source link-layer address"),
            Type::DstLLAddr => write!(f, "target link-layer address"),
            Type::PrefixInfo => write!(f, "prefix information"),
            // Type::RedirectedHeader => write!(f, "redirected header"),
            Type::Mtu => write!(f, "mtu"),
            Type::Unknown(id) => write!(f, "{id}"),
        }
    }
}

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct PrefixInfoFlags: u8 {
        const ON_LINK  = 0b10000000;
        const ADDRCONF = 0b01000000;
    }
}

struct RawOpt<T: ?Sized>(T);

// Format of an NDISC Option
//
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |     Type      |    Length     |              ...              |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// ~                              ...                              ~
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
// See https://tools.ietf.org/html/rfc4861#section-4.6 for details.
mod field {
    #![allow(non_snake_case)]

    use crate::field::*;

    // 8-bit identifier of the type of option.
    pub const TYPE: usize = 0;
    // 8-bit unsigned integer. Length of the option, in units of 8 octets.
    pub const LENGTH: usize = 1;
    // Variable-length field. Option-Type-specific data.
    pub const fn DATA(length: u8) -> Field {
        2..length as usize * 8
    }

    // Source/Target Link-layer Option fields.
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |     Type      |    Length     |    Link-Layer Address ...
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    // Prefix Information Option fields.
    //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //  |     Type      |    Length     | Prefix Length |L|A| Reserved1 |
    //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //  |                         Valid Lifetime                        |
    //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //  |                       Preferred Lifetime                      |
    //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //  |                           Reserved2                           |
    //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //  |                                                               |
    //  + +
    //  |                                                               |
    //  + Prefix                             +
    //  |                                                               |
    //  + +
    //  |                                                               |
    //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    // Prefix length.
    pub const PREFIX_LEN: usize = 2;
    // Flags field of prefix header.
    pub const FLAGS: usize = 3;
    // Valid lifetime.
    pub const VALID_LT: Field = 4..8;
    // Preferred lifetime.
    pub const PREF_LT: Field = 8..12;
    // Reserved bits
    pub const PREF_RESERVED: Field = 12..16;
    // Prefix
    pub const PREFIX: Field = 16..32;

    // MTU Option fields
    //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //  |     Type      |    Length     |           Reserved            |
    //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //  |                              MTU                              |
    //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    //  MTU
    pub const MTU: Field = 4..8;
}
// Minimum length of an option.
pub const MIN_OPT_LEN: usize = 8;

wire!(impl RawOpt {
    option_type/set_option_type: Type =>
        |data| Type::from(data[field::TYPE]);
        |data, value| data[field::TYPE] = value.into();

    data_len/set_data_len: u8 =>
        |data| data[field::LENGTH];
        |data, value| data[field::LENGTH] = value;

    // Type-specific:

    ll_addr/set_ll_addr: RawHwAddr =>
        @this |data| {
            let len = HWADDR_MAX_LEN.min(this.data_len() as usize * 8 - 2);
            RawHwAddr::from_bytes(&data[2..len + 2])
        };
        |data, value| data[2..2 + value.len()].copy_from_slice(value.as_bytes());

    mtu/set_mtu: u32 =>
        |data| NetworkEndian::read_u32(&data[field::MTU]);
        |data, value| NetworkEndian::write_u32(&mut data[field::MTU], value);

    prefix_len/set_prefix_len: u8 =>
        |data| data[field::PREFIX_LEN];
        |data, value| data[field::PREFIX_LEN] = value;

    prefix_flags/set_prefix_flags: PrefixInfoFlags =>
        |data| PrefixInfoFlags::from_bits_truncate(data[field::FLAGS]);
        |data, value| data[field::FLAGS] = value.bits();

    valid_lifetime/set_valid_lifetime: Duration =>
        |data| Duration::from_secs(u64::from(NetworkEndian::read_u32(&data[field::VALID_LT])));
        |data, value| NetworkEndian::write_u32(&mut data[field::VALID_LT], value.as_secs() as u32);

    preferred_lifetime/set_preferred_lifetime: Duration =>
        |data| Duration::from_secs(u64::from(NetworkEndian::read_u32(&data[field::PREF_LT])));
        |data, value| NetworkEndian::write_u32(&mut data[field::PREF_LT], value.as_secs() as u32);

    prefix/set_prefix: Ipv6Addr =>
        |data| Ipv6Addr::from_bytes(&data[field::PREFIX]);
        |data, value| data[field::PREFIX].copy_from_slice(&value.octets());
});

impl<T: DataMut + ?Sized> RawOpt<T> {
    fn clear_prefix_reserved(&mut self) {
        NetworkEndian::write_u32(&mut self.0.as_mut()[field::PREF_RESERVED], 0);
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct PrefixInfo {
    pub prefix_len: u8,
    pub flags: PrefixInfoFlags,
    pub valid_lifetime: Duration,
    pub preferred_lifetime: Duration,
    pub prefix: Ipv6Addr,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NdOption {
    SrcLLAddr(RawHwAddr),
    DstLLAddr(RawHwAddr),
    PrefixInfo(PrefixInfo),
    Mtu(u32),
    Unknown { id: u8, data_len: u8 },
}

impl NdOption {
    pub fn buffer_len(&self) -> usize {
        match self {
            NdOption::SrcLLAddr(addr) | NdOption::DstLLAddr(addr) => {
                let len = 2 + addr.len(); // Round up to next multiple of 8
                len.next_multiple_of(8)
            }
            NdOption::PrefixInfo(_) => field::PREFIX.end,
            NdOption::Mtu(_) => field::MTU.end,
            &NdOption::Unknown { data_len, .. } => field::DATA(data_len).end,
        }
    }

    pub fn parse(data: &[u8]) -> Result<(Self, &[u8]), ParseErrorKind> {
        let len = data.len();
        let packet = RawOpt(data);

        if len < MIN_OPT_LEN {
            return Err(ParseErrorKind::PacketTooShort);
        }

        let data_range = field::DATA(data[field::LENGTH]);
        if len < data_range.end {
            return Err(ParseErrorKind::PacketTooShort);
        } else {
            match packet.option_type() {
                Type::SrcLLAddr | Type::DstLLAddr | Type::Mtu => {}
                Type::PrefixInfo if data_range.end >= field::PREFIX.end => {}
                Type::Unknown(_) => {}
                _ => return Err(ParseErrorKind::FormatInvalid),
            }
        }

        let data_len = packet.data_len();
        let opt = match packet.option_type() {
            Type::SrcLLAddr if data_len >= 1 => NdOption::SrcLLAddr(packet.ll_addr()),
            Type::SrcLLAddr => return Err(ParseErrorKind::FormatInvalid),

            Type::DstLLAddr if data_len >= 1 => NdOption::DstLLAddr(packet.ll_addr()),
            Type::DstLLAddr => return Err(ParseErrorKind::FormatInvalid),

            Type::PrefixInfo if data_len == 4 => NdOption::PrefixInfo(PrefixInfo {
                prefix_len: packet.prefix_len(),
                flags: packet.prefix_flags(),
                valid_lifetime: packet.valid_lifetime(),
                preferred_lifetime: packet.preferred_lifetime(),
                prefix: packet.prefix(),
            }),
            Type::PrefixInfo => return Err(ParseErrorKind::FormatInvalid),

            Type::Mtu if data_len == 1 => NdOption::Mtu(packet.mtu()),
            Type::Mtu => return Err(ParseErrorKind::FormatInvalid),

            // A length of 0 is invalid.
            Type::Unknown(id) if data_len != 0 => NdOption::Unknown { id, data_len },
            Type::Unknown(_id) => return Err(ParseErrorKind::FormatInvalid),
        };
        Ok((opt, &data[usize::from(data_len * 8)..]))
    }

    pub fn build(self, data: &mut [u8]) -> &mut [u8] {
        let len = self.buffer_len();

        let mut opt = RawOpt(data);
        opt.set_data_len((len / 8) as u8);
        match self {
            NdOption::SrcLLAddr(addr) => {
                opt.set_option_type(Type::SrcLLAddr);
                opt.set_ll_addr(addr);
            }
            NdOption::DstLLAddr(addr) => {
                opt.set_option_type(Type::DstLLAddr);
                opt.set_ll_addr(addr);
            }
            NdOption::PrefixInfo(PrefixInfo {
                prefix_len,
                flags,
                valid_lifetime,
                preferred_lifetime,
                prefix,
            }) => {
                opt.clear_prefix_reserved();
                opt.set_option_type(Type::PrefixInfo);
                opt.set_prefix_len(prefix_len);
                opt.set_prefix_flags(flags);
                opt.set_valid_lifetime(valid_lifetime);
                opt.set_preferred_lifetime(preferred_lifetime);
                opt.set_prefix(prefix);
            }
            NdOption::Mtu(mtu) => {
                opt.set_option_type(Type::Mtu);
                opt.set_mtu(mtu);
            }
            NdOption::Unknown { id, .. } => {
                opt.set_option_type(Type::Unknown(id));
            }
        }
        &mut opt.0[len..]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ethernet, ieee802154};

    static PREFIX_OPT_BYTES: [u8; 32] = [
        0x03, 0x04, 0x40, 0xc0, 0x00, 0x00, 0x03, 0x84, 0x00, 0x00, 0x03, 0xe8, 0x00, 0x00, 0x00,
        0x00, 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x01,
    ];

    #[test]
    fn test_deconstruct() {
        let (opt, rest) = NdOption::parse(&PREFIX_OPT_BYTES[..]).unwrap();
        assert_eq!(
            opt,
            NdOption::PrefixInfo(PrefixInfo {
                prefix_len: 64,
                flags: PrefixInfoFlags::ON_LINK | PrefixInfoFlags::ADDRCONF,
                valid_lifetime: Duration::from_secs(900),
                preferred_lifetime: Duration::from_secs(1000),
                prefix: Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1),
            })
        );
        assert_eq!(rest, &[]);
    }

    #[test]
    fn test_short_packet() {
        assert_eq!(
            NdOption::parse(&[0x00, 0x00]).unwrap_err(),
            ParseErrorKind::PacketTooShort,
        );
        let bytes = [0x03, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        assert_eq!(
            NdOption::parse(&bytes).unwrap_err(),
            ParseErrorKind::FormatInvalid,
        );
    }

    #[test]
    fn test_repr_parse_link_layer_opt_ethernet() {
        let mut bytes = [0x01, 0x01, 0x54, 0x52, 0x00, 0x12, 0x23, 0x34];
        let addr = ethernet::Addr([0x54, 0x52, 0x00, 0x12, 0x23, 0x34]);
        {
            assert_eq!(
                NdOption::parse(&bytes),
                Ok((NdOption::SrcLLAddr(addr.into()), &[][..]))
            );
        }
        bytes[0] = 0x02;
        {
            assert_eq!(
                NdOption::parse(&bytes),
                Ok((NdOption::DstLLAddr(addr.into()), &[][..]))
            );
        }
    }

    #[test]
    fn test_repr_parse_link_layer_opt_ieee802154() {
        let mut bytes = [
            0x01, 0x02, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00,
        ];
        let addr = ieee802154::Addr::Extended([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
        {
            assert_eq!(
                NdOption::parse(&bytes),
                Ok((NdOption::SrcLLAddr(addr.into()), &[][..]))
            );
        }
        bytes[0] = 0x02;
        {
            assert_eq!(
                NdOption::parse(&bytes),
                Ok((NdOption::DstLLAddr(addr.into()), &[][..]))
            );
        }
    }

    #[test]
    fn test_repr_parse_prefix_info() {
        let repr = NdOption::PrefixInfo(PrefixInfo {
            prefix_len: 64,
            flags: PrefixInfoFlags::ON_LINK | PrefixInfoFlags::ADDRCONF,
            valid_lifetime: Duration::from_secs(900),
            preferred_lifetime: Duration::from_secs(1000),
            prefix: Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1),
        });
        assert_eq!(NdOption::parse(&PREFIX_OPT_BYTES), Ok((repr, &[][..])));
    }

    #[test]
    fn test_repr_emit_prefix_info() {
        let mut bytes = [0x2a; 32];
        let repr = NdOption::PrefixInfo(PrefixInfo {
            prefix_len: 64,
            flags: PrefixInfoFlags::ON_LINK | PrefixInfoFlags::ADDRCONF,
            valid_lifetime: Duration::from_secs(900),
            preferred_lifetime: Duration::from_secs(1000),
            prefix: Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1),
        });
        let rest = repr.build(&mut bytes);
        assert_eq!(rest, &[]);
        assert_eq!(bytes, &PREFIX_OPT_BYTES[..]);
    }

    #[test]
    fn test_repr_parse_mtu() {
        let bytes = [0x05, 0x01, 0x00, 0x00, 0x00, 0x00, 0x05, 0xdc];
        assert_eq!(NdOption::parse(&bytes), Ok((NdOption::Mtu(1500), &[][..])));
    }
}
