use core::fmt;

use byteorder::{ByteOrder, NetworkEndian};

use crate::{prelude::*, Data, DataMut};

enum_with_unknown! {
    /// IPv6 Extension Header Option Type
    pub enum Type(u8) {
        /// 1 byte of padding
        Pad1 = 0,
        /// Multiple bytes of padding
        PadN = 1,
        /// Router Alert
        RouterAlert = 5,
        /// RPL Option
        Rpl  = 0x63,
    }
}

impl fmt::Display for Type {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Type::Pad1 => write!(f, "Pad1"),
            Type::PadN => write!(f, "PadN"),
            Type::Rpl => write!(f, "RPL"),
            Type::RouterAlert => write!(f, "RouterAlert"),
            Type::Unknown(id) => write!(f, "{id}"),
        }
    }
}

enum_with_unknown! {
    /// A high-level representation of an IPv6 Router Alert Header Option.
    ///
    /// Router Alert options always contain exactly one `u16`; see [RFC 2711 § 2.1].
    ///
    /// [RFC 2711 § 2.1]: https://tools.ietf.org/html/rfc2711#section-2.1
    pub enum RouterAlert(u16) {
        MulticastListenerDiscovery = 0,
        Rsvp = 1,
        ActiveNetworks = 2,
    }
}

impl RouterAlert {
    /// Per [RFC 2711 § 2.1], Router Alert options always have 2 bytes of data.
    ///
    /// [RFC 2711 § 2.1]: https://tools.ietf.org/html/rfc2711#section-2.1
    pub const DATA_LEN: u8 = 2;
}

enum_with_unknown! {
    /// Action required when parsing the given IPv6 Extension
    /// Header Option Type fails
    pub enum FailureType(u8) {
        /// Skip this option and continue processing the packet
        Skip               = 0b00000000,
        /// Discard the containing packet
        Discard            = 0b01000000,
        /// Discard the containing packet and notify the sender
        DiscardSendAll     = 0b10000000,
        /// Discard the containing packet and only notify the sender
        /// if the sender is a unicast address
        DiscardSendUnicast = 0b11000000,
    }
}

impl fmt::Display for FailureType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            FailureType::Skip => write!(f, "skip"),
            FailureType::Discard => write!(f, "discard"),
            FailureType::DiscardSendAll => write!(f, "discard and send error"),
            FailureType::DiscardSendUnicast => write!(f, "discard and send error if unicast"),
            FailureType::Unknown(id) => write!(f, "Unknown({id})"),
        }
    }
}

impl From<Type> for FailureType {
    fn from(other: Type) -> FailureType {
        let raw: u8 = other.into();
        Self::from(raw & 0b11000000u8)
    }
}

struct RawOpt<T: ?Sized>(T);

// Format of Option
//
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+- - - - - - - - -
// |  Option Type  |  Opt Data Len |  Option Data
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+- - - - - - - - -
//
//
// See https://tools.ietf.org/html/rfc8200#section-4.2 for details.
mod field {
    #![allow(non_snake_case)]

    use crate::field::*;

    // 8-bit identifier of the type of option.
    pub const TYPE: usize = 0;
    // 8-bit unsigned integer. Length of the DATA field of this option, in octets.
    pub const LENGTH: usize = 1;
    // Variable-length field. Option-Type-specific data.
    pub const fn DATA(length: u8) -> Field {
        2..length as usize + 2
    }

    pub const ROUTER_ALERT: Field = DATA(super::RouterAlert::DATA_LEN);
}

wire!(impl RawOpt {
    option_type/set_option_type: Type =>
        |data| Type::from(data[field::TYPE]);
        |data, value| data[field::TYPE] = value.into();

    data_len/set_data_len: u8 =>
        |data| data[field::LENGTH];
        |data, value| data[field::LENGTH] = value;

        // Type-specific:
    router_alert/set_router_alert: RouterAlert =>
        |data| RouterAlert::from(NetworkEndian::read_u16(&data[field::ROUTER_ALERT]));
        |data, value| NetworkEndian::write_u16(&mut data[field::ROUTER_ALERT], value.into());
});

impl<T: ?Sized + DataMut> RawOpt<T> {
    fn data_mut(&mut self) -> &mut [u8] {
        let index = field::DATA(self.data_len());
        &mut self.0.as_mut()[index]
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[non_exhaustive]
pub enum Opt {
    Pad1,
    PadN(u8),
    RouterAlert(RouterAlert),
    Unknown { option_type: Type, data_len: u8 },
}

impl Opt {
    pub const fn buffer_len(&self) -> usize {
        match *self {
            Opt::Pad1 => 1,
            Opt::PadN(length) => field::DATA(length).end,
            Opt::RouterAlert(_) => field::DATA(RouterAlert::DATA_LEN).end,
            Opt::Unknown { data_len, .. } => field::DATA(data_len).end,
        }
    }

    pub fn parse(data: &[u8]) -> Result<(Self, &[u8]), ParseErrorKind> {
        let len = data.len();
        let raw = RawOpt(data);

        if len < field::LENGTH {
            return Err(ParseErrorKind::PacketTooShort);
        }

        if raw.option_type() == Type::Pad1 {
            return Ok((Opt::Pad1, &data[1..]));
        }

        if len == field::LENGTH {
            return Err(ParseErrorKind::PacketTooShort);
        }

        let data_len = raw.data_len();
        let data_range = field::DATA(data_len);
        if len < data_range.end {
            return Err(ParseErrorKind::PacketTooShort);
        }

        match raw.option_type() {
            Type::Pad1 => unreachable!(),
            Type::PadN => Ok((Opt::PadN(data_len), &data[data_range.end..])),
            Type::RouterAlert if data_len == RouterAlert::DATA_LEN => Ok((
                Opt::RouterAlert(raw.router_alert()),
                &data[data_range.end..],
            )),
            Type::RouterAlert => Err(ParseErrorKind::FormatInvalid),
            Type::Rpl => Ok((
                Opt::Unknown { option_type: Type::Rpl, data_len },
                &data[data_range.end..],
            )),
            Type::Unknown(ty) => Ok((
                Opt::Unknown {
                    option_type: Type::Unknown(ty),
                    data_len,
                },
                &data[data_range.end..],
            )),
        }
    }

    pub fn build(self, data: &mut [u8]) -> &mut [u8] {
        let len = self.buffer_len();

        let mut raw = RawOpt(&mut *data);
        match self {
            Opt::Pad1 => {
                raw.set_option_type(Type::Pad1);
            }
            Opt::PadN(n) => {
                raw.set_option_type(Type::PadN);
                raw.set_data_len(n);
                raw.data_mut().fill(0);
            }
            Opt::RouterAlert(ra) => {
                raw.set_option_type(Type::RouterAlert);
                raw.set_data_len(RouterAlert::DATA_LEN);
                raw.set_router_alert(ra);
            }
            Opt::Unknown { option_type, data_len } => {
                raw.set_option_type(option_type);
                raw.set_data_len(data_len);
                raw.data_mut().fill(0);
            }
        }
        &mut data[len..]
    }
}

#[cfg(test)]
mod test {
    use super::*;

    static IPV6OPTION_BYTES_PAD1: [u8; 1] = [0x0];
    static IPV6OPTION_BYTES_PADN: [u8; 3] = [0x1, 0x1, 0x0];
    static IPV6OPTION_BYTES_UNKNOWN: [u8; 5] = [0xff, 0x3, 0x0, 0x0, 0x0];
    static IPV6OPTION_BYTES_ROUTER_ALERT_MLD: [u8; 4] = [0x05, 0x02, 0x00, 0x00];
    static IPV6OPTION_BYTES_ROUTER_ALERT_RSVP: [u8; 4] = [0x05, 0x02, 0x00, 0x01];
    static IPV6OPTION_BYTES_ROUTER_ALERT_ACTIVE_NETWORKS: [u8; 4] = [0x05, 0x02, 0x00, 0x02];
    static IPV6OPTION_BYTES_ROUTER_ALERT_UNKNOWN: [u8; 4] = [0x05, 0x02, 0xbe, 0xef];

    #[test]
    fn test_check_len() {
        let bytes = [];
        // zero byte buffer
        assert_eq!(Err(ParseErrorKind::PacketTooShort), Opt::parse(&bytes));
    }

    #[test]
    fn test_option_deconstruct() {
        // one octet of padding
        let (opt, _) = Opt::parse(&IPV6OPTION_BYTES_PAD1).unwrap();
        assert_eq!(opt, Opt::Pad1);
        assert_eq!(opt.buffer_len(), 1);

        // two or more octets of padding
        let (opt, _) = Opt::parse(&IPV6OPTION_BYTES_PADN).unwrap();
        assert_eq!(opt, Opt::PadN(1));
        assert_eq!(opt.buffer_len(), 3);

        // router alert (MLD)
        let (opt, _) = Opt::parse(&IPV6OPTION_BYTES_ROUTER_ALERT_MLD).unwrap();
        assert_eq!(
            opt,
            Opt::RouterAlert(RouterAlert::MulticastListenerDiscovery)
        );
        assert_eq!(opt.buffer_len(), 4);

        // router alert (RSVP)
        let (opt, _) = Opt::parse(&IPV6OPTION_BYTES_ROUTER_ALERT_RSVP).unwrap();
        assert_eq!(opt, Opt::RouterAlert(RouterAlert::Rsvp));
        assert_eq!(opt.buffer_len(), 4);

        // router alert (active networks)
        let (opt, _) = Opt::parse(&IPV6OPTION_BYTES_ROUTER_ALERT_ACTIVE_NETWORKS).unwrap();
        assert_eq!(opt, Opt::RouterAlert(RouterAlert::ActiveNetworks));
        assert_eq!(opt.buffer_len(), 4);

        // router alert (unknown)
        let (opt, _) = Opt::parse(&IPV6OPTION_BYTES_ROUTER_ALERT_UNKNOWN).unwrap();
        assert_eq!(opt, Opt::RouterAlert(RouterAlert::Unknown(0xbeef)));
        assert_eq!(opt.buffer_len(), 4);

        // router alert (incorrect data length)
        let res = Opt::parse(&[0x05, 0x03, 0x00, 0x00, 0x00]);
        assert_eq!(res, Err(ParseErrorKind::FormatInvalid));

        // unrecognized option type
        let (opt, _) = Opt::parse(&IPV6OPTION_BYTES_UNKNOWN).unwrap();
        assert_eq!(opt, Opt::Unknown {
            option_type: Type::Unknown(255),
            data_len: 3,
        });
    }

    #[test]
    fn test_option_emit() {
        let repr = Opt::Pad1;
        let mut bytes = [255u8; 1]; // don't assume bytes are initialized to zero
        repr.build(&mut bytes);
        assert_eq!(&bytes, &IPV6OPTION_BYTES_PAD1);

        let repr = Opt::PadN(1);
        let mut bytes = [255u8; 3]; // don't assume bytes are initialized to zero
        repr.build(&mut bytes);
        assert_eq!(&bytes, &IPV6OPTION_BYTES_PADN);

        let repr = Opt::RouterAlert(RouterAlert::MulticastListenerDiscovery);
        let mut bytes = [255u8; 4]; // don't assume bytes are initialized to zero
        repr.build(&mut bytes);
        assert_eq!(&bytes, &IPV6OPTION_BYTES_ROUTER_ALERT_MLD);

        let repr = Opt::Unknown {
            option_type: Type::Unknown(255),
            data_len: 3,
        };
        let mut bytes = [254u8; 5]; // don't assume bytes are initialized to zero
        repr.build(&mut bytes);
        assert_eq!(&bytes, &IPV6OPTION_BYTES_UNKNOWN);
    }

    #[test]
    fn test_failure_type() {
        let mut failure_type: FailureType = Type::Pad1.into();
        assert_eq!(failure_type, FailureType::Skip);
        failure_type = Type::PadN.into();
        assert_eq!(failure_type, FailureType::Skip);
        failure_type = Type::RouterAlert.into();
        assert_eq!(failure_type, FailureType::Skip);
        failure_type = Type::Unknown(0b01000001).into();
        assert_eq!(failure_type, FailureType::Discard);
        failure_type = Type::Unknown(0b10100000).into();
        assert_eq!(failure_type, FailureType::DiscardSendAll);
        failure_type = Type::Unknown(0b11000100).into();
        assert_eq!(failure_type, FailureType::DiscardSendUnicast);
    }
}
