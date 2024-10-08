use core::fmt;

use byteorder::{ByteOrder, NetworkEndian};
use cutenet_storage::PushOption;

use crate::{context::WireCx, ip::checksum, prelude::*, Ipv4Packet};

enum_with_unknown! {
    /// Internet protocol control message type.
    pub enum Message(u8) {
        /// Echo reply
        EchoReply      =  0,
        /// Destination unreachable
        DstUnreachable =  3,
        /// Message redirect
        Redirect       =  5,
        /// Echo request
        EchoRequest    =  8,
        /// Router advertisement
        RouterAdvert   =  9,
        /// Router solicitation
        RouterSolicit  = 10,
        /// Time exceeded
        TimeExceeded   = 11,
        /// Parameter problem
        ParamProblem   = 12,
        /// Timestamp
        Timestamp      = 13,
        /// Timestamp reply
        TimestampReply = 14
    }
}

impl fmt::Display for Message {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Message::EchoReply => write!(f, "echo reply"),
            Message::DstUnreachable => write!(f, "destination unreachable"),
            Message::Redirect => write!(f, "message redirect"),
            Message::EchoRequest => write!(f, "echo request"),
            Message::RouterAdvert => write!(f, "router advertisement"),
            Message::RouterSolicit => write!(f, "router solicitation"),
            Message::TimeExceeded => write!(f, "time exceeded"),
            Message::ParamProblem => write!(f, "parameter problem"),
            Message::Timestamp => write!(f, "timestamp"),
            Message::TimestampReply => write!(f, "timestamp reply"),
            Message::Unknown(id) => write!(f, "{id}"),
        }
    }
}

enum_with_unknown! {
    /// Internet protocol control message subtype for type "Destination Unreachable".
    pub enum DstUnreachable(u8) {
        /// Destination network unreachable
        NetUnreachable   =  0,
        /// Destination host unreachable
        HostUnreachable  =  1,
        /// Destination protocol unreachable
        ProtoUnreachable =  2,
        /// Destination port unreachable
        PortUnreachable  =  3,
        /// Fragmentation required, and DF flag set
        FragRequired     =  4,
        /// Source route failed
        SrcRouteFailed   =  5,
        /// Destination network unknown
        DstNetUnknown    =  6,
        /// Destination host unknown
        DstHostUnknown   =  7,
        /// Source host isolated
        SrcHostIsolated  =  8,
        /// Network administratively prohibited
        NetProhibited    =  9,
        /// Host administratively prohibited
        HostProhibited   = 10,
        /// Network unreachable for ToS
        NetUnreachToS    = 11,
        /// Host unreachable for ToS
        HostUnreachToS   = 12,
        /// Communication administratively prohibited
        CommProhibited   = 13,
        /// Host precedence violation
        HostPrecedViol   = 14,
        /// Precedence cutoff in effect
        PrecedCutoff     = 15
    }
}

impl fmt::Display for DstUnreachable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            DstUnreachable::NetUnreachable => write!(f, "destination network unreachable"),
            DstUnreachable::HostUnreachable => write!(f, "destination host unreachable"),
            DstUnreachable::ProtoUnreachable => write!(f, "destination protocol unreachable"),
            DstUnreachable::PortUnreachable => write!(f, "destination port unreachable"),
            DstUnreachable::FragRequired => write!(f, "fragmentation required, and DF flag set"),
            DstUnreachable::SrcRouteFailed => write!(f, "source route failed"),
            DstUnreachable::DstNetUnknown => write!(f, "destination network unknown"),
            DstUnreachable::DstHostUnknown => write!(f, "destination host unknown"),
            DstUnreachable::SrcHostIsolated => write!(f, "source host isolated"),
            DstUnreachable::NetProhibited => write!(f, "network administratively prohibited"),
            DstUnreachable::HostProhibited => write!(f, "host administratively prohibited"),
            DstUnreachable::NetUnreachToS => write!(f, "network unreachable for ToS"),
            DstUnreachable::HostUnreachToS => write!(f, "host unreachable for ToS"),
            DstUnreachable::CommProhibited => {
                write!(f, "communication administratively prohibited")
            }
            DstUnreachable::HostPrecedViol => write!(f, "host precedence violation"),
            DstUnreachable::PrecedCutoff => write!(f, "precedence cutoff in effect"),
            DstUnreachable::Unknown(id) => write!(f, "{id}"),
        }
    }
}

enum_with_unknown! {
    /// Internet protocol control message subtype for type "Redirect Message".
    pub enum Redirect(u8) {
        /// Redirect Datagram for the Network
        Net     = 0,
        /// Redirect Datagram for the Host
        Host    = 1,
        /// Redirect Datagram for the ToS & network
        NetToS  = 2,
        /// Redirect Datagram for the ToS & host
        HostToS = 3
    }
}

enum_with_unknown! {
    /// Internet protocol control message subtype for type "Time Exceeded".
    pub enum TimeExceeded(u8) {
        /// TTL expired in transit
        TtlExpired  = 0,
        /// Fragment reassembly time exceeded
        FragExpired = 1
    }
}

impl fmt::Display for TimeExceeded {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            TimeExceeded::TtlExpired => write!(f, "time-to-live exceeded in transit"),
            TimeExceeded::FragExpired => write!(f, "fragment reassembly time exceeded"),
            TimeExceeded::Unknown(id) => write!(f, "{id}"),
        }
    }
}

enum_with_unknown! {
    /// Internet protocol control message subtype for type "Parameter Problem".
    pub enum ParamProblem(u8) {
        /// Pointer indicates the error
        AtPointer     = 0,
        /// Missing a required option
        MissingOption = 1,
        /// Bad length
        BadLength     = 2
    }
}

struct RawPacket<T: ?Sized>(T);

mod field {
    use crate::field::*;

    pub const TYPE: usize = 0;
    pub const CODE: usize = 1;
    pub const CHECKSUM: Field = 2..4;

    pub const UNUSED: Field = 4..8;

    pub const ECHO_IDENT: Field = 4..6;
    pub const ECHO_SEQNO: Field = 6..8;

    pub const HEADER_END: usize = 8;
}

wire!(impl RawPacket {
    /// Return the message type field.
    msg_type/set_msg_type: Message =>
        |data| Message::from(data[field::TYPE]);
        |data, value| data[field::TYPE] = value.into();

    /// Return the message code field.
    msg_code/set_msg_code: u8 =>
        |data| data[field::CODE];
        |data, value| data[field::CODE] = value;

    /// Return the checksum field.
    #[allow(unused)]
    checksum/set_checksum: u16 =>
        |data| NetworkEndian::read_u16(&data[field::CHECKSUM]);
        |data, value| NetworkEndian::write_u16(&mut data[field::CHECKSUM], value);

    /// Return the identifier field (for echo request and reply packets).
    ///
    /// # Panics
    ///
    /// This function may panic if this packet is not an echo request or reply
    /// packet.
    echo_ident/set_echo_ident: u16 =>
        |data| NetworkEndian::read_u16(&data[field::ECHO_IDENT]);
        |data, value| NetworkEndian::write_u16(&mut data[field::ECHO_IDENT], value);

    /// Return the sequence number field (for echo request and reply packets).
    ///
    /// # Panics
    ///
    /// This function may panic if this packet is not an echo request or reply
    /// packet.
    echo_seq_no/set_echo_seq_no: u16 =>
        |data| NetworkEndian::read_u16(&data[field::ECHO_SEQNO]);
        |data, value| NetworkEndian::write_u16(&mut data[field::ECHO_SEQNO], value);
});

impl<T: AsRef<[u8]> + ?Sized> RawPacket<T> {
    /// Validate the header checksum.
    pub fn verify_checksum<'a>(&self, next_iter: impl Iterator<Item = &'a [u8]>) -> bool {
        checksum::data_iter(self.0.as_ref(), next_iter).0 == !0
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]> + ?Sized> RawPacket<T> {
    pub fn fill_checksum<'a>(&mut self, next_iter: impl Iterator<Item = &'a [u8]>) {
        self.set_checksum(0);
        let checksum = !checksum::data_iter(self.0.as_ref(), next_iter).0;
        self.set_checksum(checksum)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Wire)]
#[prefix(crate)]
#[non_exhaustive]
pub enum Packet<#[wire] T> {
    EchoRequest {
        ident: u16,
        seq_no: u16,
        #[wire]
        payload: T,
    },
    EchoReply {
        ident: u16,
        seq_no: u16,
        #[wire]
        payload: T,
    },
    DstUnreachable {
        reason: DstUnreachable,
        #[wire]
        payload: Lax<Ipv4Packet<T>>,
    },
    TimeExceeded {
        reason: TimeExceeded,
        #[wire]
        payload: Lax<Ipv4Packet<T>>,
    },
}

impl<P: PayloadParse, T: WireParse<Payload = P>> WireParse for Packet<T> {
    fn parse(cx: &dyn WireCx, raw: P) -> Result<Self, ParseError<P>> {
        let packet = RawPacket(raw.header_data());

        let len = packet.0.len();
        if len < field::HEADER_END {
            return Err(ParseErrorKind::PacketTooShort.with(raw));
        }

        if cx.checksums().icmp() && !packet.verify_checksum(raw.next_data_iter()) {
            return Err(ParseErrorKind::ChecksumInvalid.with(raw));
        }

        let map_err = |err| ParseErrorKind::PacketTooShort.with(err);
        match (packet.msg_type(), packet.msg_code()) {
            (Message::EchoRequest, 0) => Ok(Packet::EchoRequest {
                ident: packet.echo_ident(),
                seq_no: packet.echo_seq_no(),
                payload: T::parse(cx, raw.pop(field::ECHO_SEQNO.end..len).map_err(map_err)?)?,
            }),

            (Message::EchoReply, 0) => Ok(Packet::EchoReply {
                ident: packet.echo_ident(),
                seq_no: packet.echo_seq_no(),
                payload: T::parse(cx, raw.pop(field::ECHO_SEQNO.end..len).map_err(map_err)?)?,
            }),

            (Message::DstUnreachable, code) => Ok(Packet::DstUnreachable {
                reason: DstUnreachable::from(code),
                payload: Lax::parse(cx, raw.pop(field::UNUSED.end..len).map_err(map_err)?)?,
            }),

            (Message::TimeExceeded, code) => Ok(Packet::TimeExceeded {
                reason: TimeExceeded::from(code),
                payload: Lax::parse(cx, raw.pop(field::UNUSED.end..len).map_err(map_err)?)?,
            }),

            _ => Err(ParseErrorKind::ProtocolUnknown.with(raw)),
        }
    }
}

impl<P: PayloadBuild, T: WireBuild<Payload = P>> WireBuild for Packet<T> {
    fn buffer_len(&self) -> usize {
        match self {
            Packet::EchoRequest { payload, .. } | Packet::EchoReply { payload, .. } => {
                field::ECHO_SEQNO.end + payload.buffer_len()
            }
            Packet::DstUnreachable { payload, .. } | Packet::TimeExceeded { payload, .. } => {
                field::UNUSED.end + payload.buffer_len()
            }
        }
    }

    fn build(self, cx: &dyn WireCx) -> Result<P, BuildError<P>> {
        fn checksum<'a>(
            mut packet: RawPacket<&mut [u8]>,
            next_iter: impl Iterator<Item = &'a [u8]>,
            cx: &dyn WireCx,
        ) -> Result<(), BuildErrorKind> {
            if cx.checksums().icmp() {
                packet.fill_checksum(next_iter);
            } else {
                // make sure we get a consistently zeroed checksum,
                // since implementations might rely on it
                packet.set_checksum(0);
            }
            Ok(())
        }

        let opt = PushOption::new().truncate(usize::MAX);
        match self {
            Packet::EchoRequest { ident, seq_no, payload } => {
                payload.build(cx)?.push(field::ECHO_SEQNO.end, |buf, iter| {
                    let mut packet = RawPacket(buf);

                    packet.set_msg_type(Message::EchoRequest);
                    packet.set_msg_code(0);
                    packet.set_echo_ident(ident);
                    packet.set_echo_seq_no(seq_no);

                    checksum(packet, iter, cx)
                })
            }
            Packet::EchoReply { ident, seq_no, payload } => {
                payload.build(cx)?.push(field::ECHO_SEQNO.end, |buf, iter| {
                    let mut packet = RawPacket(buf);

                    packet.set_msg_type(Message::EchoReply);
                    packet.set_msg_code(0);
                    packet.set_echo_ident(ident);
                    packet.set_echo_seq_no(seq_no);

                    checksum(packet, iter, cx)
                })
            }
            Packet::DstUnreachable { reason, payload } => {
                (payload.build(&())?).push_with(field::UNUSED.end, &opt, |buf, iter| {
                    let mut packet = RawPacket(buf);

                    packet.set_msg_type(Message::DstUnreachable);
                    packet.set_msg_code(reason.into());

                    checksum(packet, iter, cx)
                })
            }
            Packet::TimeExceeded { reason, payload } => {
                (payload.build(&())?).push_with(field::UNUSED.end, &opt, |buf, iter| {
                    let mut packet = RawPacket(buf);

                    packet.set_msg_type(Message::TimeExceeded);
                    packet.set_msg_code(reason.into());

                    checksum(packet, iter, cx)
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::vec::Vec;

    use super::*;
    use crate::Checksums;

    static ECHO_PACKET_BYTES: [u8; 12] = [
        0x08, 0x00, 0x8e, 0xfe, 0x12, 0x34, 0xab, 0xcd, 0xaa, 0x00, 0x00, 0xff,
    ];

    static ECHO_DATA_BYTES: [u8; 4] = [0xaa, 0x00, 0x00, 0xff];

    const CX: (Checksums,) = (Checksums::new(),);

    #[test]
    fn test_echo_deconstruct() {
        let packet: Packet<&[u8]> = Packet::parse(&CX, &ECHO_PACKET_BYTES[..]).unwrap();
        assert_eq!(packet, Packet::EchoRequest {
            ident: 0x1234,
            seq_no: 0xabcd,
            payload: &ECHO_DATA_BYTES[..]
        });
    }

    #[test]
    fn test_echo_construct() {
        let tag = Packet::EchoRequest {
            ident: 0x1234,
            seq_no: 0xabcd,
            payload: Vec::from(ECHO_DATA_BYTES),
        };

        let packet = tag.build(&CX).unwrap();
        assert_eq!(packet, &ECHO_PACKET_BYTES[..]);
    }
}
