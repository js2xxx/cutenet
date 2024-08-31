use core::{fmt, net::IpAddr};

use byteorder::{ByteOrder, NetworkEndian};

use crate::{
    context::{Ends, WireCx},
    ip::{self, checksum},
    prelude::*,
    Data, DataMut, IpAddrExt, Ipv6Packet,
};

#[path = "v6_nd.rs"]
pub mod nd;

/// Error packets must not exceed min MTU
const MAX_ERROR_PACKET_LEN: usize = ip::v6::MIN_MTU - ip::v6::HEADER_LEN;

enum_with_unknown! {
    /// Internet protocol control message type.
    pub enum Message(u8) {
        /// Destination Unreachable.
        DstUnreachable  = 0x01,
        /// RawPacket Too Big.
        PktTooBig       = 0x02,
        /// Time Exceeded.
        TimeExceeded    = 0x03,
        /// Parameter Problem.
        ParamProblem    = 0x04,
        /// Echo Request
        EchoRequest     = 0x80,
        /// Echo Reply
        EchoReply       = 0x81,
        /// Multicast Listener Query
        MldQuery        = 0x82,
        /// Router Solicitation
        RouterSolicit   = 0x85,
        /// Router Advertisement
        RouterAdvert    = 0x86,
        /// Neighbor Solicitation
        NeighborSolicit = 0x87,
        /// Neighbor Advertisement
        NeighborAdvert  = 0x88,
        /// Redirect
        Redirect        = 0x89,
        /// Multicast Listener Report
        MldReport       = 0x8f,
        /// RPL Control Message
        RplControl      = 0x9b,
    }
}

impl Message {
    /// Per [RFC 4443 § 2.1] ICMPv6 message types with the highest order
    /// bit set are informational messages while message types without
    /// the highest order bit set are error messages.
    ///
    /// [RFC 4443 § 2.1]: https://tools.ietf.org/html/rfc4443#section-2.1
    pub fn is_error(&self) -> bool {
        (u8::from(*self) & 0x80) != 0x80
    }

    /// Return a boolean value indicating if the given message type
    /// is an [NDISC] message type.
    ///
    /// [NDISC]: https://tools.ietf.org/html/rfc4861
    pub const fn is_nd(&self) -> bool {
        matches!(
            self,
            Message::RouterSolicit
                | Message::RouterAdvert
                | Message::NeighborSolicit
                | Message::NeighborAdvert
                | Message::Redirect
        )
    }

    /// Return a boolean value indicating if the given message type
    /// is an [MLD] message type.
    ///
    /// [MLD]: https://tools.ietf.org/html/rfc3810
    pub const fn is_mld(&self) -> bool {
        matches!(self, Message::MldQuery | Message::MldReport)
    }
}

impl fmt::Display for Message {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Message::DstUnreachable => write!(f, "destination unreachable"),
            Message::PktTooBig => write!(f, "packet too big"),
            Message::TimeExceeded => write!(f, "time exceeded"),
            Message::ParamProblem => write!(f, "parameter problem"),
            Message::EchoReply => write!(f, "echo reply"),
            Message::EchoRequest => write!(f, "echo request"),
            Message::RouterSolicit => write!(f, "router solicitation"),
            Message::RouterAdvert => write!(f, "router advertisement"),
            Message::NeighborSolicit => write!(f, "neighbor solicitation"),
            Message::NeighborAdvert => write!(f, "neighbor advert"),
            Message::Redirect => write!(f, "redirect"),
            Message::MldQuery => write!(f, "multicast listener query"),
            Message::MldReport => write!(f, "multicast listener report"),
            Message::RplControl => write!(f, "RPL control message"),
            Message::Unknown(id) => write!(f, "{id}"),
        }
    }
}

enum_with_unknown! {
    /// Internet protocol control message subtype for type "Destination Unreachable".
    pub enum DstUnreachable(u8) {
        /// No Route to destination.
        NoRoute         = 0,
        /// Communication with destination administratively prohibited.
        AdminProhibit   = 1,
        /// Beyond scope of source address.
        BeyondScope     = 2,
        /// Address unreachable.
        AddrUnreachable = 3,
        /// Port unreachable.
        PortUnreachable = 4,
        /// Source address failed ingress/egress policy.
        FailedPolicy    = 5,
        /// Reject route to destination.
        RejectRoute     = 6
    }
}

impl fmt::Display for DstUnreachable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            DstUnreachable::NoRoute => write!(f, "no route to destination"),
            DstUnreachable::AdminProhibit => write!(
                f,
                "communication with destination administratively prohibited"
            ),
            DstUnreachable::BeyondScope => write!(f, "beyond scope of source address"),
            DstUnreachable::AddrUnreachable => write!(f, "address unreachable"),
            DstUnreachable::PortUnreachable => write!(f, "port unreachable"),
            DstUnreachable::FailedPolicy => {
                write!(f, "source address failed ingress/egress policy")
            }
            DstUnreachable::RejectRoute => write!(f, "reject route to destination"),
            DstUnreachable::Unknown(id) => write!(f, "{id}"),
        }
    }
}

enum_with_unknown! {
    /// Internet protocol control message subtype for the type "Parameter Problem".
    pub enum ParamProblem(u8) {
        /// Erroneous header field encountered.
        ErroneousHdrField  = 0,
        /// Unrecognized Next Header type encountered.
        UnrecognizedNxtHdr = 1,
        /// Unrecognized IPv6 option encountered.
        UnrecognizedOption = 2
    }
}

impl fmt::Display for ParamProblem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            ParamProblem::ErroneousHdrField => write!(f, "erroneous header field."),
            ParamProblem::UnrecognizedNxtHdr => write!(f, "unrecognized next header type."),
            ParamProblem::UnrecognizedOption => write!(f, "unrecognized IPv6 option."),
            ParamProblem::Unknown(id) => write!(f, "{id}"),
        }
    }
}

enum_with_unknown! {
    /// Internet protocol control message subtype for the type "Time Exceeded".
    pub enum TimeExceeded(u8) {
        /// Hop limit exceeded in transit.
        HopLimitExceeded    = 0,
        /// Fragment reassembly time exceeded.
        FragReassemExceeded = 1
    }
}

impl fmt::Display for TimeExceeded {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            TimeExceeded::HopLimitExceeded => write!(f, "hop limit exceeded in transit"),
            TimeExceeded::FragReassemExceeded => write!(f, "fragment reassembly time exceeded"),
            TimeExceeded::Unknown(id) => write!(f, "{id}"),
        }
    }
}

struct RawPacket<T: ?Sized>(T);

// Ranges and constants describing key boundaries in the ICMPv6 header.
#[allow(unused)]
pub(super) mod field {
    use crate::field::*;

    // ICMPv6: See https://tools.ietf.org/html/rfc4443
    pub const TYPE: usize = 0;
    pub const CODE: usize = 1;
    pub const CHECKSUM: Field = 2..4;

    pub const UNUSED: Field = 4..8;
    pub const MTU: Field = 4..8;
    pub const POINTER: Field = 4..8;
    pub const ECHO_IDENT: Field = 4..6;
    pub const ECHO_SEQNO: Field = 6..8;

    pub const HEADER_END: usize = 8;

    // NDISC: See https://tools.ietf.org/html/rfc4861
    // Router Advertisement message offsets
    pub const CUR_HOP_LIMIT: usize = 4;
    pub const ROUTER_FLAGS: usize = 5;
    pub const ROUTER_LT: Field = 6..8;
    pub const REACHABLE_TM: Field = 8..12;
    pub const RETRANS_TM: Field = 12..16;

    // Neighbor Solicitation message offsets
    pub const TARGET_ADDR: Field = 8..24;

    // Neighbor Advertisement message offsets
    pub const NEIGH_FLAGS: usize = 4;

    // Redirected Header message offsets
    pub const DEST_ADDR: Field = 24..40;

    // MLD:
    //   - https://tools.ietf.org/html/rfc3810
    //   - https://tools.ietf.org/html/rfc3810
    // Multicast Listener Query message
    pub const MAX_RESP_CODE: Field = 4..6;
    pub const QUERY_RESV: Field = 6..8;
    pub const QUERY_MCAST_ADDR: Field = 8..24;
    pub const SQRV: usize = 24;
    pub const QQIC: usize = 25;
    pub const QUERY_NUM_SRCS: Field = 26..28;

    // Multicast Listener Report Message
    pub const RECORD_RESV: Field = 4..6;
    pub const NR_MCAST_RCRDS: Field = 6..8;

    // Multicast Address Record Offsets
    pub const RECORD_TYPE: usize = 0;
    pub const AUX_DATA_LEN: usize = 1;
    pub const RECORD_NUM_SRCS: Field = 2..4;
    pub const RECORD_MCAST_ADDR: Field = 4..20;
}

wire!(impl RawPacket {
    msg_type/set_msg_type: Message =>
        |data| Message::from(data[field::TYPE]);
        |data, value| data[field::TYPE] = value.into();

    msg_code/set_msg_code: u8 =>
        |data| data[field::CODE];
        |data, value| data[field::CODE] = value;

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

    pkt_too_big_mtu/set_pkt_too_big_mtu: u32 =>
        |data| NetworkEndian::read_u32(&data[field::MTU]);
        |data, value| NetworkEndian::write_u32(&mut data[field::MTU], value);

    param_problem_ptr/set_param_problem_ptr: u32 =>
        |data| NetworkEndian::read_u32(&data[field::POINTER]);
        |data, value| NetworkEndian::write_u32(&mut data[field::POINTER], value);
});

impl<T: Data + ?Sized> RawPacket<T> {
    pub fn header_len(&self) -> usize {
        match self.msg_type() {
            Message::DstUnreachable => field::UNUSED.end,
            Message::PktTooBig => field::MTU.end,
            Message::TimeExceeded => field::UNUSED.end,
            Message::ParamProblem => field::POINTER.end,
            Message::EchoRequest => field::ECHO_SEQNO.end,
            Message::EchoReply => field::ECHO_SEQNO.end,
            Message::RouterSolicit => field::UNUSED.end,
            Message::RouterAdvert => field::RETRANS_TM.end,
            Message::NeighborSolicit => field::TARGET_ADDR.end,
            Message::NeighborAdvert => field::TARGET_ADDR.end,
            Message::Redirect => field::DEST_ADDR.end,
            // For packets that are not included in RFC 4443, do not
            // include the last 32 bits of the ICMPv6 header in
            // `header_bytes`. This must be done so that these bytes
            // can be accessed in the `payload`.
            _ => field::CHECKSUM.end,
        }
    }

    pub fn data(&self) -> &[u8] {
        &self.0.as_ref()[self.header_len()..]
    }

    /// Validate the header checksum.
    pub fn verify_checksum(&self, addr: Ends<IpAddr>) -> bool {
        let data = self.0.as_ref();
        checksum::combine(&[
            checksum::pseudo_header_v6(
                &addr.src.unwrap_v6(),
                &addr.dst.unwrap_v6(),
                ip::Protocol::Icmpv6,
                data.len() as u32,
            ),
            checksum::data(data),
        ]) == !0
    }
}

impl<T: DataMut + ?Sized> RawPacket<T> {
    pub fn data_mut(&mut self) -> &mut [u8] {
        let header_len = self.header_len();
        &mut self.0.as_mut()[header_len..]
    }

    pub fn clear_reserved(&mut self) {
        match self.msg_type() {
            Message::RouterSolicit
            | Message::NeighborSolicit
            | Message::NeighborAdvert
            | Message::Redirect => {
                NetworkEndian::write_u32(&mut self.0.as_mut()[field::UNUSED], 0);
            }
            Message::MldQuery => {
                let data = self.0.as_mut();
                NetworkEndian::write_u16(&mut data[field::QUERY_RESV], 0);
                data[field::SQRV] &= 0xf;
            }
            Message::MldReport => {
                NetworkEndian::write_u16(&mut self.0.as_mut()[field::RECORD_RESV], 0);
            }
            ty => panic!("Message type `{ty}` does not have any reserved fields."),
        }
    }

    pub fn fill_checksum(&mut self, addr: Ends<IpAddr>) {
        self.set_checksum(0);
        let checksum = {
            let data = self.0.as_ref();
            !checksum::combine(&[
                checksum::pseudo_header_v6(
                    &addr.src.unwrap_v6(),
                    &addr.dst.unwrap_v6(),
                    ip::Protocol::Icmpv6,
                    data.len() as u32,
                ),
                checksum::data(data),
            ])
        };
        self.set_checksum(checksum);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Wire)]
#[prefix(crate)]
#[non_exhaustive]
pub enum Packet<#[wire] T, #[no_payload] U> {
    DstUnreachable {
        reason: DstUnreachable,
        #[wire]
        payload: Ipv6Packet<T>,
    },
    PktTooBig {
        mtu: u32,
        #[wire]
        payload: Ipv6Packet<T>,
    },
    TimeExceeded {
        reason: TimeExceeded,
        #[wire]
        payload: Ipv6Packet<T>,
    },
    ParamProblem {
        reason: ParamProblem,
        pointer: u32,
        #[wire]
        payload: Ipv6Packet<T>,
    },
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
    Nd {
        nd: nd::Nd,
        #[no_payload]
        payload: U,
    },
    // Mld(MldPacket),
    // Rpl(RplPacket),
}

impl<P, T, U> WireParse for Packet<T, U>
where
    P: PayloadParse<NoPayload = U> + Data,
    T: WireParse<Payload = P>,
    U: NoPayload<Init = P>,
{
    fn parse(cx: &dyn WireCx, raw: P) -> Result<Self, ParseError<P>> {
        let len = raw.len();
        let packet = RawPacket(raw);

        if len < 4 {
            return Err(ParseErrorKind::PacketTooShort.with(packet.0));
        }

        match packet.msg_type() {
            Message::DstUnreachable
            | Message::PktTooBig
            | Message::TimeExceeded
            | Message::ParamProblem
            | Message::EchoRequest
            | Message::EchoReply
            | Message::MldQuery
            | Message::RouterSolicit
            | Message::RouterAdvert
            | Message::NeighborSolicit
            | Message::NeighborAdvert
            | Message::Redirect
            | Message::MldReport => {
                if len < field::HEADER_END || len < packet.header_len() {
                    return Err(ParseErrorKind::PacketTooShort.with(packet.0));
                }
            }
            Message::RplControl => return Err(ParseErrorKind::ProtocolUnknown.with(packet.0)),
            Message::Unknown(_) => return Err(ParseErrorKind::ProtocolUnknown.with(packet.0)),
        }

        if cx.checksums().icmp() && !packet.verify_checksum(cx.ip_addrs()) {
            return Err(ParseErrorKind::ChecksumInvalid.with(packet.0));
        }

        match (packet.msg_type(), packet.msg_code()) {
            (Message::DstUnreachable, code) => Ok(Packet::DstUnreachable {
                reason: DstUnreachable::from(code),
                payload: Ipv6Packet::parse(&(), packet.0.pop(field::UNUSED.end..len)?)?,
            }),
            (Message::PktTooBig, 0) => Ok(Packet::PktTooBig {
                mtu: packet.pkt_too_big_mtu(),
                payload: Ipv6Packet::parse(&(), packet.0.pop(field::MTU.end..len)?)?,
            }),
            (Message::TimeExceeded, code) => Ok(Packet::TimeExceeded {
                reason: TimeExceeded::from(code),
                payload: Ipv6Packet::parse(&(), packet.0.pop(field::UNUSED.end..len)?)?,
            }),
            (Message::ParamProblem, code) => Ok(Packet::ParamProblem {
                reason: ParamProblem::from(code),
                pointer: packet.param_problem_ptr(),
                payload: Ipv6Packet::parse(&(), packet.0.pop(field::POINTER.end..len)?)?,
            }),
            (Message::EchoRequest, 0) => Ok(Packet::EchoRequest {
                ident: packet.echo_ident(),
                seq_no: packet.echo_seq_no(),
                payload: T::parse(cx, packet.0.pop(field::ECHO_SEQNO.end..len)?)?,
            }),
            (Message::EchoReply, 0) => Ok(Packet::EchoReply {
                ident: packet.echo_ident(),
                seq_no: packet.echo_seq_no(),
                payload: T::parse(cx, packet.0.pop(field::ECHO_SEQNO.end..len)?)?,
            }),
            (msg, 0) if msg.is_nd() => Ok(Packet::Nd {
                nd: match nd::Nd::parse(RawPacket(packet.0.as_ref())) {
                    Ok(nd) => nd,
                    Err(kind) => return Err(kind.with(packet.0)),
                },
                payload: packet.0.truncate(),
            }),
            _ => Err(ParseErrorKind::ProtocolUnknown.with(packet.0)),
        }
    }
}

impl<P, T, U> WireBuild for Packet<T, U>
where
    P: PayloadBuild<NoPayload = U>,
    T: WireBuild<Payload = P>,
    U: NoPayload<Init = P>,
{
    fn buffer_len(&self) -> usize {
        MAX_ERROR_PACKET_LEN.min(match self {
            Packet::DstUnreachable { payload, .. } => field::UNUSED.end + payload.buffer_len(),
            Packet::PktTooBig { payload, .. } => field::MTU.end + payload.buffer_len(),
            Packet::TimeExceeded { payload, .. } => field::UNUSED.end + payload.buffer_len(),
            Packet::ParamProblem { payload, .. } => field::POINTER.end + payload.buffer_len(),
            Packet::EchoRequest { payload, .. } | Packet::EchoReply { payload, .. } => {
                field::ECHO_SEQNO.end + payload.buffer_len()
            }
            Packet::Nd { nd, payload: _ } => nd.len(),
        })
    }

    fn build(self, cx: &dyn WireCx) -> Result<P, BuildError<P>> {
        let checksum = |mut packet: RawPacket<&mut [u8]>| {
            if cx.checksums().icmp() {
                packet.fill_checksum(cx.ip_addrs());
            } else {
                // make sure we get a consistently zeroed checksum,
                // since implementations might rely on it
                packet.set_checksum(0);
            }
            Ok(())
        };

        let push_opt = PayloadPush::Truncate(MAX_ERROR_PACKET_LEN);
        match self {
            Packet::DstUnreachable { reason, payload } => {
                (payload.build(&())?).push_with(field::UNUSED.end, push_opt, |buf| {
                    let mut packet = RawPacket(buf);
                    packet.set_msg_type(Message::DstUnreachable);
                    packet.set_msg_code(reason.into());
                    checksum(packet)
                })
            }
            Packet::PktTooBig { mtu, payload } => {
                (payload.build(&())?).push_with(field::MTU.end, push_opt, |buf| {
                    let mut packet = RawPacket(buf);
                    packet.set_msg_type(Message::PktTooBig);
                    packet.set_msg_code(0);
                    packet.set_pkt_too_big_mtu(mtu);
                    checksum(packet)
                })
            }
            Packet::TimeExceeded { reason, payload } => {
                (payload.build(&())?).push_with(field::UNUSED.end, push_opt, |buf| {
                    let mut packet = RawPacket(buf);
                    packet.set_msg_type(Message::TimeExceeded);
                    packet.set_msg_code(reason.into());
                    checksum(packet)
                })
            }

            Packet::ParamProblem { reason, pointer, payload } => {
                (payload.build(&())?).push_with(field::POINTER.end, push_opt, |buf| {
                    let mut packet = RawPacket(buf);
                    packet.set_msg_type(Message::ParamProblem);
                    packet.set_msg_code(reason.into());
                    packet.set_param_problem_ptr(pointer);
                    checksum(packet)
                })
            }
            Packet::EchoRequest { ident, seq_no, payload } => {
                payload.build(cx)?.push(field::ECHO_SEQNO.end, |buf| {
                    let mut packet = RawPacket(buf);
                    packet.set_msg_type(Message::EchoRequest);
                    packet.set_msg_code(0);
                    packet.set_echo_ident(ident);
                    packet.set_echo_seq_no(seq_no);
                    checksum(packet)
                })
            }
            Packet::EchoReply { ident, seq_no, payload } => {
                payload.build(cx)?.push(field::ECHO_SEQNO.end, |buf| {
                    let mut packet = RawPacket(buf);
                    packet.set_msg_type(Message::EchoReply);
                    packet.set_msg_code(0);
                    packet.set_echo_ident(ident);
                    packet.set_echo_seq_no(seq_no);
                    checksum(packet)
                })
            }
            Packet::Nd { nd, payload } => payload.init().push(nd.len(), |buf| {
                nd.build(RawPacket(buf));
                checksum(RawPacket(buf))
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use core::net::Ipv6Addr;
    use std::vec;

    use cutenet_storage::Buf;
    use ip::IpAddrExt;

    use super::*;
    use crate::Checksums;

    const MOCK_IP_ADDR_1: IpAddr = IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1));
    const MOCK_IP_ADDR_2: IpAddr = IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 2));
    const MOCK_IP_ADDRS: Ends<IpAddr> = Ends {
        src: MOCK_IP_ADDR_1,
        dst: MOCK_IP_ADDR_2,
    };

    const CX: (Checksums, Ends<IpAddr>) = (Checksums::new(), MOCK_IP_ADDRS);

    static ECHO_PACKET_BYTES: [u8; 12] = [
        0x80, 0x00, 0x19, 0xb3, 0x12, 0x34, 0xab, 0xcd, 0xaa, 0x00, 0x00, 0xff,
    ];

    static ECHO_PACKET_PAYLOAD: [u8; 4] = [0xaa, 0x00, 0x00, 0xff];

    static PKT_TOO_BIG_BYTES: [u8; 60] = [
        0x02, 0x00, 0x0f, 0xc9, 0x00, 0x00, 0x05, 0xdc, 0x60, 0x00, 0x00, 0x00, 0x00, 0x0c, 0x11,
        0x40, 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x01, 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x02, 0xbf, 0x00, 0x00, 0x35, 0x00, 0x0c, 0x12, 0x4d, 0xaa, 0x00, 0x00, 0xff,
    ];

    static PKT_TOO_BIG_UDP_PAYLOAD: [u8; 12] = [
        0xbf, 0x00, 0x00, 0x35, 0x00, 0x0c, 0x12, 0x4d, 0xaa, 0x00, 0x00, 0xff,
    ];

    #[test]
    fn test_echo_deconstruct() {
        let packet: Packet<&[u8], _> = Packet::parse(&CX, &ECHO_PACKET_BYTES[..]).unwrap();
        assert_eq!(packet, Packet::EchoRequest {
            ident: 0x1234,
            seq_no: 0xabcd,
            payload: &ECHO_PACKET_PAYLOAD[..]
        });
    }

    #[test]
    fn test_echo_construct() {
        let repr = Packet::EchoRequest {
            ident: 0x1234,
            seq_no: 0xabcd,
            payload: PayloadHolder(ECHO_PACKET_PAYLOAD.len()),
        };
        let bytes = vec![0xa5; repr.buffer_len()];
        let mut buf = Buf::builder(bytes).reserve_for(&repr).build();
        buf.append_slice(&ECHO_PACKET_PAYLOAD);
        let packet = repr.sub_payload(|_| buf).build(&CX).unwrap();
        assert_eq!(packet.data(), &ECHO_PACKET_BYTES[..]);
    }

    #[test]
    fn test_too_big_deconstruct() {
        let packet: Packet<&[u8], _> = Packet::parse(&CX, &PKT_TOO_BIG_BYTES[..]).unwrap();
        assert!(matches!(packet, Packet::PktTooBig {
                mtu: 1500,
                payload: Ipv6Packet {
                    next_header: ip::Protocol::Udp,
                    hop_limit: 0x40,
                    payload,
                    ..
                }
            } if payload == &PKT_TOO_BIG_UDP_PAYLOAD[..]));
    }

    #[test]
    fn test_too_big_construct() {
        let repr = Packet::PktTooBig {
            mtu: 1500,
            payload: Ipv6Packet {
                addr: MOCK_IP_ADDRS.map(|ip| ip.unwrap_v6()),
                next_header: ip::Protocol::Udp,
                hop_limit: 0x40,
                payload: PayloadHolder(PKT_TOO_BIG_UDP_PAYLOAD.len()),
            },
        };
        let bytes = vec![0xa5; repr.buffer_len()];
        let mut buf = Buf::builder(bytes).reserve_for(&repr).build();
        buf.append_slice(&PKT_TOO_BIG_UDP_PAYLOAD);

        let packet = repr.sub_payload(|_| buf).build(&CX).unwrap();
        assert_eq!(packet.data(), &PKT_TOO_BIG_BYTES[..]);
    }

    #[test]
    fn test_buffer_length_is_truncated_to_mtu() {
        let repr = Packet::PktTooBig {
            mtu: 1280,
            payload: Ipv6Packet {
                addr: Ends {
                    src: Ipv6Addr::UNSPECIFIED,
                    dst: Ipv6Addr::UNSPECIFIED,
                },
                next_header: ip::Protocol::Tcp,
                hop_limit: 64,
                payload: PayloadHolder(9999),
            },
        };
        assert_eq!(repr.buffer_len(), 1280 - ip::v6::HEADER_LEN);
    }
}
