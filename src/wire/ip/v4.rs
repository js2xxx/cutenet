use core::net::{IpAddr, Ipv4Addr};

use byteorder::{ByteOrder, NetworkEndian};

pub use self::cidr::Cidr;
use super::{checksum, IpAddrExt, Protocol, WireCx};
use crate as cutenet;
use crate::{
    context::Ends,
    wire::{prelude::*, Data, DataMut},
};

#[path = "v4_cidr.rs"]
mod cidr;

#[derive(Debug, Eq, PartialEq, Ord, PartialOrd, Clone, Copy)]
pub struct Key {
    id: u16,
    src_addr: Ipv4Addr,
    dst_addr: Ipv4Addr,
    protocol: Protocol,
}

#[derive(Debug, Eq, PartialEq, Ord, PartialOrd, Clone, Copy)]
pub struct FragInfo {
    pub offset: u16,
    pub key: Key,
}

struct RawPacket<T: ?Sized>(T);

mod field {
    use crate::wire::field::*;

    pub const VER_IHL: usize = 0;
    pub const DSCP_ECN: usize = 1;
    pub const LENGTH: Field = 2..4;
    pub const IDENT: Field = 4..6;
    pub const FLG_OFF: Field = 6..8;
    pub const TTL: usize = 8;
    pub const PROTOCOL: usize = 9;
    pub const CHECKSUM: Field = 10..12;
    pub const SRC_ADDR: Field = 12..16;
    pub const DST_ADDR: Field = 16..20;
}
pub const HEADER_LEN: usize = field::DST_ADDR.end;

wire!(impl RawPacket {
    /// Return the version field.
    version/set_version: u8 =>
        |data| data[field::VER_IHL] >> 4;
        |data, value| data[field::VER_IHL] = (data[field::VER_IHL] & !0xf0) | (value << 4);

    /// Return the header length, in octets.
    header_len/set_header_len: u8 =>
        |data| (data[field::VER_IHL] & 0x0f) * 4;
        |data, value| data[field::VER_IHL] = (data[field::VER_IHL] & !0x0f) | ((value / 4) & 0x0f);

    /// Return the Differential Services Code Point field.
    #[allow(unused)]
    dscp/set_dscp: u8 =>
        |data| data[field::DSCP_ECN] >> 2;
        |data, value| data[field::DSCP_ECN] = (data[field::DSCP_ECN] & !0xfc) | (value << 2);

    /// Return the Explicit Congestion Notification field.
    #[allow(unused)]
    ecn/set_ecn: u8 =>
        |data| data[field::DSCP_ECN] & 0x03;
        |data, value| data[field::DSCP_ECN] = (data[field::DSCP_ECN] & !0x03) | (value & 0x03);

    /// Return the total length field.
    total_len/set_total_len: u16 =>
        |data| NetworkEndian::read_u16(&data[field::LENGTH]);
        |data, value| NetworkEndian::write_u16(&mut data[field::LENGTH], value);

    /// Return the fragment identification field.
    ident/set_ident: u16 =>
        |data| NetworkEndian::read_u16(&data[field::IDENT]);
        |data, value| NetworkEndian::write_u16(&mut data[field::IDENT], value);

    /// Return the "don't fragment" flag.
    #[allow(unused)]
    dont_frag/set_dont_frag: bool =>
        |data| NetworkEndian::read_u16(&data[field::FLG_OFF]) & 0x4000 != 0;
        |data, value| {
            let raw = NetworkEndian::read_u16(&data[field::FLG_OFF]);
            let raw = if value { raw | 0x4000 } else { raw & !0x4000 };
            NetworkEndian::write_u16(&mut data[field::FLG_OFF], raw);
        };

    /// Return the "more fragments" flag.
    more_frags/set_more_frags: bool =>
        |data| NetworkEndian::read_u16(&data[field::FLG_OFF]) & 0x2000 != 0;
        |data, value| {
            let raw = NetworkEndian::read_u16(&data[field::FLG_OFF]);
            let raw = if value { raw | 0x2000 } else { raw & !0x2000 };
            NetworkEndian::write_u16(&mut data[field::FLG_OFF], raw);
        };

    /// Return the fragment offset, in octets.
    frag_offset/set_frag_offset: u16 =>
        |data| NetworkEndian::read_u16(&data[field::FLG_OFF]) << 3;
        |data, value| {
            let raw = NetworkEndian::read_u16(&data[field::FLG_OFF]);
            let raw = (raw & 0xe000) | (value >> 3);
            NetworkEndian::write_u16(&mut data[field::FLG_OFF], raw);
        };

    /// Return the time to live field.
    hop_limit/set_hop_limit: u8 =>
        |data| data[field::TTL];
        |data, value| data[field::TTL] = value;

    /// Return the next_header (protocol) field.
    next_header/set_next_header: Protocol =>
        |data| Protocol::from(data[field::PROTOCOL]);
        |data, value| data[field::PROTOCOL] = value.into();

    /// Return the header checksum field.
    #[allow(unused)]
    checksum/set_checksum: u16 =>
        |data| NetworkEndian::read_u16(&data[field::CHECKSUM]);
        |data, value| NetworkEndian::write_u16(&mut data[field::CHECKSUM], value);

    /// Return the source address field.
    src_addr/set_src_addr: Ipv4Addr =>
        |data| Ipv4Addr::from_bytes(&data[field::SRC_ADDR]);
        |data, value| data[field::SRC_ADDR].copy_from_slice(&value.octets());

    /// Return the destination address field.
    dst_addr/set_dst_addr: Ipv4Addr =>
        |data| Ipv4Addr::from_bytes(&data[field::DST_ADDR]);
        |data, value| data[field::DST_ADDR].copy_from_slice(&value.octets());
});

impl<T: Data + ?Sized> RawPacket<T> {
    pub fn addr(&self) -> Ends<Ipv4Addr> {
        Ends {
            src: self.src_addr(),
            dst: self.dst_addr(),
        }
    }

    pub fn verify_checksum(&self) -> bool {
        checksum::data(&self.0.as_ref()[..usize::from(self.header_len())]) == !0
    }

    pub fn key(&self) -> Key {
        Key {
            id: self.ident(),
            src_addr: self.src_addr(),
            dst_addr: self.dst_addr(),
            protocol: self.next_header(),
        }
    }
}

impl<T: DataMut + ?Sized> RawPacket<T> {
    fn clear_flags(&mut self) {
        let raw = NetworkEndian::read_u16(&self.0.as_mut()[field::FLG_OFF]);
        let raw = raw & !0xe000;
        NetworkEndian::write_u16(&mut self.0.as_mut()[field::FLG_OFF], raw);
    }

    pub fn fill_checksum(&mut self) {
        self.set_checksum(0);
        let checksum = !checksum::data(&self.0.as_ref()[..usize::from(self.header_len())]);
        self.set_checksum(checksum);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Wire)]
pub struct Packet<#[wire] T> {
    pub addr: Ends<Ipv4Addr>,
    pub next_header: Protocol,
    pub hop_limit: u8,
    pub frag_info: Option<FragInfo>,
    #[wire]
    pub payload: T,
}

impl<P: PayloadParse + Data, T: WireParse<Payload = P>> WireParse for Packet<T> {
    fn parse(cx: &dyn WireCx, raw: P) -> Result<Self, ParseError<P>> {
        let packet = RawPacket(raw);

        let len = packet.0.len();
        let total_len = packet.total_len();
        if len < field::DST_ADDR.end
            || len < usize::from(packet.header_len())
            || u16::from(packet.header_len()) > total_len
            || len < usize::from(packet.total_len())
        {
            return Err(ParseErrorKind::PacketTooShort.with(packet.0));
        }

        if packet.version() != 4 {
            return Err(ParseErrorKind::VersionInvalid.with(packet.0));
        }

        if cx.checksums().ip() && !packet.verify_checksum() {
            return Err(ParseErrorKind::ChecksumInvalid.with(packet.0));
        }

        let generic_addr = packet.addr().map(IpAddr::V4);
        let next_header = packet.next_header();

        Ok(Packet {
            addr: packet.addr(),
            next_header,
            hop_limit: packet.hop_limit(),
            frag_info: packet.more_frags().then(|| FragInfo {
                offset: packet.frag_offset(),
                key: packet.key(),
            }),

            payload: T::parse(
                &[cx, &(generic_addr, next_header)],
                packet.0.pop(HEADER_LEN..usize::from(total_len))?,
            )?,
        })
    }
}

impl<P: PayloadBuild, T: WireBuild<Payload = P>> WireBuild for Packet<T> {
    fn buffer_len(&self) -> usize {
        HEADER_LEN + self.payload_len()
    }

    fn build(self, cx: &dyn WireCx) -> Result<P, BuildError<P>> {
        let Packet {
            addr,
            next_header,
            hop_limit,
            frag_info,
            payload,
        } = self;

        let generic_addr = addr.map(IpAddr::V4);
        let payload = payload.build(&[cx, &(generic_addr, next_header)])?;

        payload.push(HEADER_LEN, |buf| {
            let mut packet = RawPacket(buf);

            let total_len = u16::try_from(packet.0.len());
            packet.set_total_len(total_len.map_err(|_| BuildErrorKind::PayloadTooLong)?);

            packet.set_version(4);
            packet.set_header_len(u8::try_from(HEADER_LEN).unwrap());
            packet.set_dscp(0);
            packet.set_ecn(0);

            packet.clear_flags();
            packet.set_dont_frag(true);

            if let Some(frag_info) = frag_info {
                packet.set_more_frags(true);
                packet.set_frag_offset(frag_info.offset);
                packet.set_ident(frag_info.key.id);
            } else {
                packet.set_more_frags(false);
                packet.set_frag_offset(0);
                packet.set_ident(0);
            }

            packet.set_src_addr(addr.src);
            packet.set_dst_addr(addr.dst);
            packet.set_next_header(next_header);
            packet.set_hop_limit(hop_limit);

            if cx.checksums().ip() {
                packet.fill_checksum();
            } else {
                packet.set_checksum(0);
            }
            Ok(())
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Wire)]
pub enum Ipv4Payload<#[wire] T> {
    Icmp(#[wire] crate::wire::Icmpv4Packet<T>),
    Udp(#[wire] crate::wire::UdpPacket<T>),
    Tcp(#[wire] crate::wire::TcpPacket<T>),
}

impl<T, P, U> WireParse for Ipv4Payload<T>
where
    T: WireParse<Payload = P>,
    P: PayloadParse<NoPayload = U> + Data,
    U: NoPayload<Init = P>,
{
    fn parse(cx: &dyn WireCx, raw: P) -> Result<Self, ParseError<P>> {
        Ok(match cx.ip_protocol() {
            Protocol::Icmp => Ipv4Payload::Icmp(crate::wire::Icmpv4Packet::parse(cx, raw)?),
            Protocol::Tcp => Ipv4Payload::Tcp(crate::wire::TcpPacket::parse(cx, raw)?),
            Protocol::Udp => Ipv4Payload::Udp(crate::wire::UdpPacket::parse(cx, raw)?),
            _ => return Err(ParseErrorKind::ProtocolUnknown.with(raw)),
        })
    }
}

impl<T, P, U> WireBuild for Ipv4Payload<T>
where
    T: WireBuild<Payload = P>,
    P: PayloadBuild<NoPayload = U>,
    U: NoPayload<Init = P>,
{
    fn buffer_len(&self) -> usize {
        match self {
            Ipv4Payload::Icmp(packet) => packet.buffer_len(),
            Ipv4Payload::Tcp(packet) => packet.buffer_len(),
            Ipv4Payload::Udp(packet) => packet.buffer_len(),
        }
    }

    fn build(self, cx: &dyn WireCx) -> Result<P, BuildError<P>> {
        match self {
            Ipv4Payload::Icmp(packet) => packet.build(cx),
            Ipv4Payload::Tcp(packet) => packet.build(cx),
            Ipv4Payload::Udp(packet) => packet.build(cx),
        }
    }
}

#[cfg(test)]
mod tests {

    use std::vec;

    use super::*;
    use crate::{layer::Checksums, storage::Buf};

    const INGRESS_PACKET_BYTES: [u8; 30] = [
        0x45, 0x00, 0x00, 0x1e, 0x01, 0x02, 0x62, 0x03, 0x1a, 0x01, 0xd5, 0x6e, 0x11, 0x12, 0x13,
        0x14, 0x21, 0x22, 0x23, 0x24, 0xaa, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff,
    ];

    const EGRESS_PACKET_BYTES: [u8; 30] = [
        0x45, 0x00, 0x00, 0x1e, 0x00, 0x00, 0x40, 0x00, 0x1a, 0x01, 0xf8, 0x73, 0x11, 0x12, 0x13,
        0x14, 0x21, 0x22, 0x23, 0x24, 0xaa, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff,
    ];

    const PAYLOAD_BYTES: [u8; 10] = [0xaa, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff];

    const CX: (Checksums,) = (Checksums::new(),);

    #[test]
    fn test_deconstruct() {
        let mut pb = INGRESS_PACKET_BYTES;
        let packet: Packet<Buf<_>> = Packet::parse(&CX, Buf::full(&mut pb[..])).unwrap();
        assert_eq!(packet.hop_limit, 0x1a);
        assert_eq!(packet.next_header, Protocol::Icmp);
        assert_eq!(packet.addr, Ends {
            src: Ipv4Addr::from([0x11, 0x12, 0x13, 0x14]),
            dst: Ipv4Addr::from([0x21, 0x22, 0x23, 0x24]),
        });
        assert_eq!(
            packet.frag_info,
            Some(FragInfo {
                offset: 4120,
                key: Key {
                    id: 258,
                    src_addr: Ipv4Addr::from([0x11, 0x12, 0x13, 0x14]),
                    dst_addr: Ipv4Addr::from([0x21, 0x22, 0x23, 0x24]),
                    protocol: Protocol::Icmp
                }
            })
        );
        assert_eq!(packet.payload.data(), &PAYLOAD_BYTES[..]);
    }

    #[test]
    fn test_construct() {
        let tag = Packet {
            addr: Ends {
                src: Ipv4Addr::from([0x11, 0x12, 0x13, 0x14]),
                dst: Ipv4Addr::from([0x21, 0x22, 0x23, 0x24]),
            },
            next_header: Protocol::Icmp,
            hop_limit: 0x1a,
            frag_info: None,
            payload: PayloadHolder(PAYLOAD_BYTES.len()),
        };

        let bytes = vec![0xa5; 30];
        let mut payload = Buf::builder(bytes).reserve_for(&tag).build();
        payload.append_slice(&PAYLOAD_BYTES);

        let packet = tag.sub_payload(|_| payload).build(&CX).unwrap();
        assert_eq!(packet.data(), &EGRESS_PACKET_BYTES[..]);
    }

    #[test]
    fn test_overlong() {
        let mut pb = vec![];
        pb.extend(INGRESS_PACKET_BYTES);
        pb.push(0);
        let packet: Packet<Buf<_>> = Packet::parse(&CX, Buf::full(&mut pb[..])).unwrap();

        assert_eq!(packet.payload.len(), PAYLOAD_BYTES.len());
    }

    #[test]
    fn test_parse_total_len_less_than_header_len() {
        let mut bytes = [0; 40];
        bytes[0] = 0x09;
        assert!(Packet::<Buf<_>>::parse(&(), Buf::full(&mut bytes[..])).is_err());
    }
}
