use core::net::IpAddr;

use byteorder::{ByteOrder, NetworkEndian};

use crate::{
    context::{Ends, WireCx},
    ip::{self, checksum},
    prelude::*,
};

struct RawPacket<T: ?Sized>(T);

pub mod field {
    #![allow(non_snake_case)]

    use crate::field::*;

    pub const SRC_PORT: Field = 0..2;
    pub const DST_PORT: Field = 2..4;
    pub const LENGTH: Field = 4..6;
    pub const CHECKSUM: Field = 6..8;

    pub const PAYLOAD: Rest = CHECKSUM.end..;
}

pub const HEADER_LEN: usize = field::PAYLOAD.start;

wire!(impl RawPacket {
    src_port/set_src_port: u16 =>
        |data| NetworkEndian::read_u16(&data[field::SRC_PORT]);
        |data, value| NetworkEndian::write_u16(&mut data[field::SRC_PORT], value);

    dst_port/set_dst_port: u16 =>
        |data| NetworkEndian::read_u16(&data[field::DST_PORT]);
        |data, value| NetworkEndian::write_u16(&mut data[field::DST_PORT], value);

    len/set_len: u16 =>
        |data| NetworkEndian::read_u16(&data[field::LENGTH]);
        |data, value| NetworkEndian::write_u16(&mut data[field::LENGTH], value);

    checksum/set_checksum: u16 =>
        |data| NetworkEndian::read_u16(&data[field::CHECKSUM]);
        |data, value| NetworkEndian::write_u16(&mut data[field::CHECKSUM], value);
});

impl<T: AsRef<[u8]> + ?Sized> RawPacket<T> {
    fn port(&self) -> Ends<u16> {
        Ends {
            src: self.src_port(),
            dst: self.dst_port(),
        }
    }

    fn verify_checksum<'a>(
        &self,
        addr: Ends<IpAddr>,
        next_iter: impl Iterator<Item = &'a [u8]>,
    ) -> bool {
        // From the RFC:
        // > An all zero transmitted checksum value means that the transmitter
        // > generated no checksum (for debugging or for higher level protocols
        // > that don't care).
        if self.checksum() == 0 {
            return true;
        }

        let len = self.len();
        let combine = checksum::combine(&[
            checksum::pseudo_header(&addr.src, &addr.dst, ip::Protocol::Udp, len.into()),
            checksum::data_iter_limited(self.0.as_ref(), next_iter, len.into()),
        ]);
        combine == !0
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]> + ?Sized> RawPacket<T> {
    fn fill_checksum<'a>(&mut self, addr: Ends<IpAddr>, next_iter: impl Iterator<Item = &'a [u8]>) {
        self.set_checksum(0);

        let len = self.len();
        let checksum = !checksum::combine(&[
            checksum::pseudo_header(&addr.src, &addr.dst, ip::Protocol::Udp, len.into()),
            checksum::data_iter_limited(self.0.as_ref(), next_iter, len.into()),
        ]);
        self.set_checksum(if checksum == 0 { 0xffff } else { checksum });
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Wire)]
#[prefix(crate)]
pub struct Packet<#[wire] T> {
    pub port: Ends<u16>,
    #[wire]
    pub payload: T,
}

impl<P: PayloadParse, T: WireParse<Payload = P>> WireParse for Packet<T> {
    fn parse(cx: &dyn WireCx, raw: P) -> Result<Self, ParseError<P>> {
        let packet = RawPacket(raw.header_data());

        let buffer_len = packet.0.len();
        if buffer_len < HEADER_LEN {
            return Err(ParseErrorKind::PacketTooShort.with(raw));
        }

        let field_len = usize::from(packet.len());
        if buffer_len < field_len || field_len < HEADER_LEN {
            return Err(ParseErrorKind::PacketTooShort.with(raw));
        }

        if packet.dst_port() == 0 {
            return Err(ParseErrorKind::DstInvalid.with(raw));
        }

        if cx.checksums().udp() && !packet.verify_checksum(cx.ip_addrs(), raw.next_data_iter()) {
            return Err(ParseErrorKind::ChecksumInvalid.with(raw));
        }

        Ok(Packet {
            port: packet.port(),
            payload: T::parse(
                cx,
                raw.pop(HEADER_LEN..field_len)
                    .map_err(|err| ParseErrorKind::PacketTooShort.with(err))?,
            )?,
        })
    }
}

impl<P: PayloadBuild, T: WireBuild<Payload = P>> WireBuild for Packet<T> {
    fn buffer_len(&self) -> usize {
        HEADER_LEN + self.payload_len()
    }

    fn build(self, cx: &dyn WireCx) -> Result<P, BuildError<P>> {
        let Packet { port: Ends { src, dst }, payload } = self;

        let payload = payload.build(cx)?;
        let len = payload.len();
        payload.push(HEADER_LEN, |buf, iter| {
            let len =
                u16::try_from(len + HEADER_LEN).map_err(|_| BuildErrorKind::PayloadTooLong)?;
            let mut packet = RawPacket(buf);
            packet.set_len(len);

            packet.set_src_port(src);
            packet.set_dst_port(dst);

            if cx.checksums().udp() {
                packet.fill_checksum(cx.ip_addrs(), iter);
            } else {
                packet.set_checksum(0);
            }
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use core::net::Ipv4Addr;
    use std::vec::Vec;

    use super::*;
    use crate::Checksums;

    const SRC_ADDR: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 1);
    const DST_ADDR: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 2);
    const ADDR: Ends<IpAddr> = Ends {
        src: IpAddr::V4(SRC_ADDR),
        dst: IpAddr::V4(DST_ADDR),
    };

    const CX: (Checksums, Ends<IpAddr>) = (Checksums::new(), ADDR);

    const PACKET_BYTES: [u8; 12] = [
        0xbf, 0x00, 0x00, 0x35, 0x00, 0x0c, 0x12, 0x4d, 0xaa, 0x00, 0x00, 0xff,
    ];

    const PAYLOAD_BYTES: [u8; 4] = [0xaa, 0x00, 0x00, 0xff];

    #[test]
    fn test_deconstruct() {
        let packet: Packet<&[u8]> = Packet::parse(&CX, &PACKET_BYTES[..]).unwrap();
        assert_eq!(packet.port, Ends { src: 48896, dst: 53 });
        assert_eq!(packet.payload, &PAYLOAD_BYTES[..]);
    }

    #[test]
    fn test_construct() {
        let tag = Packet {
            port: Ends { src: 48896, dst: 53 },
            payload: Vec::from(PAYLOAD_BYTES),
        };

        let packet = tag.build(&CX).unwrap();
        assert_eq!(packet, &PACKET_BYTES[..]);
    }

    #[test]
    fn test_zero_checksum() {
        let tag = Packet {
            port: Ends { src: 1, dst: 0x7c89 },
            payload: Vec::new(),
        };

        let packet = tag.build(&CX).unwrap();
        assert_eq!(packet, &[0, 1, 0x7c, 0x89, 0, 8, 0xff, 0xff]);
    }

    #[test]
    fn test_no_checksum() {
        let tag = Packet {
            port: Ends { src: 1, dst: 0x7c89 },
            payload: Vec::new(),
        };

        let packet = tag.build(&()).unwrap();
        assert!(Packet::<Vec<_>>::parse(&CX, packet).is_ok());
    }
}
