use core::{net::IpAddr, ops::Range};

use byteorder::{ByteOrder, NetworkEndian};

use super::{
    ip::{self, checksum},
    BuildErrorKind, Data, DataMut, Dst, Ends, ParseErrorKind, Src, VerifyChecksum, Wire,
};

pub type Packet<T: ?Sized> = super::Packet<Udp, T>;

pub mod field {
    #![allow(non_snake_case)]

    use crate::wire::field::*;

    pub const SRC_PORT: Field = 0..2;
    pub const DST_PORT: Field = 2..4;
    pub const LENGTH: Field = 4..6;
    pub const CHECKSUM: Field = 6..8;

    pub const PAYLOAD: Rest = CHECKSUM.end..;
}

pub const HEADER_LEN: usize = field::PAYLOAD.start;

wire!(impl Packet {
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

impl<T: Data + ?Sized> Packet<T> {
    pub fn port(&self) -> Ends<u16> {
        (Src(self.src_port()), Dst(self.dst_port()))
    }

    pub fn verify_checksum(&self, addr: Ends<IpAddr>) -> bool {
        let (Src(src), Dst(dst)) = addr;
        // From the RFC:
        // > An all zero transmitted checksum value means that the transmitter
        // > generated no checksum (for debugging or for higher level protocols
        // > that don't care).
        if self.checksum() == 0 {
            return true;
        }

        checksum::combine(&[
            checksum::pseudo_header(&src, &dst, ip::Protocol::Udp, u32::from(self.len())),
            checksum::data(&self.inner.as_ref()[..usize::from(self.len())]),
        ]) == !0
    }
}

impl<T: DataMut + ?Sized> Packet<T> {
    pub fn fill_checksum(&mut self, addr: Ends<IpAddr>) {
        let (Src(src), Dst(dst)) = addr;
        self.set_checksum(0);

        let len = self.len();
        let checksum = !checksum::combine(&[
            checksum::pseudo_header(&src, &dst, ip::Protocol::Udp, u32::from(len)),
            checksum::data(&self.inner.as_ref()[..usize::from(len)]),
        ]);
        self.set_checksum(if checksum == 0 { 0xffff } else { checksum });
    }
}

#[derive(Debug)]
pub struct Udp {
    pub port: Ends<u16>,
}

impl Wire for Udp {
    const EMPTY_PAYLOAD: bool = false;

    fn header_len(&self) -> usize {
        HEADER_LEN
    }

    fn buffer_len(&self, payload_len: usize) -> usize {
        HEADER_LEN + payload_len
    }

    fn payload_range(packet: Packet<&[u8]>) -> Range<usize> {
        HEADER_LEN..packet.inner.len()
    }

    type ParseArg<'a> = VerifyChecksum<Option<Ends<IpAddr>>>;
    fn parse_packet(
        packet: Packet<&[u8]>,
        VerifyChecksum(verify_checksum): VerifyChecksum<Option<Ends<IpAddr>>>,
    ) -> Result<Udp, ParseErrorKind> {
        let buffer_len = packet.inner.len();
        if buffer_len < HEADER_LEN {
            return Err(ParseErrorKind::PacketTooShort);
        } else {
            let field_len = usize::from(packet.len());
            if buffer_len < field_len || field_len < HEADER_LEN {
                return Err(ParseErrorKind::PacketTooShort);
            }
        }

        if packet.dst_port() == 0 {
            return Err(ParseErrorKind::DstInvalid);
        }

        if let Some(addr) = verify_checksum
            && !packet.verify_checksum(addr)
            && !matches!(addr, (Src(IpAddr::V4(_)), Dst(IpAddr::V4(_))) if packet.checksum() == 0)
        {
            return Err(ParseErrorKind::ChecksumInvalid);
        }

        Ok(Udp { port: packet.port() })
    }

    fn build_packet(self, mut packet: Packet<&mut [u8]>, _: usize) -> Result<(), BuildErrorKind> {
        let len = u16::try_from(packet.inner.len()).map_err(|_| BuildErrorKind::PayloadTooLong)?;
        packet.set_len(len);

        let Udp { port: (Src(src), Dst(dst)) } = self;
        packet.set_src_port(src);
        packet.set_dst_port(dst);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use core::net::Ipv4Addr;
    use std::vec;

    use super::*;
    use crate::{storage::Buf, wire::WireExt};

    const SRC_ADDR: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 1);
    const DST_ADDR: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 2);
    const ADDR: Ends<IpAddr> = (Src(IpAddr::V4(SRC_ADDR)), Dst(IpAddr::V4(DST_ADDR)));

    const PACKET_BYTES: [u8; 12] = [
        0xbf, 0x00, 0x00, 0x35, 0x00, 0x0c, 0x12, 0x4d, 0xaa, 0x00, 0x00, 0xff,
    ];

    const PAYLOAD_BYTES: [u8; 4] = [0xaa, 0x00, 0x00, 0xff];

    #[test]
    fn test_deconstruct() {
        let mut fb = PACKET_BYTES;
        let packet = Packet::parse(Buf::full(&mut fb[..]), VerifyChecksum(Some(ADDR))).unwrap();
        assert_eq!(packet.src_port(), 48896);
        assert_eq!(packet.dst_port(), 53);
        assert_eq!(packet.len(), 12);
        assert_eq!(packet.checksum(), 0x124d);
        assert_eq!(packet.payload(), &PAYLOAD_BYTES[..]);
        assert!(packet.verify_checksum(ADDR));
    }

    #[test]
    fn test_construct() {
        let tag = Udp { port: (Src(48896), Dst(53)) };

        let bytes = vec![0xa5; 12];
        let mut payload = Buf::builder(bytes).reserve_for(&tag).build();
        payload.append_slice(&PAYLOAD_BYTES[..]);

        let mut packet = tag.build(payload).unwrap();
        packet.fill_checksum(ADDR);
        assert_eq!(packet.into_raw().data(), &PACKET_BYTES[..]);
    }

    #[test]
    fn test_zero_checksum() {
        let tag = Udp { port: (Src(1), Dst(31881)) };

        let payload = Buf::builder(vec![0; 8]).reserve_for(&tag).build();
        let mut packet = tag.build(payload).unwrap();
        packet.fill_checksum(ADDR);
        assert_eq!(packet.checksum(), 0xffff);
    }

    #[test]
    fn test_no_checksum() {
        let tag = Udp { port: (Src(1), Dst(31881)) };

        let payload = Buf::builder(vec![0; 8]).reserve_for(&tag).build();
        let packet = tag.build(payload).unwrap();
        assert!(packet.verify_checksum(ADDR));
    }
}
