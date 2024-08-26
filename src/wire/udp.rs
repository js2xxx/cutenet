use core::{net::IpAddr, ops::Range};

use byteorder::{ByteOrder, NetworkEndian};

use super::{
    ip::{self, checksum},
    BuildErrorKind, Dst, Ends, ParseErrorKind, Src, VerifyChecksum, Wire,
};
use crate::storage::Storage;

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

#[derive(Debug)]
pub struct Udp {
    pub port: Ends<u16>,
}

pub type Packet<S: Storage + ?Sized> = super::Packet<Udp, S>;

impl<S: Storage + ?Sized> Packet<S> {
    pub fn src_port(&self) -> u16 {
        NetworkEndian::read_u16(&self.inner.data()[field::SRC_PORT])
    }

    fn set_src_port(&mut self, value: u16) {
        NetworkEndian::write_u16(&mut self.inner.data_mut()[field::SRC_PORT], value)
    }

    pub fn dst_port(&self) -> u16 {
        NetworkEndian::read_u16(&self.inner.data()[field::DST_PORT])
    }

    fn set_dst_port(&mut self, value: u16) {
        NetworkEndian::write_u16(&mut self.inner.data_mut()[field::DST_PORT], value)
    }

    pub fn port(&self) -> Ends<u16> {
        (Src(self.src_port()), Dst(self.dst_port()))
    }

    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> u16 {
        NetworkEndian::read_u16(&self.inner.data()[field::LENGTH])
    }

    fn set_len(&mut self, value: u16) {
        NetworkEndian::write_u16(&mut self.inner.data_mut()[field::LENGTH], value)
    }

    pub fn checksum(&self) -> u16 {
        NetworkEndian::read_u16(&self.inner.data()[field::CHECKSUM])
    }

    fn set_checksum(&mut self, value: u16) {
        NetworkEndian::write_u16(&mut self.inner.data_mut()[field::CHECKSUM], value)
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
            checksum::data(&self.inner.data()[..usize::from(self.len())]),
        ]) == !0
    }

    pub fn fill_checksum(&mut self, addr: Ends<IpAddr>) {
        let (Src(src), Dst(dst)) = addr;
        self.set_checksum(0);

        let len = self.len();
        let checksum = !checksum::combine(&[
            checksum::pseudo_header(&src, &dst, ip::Protocol::Udp, u32::from(len)),
            checksum::data(&self.inner.data()[..usize::from(len)]),
        ]);
        self.set_checksum(if checksum == 0 { 0xffff } else { checksum });
    }
}

impl Wire for Udp {
    const EMPTY_PAYLOAD: bool = false;

    fn header_len(&self) -> usize {
        HEADER_LEN
    }

    fn buffer_len(&self, payload_len: usize) -> usize {
        HEADER_LEN + payload_len
    }

    fn payload_range<S: Storage + ?Sized>(packet: &super::Packet<Self, S>) -> Range<usize> {
        HEADER_LEN..packet.inner.len()
    }

    type ParseArg<'a> = VerifyChecksum<Option<Ends<IpAddr>>>;
    fn parse_packet<S>(
        packet: &Packet<S>,
        VerifyChecksum(verify_checksum): VerifyChecksum<Option<Ends<IpAddr>>>,
    ) -> Result<(), ParseErrorKind>
    where
        S: Storage,
    {
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

        Ok(())
    }

    fn build_packet<S: Storage>(
        self,
        packet: &mut Packet<S>,
        _: usize,
    ) -> Result<(), BuildErrorKind> {
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
