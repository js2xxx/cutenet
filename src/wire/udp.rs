use core::net::IpAddr;

use byteorder::{ByteOrder, NetworkEndian};

use super::{
    ip::{self, checksum},
    Dst, Src, WireBuf,
};
use crate::storage::{Buf, Storage};

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

pub struct Packet<S: Storage + ?Sized> {
    inner: Buf<S>,
}

impl<S: Storage> Packet<S> {
    pub fn builder(payload: Buf<S>) -> Result<PacketBuilder<S>, BuildError> {
        PacketBuilder::new(payload)
    }

    pub fn parse(
        raw: Buf<S>,
        verify_checksum: Option<(Src<IpAddr>, Dst<IpAddr>)>,
    ) -> Result<Packet<S>, ParseError> {
        let packet = Packet { inner: raw };

        let buffer_len = packet.inner.len();
        if buffer_len < HEADER_LEN {
            return Err(ParseError::PacketTooShort);
        } else {
            let field_len = packet.len() as usize;
            if buffer_len < field_len || field_len < HEADER_LEN {
                return Err(ParseError::PacketTooShort);
            }
        }

        if packet.dst_port() == 0 {
            return Err(ParseError::DstInvalid);
        }

        if let Some(addr) = verify_checksum
            && !packet.verify_checksum(addr)
            && !matches!(addr, (Src(IpAddr::V4(_)), Dst(IpAddr::V4(_))) if packet.checksum() == 0)
        {
            return Err(ParseError::ChecksumInvalid);
        }

        Ok(packet)
    }
}

impl<S: Storage + ?Sized> WireBuf for Packet<S> {
    type Storage = S;

    const RESERVE: usize = HEADER_LEN;

    fn into_inner(self) -> Buf<Self::Storage>
    where
        S: Sized,
    {
        self.inner
    }

    fn into_payload(mut self) -> Buf<Self::Storage>
    where
        S: Sized,
    {
        self.inner.append_head_fixed::<HEADER_LEN>();
        self.inner
    }
}

impl<S: Storage + ?Sized> Packet<S> {
    pub fn src_port(&self) -> u16 {
        NetworkEndian::read_u16(&self.inner.data()[field::SRC_PORT])
    }

    pub fn dst_port(&self) -> u16 {
        NetworkEndian::read_u16(&self.inner.data()[field::DST_PORT])
    }

    pub fn port(&self) -> (Src<u16>, Dst<u16>) {
        (Src(self.src_port()), Dst(self.dst_port()))
    }

    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> u16 {
        NetworkEndian::read_u16(&self.inner.data()[field::LENGTH])
    }

    pub fn checksum(&self) -> u16 {
        NetworkEndian::read_u16(&self.inner.data()[field::CHECKSUM])
    }

    pub fn payload(&self) -> &[u8] {
        &self.inner.data()[field::PAYLOAD]
    }

    pub fn verify_checksum(&self, addr: (Src<IpAddr>, Dst<IpAddr>)) -> bool {
        let (Src(src), Dst(dst)) = addr;
        // From the RFC:
        // > An all zero transmitted checksum value means that the transmitter
        // > generated no checksum (for debugging or for higher level protocols
        // > that don't care).
        if self.checksum() == 0 {
            return true;
        }

        checksum::combine(&[
            checksum::pseudo_header(&src, &dst, ip::Protocol::Udp, self.len() as u32),
            checksum::data(&self.inner.data()[..self.len() as usize]),
        ]) == !0
    }
}

pub struct PacketBuilder<S: Storage + ?Sized> {
    inner: Buf<S>,
}

impl<S: Storage + ?Sized> PacketBuilder<S> {
    fn set_src_port(&mut self, value: u16) {
        NetworkEndian::write_u16(&mut self.inner.data_mut()[field::SRC_PORT], value)
    }

    fn set_dst_port(&mut self, value: u16) {
        NetworkEndian::write_u16(&mut self.inner.data_mut()[field::DST_PORT], value)
    }

    fn len(&self) -> u16 {
        NetworkEndian::read_u16(&self.inner.data()[field::LENGTH])
    }

    fn set_len(&mut self, value: u16) {
        NetworkEndian::write_u16(&mut self.inner.data_mut()[field::LENGTH], value)
    }

    fn set_checksum(&mut self, value: u16) {
        NetworkEndian::write_u16(&mut self.inner.data_mut()[field::CHECKSUM], value)
    }
}

impl<S: Storage> PacketBuilder<S> {
    fn new(payload: Buf<S>) -> Result<Self, BuildError> {
        let mut inner = payload;
        inner.prepend_fixed::<HEADER_LEN>();
        let mut ret = PacketBuilder { inner };

        let len = u16::try_from(ret.inner.len()).map_err(|_| BuildError(()))?;
        ret.set_len(len);
        ret.set_checksum(0);
        Ok(ret)
    }

    pub fn port(mut self, port: (Src<u16>, Dst<u16>)) -> Self {
        let (Src(src), Dst(dst)) = port;
        self.set_src_port(src);
        self.set_dst_port(dst);
        self
    }

    pub fn checksum(mut self, addr: (Src<IpAddr>, Dst<IpAddr>)) -> Self {
        let (Src(src), Dst(dst)) = addr;
        self.set_checksum(0);
        let checksum = !checksum::combine(&[
            checksum::pseudo_header(&src, &dst, ip::Protocol::Udp, self.len() as u32),
            checksum::data(&self.inner.data()[..self.len() as usize]),
        ]);
        self.set_checksum(if checksum == 0 { 0xffff } else { checksum });
        self
    }

    pub fn build(self) -> Packet<S> {
        Packet { inner: self.inner }
    }
}

#[derive(Debug)]
pub struct BuildError(());

#[derive(Debug)]
pub enum ParseError {
    PacketTooShort,
    DstInvalid,
    ChecksumInvalid,
}

#[cfg(test)]
mod test {
    use core::net::Ipv4Addr;
    use std::vec;

    use super::*;

    const SRC_ADDR: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 1);
    const DST_ADDR: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 2);
    const ADDR: (Src<IpAddr>, Dst<IpAddr>) = (Src(IpAddr::V4(SRC_ADDR)), Dst(IpAddr::V4(DST_ADDR)));

    const PACKET_BYTES: [u8; 12] = [
        0xbf, 0x00, 0x00, 0x35, 0x00, 0x0c, 0x12, 0x4d, 0xaa, 0x00, 0x00, 0xff,
    ];

    const PAYLOAD_BYTES: [u8; 4] = [0xaa, 0x00, 0x00, 0xff];

    #[test]
    fn test_deconstruct() {
        let mut fb = PACKET_BYTES;
        let packet = Packet { inner: Buf::full(&mut fb[..]) };
        assert_eq!(packet.src_port(), 48896);
        assert_eq!(packet.dst_port(), 53);
        assert_eq!(packet.len(), 12);
        assert_eq!(packet.checksum(), 0x124d);
        assert_eq!(packet.payload(), &PAYLOAD_BYTES[..]);
        assert!(packet.verify_checksum(ADDR));
    }

    #[test]
    fn test_construct() {
        let bytes = vec![0xa5; 12];
        let mut payload = Buf::builder(bytes).reserve_for::<Packet<_>>().build();
        payload.append_slice(&PAYLOAD_BYTES[..]);

        let packet = Packet::builder(payload).unwrap();
        let packet = packet.port((Src(48896), Dst(53))).checksum(ADDR).build();
        assert_eq!(packet.into_inner().data(), &PACKET_BYTES[..]);
    }

    #[test]
    fn test_zero_checksum() {
        let payload = Buf::builder(vec![0; 8]).reserve_for::<Packet<_>>().build();
        let packet = Packet::builder(payload).unwrap();
        let packet = packet.port((Src(1), Dst(31881))).checksum(ADDR).build();
        assert_eq!(packet.checksum(), 0xffff);
    }

    #[test]
    fn test_no_checksum() {
        let payload = Buf::builder(vec![0; 8]).reserve_for::<Packet<_>>().build();
        let packet = Packet::builder(payload).unwrap();
        let packet = packet.port((Src(1), Dst(31881))).build();
        assert!(packet.verify_checksum(ADDR));
    }

    #[test]
    fn test_parse() {
        let mut fb = PACKET_BYTES;
        let packet = Packet::parse(Buf::full(&mut fb[..]), Some(ADDR)).unwrap();
        assert_eq!(packet.port(), (Src(48896), Dst(53)));
    }
}
