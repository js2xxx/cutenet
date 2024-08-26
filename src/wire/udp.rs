use core::net::IpAddr;

use byteorder::{ByteOrder, NetworkEndian};

use super::{
    ip::{self, checksum},
    Builder, Dst, Ends, Src, WireBuf,
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

#[derive(Debug)]
pub struct Packet<S: Storage + ?Sized> {
    inner: Buf<S>,
}

impl<S: Storage> Packet<S> {
    pub fn parse(
        raw: Buf<S>,
        verify_checksum: Option<Ends<IpAddr>>,
    ) -> Result<Packet<S>, ParseError> {
        let packet = Packet { inner: raw };

        let buffer_len = packet.inner.len();
        if buffer_len < HEADER_LEN {
            return Err(ParseError::PacketTooShort);
        } else {
            let field_len = usize::from(packet.len());
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

    const HEADER_LEN: usize = HEADER_LEN;

    type BuildError = BuildError;
    fn build_default(payload: Buf<S>) -> Result<Self, BuildError>
    where
        S: Sized,
    {
        let mut inner = payload;
        inner.prepend_fixed::<HEADER_LEN>();
        let mut packet = Packet { inner };

        let len = u16::try_from(packet.inner.len()).map_err(|_| BuildError(()))?;
        packet.set_len(len);
        packet.set_checksum(0);
        Ok(packet)
    }

    fn into_raw(self) -> Buf<S>
    where
        S: Sized,
    {
        self.inner
    }

    fn into_payload(self) -> Buf<S>
    where
        S: Sized,
    {
        self.inner.slice_into(HEADER_LEN..)
    }
}

impl<S: Storage + ?Sized> Packet<S> {
    pub fn src_port(&self) -> u16 {
        NetworkEndian::read_u16(&self.inner.data()[field::SRC_PORT])
    }

    pub fn dst_port(&self) -> u16 {
        NetworkEndian::read_u16(&self.inner.data()[field::DST_PORT])
    }

    pub fn port(&self) -> Ends<u16> {
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
}

impl<S: Storage + ?Sized> Packet<S> {
    fn set_src_port(&mut self, value: u16) {
        NetworkEndian::write_u16(&mut self.inner.data_mut()[field::SRC_PORT], value)
    }

    fn set_dst_port(&mut self, value: u16) {
        NetworkEndian::write_u16(&mut self.inner.data_mut()[field::DST_PORT], value)
    }

    fn set_len(&mut self, value: u16) {
        NetworkEndian::write_u16(&mut self.inner.data_mut()[field::LENGTH], value)
    }

    fn set_checksum(&mut self, value: u16) {
        NetworkEndian::write_u16(&mut self.inner.data_mut()[field::CHECKSUM], value)
    }
}

impl<S: Storage> Builder<Packet<S>> {
    pub fn port(mut self, port: Ends<u16>) -> Self {
        let (Src(src), Dst(dst)) = port;
        self.0.set_src_port(src);
        self.0.set_dst_port(dst);
        self
    }

    pub fn checksum(mut self, addr: Ends<IpAddr>) -> Self {
        let (Src(src), Dst(dst)) = addr;
        self.0.set_checksum(0);

        let len = self.0.len();
        let checksum = !checksum::combine(&[
            checksum::pseudo_header(&src, &dst, ip::Protocol::Udp, u32::from(len)),
            checksum::data(&self.0.inner.data()[..usize::from(len)]),
        ]);
        self.0
            .set_checksum(if checksum == 0 { 0xffff } else { checksum });
        self
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
    const ADDR: Ends<IpAddr> = (Src(IpAddr::V4(SRC_ADDR)), Dst(IpAddr::V4(DST_ADDR)));

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
        assert_eq!(packet.into_raw().data(), &PACKET_BYTES[..]);
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
