use core::net::Ipv4Addr;

use byteorder::{ByteOrder, NetworkEndian};

use super::{
    ethernet::{self, Protocol},
    ip::IpAddrExt,
    BuildErrorKind, Builder, Dst, Ends, ParseErrorKind, Src, Wire,
};
use crate::storage::Storage;

enum_with_unknown! {
    /// ARP hardware type.
    pub enum Hardware(u16) {
        Ethernet = 1,
    }
}

enum_with_unknown! {
    /// ARP operation type.
    pub enum Operation(u16) {
        Request = 1,
        Reply = 2,
    }
}

mod field {
    #![allow(non_snake_case)]

    use crate::wire::field::*;

    pub const HTYPE: Field = 0..2;
    pub const PTYPE: Field = 2..4;
    pub const HLEN: usize = 4;
    pub const PLEN: usize = 5;
    pub const OPER: Field = 6..8;

    #[inline]
    pub const fn SHA(hardware_len: u8, _protocol_len: u8) -> Field {
        let start = OPER.end;
        start..(start + hardware_len as usize)
    }

    #[inline]
    pub const fn SPA(hardware_len: u8, protocol_len: u8) -> Field {
        let start = SHA(hardware_len, protocol_len).end;
        start..(start + protocol_len as usize)
    }

    #[inline]
    pub const fn THA(hardware_len: u8, protocol_len: u8) -> Field {
        let start = SPA(hardware_len, protocol_len).end;
        start..(start + hardware_len as usize)
    }

    #[inline]
    pub const fn TPA(hardware_len: u8, protocol_len: u8) -> Field {
        let start = THA(hardware_len, protocol_len).end;
        start..(start + protocol_len as usize)
    }
}

pub const HARDWARE_LEN: u8 = 6;
pub const PROTOCOL_LEN: u8 = 4;
pub const HEADER_LEN: usize = field::TPA(HARDWARE_LEN, PROTOCOL_LEN).end;

pub enum ArpV4 {}
pub type Packet<S: Storage + ?Sized> = super::Packet<ArpV4, S>;

impl<S: Storage + ?Sized> Packet<S> {
    pub fn hardware_type(&self) -> Hardware {
        Hardware::from(NetworkEndian::read_u16(&self.inner.data()[field::HTYPE]))
    }

    fn set_hardware_type(&mut self, value: Hardware) {
        NetworkEndian::write_u16(&mut self.inner.data_mut()[field::HTYPE], value.into())
    }

    /// Return the protocol type field.
    pub fn protocol_type(&self) -> Protocol {
        Protocol::from(NetworkEndian::read_u16(&self.inner.data()[field::PTYPE]))
    }

    fn set_protocol_type(&mut self, value: Protocol) {
        NetworkEndian::write_u16(&mut self.inner.data_mut()[field::PTYPE], value.into())
    }

    /// Return the hardware length field.
    pub fn hardware_len(&self) -> u8 {
        self.inner.data()[field::HLEN]
    }

    fn set_hardware_len(&mut self, value: u8) {
        self.inner.data_mut()[field::HLEN] = value
    }

    /// Return the protocol length field.
    pub fn protocol_len(&self) -> u8 {
        self.inner.data()[field::PLEN]
    }

    fn set_protocol_len(&mut self, value: u8) {
        self.inner.data_mut()[field::PLEN] = value
    }

    /// Return the operation field.
    pub fn operation(&self) -> Operation {
        Operation::from(NetworkEndian::read_u16(&self.inner.data()[field::OPER]))
    }

    fn set_operation(&mut self, value: Operation) {
        NetworkEndian::write_u16(&mut self.inner.data_mut()[field::OPER], value.into())
    }

    /// Return the source hardware address field.
    pub fn source_hardware_addr(&self) -> ethernet::Addr {
        ethernet::Addr::from_bytes(&self.inner.data()[field::SHA(HARDWARE_LEN, PROTOCOL_LEN)])
    }

    fn set_source_hardware_addr(&mut self, value: ethernet::Addr) {
        let index = field::SHA(HARDWARE_LEN, PROTOCOL_LEN);
        self.inner.data_mut()[index].copy_from_slice(value.as_bytes())
    }

    /// Return the source protocol address field.
    pub fn source_protocol_addr(&self) -> Ipv4Addr {
        Ipv4Addr::from_bytes(&self.inner.data()[field::SPA(HARDWARE_LEN, PROTOCOL_LEN)])
    }

    fn set_source_protocol_addr(&mut self, value: Ipv4Addr) {
        self.inner.data_mut()[field::SPA(HARDWARE_LEN, PROTOCOL_LEN)]
            .copy_from_slice(&value.octets())
    }

    /// Return the target hardware address field.
    pub fn target_hardware_addr(&self) -> ethernet::Addr {
        ethernet::Addr::from_bytes(&self.inner.data()[field::THA(HARDWARE_LEN, PROTOCOL_LEN)])
    }

    fn set_target_hardware_addr(&mut self, value: ethernet::Addr) {
        let index = field::THA(HARDWARE_LEN, PROTOCOL_LEN);
        self.inner.data_mut()[index].copy_from_slice(value.as_bytes())
    }

    /// Return the target protocol address field.
    pub fn target_protocol_addr(&self) -> Ipv4Addr {
        Ipv4Addr::from_bytes(&self.inner.data()[field::TPA(HARDWARE_LEN, PROTOCOL_LEN)])
    }

    fn set_target_protocol_addr(&mut self, value: Ipv4Addr) {
        self.inner.data_mut()[field::TPA(HARDWARE_LEN, PROTOCOL_LEN)]
            .copy_from_slice(&value.octets())
    }

    pub fn addr(&self) -> Ends<(ethernet::Addr, Ipv4Addr)> {
        (
            Src((self.source_hardware_addr(), self.source_protocol_addr())),
            Dst((self.target_hardware_addr(), self.target_protocol_addr())),
        )
    }
}

impl Wire for ArpV4 {
    const EMPTY_PAYLOAD: bool = true;

    const HEAD_LEN: usize = HEADER_LEN;
    const TAIL_LEN: usize = 0;

    type ParseArg<'a> = ();
    fn parse<S: Storage>(packet: &Packet<S>, _: ()) -> Result<(), ParseErrorKind> {
        let len = packet.inner.len();
        if len < field::OPER.end
            || len < field::TPA(packet.hardware_len(), packet.protocol_len()).end
        {
            return Err(ParseErrorKind::PacketTooShort);
        }

        if !matches!(
            (
                packet.hardware_type(),
                packet.protocol_type(),
                packet.hardware_len(),
                packet.protocol_len(),
            ),
            (
                Hardware::Ethernet,
                Protocol::Ipv4,
                HARDWARE_LEN,
                PROTOCOL_LEN,
            )
        ) {
            return Err(ParseErrorKind::ProtocolUnknown);
        }

        Ok(())
    }

    fn build_default<S: Storage>(packet: &mut Packet<S>, _: usize) -> Result<(), BuildErrorKind> {
        packet.set_hardware_type(Hardware::Ethernet);
        packet.set_protocol_type(Protocol::Ipv4);
        packet.set_hardware_len(HARDWARE_LEN);
        packet.set_protocol_len(PROTOCOL_LEN);
        Ok(())
    }
}

impl<S: Storage> Builder<Packet<S>> {
    pub fn operation(mut self, op: Operation) -> Self {
        self.0.set_operation(op);
        self
    }

    pub fn addr(mut self, ends: Ends<(ethernet::Addr, Ipv4Addr)>) -> Self {
        let (Src((src_hd, src_ip)), Dst((dst_hd, dst_ip))) = ends;
        self.0.set_source_hardware_addr(src_hd);
        self.0.set_source_protocol_addr(src_ip);
        self.0.set_target_hardware_addr(dst_hd);
        self.0.set_target_protocol_addr(dst_ip);
        self
    }
}

#[cfg(test)]
mod tests {
    use std::vec;

    use super::*;
    use crate::storage::Buf;

    const PACKET_BYTES: [u8; 28] = [
        0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x01, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x21,
        0x22, 0x23, 0x24, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x41, 0x42, 0x43, 0x44,
    ];

    #[test]
    fn test_deconstruct() {
        let mut fb = PACKET_BYTES;
        let packet = Packet::parse(Buf::full(&mut fb[..]), ()).unwrap();

        assert_eq!(packet.hardware_type(), Hardware::Ethernet);
        assert_eq!(packet.protocol_type(), Protocol::Ipv4);
        assert_eq!(packet.hardware_len(), HARDWARE_LEN);
        assert_eq!(packet.protocol_len(), PROTOCOL_LEN);
        assert_eq!(packet.operation(), Operation::Request);
        assert_eq!(
            packet.source_hardware_addr(),
            ethernet::Addr([0x11, 0x12, 0x13, 0x14, 0x15, 0x16])
        );
        assert_eq!(
            packet.source_protocol_addr(),
            Ipv4Addr::from([0x21, 0x22, 0x23, 0x24])
        );
        assert_eq!(
            packet.target_hardware_addr(),
            ethernet::Addr([0x31, 0x32, 0x33, 0x34, 0x35, 0x36])
        );
        assert_eq!(
            packet.target_protocol_addr(),
            Ipv4Addr::from([0x41, 0x42, 0x43, 0x44])
        );
    }

    #[test]
    fn test_construct() {
        let bytes = vec![0xa5; 28];
        let payload = Buf::builder(bytes).reserve_for::<ArpV4>().build();

        let packet = Packet::builder(payload).unwrap();
        let packet = packet
            .operation(Operation::Request)
            .addr((
                Src((
                    ethernet::Addr([0x11, 0x12, 0x13, 0x14, 0x15, 0x16]),
                    Ipv4Addr::from([0x21, 0x22, 0x23, 0x24]),
                )),
                Dst((
                    ethernet::Addr([0x31, 0x32, 0x33, 0x34, 0x35, 0x36]),
                    Ipv4Addr::from([0x41, 0x42, 0x43, 0x44]),
                )),
            ))
            .build();
        assert_eq!(packet.into_raw().data(), &PACKET_BYTES[..]);
    }
}
