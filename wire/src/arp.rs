use core::net::Ipv4Addr;

use byteorder::{ByteOrder, NetworkEndian};

use crate::{
    context::{Ends, WireCx},
    ethernet,
    ip::IpAddrExt,
    prelude::*,
};

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

struct RawPacket<T: ?Sized>(T);

mod field {
    #![allow(non_snake_case)]

    use crate::field::*;

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

wire!(impl RawPacket {
    /// Return the hardware type field.
    hardware_type/set_hardware_type: Hardware =>
        |data| Hardware::from(NetworkEndian::read_u16(&data[field::HTYPE]));
        |data, value| NetworkEndian::write_u16(&mut data[field::HTYPE], value.into());

    /// Return the protocol type field.
    protocol_type/set_protocol_type: ethernet::Protocol =>
        |data| ethernet::Protocol::from(NetworkEndian::read_u16(&data[field::PTYPE]));
        |data, value| NetworkEndian::write_u16(&mut data[field::PTYPE], value.into());

    /// Return the hardware length field.
    hardware_len/set_hardware_len: u8 =>
        |data| data[field::HLEN];
        |data, value| data[field::HLEN] = value;

    /// Return the protocol length field.
    protocol_len/set_protocol_len: u8 =>
        |data| data[field::PLEN];
        |data, value| data[field::PLEN] = value;

    /// Return the operation field.
    operation/set_operation: Operation =>
        |data| Operation::from(NetworkEndian::read_u16(&data[field::OPER]));
        |data, value| NetworkEndian::write_u16(&mut data[field::OPER], value.into());

    /// Return the source hardware address field.
    source_hardware_addr/set_source_hardware_addr: ethernet::Addr =>
        |data| ethernet::Addr::from_bytes(&data[field::SHA(HARDWARE_LEN, PROTOCOL_LEN)]);
        |data, value| {
            let index = field::SHA(HARDWARE_LEN, PROTOCOL_LEN);
            data[index].copy_from_slice(value.as_bytes())
        };

    /// Return the source protocol address field.
    source_protocol_addr/set_source_protocol_addr: Ipv4Addr =>
        |data| Ipv4Addr::from_bytes(&data[field::SPA(HARDWARE_LEN, PROTOCOL_LEN)]);
        |data, value| {
            data[field::SPA(HARDWARE_LEN, PROTOCOL_LEN)].copy_from_slice(&value.octets())
        };

    /// Return the target hardware address field.
    target_hardware_addr/set_target_hardware_addr: ethernet::Addr =>
        |data| ethernet::Addr::from_bytes(&data[field::THA(HARDWARE_LEN, PROTOCOL_LEN)]);
        |data, value| {
            let index = field::THA(HARDWARE_LEN, PROTOCOL_LEN);
            data[index].copy_from_slice(value.as_bytes())
        };

    /// Return the target protocol address field.
    target_protocol_addr/set_target_protocol_addr: Ipv4Addr =>
        |data| Ipv4Addr::from_bytes(&data[field::TPA(HARDWARE_LEN, PROTOCOL_LEN)]);
        |data, value| {
            data[field::TPA(HARDWARE_LEN, PROTOCOL_LEN)].copy_from_slice(&value.octets())
        };
});

impl<T: AsRef<[u8]> + ?Sized> RawPacket<T> {
    pub fn addr(&self) -> Ends<(ethernet::Addr, Ipv4Addr)> {
        Ends {
            src: (self.source_hardware_addr(), self.source_protocol_addr()),
            dst: (self.target_hardware_addr(), self.target_protocol_addr()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Wire)]
#[prefix(crate)]
pub struct Packet<#[no_payload] U> {
    pub operation: Operation,
    pub addr: Ends<(ethernet::Addr, Ipv4Addr)>,
    #[no_payload]
    pub payload: U,
}

impl<P, U> WireParse for Packet<U>
where
    P: PayloadParse<NoPayload = U>,
    U: NoPayload<Init = P>,
{
    fn parse(_: &dyn WireCx, raw: P) -> Result<Self, ParseError<P>> {
        let packet = RawPacket(raw.header_data());
        let len = packet.0.len();
        if len < field::OPER.end
            || len < field::TPA(packet.hardware_len(), packet.protocol_len()).end
        {
            return Err(ParseErrorKind::PacketTooShort.with(raw));
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
                ethernet::Protocol::Ipv4,
                HARDWARE_LEN,
                PROTOCOL_LEN,
            )
        ) {
            return Err(ParseErrorKind::ProtocolUnknown.with(raw));
        }

        Ok(Packet {
            operation: packet.operation(),
            addr: packet.addr(),
            payload: raw.truncate(),
        })
    }
}

impl<P, U> WireBuild for Packet<U>
where
    P: PayloadBuild<NoPayload = U>,
    U: NoPayload<Init = P>,
{
    fn buffer_len(&self) -> usize {
        HEADER_LEN + self.payload_len()
    }

    fn build(self, _: &dyn WireCx) -> Result<P, BuildError<P>> {
        let Packet {
            operation,
            addr: Ends { src, dst },
            payload,
        } = self;

        payload.init().push(HEADER_LEN, |buf, _| {
            let mut packet = RawPacket(buf);

            packet.set_hardware_type(Hardware::Ethernet);
            packet.set_protocol_type(ethernet::Protocol::Ipv4);
            packet.set_hardware_len(HARDWARE_LEN);
            packet.set_protocol_len(PROTOCOL_LEN);

            packet.set_operation(operation);
            let (src_hw, src_ip) = src;
            let (dst_hw, dst_ip) = dst;
            packet.set_source_hardware_addr(src_hw);
            packet.set_source_protocol_addr(src_ip);
            packet.set_target_hardware_addr(dst_hw);
            packet.set_target_protocol_addr(dst_ip);

            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use std::vec;

    use cutenet_storage::NoPayloadHolder;

    use super::*;

    const PACKET_BYTES: [u8; 28] = [
        0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x01, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x21,
        0x22, 0x23, 0x24, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x41, 0x42, 0x43, 0x44,
    ];

    #[test]
    fn test_deconstruct() {
        let packet = Packet::parse(&(), &PACKET_BYTES[..]).unwrap();

        assert_eq!(packet.operation, Operation::Request);
        assert_eq!(packet.addr, Ends {
            src: (
                ethernet::Addr([0x11, 0x12, 0x13, 0x14, 0x15, 0x16]),
                Ipv4Addr::from([0x21, 0x22, 0x23, 0x24]),
            ),
            dst: (
                ethernet::Addr([0x31, 0x32, 0x33, 0x34, 0x35, 0x36]),
                Ipv4Addr::from([0x41, 0x42, 0x43, 0x44]),
            ),
        });
    }

    #[test]
    fn test_construct() {
        let tag = Packet {
            operation: Operation::Request,
            addr: Ends {
                src: (
                    ethernet::Addr([0x11, 0x12, 0x13, 0x14, 0x15, 0x16]),
                    Ipv4Addr::from([0x21, 0x22, 0x23, 0x24]),
                ),
                dst: (
                    ethernet::Addr([0x31, 0x32, 0x33, 0x34, 0x35, 0x36]),
                    Ipv4Addr::from([0x41, 0x42, 0x43, 0x44]),
                ),
            },
            payload: NoPayloadHolder,
        };

        let bytes = vec![0xa5; 28];
        let payload = bytes.reset().reserve(tag.buffer_len());

        let packet = tag.sub_no_payload(|_| payload).build(&()).unwrap();
        assert_eq!(packet, &PACKET_BYTES[..]);
    }
}
