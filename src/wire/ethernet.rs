use core::fmt;

use byteorder::{ByteOrder, NetworkEndian};

use crate::{
    self as cutenet,
    context::Ends,
    wire::{prelude::*, Data, DataMut},
};

#[derive(Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Default)]
pub struct Addr(pub [u8; 6]);

impl Addr {
    /// The broadcast address.
    pub const BROADCAST: Addr = Addr([0xff; 6]);

    /// Construct an Ethernet address from a sequence of octets, in big-endian.
    ///
    /// # Panics
    /// The function panics if `data` is not six octets long.
    pub fn from_bytes(data: &[u8]) -> Addr {
        let mut bytes = [0; 6];
        bytes.copy_from_slice(data);
        Addr(bytes)
    }

    /// Return an Ethernet address as a sequence of octets, in big-endian.
    pub const fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Query whether the address is an unicast address.
    pub fn is_unicast(&self) -> bool {
        !(self.is_broadcast() || self.is_multicast())
    }

    /// Query whether this address is the broadcast address.
    pub fn is_broadcast(&self) -> bool {
        *self == Self::BROADCAST
    }

    /// Query whether the "multicast" bit in the OUI is set.
    pub const fn is_multicast(&self) -> bool {
        self.0[0] & 0x01 != 0
    }

    /// Query whether the "locally administered" bit in the OUI is set.
    pub const fn is_local(&self) -> bool {
        self.0[0] & 0x02 != 0
    }
}

impl fmt::Display for Addr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let [b0, b1, b2, b3, b4, b5] = self.0;
        write!(f, "{b0:02x}-{b1:02x}-{b2:02x}-{b3:02x}-{b4:02x}-{b5:02x}")
    }
}

enum_with_unknown! {
    /// Ethernet protocol type.
    pub enum Protocol(u16) {
        Ipv4 = 0x0800,
        Arp  = 0x0806,
        Ipv6 = 0x86DD,
    }
}

struct RawFrame<T: ?Sized>(T);

pub mod field {
    use crate::wire::field::*;

    pub const DESTINATION: Field = 0..6;
    pub const SOURCE: Field = 6..12;
    pub const ETHERTYPE: Field = 12..14;
    pub const PAYLOAD: Rest = 14..;
}
pub const HEADER_LEN: usize = field::PAYLOAD.start;

wire!(impl RawFrame {
    dst_addr/set_dst_addr: Addr =>
        |data| Addr::from_bytes(&data[field::DESTINATION]);
        |data, value| data[field::DESTINATION].copy_from_slice(value.as_bytes());

    src_addr/set_src_addr: Addr =>
        |data| Addr::from_bytes(&data[field::SOURCE]);
        |data, value| data[field::SOURCE].copy_from_slice(value.as_bytes());

    protocol/set_protocol: Protocol =>
        |data| Protocol::from(NetworkEndian::read_u16(&data[field::ETHERTYPE]));
        |data, value| NetworkEndian::write_u16(&mut data[field::ETHERTYPE], value.into());
});

impl<T: Data + ?Sized> RawFrame<T> {
    pub fn addr(&self) -> Ends<Addr> {
        Ends {
            src: self.src_addr(),
            dst: self.dst_addr(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Wire)]
pub struct Frame<#[wire] T> {
    pub addr: Ends<Addr>,
    pub protocol: Protocol,
    #[wire]
    pub payload: T,
}

impl<P: PayloadParse + Data, T: WireParse<Payload = P>> WireParse for Frame<T> {
    fn parse(cx: &mut WireCx, raw: P) -> Result<Self, ParseError<P>> {
        let len = raw.len();
        if len < HEADER_LEN {
            return Err(ParseErrorKind::PacketTooShort.with(raw));
        }

        let frame = RawFrame(raw);

        Ok(Frame {
            addr: frame.addr(),
            protocol: frame.protocol(),

            payload: T::parse(cx, frame.0.pop(HEADER_LEN..len)?)?,
        })
    }
}

impl<P: PayloadBuild, T: WireBuild<Payload = P>> WireBuild for Frame<T> {
    fn build(self, cx: &mut WireCx) -> Result<P, BuildError<P>> {
        let Frame {
            addr: Ends { src, dst },
            protocol: proto,
            payload,
        } = self;

        payload.build(cx)?.push(HEADER_LEN, |buf| {
            let mut frame = RawFrame(buf);
            frame.set_src_addr(src);
            frame.set_dst_addr(dst);
            frame.set_protocol(proto);
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    // Tests that are valid with any combination of
    // "proto-*" features.
    use super::*;

    #[test]
    fn test_broadcast() {
        assert!(Addr::BROADCAST.is_broadcast());
        assert!(!Addr::BROADCAST.is_unicast());
        assert!(Addr::BROADCAST.is_multicast());
        assert!(Addr::BROADCAST.is_local());
    }
}

#[cfg(test)]
mod test_ipv4 {
    use std::vec;

    // Tests that are valid only with "proto-ipv4"
    use super::*;
    use crate::storage::Buf;

    const FRAME_BYTES: [u8; 64] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x08, 0x00, 0xaa,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0xff,
    ];

    const PAYLOAD_BYTES: [u8; 50] = [
        0xaa, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0xff,
    ];

    #[test]
    fn test_deconstruct() {
        let mut fb = FRAME_BYTES;
        let frame: Frame<Buf<_>> = Frame::parse(&mut false.into(), Buf::full(&mut fb[..])).unwrap();
        assert_eq!(frame.addr, Ends {
            src: Addr([0x11, 0x12, 0x13, 0x14, 0x15, 0x16]),
            dst: Addr([0x01, 0x02, 0x03, 0x04, 0x05, 0x06]),
        },);
        assert_eq!(frame.protocol, Protocol::Ipv4);
        assert_eq!(frame.payload.data(), &PAYLOAD_BYTES[..]);
    }

    #[test]
    fn test_construct() {
        let tag = Frame {
            addr: Ends {
                src: Addr([0x11, 0x12, 0x13, 0x14, 0x15, 0x16]),
                dst: Addr([0x01, 0x02, 0x03, 0x04, 0x05, 0x06]),
            },
            protocol: Protocol::Ipv4,
            payload: PayloadHolder(PAYLOAD_BYTES.len()),
        };

        let bytes = vec![0xa5; 64];
        let mut payload = Buf::builder(bytes).reserve_for(tag).build();
        payload.append_slice(&PAYLOAD_BYTES[..]);

        let frame = tag
            .sub_payload(|_| payload)
            .build(&mut false.into())
            .unwrap();
        assert_eq!(frame.data(), &FRAME_BYTES[..]);
    }
}

#[cfg(test)]
mod test_ipv6 {
    use std::vec;

    // Tests that are valid only with "proto-ipv6"
    use super::*;
    use crate::storage::Buf;

    const FRAME_BYTES: [u8; 54] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x86, 0xdd, 0x60,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
    ];

    const PAYLOAD_BYTES: [u8; 40] = [
        0x60, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
    ];

    #[test]
    fn test_deconstruct() {
        let mut binding = FRAME_BYTES;
        let frame: Frame<Buf<_>> =
            Frame::parse(&mut false.into(), Buf::full(&mut binding[..])).unwrap();
        assert_eq!(frame.addr, Ends {
            src: Addr([0x11, 0x12, 0x13, 0x14, 0x15, 0x16]),
            dst: Addr([0x01, 0x02, 0x03, 0x04, 0x05, 0x06]),
        });
        assert_eq!(frame.protocol, Protocol::Ipv6);
        assert_eq!(frame.payload.data(), &PAYLOAD_BYTES[..]);
    }

    #[test]
    fn test_construct() {
        let tag = Frame {
            addr: Ends {
                src: Addr([0x11, 0x12, 0x13, 0x14, 0x15, 0x16]),
                dst: Addr([0x01, 0x02, 0x03, 0x04, 0x05, 0x06]),
            },
            protocol: Protocol::Ipv6,
            payload: PayloadHolder(PAYLOAD_BYTES.len()),
        };

        let bytes = vec![0xa5; 54];

        let mut payload = Buf::builder(bytes).reserve_for(tag).build();
        payload.append_slice(&PAYLOAD_BYTES[..]);

        let frame = tag
            .sub_payload(|_| payload)
            .build(&mut false.into())
            .unwrap();
        assert_eq!(frame.data(), &FRAME_BYTES[..]);
    }
}
