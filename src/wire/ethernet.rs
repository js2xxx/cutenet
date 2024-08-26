use core::{fmt, ops::Range};

use byteorder::{ByteOrder, NetworkEndian};

use super::{BuildErrorKind, Data, DataMut, Dst, Ends, ParseErrorKind, Src, Wire};

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

pub type Frame<T: ?Sized> = super::Packet<Ethernet, T>;

pub mod field {
    use crate::wire::field::*;

    pub const DESTINATION: Field = 0..6;
    pub const SOURCE: Field = 6..12;
    pub const ETHERTYPE: Field = 12..14;
    pub const PAYLOAD: Rest = 14..;
}
pub const HEADER_LEN: usize = field::PAYLOAD.start;

wire!(impl Frame {
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

impl<T: Data + ?Sized> Frame<T> {
    pub fn addr(&self) -> Ends<Addr> {
        (Src(self.src_addr()), Dst(self.dst_addr()))
    }
}

#[derive(Debug)]
pub struct Ethernet {
    pub addr: Ends<Addr>,
    pub proto: Protocol,
}

impl Wire for Ethernet {
    const EMPTY_PAYLOAD: bool = false;

    fn header_len(&self) -> usize {
        HEADER_LEN
    }

    fn buffer_len(&self, payload_len: usize) -> usize {
        HEADER_LEN + payload_len
    }

    fn payload_range(frame: Frame<&[u8]>) -> Range<usize> {
        HEADER_LEN..frame.inner.len()
    }

    type ParseArg<'a> = ();
    fn parse_packet(frame: Frame<&[u8]>, _: ()) -> Result<Ethernet, ParseErrorKind> {
        if frame.inner.len() < HEADER_LEN {
            return Err(ParseErrorKind::PacketTooShort);
        }
        Ok(Ethernet {
            addr: frame.addr(),
            proto: frame.protocol(),
        })
    }

    fn build_packet(self, mut frame: Frame<&mut [u8]>, _: usize) -> Result<(), BuildErrorKind> {
        let Ethernet {
            addr: (Src(src), Dst(dst)),
            proto,
        } = self;
        frame.set_src_addr(src);
        frame.set_dst_addr(dst);
        frame.set_protocol(proto);
        Ok(())
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
    use crate::{storage::Buf, wire::WireExt};

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
        let frame = Frame::parse(Buf::full(&mut fb[..]), ()).unwrap();
        assert_eq!(frame.dst_addr(), Addr([0x01, 0x02, 0x03, 0x04, 0x05, 0x06]));
        assert_eq!(frame.src_addr(), Addr([0x11, 0x12, 0x13, 0x14, 0x15, 0x16]));
        assert_eq!(frame.protocol(), Protocol::Ipv4);
        assert_eq!(frame.payload(), &PAYLOAD_BYTES[..]);
    }

    #[test]
    fn test_construct() {
        let tag = Ethernet {
            addr: (
                Src(Addr([0x11, 0x12, 0x13, 0x14, 0x15, 0x16])),
                Dst(Addr([0x01, 0x02, 0x03, 0x04, 0x05, 0x06])),
            ),
            proto: Protocol::Ipv4,
        };

        let bytes = vec![0xa5; 64];
        let mut payload = Buf::builder(bytes).reserve_for(&tag).build();
        payload
            .append(PAYLOAD_BYTES.len())
            .copy_from_slice(&PAYLOAD_BYTES[..]);

        let frame = tag.build(payload).unwrap();
        assert_eq!(frame.into_raw().data(), &FRAME_BYTES[..]);
    }
}

#[cfg(test)]
mod test_ipv6 {
    use std::vec;

    // Tests that are valid only with "proto-ipv6"
    use super::*;
    use crate::{storage::Buf, wire::WireExt};

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
        let frame = Frame::parse(Buf::full(&mut binding[..]), ()).unwrap();
        assert_eq!(frame.dst_addr(), Addr([0x01, 0x02, 0x03, 0x04, 0x05, 0x06]));
        assert_eq!(frame.src_addr(), Addr([0x11, 0x12, 0x13, 0x14, 0x15, 0x16]));
        assert_eq!(frame.protocol(), Protocol::Ipv6);
        assert_eq!(frame.payload(), &PAYLOAD_BYTES[..]);
    }

    #[test]
    fn test_construct() {
        let tag = Ethernet {
            addr: (
                Src(Addr([0x11, 0x12, 0x13, 0x14, 0x15, 0x16])),
                Dst(Addr([0x01, 0x02, 0x03, 0x04, 0x05, 0x06])),
            ),
            proto: Protocol::Ipv6,
        };

        let bytes = vec![0xa5; 54];

        let mut payload = Buf::builder(bytes).reserve_for(&tag).build();
        payload
            .append(PAYLOAD_BYTES.len())
            .copy_from_slice(&PAYLOAD_BYTES[..]);

        let frame = tag.build(payload).unwrap();
        assert_eq!(frame.into_raw().data(), &FRAME_BYTES[..]);
    }
}
