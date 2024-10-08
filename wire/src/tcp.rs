use core::{cmp, fmt, net::IpAddr, ops};

use byteorder::{ByteOrder, NetworkEndian};

use crate::{
    context::{Ends, WireCx},
    ip::{self, checksum},
    prelude::*,
};

mod opt;
pub use self::opt::{Control, TcpOption, TcpTimestamp, TcpTimestampGenerator};

bitflags::bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct TcpFlags: u16 {
        const FIN = 0x001;
        const SYN = 0x002;
        const RST = 0x004;
        const PSH = 0x008;
        const ACK = 0x010;
        const URG = 0x020;
        const ECE = 0x040;
        const CWR = 0x080;
        const NS = 0x100;

        const ALL = 0xfff;
    }
}

/// A TCP sequence number.
///
/// A sequence number is a monotonically advancing integer modulo
/// 2<sup>32</sup>. Sequence numbers do not have a discontiguity when compared
/// pairwise across a signed overflow.
#[derive(Debug, PartialEq, Eq, Clone, Copy, Default)]
pub struct SeqNumber(pub u32);

impl SeqNumber {
    pub fn max(self, rhs: Self) -> Self {
        if self > rhs {
            self
        } else {
            rhs
        }
    }

    pub fn min(self, rhs: Self) -> Self {
        if self < rhs {
            self
        } else {
            rhs
        }
    }
}

impl fmt::Display for SeqNumber {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl ops::Add<usize> for SeqNumber {
    type Output = SeqNumber;

    fn add(self, rhs: usize) -> SeqNumber {
        if rhs > i32::MAX as usize {
            panic!("attempt to add to sequence number with unsigned overflow")
        }
        SeqNumber(self.0.wrapping_add(rhs as u32))
    }
}

impl ops::Sub<usize> for SeqNumber {
    type Output = SeqNumber;

    fn sub(self, rhs: usize) -> SeqNumber {
        if rhs > i32::MAX as usize {
            panic!("attempt to subtract to sequence number with unsigned overflow")
        }
        SeqNumber(self.0.wrapping_sub(rhs as u32))
    }
}

impl ops::AddAssign<usize> for SeqNumber {
    fn add_assign(&mut self, rhs: usize) {
        *self = *self + rhs;
    }
}

impl ops::Sub for SeqNumber {
    type Output = usize;

    fn sub(self, rhs: SeqNumber) -> usize {
        if self < rhs {
            panic!("attempt to subtract sequence numbers with underflow")
        }
        let result = self.0.wrapping_sub(rhs.0);
        result as usize
    }
}

impl cmp::PartialOrd for SeqNumber {
    fn partial_cmp(&self, other: &SeqNumber) -> Option<cmp::Ordering> {
        (self.0.wrapping_sub(other.0) as i32).partial_cmp(&0)
    }
}

struct RawPacket<T: ?Sized>(T);

mod field {
    #![allow(non_snake_case)]

    use crate::field::*;

    pub const SRC_PORT: Field = 0..2;
    pub const DST_PORT: Field = 2..4;
    pub const SEQ_NUM: Field = 4..8;
    pub const ACK_NUM: Field = 8..12;
    pub const FLAGS: Field = 12..14;
    pub const WIN_SIZE: Field = 14..16;
    pub const CHECKSUM: Field = 16..18;
    pub const URGENT: Field = 18..20;

    pub const fn OPTIONS(length: u8) -> Field {
        URGENT.end..(length as usize)
    }

    pub const OPT_END: u8 = 0x00;
    pub const OPT_NOP: u8 = 0x01;
    pub const OPT_MSS: u8 = 0x02;
    pub const OPT_WS: u8 = 0x03;
    pub const OPT_SACKPERM: u8 = 0x04;
    pub const OPT_SACKRNG: u8 = 0x05;
    pub const OPT_TSTAMP: u8 = 0x08;
}

pub const HEADER_LEN: usize = field::URGENT.end;

wire!(impl RawPacket {
    src_port/set_src_port: u16 =>
        |data| NetworkEndian::read_u16(&data[field::SRC_PORT]);
        |data, value| NetworkEndian::write_u16(&mut data[field::SRC_PORT], value);

    dst_port/set_dst_port: u16 =>
        |data| NetworkEndian::read_u16(&data[field::DST_PORT]);
        |data, value| NetworkEndian::write_u16(&mut data[field::DST_PORT], value);

    seq_number/set_seq_number: SeqNumber =>
        |data| SeqNumber(NetworkEndian::read_u32(&data[field::SEQ_NUM]));
        |data, value| NetworkEndian::write_u32(&mut data[field::SEQ_NUM], value.0);

    ack_number/set_ack_number: SeqNumber =>
        |data| SeqNumber(NetworkEndian::read_u32(&data[field::ACK_NUM]));
        |data, value| NetworkEndian::write_u32(&mut data[field::ACK_NUM], value.0);

    flags/set_flags: TcpFlags =>
        |data| TcpFlags::from_bits_truncate(NetworkEndian::read_u16(&data[field::FLAGS]));
        |data, value| {
            let raw = NetworkEndian::read_u16(&data[field::FLAGS]);
            let raw = (raw & !TcpFlags::all().bits()) | value.bits();
            NetworkEndian::write_u16(&mut data[field::FLAGS], raw);
        };

    header_len/set_header_len: u8 =>
        |data| ((NetworkEndian::read_u16(&data[field::FLAGS]) >> 12) * 4) as u8;
        |data, value| {
            let raw = NetworkEndian::read_u16(&data[field::FLAGS]);
            let raw = (raw & !0xf000) | (u16::from(value) / 4) << 12;
            NetworkEndian::write_u16(&mut data[field::FLAGS], raw);
        };

    window_len/set_window_len: u16 =>
        |data| NetworkEndian::read_u16(&data[field::WIN_SIZE]);
        |data, value| NetworkEndian::write_u16(&mut data[field::WIN_SIZE], value);

    #[allow(unused)]
    checksum/set_checksum: u16 =>
        |data| NetworkEndian::read_u16(&data[field::CHECKSUM]);
        |data, value| NetworkEndian::write_u16(&mut data[field::CHECKSUM], value);

    #[allow(unused)]
    urgent_at/set_urgent_at: u16 =>
        |data| NetworkEndian::read_u16(&data[field::URGENT]);
        |data, value| NetworkEndian::write_u16(&mut data[field::URGENT], value);
});

macro_rules! wire_flags {
    ($($get:ident/$set:ident => $c:ident,)*) => {
        impl<T: AsRef<[u8]> + ?Sized> RawPacket<T> {
            $(
                #[allow(unused)]
                fn $get(&self) -> bool {
                    self.flags().contains(TcpFlags:: $c)
                }
            )*
        }

        impl<T: AsRef<[u8]> + AsMut<[u8]> + ?Sized> RawPacket<T> {
            $(
                #[allow(unused)]
                fn $set(&mut self, value: bool) {
                    self.set_flags(if value {
                        self.flags() | TcpFlags:: $c
                    } else {
                        self.flags() & !TcpFlags:: $c
                    })
                }
            )*
        }
    };
}

wire_flags! {
    fin/set_fin => FIN, syn/set_syn => SYN, rst/set_rst => RST,
    psh/set_psh => PSH, ack/set_ack => ACK, urg/set_urg => URG,
    ece/set_ece => ECE, cwr/set_cwr => CWR, ns/set_ns => NS,
}

impl<T: AsRef<[u8]> + ?Sized> RawPacket<T> {
    pub fn port(&self) -> Ends<u16> {
        Ends {
            src: self.src_port(),
            dst: self.dst_port(),
        }
    }

    /// Validate the packet checksum.
    ///
    /// # Panics
    ///
    /// This function panics unless `src_addr` and `dst_addr` belong to the same
    /// family, and that family is IPv4 or IPv6.
    pub fn verify_checksum<'a>(
        &self,
        addr: Ends<IpAddr>,
        next_iter: impl Iterator<Item = &'a [u8]>,
    ) -> bool {
        let (data_sum, data_len) = checksum::data_iter(self.0.as_ref(), next_iter);
        checksum::combine(&[
            checksum::pseudo_header(&addr.src, &addr.dst, ip::Protocol::Tcp, data_len as u32),
            data_sum,
        ]) == !0
    }

    pub fn options(&self) -> &[u8] {
        &self.0.as_ref()[field::OPTIONS(self.header_len())]
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]> + ?Sized> RawPacket<T> {
    /// Compute and fill in the header checksum.
    ///
    /// # Panics
    /// This function panics unless `src_addr` and `dst_addr` belong to the same
    /// family, and that family is IPv4 or IPv6.
    pub fn fill_checksum<'a>(
        &mut self,
        addr: Ends<IpAddr>,
        next_iter: impl Iterator<Item = &'a [u8]>,
    ) {
        self.set_checksum(0);
        let (data_sum, data_len) = checksum::data_iter(self.0.as_ref(), next_iter);
        let checksum = !checksum::combine(&[
            checksum::pseudo_header(&addr.src, &addr.dst, ip::Protocol::Tcp, data_len as u32),
            data_sum,
        ]);
        self.set_checksum(checksum);
    }

    /// Return a pointer to the options.
    #[inline]
    fn options_mut(&mut self) -> &mut [u8] {
        let header_len = self.header_len();
        &mut self.0.as_mut()[field::OPTIONS(header_len)]
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Wire)]
#[prefix(crate)]
pub struct Packet<#[wire] T> {
    pub port: Ends<u16>,
    pub control: Control,
    pub seq_number: SeqNumber,
    pub ack_number: Option<SeqNumber>,
    pub window_len: usize,
    pub max_seg_size: Option<u16>,
    pub sack_permitted: bool,
    // Not `Range<SeqNumber>` because `Range` is not `Copy`.
    pub sack_ranges: [Option<(SeqNumber, SeqNumber)>; 3],
    pub timestamp: Option<TcpTimestamp>,
    #[wire]
    pub payload: T,
}

impl<T> Packet<T> {
    fn scale_window(&self) -> (u16, Option<u8>) {
        match (usize::BITS - self.window_len.leading_zeros()).checked_sub(u16::BITS) {
            Some(window_scale) => (
                (self.window_len >> window_scale).min(u16::MAX.into()) as u16,
                Some(window_scale as u8),
            ),
            None => (self.window_len as u16, None),
        }
    }
}

impl<P: PayloadParse, T: WireParse<Payload = P>> WireParse for Packet<T> {
    fn parse(cx: &dyn WireCx, raw: P) -> Result<Self, ParseError<P>> {
        let packet = RawPacket(raw.header_data());

        let len = packet.0.len();
        if len < field::URGENT.end {
            return Err(ParseErrorKind::PacketTooShort.with(raw));
        }
        let header_len = usize::from(packet.header_len());
        if len < header_len || header_len < field::URGENT.end {
            return Err(ParseErrorKind::PacketTooShort.with(raw));
        }

        // Source and destination ports must be present.
        if packet.src_port() == 0 {
            return Err(ParseErrorKind::SrcInvalid.with(raw));
        }
        if packet.dst_port() == 0 {
            return Err(ParseErrorKind::DstInvalid.with(raw));
        }

        // Valid checksum is expected.
        if cx.checksums().tcp() && !packet.verify_checksum(cx.ip_addrs(), raw.next_data_iter()) {
            return Err(ParseErrorKind::ChecksumInvalid.with(raw));
        }

        let control = match (packet.syn(), packet.fin(), packet.rst(), packet.psh()) {
            (false, false, false, false) => Control::None,
            (false, false, false, true) => Control::Psh,
            (true, false, false, _) => Control::Syn,
            (false, true, false, _) => Control::Fin,
            (false, false, true, _) => Control::Rst,
            _ => return Err(ParseErrorKind::FormatInvalid.with(raw)),
        };

        let ack_number = match packet.ack() {
            true => Some(packet.ack_number()),
            false => None,
        };

        // The PSH flag is ignored.
        // The URG flag and the urgent field is ignored. This behavior is
        // standards-compliant, however, most deployed systems (e.g. Linux) are
        // *not* standards-compliant, and would cut the byte at the urgent
        // pointer from the stream.

        let mut max_seg_size = None;
        let mut window_scale = None;
        let mut sack_permitted = false;
        let mut sack_ranges = [None, None, None];
        let mut timestamp = None;

        let mut options = packet.options();
        while !options.is_empty() {
            let (next_options, option) = match TcpOption::parse(options) {
                Ok(ret) => ret,
                Err(kind) => return Err(kind.with(raw)),
            };
            match option {
                TcpOption::EndOfList => break,
                TcpOption::NoOperation => {}
                TcpOption::MaxSegmentSize(value) => max_seg_size = Some(value),
                TcpOption::WindowScale(value) => {
                    // RFC 1323: Thus, the shift count must be limited to 14 (which allows windows
                    // of 2**30 = 1 Gigabyte). If a Window Scale option is received with a shift.cnt
                    // value exceeding 14, the TCP should log the error but use 14 instead of the
                    // specified value.
                    window_scale = if value > 14 {
                        #[cfg(feature = "log")]
                        tracing::debug!(
                            "{}:{}: parsed window scaling factor>14, setting to 14",
                            packet.src_port(),
                            packet.dst_port(),
                        );
                        Some(14)
                    } else {
                        Some(value)
                    };
                }
                TcpOption::SackPermitted => sack_permitted = true,
                TcpOption::SackRange(slice) => sack_ranges = slice,
                TcpOption::TimeStamp { tsval, tsecr } => {
                    timestamp = Some(TcpTimestamp::new(tsval, tsecr));
                }
                TcpOption::Unknown { .. } => {}
            }
            options = next_options;
        }

        let mut window_len = usize::from(packet.window_len());
        if let Some(scale) = window_scale {
            window_len = match window_len.checked_shl(scale.into()) {
                Some(window_len) => window_len,
                None => return Err(ParseErrorKind::FormatInvalid.with(raw)),
            }
        }

        Ok(Packet {
            port: packet.port(),
            control,
            seq_number: packet.seq_number(),
            ack_number,
            window_len,
            max_seg_size,
            sack_permitted,
            sack_ranges,
            timestamp,
            payload: T::parse(
                cx,
                raw.pop(header_len..len)
                    .map_err(|err| ParseErrorKind::PacketTooShort.with(err))?,
            )?,
        })
    }
}

impl<P: PayloadBuild, T: WireBuild<Payload = P>> WireBuild for Packet<T> {
    fn buffer_len(&self) -> usize {
        self.header_len() + self.payload_len()
    }

    fn header_len(&self) -> usize {
        self.header_len()
    }

    fn build(self, cx: &dyn WireCx) -> Result<P, BuildError<P>> {
        let header_len = self.header_len();

        let (window_len, window_scale) = self.scale_window();

        let Packet {
            port: Ends { src, dst },
            control,
            seq_number,
            ack_number,
            window_len: _,
            max_seg_size,
            sack_permitted,
            sack_ranges,
            timestamp,
            payload,
        } = self;

        payload.build(cx)?.push(header_len, |buf, iter| {
            let mut packet = RawPacket(buf);

            packet.set_src_port(src);
            packet.set_dst_port(dst);
            packet.set_seq_number(seq_number);
            packet.set_ack_number(ack_number.unwrap_or(SeqNumber(0)));
            packet.set_window_len(window_len);
            packet.set_header_len(header_len as u8);

            let mut flags = match control {
                Control::None => TcpFlags::empty(),
                Control::Psh => TcpFlags::PSH,
                Control::Syn => TcpFlags::SYN,
                Control::Fin => TcpFlags::FIN,
                Control::Rst => TcpFlags::RST,
            };
            if ack_number.is_some() {
                flags |= TcpFlags::ACK;
            }
            packet.set_flags(flags);

            {
                let mut options = packet.options_mut();
                if let Some(value) = max_seg_size {
                    options = TcpOption::MaxSegmentSize(value).build(options);
                }
                if let Some(value) = window_scale {
                    options = TcpOption::WindowScale(value).build(options);
                }
                if sack_permitted {
                    options = TcpOption::SackPermitted.build(options);
                } else if ack_number.is_some() && sack_ranges.iter().any(|s| s.is_some()) {
                    options = TcpOption::SackRange(sack_ranges).build(options);
                }
                if let Some(timestamp) = timestamp {
                    options = TcpOption::TimeStamp {
                        tsval: timestamp.tsval,
                        tsecr: timestamp.tsecr,
                    }
                    .build(options);
                }

                if !options.is_empty() {
                    TcpOption::EndOfList.build(options);
                }
            }
            packet.set_urgent_at(0);

            if cx.checksums().tcp() {
                packet.fill_checksum(cx.ip_addrs(), iter)
            } else {
                // make sure we get a consistently zeroed checksum,
                // since implementations might rely on it
                packet.set_checksum(0);
            }

            Ok(())
        })
    }
}

impl<T> Packet<T> {
    fn header_len(&self) -> usize {
        let mut length = field::URGENT.end;
        if self.max_seg_size.is_some() {
            length += 4
        }
        if self.scale_window().1.is_some() {
            length += 3
        }
        if self.sack_permitted {
            length += 2;
        }
        if self.timestamp.is_some() {
            length += 10;
        }
        let sack_range_len: usize = self
            .sack_ranges
            .iter()
            .map(|o| o.map(|_| 8).unwrap_or(0))
            .sum();
        if sack_range_len > 0 {
            length += sack_range_len + 2;
        }
        if length % 4 != 0 {
            length += 4 - length % 4;
        }
        length
    }
}

impl<T: Wire> Packet<T> {
    /// Return the length of the segment, in terms of sequence space.
    pub fn segment_len(&self) -> usize {
        self.payload_len() + self.control.len()
    }

    /// Return whether the segment has no flags set (except PSH) and no data.
    pub fn is_empty(&self) -> bool {
        match self.control {
            _ if self.payload_len() != 0 => false,
            Control::Syn | Control::Fin | Control::Rst => false,
            Control::None | Control::Psh => true,
        }
    }
}

#[cfg(test)]
mod tests {
    use core::net::Ipv4Addr;
    use std::vec::Vec;

    use super::*;
    use crate::Checksums;

    const SRC_ADDR: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
    const DST_ADDR: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2));
    const CX: (Checksums, Ends<IpAddr>) = (Checksums::new(), Ends { src: SRC_ADDR, dst: DST_ADDR });

    static PACKET_BYTES: [u8; 28] = [
        0xbf, 0x00, 0x00, 0x50, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x60, 0x31, 0x01,
        0x23, 0x01, 0xba, 0x02, 0x01, 0x03, 0x03, 0x0c, 0x01, 0xaa, 0x00, 0x00, 0xff,
    ];

    static PAYLOAD_BYTES: [u8; 4] = [0xaa, 0x00, 0x00, 0xff];

    #[test]
    fn test_deconstruct() {
        let packet: Packet<&[u8]> = Packet::parse(&CX, &PACKET_BYTES[..]).unwrap();
        assert_eq!(packet.port, Ends { src: 48896, dst: 80 });
        assert_eq!(packet.seq_number, SeqNumber(0x01234567));
        assert_eq!(packet.ack_number, Some(SeqNumber(0x89abcdefu32)));
        assert_eq!(packet.header_len(), 24);
        assert_eq!(packet.control, Control::Fin);
        assert_eq!(packet.window_len, 0x123000);
        assert_eq!(packet.payload, &PAYLOAD_BYTES[..]);
    }

    #[test]
    fn test_truncated() {
        let err = Packet::<&[u8]>::parse(&(), &PACKET_BYTES[..23]).unwrap_err();
        assert_eq!(err.kind, ParseErrorKind::PacketTooShort);
    }

    static SYN_PACKET_BYTES: [u8; 24] = [
        0xbf, 0x00, 0x00, 0x50, 0x01, 0x23, 0x45, 0x67, 0x00, 0x00, 0x00, 0x00, 0x50, 0x02, 0x01,
        0x23, 0x7a, 0x8d, 0x00, 0x00, 0xaa, 0x00, 0x00, 0xff,
    ];

    fn packet_repr<T>(t: T) -> Packet<T> {
        Packet {
            port: Ends { src: 48896, dst: 80 },
            seq_number: SeqNumber(0x01234567),
            ack_number: None,
            window_len: 0x0123,
            control: Control::Syn,
            max_seg_size: None,
            sack_permitted: false,
            sack_ranges: [None, None, None],
            timestamp: None,
            payload: t,
        }
    }

    #[test]
    fn test_parse() {
        let repr = Packet::parse(&CX, &SYN_PACKET_BYTES[..]).unwrap();
        assert_eq!(repr, packet_repr(&PAYLOAD_BYTES[..]));
    }

    #[test]
    fn test_construct() {
        let repr = packet_repr(Vec::from(PAYLOAD_BYTES));
        let packet = repr.build(&CX).unwrap();
        assert_eq!(packet, &SYN_PACKET_BYTES[..]);
    }

    #[test]
    fn test_header_len_multiple_of_4() {
        let repr = packet_repr::<&[u8; 0]>(&[]);
        assert_eq!(repr.header_len() % 4, 0); // Should e.g. be 28 instead of
                                              // 27.
    }

    macro_rules! assert_option_parses {
        ($opt:expr, $data:expr) => {{
            assert_eq!(TcpOption::parse($data), Ok((&[][..], $opt)));
            let buffer = &mut [0; 40][..$opt.buffer_len()];
            assert_eq!($opt.build(buffer), &mut []);
            assert_eq!(&*buffer, $data);
        }};
    }

    #[test]
    fn test_tcp_options() {
        assert_option_parses!(TcpOption::EndOfList, &[0x00]);
        assert_option_parses!(TcpOption::NoOperation, &[0x01]);
        assert_option_parses!(TcpOption::MaxSegmentSize(1500), &[0x02, 0x04, 0x05, 0xdc]);
        assert_option_parses!(TcpOption::WindowScale(12), &[0x03, 0x03, 0x0c]);
        assert_option_parses!(TcpOption::SackPermitted, &[0x4, 0x02]);
        assert_option_parses!(
            TcpOption::SackRange([Some((SeqNumber(500), SeqNumber(1500))), None, None]),
            &[0x05, 0x0a, 0x00, 0x00, 0x01, 0xf4, 0x00, 0x00, 0x05, 0xdc]
        );
        assert_option_parses!(
            TcpOption::SackRange([
                Some((SeqNumber(875), SeqNumber(1225))),
                Some((SeqNumber(1500), SeqNumber(2500))),
                None
            ]),
            &[
                0x05, 0x12, 0x00, 0x00, 0x03, 0x6b, 0x00, 0x00, 0x04, 0xc9, 0x00, 0x00, 0x05, 0xdc,
                0x00, 0x00, 0x09, 0xc4
            ]
        );
        assert_option_parses!(
            TcpOption::SackRange([
                Some((SeqNumber(875000), SeqNumber(1225000))),
                Some((SeqNumber(1500000), SeqNumber(2500000))),
                Some((SeqNumber(876543210), SeqNumber(876654320)))
            ]),
            &[
                0x05, 0x1a, 0x00, 0x0d, 0x59, 0xf8, 0x00, 0x12, 0xb1, 0x28, 0x00, 0x16, 0xe3, 0x60,
                0x00, 0x26, 0x25, 0xa0, 0x34, 0x3e, 0xfc, 0xea, 0x34, 0x40, 0xae, 0xf0
            ]
        );
        assert_option_parses!(TcpOption::TimeStamp { tsval: 5000000, tsecr: 7000000 }, &[
            0x08, // data length
            0x0a, // type
            0x00, 0x4c, 0x4b, 0x40, // tsval
            0x00, 0x6a, 0xcf, 0xc0 // tsecr
        ]);
        assert_option_parses!(TcpOption::Unknown { kind: 12, data: &[1, 2, 3][..] }, &[
            0x0c, 0x05, 0x01, 0x02, 0x03
        ])
    }

    #[test]
    fn test_malformed_tcp_options() {
        assert_eq!(TcpOption::parse(&[]), Err(ParseErrorKind::PacketTooShort));
        assert_eq!(
            TcpOption::parse(&[0xc]),
            Err(ParseErrorKind::PacketTooShort)
        );
        assert_eq!(
            TcpOption::parse(&[0xc, 0x05, 0x01, 0x02]),
            Err(ParseErrorKind::PacketTooShort)
        );
        assert_eq!(
            TcpOption::parse(&[0xc, 0x01]),
            Err(ParseErrorKind::PacketTooShort)
        );
        assert_eq!(
            TcpOption::parse(&[0x2, 0x02]),
            Err(ParseErrorKind::FormatInvalid)
        );
        assert_eq!(
            TcpOption::parse(&[0x3, 0x02]),
            Err(ParseErrorKind::FormatInvalid)
        );
    }
}
