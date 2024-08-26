use core::{cmp, fmt, net::IpAddr, ops};

use byteorder::{ByteOrder, NetworkEndian};

use super::{
    ip::{self, checksum},
    BuildErrorKind, Dst, Ends, ParseErrorKind, Src, VerifyChecksum, Wire,
};
use crate::wire::{Data, DataMut};

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
pub struct SeqNumber(pub i32);

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
        write!(f, "{}", self.0 as u32)
    }
}

impl ops::Add<usize> for SeqNumber {
    type Output = SeqNumber;

    fn add(self, rhs: usize) -> SeqNumber {
        if rhs > i32::MAX as usize {
            panic!("attempt to add to sequence number with unsigned overflow")
        }
        SeqNumber(self.0.wrapping_add(rhs as i32))
    }
}

impl ops::Sub<usize> for SeqNumber {
    type Output = SeqNumber;

    fn sub(self, rhs: usize) -> SeqNumber {
        if rhs > i32::MAX as usize {
            panic!("attempt to subtract to sequence number with unsigned overflow")
        }
        SeqNumber(self.0.wrapping_sub(rhs as i32))
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
        let result = self.0.wrapping_sub(rhs.0);
        if result < 0 {
            panic!("attempt to subtract sequence numbers with underflow")
        }
        result as usize
    }
}

impl cmp::PartialOrd for SeqNumber {
    fn partial_cmp(&self, other: &SeqNumber) -> Option<cmp::Ordering> {
        self.0.wrapping_sub(other.0).partial_cmp(&0)
    }
}

pub type Packet<T: ?Sized> = super::Packet<Tcp, T>;

mod field {
    #![allow(non_snake_case)]

    use crate::wire::field::*;

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

wire!(impl Packet {
    src_port/set_src_port: u16 =>
        |data| NetworkEndian::read_u16(&data[field::SRC_PORT]);
        |data, value| NetworkEndian::write_u16(&mut data[field::SRC_PORT], value);

    dst_port/set_dst_port: u16 =>
        |data| NetworkEndian::read_u16(&data[field::DST_PORT]);
        |data, value| NetworkEndian::write_u16(&mut data[field::DST_PORT], value);

    seq_number/set_seq_number: SeqNumber =>
        |data| SeqNumber(NetworkEndian::read_i32(&data[field::SEQ_NUM]));
        |data, value| NetworkEndian::write_i32(&mut data[field::SEQ_NUM], value.0);

    ack_number/set_ack_number: SeqNumber =>
        |data| SeqNumber(NetworkEndian::read_i32(&data[field::ACK_NUM]));
        |data, value| NetworkEndian::write_i32(&mut data[field::ACK_NUM], value.0);

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

    checksum/set_checksum: u16 =>
        |data| NetworkEndian::read_u16(&data[field::CHECKSUM]);
        |data, value| NetworkEndian::write_u16(&mut data[field::CHECKSUM], value);

    urgent_at/set_urgent_at: u16 =>
        |data| NetworkEndian::read_u16(&data[field::URGENT]);
        |data, value| NetworkEndian::write_u16(&mut data[field::URGENT], value);
});

macro_rules! wire_flags {
    ($($get:ident/$set:ident => $c:ident,)*) => {
        impl<T: Data + ?Sized> Packet<T> {
            $(
                pub fn $get(&self) -> bool {
                    self.flags().contains(TcpFlags:: $c)
                }
            )*
        }

        impl<T: DataMut + ?Sized> Packet<T> {
            $(
                pub fn $set(&mut self, value: bool) {
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

impl<T: Data + ?Sized> Packet<T> {
    pub fn port(&self) -> Ends<u16> {
        (Src(self.src_port()), Dst(self.dst_port()))
    }

    pub fn segment_len(&self) -> usize {
        let data = self.inner.as_ref();
        let mut length = data.len() - self.header_len() as usize;
        if self.syn() {
            length += 1
        }
        if self.fin() {
            length += 1
        }
        length
    }

    /// Returns whether the selective acknowledgement SYN flag is set or not.
    pub fn selective_ack_permitted(&self) -> Result<bool, ParseErrorKind> {
        let data = self.inner.as_ref();
        let mut options = &data[field::OPTIONS(self.header_len())];
        while !options.is_empty() {
            let (next_options, option) = TcpOption::parse(options)?;
            if option == TcpOption::SackPermitted {
                return Ok(true);
            }
            options = next_options;
        }
        Ok(false)
    }

    /// Return the selective acknowledgement ranges, if any. If there are none
    /// in the packet, an array of ``None`` values will be returned.
    pub fn selective_ack_ranges(&self) -> Result<[Option<(u32, u32)>; 3], ParseErrorKind> {
        let data = self.inner.as_ref();
        let mut options = &data[field::OPTIONS(self.header_len())];
        while !options.is_empty() {
            let (next_options, option) = TcpOption::parse(options)?;
            if let TcpOption::SackRange(slice) = option {
                return Ok(slice);
            }
            options = next_options;
        }
        Ok([None, None, None])
    }

    /// Validate the packet checksum.
    ///
    /// # Panics
    ///
    /// This function panics unless `src_addr` and `dst_addr` belong to the same
    /// family, and that family is IPv4 or IPv6.
    pub fn verify_checksum(&self, src_addr: &IpAddr, dst_addr: &IpAddr) -> bool {
        let data = self.inner.as_ref();
        let combine = checksum::combine(&[
            checksum::pseudo_header(src_addr, dst_addr, ip::Protocol::Tcp, data.len() as u32),
            checksum::data(data),
        ]);
        combine == !0
    }

    pub fn options(&self) -> &[u8] {
        &self.inner.as_ref()[field::OPTIONS(self.header_len())]
    }
}

impl<T: DataMut + ?Sized> Packet<T> {
    /// Compute and fill in the header checksum.
    ///
    /// # Panics
    /// This function panics unless `src_addr` and `dst_addr` belong to the same
    /// family, and that family is IPv4 or IPv6.
    pub fn fill_checksum(&mut self, src_addr: &IpAddr, dst_addr: &IpAddr) {
        self.set_checksum(0);
        let checksum = {
            let data = self.inner.as_ref();
            !checksum::combine(&[
                checksum::pseudo_header(src_addr, dst_addr, ip::Protocol::Tcp, data.len() as u32),
                checksum::data(data),
            ])
        };
        self.set_checksum(checksum);
    }

    /// Return a pointer to the options.
    #[inline]
    fn options_mut(&mut self) -> &mut [u8] {
        let header_len = self.header_len();
        &mut self.inner.as_mut()[field::OPTIONS(header_len)]
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum TcpOption<'a> {
    EndOfList,
    NoOperation,
    MaxSegmentSize(u16),
    WindowScale(u8),
    SackPermitted,
    SackRange([Option<(u32, u32)>; 3]),
    TimeStamp { tsval: u32, tsecr: u32 },
    Unknown { kind: u8, data: &'a [u8] },
}

impl<'a> TcpOption<'a> {
    pub fn parse(buffer: &'a [u8]) -> Result<(&'a [u8], TcpOption<'a>), ParseErrorKind> {
        let (length, option);
        match *buffer.first().ok_or(ParseErrorKind::PacketTooShort)? {
            field::OPT_END => {
                length = 1;
                option = TcpOption::EndOfList;
            }
            field::OPT_NOP => {
                length = 1;
                option = TcpOption::NoOperation;
            }
            kind => {
                length = *buffer.get(1).ok_or(ParseErrorKind::PacketTooShort)? as usize;
                let data = buffer
                    .get(2..length)
                    .ok_or(ParseErrorKind::PacketTooShort)?;
                match (kind, length) {
                    (field::OPT_END, _) | (field::OPT_NOP, _) => unreachable!(),
                    (field::OPT_MSS, 4) => {
                        option = TcpOption::MaxSegmentSize(NetworkEndian::read_u16(data))
                    }
                    (field::OPT_MSS, _) => return Err(ParseErrorKind::FormatInvalid),
                    (field::OPT_WS, 3) => option = TcpOption::WindowScale(data[0]),
                    (field::OPT_WS, _) => return Err(ParseErrorKind::FormatInvalid),
                    (field::OPT_SACKPERM, 2) => option = TcpOption::SackPermitted,
                    (field::OPT_SACKPERM, _) => return Err(ParseErrorKind::FormatInvalid),
                    (field::OPT_SACKRNG, n) => {
                        if n < 10 || (n - 2) % 8 != 0 {
                            return Err(ParseErrorKind::FormatInvalid);
                        }
                        if n > 26 {
                            // It's possible for a remote to send 4 SACK blocks,
                            // but extremely rare.
                            // Better to "lose" that 4th block and save the
                            // extra RAM and CPU
                            // cycles in the vastly more common case.
                            //
                            // RFC 2018: SACK option that specifies n blocks
                            // will have a length of
                            // 8*n+2 bytes, so the 40 bytes available for TCP
                            // options can specify a
                            // maximum of 4 blocks.  It is expected that SACK
                            // will often be used in
                            // conjunction with the Timestamp option used for
                            // RTTM [...] thus a
                            // maximum of 3 SACK blocks will be allowed in this
                            // case. net_debug!("
                            // sACK with >3 blocks, truncating to 3");
                        }
                        let mut sack_ranges: [Option<(u32, u32)>; 3] = [None; 3];

                        // RFC 2018: Each contiguous block of data queued at the data receiver is
                        // defined in the SACK option by two 32-bit unsigned integers in network
                        // byte order[...]
                        sack_ranges.iter_mut().enumerate().for_each(|(i, nmut)| {
                            let left = i * 8;
                            *nmut = if left < data.len() {
                                let mid = left + 4;
                                let right = mid + 4;
                                let range_left = NetworkEndian::read_u32(&data[left..mid]);
                                let range_right = NetworkEndian::read_u32(&data[mid..right]);
                                Some((range_left, range_right))
                            } else {
                                None
                            };
                        });
                        option = TcpOption::SackRange(sack_ranges);
                    }
                    (field::OPT_TSTAMP, 10) => {
                        let tsval = NetworkEndian::read_u32(&data[0..4]);
                        let tsecr = NetworkEndian::read_u32(&data[4..8]);
                        option = TcpOption::TimeStamp { tsval, tsecr };
                    }
                    (..) => option = TcpOption::Unknown { kind, data },
                }
            }
        }
        Ok((&buffer[length..], option))
    }

    pub fn buffer_len(&self) -> usize {
        match *self {
            TcpOption::EndOfList => 1,
            TcpOption::NoOperation => 1,
            TcpOption::MaxSegmentSize(_) => 4,
            TcpOption::WindowScale(_) => 3,
            TcpOption::SackPermitted => 2,
            TcpOption::SackRange(s) => s.iter().filter(|s| s.is_some()).count() * 8 + 2,
            TcpOption::TimeStamp { tsval: _, tsecr: _ } => 10,
            TcpOption::Unknown { data, .. } => 2 + data.len(),
        }
    }

    pub fn build<'b>(&self, buffer: &'b mut [u8]) -> &'b mut [u8] {
        let length;
        match *self {
            TcpOption::EndOfList => {
                length = 1;
                // There may be padding space which also should be initialized.
                for p in buffer.iter_mut() {
                    *p = field::OPT_END;
                }
            }
            TcpOption::NoOperation => {
                length = 1;
                buffer[0] = field::OPT_NOP;
            }
            _ => {
                length = self.buffer_len();
                buffer[1] = length as u8;
                match self {
                    &TcpOption::EndOfList | &TcpOption::NoOperation => unreachable!(),
                    &TcpOption::MaxSegmentSize(value) => {
                        buffer[0] = field::OPT_MSS;
                        NetworkEndian::write_u16(&mut buffer[2..], value)
                    }
                    &TcpOption::WindowScale(value) => {
                        buffer[0] = field::OPT_WS;
                        buffer[2] = value;
                    }
                    &TcpOption::SackPermitted => {
                        buffer[0] = field::OPT_SACKPERM;
                    }
                    &TcpOption::SackRange(slice) => {
                        buffer[0] = field::OPT_SACKRNG;
                        slice
                            .iter()
                            .filter(|s| s.is_some())
                            .enumerate()
                            .for_each(|(i, s)| {
                                let (first, second) = *s.as_ref().unwrap();
                                let pos = i * 8 + 2;
                                NetworkEndian::write_u32(&mut buffer[pos..], first);
                                NetworkEndian::write_u32(&mut buffer[pos + 4..], second);
                            });
                    }
                    &TcpOption::TimeStamp { tsval, tsecr } => {
                        buffer[0] = field::OPT_TSTAMP;
                        NetworkEndian::write_u32(&mut buffer[2..], tsval);
                        NetworkEndian::write_u32(&mut buffer[6..], tsecr);
                    }
                    &TcpOption::Unknown { kind, data: provided } => {
                        buffer[0] = kind;
                        buffer[2..].copy_from_slice(provided)
                    }
                }
            }
        }
        &mut buffer[length..]
    }
}

/// The possible control flags of a Transmission Control Protocol packet.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Control {
    None,
    Psh,
    Syn,
    Fin,
    Rst,
}

#[allow(clippy::len_without_is_empty)]
impl Control {
    /// Return the length of a control flag, in terms of sequence space.
    pub const fn len(self) -> usize {
        match self {
            Control::Syn | Control::Fin => 1,
            _ => 0,
        }
    }

    /// Turn the PSH flag into no flag, and keep the rest as-is.
    pub const fn quash_psh(self) -> Control {
        match self {
            Control::Psh => Control::None,
            _ => self,
        }
    }
}

pub type TcpTimestampGenerator = fn() -> u32;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct TcpTimestamp {
    pub tsval: u32,
    pub tsecr: u32,
}

impl TcpTimestamp {
    pub fn new(tsval: u32, tsecr: u32) -> Self {
        Self { tsval, tsecr }
    }

    pub fn generate_reply(&self, generator: Option<TcpTimestampGenerator>) -> Option<Self> {
        Self::generate_reply_with_tsval(generator, self.tsval)
    }

    pub fn generate_reply_with_tsval(
        generator: Option<TcpTimestampGenerator>,
        tsval: u32,
    ) -> Option<Self> {
        Some(Self::new(generator?(), tsval))
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct Tcp {
    pub port: Ends<u16>,
    pub control: Control,
    pub seq_number: SeqNumber,
    pub ack_number: Option<SeqNumber>,
    pub window_len: u16,
    pub window_scale: Option<u8>,
    pub max_seg_size: Option<u16>,
    pub sack_permitted: bool,
    pub sack_ranges: [Option<(u32, u32)>; 3],
    pub timestamp: Option<TcpTimestamp>,
}

impl Wire for Tcp {
    const EMPTY_PAYLOAD: bool = false;

    fn header_len(&self) -> usize {
        let mut length = field::URGENT.end;
        if self.max_seg_size.is_some() {
            length += 4
        }
        if self.window_scale.is_some() {
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

    fn buffer_len(&self, payload_len: usize) -> usize {
        self.header_len() + payload_len
    }

    fn payload_range(packet: Packet<&[u8]>) -> ops::Range<usize> {
        usize::from(packet.header_len())..packet.inner.len()
    }

    type ParseArg<'a> = VerifyChecksum<Option<Ends<IpAddr>>>;

    fn parse_packet(
        packet: Packet<&[u8]>,
        VerifyChecksum(verify_checksum): VerifyChecksum<Option<Ends<IpAddr>>>,
    ) -> Result<Self, ParseErrorKind> {
        let len = packet.inner.len();
        if len < field::URGENT.end {
            return Err(ParseErrorKind::PacketTooShort);
        } else {
            let header_len = usize::from(packet.header_len());
            if len < header_len || header_len < field::URGENT.end {
                return Err(ParseErrorKind::PacketTooShort);
            }
        }

        // Source and destination ports must be present.
        if packet.src_port() == 0 {
            return Err(ParseErrorKind::SrcInvalid);
        }
        if packet.dst_port() == 0 {
            return Err(ParseErrorKind::DstInvalid);
        }

        // Valid checksum is expected.
        if let Some((Src(src_addr), Dst(dst_addr))) = verify_checksum
            && !packet.verify_checksum(&src_addr, &dst_addr)
        {
            return Err(ParseErrorKind::ChecksumInvalid);
        }

        let control = match (packet.syn(), packet.fin(), packet.rst(), packet.psh()) {
            (false, false, false, false) => Control::None,
            (false, false, false, true) => Control::Psh,
            (true, false, false, _) => Control::Syn,
            (false, true, false, _) => Control::Fin,
            (false, false, true, _) => Control::Rst,
            _ => return Err(ParseErrorKind::FormatInvalid),
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
        let mut options = packet.options();
        let mut sack_permitted = false;
        let mut sack_ranges = [None, None, None];
        let mut timestamp = None;
        while !options.is_empty() {
            let (next_options, option) = TcpOption::parse(options)?;
            match option {
                TcpOption::EndOfList => break,
                TcpOption::NoOperation => (),
                TcpOption::MaxSegmentSize(value) => max_seg_size = Some(value),
                TcpOption::WindowScale(value) => {
                    // RFC 1323: Thus, the shift count must be limited to 14 (which allows windows
                    // of 2**30 = 1 Gigabyte). If a Window Scale option is received with a shift.cnt
                    // value exceeding 14, the TCP should log the error but use 14 instead of the
                    // specified value.
                    window_scale = if value > 14 {
                        // net_debug!(
                        //     "{}:{}:{}:{}: parsed window scaling factor >14, setting to 14",
                        //     src_addr,
                        //     packet.src_port(),
                        //     dst_addr,
                        //     packet.dst_port()
                        // );
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
                _ => (),
            }
            options = next_options;
        }

        Ok(Tcp {
            port: packet.port(),
            control,
            seq_number: packet.seq_number(),
            ack_number,
            window_len: packet.window_len(),
            window_scale,
            max_seg_size,
            sack_permitted,
            sack_ranges,
            timestamp,
        })
    }

    fn build_packet(self, mut packet: Packet<&mut [u8]>, _: usize) -> Result<(), BuildErrorKind> {
        let (Src(src_port), Dst(dst_port)) = self.port;
        packet.set_src_port(src_port);
        packet.set_dst_port(dst_port);
        packet.set_seq_number(self.seq_number);
        packet.set_ack_number(self.ack_number.unwrap_or(SeqNumber(0)));
        packet.set_window_len(self.window_len);
        packet.set_header_len(self.header_len() as u8);

        let mut flags = match self.control {
            Control::None => TcpFlags::empty(),
            Control::Psh => TcpFlags::PSH,
            Control::Syn => TcpFlags::SYN,
            Control::Fin => TcpFlags::FIN,
            Control::Rst => TcpFlags::RST,
        };
        if self.ack_number.is_some() {
            flags |= TcpFlags::ACK;
        }
        packet.set_flags(flags);

        {
            let mut options = packet.options_mut();
            if let Some(value) = self.max_seg_size {
                options = TcpOption::MaxSegmentSize(value).build(options);
            }
            if let Some(value) = self.window_scale {
                options = TcpOption::WindowScale(value).build(options);
            }
            if self.sack_permitted {
                options = TcpOption::SackPermitted.build(options);
            } else if self.ack_number.is_some() && self.sack_ranges.iter().any(|s| s.is_some()) {
                options = TcpOption::SackRange(self.sack_ranges).build(options);
            }
            if let Some(timestamp) = self.timestamp {
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

        // make sure we get a consistently zeroed checksum,
        // since implementations might rely on it
        packet.set_checksum(0);

        Ok(())
    }
}

impl Tcp {
    /// Return the length of the segment, in terms of sequence space.
    pub const fn segment_len(&self, payload_len: usize) -> usize {
        payload_len + self.control.len()
    }

    /// Return whether the segment has no flags set (except PSH) and no data.
    pub const fn is_empty(&self, payload_len: usize) -> bool {
        match self.control {
            _ if payload_len != 0 => false,
            Control::Syn | Control::Fin | Control::Rst => false,
            Control::None | Control::Psh => true,
        }
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

    static PACKET_BYTES: [u8; 28] = [
        0xbf, 0x00, 0x00, 0x50, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x60, 0x31, 0x01,
        0x23, 0x01, 0xba, 0x02, 0x01, 0x03, 0x03, 0x0c, 0x01, 0xaa, 0x00, 0x00, 0xff,
    ];

    static OPTION_BYTES: [u8; 4] = [0x03, 0x03, 0x0c, 0x01];

    static PAYLOAD_BYTES: [u8; 4] = [0xaa, 0x00, 0x00, 0xff];

    #[test]
    fn test_deconstruct() {
        let packet = Packet::parse(&PACKET_BYTES[..], VerifyChecksum(None)).unwrap();
        assert_eq!(packet.src_port(), 48896);
        assert_eq!(packet.dst_port(), 80);
        assert_eq!(packet.seq_number(), SeqNumber(0x01234567));
        assert_eq!(packet.ack_number(), SeqNumber(0x89abcdefu32 as i32));
        assert_eq!(packet.header_len(), 24);
        assert!(packet.fin());
        assert!(!packet.syn());
        assert!(!packet.rst());
        assert!(!packet.psh());
        assert!(packet.ack());
        assert!(packet.urg());
        assert_eq!(packet.window_len(), 0x0123);
        assert_eq!(packet.urgent_at(), 0x0201);
        assert_eq!(packet.checksum(), 0x01ba);
        assert_eq!(packet.options(), &OPTION_BYTES[..]);
        assert_eq!(packet.payload(), &PAYLOAD_BYTES[..]);
        assert!(packet.verify_checksum(&SRC_ADDR.into(), &DST_ADDR.into()));
    }

    #[test]
    fn test_truncated() {
        let err = Packet::parse(&PACKET_BYTES[..23], VerifyChecksum(None)).unwrap_err();
        assert_eq!(err.kind, ParseErrorKind::PacketTooShort);
    }

    static SYN_PACKET_BYTES: [u8; 24] = [
        0xbf, 0x00, 0x00, 0x50, 0x01, 0x23, 0x45, 0x67, 0x00, 0x00, 0x00, 0x00, 0x50, 0x02, 0x01,
        0x23, 0x7a, 0x8d, 0x00, 0x00, 0xaa, 0x00, 0x00, 0xff,
    ];

    fn packet_repr() -> Tcp {
        Tcp {
            port: (Src(48896), Dst(80)),
            seq_number: SeqNumber(0x01234567),
            ack_number: None,
            window_len: 0x0123,
            window_scale: None,
            control: Control::Syn,
            max_seg_size: None,
            sack_permitted: false,
            sack_ranges: [None, None, None],
            timestamp: None,
        }
    }

    #[test]
    fn test_parse() {
        let repr = Tcp::parse(
            &SYN_PACKET_BYTES[..],
            VerifyChecksum(Some((Src(SRC_ADDR.into()), Dst(DST_ADDR.into())))),
        )
        .unwrap();
        assert_eq!(repr, packet_repr());
    }

    #[test]
    fn test_construct() {
        let repr = packet_repr();
        let bytes = vec![0xa5; repr.buffer_len(PAYLOAD_BYTES.len())];
        let mut payload = Buf::builder(bytes).reserve_for(&repr).build();
        payload.append_slice(&PAYLOAD_BYTES);

        let mut packet = Packet::build(payload, repr).unwrap();
        packet.fill_checksum(&SRC_ADDR.into(), &DST_ADDR.into());
        assert_eq!(packet.into_raw().data(), &SYN_PACKET_BYTES[..]);
    }

    #[test]
    fn test_header_len_multiple_of_4() {
        let mut repr = packet_repr();
        repr.window_scale = Some(0); // This TCP Option needs 3 bytes.
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
        assert_option_parses!(TcpOption::SackRange([Some((500, 1500)), None, None]), &[
            0x05, 0x0a, 0x00, 0x00, 0x01, 0xf4, 0x00, 0x00, 0x05, 0xdc
        ]);
        assert_option_parses!(
            TcpOption::SackRange([Some((875, 1225)), Some((1500, 2500)), None]),
            &[
                0x05, 0x12, 0x00, 0x00, 0x03, 0x6b, 0x00, 0x00, 0x04, 0xc9, 0x00, 0x00, 0x05, 0xdc,
                0x00, 0x00, 0x09, 0xc4
            ]
        );
        assert_option_parses!(
            TcpOption::SackRange([
                Some((875000, 1225000)),
                Some((1500000, 2500000)),
                Some((876543210, 876654320))
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
