use core::{fmt, net::Ipv6Addr};

use byteorder::{ByteOrder, LittleEndian};

use crate as cutenet;
use crate::{
    provide_any::Provider,
    wire::{ip::IpAddrExt, prelude::*, Data, DataMut, Dst, Ends, Src},
};

enum_with_unknown! {
    /// IEEE 802.15.4 frame type.
    pub enum FrameType(u8) {
        Beacon = 0b000,
        Data = 0b001,
        Acknowledgement = 0b010,
        MacCommand = 0b011,
        Multipurpose = 0b101,
        FragmentOrFrak = 0b110,
        Extended = 0b111,
    }
}

impl fmt::Display for FrameType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FrameType::Beacon => write!(f, "Beacon"),
            FrameType::Data => write!(f, "Data"),
            FrameType::Acknowledgement => write!(f, "Ack"),
            FrameType::MacCommand => write!(f, "MAC command"),
            FrameType::Multipurpose => write!(f, "Multipurpose"),
            FrameType::FragmentOrFrak => write!(f, "FragmentOrFrak"),
            FrameType::Extended => write!(f, "Extended"),
            FrameType::Unknown(id) => write!(f, "0b{id:04b}"),
        }
    }
}
enum_with_unknown! {
    /// IEEE 802.15.4 addressing mode for destination and source addresses.
    pub enum AddressingMode(u8) {
        Absent    = 0b00,
        Short     = 0b10,
        Extended  = 0b11,
    }
}

impl AddressingMode {
    /// Return the size in octets of the address.
    const fn size(&self) -> usize {
        match self {
            AddressingMode::Absent => 0,
            AddressingMode::Short => 2,
            AddressingMode::Extended => 8,
            AddressingMode::Unknown(_) => 0, // TODO(thvdveld): what do we need to here?
        }
    }
}

impl fmt::Display for AddressingMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AddressingMode::Absent => write!(f, "Absent"),
            AddressingMode::Short => write!(f, "Short"),
            AddressingMode::Extended => write!(f, "Extended"),
            AddressingMode::Unknown(id) => write!(f, "0b{id:04b}"),
        }
    }
}

/// A IEEE 802.15.4 PAN.
#[derive(Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
pub struct Pan(pub u16);

impl Pan {
    pub const BROADCAST: Self = Self(0xffff);

    /// Return the PAN ID as bytes.
    pub fn as_bytes(&self) -> [u8; 2] {
        let mut pan = [0u8; 2];
        LittleEndian::write_u16(&mut pan, self.0);
        pan
    }
}

impl fmt::Display for Pan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:0x}", self.0)
    }
}

/// A IEEE 802.15.4 address.
#[derive(Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
pub enum Addr {
    Absent,
    Short([u8; 2]),
    Extended([u8; 8]),
}

#[cfg(test)]
impl Default for Addr {
    fn default() -> Self {
        Addr::Extended([0u8; 8])
    }
}

impl Addr {
    /// The broadcast address.
    pub const BROADCAST: Addr = Addr::Short([0xff; 2]);

    /// Query whether the address is an unicast address.
    pub fn is_unicast(&self) -> bool {
        !self.is_broadcast()
    }

    /// Query whether this address is the broadcast address.
    pub fn is_broadcast(&self) -> bool {
        *self == Self::BROADCAST
    }

    const fn short_from_bytes(a: [u8; 2]) -> Self {
        Self::Short(a)
    }

    const fn extended_from_bytes(a: [u8; 8]) -> Self {
        Self::Extended(a)
    }

    pub fn from_bytes(a: &[u8]) -> Self {
        if a.len() == 2 {
            let mut b = [0u8; 2];
            b.copy_from_slice(a);
            Addr::Short(b)
        } else if a.len() == 8 {
            let mut b = [0u8; 8];
            b.copy_from_slice(a);
            Addr::Extended(b)
        } else {
            panic!("Not an IEEE802.15.4 address");
        }
    }

    pub const fn as_bytes(&self) -> &[u8] {
        match self {
            Addr::Absent => &[],
            Addr::Short(value) => value,
            Addr::Extended(value) => value,
        }
    }

    /// Convert the extended address to an Extended Unique Identifier (EUI-64)
    pub fn as_eui_64(&self) -> Option<[u8; 8]> {
        match self {
            Addr::Absent | Addr::Short(_) => None,
            Addr::Extended(value) => {
                let mut bytes = [0; 8];
                bytes.copy_from_slice(&value[..]);

                bytes[0] ^= 1 << 1;

                Some(bytes)
            }
        }
    }

    /// Convert an extended address to a link-local IPv6 address using the
    /// EUI-64 format from RFC2464.
    pub fn as_link_local_address(&self) -> Option<Ipv6Addr> {
        let mut bytes = [0; 16];
        bytes[0] = 0xfe;
        bytes[1] = 0x80;
        bytes[8..].copy_from_slice(&self.as_eui_64()?);

        Some(Ipv6Addr::from_bytes(&bytes))
    }
}

impl fmt::Display for Addr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Absent => write!(f, "not-present"),
            Self::Short(bytes) => write!(f, "{:02x}:{:02x}", bytes[0], bytes[1]),
            Self::Extended(bytes) => write!(
                f,
                "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7]
            ),
        }
    }
}

enum_with_unknown! {
    /// IEEE 802.15.4 addressing mode for destination and source addresses.
    pub enum FrameVersion(u8) {
        Ieee802154_2003 = 0b00,
        Ieee802154_2006 = 0b01,
        Ieee802154 = 0b10,
    }
}

macro_rules! fc_bit_field {
    ($field:ident, $set_field:ident, $bit:literal) => {
        fc_bit_field!($field, $bit);

        fn $set_field(&mut self, val: bool)
        where
            T: DataMut,
        {
            let data = &mut self.0.as_mut()[field::FRAMECONTROL];
            let mut raw = LittleEndian::read_u16(data);
            raw |= ((val as u16) << $bit);

            data.copy_from_slice(&raw.to_le_bytes());
        }
    };
    ($field:ident, $bit:literal) => {
        #[inline]
        #[allow(unused)]
        pub fn $field(&self) -> bool {
            let data = self.0.as_ref();
            let raw = LittleEndian::read_u16(&data[field::FRAMECONTROL]);

            ((raw >> $bit) & 0b1) == 0b1
        }
    };
}

struct Frame<T: ?Sized>(T);

mod field {
    use crate::wire::field::*;

    pub const FRAMECONTROL: Field = 0..2;
    pub const SEQUENCE_NUMBER: usize = 2;
    pub const ADDRESSING: Rest = 3..;
}

wire!(impl Frame {
    frame_type/set_frame_type: FrameType =>
        |data| {
            let raw = LittleEndian::read_u16(&data[field::FRAMECONTROL]);
            let ft = (raw & 0b111) as u8;
            FrameType::from(ft)
        };
        |data, frame_type| {
            let data = &mut data[field::FRAMECONTROL];
            let mut raw = LittleEndian::read_u16(data);
            raw = (raw & !(0b111)) | (u8::from(frame_type) as u16 & 0b111);
            data.copy_from_slice(&raw.to_le_bytes());
        };

    /// Return the destination addressing mode.
    dst_addressing_mode/set_dst_addressing_mode: AddressingMode =>
        |data| {
            let raw = LittleEndian::read_u16(&data[field::FRAMECONTROL]);
            let am = ((raw >> 10) & 0b11) as u8;
            AddressingMode::from(am)
        };
        |data, value| {
            let data = &mut data[field::FRAMECONTROL];
            let mut raw = LittleEndian::read_u16(data);

            raw = (raw & !(0b11 << 10)) | ((u8::from(value) as u16 & 0b11) << 10);
            data.copy_from_slice(&raw.to_le_bytes());
        };

    /// Return the frame version.
    frame_version/set_frame_version: FrameVersion =>
        |data| {
            let raw = LittleEndian::read_u16(&data[field::FRAMECONTROL]);
            let fv = ((raw >> 12) & 0b11) as u8;
            FrameVersion::from(fv)
        };
        |data, version| {
            let data = &mut data[field::FRAMECONTROL];
            let mut raw = LittleEndian::read_u16(data);

            raw = (raw & !(0b11 << 12)) | ((u8::from(version) as u16 & 0b11) << 12);
            data.copy_from_slice(&raw.to_le_bytes());
        };

    /// Return the source addressing mode.
    src_addressing_mode/set_src_addressing_mode: AddressingMode =>
        |data| {
            let raw = LittleEndian::read_u16(&data[field::FRAMECONTROL]);
            let am = ((raw >> 14) & 0b11) as u8;
            AddressingMode::from(am)
        };
        |data, value| {
            let data = &mut data[field::FRAMECONTROL];
            let mut raw = LittleEndian::read_u16(data);

            raw = (raw & !(0b11 << 14)) | ((u8::from(value) as u16 & 0b11) << 14);
            data.copy_from_slice(&raw.to_le_bytes());
        };
});

impl<T: Data + ?Sized> Frame<T> {
    fc_bit_field!(security_enabled, set_security_enabled, 3);
    fc_bit_field!(frame_pending, set_frame_pending, 4);
    fc_bit_field!(ack_request, set_ack_request, 5);
    fc_bit_field!(pan_id_compression, set_pan_id_compression, 6);

    fc_bit_field!(sequence_number_suppression, 8);
    fc_bit_field!(ie_present, 9);

    /// Return the sequence number of the frame.
    #[inline]
    pub fn sequence_number(&self) -> Option<u8> {
        match self.frame_type() {
            FrameType::Beacon
            | FrameType::Data
            | FrameType::Acknowledgement
            | FrameType::MacCommand
            | FrameType::Multipurpose => Some(self.0.as_ref()[field::SEQUENCE_NUMBER]),
            FrameType::Extended | FrameType::FragmentOrFrak | FrameType::Unknown(_) => None,
        }
    }

    fn set_sequence_number(&mut self, value: u8)
    where
        T: DataMut,
    {
        self.0.as_mut()[field::SEQUENCE_NUMBER] = value;
    }

    /// Return the destination PAN field.
    #[inline]
    pub fn dst_pan_id(&self) -> Option<Pan> {
        if let Some((true, ..)) = self.addr_present_flags() {
            let addressing_fields = self.addressing_fields()?;
            Some(Pan(LittleEndian::read_u16(&addressing_fields[..2])))
        } else {
            None
        }
    }

    fn set_dst_pan_id(&mut self, value: Pan)
    where
        T: DataMut,
    {
        // NOTE the destination addressing mode must be different than Absent.
        // This is the reason why we set it to Extended.
        self.set_dst_addressing_mode(AddressingMode::Extended);

        let data = self.0.as_mut();
        data[field::ADDRESSING][..2].copy_from_slice(&value.as_bytes());
    }

    /// Return the destination address field.
    #[inline]
    pub fn dst_addr(&self) -> Option<Addr> {
        if let Some((dst_pan_id, dst_addr, ..)) = self.addr_present_flags() {
            let addressing_fields = self.addressing_fields()?;
            let offset = if dst_pan_id { 2 } else { 0 };

            match dst_addr {
                AddressingMode::Absent => Some(Addr::Absent),
                AddressingMode::Short => {
                    let mut raw = [0u8; 2];
                    raw.clone_from_slice(&addressing_fields[offset..offset + 2]);
                    raw.reverse();
                    Some(Addr::short_from_bytes(raw))
                }
                AddressingMode::Extended => {
                    let mut raw = [0u8; 8];
                    raw.clone_from_slice(&addressing_fields[offset..offset + 8]);
                    raw.reverse();
                    Some(Addr::extended_from_bytes(raw))
                }
                AddressingMode::Unknown(_) => None,
            }
        } else {
            None
        }
    }

    fn set_dst_addr(&mut self, value: Addr)
    where
        T: DataMut,
    {
        match value {
            Addr::Absent => self.set_dst_addressing_mode(AddressingMode::Absent),
            Addr::Short(mut value) => {
                value.reverse();
                self.set_dst_addressing_mode(AddressingMode::Short);
                let data = self.0.as_mut();
                data[field::ADDRESSING][2..2 + 2].copy_from_slice(&value);
                value.reverse();
            }
            Addr::Extended(mut value) => {
                value.reverse();
                self.set_dst_addressing_mode(AddressingMode::Extended);
                let data = &mut self.0.as_mut()[field::ADDRESSING];
                data[2..2 + 8].copy_from_slice(&value);
                value.reverse();
            }
        }
    }

    /// Return the destination PAN field.
    #[inline]
    pub fn src_pan_id(&self) -> Option<Pan> {
        if let Some((dst_pan_id, dst_addr, true, _)) = self.addr_present_flags() {
            let mut offset = if dst_pan_id { 2 } else { 0 };
            offset += dst_addr.size();
            let addressing_fields = self.addressing_fields()?;
            Some(Pan(LittleEndian::read_u16(
                &addressing_fields[offset..][..2],
            )))
        } else {
            None
        }
    }

    fn set_src_pan_id(&mut self, value: Pan)
    where
        T: DataMut,
    {
        let offset = match self.dst_addressing_mode() {
            AddressingMode::Absent => 0,
            AddressingMode::Short => 2,
            AddressingMode::Extended => 8,
            _ => unreachable!(),
        } + 2;

        let data = &mut self.0.as_mut()[field::ADDRESSING];
        data[offset..offset + 2].copy_from_slice(&value.as_bytes());
    }

    /// Return the source address field.
    #[inline]
    pub fn src_addr(&self) -> Option<Addr> {
        if let Some((dst_pan_id, dst_addr, src_pan_id, src_addr)) = self.addr_present_flags() {
            let addressing_fields = self.addressing_fields()?;
            let mut offset = if dst_pan_id { 2 } else { 0 };
            offset += dst_addr.size();
            offset += if src_pan_id { 2 } else { 0 };

            match src_addr {
                AddressingMode::Absent => Some(Addr::Absent),
                AddressingMode::Short => {
                    let mut raw = [0u8; 2];
                    raw.clone_from_slice(&addressing_fields[offset..offset + 2]);
                    raw.reverse();
                    Some(Addr::short_from_bytes(raw))
                }
                AddressingMode::Extended => {
                    let mut raw = [0u8; 8];
                    raw.clone_from_slice(&addressing_fields[offset..offset + 8]);
                    raw.reverse();
                    Some(Addr::extended_from_bytes(raw))
                }
                AddressingMode::Unknown(_) => None,
            }
        } else {
            None
        }
    }

    fn set_src_addr(&mut self, value: Addr)
    where
        T: DataMut,
    {
        let offset = match self.dst_addressing_mode() {
            AddressingMode::Absent => 0,
            AddressingMode::Short => 2,
            AddressingMode::Extended => 8,
            _ => unreachable!(),
        } + 2;

        let offset = offset + if self.pan_id_compression() { 0 } else { 2 };

        match value {
            Addr::Absent => self.set_src_addressing_mode(AddressingMode::Absent),
            Addr::Short(mut value) => {
                value.reverse();
                self.set_src_addressing_mode(AddressingMode::Short);
                let data = &mut self.0.as_mut()[field::ADDRESSING];
                data[offset..offset + 2].copy_from_slice(&value);
                value.reverse();
            }
            Addr::Extended(mut value) => {
                value.reverse();
                self.set_src_addressing_mode(AddressingMode::Extended);
                let data = &mut self.0.as_mut()[field::ADDRESSING];
                data[offset..offset + 8].copy_from_slice(&value);
                value.reverse();
            }
        }
    }

    /// Return the addressing fields.
    #[inline]
    fn addressing_fields(&self) -> Option<&[u8]> {
        match self.frame_type() {
            FrameType::Beacon
            | FrameType::Data
            | FrameType::MacCommand
            | FrameType::Multipurpose => (),
            FrameType::Acknowledgement if self.frame_version() == FrameVersion::Ieee802154 => (),
            FrameType::Acknowledgement
            | FrameType::Extended
            | FrameType::FragmentOrFrak
            | FrameType::Unknown(_) => return None,
        }

        if let Some((dst_pan_id, dst_addr, src_pan_id, src_addr)) = self.addr_present_flags() {
            let mut offset = if dst_pan_id { 2 } else { 0 };
            offset += dst_addr.size();
            offset += if src_pan_id { 2 } else { 0 };
            offset += src_addr.size();

            let data = self.0.as_ref();
            Some(&data[field::ADDRESSING][..offset])
        } else {
            None
        }
    }

    fn addr_present_flags(&self) -> Option<(bool, AddressingMode, bool, AddressingMode)> {
        let dst_addr_mode = self.dst_addressing_mode();
        let src_addr_mode = self.src_addressing_mode();
        let pan_id_compression = self.pan_id_compression();

        use AddressingMode::*;
        match self.frame_version() {
            FrameVersion::Ieee802154_2003 | FrameVersion::Ieee802154_2006 => {
                match (dst_addr_mode, src_addr_mode) {
                    (Absent, src) => Some((false, Absent, true, src)),
                    (dst, Absent) => Some((true, dst, false, Absent)),

                    (dst, src) if pan_id_compression => Some((true, dst, false, src)),
                    (dst, src) if !pan_id_compression => Some((true, dst, true, src)),
                    _ => None,
                }
            }
            FrameVersion::Ieee802154 => {
                Some(match (dst_addr_mode, src_addr_mode, pan_id_compression) {
                    (Absent, Absent, false) => (false, Absent, false, Absent),
                    (Absent, Absent, true) => (true, Absent, false, Absent),
                    (dst, Absent, false) if !matches!(dst, Absent) => (true, dst, false, Absent),
                    (dst, Absent, true) if !matches!(dst, Absent) => (false, dst, false, Absent),
                    (Absent, src, false) if !matches!(src, Absent) => (false, Absent, true, src),
                    (Absent, src, true) if !matches!(src, Absent) => (false, Absent, true, src),
                    (Extended, Extended, false) => (true, Extended, false, Extended),
                    (Extended, Extended, true) => (false, Extended, false, Extended),
                    (Short, Short, false) => (true, Short, true, Short),
                    (Short, Extended, false) => (true, Short, true, Extended),
                    (Extended, Short, false) => (true, Extended, true, Short),
                    (Short, Extended, true) => (true, Short, false, Extended),
                    (Extended, Short, true) => (true, Extended, false, Short),
                    (Short, Short, true) => (true, Short, false, Short),
                    _ => return None,
                })
            }
            _ => None,
        }
    }

    pub fn ends(&self) -> Ends<(Option<Pan>, Option<Addr>)> {
        (
            Src((self.src_pan_id(), self.src_addr())),
            Dst((self.dst_pan_id(), self.dst_addr())),
        )
    }

    /// Return the index where the auxiliary security header starts.
    fn aux_security_header_start(&self) -> usize {
        // We start with 3, because 2 bytes for frame control and the sequence number.
        let mut index = 3;
        index += if let Some(addrs) = self.addressing_fields() {
            addrs.len()
        } else {
            0
        };
        index
    }

    /// Return the size of the security header.
    fn security_header_len(&self) -> usize {
        let mut size = 1;
        size += if self.frame_counter_suppressed() {
            0
        } else {
            4
        };
        size += if let Some(len) = self.key_identifier_length() {
            len as usize
        } else {
            0
        };
        size
    }

    /// Return the length of the key identifier field.
    fn key_identifier_length(&self) -> Option<u8> {
        Some(match self.key_identifier_mode() {
            0 => 0,
            1 => 1,
            2 => 5,
            3 => 9,
            _ => return None,
        })
    }

    /// Return the security level of the auxiliary security header.
    pub fn security_level(&self) -> u8 {
        let index = self.aux_security_header_start();
        let b = self.0.as_ref()[index..][0];
        b & 0b111
    }

    /// Return the key identifier mode used by the auxiliary security header.
    pub fn key_identifier_mode(&self) -> u8 {
        let index = self.aux_security_header_start();
        let b = self.0.as_ref()[index..][0];
        (b >> 3) & 0b11
    }

    /// Return `true` when the frame counter in the security header is
    /// suppressed.
    pub fn frame_counter_suppressed(&self) -> bool {
        let index = self.aux_security_header_start();
        let b = self.0.as_ref()[index..][0];
        ((b >> 5) & 0b1) == 0b1
    }

    /// Return the frame counter field.

    #[allow(unused)]
    pub fn frame_counter(&self) -> Option<u32> {
        if self.frame_counter_suppressed() {
            None
        } else {
            let index = self.aux_security_header_start();
            let b = &self.0.as_ref()[index..];
            Some(LittleEndian::read_u32(&b[1..1 + 4]))
        }
    }

    /// Return the Key Identifier field.
    fn key_identifier(&self) -> &[u8] {
        let index = self.aux_security_header_start();
        let b = &self.0.as_ref()[index..];
        let length = if let Some(len) = self.key_identifier_length() {
            len as usize
        } else {
            0
        };
        &b[5..][..length]
    }

    /// Return the Key Source field.
    #[allow(unused)]
    pub fn key_source(&self) -> Option<&[u8]> {
        let ki = self.key_identifier();
        let len = ki.len();
        if len > 1 {
            Some(&ki[..len - 1])
        } else {
            None
        }
    }

    /// Return the Key Index field.
    #[allow(unused)]
    pub fn key_index(&self) -> Option<u8> {
        let ki = self.key_identifier();
        let len = ki.len();

        if len > 0 {
            Some(ki[len - 1])
        } else {
            None
        }
    }

    /// Return the Message Integrity Code (MIC).
    #[allow(unused)]
    pub fn message_integrity_code(&self) -> Option<&[u8]> {
        let mic_len = match self.security_level() {
            0 | 4 => return None,
            1 | 5 => 4,
            2 | 6 => 8,
            3 | 7 => 16,
            _ => panic!(),
        };

        let data = &self.0.as_ref();
        let len = data.len();

        Some(&data[len - mic_len..])
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Wire)]
pub struct Ieee802154<#[wire] T> {
    pub frame_type: FrameType,
    pub security_enabled: bool,
    pub frame_pending: bool,
    pub ack_request: bool,
    pub sequence_number: Option<u8>,
    pub pan_id_compression: bool,
    pub frame_version: FrameVersion,
    pub ends: Ends<(Option<Pan>, Option<Addr>)>,
    #[wire]
    pub payload: T,
}

impl<P: PayloadParse + Data, T: WireParse<Payload = P>> WireParse for Ieee802154<T> {
    fn parse(cx: &dyn Provider, raw: P) -> Result<Self, ParseError<P>> {
        let frame = Frame(raw);

        let len = frame.0.len();

        // We need at least 3 bytes
        if len < 3 {
            return Err(ParseErrorKind::PacketTooShort.with(frame.0));
        }

        // We don't handle frames with a payload larger than 127 bytes.
        if len > 127 {
            return Err(ParseErrorKind::PacketTooLong.with(frame.0));
        }

        let mut offset = field::ADDRESSING.start
            + if let Some((dst_pan_id, dst_addr, src_pan_id, src_addr)) = frame.addr_present_flags()
            {
                let mut offset = if dst_pan_id { 2 } else { 0 };
                offset += dst_addr.size();
                offset += if src_pan_id { 2 } else { 0 };
                offset += src_addr.size();

                if offset > len {
                    return Err(ParseErrorKind::PacketTooShort.with(frame.0));
                }
                offset
            } else {
                0
            };

        if frame.security_enabled() {
            // First check that we can access the security header control bits.
            if offset + 1 > len {
                return Err(ParseErrorKind::PacketTooShort.with(frame.0));
            }

            offset += frame.security_header_len();
        }

        if offset > len {
            return Err(ParseErrorKind::PacketTooShort.with(frame.0));
        }

        Ok(Ieee802154 {
            frame_type: frame.frame_type(),
            security_enabled: frame.security_enabled(),
            frame_pending: frame.frame_pending(),
            ack_request: frame.ack_request(),
            sequence_number: frame.sequence_number(),
            pan_id_compression: frame.pan_id_compression(),
            frame_version: frame.frame_version(),
            ends: frame.ends(),

            payload: T::parse(cx, frame.0.pop(offset..len)?)?,
        })
    }
}

impl<P: PayloadBuild, T: WireBuild<Payload = P>> WireBuild for Ieee802154<T> {
    fn build(self, cx: &dyn Provider) -> Result<P, BuildError<P>> {
        let header_len = self.header_len();

        let Ieee802154 {
            frame_type,
            security_enabled,
            frame_pending,
            ack_request,
            sequence_number,
            pan_id_compression,
            frame_version,
            ends: (Src((src_pan_id, src_addr)), Dst((dst_pan_id, dst_addr))),
            payload,
        } = self;

        payload.build(cx)?.push(header_len, |buf| {
            let mut frame = Frame(buf);

            frame.set_frame_type(frame_type);
            frame.set_security_enabled(security_enabled);
            frame.set_frame_pending(frame_pending);
            frame.set_ack_request(ack_request);
            frame.set_pan_id_compression(pan_id_compression);
            frame.set_frame_version(frame_version);

            if let Some(sequence_number) = sequence_number {
                frame.set_sequence_number(sequence_number);
            }

            if let Some(dst_pan_id) = dst_pan_id {
                frame.set_dst_pan_id(dst_pan_id);
            }
            if let Some(dst_addr) = dst_addr {
                frame.set_dst_addr(dst_addr);
            }

            if !pan_id_compression && let Some(src_pan_id) = src_pan_id {
                frame.set_src_pan_id(src_pan_id);
            }

            if let Some(src_addr) = src_addr {
                frame.set_src_addr(src_addr);
            }

            Ok(())
        })
    }
}

impl<T> Ieee802154<T> {
    fn header_len(&self) -> usize {
        let (Src((_, src_addr)), Dst((_, dst_addr))) = self.ends;
        3 + 2
            + match dst_addr {
                Some(Addr::Absent) | None => 0,
                Some(Addr::Short(_)) => 2,
                Some(Addr::Extended(_)) => 8,
            }
            + if !self.pan_id_compression { 2 } else { 0 }
            + match src_addr {
                Some(Addr::Absent) | None => 0,
                Some(Addr::Short(_)) => 2,
                Some(Addr::Extended(_)) => 8,
            }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::Buf;

    #[test]
    fn test_broadcast() {
        assert!(Addr::BROADCAST.is_broadcast());
        assert!(!Addr::BROADCAST.is_unicast());
    }

    #[test]
    fn prepare_frame() {
        let mut buffer = [0u8; 128];

        let repr = Ieee802154 {
            frame_type: FrameType::Data,
            security_enabled: false,
            frame_pending: false,
            ack_request: true,
            pan_id_compression: true,
            frame_version: FrameVersion::Ieee802154,
            sequence_number: Some(1),
            ends: (
                Src((
                    None,
                    Some(Addr::Extended([
                        0xc7, 0xd9, 0xb5, 0x14, 0x00, 0x4b, 0x12, 0x00,
                    ])),
                )),
                Dst((Some(Pan(0xabcd)), Some(Addr::BROADCAST))),
            ),
            payload: PayloadHolder(10),
        };

        let buffer_len = repr.header_len();

        let buf = Buf::builder(&mut buffer[..buffer_len])
            .reserve_for(repr)
            .build();

        let buf: Buf<_> = repr.sub_payload(|_| buf).build(&()).unwrap();

        // println!("{frame:2x?}");

        let frame: Ieee802154<Buf<_>> = Ieee802154::parse(&(), buf).unwrap();

        assert_eq!(frame.frame_type, FrameType::Data);
        assert!(!frame.security_enabled);
        assert!(!frame.frame_pending);
        assert!(frame.ack_request);
        assert!(frame.pan_id_compression);
        assert_eq!(frame.frame_version, FrameVersion::Ieee802154);
        assert_eq!(frame.sequence_number, Some(1));
        assert_eq!(
            frame.ends,
            (
                Src((
                    None,
                    Some(Addr::Extended([
                        0xc7, 0xd9, 0xb5, 0x14, 0x00, 0x4b, 0x12, 0x00,
                    ])),
                )),
                Dst((Some(Pan(0xabcd)), Some(Addr::BROADCAST))),
            )
        );
    }

    macro_rules! vector_test {
        ($name:ident $bytes:expr ; $($test_method:ident -> $expected:expr,)*) => {
            #[test]
            #[allow(clippy::bool_assert_comparison)]
            fn $name() {
                let frame = &$bytes[..];
                let frame: Ieee802154<&[u8]> = Ieee802154::parse(&(), frame).unwrap();

                $(
                    assert_eq!(frame.$test_method, $expected, stringify!($test_method));
                )*
            }
        }
    }

    vector_test! {
        extended_addr
        [
            0b0000_0001, 0b1100_1100, // frame control
            0b0, // seq
            0xcd, 0xab, // pan id
            0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01, // dst addr
            0x03, 0x04, // pan id
            0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x02, // src addr
        ];
        frame_type -> FrameType::Data,
        ends -> (
            Src((Some(Pan(0x0403)), Some(Addr::Extended([0x02, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00])))),
            Dst((Some(Pan(0xabcd)), Some(Addr::Extended([0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00])))),
        ),
    }

    vector_test! {
        short_addr
        [
            0x01, 0x98,             // frame control
            0x00,                   // sequence number
            0x34, 0x12, 0x78, 0x56, // PAN identifier and address of destination
            0x34, 0x12, 0xbc, 0x9a, // PAN identifier and address of source
        ];
        frame_type -> FrameType::Data,
        security_enabled -> false,
        frame_pending -> false,
        ack_request -> false,
        pan_id_compression -> false,
        frame_version -> FrameVersion::Ieee802154_2006,
        ends -> (
            Src((Some(Pan(0x1234)), Some(Addr::Short([0x9a, 0xbc])))),
            Dst((Some(Pan(0x1234)), Some(Addr::Short([0x56, 0x78])))),
        ),
    }

    vector_test! {
        zolertia_remote
        [
            0x41, 0xd8, // frame control
            0x01, // sequence number
            0xcd, 0xab, // Destination PAN id
            0xff, 0xff, // Short destination address
            0xc7, 0xd9, 0xb5, 0x14, 0x00, 0x4b, 0x12, 0x00, // Extended source address
            0x2b, 0x00, 0x00, 0x00, // payload
        ];
        frame_type -> FrameType::Data,
        security_enabled -> false,
        frame_pending -> false,
        ack_request -> false,
        pan_id_compression -> true,
        frame_version -> FrameVersion::Ieee802154_2006,
        payload -> &[0x2b, 0x00, 0x00, 0x00][..],
    }

    vector_test! {
        security
        [
            0x69,0xdc, // frame control
            0x32, // sequence number
            0xcd,0xab, // destination PAN id
            0xbf,0x9b,0x15,0x06,0x00,0x4b,0x12,0x00, // extended destination address
            0xc7,0xd9,0xb5,0x14,0x00,0x4b,0x12,0x00, // extended source address
            0x05, // security control field
            0x31,0x01,0x00,0x00, // frame counter
            0x3e,0xe8,0xfb,0x85,0xe4,0xcc,0xf4,0x48,0x90,0xfe,0x56,0x66,0xf7,0x1c,0x65,0x9e,0xf9, // data
            0x93,0xc8,0x34,0x2e,// MIC
        ];
        frame_type -> FrameType::Data,
        security_enabled -> true,
        frame_pending -> false,
        ack_request -> true,
        pan_id_compression -> true,
        frame_version -> FrameVersion::Ieee802154_2006,
        ends -> (
            Src((None, Some(Addr::Extended([0x00,0x12,0x4b,0x00,0x14,0xb5,0xd9,0xc7])))),
            Dst((Some(Pan(0xabcd)), Some(Addr::Extended([0x00,0x12,0x4b,0x00,0x06,0x15,0x9b,0xbf])))),
        ),
        // security_level -> 5,
        // key_identifier_mode -> 0,
        // frame_counter -> Some(305),
        // key_source -> None,
        // key_index -> None,
        payload -> &[
            0x3e,0xe8,0xfb,0x85,0xe4,0xcc,0xf4,0x48,0x90,0xfe,0x56,0x66,
            0xf7,0x1c,0x65,0x9e,0xf9,0x93,0xc8,0x34,0x2e
        ][..],
        // message_integrity_code -> Some(&[0x93, 0xC8, 0x34, 0x2E][..]),
    }
}
