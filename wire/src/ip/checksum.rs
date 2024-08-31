use byteorder::{ByteOrder, NetworkEndian};

use super::*;

const fn propagate_carries(word: u32) -> u16 {
    let sum = (word >> 16) + (word & 0xffff);
    ((sum >> 16) as u16) + (sum as u16)
}

/// Compute an RFC 1071 compliant checksum (without the final complement).
pub fn data(mut data: &[u8]) -> u16 {
    let mut accum = 0;

    // For each 32-byte chunk...
    const CHUNK_SIZE: usize = 32;
    while data.len() >= CHUNK_SIZE {
        let mut d = &data[..CHUNK_SIZE];
        // ... take by 2 bytes and sum them.
        while d.len() >= 2 {
            accum += u32::from(NetworkEndian::read_u16(d));
            d = &d[2..];
        }

        data = &data[CHUNK_SIZE..];
    }

    // Sum the rest that does not fit the last 32-byte chunk,
    // taking by 2 bytes.
    while data.len() >= 2 {
        accum += u32::from(NetworkEndian::read_u16(data));
        data = &data[2..];
    }

    // Add the last remaining odd byte, if any.
    if let Some(&value) = data.first() {
        accum += u32::from(value) << 8;
    }

    propagate_carries(accum)
}

/// Combine several RFC 1071 compliant checksums.
pub fn combine(checksums: &[u16]) -> u16 {
    let accum = checksums.iter().copied().map(u32::from).sum();
    propagate_carries(accum)
}

pub fn pseudo_header_v4(
    src_addr: &Ipv4Addr,
    dst_addr: &Ipv4Addr,
    next_header: Protocol,
    length: u32,
) -> u16 {
    let mut proto_len = [0u8; 4];
    proto_len[1] = next_header.into();
    NetworkEndian::write_u16(&mut proto_len[2..4], length as u16);

    combine(&[
        data(&src_addr.octets()),
        data(&dst_addr.octets()),
        data(&proto_len[..]),
    ])
}

pub fn pseudo_header_v6(
    src_addr: &Ipv6Addr,
    dst_addr: &Ipv6Addr,
    next_header: Protocol,
    length: u32,
) -> u16 {
    let mut proto_len = [0u8; 4];
    proto_len[1] = next_header.into();
    NetworkEndian::write_u16(&mut proto_len[2..4], length as u16);

    combine(&[
        data(&src_addr.octets()),
        data(&dst_addr.octets()),
        data(&proto_len[..]),
    ])
}

pub fn pseudo_header(
    src_addr: &IpAddr,
    dst_addr: &IpAddr,
    next_header: Protocol,
    length: u32,
) -> u16 {
    match (src_addr, dst_addr) {
        (IpAddr::V4(src_addr), IpAddr::V4(dst_addr)) => {
            pseudo_header_v4(src_addr, dst_addr, next_header, length)
        }
        (IpAddr::V6(src_addr), IpAddr::V6(dst_addr)) => {
            pseudo_header_v6(src_addr, dst_addr, next_header, length)
        }
        #[allow(unreachable_patterns)]
        _ => unreachable!(),
    }
}

// We use this in pretty printer implementations.
#[allow(dead_code)]
pub(crate) fn format_checksum(f: &mut fmt::Formatter<'_>, correct: bool) -> fmt::Result {
    if !correct {
        write!(f, " (checksum incorrect)")
    } else {
        Ok(())
    }
}
