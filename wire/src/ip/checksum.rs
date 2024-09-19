use byteorder::{ByteOrder, NetworkEndian};

use super::*;

const fn propagate_carries(word: u32) -> u16 {
    let sum = (word >> 16) + (word & 0xffff);
    ((sum >> 16) as u16) + (sum as u16)
}

fn data_impl(mut data: &[u8]) -> u32 {
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

    accum
}

#[inline(always)]
fn data_elem(mut data: &[u8], odd: bool) -> u32 {
    let mut accum = 0;
    if odd {
        accum += u32::from(data[0]);
        data = &data[1..];
    }
    accum + data_impl(data)
}

/// Compute an RFC 1071 compliant checksum (without the final complement).
pub fn data(data: &[u8]) -> u16 {
    propagate_carries(data_impl(data))
}

pub fn data_iter<'a>(first: &[u8], iter: impl Iterator<Item = &'a [u8]>) -> (u16, usize) {
    let first_sum = data_elem(first, false);
    let mut odd = first.len() % 2 == 1;

    let (sum, len) = iter.fold((first_sum, first.len()), |(accum, len), data| {
        let sum = data_elem(data, odd);
        odd ^= data.len() % 2 == 1;
        (accum + sum, len + data.len())
    });
    (propagate_carries(sum), len)
}

pub fn data_iter_limited<'a>(
    first: &[u8],
    mut iter: impl Iterator<Item = &'a [u8]>,
    mut limit_len: usize,
) -> u16 {
    let len = first.len().min(limit_len);
    let mut sum = data_elem(&first[..len], false);

    limit_len -= len;
    if limit_len == 0 {
        return propagate_carries(sum);
    }

    let mut odd = first.len() % 2 == 1;

    propagate_carries(loop {
        let Some(data) = iter.next() else {
            break sum;
        };

        let len = data.len().min(limit_len);
        if len == 0 {
            break sum;
        }
        limit_len -= len;

        sum += data_elem(&data[..len], odd);
        odd ^= len % 2 == 1;
    })
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_combine_non_4_byte() {
        const DATA_1: &[u8] = &[0xbf, 0x00, 0x00, 0x35, 0x00, 0x0c, 0, 0];
        const DATA_2: &[u8] = &[0xaa, 0x00, 0x00, 0xff];

        let combined = std::vec::Vec::from_iter(DATA_1.iter().chain(DATA_2).copied());

        let sum = data_iter(DATA_1, [DATA_2].into_iter()).0;

        let header = pseudo_header(
            &IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            &IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2)),
            crate::IpProtocol::Udp,
            12,
        );

        let sum = combine(&[header, sum]);
        let combined = combine(&[header, data(&combined)]);
        assert_eq!(sum, combined);
    }
}
