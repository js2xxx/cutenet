use core::iter;

use cutenet_config::*;
use heapless::Vec;

use super::option::Opt;
use crate::{context::WireCx, prelude::*, IpProtocol};

struct RawHeader<T: ?Sized>(T);

mod field {
    #![allow(non_snake_case)]

    use crate::field::*;

    pub const MIN_HEADER_SIZE: usize = 8;

    pub const NXT_HDR: usize = 0;
    pub const LENGTH: usize = 1;
    // Variable-length field.
    //
    // Length of the header is in 8-octet units, not including the first 8 octets.
    // The first two octets are the next header type and the header length.
    pub const fn PAYLOAD(length_field: u8) -> Field {
        let bytes = length_field as usize * 8 + 8;
        2..bytes
    }
}

wire!(impl RawHeader {
    next_header/set_next_header: IpProtocol =>
        |data| IpProtocol::from(data[field::NXT_HDR]);
        |data, value| data[field::NXT_HDR] = value.into();

    data_len/set_data_len: u8 =>
        |data| data[field::LENGTH];
        |data, value| data[field::LENGTH] = value;
});

#[derive(Debug, Clone, PartialEq, Eq, Wire)]
#[prefix(crate)]
pub struct Header<#[wire] T> {
    pub next_header: IpProtocol,
    pub options: Vec<Opt, MAX_IPV6_OPT_COUNT>,
    #[wire]
    pub payload: T,
}

impl<P: PayloadParse, T: WireParse<Payload = P>> WireParse for Header<T> {
    fn parse(cx: &dyn WireCx, raw: P) -> Result<Self, ParseError<P>> {
        let len = raw.len();
        let header = RawHeader(raw.header_data());

        if len < field::MIN_HEADER_SIZE {
            return Err(ParseErrorKind::PacketTooShort.with(raw));
        }

        let opts_range = field::PAYLOAD(header.data_len());
        if len < opts_range.end {
            return Err(ParseErrorKind::PacketTooShort.with(raw));
        }

        let mut raw_opts = &header.0[opts_range.clone()];
        let mut iter = iter::from_fn(|| {
            (!raw_opts.is_empty()).then(|| {
                Opt::parse(raw_opts)
                    .inspect(|&(_, rest)| raw_opts = rest)
                    .map(|(opt, _)| opt)
            })
        });

        let options = match iter.try_fold(Vec::new(), |mut acc, opt| {
            acc.push(opt?)
                .map_or(Err(ParseErrorKind::PacketTooLong), |_| Ok(acc))
        }) {
            Ok(t) => t,
            Err(err) => return Err(err.with(raw)),
        };

        Ok(Header {
            next_header: header.next_header(),
            options,
            payload: T::parse(
                cx,
                raw.pop(opts_range.end..len)
                    .map_err(|err| ParseErrorKind::PacketTooShort.with(err))?,
            )?,
        })
    }
}

impl<P: PayloadBuild, T: WireBuild<Payload = P>> WireBuild for Header<T> {
    fn buffer_len(&self) -> usize {
        2 + self
            .options
            .iter()
            .map(|opt| opt.buffer_len())
            .sum::<usize>()
            + self.payload.buffer_len()
    }

    fn build(self, cx: &dyn WireCx) -> Result<P, BuildError<P>> {
        let header_len = self.header_len();
        let Header { next_header, options, payload } = self;

        let payload = payload.build(cx)?;

        payload.push(header_len, |buf, _| {
            let data_len =
                u8::try_from((header_len - 1) / 8).map_err(|_| BuildErrorKind::PayloadTooLong)?;
            let mut raw_header = RawHeader(buf);

            raw_header.set_next_header(next_header);
            raw_header.set_data_len(data_len);

            let mut raw_opts = &mut raw_header.0[field::PAYLOAD(data_len)];
            for opt in options {
                raw_opts = opt.build(raw_opts);
            }

            Ok(())
        })
    }
}

#[cfg(test)]
mod test {
    use super::*;

    // A Hop-by-Hop Option header with a PadN option of option data length 4.
    static REPR_PACKET_PAD4: [u8; 8] = [0x6, 0x0, 0x1, 0x4, 0x0, 0x0, 0x0, 0x0];

    // A Hop-by-Hop Option header with a PadN option of option data length 12.
    static REPR_PACKET_PAD12: [u8; 16] = [
        0x06, 0x1, 0x1, 0x0C, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    ];

    #[test]
    fn test_check_len() {
        // zero byte buffer
        assert_eq!(
            Header::<&[u8]>::parse(&(), &[][..]),
            Err(ParseError {
                kind: ParseErrorKind::PacketTooShort,
                data: &[][..]
            }),
        );
        // no length field
        assert_eq!(
            Header::<&[u8]>::parse(&(), &REPR_PACKET_PAD4[..1]),
            Err(ParseError {
                kind: ParseErrorKind::PacketTooShort,
                data: &REPR_PACKET_PAD4[..1]
            }),
        );
        // less than 8 bytes
        assert_eq!(
            Header::<&[u8]>::parse(&(), &REPR_PACKET_PAD4[..7]),
            Err(ParseError {
                kind: ParseErrorKind::PacketTooShort,
                data: &REPR_PACKET_PAD4[..7]
            }),
        );
        // length field value greater than number of bytes
        let header: [u8; 8] = [0x06, 0x2, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0];
        assert_eq!(
            Header::<&[u8]>::parse(&(), &header[..]),
            Err(ParseError {
                kind: ParseErrorKind::PacketTooShort,
                data: &header[..]
            }),
        );
    }

    #[test]
    fn test_header_deconstruct() {
        let header = Header::parse(&(), &REPR_PACKET_PAD4[..]).unwrap();
        assert_eq!(header, Header {
            next_header: IpProtocol::Tcp,
            options: [Opt::PadN(4)].into_iter().collect(),
            payload: &[][..]
        });

        let header = Header::parse(&(), &REPR_PACKET_PAD12[..]).unwrap();
        assert_eq!(header, Header {
            next_header: IpProtocol::Tcp,
            options: [Opt::PadN(12)].into_iter().collect(),
            payload: &[][..]
        });
    }

    #[test]
    fn test_repr_construct() {
        let repr = Header {
            next_header: IpProtocol::Tcp,
            options: [Opt::PadN(4)].into_iter().collect(),
            payload: std::vec::Vec::new(),
        };
        let header = repr.build(&()).unwrap();
        assert_eq!(header, &REPR_PACKET_PAD4);

        let repr = Header {
            next_header: IpProtocol::Tcp,
            options: [Opt::PadN(12)].into_iter().collect(),
            payload: std::vec::Vec::new(),
        };
        let header = repr.build(&()).unwrap();
        assert_eq!(header, &REPR_PACKET_PAD12);
    }
}
