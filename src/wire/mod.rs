use core::fmt;

mod traits;
pub use self::traits::{
    NoPayload, NoPayloadHolder, Payload, PayloadBuild, PayloadHolder, PayloadParse, Wire,
    WireBuild, WireParse, WireSubNoPayload, WireSubstitute,
};

mod error;
pub use self::error::{BuildError, BuildErrorKind, ParseError, ParseErrorKind};

pub mod arpv4;
pub use self::arpv4::ArpV4;

pub mod ethernet;
pub use self::ethernet::Ethernet;

pub mod icmp;
pub use self::icmp::{v4::Icmpv4, v6::Icmpv6};

pub mod ieee802154;
pub use self::ieee802154::Ieee802154;

pub mod ip;
pub use self::ip::{Ip, v4::Ipv4, v6::Ipv6};

pub mod tcp;
pub use self::tcp::Tcp;

pub mod udp;
pub use self::udp::Udp;

mod field {
    use core::ops::{Range, RangeFrom};

    pub type Field = Range<usize>;
    pub type Rest = RangeFrom<usize>;
}

mod prelude {
    pub use cutenet_macros::Wire;

    pub use super::{error::*, traits::*};
}

pub trait Data: AsRef<[u8]> {}
impl<T: AsRef<[u8]> + ?Sized> Data for T {}

pub trait DataMut: Data + AsMut<[u8]> {}
impl<T: Data + AsMut<[u8]> + ?Sized> DataMut for T {}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Src<T>(pub T);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Dst<T>(pub T);

pub type Ends<T> = (Src<T>, Dst<T>);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Checksum;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct CheckPayloadLen(pub usize);

pub const MAX_HWADDR_LEN: usize = 8;

/// Unparsed hardware address.
///
/// Used to make NDISC parsing agnostic of the hardware medium in use.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct RawHwAddr {
    len: u8,
    data: [u8; MAX_HWADDR_LEN],
}

impl RawHwAddr {
    pub fn from_bytes(addr: &[u8]) -> Self {
        let mut data = [0u8; MAX_HWADDR_LEN];
        data[..addr.len()].copy_from_slice(addr);

        Self { len: addr.len() as u8, data }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.data[..self.len as usize]
    }

    pub const fn len(&self) -> usize {
        self.len as usize
    }

    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    // pub fn parse(&self, medium: Medium) -> Result<HardwareAddress> {
    //     match medium {
    //         #[cfg(feature = "medium-ethernet")]
    //         Medium::Ethernet => {
    //             if self.len() < 6 {
    //                 return Err(Error);
    //             }
    //             Ok(HardwareAddress::Ethernet(ethernet::Addr::from_bytes(
    //                 self.as_bytes(),
    //             )))
    //         }
    //         #[cfg(feature = "medium-ieee802154")]
    //         Medium::Ieee802154 => {
    //             if self.len() < 8 {
    //                 return Err(Error);
    //             }

    //             Ok(HardwareAddress::Ieee802154(ieee802154::Addr::from_bytes(
    //                 self.as_bytes(),
    //             )))
    //         }
    //         #[cfg(feature = "medium-ip")]
    //         Medium::Ip => unreachable!(),
    //     }
    // }
}

impl fmt::Display for RawHwAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, &b) in self.as_bytes().iter().enumerate() {
            if i != 0 {
                write!(f, ":")?;
            }
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

impl From<ethernet::Addr> for RawHwAddr {
    fn from(addr: ethernet::Addr) -> Self {
        Self::from_bytes(addr.as_bytes())
    }
}

impl From<ieee802154::Addr> for RawHwAddr {
    fn from(addr: ieee802154::Addr) -> Self {
        Self::from_bytes(addr.as_bytes())
    }
}
