use core::fmt;

use super::{EthernetAddr, Ieee802154Addr};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HwAddr {
    Ip,
    Ethernet(EthernetAddr),
    Ieee802154(Ieee802154Addr),
}

impl From<Ieee802154Addr> for HwAddr {
    fn from(v: Ieee802154Addr) -> Self {
        Self::Ieee802154(v)
    }
}

impl From<EthernetAddr> for HwAddr {
    fn from(v: EthernetAddr) -> Self {
        Self::Ethernet(v)
    }
}

impl HwAddr {
    pub fn ethernet(self) -> Option<EthernetAddr> {
        match self {
            HwAddr::Ethernet(eth) => Some(eth),
            HwAddr::Ip | HwAddr::Ieee802154(_) => None,
        }
    }

    pub fn unwrap_ethernet(self) -> EthernetAddr {
        self.ethernet().expect("expeced Ethernet address")
    }

    pub fn ieee802154(self) -> Option<Ieee802154Addr> {
        match self {
            HwAddr::Ieee802154(ieee) => Some(ieee),
            HwAddr::Ip | HwAddr::Ethernet(_) => None,
        }
    }

    pub fn unwrap_ieee802154(self) -> Ieee802154Addr {
        self.ieee802154().expect("expeced IEEE.802154 address")
    }
}

pub const HWADDR_MAX_LEN: usize = 8;

/// Unparsed hardware address.
///
/// Used to make NDISC parsing agnostic of the hardware medium in use.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct RawHwAddr {
    len: u8,
    data: [u8; HWADDR_MAX_LEN],
}

impl RawHwAddr {
    pub fn from_bytes(addr: &[u8]) -> Self {
        let mut data = [0u8; HWADDR_MAX_LEN];
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

    pub fn to_ethernet(self) -> Option<EthernetAddr> {
        if self.len() < 6 {
            return None;
        }
        Some(EthernetAddr::from_bytes(self.as_bytes()))
    }

    pub fn to_ieee802154(self) -> Option<Ieee802154Addr> {
        if self.len() < 8 {
            return None;
        }
        Some(Ieee802154Addr::from_bytes(self.as_bytes()))
    }
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

impl From<HwAddr> for RawHwAddr {
    fn from(value: HwAddr) -> Self {
        match value {
            HwAddr::Ip => RawHwAddr {
                len: 0,
                data: [0; HWADDR_MAX_LEN],
            },
            HwAddr::Ethernet(eth) => eth.into(),
            HwAddr::Ieee802154(ieee) => ieee.into(),
        }
    }
}

impl From<EthernetAddr> for RawHwAddr {
    fn from(addr: EthernetAddr) -> Self {
        Self::from_bytes(addr.as_bytes())
    }
}

impl From<Ieee802154Addr> for RawHwAddr {
    fn from(addr: Ieee802154Addr) -> Self {
        Self::from_bytes(addr.as_bytes())
    }
}

pub trait HwAddrExt: Copy + Eq + fmt::Display + fmt::Debug {
    fn from_bytes(bytes: &[u8]) -> Self;
}

impl HwAddrExt for EthernetAddr {
    fn from_bytes(bytes: &[u8]) -> Self {
        EthernetAddr::from_bytes(bytes)
    }
}

impl HwAddrExt for Ieee802154Addr {
    fn from_bytes(bytes: &[u8]) -> Self {
        Ieee802154Addr::from_bytes(bytes)
    }
}
