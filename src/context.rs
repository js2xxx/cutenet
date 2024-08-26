use core::{fmt, net::IpAddr};

use crate::{
    layer::Checksums,
    wire::{EthernetProtocol, IpProtocol},
};

mod provide_any;
pub use self::provide_any::{
    request_mut, request_ref, request_value, Demand, DemandWith, Provider,
};

pub trait WireCx: Provider {}

impl<T: Provider + ?Sized> WireCx for T {}

impl dyn WireCx + '_ {
    pub fn checksums(&self) -> Checksums {
        request_ref(self).copied().unwrap_or(Checksums::IGNORE)
    }

    pub fn ip_addrs(&self) -> Ends<IpAddr> {
        *request_ref(self).expect("the context has no IP address endpoints when doing checksums")
    }

    pub fn ethernet_protocol(&self) -> EthernetProtocol {
        *request_ref(self).expect("the context has no Ethernet protocol when parsing payloads")
    }

    pub fn ip_protocol(&self) -> IpProtocol {
        *request_ref(self).expect("the context has no IP protocol when parsing payloads")
    }
}

impl<const N: usize> Provider for [&dyn WireCx; N] {
    fn provide<'a>(&'a self, req: &mut Demand<'a>) {
        for p in self {
            p.provide(req);
        }
    }
}

impl<const N: usize> Provider for [&mut dyn WireCx; N] {
    fn provide<'a>(&'a self, req: &mut Demand<'a>) {
        for p in self {
            p.provide(req);
        }
    }

    fn provide_mut<'a>(&'a mut self, req: &mut Demand<'a>) {
        for p in self {
            p.provide_mut(req);
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Ends<T> {
    pub src: T,
    pub dst: T,
}

impl<T> Ends<T> {
    pub fn map<U>(self, mut f: impl FnMut(T) -> U) -> Ends<U> {
        Ends {
            src: f(self.src),
            dst: f(self.dst),
        }
    }

    pub fn reverse(self) -> Self {
        Ends { src: self.dst, dst: self.src }
    }
}

impl<T: fmt::Display> fmt::Display for Ends<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} -> {}", self.src, self.dst)
    }
}
