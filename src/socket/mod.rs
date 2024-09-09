use core::net::IpAddr;

use crate::{phy::DeviceCaps, route::Router, time::Instant, wire::*};

pub mod udp;

pub trait RawSocketSet<P: Payload> {
    fn receive(&mut self, now: Instant, device_caps: &DeviceCaps, packet: &IpPacket<P>) -> bool;
}

pub trait SocketSet<T: Wire> {
    fn receive<R: Router<T::Payload>>(
        self,
        now: Instant,
        device_caps: &DeviceCaps,
        router: &mut R,
        addr: Ends<IpAddr>,
        packet: T,
    ) -> Result<(), T>;
}

pub trait AllSocketSet<P: Payload> {
    type Raw<'a>: RawSocketSet<P>
    where
        Self: 'a;
    fn raw(&mut self) -> Self::Raw<'_>;

    type Udp<'a>: SocketSet<UdpPacket<P>>
    where
        Self: 'a;
    fn udp(&mut self) -> Self::Udp<'_>;

    type Tcp<'a>: SocketSet<TcpPacket<P>>
    where
        Self: 'a;
    fn tcp(&mut self) -> Self::Tcp<'_>;
}
