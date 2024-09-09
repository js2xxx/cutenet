use core::net::IpAddr;

use crate::{phy::DeviceCaps, route::Router, time::Instant, wire::*};

pub mod udp;

pub trait RawSocketSet<P: Payload> {
    fn receive(&mut self, now: Instant, device_caps: &DeviceCaps, packet: &IpPacket<P>) -> bool;
}

pub trait UdpSocketSet<P: Payload> {
    fn receive(
        self,
        now: Instant,
        device_caps: &DeviceCaps,
        addr: Ends<IpAddr>,
        packet: UdpPacket<P>,
    ) -> Result<(), UdpPacket<P>>;
}

pub trait TcpSocketSet<P: Payload> {
    fn receive<R: Router<P>>(
        self,
        now: Instant,
        device_caps: &DeviceCaps,
        router: &mut R,
        addr: Ends<IpAddr>,
        packet: TcpPacket<P>,
    ) -> Result<(), TcpPacket<P>>;
}

pub trait AllSocketSet<P: Payload> {
    type Raw<'a>: RawSocketSet<P>
    where
        Self: 'a;
    fn raw(&mut self) -> Self::Raw<'_>;

    type Udp<'a>: UdpSocketSet<P>
    where
        Self: 'a;
    fn udp(&mut self) -> Self::Udp<'_>;

    type Tcp<'a>: TcpSocketSet<P>
    where
        Self: 'a;
    fn tcp(&mut self) -> Self::Tcp<'_>;
}
