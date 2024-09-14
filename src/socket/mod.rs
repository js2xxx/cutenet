use core::net::IpAddr;

use crate::{phy::DeviceCaps, route::Router, time::Instant, wire::*};

pub mod tcp;
pub mod udp;

#[derive(Debug, Clone, Copy)]
pub enum RxErrorKind {
    Full,
    Disconnected,
}
crate::error::make_error!(RxErrorKind => pub RxError);

pub trait SocketRx {
    type Item;

    fn is_connected(&self) -> bool;

    fn is_full(&self) -> bool;

    fn receive(
        &mut self,
        now: Instant,
        src: IpAddr,
        data: Self::Item,
    ) -> Result<(), RxError<Self::Item>>;
}

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
