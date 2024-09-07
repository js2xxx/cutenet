use core::net::IpAddr;

use crate::{phy::DeviceCaps, time::Instant, wire::*};

pub mod udp;

pub trait SocketState {
    fn update(&mut self, now: Instant, test: impl FnOnce(IpAddr) -> bool) -> bool;

    fn neighbor_missing(self, now: Instant, ip: IpAddr);
}

impl SocketState for () {
    fn update(&mut self, _now: Instant, _test: impl FnOnce(IpAddr) -> bool) -> bool {
        false
    }

    fn neighbor_missing(self, _now: Instant, _ip: IpAddr) {}
}

#[derive(Debug)]
pub enum SocketRecv<Orig, Reply> {
    NotReceived(Orig),
    Received(Reply),
}

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
    ) -> SocketRecv<UdpPacket<P>, ()>;
}

pub type TcpSocketRecv<P: Payload, Ss: SocketState> =
    SocketRecv<TcpPacket<P>, Option<(TcpPacket<P>, Ss)>>;

pub trait TcpSocketSet<P: Payload> {
    type SocketState: SocketState;

    fn receive(
        self,
        now: Instant,
        device_caps: &DeviceCaps,
        addr: Ends<IpAddr>,
        packet: TcpPacket<P>,
    ) -> TcpSocketRecv<P, Self::SocketState>;
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
