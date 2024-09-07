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

pub trait RawSocketSet<T: Wire> {
    fn receive(&mut self, now: Instant, device_caps: &DeviceCaps, packet: &IpPacket<T>) -> bool;
}

pub trait UdpSocketSet<T: Wire> {
    fn receive(
        self,
        now: Instant,
        device_caps: &DeviceCaps,
        addr: Ends<IpAddr>,
        packet: UdpPacket<T>,
    ) -> SocketRecv<UdpPacket<T>, ()>;
}

pub type TcpSocketRecv<T: Wire, Ss: SocketState> =
    SocketRecv<TcpPacket<T>, Option<(TcpPacket<T>, Ss)>>;

pub trait TcpSocketSet<T: Wire> {
    type SocketState: SocketState;

    fn receive(
        self,
        now: Instant,
        device_caps: &DeviceCaps,
        addr: Ends<IpAddr>,
        packet: TcpPacket<T>,
    ) -> TcpSocketRecv<T, Self::SocketState>;
}

pub trait AllSocketSet<T: Wire> {
    type Raw<'a>: RawSocketSet<T>
    where
        Self: 'a;
    fn raw(&mut self) -> Self::Raw<'_>;

    type Udp<'a>: UdpSocketSet<T>
    where
        Self: 'a;
    fn udp(&mut self) -> Self::Udp<'_>;

    type Tcp<'a>: TcpSocketSet<T>
    where
        Self: 'a;
    fn tcp(&mut self) -> Self::Tcp<'_>;
}
