use core::net::IpAddr;

use crate::{
    context::Ends,
    layer::phy::DeviceCaps,
    storage::{Buf, Storage},
    time::Instant,
    wire::{IpPacket, TcpPacket, UdpPacket},
};

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

pub trait RawSocketSet<S: Storage> {
    fn receive(
        &mut self,
        now: Instant,
        device_caps: &DeviceCaps,
        packet: &IpPacket<Buf<S>>,
    ) -> bool;
}

pub trait UdpSocketSet<S: Storage> {
    fn receive(
        self,
        now: Instant,
        device_caps: &DeviceCaps,
        addr: Ends<IpAddr>,
        packet: UdpPacket<Buf<S>>,
    ) -> SocketRecv<UdpPacket<Buf<S>>, ()>;
}

pub type TcpSocketRecv<S: Storage, Ss: SocketState> =
    SocketRecv<TcpPacket<Buf<S>>, Option<(TcpPacket<Buf<S>>, Ss)>>;

pub trait TcpSocketSet<S: Storage> {
    type SocketState: SocketState;

    fn receive(
        self,
        now: Instant,
        device_caps: &DeviceCaps,
        addr: Ends<IpAddr>,
        packet: TcpPacket<Buf<S>>,
    ) -> TcpSocketRecv<S, Self::SocketState>;
}

pub trait AllSocketSet<S: Storage> {
    type Raw<'a>: RawSocketSet<S>
    where
        Self: 'a;
    fn raw(&mut self) -> Self::Raw<'_>;

    type Udp<'a>: UdpSocketSet<S>
    where
        Self: 'a;
    fn udp(&mut self) -> Self::Udp<'_>;

    type Tcp<'a>: TcpSocketSet<S>
    where
        Self: 'a;
    fn tcp(&mut self) -> Self::Tcp<'_>;
}
