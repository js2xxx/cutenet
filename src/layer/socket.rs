use core::net::IpAddr;

use crate::{
    context::Ends,
    layer::phy::DeviceCaps,
    storage::{Buf, Storage},
    time::Instant,
    wire::{IpPacket, TcpPacket, UdpPacket},
};

#[derive(Debug)]
pub enum SocketRecv<Orig, Reply> {
    NotReceived(Orig),
    Received { reply: Reply },
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
        &mut self,
        now: Instant,
        device_caps: &DeviceCaps,
        addr: Ends<IpAddr>,
        packet: UdpPacket<Buf<S>>,
    ) -> SocketRecv<UdpPacket<Buf<S>>, ()>;
}

pub trait TcpSocketSet<S: Storage> {
    fn receive(
        &mut self,
        now: Instant,
        device_caps: &DeviceCaps,
        addr: Ends<IpAddr>,
        packet: TcpPacket<Buf<S>>,
    ) -> SocketRecv<TcpPacket<Buf<S>>, Option<TcpPacket<Buf<S>>>>;
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
