use crate::{
    storage::{Buf, Storage},
    wire::{PayloadHolder, WireBuild},
};

#[derive(Debug, Clone, Copy)]
pub struct Checksums {
    pub ip: bool,
    pub udp: bool,
    pub tcp: bool,
    pub icmp: bool,
}

impl Checksums {
    pub const fn new() -> Self {
        Checksums {
            ip: true,
            udp: true,
            tcp: true,
            icmp: true,
        }
    }
}

impl Default for Checksums {
    fn default() -> Self {
        Checksums::new()
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct DeviceCaps {
    pub header_len: usize,
    pub rx_checksums: Checksums,
    pub tx_checksums: Checksums,
}

impl DeviceCaps {
    pub const fn new() -> Self {
        DeviceCaps {
            header_len: 0,
            rx_checksums: Checksums::new(),
            tx_checksums: Checksums::new(),
        }
    }
}

pub trait Device {
    fn caps(&self) -> DeviceCaps;

    type Storage: Storage;

    type TxToken<'a>: TxToken<Storage = Self::Storage>
    where
        Self: 'a;

    fn receive(&mut self) -> Option<(Buf<Self::Storage>, Self::TxToken<'_>)>;

    fn transmit(&mut self) -> Option<Self::TxToken<'_>>;
}

pub trait TxToken {
    type Storage: Storage;

    fn wire_len<W: WireBuild<Payload = PayloadHolder>>(&self, wire: W) -> usize;

    fn header_len(&self) -> usize {
        self.wire_len(PayloadHolder(0))
    }

    fn consume(self, buf: Buf<Self::Storage>);
}

impl<S: Storage, D: Device<Storage = S>> Device for &mut D {
    fn caps(&self) -> DeviceCaps {
        (**self).caps()
    }

    type Storage = S;

    type TxToken<'a> = D::TxToken<'a>
    where
        Self: 'a;

    fn receive(&mut self) -> Option<(Buf<Self::Storage>, Self::TxToken<'_>)> {
        (**self).receive()
    }

    fn transmit(&mut self) -> Option<Self::TxToken<'_>> {
        (**self).transmit()
    }
}
