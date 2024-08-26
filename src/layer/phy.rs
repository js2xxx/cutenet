use super::Checksums;
use crate::{
    storage::{Buf, Storage},
    time::Instant,
    wire::HwAddr,
};

#[derive(Debug, Clone, Copy, Default)]
pub struct DeviceCaps {
    pub header_len: usize,
    pub ip_mtu: usize,

    pub rx_checksums: Checksums,
    pub tx_checksums: Checksums,
}

impl DeviceCaps {
    pub const fn new() -> Self {
        DeviceCaps {
            header_len: 0,
            ip_mtu: 1500,

            rx_checksums: Checksums::new(),
            tx_checksums: Checksums::new(),
        }
    }

    pub fn add_header_len(mut self, len: usize) -> Self {
        self.header_len += len;
        self
    }

    pub fn with_mtu(mut self, mtu: usize) -> Self {
        self.ip_mtu = mtu;
        self
    }
}

pub trait PhyRx<S: Storage> {
    fn hw_addr(&self) -> HwAddr;

    fn caps(&self) -> DeviceCaps;

    fn receive(&mut self, now: Instant) -> Option<Buf<S>>;
}

pub trait PhyTx<S: Storage> {
    fn hw_addr(&self) -> HwAddr;

    fn caps(&self) -> DeviceCaps;

    fn transmit(&mut self, now: Instant, buf: Buf<S>);
}