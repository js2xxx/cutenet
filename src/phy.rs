use super::TxResult;
use crate::{time::Instant, wire::*};

#[derive(Debug, Clone, Copy, Default)]
pub struct DeviceCaps {
    pub header_len: usize,
    pub mtu: usize,

    pub rx_checksums: Checksums,
    pub tx_checksums: Checksums,
}

impl DeviceCaps {
    pub const fn new() -> Self {
        DeviceCaps {
            header_len: 0,
            mtu: 1500,

            rx_checksums: Checksums::new(),
            tx_checksums: Checksums::new(),
        }
    }

    pub fn add_header_len(mut self, len: usize) -> Self {
        self.header_len += len;
        self
    }
}

pub trait PhyRx<P: Payload> {
    fn hw_addr(&self) -> HwAddr;

    fn caps(&self) -> DeviceCaps;

    fn receive(&mut self, now: Instant) -> Option<P>;
}

pub trait PhyTx<P: Payload> {
    fn hw_addr(&self) -> HwAddr;

    fn caps(&self) -> DeviceCaps;

    fn transmit(&mut self, now: Instant, payload: P) -> TxResult;
}
