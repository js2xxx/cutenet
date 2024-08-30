mod frag;
pub use self::frag::{
    r#static::{StaticAssembled, StaticAssembler},
    Assembler, FragError, Fragment,
};

mod iface;
#[cfg(any(feature = "std", feature = "alloc"))]
pub use self::iface::loopback::{arc_loopback, ArcLoopbackRx, ArcLoopbackTx};
pub use self::iface::{
    dynamic::{
        DynNetRx, DynNetRxLocal, DynNetRxVTable, DynNetTx, DynNetTxLocal, DynNetTxVTable,
        DynSyncNetTx,
    },
    ethernet::{EthernetRx, EthernetTx},
    loopback::{StaticLoopback, DEVICE_CAPS as LOOPBACK_DEVICE_CAPS, IP as LOOPBACK_IP},
    neighbor::{NeighborCacheOption, NeighborLookupError, StaticNeighborCache},
    NetRx, NetTx, SyncNetTx,
};

mod phy;
pub use self::phy::{DeviceCaps, PhyRx, PhyTx};

mod route;
pub use self::route::{
    r#static::{Destination as StaticDestination, Route as StaticRoute, StaticRouter},
    Action as RouteAction, Query as RouteQuery, Router,
};

mod socket;
pub use self::socket::{
    AllSocketSet, RawSocketSet, SocketRecv, SocketState, TcpSocketSet, UdpSocketSet,
};

mod stack;
pub use self::stack::{dispatch, process};

bitflags::bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
    pub struct Checksums: u8 {
        const IP = 1 << 0;
        const UDP = 1 << 1;
        const TCP = 1 << 2;
        const ICMP = 1 << 3;
    }
}

impl Checksums {
    pub const fn new() -> Self {
        Checksums::all()
    }

    pub const fn ip(&self) -> bool {
        self.contains(Checksums::IP)
    }

    pub const fn udp(&self) -> bool {
        self.contains(Checksums::UDP)
    }

    pub const fn tcp(&self) -> bool {
        self.contains(Checksums::TCP)
    }

    pub const fn icmp(&self) -> bool {
        self.contains(Checksums::ICMP)
    }

    pub const IGNORE: Self = Checksums::empty();
}

#[must_use]
#[derive(Debug, PartialEq, Eq, Clone, Copy, PartialOrd, Ord, Hash)]
pub enum TxResult {
    /// Transmission successful.
    Success,
    /// Also success, but with a warning.
    CongestionAlert,
    /// Transmission failed & packet dropped.
    Dropped(TxDropReason),
}

#[derive(Debug, PartialEq, Eq, Clone, Copy, PartialOrd, Ord, Hash)]
pub enum TxDropReason {
    QueueFull,
    NoRoute,
    NeighborPending,
}
