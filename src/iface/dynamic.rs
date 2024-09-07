use core::{
    net::{IpAddr, Ipv6Addr},
    ptr,
};

use super::{HwAddr, NetPayload, NetRx, NetTx, TxResult};
use crate::{
    iface::neighbor::{CacheOption, LookupError},
    phy::DeviceCaps,
    time::Instant,
    wire::*,
};

#[derive(Debug, Clone, Copy)]
pub struct DynNetTxVTable<P: Payload> {
    pub hw_addr: unsafe fn(*const ()) -> HwAddr,

    pub device_caps: unsafe fn(*const ()) -> DeviceCaps,

    pub has_ip: unsafe fn(*const (), ip: IpAddr) -> bool,

    pub is_same_net: unsafe fn(*const (), ip: IpAddr) -> bool,

    pub is_broadcast: unsafe fn(*const (), ip: IpAddr) -> bool,

    pub has_solicited_node: unsafe fn(*const (), ip: Ipv6Addr) -> bool,

    pub fill_neighbor_cache:
        unsafe fn(*mut (), now: Instant, entry: (IpAddr, HwAddr), opt: CacheOption),

    pub lookup_neighbor_cache:
        unsafe fn(*const (), now: Instant, ip: IpAddr) -> Result<HwAddr, LookupError>,

    pub transmit: unsafe fn(*mut (), now: Instant, dst: HwAddr, packet: NetPayload<P>) -> TxResult,

    pub drop: unsafe fn(*mut ()),
}

impl<P: Payload> PartialEq for DynNetTxVTable<P> {
    fn eq(&self, other: &Self) -> bool {
        ptr::addr_eq(self, other)
    }
}

macro_rules! dyn_net_tx {
    ($(#[$r:meta])* $(@ $ref:tt)? $t:ident $(#[$r2:meta])* / [$($r3:tt)*]) => {
        $(#[$r])*
        #[derive(Debug)]
        pub struct $t<P: Payload + 'static> {
            data: *mut (),
            vtable: &'static DynNetTxVTable<P>,
        }

        impl<P: Payload> $t<P> {
            $(#[$r2])*
            pub unsafe fn from_raw(data: *mut (), vtable: &'static DynNetTxVTable<P>) -> Self {
                $t { data, vtable }
            }

            pub fn data(&self) -> *mut () {
                self.data
            }

            pub fn vtable(&self) -> &'static DynNetTxVTable<P> {
                self.vtable
            }
        }

        impl<P: Payload> Unpin for $t<P> {}

        impl<P: Payload> NetTx<P> for $($ref)? $t<P> {
            fn hw_addr(&self) -> HwAddr {
                // SAFETY: `self.data` and `self.vtable` is valid.
                unsafe { (self.vtable.hw_addr)(self.data) }
            }

            fn device_caps(&self) -> DeviceCaps {
                // SAFETY: `self.data` and `self.vtable` is valid.
                unsafe { (self.vtable.device_caps)(self.data) }
            }

            fn has_ip(&self, ip: IpAddr) -> bool {
                // SAFETY: `self.data` and `self.vtable` is valid.
                unsafe { (self.vtable.has_ip)(self.data, ip) }
            }

            fn is_same_net(&self, ip: IpAddr) -> bool {
                // SAFETY: `self.data` and `self.vtable` is valid.
                unsafe { (self.vtable.is_same_net)(self.data, ip) }
            }

            fn is_broadcast(&self, ip: IpAddr) -> bool {
                // SAFETY: `self.data` and `self.vtable` is valid.
                unsafe { (self.vtable.is_broadcast)(self.data, ip) }
            }

            fn has_solicited_node(&self, ip: Ipv6Addr) -> bool {
                // SAFETY: `self.data` and `self.vtable` is valid.
                unsafe { (self.vtable.has_solicited_node)(self.data, ip) }
            }

            fn fill_neighbor_cache(
                &mut self,
                now: Instant,
                entry: (IpAddr, HwAddr),
                opt: CacheOption,
            ) {
                // SAFETY: `self.data` and `self.vtable` is valid.
                unsafe { (self.vtable.fill_neighbor_cache)(self.data, now, entry, opt) }
            }

            fn lookup_neighbor_cache(
                &self,
                now: Instant,
                ip: IpAddr,
            ) -> Result<HwAddr, LookupError> {
                // SAFETY: `self.data` and `self.vtable` is valid.
                unsafe { (self.vtable.lookup_neighbor_cache)(self.data, now, ip) }
            }

            fn transmit(&mut self, now: Instant, dst: HwAddr, packet: NetPayload<P>) -> TxResult {
                // SAFETY: `self.data` and `self.vtable` is valid.
                unsafe { (self.vtable.transmit)(self.data, now, dst, packet) }
            }
        }

        impl<P: Payload> Drop for $t<P> {
            fn drop(&mut self) {
                // SAFETY: `self.data` and `self.vtable` is valid.
                unsafe { (self.vtable.drop)(self.data) }
            }
        }

        impl<P: Payload, X> From<&'static mut X> for $t<P> where $($r3)* {
            fn from(tx: &'static mut X) -> Self {
                Self {
                    data: ptr::from_mut(tx).cast(),
                    vtable: &DynNetTxVTable {
                        hw_addr: |data| unsafe { ($($ref)? *data.cast::<X>()).hw_addr() },
                        device_caps: |data| unsafe { ($($ref)? *data.cast::<X>()).device_caps() },
                        has_ip: |data, ip| unsafe { ($($ref)? *data.cast::<X>()).has_ip(ip) },
                        is_same_net: |data, ip| unsafe { ($($ref)? *data.cast::<X>()).is_same_net(ip) },
                        is_broadcast: |data, ip| unsafe { ($($ref)? *data.cast::<X>()).is_broadcast(ip) },
                        has_solicited_node: |data, ip| unsafe {
                            ($($ref)? *data.cast::<X>()).has_solicited_node(ip)
                        },
                        fill_neighbor_cache: |data, now, entry, opt| unsafe {
                            ($($ref)? *data.cast::<X>()).fill_neighbor_cache(now, entry, opt)
                        },
                        lookup_neighbor_cache: |data, now, ip| unsafe {
                            ($($ref)? *data.cast::<X>()).lookup_neighbor_cache(now, ip)
                        },
                        transmit: |data, now, dst, packet| unsafe {
                            ($($ref)? *data.cast::<X>()).transmit(now, dst, packet)
                        },
                        drop: |_| {},
                    },
                }
            }
        }

        #[cfg(any(feature = "std", feature = "alloc"))]
        impl<P: Payload, X> From<alloc::boxed::Box<X>> for $t<P> where $($r3)* {
            fn from(tx: alloc::boxed::Box<X>) -> Self {
                Self {
                    data: alloc::boxed::Box::into_raw(tx).cast(),
                    vtable: &DynNetTxVTable {
                        hw_addr: |data| unsafe { ($($ref)? *data.cast::<X>()).hw_addr() },
                        device_caps: |data| unsafe { ($($ref)? *data.cast::<X>()).device_caps() },
                        has_ip: |data, ip| unsafe { ($($ref)? *data.cast::<X>()).has_ip(ip) },
                        is_same_net: |data, ip| unsafe { ($($ref)? *data.cast::<X>()).is_same_net(ip) },
                        is_broadcast: |data, ip| unsafe { ($($ref)? *data.cast::<X>()).is_broadcast(ip) },
                        has_solicited_node: |data, ip| unsafe {
                            ($($ref)? *data.cast::<X>()).has_solicited_node(ip)
                        },
                        fill_neighbor_cache: |data, now, entry, opt| unsafe {
                            ($($ref)? *data.cast::<X>()).fill_neighbor_cache(now, entry, opt)
                        },
                        lookup_neighbor_cache: |data, now, ip| unsafe {
                            ($($ref)? *data.cast::<X>()).lookup_neighbor_cache(now, ip)
                        },
                        transmit: |data, now, dst, packet| unsafe {
                            ($($ref)? *data.cast::<X>()).transmit(now, dst, packet)
                        },
                        drop: |t| drop(unsafe { alloc::boxed::Box::from_raw(t.cast::<X>()) }),
                    },
                }
            }
        }

    };
}

dyn_net_tx! {
    /// The trasmission endpoint of a dynamic network interface which can be shared
    /// by threads.
    ///
    /// The design of this structure resembles to [`core::task::Waker`].
    @& DynSyncNetTx

    /// # Safety
    ///
    /// `data` must be a valid pointer to a struct that implements `NetTx<P> +
    /// Send + Sync`, which is dynamically provided by `vtable`.

    / [for<'a> &'a X: NetTx<P>, X: Send + Sync]
}
unsafe impl<P: Payload> Send for DynSyncNetTx<P> {}
unsafe impl<P: Payload> Sync for DynSyncNetTx<P> {}

dyn_net_tx! {
    /// The trasmission endpoint of a dynamic network interface which can be transferred
    /// between threads.
    ///
    /// The design of this structure resembles to [`core::task::Waker`].
    DynNetTx

    /// # Safety
    ///
    /// `data` must be a valid pointer to a struct that implements `NetTx<P> +
    /// Send + Sync`, which is dynamically provided by `vtable`.

    / [X: NetTx<P> + Send]
}
unsafe impl<P: Payload> Send for DynNetTx<P> {}

dyn_net_tx! {
    /// The trasmission endpoint of a dynamic network interface which cannot be shared
    /// by threads.
    ///
    /// The design of this structure resembles to [`core::task::LocalWaker`].
    DynNetTxLocal

    /// # Safety
    ///
    /// `data` must be a valid pointer to a struct that implements `NetTx<P>`, which
    /// is dynamically provided by `vtable`.

    / [X: NetTx<P>]
}

#[derive(Debug, Clone, Copy)]
pub struct DynNetRxVTable<P: Payload> {
    pub hw_addr: unsafe fn(*const ()) -> HwAddr,

    pub device_caps: unsafe fn(*const ()) -> DeviceCaps,

    #[allow(clippy::type_complexity)]
    pub receive: unsafe fn(*mut (), now: Instant) -> Option<(HwAddr, NetPayload<P>)>,

    pub drop: unsafe fn(*mut ()),
}

impl<P: Payload> PartialEq for DynNetRxVTable<P> {
    fn eq(&self, other: &Self) -> bool {
        ptr::addr_eq(self, other)
    }
}

macro_rules! dyn_net_rx {
    ($(#[$r:meta])* $t:ident $(#[$r2:meta])* / $($r3:tt)*) => {
        $(#[$r])*
        #[derive(Debug)]
        pub struct $t<P: Payload + 'static> {
            pub data: *mut (),
            pub vtable: &'static DynNetRxVTable<P>,
        }

        impl<P: Payload> $t<P> {
            $(#[$r2])*
            pub unsafe fn from_raw(data: *mut (), vtable: &'static DynNetRxVTable<P>) -> Self {
                Self { data, vtable }
            }

            pub fn data(&self) -> *mut () {
                self.data
            }

            pub fn vtable(&self) -> &'static DynNetRxVTable<P> {
                self.vtable
            }
        }

        impl<P: Payload> Unpin for $t<P> {}

        impl<P: Payload> NetRx<P> for $t<P> {
            fn hw_addr(&self) -> HwAddr {
                unsafe { (self.vtable.hw_addr)(self.data) }
            }

            fn device_caps(&self) -> DeviceCaps {
                unsafe { (self.vtable.device_caps)(self.data) }
            }

            fn receive(&mut self, now: Instant) -> Option<(HwAddr, NetPayload<P>)> {
                unsafe { (self.vtable.receive)(self.data, now) }
            }
        }

        impl<P: Payload, X: NetRx<P> + $($r3)*> From<&'static mut X> for $t<P> {
            fn from(rx: &'static mut X) -> Self {
                Self {
                    data: ptr::from_mut(rx).cast(),
                    vtable: &DynNetRxVTable {
                        hw_addr: |data| unsafe { (*data.cast::<X>()).hw_addr() },
                        device_caps: |data| unsafe { (*data.cast::<X>()).device_caps() },
                        receive: |data, now| unsafe { (*data.cast::<X>()).receive(now) },
                        drop: |_| {},
                    },
                }
            }
        }

        #[cfg(any(feature = "std", feature = "alloc"))]
        impl<P: Payload, X: NetRx<P> + $($r3)*> From<alloc::boxed::Box<X>> for $t<P> {
            fn from(rx: alloc::boxed::Box<X>) -> Self {
                Self {
                    data: alloc::boxed::Box::into_raw(rx).cast(),
                    vtable: &DynNetRxVTable {
                        hw_addr: |data| unsafe { (*data.cast::<X>()).hw_addr() },
                        device_caps: |data| unsafe { (*data.cast::<X>()).device_caps() },
                        receive: |data, now| unsafe { (*data.cast::<X>()).receive(now) },
                        drop: |data| drop(unsafe { alloc::boxed::Box::from_raw(data.cast::<X>()) }),
                    },
                }
            }
        }
    };
}

dyn_net_rx! {
    /// The reception endpoint of a dynamic network interface which can be transferred
    /// between threads.
    ///
    /// The design of this structure resembles to [`core::task::Waker`].
    DynNetRx

    /// # Safety
    ///
    /// `data` must be a valid pointer to a struct that implements `NetRx<P> +
    /// Send + Sync`, which is dynamically provided by `vtable`.

    / Send
}
unsafe impl<P: Payload> Send for DynNetRx<P> {}

dyn_net_rx! {
    /// The reception endpoint of a dynamic network interface which cannot be
    /// shared by threads.
    ///
    /// The design of this structure resembles to [`core::task::LocalWaker`].
    DynNetRxLocal

    /// # Safety
    ///
    /// `data` must be a valid pointer to a struct that implements `NetRx<P>`,
    /// which is dynamically provided by `vtable`.

    /
}
