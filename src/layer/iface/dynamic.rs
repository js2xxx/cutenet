use core::{
    net::{IpAddr, Ipv6Addr},
    ptr,
};

use super::{HwAddr, NetRx, NetTx, Payload};
use crate::{
    layer::{DeviceCaps, NeighborCacheOption, NeighborLookupError},
    storage::Storage,
    time::Instant,
};

#[derive(Debug, Clone, Copy)]
pub struct DynNetTxVtable<S: Storage> {
    pub hw_addr: unsafe fn(*const ()) -> HwAddr,

    pub device_caps: unsafe fn(*const ()) -> DeviceCaps,

    pub has_ip: unsafe fn(*const (), ip: IpAddr) -> bool,

    pub is_same_net: unsafe fn(*const (), ip: IpAddr) -> bool,

    pub is_broadcast: unsafe fn(*const (), ip: IpAddr) -> bool,

    pub has_solicited_node: unsafe fn(*const (), ip: Ipv6Addr) -> bool,

    pub fill_neighbor_cache:
        unsafe fn(*mut (), now: Instant, entry: (IpAddr, HwAddr), opt: NeighborCacheOption),

    pub lookup_neighbor_cache:
        unsafe fn(*const (), now: Instant, ip: IpAddr) -> Result<HwAddr, NeighborLookupError>,

    pub transmit: unsafe fn(*mut (), now: Instant, dst: HwAddr, packet: Payload<S>),

    pub drop: unsafe fn(*mut ()),
}

impl<S: Storage> PartialEq for DynNetTxVtable<S> {
    fn eq(&self, other: &Self) -> bool {
        ptr::addr_eq(self, other)
    }
}

macro_rules! dyn_net_tx {
    ($(#[$r:meta])* $t:ident $(#[$r2:meta])* / $($r3:tt)*) => {
        $(#[$r])*
        #[derive(Debug)]
        pub struct $t<S: Storage + 'static> {
            data: *mut (),
            vtable: &'static DynNetTxVtable<S>,
        }

        impl<S: Storage> $t<S> {
            $(#[$r2])*
            pub unsafe fn from_raw(data: *mut (), vtable: &'static DynNetTxVtable<S>) -> Self {
                $t { data, vtable }
            }

            pub fn data(&self) -> *mut () {
                self.data
            }

            pub fn raw_eq(&self, other: &Self) -> bool {
                self.data == other.data && self.vtable == other.vtable
            }
        }

        impl<S: Storage> Unpin for $t<S> {}

        impl<S: Storage> NetTx<S> for $t<S> {
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
                opt: NeighborCacheOption,
            ) {
                // SAFETY: `self.data` and `self.vtable` is valid.
                unsafe { (self.vtable.fill_neighbor_cache)(self.data, now, entry, opt) }
            }

            fn lookup_neighbor_cache(
                &self,
                now: Instant,
                ip: IpAddr,
            ) -> Result<HwAddr, NeighborLookupError> {
                // SAFETY: `self.data` and `self.vtable` is valid.
                unsafe { (self.vtable.lookup_neighbor_cache)(self.data, now, ip) }
            }

            fn transmit(&mut self, now: Instant, dst: HwAddr, packet: Payload<S>) {
                // SAFETY: `self.data` and `self.vtable` is valid.
                unsafe { (self.vtable.transmit)(self.data, now, dst, packet) }
            }
        }

        impl<S: Storage> Drop for $t<S> {
            fn drop(&mut self) {
                // SAFETY: `self.data` and `self.vtable` is valid.
                unsafe { (self.vtable.drop)(self.data) }
            }
        }

        impl<S: Storage, T: NetTx<S> + $($r3)*> From<&'static mut T> for $t<S> {
            fn from(tx: &'static mut T) -> Self {
                Self {
                    data: ptr::from_mut(tx).cast(),
                    vtable: &DynNetTxVtable {
                        hw_addr: |data| unsafe { (*data.cast::<T>()).hw_addr() },
                        device_caps: |data| unsafe { (*data.cast::<T>()).device_caps() },
                        has_ip: |data, ip| unsafe { (*data.cast::<T>()).has_ip(ip) },
                        is_same_net: |data, ip| unsafe { (*data.cast::<T>()).is_same_net(ip) },
                        is_broadcast: |data, ip| unsafe { (*data.cast::<T>()).is_broadcast(ip) },
                        has_solicited_node: |data, ip| unsafe {
                            (*data.cast::<T>()).has_solicited_node(ip)
                        },
                        fill_neighbor_cache: |data, now, entry, opt| unsafe {
                            (*data.cast::<T>()).fill_neighbor_cache(now, entry, opt)
                        },
                        lookup_neighbor_cache: |data, now, ip| unsafe {
                            (*data.cast::<T>()).lookup_neighbor_cache(now, ip)
                        },
                        transmit: |data, now, dst, packet| unsafe {
                            (*data.cast::<T>()).transmit(now, dst, packet)
                        },
                        drop: |_| {},
                    },
                }
            }
        }

        #[cfg(any(feature = "std", feature = "alloc"))]
        impl<S: Storage, T: NetTx<S> + $($r3)*> From<alloc::boxed::Box<T>> for $t<S> {
            fn from(tx: alloc::boxed::Box<T>) -> Self {
                Self {
                    data: alloc::boxed::Box::into_raw(tx).cast(),
                    vtable: &DynNetTxVtable {
                        hw_addr: |data| unsafe { (*data.cast::<T>()).hw_addr() },
                        device_caps: |data| unsafe { (*data.cast::<T>()).device_caps() },
                        has_ip: |data, ip| unsafe { (*data.cast::<T>()).has_ip(ip) },
                        is_same_net: |data, ip| unsafe { (*data.cast::<T>()).is_same_net(ip) },
                        is_broadcast: |data, ip| unsafe { (*data.cast::<T>()).is_broadcast(ip) },
                        has_solicited_node: |data, ip| unsafe {
                            (*data.cast::<T>()).has_solicited_node(ip)
                        },
                        fill_neighbor_cache: |data, now, entry, opt| unsafe {
                            (*data.cast::<T>()).fill_neighbor_cache(now, entry, opt)
                        },
                        lookup_neighbor_cache: |data, now, ip| unsafe {
                            (*data.cast::<T>()).lookup_neighbor_cache(now, ip)
                        },
                        transmit: |data, now, dst, packet| unsafe {
                            (*data.cast::<T>()).transmit(now, dst, packet)
                        },
                        drop: |t| drop(unsafe { alloc::boxed::Box::from_raw(t.cast::<T>()) }),
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
    DynNetTx

    /// # Safety
    ///
    /// `data` must be a valid pointer to a struct that implements `NetTx<S> +
    /// Send + Sync`, which is dynamically provided by `vtable`.

    / Send + Sync
}
unsafe impl<S: Storage> Send for DynNetTx<S> {}
unsafe impl<S: Storage> Sync for DynNetTx<S> {}

dyn_net_tx! {
    /// The trasmission endpoint of a dynamic network interface which cannot be shared
    /// by threads.
    ///
    /// The design of this structure resembles to [`core::task::LocalWaker`].
    LocalDynNetTx

    /// # Safety
    ///
    /// `data` must be a valid pointer to a struct that implements `NetTx<S>`, which
    /// is dynamically provided by `vtable`.

    /
}

#[derive(Debug, Clone, Copy)]
pub struct DynNetRxVtable<S: Storage> {
    pub hw_addr: unsafe fn(*const ()) -> HwAddr,

    pub device_caps: unsafe fn(*const ()) -> DeviceCaps,

    #[allow(clippy::type_complexity)]
    pub receive: unsafe fn(*mut (), now: Instant) -> Option<(HwAddr, Payload<S>)>,

    pub drop: unsafe fn(*mut ()),
}

impl<S: Storage> PartialEq for DynNetRxVtable<S> {
    fn eq(&self, other: &Self) -> bool {
        ptr::addr_eq(self, other)
    }
}

macro_rules! dyn_net_rx {
    ($(#[$r:meta])* $t:ident $(#[$r2:meta])* / $($r3:tt)*) => {
        $(#[$r])*
        #[derive(Debug)]
        pub struct $t<S: Storage + 'static> {
            pub data: *mut (),
            pub vtable: &'static DynNetRxVtable<S>,
        }

        impl<S: Storage> $t<S> {
            $(#[$r2])*
            pub unsafe fn from_raw(data: *mut (), vtable: &'static DynNetRxVtable<S>) -> Self {
                Self { data, vtable }
            }

            pub fn data(&self) -> *mut () {
                self.data
            }

            pub fn raw_eq(&self, other: &Self) -> bool {
                self.data == other.data && self.vtable == other.vtable
            }
        }

        impl<S: Storage> Unpin for $t<S> {}

        impl<S: Storage> NetRx<S> for $t<S> {
            fn hw_addr(&self) -> HwAddr {
                unsafe { (self.vtable.hw_addr)(self.data) }
            }

            fn device_caps(&self) -> DeviceCaps {
                unsafe { (self.vtable.device_caps)(self.data) }
            }

            fn receive(&mut self, now: Instant) -> Option<(HwAddr, Payload<S>)> {
                unsafe { (self.vtable.receive)(self.data, now) }
            }
        }

        impl<S: Storage, T: NetRx<S> + $($r3)*> From<&'static mut T> for $t<S> {
            fn from(rx: &'static mut T) -> Self {
                Self {
                    data: ptr::from_mut(rx).cast(),
                    vtable: &DynNetRxVtable {
                        hw_addr: |data| unsafe { (*data.cast::<T>()).hw_addr() },
                        device_caps: |data| unsafe { (*data.cast::<T>()).device_caps() },
                        receive: |data, now| unsafe { (*data.cast::<T>()).receive(now) },
                        drop: |_| {},
                    },
                }
            }
        }

        #[cfg(any(feature = "std", feature = "alloc"))]
        impl<S: Storage, T: NetRx<S> + $($r3)*> From<alloc::boxed::Box<T>> for $t<S> {
            fn from(rx: alloc::boxed::Box<T>) -> Self {
                Self {
                    data: alloc::boxed::Box::into_raw(rx).cast(),
                    vtable: &DynNetRxVtable {
                        hw_addr: |data| unsafe { (*data.cast::<T>()).hw_addr() },
                        device_caps: |data| unsafe { (*data.cast::<T>()).device_caps() },
                        receive: |data, now| unsafe { (*data.cast::<T>()).receive(now) },
                        drop: |data| drop(unsafe { alloc::boxed::Box::from_raw(data.cast::<T>()) }),
                    },
                }
            }
        }
    };
}

dyn_net_rx! {
    /// The reception endpoint of a dynamic network interface which can be shared
    /// by threads.
    ///
    /// The design of this structure resembles to [`core::task::Waker`].
    DynNetRx

    /// # Safety
    ///
    /// `data` must be a valid pointer to a struct that implements `NetRx<S> +
    /// Send + Sync`, which is dynamically provided by `vtable`.

    / Send + Sync
}
unsafe impl<S: Storage> Send for DynNetRx<S> {}
unsafe impl<S: Storage> Sync for DynNetRx<S> {}

dyn_net_rx! {
    /// The reception endpoint of a dynamic network interface which cannot be
    /// shared by threads.
    ///
    /// The design of this structure resembles to [`core::task::LocalWaker`].
    LocalDynNetRx

    /// # Safety
    ///
    /// `data` must be a valid pointer to a struct that implements `NetRx<S>`,
    /// which is dynamically provided by `vtable`.

    /
}