use core::ops::DerefMut;

use stable_deref_trait::StableDeref;

use crate::wire::WireBuf;

pub trait Storage: DerefMut<Target = [u8]> + StableDeref {}
impl<T: DerefMut<Target = [u8]> + StableDeref + ?Sized> Storage for T {}

// INVARIANT: 0 <= reserved <= storage.len()
pub struct ReserveBuf<S: Storage + ?Sized> {
    reserved: usize,
    storage: S,
}

impl<S: Storage> ReserveBuf<S> {
    pub const fn new(storage: S) -> Self {
        ReserveBuf { reserved: 0, storage }
    }

    /// # Safety
    ///
    /// `size` must not exceeds `len() - reserved()`.
    pub unsafe fn add_reservation_unchecked(mut self, size: usize) -> Self {
        // SAFETY: size <= len() - reserved.
        unsafe { self.reserve_unchecked(size) };
        self
    }

    pub fn add_reservation(mut self, size: usize) -> Self {
        self.reserve(size);
        self
    }

    pub fn reserve_for<W: WireBuf<Storage = S>>(self) -> Self {
        self.add_reservation(W::RESERVE)
    }

    pub fn build(self) -> Buf<S> {
        Buf {
            head: self.reserved,
            tail: self.reserved,
            storage: self.storage,
        }
    }
}

impl<S: Storage + ?Sized> ReserveBuf<S> {
    pub const fn reserved(&self) -> usize {
        self.reserved
    }

    pub fn len(&self) -> usize {
        self.storage.len()
    }

    pub fn is_empty(&self) -> bool {
        self.storage.is_empty()
    }

    /// # Safety
    ///
    /// `size` must not exceeds `len() - reserved()`.
    pub unsafe fn reserve_unchecked(&mut self, size: usize) {
        self.reserved += size;
    }

    pub fn reserve(&mut self, size: usize) {
        assert!(
            size <= self.storage.len() - self.reserved,
            "reservation failed: size ({size}) must not exceeds len - reserved ({} - {})",
            self.storage.len(),
            self.reserved
        );
        // SAFETY: size <= len() - reserved.
        unsafe { self.reserve_unchecked(size) };
    }
}

// INVARIANT: 0 <= head <= tail <= storage.len()
pub struct Buf<S: Storage + ?Sized> {
    head: usize,
    tail: usize,
    storage: S,
}

impl<S: Storage> Buf<S> {
    pub const fn builder(storage: S) -> ReserveBuf<S> {
        ReserveBuf { reserved: 0, storage }
    }

    pub const fn new(storage: S) -> Self {
        Buf { head: 0, tail: 0, storage }
    }

    pub fn full(storage: S) -> Self {
        Buf {
            head: 0,
            tail: storage.len(),
            storage,
        }
    }
}

impl<S: Storage + ?Sized> Buf<S> {
    pub fn capacity(&self) -> usize {
        self.storage.len()
    }

    pub const fn len(&self) -> usize {
        self.tail - self.head
    }

    pub const fn is_empty(&self) -> bool {
        self.tail == self.head
    }

    pub const fn head_len(&self) -> usize {
        self.head
    }

    pub fn tail_len(&self) -> usize {
        self.storage.len() - self.tail
    }

    pub fn head(&self) -> &[u8] {
        // SAFETY: 0 <= head <= storage.len()
        unsafe { self.storage.get_unchecked(..self.head) }
    }

    pub fn head_mut(&mut self) -> &mut [u8] {
        // SAFETY: 0 <= head <= storage.len()
        unsafe { self.storage.get_unchecked_mut(..self.head) }
    }

    pub fn data(&self) -> &[u8] {
        // SAFETY: 0 <= head <= tail <= storage.len()
        unsafe { self.storage.get_unchecked(self.head..self.tail) }
    }

    pub fn data_mut(&mut self) -> &mut [u8] {
        // SAFETY: 0 <= head <= tail <= storage.len()
        unsafe { self.storage.get_unchecked_mut(self.head..self.tail) }
    }

    pub fn tail(&self) -> &[u8] {
        // SAFETY: 0 <= tail <= storage.len()
        unsafe { self.storage.get_unchecked(self.tail..) }
    }

    pub fn tail_mut(&mut self) -> &mut [u8] {
        // SAFETY: 0 <= tail <= storage.len()
        unsafe { self.storage.get_unchecked_mut(self.tail..) }
    }
}

impl<S: Storage + ?Sized> Buf<S> {
    /// # Safety
    ///
    /// `size` must not exceeds `tail_len()`.
    pub unsafe fn append_unchecked(&mut self, size: usize) -> &mut [u8] {
        let start = self.tail;
        self.tail += size;
        // SAFETY: 0 <= start (old tail) <= tail <= storage.len()
        unsafe { self.storage.get_unchecked_mut(start..self.tail) }
    }

    pub fn append(&mut self, size: usize) -> &mut [u8] {
        assert!(
            size <= self.tail_len(),
            "appending failed: size ({size}) must not exceeds tail_len ({})",
            self.tail_len(),
        );
        // SAFETY: size <= tail_len().
        unsafe { self.append_unchecked(size) }
    }

    pub fn append_slice(&mut self, slice: &[u8]) {
        self.append(slice.len()).copy_from_slice(slice)
    }

    pub fn append_fixed<const N: usize>(&mut self) -> &mut [u8; N] {
        let slice = self.append(N).try_into();
        // SAFETY: slice.len() == N
        unsafe { slice.unwrap_unchecked() }
    }

    /// # Safety
    ///
    /// `size` must not exceeds `head_len()`.
    pub unsafe fn prepend_unchecked(&mut self, size: usize) -> &mut [u8] {
        let end = self.head;
        self.head -= size;
        unsafe { self.storage.get_unchecked_mut(self.head..end) }
    }

    pub fn prepend(&mut self, size: usize) -> &mut [u8] {
        assert!(
            size <= self.head_len(),
            "prepending failed: size ({size}) must not exceeds head_len ({})",
            self.head_len(),
        );
        // SAFETY: size <= head_len().
        unsafe { self.prepend_unchecked(size) }
    }

    pub fn prepend_slice(&mut self, slice: &[u8]) {
        self.prepend(slice.len()).copy_from_slice(slice)
    }

    pub fn prepend_fixed<const N: usize>(&mut self) -> &mut [u8; N] {
        let slice = self.prepend(N).try_into();
        // SAFETY: slice.len() == N
        unsafe { slice.unwrap_unchecked() }
    }

    /// # Safety
    ///
    /// `size` must not exceeds `len()`.
    pub unsafe fn append_head_unchecked(&mut self, size: usize) -> &mut [u8] {
        let start = self.head;
        self.head += size;
        // SAFETY: 0 <= start (old head) <= head <= tail <= storage.len()
        unsafe { self.storage.get_unchecked_mut(start..self.head) }
    }

    pub fn append_head(&mut self, size: usize) -> &mut [u8] {
        assert!(
            size <= self.len(),
            "head-appending failed: size ({size}) must not exceeds len ({})",
            self.len(),
        );
        // SAFETY: size <= len().
        unsafe { self.append_head_unchecked(size) }
    }

    pub fn append_head_fixed<const N: usize>(&mut self) -> &mut [u8; N] {
        let slice = self.append_head(N).try_into();
        // SAFETY: slice.len() == N
        unsafe { slice.unwrap_unchecked() }
    }
}

#[cfg(test)]
mod tests {
    use std::vec;

    use super::*;

    #[test]
    fn reserve() {
        let mut buf = Buf::builder(vec![0; 10]);
        buf.reserve(5);
        let buf = buf.build();
        assert_eq!(buf.len(), 0);
        assert_eq!(buf.head_len(), 5);
        assert_eq!(buf.tail_len(), 5);
    }

    #[test]
    #[should_panic]
    fn reserve_failed() {
        let mut buf = Buf::builder(vec![0; 5]);
        buf.reserve(10);
    }

    #[test]
    fn append_prepend() {
        let mut buf = Buf::builder(vec![0; 10]).add_reservation(5).build();
        *buf.prepend_fixed() = [0, 1, 2];
        *buf.append_head_fixed() = [10];
        *buf.append_fixed() = [3, 4, 5];

        assert_eq!(buf.head(), &[0, 0, 10]);
        assert_eq!(buf.data(), &[1, 2, 3, 4, 5]);
        assert_eq!(buf.tail(), &[0, 0]);
    }
}
