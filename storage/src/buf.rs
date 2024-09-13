use core::{
    cmp,
    ops::{Bound, Range, RangeBounds},
};

use cutenet_error::Error;

use crate::Storage;

// INVARIANT: 0 <= reserved <= storage.len()
#[derive(Debug)]
pub struct ReserveBuf<S: Storage + ?Sized> {
    reserved: usize,
    storage: S,
}

impl<S: Storage> ReserveBuf<S> {
    pub const fn new(storage: S) -> Self {
        ReserveBuf { reserved: 0, storage }
    }

    pub fn reset(self) -> Self {
        Self::new(self.storage)
    }

    pub fn from_buf_truncate(buf: Buf<S>) -> Self {
        ReserveBuf {
            reserved: buf.head,
            storage: buf.storage,
        }
    }

    /// # Safety
    ///
    /// `size` must not exceeds `len() - reserved()`.
    pub unsafe fn add_reservation_unchecked(mut self, size: usize) -> Self {
        // SAFETY: size <= len() - reserved.
        unsafe { self.reserve_unchecked(size) };
        self
    }

    pub fn try_add_reservation(mut self, size: usize) -> Result<Self, Self> {
        if self.try_reserve(size) {
            Ok(self)
        } else {
            Err(self)
        }
    }

    pub fn add_reservation(mut self, size: usize) -> Self {
        self.reserve(size);
        self
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

    pub fn try_reserve(&mut self, size: usize) -> bool {
        if size <= self.storage.len() - self.reserved {
            // SAFETY: size <= len() - reserved.
            unsafe { self.reserve_unchecked(size) };
            true
        } else {
            false
        }
    }
}

// INVARIANT: 0 <= head <= tail <= storage.len()
#[derive(Debug)]
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

    pub fn reset(self) -> ReserveBuf<S> {
        ReserveBuf {
            reserved: 0,
            storage: self.storage,
        }
    }
}

impl<S: Storage + ?Sized> Buf<S> {
    pub fn capacity(&self) -> usize {
        self.storage.len()
    }

    pub fn storage(&self) -> &S {
        &self.storage
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

impl<S: Storage + ?Sized> AsRef<[u8]> for Buf<S> {
    fn as_ref(&self) -> &[u8] {
        self.data()
    }
}

impl<S: Storage + ?Sized> AsMut<[u8]> for Buf<S> {
    fn as_mut(&mut self) -> &mut [u8] {
        self.data_mut()
    }
}

impl<S: Storage + ?Sized> Buf<S> {
    /// - Positive: moving towards the tail;
    /// - Negative: moving towards the head.
    pub fn try_move(&mut self, offset: isize) -> bool {
        match offset.cmp(&0) {
            cmp::Ordering::Equal => true,
            cmp::Ordering::Greater => {
                let offset = offset as usize;

                if offset < self.tail_len() {
                    let new_head = self.head + offset;
                    let new_tail = self.tail + offset;
                    self.storage.copy_within(self.head..self.tail, new_head);
                    (self.head, self.tail) = (new_head, new_tail);
                    true
                } else {
                    false
                }
            }
            cmp::Ordering::Less => {
                let offset = -offset as usize;

                if offset < self.head_len() {
                    let new_head = self.head - offset;
                    let new_tail = self.tail - offset;
                    self.storage.copy_within(self.head..self.tail, new_head);
                    (self.head, self.tail) = (new_head, new_tail);
                    true
                } else {
                    false
                }
            }
        }
    }

    /// - Positive: moving towards the tail;
    /// - Negative: moving towards the head.
    pub fn move_truncate(&mut self, offset: isize) {
        match offset.cmp(&0) {
            cmp::Ordering::Equal => {}
            cmp::Ordering::Greater => {
                let offset = offset as usize;

                let new_head = self.head + offset;
                let new_tail = self.tail + offset;

                let bleed = new_tail.saturating_sub(self.capacity());
                let new_tail = new_tail - bleed;
                let new_head = new_head.min(new_tail);

                if bleed < self.len() && new_head < self.capacity() {
                    self.storage
                        .copy_within(self.head..(self.tail - bleed), new_head);
                }
                (self.head, self.tail) = (new_head, new_tail);
            }
            cmp::Ordering::Less => {
                let offset = -offset as usize;

                let bleed = offset.saturating_sub(self.head);
                let new_head = self.head + bleed - offset;
                let new_tail = self.tail.saturating_sub(offset);

                if bleed < self.len() && new_tail > 0 {
                    self.storage
                        .copy_within((self.head + bleed)..self.tail, new_head);
                }
                (self.head, self.tail) = (new_head, new_tail);
            }
        }
    }

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

    pub fn try_prepend(&mut self, size: usize) -> Option<&mut [u8]> {
        (size <= self.head_len()).then(|| {
            // SAFETY: size <= head_len().
            unsafe { self.prepend_unchecked(size) }
        })
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
}

impl<S: Storage> Buf<S> {
    fn bounds(&self, s: impl RangeBounds<usize>) -> [usize; 2] {
        [
            match s.start_bound() {
                Bound::Included(&bound) => self.head + bound,
                Bound::Excluded(&bound) => self.head + bound + 1,
                Bound::Unbounded => self.head,
            },
            match s.end_bound() {
                Bound::Included(&bound) => self.head + bound - 1,
                Bound::Excluded(&bound) => self.head + bound,
                Bound::Unbounded => self.tail,
            },
        ]
    }

    /// # Safety
    ///
    /// `s` must reside with the current range (0..len).
    pub unsafe fn slice_into_unchecked(&mut self, s: impl RangeBounds<usize>) {
        let [head, tail] = self.bounds(s);
        (self.head, self.tail) = (head, tail);
    }

    pub fn slice_into(&mut self, s: impl RangeBounds<usize>) {
        let [head, tail] = self.bounds(s);
        assert!(
            self.head <= head && head <= tail && tail <= self.tail,
            "s must reside within the range (0..len)"
        );
        (self.head, self.tail) = (head, tail);
    }
}

impl<S: Storage> crate::Payload for Buf<S> {
    type NoPayload = ReserveBuf<S>;

    fn len(&self) -> usize {
        self.len()
    }

    fn truncate(self) -> Self::NoPayload {
        ReserveBuf::from_buf_truncate(self)
    }

    fn reset(self) -> Self::NoPayload {
        self.reset()
    }
}

impl<S: Storage> crate::NoPayload for ReserveBuf<S> {
    type Init = Buf<S>;

    fn reset(self) -> Self {
        self.reset()
    }

    fn reserve(self, headroom: usize) -> Self {
        self.add_reservation(headroom)
    }

    fn init(self) -> Self::Init {
        self.build()
    }
}

impl<S: Storage> crate::PayloadBuild for Buf<S> {
    fn capacity(&self) -> usize {
        self.capacity()
    }

    fn push_with<F, E>(
        mut self,
        size: usize,
        opt: &crate::PushOption,
        set_header: F,
    ) -> Result<Self, Error<E, Self>>
    where
        F: FnOnce(&mut [u8]) -> Result<(), E>,
    {
        let len = size + self.len();
        let new_len = match opt.truncate {
            Some(mtu) => len.min(mtu),
            None => len,
        };
        let new_payload_len = new_len - size;
        self.slice_into(..new_payload_len);

        if self.try_prepend(size).is_none() {
            let offset = (size - self.head_len()) as isize;
            match opt.truncate {
                Some(_) => self.move_truncate(offset),
                None if self.try_move(offset) => {}
                None => panic!("headroom too short; required additional {offset} bytes"),
            }
            Buf::prepend(&mut self, size);
        }

        match set_header(self.data_mut()) {
            Ok(()) => Ok(self),
            Err(e) => {
                self.slice_into(size..);
                Err((e, self).into())
            }
        }
    }
}

impl<S: Storage> crate::PayloadParse for Buf<S> {
    fn header_data(&self) -> &[u8] {
        self.data()
    }

    fn pop(mut self, range: Range<usize>) -> Result<Self, Self> {
        if range.end <= self.len() {
            self.slice_into(range);
            Ok(self)
        } else {
            Err(self)
        }
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
        *buf.prepend_fixed() = [1, 2];
        *buf.append_fixed() = [3, 4, 5];

        assert_eq!(buf.head(), &[0, 0, 0]);
        assert_eq!(buf.data(), &[1, 2, 3, 4, 5]);
        assert_eq!(buf.tail(), &[0, 0]);
    }

    #[test]
    fn move_truncate() {
        let mut buf = Buf::builder(vec![0; 10]).add_reservation(5).build();
        *buf.prepend_fixed() = [1, 2];
        *buf.append_fixed() = [3, 4, 5];

        buf.move_truncate(-2);
        assert_eq!(buf.data(), &[1, 2, 3, 4, 5]);
        buf.move_truncate(-3);
        assert_eq!(buf.data(), &[3, 4, 5]);

        buf.move_truncate(4);
        assert_eq!(buf.data(), &[3, 4, 5]);
        buf.move_truncate(4);
        assert_eq!(buf.data(), &[3, 4]);
    }
}
