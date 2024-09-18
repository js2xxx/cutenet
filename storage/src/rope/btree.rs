use alloc::{collections::BTreeMap, vec::Vec};
use core::ops::{Add, Bound, Range, RangeBounds, Sub};

use super::retx;
use crate::{Payload, PayloadMerge, PayloadSplit};

#[derive(Debug, Clone)]
pub struct ReorderQueue<P> {
    map: BTreeMap<usize, P>,
}

impl<P> ReorderQueue<P> {
    pub const fn new() -> Self {
        Self { map: BTreeMap::new() }
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
}

impl<P: PayloadMerge + PayloadSplit> ReorderQueue<P> {
    pub fn merge(&mut self, pos: usize, p: P) -> Result<Option<P>, P> {
        if self.map.is_empty() {
            return Ok(if pos == 0 {
                Some(p)
            } else {
                self.map.insert(pos, p);
                None
            });
        }

        let mut cursor = self.map.lower_bound_mut(Bound::Included(&pos));
        let len = p.len();

        if let Some((&cur_pos, _)) = cursor.peek_next()
            && cur_pos == pos
        {
            return Ok(None);
        }

        if let Some((&prev_pos, prev)) = cursor.peek_prev()
            && prev_pos + prev.len() >= pos
        {
            let (_, p) = p.split(prev_pos + prev.len() - pos)?;
            prev.merge(p);
            let prev_len = prev.len();

            if let Some((&next_pos, _)) = cursor.peek_next()
                && prev_pos + prev_len >= next_pos
            {
                let (_, next) = cursor.remove_next().unwrap();
                let (_, prev) = cursor.peek_prev().unwrap();
                let (_, next) = next.split(prev_pos + prev_len - next_pos)?;
                prev.merge(next);
            }
        } else {
            cursor.insert_after(pos, p).unwrap();
            cursor.next();

            if let Some((&next_pos, _)) = cursor.peek_next()
                && pos + len >= next_pos
            {
                let (_, next) = cursor.remove_next().unwrap();
                let (_, cur) = cursor.peek_prev().unwrap();
                let (_, next) = next.split(pos + len - next_pos)?;
                cur.merge(next);
            }
        }

        if self.map.len() == 1
            && let Some(entry) = self.map.first_entry()
            && entry.key() == &0
        {
            Ok(Some(entry.remove()))
        } else {
            Ok(None)
        }
    }
}

impl<P: Payload> ReorderQueue<P> {
    pub fn ranges(&self) -> impl Iterator<Item = Range<usize>> + use<'_, P> {
        self.map.iter().map(|(&pos, p)| pos..pos + p.len())
    }
}

impl<P> Default for ReorderQueue<P> {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
pub struct RetxQueue<T, P> {
    // INVARIANT: map is sorted by T.
    map: Vec<(T, P)>,
    len: usize,
}

impl<T, P> RetxQueue<T, P> {
    pub const fn new() -> Self {
        Self { map: Vec::new(), len: 0 }
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
}

impl<T, P> RetxQueue<T, P>
where
    T: PartialOrd + Copy + Sub<Output = usize> + Add<usize, Output = T>,
    P: Payload,
{
    pub fn push(&mut self, pos: T, p: P) -> Result<(), P> {
        let data = retx::push(self.map.last(), pos, p)?;
        self.len += data.1.len();
        self.map.push(data);
        Ok(())
    }

    pub fn peek(&mut self, end: T) -> impl Iterator<Item = (T, P)> + '_
    where
        P: Clone,
    {
        retx::peek(self.map.iter_mut(), end)
    }

    pub fn remove(&mut self, range: impl RangeBounds<T>) {
        if let Some((start_index, end_index)) = retx::remove(&self.map, range) {
            let drain = self.map.drain(start_index..end_index);
            drain.for_each(|(_, p)| self.len -= p.len());
        }
    }
}

impl<T, P> Default for RetxQueue<T, P> {
    fn default() -> Self {
        Self::new()
    }
}

vector_tests!(super::ReorderQueue::new(), super::RetxQueue::new());
