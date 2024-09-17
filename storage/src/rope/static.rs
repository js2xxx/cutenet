use core::ops::{Add, Range, RangeBounds, Sub};

use heapless::Vec;

use super::retx;
use crate::{Payload, PayloadMerge, PayloadSplit};

#[derive(Debug, Clone)]
pub struct ReorderQueue<P, const CAP: usize> {
    map: Vec<(usize, P), CAP>,
}

impl<P, const CAP: usize> ReorderQueue<P, CAP> {
    pub const fn new() -> Self {
        Self { map: Vec::new() }
    }
}

impl<P, const CAP: usize> ReorderQueue<P, CAP>
where
    P: PayloadMerge + PayloadSplit,
{
    pub fn merge(&mut self, pos: usize, p: P) -> Result<Option<P>, P> {
        let m = |(_, p)| p;

        if self.map.is_empty() {
            return Ok(if pos == 0 {
                Some(p)
            } else {
                self.map.push((pos, p)).map_err(m)?;
                None
            });
        }

        let index = self.map.partition_point(|&(i, _)| i <= pos);
        let len = p.len();

        if let Some(&(cur_pos, _)) = self.map.get(index)
            && cur_pos == pos
        {
            return Ok(None);
        }

        if let Some(prev_index) = index.checked_sub(1)
            && let Some(&mut (prev_pos, ref mut prev)) = self.map.get_mut(prev_index)
            && prev_pos + prev.len() >= pos
        {
            let (_, p) = p.split(prev_pos + prev.len() - pos)?;
            prev.merge(p);
            let prev_len = prev.len();

            if let Some(&(next_pos, _)) = self.map.get(index)
                && prev_pos + prev_len >= next_pos
            {
                let (_, next) = self.map.remove(index);
                let (_, prev) = &mut self.map[prev_index];
                let (_, next) = next.split(prev_pos + prev_len - next_pos)?;
                prev.merge(next);
            }
        } else {
            self.map.insert(index, (pos, p)).map_err(m)?;
            let next_index = index + 1;

            if let Some(&(next_pos, _)) = self.map.get(next_index)
                && pos + len >= next_pos
            {
                let (_, next) = self.map.remove(next_index);
                let (_, cur) = &mut self.map[index];
                let (_, next) = next.split(pos + len - next_pos)?;
                cur.merge(next);
            }
        }

        Ok(if self.map.len() == 1 && self.map[0].0 == 0 {
            Some(self.map.remove(0).1)
        } else {
            None
        })
    }
}

impl<P, const CAP: usize> ReorderQueue<P, CAP>
where
    P: Payload,
{
    pub fn ranges(&self) -> impl Iterator<Item = Range<usize>> + use<'_, P, CAP> {
        self.map.iter().map(|&(pos, ref p)| pos..pos + p.len())
    }
}

impl<P, const CAP: usize> Default for ReorderQueue<P, CAP> {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
pub struct RetxQueue<T, P, const CAP: usize> {
    // INVARIANT: map is sorted by T.
    map: Vec<(T, P), CAP>,
    len: usize,
}

impl<T, P, const CAP: usize> RetxQueue<T, P, CAP> {
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

impl<T, P, const CAP: usize> RetxQueue<T, P, CAP>
where
    T: PartialOrd + Copy + Sub<Output = usize> + Add<usize, Output = T>,
    P: Payload,
{
    pub fn push(&mut self, pos: T, p: P) -> Result<(), P> {
        let data = retx::push(self.map.last(), pos, p)?;
        self.len += data.1.len();
        self.map.push(data).map_err(|(_, p)| p)
    }

    pub fn peek(&mut self, end: T) -> impl Iterator<Item = (T, P)> + '_
    where
        P: Clone,
    {
        retx::peek(self.map.iter_mut(), end)
    }

    pub fn remove(&mut self, range: impl RangeBounds<T>) {
        if let Some((start_index, end_index)) = retx::remove(&self.map, range) {
            // self.map.drain(start_index..end_index);
            for _ in 0..(end_index - start_index) {
                let (_, p) = self.map.remove(start_index);
                self.len -= p.len();
            }
        }
    }
}

impl<T, P, const CAP: usize> Default for RetxQueue<T, P, CAP> {
    fn default() -> Self {
        Self::new()
    }
}

vector_tests!(
    super::ReorderQueue::<_, 8>::new(),
    super::RetxQueue::<_, _, 8>::new()
);
