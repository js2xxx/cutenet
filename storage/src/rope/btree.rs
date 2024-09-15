use alloc::collections::BTreeMap;
use core::ops::Bound;

use crate::{PayloadMerge, PayloadSplit};

#[derive(Debug, Clone)]
pub struct ReorderQueue<P> {
    map: BTreeMap<usize, P>,
}

impl<P> ReorderQueue<P> {
    pub const fn new() -> Self {
        Self { map: BTreeMap::new() }
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
            prev.merge(p)?;
            let prev_len = prev.len();

            if let Some((&next_pos, _)) = cursor.peek_next()
                && prev_pos + prev_len >= next_pos
            {
                let (_, next) = cursor.remove_next().unwrap();
                let (_, prev) = cursor.peek_prev().unwrap();
                let (_, next) = next.split(prev_pos + prev_len - next_pos)?;
                prev.merge(next)?;
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
                cur.merge(next)?;
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

impl<P> Default for ReorderQueue<P> {
    fn default() -> Self {
        Self::new()
    }
}

vector_tests!(super::ReorderQueue::new());
