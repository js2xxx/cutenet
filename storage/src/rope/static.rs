use heapless::Vec;

use crate::{PayloadMerge, PayloadSplit};

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
            prev.merge(p)?;
            let prev_len = prev.len();

            if let Some(&(next_pos, _)) = self.map.get(index)
                && prev_pos + prev_len >= next_pos
            {
                let (_, next) = self.map.remove(index);
                let (_, prev) = &mut self.map[prev_index];
                let (_, next) = next.split(prev_pos + prev_len - next_pos)?;
                prev.merge(next)?;
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
                cur.merge(next)?;
            }
        }

        Ok(if self.map.len() == 1 && self.map[0].0 == 0 {
            Some(self.map.remove(0).1)
        } else {
            None
        })
    }
}

impl<P, const CAP: usize> Default for ReorderQueue<P, CAP> {
    fn default() -> Self {
        Self::new()
    }
}

vector_tests!(super::ReorderQueue::<_, 8>::new());