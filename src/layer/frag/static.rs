use core::{mem, ops::Range, time::Duration};

use heapless::Vec;

use super::{Assembler, FragError, Fragment};
use crate::{config::STATIC_MAX_FRAGMENT_PACKET_COUNT, time::Instant};

#[derive(Debug)]
pub struct StaticAssembler<F: Fragment> {
    fragments: Vec<F, STATIC_MAX_FRAGMENT_PACKET_COUNT>,
    assembled_len: usize,
    total_len: Option<usize>,
    deadline: Option<Instant>,
}

impl<F: Fragment> StaticAssembler<F> {
    pub const REASSEMBLY_TIMEOUT: Duration = Duration::from_secs(60);

    pub const fn new() -> Self {
        Self {
            fragments: Vec::new(),
            assembled_len: 0,
            total_len: None,
            deadline: None,
        }
    }
}

impl<F: Fragment> Default for StaticAssembler<F> {
    fn default() -> Self {
        Self::new()
    }
}

impl<F: Fragment> Assembler for StaticAssembler<F> {
    type Fragment = F;

    type Assembled<'a> = StaticAssembled<F> where Self: 'a;

    fn push(&mut self, now: Instant, frag: F) -> Result<(), FragError> {
        match &mut self.deadline {
            Some(deadline) if *deadline < now => return Err(FragError::Timeout),
            Some(_) => {}
            ddl @ None => *ddl = Some(now + Self::REASSEMBLY_TIMEOUT),
        }

        if frag.is_end() {
            if let Some(last) = self.fragments.last()
                && last.is_end()
            {
                return Err(FragError::FormatInvalid);
            }
            self.total_len = Some(frag.offset() + frag.frag_len());
        }

        self.assembled_len += frag.frag_len();
        let pos = match self
            .fragments
            .iter()
            .rposition(|f| f.offset() < frag.offset())
        {
            Some(pos) => pos + 1,
            None => 0,
        };

        self.fragments
            .insert(pos, frag)
            .map_err(|_| FragError::BufferFull)
    }

    fn assemble(&mut self) -> Option<StaticAssembled<F>> {
        if self.assembled_len < self.total_len? {
            return None;
        }
        (self.total_len, self.deadline) = (None, None);
        Some(StaticAssembled {
            assembler: mem::take(&mut self.fragments).into_iter(),
            offset: 0,
        })
    }
}

#[must_use]
pub struct StaticAssembled<F: Fragment> {
    assembler: <Vec<F, STATIC_MAX_FRAGMENT_PACKET_COUNT> as IntoIterator>::IntoIter,
    offset: usize,
}

impl<F: Fragment> Iterator for StaticAssembled<F> {
    type Item = (Range<usize>, F);

    fn next(&mut self) -> Option<Self::Item> {
        let frag = self.assembler.next()?;
        let offset = self.offset;
        self.offset += frag.frag_len();
        Some((offset..(offset + frag.frag_len()), frag))
    }
}
