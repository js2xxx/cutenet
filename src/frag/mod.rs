use core::ops::Range;

use crate::time::Instant;

pub mod r#static;

pub trait Fragment {
    fn offset(&self) -> usize;

    fn frag_len(&self) -> usize;

    fn is_end(&self) -> bool;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FragError {
    Timeout,
    FormatInvalid,
    BufferFull,
}

pub trait Assembler {
    type Fragment: Fragment;

    type Assembled<'a>: Iterator<Item = (Range<usize>, Self::Fragment)>
    where
        Self: 'a;

    fn assemble(
        &mut self,
        now: Instant,
        fragment: Self::Fragment,
    ) -> Result<Option<Self::Assembled<'_>>, FragError>;
}
