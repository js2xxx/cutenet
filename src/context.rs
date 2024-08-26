use core::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Ends<T> {
    pub src: T,
    pub dst: T,
}

impl<T> Ends<T> {
    pub fn map<U>(self, mut f: impl FnMut(T) -> U) -> Ends<U> {
        Ends {
            src: f(self.src),
            dst: f(self.dst),
        }
    }

    pub fn reverse(self) -> Self {
        Ends { src: self.dst, dst: self.src }
    }
}

impl<T: fmt::Display> fmt::Display for Ends<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} -> {}", self.src, self.dst)
    }
}
