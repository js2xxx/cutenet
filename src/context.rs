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
}
