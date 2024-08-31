#![no_std]

use core::{any::type_name, fmt};

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct Error<K, T: ?Sized> {
    pub kind: K,
    pub data: T,
}

impl<K: fmt::Display, T: ?Sized> fmt::Display for Error<K, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.kind, type_name::<T>())
    }
}

#[macro_export]
macro_rules! make_error {
    ($kind:ident => $v:vis $err:ident) => {
        $v type $err<T: ?Sized> = cutenet_error::Error<$kind, T>;

        impl $kind {
            $v fn with<T>(self, data: T) -> $err<T> {
                $err { kind: self, data: data }
            }
        }
    };
}
