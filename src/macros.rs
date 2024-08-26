macro_rules! enum_with_unknown {
    (
        $( #[$enum_attr:meta] )*
        pub enum $name:ident($ty:ty) {
            $(
              $( #[$variant_attr:meta] )*
              $variant:ident = $value:expr
            ),+ $(,)?
        }
    ) => {
        #[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Hash)]
        $( #[$enum_attr] )*
        pub enum $name {
            $(
              $( #[$variant_attr] )*
              $variant
            ),*,
            Unknown($ty)
        }

        impl ::core::convert::From<$ty> for $name {
            fn from(value: $ty) -> Self {
                match value {
                    $( $value => $name::$variant ),*,
                    other => $name::Unknown(other)
                }
            }
        }

        impl ::core::convert::From<$name> for $ty {
            fn from(value: $name) -> Self {
                match value {
                    $( $name::$variant => $value ),*,
                    $name::Unknown(other) => other
                }
            }
        }
    }
}

macro_rules! wire {
    (impl $packet:ident {
        $(
            $(#[$attr:meta])*
            $get:ident/$set:ident: $ty:ty =>
                |$data:ident| $getter:expr;
                |$data_mut:ident, $arg:ident| $setter:expr;
        )*
    }) => {
        impl<T: Data + ?Sized> $packet<T> {
            $(
                #[allow(clippy::len_without_is_empty)]
                $(#[$attr])*
                pub fn $get(&self) -> $ty {
                    (|$data: &[u8]| $getter)(self.inner.as_ref())
                }
            )*
        }

        impl<T: DataMut + ?Sized> $packet<T> {
            $(
                fn $set(&mut self, $arg: $ty) {
                    (|$data_mut: &mut [u8]| $setter)(self.inner.as_mut())
                }
            )*
        }
    };
}
