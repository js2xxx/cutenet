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
                $(@$this:ident)? |$data:ident| $getter:expr;
                |$data_mut:ident, $arg:ident| $setter:expr;
        )*
    }) => {
        impl<T: Data + ?Sized> $packet<T> {
            $(
                #[allow(clippy::len_without_is_empty)]
                $(#[$attr])*
                fn $get(&self) -> $ty {
                    (|$($this: &Self,)? $data: &[u8]| $getter)(
                        $(self, ${ignore($this)})?
                        self.0.as_ref()
                    )
                }
            )*
        }

        impl<T: DataMut + ?Sized> $packet<T> {
            $(
                fn $set(&mut self, $arg: $ty) {
                    (|$data_mut: &mut [u8]| $setter)(self.0.as_mut())
                }
            )*
        }
    };
}

macro_rules! log_parse {
    ($err:expr => $ret:expr) => {{
        #[cfg(feature = "log")]
        tracing::info!(
            "received malformed {}: {:?}",
            core::any::type_name_of_val(&$err.data),
            $err.kind
        );
        return $ret;
    }};
}

macro_rules! log_build {
    ($err:expr) => {
        #[cfg(feature = "log")]
        tracing::info!(
            "failed to build packet {}: {:?}",
            core::any::type_name_of_val(&$err.data),
            $err.kind
        )
    };
}

macro_rules! uncheck_build {
    ($e:expr) => {
        match $e {
            Ok(value) => value,
            Err(err) => {
                log_build!(err);
                err.data
            }
        }
    };
}
