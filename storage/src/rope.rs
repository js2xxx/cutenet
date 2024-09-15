#[cfg(test)]
macro_rules! vector_test {
    ([$test:ident] $($name:ident: $perm:expr => $value:expr,)*) => {
        $(#[test]
        fn $name() {
            $test($perm, $value);
        })*
    };
}

macro_rules! vector_tests {
    ($new:expr) => {
        #[cfg(test)]
        mod tests {
            fn test(data: &[(usize, &[u8])], result: &[u8]) {
                let mut rope = $new;
                let (&last, rest) = data.split_last().unwrap();
                for &(pos, p) in rest {
                    assert_eq!(rope.merge(pos, p.to_vec()), Ok(None));
                    std::println!("{rope:?}")
                }

                let (pos, p) = last;
                assert_eq!(rope.merge(pos, p.to_vec()), Ok(Some(result.to_vec())));
            }

            const SIMPLE_DATA: &[(usize, &[u8])] = &[(0, b"hello"), (5, b" "), (6, b"world")];

            vector_test! {
                [test]

                simple_2_0: &[
                    SIMPLE_DATA[1],
                    SIMPLE_DATA[0],
                ] => b"hello ",

                simple_3_0: &[
                    SIMPLE_DATA[1],
                    SIMPLE_DATA[2],
                    SIMPLE_DATA[0],
                ] => b"hello world",

                simple_3_1: &[
                    SIMPLE_DATA[2],
                    SIMPLE_DATA[0],
                    SIMPLE_DATA[1]
                ] => b"hello world",

                simple_3_2: &[
                    SIMPLE_DATA[2],
                    SIMPLE_DATA[1],
                    SIMPLE_DATA[0],
                ] => b"hello world",
            }
        }
    };
}

#[cfg(feature = "alloc")]
mod btree;
#[cfg(feature = "alloc")]
pub use self::btree::ReorderQueue as BTreeRq;

mod r#static;
pub use self::r#static::ReorderQueue as StaticRq;
