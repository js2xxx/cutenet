#[cfg(test)]
macro_rules! reord_test {
    ([$test:ident] $($name:ident: $perm:expr => $value:expr,)*) => {
        $(#[test]
        fn $name() {
            $test($perm, $value);
        })*
    };
}

macro_rules! vector_tests {
    ($new_reord:expr, $new_retx:expr) => {
        #[cfg(test)]
        mod tests {
            fn reord_test(data: &[(usize, &[u8])], result: &[u8]) {
                let mut rope = $new_reord;
                let (&last, rest) = data.split_last().unwrap();
                for &(pos, p) in rest {
                    assert_eq!(rope.merge(pos, p.to_vec()), Ok(None));
                    std::println!("{rope:?}")
                }

                let (pos, p) = last;
                assert_eq!(rope.merge(pos, p.to_vec()), Ok(Some(result.to_vec())));
            }

            const SIMPLE_DATA: &[(usize, &[u8])] = &[(0, b"hello"), (5, b" "), (6, b"world")];

            reord_test! {
                [reord_test]

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

            #[test]
            fn test_retx() {
                use alloc::{vec, vec::Vec};

                let mut q = $new_retx;
                q.push(3usize, b"hello".to_vec()).unwrap();
                q.push(8, b" ".to_vec()).unwrap();
                q.push(9, b"world".to_vec()).unwrap();

                assert_eq!(q.peek(3).next(), None);
                assert_eq!(q.peek(5).next(), None);
                assert_eq!(q.peek(8).collect::<Vec<_>>(), vec![(3, b"hello".to_vec())]);
                assert_eq!(q.peek(9).collect::<Vec<_>>(), vec![
                    (3, b"hello".to_vec()),
                    (8, b" ".to_vec()),
                ]);
                assert_eq!(q.peek(10).collect::<Vec<_>>(), vec![
                    (3, b"hello".to_vec()),
                    (8, b" ".to_vec()),
                ]);
                assert_eq!(q.peek(14).collect::<Vec<_>>(), vec![
                    (3, b"hello".to_vec()),
                    (8, b" ".to_vec()),
                    (9, b"world".to_vec()),
                ]);

                q.remove(8..9); // pop " "

                assert_eq!(q.peek(3).next(), None);
                assert_eq!(q.peek(5).next(), None);
                assert_eq!(q.peek(8).collect::<Vec<_>>(), vec![(3, b"hello".to_vec())]);
                assert_eq!(q.peek(9).collect::<Vec<_>>(), vec![(3, b"hello".to_vec()),]);
                assert_eq!(
                    q.peek(10).collect::<Vec<_>>(),
                    vec![(3, b"hello".to_vec()),]
                );
                assert_eq!(q.peek(14).collect::<Vec<_>>(), vec![
                    (3, b"hello".to_vec()),
                    (9, b"world".to_vec()),
                ]);

                q.remove(..12); // pop "hello"

                assert_eq!(q.peek(5).next(), None);
                assert_eq!(q.peek(9).next(), None);
                assert_eq!(q.peek(14).collect::<Vec<_>>(), vec![(9, b"world".to_vec())]);
            }
        }
    };
}

#[cfg(feature = "alloc")]
mod btree;
#[cfg(feature = "alloc")]
pub use self::btree::{ReorderQueue as BTreeReord, RetxQueue as BTreeRetx};

mod r#static;
pub use self::r#static::{ReorderQueue as StaticReord, RetxQueue as StaticRetx};

mod retx {
    use core::ops::{Add, Bound, RangeBounds, Sub};

    use crate::Payload;

    pub fn push<T, P>(last_opt: Option<&(T, P)>, pos: T, p: P) -> Result<(T, P), P>
    where
        T: PartialOrd + Copy + Sub<Output = usize> + Add<usize, Output = T>,
        P: Payload,
    {
        if let Some((last_pos, last)) = last_opt
            && (pos < *last_pos || pos - *last_pos < last.len())
        {
            return Err(p);
        }
        Ok((pos, p))
    }

    pub fn peek<'a, I, T, P>(iter: I, end: T) -> impl Iterator<Item = (T, P)> + use<'a, I, T, P>
    where
        I: Iterator<Item = &'a mut (T, P)> + 'a,
        T: 'a + PartialOrd + Copy + Sub<Output = usize> + Add<usize, Output = T>,
        P: 'a + Clone + Payload,
    {
        iter.take_while(move |(pos, p)| *pos < end && p.len() <= end - *pos)
            .map(|(pos, p)| (*pos, p.clone()))
    }

    pub fn remove<T, P>(slice: &[(T, P)], range: impl RangeBounds<T>) -> Option<(usize, usize)>
    where
        T: PartialOrd + Copy + Sub<Output = usize>,
        P: Payload,
    {
        let start_index = match range.start_bound() {
            Bound::Included(&start) => slice.partition_point(|(pos, _)| *pos < start),
            Bound::Unbounded => 0,
            Bound::Excluded(_) => panic!("end bound must be exclusive or unbounded"),
        };
        let (mut end_index, end) = match range.end_bound() {
            Bound::Excluded(&end) => (slice.partition_point(|(pos, _)| *pos < end), end),
            Bound::Unbounded | Bound::Included(_) => panic!("end bound must be exclusive"),
        };

        if let Some(index) = end_index.checked_sub(1)
            && let Some((pos, p)) = slice.get(index)
            && p.len() > end - *pos
        {
            end_index = index;
        }

        (start_index < end_index).then_some((start_index, end_index))
    }
}
