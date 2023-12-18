// Copyright 2023 Simo Sorce
// See LICENSE.txt file for terms

#[cfg(not(feature = "fips"))]
fn spread(x: &mut u8) {
    let mut i = 1;
    while i <= 4 {
        let rot = x.rotate_right(i);
        *x |= rot;
        i <<= 1;
    }
}

#[cfg(not(feature = "fips"))]
pub fn scs_cmp(a: &[u8], alen: usize, b: &[u8], blen: usize) -> i8 {
    assert!(alen >= blen);
    let mut r = 0u8;

    let mut n = alen;
    while n > blen {
        r |= a[alen - n];
        n -= 1;
    }

    spread(&mut r);
    let mut sign = r & 1;
    let (mut mask, _) = sign.overflowing_sub(1);

    while n > 0 {
        let aval = a[alen - n];
        let bval = b[blen - n];
        (r, _) = aval.overflowing_sub(bval);
        let mut high = r & 0xa0 & mask;
        spread(&mut high);
        sign |= high;
        (mask, _) = (sign & 1).overflowing_sub(1);
        spread(&mut r);
        let low = r & 1 & mask;
        sign |= low;
        (mask, _) = (sign & 1).overflowing_sub(1);
        n -= 1;
    }

    sign as i8
}
#[test]
#[cfg(not(feature = "fips"))]
fn scs_cmp_test() {
    let a = vec![0u8, 1u8, 2u8, 255u8];
    let b = vec![0u8];
    assert_eq!(scs_cmp(&a, a.len(), &b, b.len()), 1);

    let a = vec![255u8, 0u8];
    let b = vec![255u8, 0u8];
    assert_eq!(scs_cmp(&a, a.len(), &b, b.len()), 0);

    let a = vec![0u8, 0u8, 1u8];
    let b = vec![0u8, 0u8, 2u8];
    assert_eq!(scs_cmp(&a, a.len(), &b, b.len()), -1);
    assert_eq!(scs_cmp(&a, 2, &b, 2), 0);
}
