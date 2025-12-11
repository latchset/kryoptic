// Copyright 2024 Simo Sorce
// See LICENSE.txt file for terms

use crate::tests::*;

use serial_test::parallel;

#[test]
#[parallel]
fn test_random() {
    let mut testtokn = TestToken::initialized("test_random", None);
    let session = testtokn.get_session(false);

    let data: &mut [u8] = &mut [0, 0, 0, 0];
    let ret = fn_generate_random(
        session,
        data.as_mut_ptr() as *mut u8,
        data.len() as CK_ULONG,
    );
    assert_eq!(ret, CKR_OK);
    assert_ne!(data, &[0, 0, 0, 0]);

    testtokn.finalize();
}

#[test]
#[parallel]
fn test_random_seed_entropy() {
    let mut testtokn = TestToken::initialized("test_random_seed_entropy", None);
    let session = testtokn.get_session(false);

    // min entropy is 32 bytes for the default DRBG, anything less should fail
    let short_seed: &mut [u8] = &mut [1; 31];
    let ret = fn_seed_random(
        session,
        short_seed.as_mut_ptr(),
        short_seed.len() as CK_ULONG,
    );
    assert_eq!(ret, CKR_ARGUMENTS_BAD);

    // 32 bytes should be fine
    let good_seed: &mut [u8] = &mut [1; 32];
    let ret = fn_seed_random(
        session,
        good_seed.as_mut_ptr(),
        good_seed.len() as CK_ULONG,
    );
    assert_eq!(ret, CKR_OK);

    // after seeding we should be able to generate random data
    let data: &mut [u8] = &mut [0, 0, 0, 0];
    let ret = fn_generate_random(
        session,
        data.as_mut_ptr() as *mut u8,
        data.len() as CK_ULONG,
    );
    assert_eq!(ret, CKR_OK);
    assert_ne!(data, &[0, 0, 0, 0]);

    testtokn.finalize();
}
