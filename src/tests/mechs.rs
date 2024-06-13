// Copyright 2024 Simo Sorce
// See LICENSE.txt file for terms

use super::tests;
use tests::*;

use serial_test::parallel;

#[test]
#[parallel]
fn test_get_mechs() {
    let mut testtokn = TestToken::initialized("test_get_mechs.sql", None);

    let mut count: CK_ULONG = 0;
    let ret = fn_get_mechanism_list(
        testtokn.get_slot(),
        std::ptr::null_mut(),
        &mut count,
    );
    assert_eq!(ret, CKR_OK);
    let mut mechs: Vec<CK_MECHANISM_TYPE> = vec![0; count as usize];
    let ret = fn_get_mechanism_list(
        testtokn.get_slot(),
        mechs.as_mut_ptr() as CK_MECHANISM_TYPE_PTR,
        &mut count,
    );
    assert_eq!(ret, CKR_OK);
    assert_eq!(true, count > 4);
    let mut info: CK_MECHANISM_INFO = Default::default();
    let ret = fn_get_mechanism_info(testtokn.get_slot(), mechs[0], &mut info);
    assert_eq!(ret, CKR_OK);

    testtokn.finalize();
}
