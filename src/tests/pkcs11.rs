// Copyright 2025 Antonin Nepras
// See LICENSE.txt file for terms

use serial_test::parallel;

use crate::pkcs11::string_to_ck_date;

#[test]
#[parallel]
fn test_string_to_ck_date() {
    let d = string_to_ck_date("2345-12-21");
    assert!(d.is_ok());

    let date = d.unwrap();
    assert_eq!(date.year, [b'2', b'3', b'4', b'5']);
    assert_eq!(date.month, [b'1', b'2']);
    assert_eq!(date.day, [b'2', b'1']);

    assert!(string_to_ck_date("").is_err());
    assert!(string_to_ck_date("23451221").is_err()); // missing dashes
    assert!(string_to_ck_date("2345-12-2").is_err()); // too short
    assert!(string_to_ck_date("2345-12-220").is_err()); // too long
    assert!(string_to_ck_date("a345-12-22").is_err()); // contains non digits
}
