// Copyright 2025 Antonin Nepras
// See LICENSE.txt file for terms

use serial_test::parallel;

use crate::pkcs11::string_to_ck_date;
use crate::pkcs11::*;

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

#[test]
#[parallel]
fn test_ck_attribute_null_pvalue() {
    let ulong_val: CK_ULONG = 42;
    let bool_val: CK_BBOOL = CK_TRUE;
    let buf_val = [1u8, 2, 3];

    // to_ulong
    let attr_null_ulong = CK_ATTRIBUTE {
        type_: CKA_CLASS,
        pValue: std::ptr::null_mut(),
        ulValueLen: std::mem::size_of::<CK_ULONG>() as CK_ULONG,
    };
    assert_eq!(
        attr_null_ulong.to_ulong().unwrap_err().rv(),
        CKR_ATTRIBUTE_VALUE_INVALID
    );

    let attr_ok_ulong = CK_ATTRIBUTE {
        type_: CKA_CLASS,
        pValue: &ulong_val as *const _ as *mut _,
        ulValueLen: std::mem::size_of::<CK_ULONG>() as CK_ULONG,
    };
    assert_eq!(attr_ok_ulong.to_ulong().unwrap(), 42);

    // to_bool
    let attr_null_bool = CK_ATTRIBUTE {
        type_: CKA_TOKEN,
        pValue: std::ptr::null_mut(),
        ulValueLen: std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
    };
    assert_eq!(
        attr_null_bool.to_bool().unwrap_err().rv(),
        CKR_ATTRIBUTE_VALUE_INVALID
    );

    let attr_ok_bool = CK_ATTRIBUTE {
        type_: CKA_TOKEN,
        pValue: &bool_val as *const _ as *mut _,
        ulValueLen: std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
    };
    assert_eq!(attr_ok_bool.to_bool().unwrap(), true);

    // to_buf
    let attr_null_buf_nonzero = CK_ATTRIBUTE {
        type_: CKA_VALUE,
        pValue: std::ptr::null_mut(),
        ulValueLen: 16,
    };
    assert_eq!(
        attr_null_buf_nonzero.to_buf().unwrap_err().rv(),
        CKR_ATTRIBUTE_VALUE_INVALID
    );

    let attr_null_buf_zero = CK_ATTRIBUTE {
        type_: CKA_VALUE,
        pValue: std::ptr::null_mut(),
        ulValueLen: 0,
    };
    assert_eq!(attr_null_buf_zero.to_buf().unwrap(), Vec::<u8>::new());

    let attr_ok_buf = CK_ATTRIBUTE {
        type_: CKA_VALUE,
        pValue: buf_val.as_ptr() as *mut _,
        ulValueLen: buf_val.len() as CK_ULONG,
    };
    assert_eq!(attr_ok_buf.to_buf().unwrap(), vec![1, 2, 3]);
}

#[test]
#[parallel]
fn test_ck_otp_param_null_pvalue() {
    let ulong_val: CK_ULONG = 42;
    let bool_val: CK_BBOOL = CK_TRUE;
    let buf_val = [1u8, 2, 3];

    // to_ulong
    let param_null_ulong = CK_OTP_PARAM {
        type_: 1,
        pValue: std::ptr::null_mut(),
        ulValueLen: std::mem::size_of::<CK_ULONG>() as CK_ULONG,
    };
    assert_eq!(
        param_null_ulong.to_ulong().unwrap_err().rv(),
        CKR_MECHANISM_PARAM_INVALID
    );

    let param_ok_ulong = CK_OTP_PARAM {
        type_: 1,
        pValue: &ulong_val as *const _ as *mut _,
        ulValueLen: std::mem::size_of::<CK_ULONG>() as CK_ULONG,
    };
    assert_eq!(param_ok_ulong.to_ulong().unwrap(), 42);

    // to_bool
    let param_null_bool = CK_OTP_PARAM {
        type_: 1,
        pValue: std::ptr::null_mut(),
        ulValueLen: std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
    };
    assert_eq!(
        param_null_bool.to_bool().unwrap_err().rv(),
        CKR_MECHANISM_PARAM_INVALID
    );

    let param_ok_bool = CK_OTP_PARAM {
        type_: 1,
        pValue: &bool_val as *const _ as *mut _,
        ulValueLen: std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
    };
    assert_eq!(param_ok_bool.to_bool().unwrap(), true);

    // to_buf
    let param_null_buf_nonzero = CK_OTP_PARAM {
        type_: 1,
        pValue: std::ptr::null_mut(),
        ulValueLen: 16,
    };
    assert_eq!(
        param_null_buf_nonzero.to_buf().unwrap_err().rv(),
        CKR_MECHANISM_PARAM_INVALID
    );

    let param_null_buf_zero = CK_OTP_PARAM {
        type_: 1,
        pValue: std::ptr::null_mut(),
        ulValueLen: 0,
    };
    assert_eq!(param_null_buf_zero.to_buf().unwrap(), Vec::<u8>::new());

    let param_ok_buf = CK_OTP_PARAM {
        type_: 1,
        pValue: buf_val.as_ptr() as *mut _,
        ulValueLen: buf_val.len() as CK_ULONG,
    };
    assert_eq!(param_ok_buf.to_buf().unwrap(), vec![1, 2, 3]);
}
