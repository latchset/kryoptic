// Copyright 2024 Simo Sorce
// See LICENSE.txt file for terms

//! This module implements miscellaneous utilities that do not really
//! belong in any specific module

use crate::attribute::{Attribute, CkAttrs};
use crate::error::Result;
use crate::object::{Object, ObjectFactories, ObjectType};

use pkcs11::*;

/// Constant containing the size of a CK_ULONG on this architecture
pub const CK_ULONG_SIZE: usize = std::mem::size_of::<CK_ULONG>();

/// Convenience helper to copy a pointer+length obtained via FFI into a
/// valid Vector of bytes.
macro_rules! bytes_to_vec {
    ($ptr:expr, $len:expr) => {{
        let ptr = $ptr as *const u8;
        let size = usize::try_from($len).unwrap();
        if ptr == std::ptr::null_mut() || size == 0 {
            Vec::new()
        } else {
            let mut v = Vec::<u8>::with_capacity(size);
            unsafe {
                std::ptr::copy_nonoverlapping(ptr, v.as_mut_ptr(), size);
                v.set_len(size);
            }
            v
        }
    }};
}
pub(crate) use bytes_to_vec;

/// Convenience macro to type cast any pointer into a CK_VOID_PTR
macro_rules! void_ptr {
    ($ptr:expr) => {
        $ptr as *const _ as CK_VOID_PTR
    };
}
pub(crate) use void_ptr;

/// Convenience macro to type cast any pointer into a CK_BYTE_PTR
macro_rules! byte_ptr {
    ($ptr:expr) => {
        $ptr as *const _ as CK_BYTE_PTR
    };
}
pub(crate) use byte_ptr;

/// Convenience macro to cast mechanism parameters passed as pointer
/// into the structure they represent.
///
/// A length check on ulParameterLen is performed to validate that
/// the correct parameter structure is being casted.
///
/// No other validation is performed, this is an UNSAFE operation
/// that requires further content validation
macro_rules! cast_params {
    ($mech:expr, $params:ty) => {{
        let Ok(len) = usize::try_from($mech.ulParameterLen) else {
            return Err(CKR_ARGUMENTS_BAD)?;
        };
        if len != std::mem::size_of::<$params>() {
            return Err(CKR_ARGUMENTS_BAD)?;
        }
        unsafe { *($mech.pParameter as *const $params) }
    }};

    (raw_err $mech:expr, $params:ty) => {{
        let Ok(len) = usize::try_from($mech.ulParameterLen) else {
            return CKR_ARGUMENTS_BAD;
        };
        if len != std::mem::size_of::<$params>() {
            return CKR_ARGUMENTS_BAD;
        }
        unsafe { *($mech.pParameter as *const $params) }
    }};

    ($param:expr, $len:expr, $params:ty) => {{
        let Ok(len) = usize::try_from($len) else {
            return Err(CKR_ARGUMENTS_BAD)?;
        };
        if len != std::mem::size_of::<$params>() {
            return Err(CKR_ARGUMENTS_BAD)?;
        }
        unsafe { *($param as *const $params) }
    }};
}
pub(crate) use cast_params;

/// Convenience function to obtain the size of a type as a [CK_ULONG]
/// instead of a [usize]
macro_rules! sizeof {
    ($type:ty) => {
        CK_ULONG::try_from(std::mem::size_of::<$type>()).unwrap()
    };
}
pub(crate) use sizeof;

/// Convenience macro to return a (mutable) reference to a slice from
/// a pointer+length obtained via FFI
///
/// Uses unsafe functions:
/// - std::slice::from_raw_parts()
/// - std::slice::from_raw_parts_mut()
///
/// If len is 0 and empty slice reference is returned
macro_rules! bytes_to_slice {
    ($ptr: expr, $len:expr, $typ:ty) => {
        if $len > 0 {
            unsafe {
                std::slice::from_raw_parts(
                    $ptr as *const $typ,
                    usize::try_from($len).unwrap(),
                )
            }
        } else {
            &[]
        }
    };

    (mut $ptr: expr, $len:expr, $typ:ty) => {
        if $len > 0 {
            unsafe {
                std::slice::from_raw_parts_mut(
                    $ptr as *mut $typ,
                    usize::try_from($len).unwrap(),
                )
            }
        } else {
            return Err(CKR_GENERAL_ERROR)?;
        }
    };
}
pub(crate) use bytes_to_slice;

/// Helper function to prepare a Data Object as result of a derivation
/// function
///
/// Uses the DataFactory create() method after removing the incompatible
/// CKA_VALUE_LEN attribute that is required to be present in the template
/// by the derivation function
///
/// Adds other potentially missing required attributes like CKA_CLASS
#[allow(dead_code)]
pub fn common_derive_data_object(
    template: &[CK_ATTRIBUTE],
    objfactories: &ObjectFactories,
    default_len: usize,
) -> Result<(Object, usize)> {
    let default_class = CKO_DATA;
    let mut tmpl = CkAttrs::from(template);
    tmpl.add_missing_ulong(CKA_CLASS, &default_class);
    /* we must remove CKA_VALUE_LEN from the template as it is not
     * a valid attribute for a CKO_DATA object */
    let value_len = match tmpl.remove_ulong(CKA_VALUE_LEN)? {
        Some(val) => usize::try_from(val)?,
        None => {
            if default_len == 0 {
                return Err(CKR_TEMPLATE_INCOMPLETE)?;
            }
            default_len
        }
    };
    let obj = match objfactories.get_factory(ObjectType::new(CKO_DATA, 0)) {
        Ok(f) => f.create(tmpl.as_slice())?,
        Err(_) => return Err(CKR_GENERAL_ERROR)?,
    };
    Ok((obj, value_len))
}

/// Helper function to derive a Key Object
///
/// Uses the relevant "Secret Key Factory" creation method via
/// derive_key_from_template().
///
/// Handles the case where a CKA_VALUE_LEN attribute was not provided
/// in the template.
///
/// Adds other potentially missing required attributes like CKA_CLASS
#[allow(dead_code)]
pub fn common_derive_key_object(
    key: &Object,
    template: &[CK_ATTRIBUTE],
    objfactories: &ObjectFactories,
    default_len: usize,
) -> Result<(Object, usize)> {
    let default_class = CKO_SECRET_KEY;
    let mut tmpl = CkAttrs::from(template);
    tmpl.add_missing_ulong(CKA_CLASS, &default_class);
    let mut obj =
        objfactories.derive_key_from_template(key, tmpl.as_slice())?;
    let value_len = match obj.get_attr_as_ulong(CKA_VALUE_LEN) {
        Ok(val) => usize::try_from(val)?,
        Err(_) => {
            if default_len == 0 {
                return Err(CKR_TEMPLATE_INCOMPLETE)?;
            }
            obj.set_attr(Attribute::from_ulong(
                CKA_VALUE_LEN,
                CK_ULONG::try_from(default_len)?,
            ))?;
            default_len
        }
    };
    Ok((obj, value_len))
}

/// Copies a ASCII/UTF8 source string into a fixed sized destination
///
/// Both the source and the destination are provided as slices of
/// raw bytes
///
/// If the source string is longer than the destination, the string
/// is truncated.
///
/// If the source string is shorter than the destination the remaining
/// bytes are filled with the 'space' character (0x20)
///
/// Any Null (string termination) byte is removed
pub fn copy_sized_string(s: &[u8], d: &mut [u8]) {
    let slen;
    match s.last() {
        None => return,
        Some(c) => {
            if *c == b'\0' {
                slen = s.len() - 1;
            } else {
                slen = s.len();
            }
        }
    }
    if slen >= d.len() {
        d.copy_from_slice(&s[..d.len()]);
    } else {
        d[..slen].copy_from_slice(&s[..slen]);
        d[slen..].fill(0x20); /* space in ASCII/UTF8 */
    }
}

/// Helper function to abstract the zeromem function from the ossl
/// module.
///
/// This future-proofs the ability to use an alternative crypto backend
pub fn zeromem(mem: &mut [u8]) {
    ossl::zeromem(mem);
}
