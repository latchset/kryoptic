// Copyright 2024 Simo Sorce
// See LICENSE.txt file for terms

//! This module implements miscellaneous utilities that do not really
//! belong in any specific module

use crate::attribute::{Attribute, CkAttrs};
use crate::error::Result;
use crate::object::{Object, ObjectFactories, ObjectType};
use crate::pkcs11::*;

/// Constant containing the size of a CK_ULONG on this architecture
pub const CK_ULONG_SIZE: usize = std::mem::size_of::<CK_ULONG>();

/// Convenience helper to copy a pointer+length obtained via FFI into a
/// valid Vector of bytes.
pub fn bytes_to_vec<T>(ptr: *const T, len: usize) -> Vec<u8> {
    if ptr.is_null() || len == 0 {
        Vec::new()
    } else {
        let mut v = Vec::<u8>::with_capacity(len);
        unsafe {
            std::ptr::copy_nonoverlapping(
                ptr as *const u8,
                v.as_mut_ptr(),
                len,
            );
            v.set_len(len);
        }
        v
    }
}

/// Convenience macro to type cast any pointer into a CK_VOID_PTR
macro_rules! void_ptr {
    ($ptr:expr) => {
        $ptr as *const _ as CK_VOID_PTR
    };
}
pub(crate) use void_ptr;

/// Returns `true` if wrapping an AES key of `aes_key_bits` bits with a
/// wrapping key that provides `wrap_strength_bits` of security strength should
/// be flagged as weak.
///
/// AES-128 is always considered acceptable as a baseline (per NIST guidance a
/// 112/128-bit wrapping key is adequate to protect an AES-128 key), so a
/// wrapping is only considered weak when a stronger AES key (>= 192 bits) is
/// wrapped by a wrapping key of lower security strength.
pub fn is_weak_key_wrap(
    wrap_strength_bits: usize,
    aes_key_bits: usize,
) -> bool {
    aes_key_bits > 128 && aes_key_bits > wrap_strength_bits
}

/// Emits a warning (when the `log` feature is enabled) if a key-wrapping
/// operation protects an AES key with a wrapping key that provides less
/// security strength than the AES key itself.
///
/// See [is_weak_key_wrap] for the exact condition.
///
/// `wrap_strength_bits` is the NIST SP800-57 security strength of the wrapping
/// key, and `aes_key_bits` is the size in bits of the AES key being wrapped.
pub fn warn_weak_key_wrap(wrap_strength_bits: usize, aes_key_bits: usize) {
    if is_weak_key_wrap(wrap_strength_bits, aes_key_bits) {
        #[cfg(feature = "log")]
        log::warn!(
            "Key wrap: wrapping key security strength ({} bits) is weaker \
             than the wrapped AES key ({} bits); the effective protection is \
             reduced to {} bits",
            wrap_strength_bits,
            aes_key_bits,
            wrap_strength_bits
        );
    }
}

#[cfg(test)]
mod weak_key_wrap_tests {
    use super::is_weak_key_wrap;

    #[test]
    fn aes128_is_always_tolerated() {
        /* AES-128 is the baseline and never flagged, even with a 112-bit
         * (RSA-2048) or weaker wrapping key */
        assert!(!is_weak_key_wrap(112, 128));
        assert!(!is_weak_key_wrap(128, 128));
        assert!(!is_weak_key_wrap(80, 128));
    }

    #[test]
    fn stronger_aes_than_wrapper_is_weak() {
        /* RSA-2048 (112 bits) wrapping AES-192/256 */
        assert!(is_weak_key_wrap(112, 192));
        assert!(is_weak_key_wrap(112, 256));
        /* RSA-3072/4096 (128 bits) wrapping AES-192/256 */
        assert!(is_weak_key_wrap(128, 192));
        assert!(is_weak_key_wrap(128, 256));
    }

    #[test]
    fn matching_or_stronger_wrapper_is_not_weak() {
        /* wrapping key at least as strong as the AES key */
        assert!(!is_weak_key_wrap(192, 192));
        assert!(!is_weak_key_wrap(256, 256));
        assert!(!is_weak_key_wrap(256, 192));
    }
}

/// Convenience macro to type cast any pointer into a CK_BYTE_PTR
macro_rules! byte_ptr {
    ($ptr:expr) => {
        $ptr as *const _ as CK_BYTE_PTR
    };
}
pub(crate) use byte_ptr;

/// Convenience function to obtain the size of a type as a [CK_ULONG]
/// instead of a [usize]
macro_rules! sizeof {
    ($type:ty) => {
        CK_ULONG::try_from(std::mem::size_of::<$type>()).unwrap()
    };
}
pub(crate) use sizeof;

/// Convenience function to return a reference to a slice from
/// a pointer+length obtained via FFI
///
/// Uses unsafe functions:
/// - std::slice::from_raw_parts()
///
/// If len is 0 and empty slice reference is returned
pub(crate) unsafe fn bytes_to_slice<'a, T>(
    ptr: *const T,
    len: usize,
) -> &'a [T] {
    if len > 0 {
        unsafe { std::slice::from_raw_parts(ptr, len) }
    } else {
        &[]
    }
}

/// Convenience function to return a mutable reference to a slice from
/// a pointer+length obtained via FFI
///
/// Uses unsafe functions:
/// - std::slice::from_raw_parts_mut()
///
/// If len is 0 an error is returned
pub(crate) unsafe fn bytes_to_slice_mut<'a, T>(
    ptr: *mut T,
    len: usize,
) -> Result<&'a mut [T]> {
    if len > 0 {
        Ok(unsafe { std::slice::from_raw_parts_mut(ptr, len) })
    } else {
        Err(CKR_GENERAL_ERROR)?
    }
}

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
