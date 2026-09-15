// Copyright 2024 Simo Sorce
// See LICENSE.txt file for terms

//! This module implements miscellaneous utilities that do not really
//! belong in any specific module

use std::borrow::Cow;

use crate::attribute::{Attribute, CkAttrs};
use crate::error::Result;
use crate::object::{Object, ObjectFactories, ObjectType};
use crate::pkcs11::*;

/// Constant containing the size of a CK_ULONG on this architecture
pub const CK_ULONG_SIZE: usize = std::mem::size_of::<CK_ULONG>();

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

/// Convenience function to obtain the size of a type as a [CK_ULONG]
/// instead of a [usize]
macro_rules! sizeof {
    ($type:ty) => {
        CK_ULONG::try_from(std::mem::size_of::<$type>()).unwrap()
    };
}
pub(crate) use sizeof;

/// Helper function to parse a CK_ULONG into a usize.
pub(crate) fn parse_len(val: CK_ULONG) -> Result<usize> {
    usize::try_from(val).map_err(|_| CKR_ARGUMENTS_BAD.into())
}

/// Trait representing 1-byte sized types that have no alignment requirements.
pub(crate) trait Byte: Copy {}

impl Byte for u8 {}
impl Byte for i8 {}
impl Byte for bool {}

/// Convenience function to return a reference to a slice from
/// a pointer+length obtained via FFI for 1-byte sized types.
///
/// Uses unsafe functions:
/// - std::slice::from_raw_parts()
///
/// If len is 0 an empty slice reference is returned
pub(crate) fn bytes_to_slice<'a, T: Byte>(
    ptr: *const T,
    len: usize,
) -> &'a [T] {
    if ptr.is_null() || len == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(ptr, len) }
    }
}

/// Convenience helper to copy a pointer+length obtained via FFI into a
/// valid Vector of bytes.
pub fn bytes_to_vec<T>(ptr: *const T, len: usize) -> Vec<u8> {
    bytes_to_slice(ptr as *const u8, len).to_vec()
}

/// Convenience function to return a mutable reference to a slice from
/// a pointer+length obtained via FFI for 1-byte sized types.
///
/// Uses unsafe functions:
/// - std::slice::from_raw_parts_mut()
///
/// If ptr is null an error is returned.
/// If len is 0 an empty slice reference is returned.
pub(crate) fn bytes_to_slice_mut<'a, T: Byte>(
    ptr: *mut T,
    len: usize,
) -> Result<&'a mut [T]> {
    if ptr.is_null() {
        Err(CKR_ARGUMENTS_BAD)?
    } else if len == 0 {
        Ok(&mut [])
    } else {
        Ok(unsafe { std::slice::from_raw_parts_mut(ptr, len) })
    }
}

/// Convenience function to return a slice from a pointer+length obtained
/// via FFI as a Cow, handling alignment requirements for multi-byte types.
///
/// Uses unsafe functions:
/// - std::slice::from_raw_parts()
/// - std::ptr::copy_nonoverlapping()
///
/// If len is 0 an empty slice reference is returned.
/// If len > 0 and ptr is null an error is returned.
/// If ptr is aligned, Cow::Borrowed is returned.
/// If ptr is not aligned, the data is copied to a Vec and Cow::Owned is returned.
pub(crate) fn struct_to_slice<'a, T: Clone>(
    ptr: *const T,
    len: usize,
) -> Result<Cow<'a, [T]>> {
    if len == 0 {
        Ok(Cow::Borrowed(&[]))
    } else if ptr.is_null() {
        Err(CKR_ARGUMENTS_BAD)?
    } else if ptr.is_aligned() {
        Ok(Cow::Borrowed(unsafe {
            std::slice::from_raw_parts(ptr, len)
        }))
    } else {
        let mut v = Vec::<T>::with_capacity(len);
        unsafe {
            std::ptr::copy_nonoverlapping(
                ptr as *const u8,
                v.as_mut_ptr() as *mut u8,
                len * std::mem::size_of::<T>(),
            );
            v.set_len(len);
        }
        Ok(Cow::Owned(v))
    }
}

/// A copy-on-write smart pointer for mutable slices from FFI pointers.
///
/// When the pointer is aligned, it borrows the slice mutably.
/// When the pointer is unaligned, it copies the data to an aligned Vec,
/// allows in-place mutation, and writes the modified data back to the
/// original pointer upon drop.
#[allow(dead_code)]
#[derive(Debug)]
pub(crate) enum CowMut<'a, T> {
    Borrowed(&'a mut [T]),
    Owned { vec: Vec<T>, ptr: *mut T },
}

impl<T> std::ops::Deref for CowMut<'_, T> {
    type Target = [T];

    fn deref(&self) -> &Self::Target {
        match self {
            CowMut::Borrowed(s) => s,
            CowMut::Owned { vec, .. } => vec.as_slice(),
        }
    }
}

impl<T> std::ops::DerefMut for CowMut<'_, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        match self {
            CowMut::Borrowed(s) => s,
            CowMut::Owned { vec, .. } => vec.as_mut_slice(),
        }
    }
}

impl<T> AsRef<[T]> for CowMut<'_, T> {
    fn as_ref(&self) -> &[T] {
        self
    }
}

impl<T> AsMut<[T]> for CowMut<'_, T> {
    fn as_mut(&mut self) -> &mut [T] {
        self
    }
}

impl<T> Drop for CowMut<'_, T> {
    fn drop(&mut self) {
        if let CowMut::Owned { vec, ptr } = self {
            unsafe {
                std::ptr::copy_nonoverlapping(
                    vec.as_ptr() as *const u8,
                    *ptr as *mut u8,
                    vec.len() * std::mem::size_of::<T>(),
                );
            }
        }
    }
}

/// Convenience function to return a mutable slice from a pointer+length obtained
/// via FFI as a CowMut, handling alignment requirements for multi-byte types.
///
/// Uses unsafe functions:
/// - std::slice::from_raw_parts_mut()
/// - std::ptr::copy_nonoverlapping()
///
/// If ptr is null an error is returned.
/// If len is 0 an empty slice reference is returned.
/// If ptr is aligned, CowMut::Borrowed is returned.
/// If ptr is not aligned, the data is copied to a Vec and CowMut::Owned is returned,
/// which copies the data back to the pointer upon drop.
#[allow(dead_code)]
pub(crate) fn struct_to_slice_mut<'a, T: Clone>(
    ptr: *mut T,
    len: usize,
) -> Result<CowMut<'a, T>> {
    if ptr.is_null() {
        Err(CKR_ARGUMENTS_BAD)?
    } else if len == 0 {
        Ok(CowMut::Borrowed(&mut []))
    } else if ptr.is_aligned() {
        Ok(CowMut::Borrowed(unsafe {
            std::slice::from_raw_parts_mut(ptr, len)
        }))
    } else {
        let mut v = Vec::<T>::with_capacity(len);
        unsafe {
            std::ptr::copy_nonoverlapping(
                ptr as *const u8,
                v.as_mut_ptr() as *mut u8,
                len * std::mem::size_of::<T>(),
            );
            v.set_len(len);
        }
        Ok(CowMut::Owned { vec: v, ptr })
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bytes_to_slice() {
        let data = [1u8, 2, 3, 4];
        let s = bytes_to_slice(data.as_ptr(), data.len());
        assert_eq!(s, &[1, 2, 3, 4]);

        let empty: *const u8 = std::ptr::null();
        let s = bytes_to_slice(empty, 0);
        assert_eq!(s, &[] as &[u8]);
    }

    #[test]
    fn test_bytes_to_slice_mut() {
        let mut data = [1u8, 2, 3, 4];
        let s = bytes_to_slice_mut(data.as_mut_ptr(), data.len()).unwrap();
        s[0] = 10;
        assert_eq!(data[0], 10);

        let empty: *mut u8 = std::ptr::null_mut();
        let s = bytes_to_slice_mut(empty, 0);
        assert!(s.is_err());

        let mut dummy = 0u8;
        let s = bytes_to_slice_mut(&mut dummy, 0).unwrap();
        assert_eq!(s, &mut [] as &mut [u8]);
    }

    #[test]
    fn test_struct_to_slice_empty() {
        let p: *const u32 = std::ptr::null();
        let s = struct_to_slice(p, 0).unwrap();
        assert_eq!(s.len(), 0);
        assert!(matches!(s, Cow::Borrowed(_)));
    }

    #[test]
    fn test_struct_to_slice_null() {
        let p: *const u32 = std::ptr::null();
        let s = struct_to_slice(p, 1);
        assert!(s.is_err());
    }

    #[test]
    fn test_struct_to_slice_aligned() {
        let data = [1u32, 2, 3, 4];
        let s = struct_to_slice(data.as_ptr(), data.len()).unwrap();
        assert_eq!(s.as_ref(), &[1, 2, 3, 4]);
        assert!(matches!(s, Cow::Borrowed(_)));
    }

    #[test]
    fn test_struct_to_slice_unaligned() {
        #[repr(align(8))]
        struct AlignedBuf([u8; 32]);
        let mut buf = AlignedBuf([0u8; 32]);
        let unaligned_bytes = &mut buf.0[1..17];
        let values = [10u32, 20, 30, 40];
        for (i, v) in values.iter().enumerate() {
            unaligned_bytes[i * 4..(i + 1) * 4]
                .copy_from_slice(&v.to_ne_bytes());
        }
        let unaligned_ptr = unaligned_bytes.as_ptr() as *const u32;
        assert!(!unaligned_ptr.is_aligned());
        let s = struct_to_slice(unaligned_ptr, 4).unwrap();
        assert_eq!(s.as_ref(), &[10, 20, 30, 40]);
        assert!(matches!(s, Cow::Owned(_)));
    }

    #[test]
    fn test_struct_to_slice_mut_empty() {
        let p: *mut u32 = std::ptr::null_mut();
        let s = struct_to_slice_mut(p, 0);
        assert!(s.is_err());

        let mut dummy = 0u32;
        let s = struct_to_slice_mut(&mut dummy, 0).unwrap();
        assert_eq!(&*s, &[] as &[u32]);
    }

    #[test]
    fn test_struct_to_slice_mut_aligned() {
        let mut data = [1u32, 2, 3, 4];
        {
            let mut s =
                struct_to_slice_mut(data.as_mut_ptr(), data.len()).unwrap();
            assert!(matches!(s, CowMut::Borrowed(_)));
            assert_eq!(&*s, &[1, 2, 3, 4]);
            s[0] = 42;
        }
        assert_eq!(data[0], 42);
    }

    #[test]
    fn test_struct_to_slice_mut_unaligned() {
        #[repr(align(8))]
        struct AlignedBuf([u8; 32]);
        let mut buf = AlignedBuf([0u8; 32]);
        let unaligned_bytes = &mut buf.0[1..17];
        let values = [10u32, 20, 30, 40];
        for (i, v) in values.iter().enumerate() {
            unaligned_bytes[i * 4..(i + 1) * 4]
                .copy_from_slice(&v.to_ne_bytes());
        }
        let unaligned_ptr = unaligned_bytes.as_mut_ptr() as *mut u32;
        assert!(!unaligned_ptr.is_aligned());
        {
            let mut s = struct_to_slice_mut(unaligned_ptr, 4).unwrap();
            assert!(matches!(s, CowMut::Owned { .. }));
            assert_eq!(&*s, &[10, 20, 30, 40]);
            s[1] = 99;
        }
        let new_val = u32::from_ne_bytes(buf.0[5..9].try_into().unwrap());
        assert_eq!(new_val, 99);
    }

    #[test]
    fn test_parse_len() {
        let val: CK_ULONG = 10;
        let l = parse_len(val).unwrap();
        assert_eq!(l, 10);
    }
}
