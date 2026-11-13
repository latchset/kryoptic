// Copyright 2024 Simo Sorce
// See LICENSE.txt file for terms

//! This module implements miscellaneous utilities that do not really
//! belong in any specific module

use std::borrow::Cow;

use crate::attribute::{Attribute, CkAttrs};
use crate::error::{Error, Result};
use crate::object::{
    DerivePolicy, KeyOrigin, Object, ObjectFactories, ObjectType,
};
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
    mech: CK_MECHANISM_TYPE,
    key: &Object,
    template: &[CK_ATTRIBUTE],
    objfactories: &ObjectFactories,
    default_len: usize,
) -> Result<(Object, usize)> {
    let default_class = CKO_SECRET_KEY;
    let mut tmpl = CkAttrs::from(template);
    tmpl.add_missing_ulong(CKA_CLASS, &default_class);
    let mut obj = objfactories.derive_key_from_template(
        KeyOrigin::Derive(mech, key, DerivePolicy::Independent),
        tmpl.as_slice(),
    )?;
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

/// A thin wrapper around a [`Vec<u8>`] that securely zeroizes its memory
/// using [`zeromem`] when dropped.
#[derive(Default)]
pub struct SecVec(Vec<u8>);

impl std::fmt::Debug for SecVec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecVec").field("len", &self.len()).finish()
    }
}

impl SecVec {
    /// Creates a new, empty `SecVec`.
    pub fn new() -> Self {
        SecVec(Vec::new())
    }

    /// Creates a new zero-filled Vector of the specified size
    pub fn sized(size: usize) -> Self {
        SecVec(vec![0u8; size])
    }

    /// Creates a new, empty `SecVec` with the specified capacity.
    pub fn with_capacity(capacity: usize) -> Self {
        SecVec(Vec::with_capacity(capacity))
    }

    /// Copies a pointer and length obtained via FFI into a new `SecVec`.
    pub fn from_raw_bytes<T, U>(ptr: *const T, plen: U) -> Result<SecVec>
    where
        usize: TryFrom<U>,
        Error: From<<usize as TryFrom<U>>::Error>,
    {
        let len = usize::try_from(plen)?;
        if ptr.is_null() && len != 0 {
            return Err(CKR_GENERAL_ERROR)?;
        }
        Ok(SecVec(bytes_to_vec(ptr, len)))
    }

    /// Extracts and hands off the inner [`Vec<u8>`].
    /// Note that the returned Vector is no longer zeroized, and the
    /// receiving owner must handle it appropriately from here on.
    pub fn extract(mut self) -> Vec<u8> {
        std::mem::take(&mut self.0)
    }

    /// Clears the vector, zeroizing its contents before clearing.
    pub fn clear(&mut self) {
        zeromem(self.0.as_mut_slice());
        self.0.clear();
    }

    /// Resizes the `SecVec` in-place.
    ///
    /// When expanding the vector, a brand new vector of the requested size is
    /// created, data is copied into it, and the original vector is zeroized
    /// before dropping it.
    /// When reducing the vector, the excess elements are zeroized with
    /// [`zeromem`] and the vector's length is reduced using `set_len`.
    pub fn resize(&mut self, new_len: usize, value: u8) {
        if new_len > self.0.capacity() {
            let mut new_vec = vec![value; new_len];
            new_vec[..self.0.len()].copy_from_slice(&self.0);
            zeromem(self.0.as_mut_slice());
            self.0 = new_vec;
        } else if new_len > self.0.len() {
            self.0.resize(new_len, value);
        } else if new_len < self.0.len() {
            zeromem(&mut self.0[new_len..]);
            self.0.truncate(new_len);
        }
    }

    /// Reduces the length of the `SecVec` to `new_len`.
    ///
    /// Invokes [`resize`] internally. Returns an error if the new length
    /// is greater than the current vector length (the current buffer is
    /// smaller than the requested length).
    pub fn reduce(&mut self, new_len: usize) -> Result<()> {
        if new_len > self.0.len() {
            return Err(CKR_GENERAL_ERROR)?;
        }
        self.resize(new_len, 0);
        Ok(())
    }

    /// Modifies the `SecVec` to contain only the subset specified by `index`,
    /// copying the data to the start of the vector, zeroizing the discarded
    /// memory, setting the length to the size of the range.
    pub fn subset<R: std::ops::RangeBounds<usize>>(
        &mut self,
        index: R,
    ) -> Result<()> {
        let start = match index.start_bound() {
            std::ops::Bound::Included(&n) => n,
            std::ops::Bound::Excluded(&n) => {
                n.checked_add(1).ok_or(CKR_GENERAL_ERROR)?
            }
            std::ops::Bound::Unbounded => 0,
        };
        let end = match index.end_bound() {
            std::ops::Bound::Included(&n) => {
                n.checked_add(1).ok_or(CKR_GENERAL_ERROR)?
            }
            std::ops::Bound::Excluded(&n) => n,
            std::ops::Bound::Unbounded => self.0.len(),
        };
        if start > end || end > self.0.len() {
            return Err(CKR_GENERAL_ERROR)?;
        }
        let size = end - start;
        self.0.copy_within(start..end, 0);
        zeromem(&mut self.0[size..]);
        unsafe {
            self.0.set_len(size);
        }
        Ok(())
    }

    /// Clones and appends all elements in a slice to the `SecVec`.
    pub fn extend_from_slice(&mut self, other: &[u8]) {
        let new_len = self.0.len() + other.len();
        if new_len > self.0.capacity() {
            let mut new_vec = Vec::with_capacity(self.0.len() + other.len());
            new_vec.extend_from_slice(&self.0);
            new_vec.extend_from_slice(other);
            zeromem(self.0.as_mut_slice());
            self.0 = new_vec;
        } else {
            self.0.extend_from_slice(other);
        }
    }
}

impl Drop for SecVec {
    fn drop(&mut self) {
        zeromem(self.0.as_mut_slice());
    }
}

impl std::ops::Deref for SecVec {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.0.as_slice()
    }
}

impl std::ops::DerefMut for SecVec {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.0.as_mut_slice()
    }
}

impl AsRef<[u8]> for SecVec {
    fn as_ref(&self) -> &[u8] {
        self.0.as_slice()
    }
}

impl AsMut<[u8]> for SecVec {
    fn as_mut(&mut self) -> &mut [u8] {
        self.0.as_mut_slice()
    }
}

impl std::borrow::Borrow<[u8]> for SecVec {
    fn borrow(&self) -> &[u8] {
        self.0.as_slice()
    }
}

impl std::borrow::BorrowMut<[u8]> for SecVec {
    fn borrow_mut(&mut self) -> &mut [u8] {
        self.0.as_mut_slice()
    }
}

impl<I: std::slice::SliceIndex<[u8]>> std::ops::Index<I> for SecVec {
    type Output = I::Output;

    fn index(&self, index: I) -> &Self::Output {
        &self.0[index]
    }
}

impl<I: std::slice::SliceIndex<[u8]>> std::ops::IndexMut<I> for SecVec {
    fn index_mut(&mut self, index: I) -> &mut Self::Output {
        &mut self.0[index]
    }
}

impl From<Vec<u8>> for SecVec {
    fn from(v: Vec<u8>) -> Self {
        SecVec(v)
    }
}

impl From<&Vec<u8>> for SecVec {
    fn from(v: &Vec<u8>) -> Self {
        SecVec(v.clone())
    }
}

impl From<&[u8]> for SecVec {
    fn from(s: &[u8]) -> Self {
        SecVec(s.to_vec())
    }
}

impl<const N: usize> From<[u8; N]> for SecVec {
    fn from(arr: [u8; N]) -> Self {
        SecVec(arr.to_vec())
    }
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

    #[test]
    fn test_zeromem() {
        let mut data = vec![1u8, 2, 3, 4, 5];
        zeromem(data.as_mut_slice());
        assert_eq!(data, vec![0, 0, 0, 0, 0]);
    }

    #[test]
    fn test_sec_vec() {
        let mut sv = SecVec::new();
        assert!(sv.is_empty());
        assert_eq!(sv.len(), 0);

        sv.extend_from_slice(&[1, 2, 3]);
        assert_eq!(sv.len(), 3);
        assert_eq!(sv[1], 2);
        sv[1] = 42;
        assert_eq!(sv[1], 42);
        assert_eq!(sv.as_ref(), &[1, 42, 3]);

        let sv2 = SecVec::from(&[10u8, 20, 30][..]);
        assert_eq!(sv2.as_ref(), &[10, 20, 30]);

        let mut sv4: SecVec = [5u8, 6, 7].into();
        sv4.extend_from_slice(&[8u8, 9]);
        assert_eq!(sv4.as_ref(), &[5, 6, 7, 8, 9]);

        let data = [99u8, 100, 101];
        let sv6 = SecVec::from_raw_bytes(data.as_ptr(), data.len()).unwrap();
        assert_eq!(sv6.as_ref(), &[99, 100, 101]);

        let mut sv_resize = SecVec::from(&[1u8, 2, 3, 4][..]);
        sv_resize.resize(2, 0);
        assert_eq!(sv_resize.as_ref(), &[1, 2]);

        sv_resize.resize(5, 9);
        assert_eq!(sv_resize.as_ref(), &[1, 2, 9, 9, 9]);

        sv_resize.resize(0, 0);
        assert!(sv_resize.is_empty());

        let mut sv_reduce = SecVec::from(&[1u8, 2, 3, 4, 5][..]);
        assert!(sv_reduce.reduce(6).is_err());
        assert_eq!(sv_reduce.as_ref(), &[1, 2, 3, 4, 5]);
        sv_reduce.reduce(3).unwrap();
        assert_eq!(sv_reduce.as_ref(), &[1, 2, 3]);
        sv_reduce.reduce(0).unwrap();
        assert!(sv_reduce.is_empty());

        let mut sub = SecVec::from(&[10u8, 20, 30, 40, 50][..]);
        sub.subset(1..4).unwrap();
        assert_eq!(sub.as_ref(), &[20, 30, 40]);
        assert_eq!(sub.len(), 3);
        assert!(sub.subset(0..10).is_err());
        sub.subset(1..1).unwrap();
        assert!(sub.is_empty());

        let empty_sv = SecVec::new();
        assert_eq!(format!("{:?}", empty_sv), "SecVec { len: 0 }");

        let sv_debug = SecVec::from(&[10u8, 20, 30][..]);
        let debug_str = format!("{:?}", sv_debug);
        assert_eq!(debug_str, "SecVec { len: 3 }");
        assert!(!debug_str.contains("10"));
        assert!(!debug_str.contains("20"));
        assert!(!debug_str.contains("30"));
    }
}
