// Copyright 2024 Simo Sorce
// See LICENSE.txt file for terms

/* misc utilities that do not really belong in any module */
use super::interface;

pub const CK_ULONG_SIZE: usize = std::mem::size_of::<interface::CK_ULONG>();

#[macro_export]
macro_rules! bytes_to_vec {
    ($ptr:expr, $len:expr) => {{
        let ptr = $ptr as *const u8;
        let size = $len as usize;
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

#[macro_export]
macro_rules! void_ptr {
    ($ptr:expr) => {
        $ptr as *const _ as CK_VOID_PTR
    };
}

#[macro_export]
macro_rules! byte_ptr {
    ($ptr:expr) => {
        $ptr as *const _ as CK_BYTE_PTR
    };
}

pub fn fixup_template(
    template: &[interface::CK_ATTRIBUTE],
    attributes: &[interface::CK_ATTRIBUTE],
) -> Vec<interface::CK_ATTRIBUTE> {
    let mut vec = template.to_vec();
    for attr in attributes {
        match template.iter().find(|a| a.type_ == attr.type_) {
            Some(_) => (),
            None => {
                vec.push(attr.clone());
            }
        }
    }
    vec
}

#[macro_export]
macro_rules! cast_params {
    ($mech:expr, $params:ty) => {{
        if $mech.ulParameterLen as usize != std::mem::size_of::<$params>() {
            return err_rv!(CKR_ARGUMENTS_BAD);
        }
        unsafe { *($mech.pParameter as *const $params) }
    }};

    (raw_err $mech:expr, $params:ty) => {{
        if $mech.ulParameterLen as usize != std::mem::size_of::<$params>() {
            return CKR_ARGUMENTS_BAD;
        }
        unsafe { *($mech.pParameter as *const $params) }
    }};
}

#[macro_export]
macro_rules! bytes_to_slice {
    ($ptr: expr, $len:expr, $typ:ty) => {
        if $len > 0 {
            unsafe {
                std::slice::from_raw_parts($ptr as *const $typ, $len as usize)
            }
        } else {
            &[]
        }
    };
}
