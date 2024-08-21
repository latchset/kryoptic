// Copyright 2024 Simo Sorce
// See LICENSE.txt file for terms

/* misc utilities that do not really belong in any module */
use super::attribute;
use super::err_rv;
use super::error;
use super::interface;
use super::object;

use attribute::{from_ulong, CkAttrs};
use error::{KError, KResult};
use interface::*;

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
macro_rules! sizeof {
    ($type:ty) => {
        std::mem::size_of::<$type>() as CK_ULONG
    };
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

pub fn common_derive_data_object(
    template: &[CK_ATTRIBUTE],
    objfactories: &object::ObjectFactories,
    default_len: usize,
) -> KResult<(object::Object, usize)> {
    let default_class = CKO_DATA;
    let mut tmpl = CkAttrs::from(template);
    tmpl.add_missing_ulong(CKA_CLASS, &default_class);
    /* we must remove CKA_VALUE_LEN from the template as it is not
     * a valid attribute for a CKO_DATA object */
    let value_len = match tmpl.remove_ulong(CKA_VALUE_LEN)? {
        Some(val) => val as usize,
        None => {
            if default_len == 0 {
                return err_rv!(CKR_TEMPLATE_INCOMPLETE);
            }
            default_len
        }
    };
    let obj =
        match objfactories.get_factory(object::ObjectType::new(CKO_DATA, 0)) {
            Ok(f) => f.create(tmpl.as_slice())?,
            Err(_) => return err_rv!(CKR_GENERAL_ERROR),
        };
    Ok((obj, value_len))
}

pub fn common_derive_key_object(
    key: &object::Object,
    template: &[CK_ATTRIBUTE],
    objfactories: &object::ObjectFactories,
    default_len: usize,
) -> KResult<(object::Object, usize)> {
    let default_class = CKO_SECRET_KEY;
    let mut tmpl = CkAttrs::from(template);
    tmpl.add_missing_ulong(CKA_CLASS, &default_class);
    let mut obj =
        objfactories.derive_key_from_template(key, tmpl.as_slice())?;
    let value_len = match obj.get_attr_as_ulong(CKA_VALUE_LEN) {
        Ok(n) => n as usize,
        Err(_) => {
            if default_len == 0 {
                return err_rv!(CKR_TEMPLATE_INCOMPLETE);
            }
            obj.set_attr(from_ulong(CKA_VALUE_LEN, default_len as CK_ULONG))?;
            default_len
        }
    };
    Ok((obj, value_len))
}
