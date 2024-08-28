// Copyright 2023 Simo Sorce
// See LICENSE.txt file for terms

#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(dead_code)]
#![allow(non_snake_case)]
include!("ossl/bindings.rs");

use once_cell::sync::Lazy;

use super::err_rv;
use super::error;
use super::interface;
use error::Result;
use interface::CKR_DEVICE_ERROR;

use std::os::raw::{c_char, c_void};
use zeroize::Zeroize;

struct OsslContext {
    context: *mut OSSL_LIB_CTX,
}

unsafe impl Send for OsslContext {}
unsafe impl Sync for OsslContext {}

static OSSL_CONTEXT: Lazy<OsslContext> = Lazy::new(|| unsafe {
    OsslContext {
        context: OSSL_LIB_CTX_new(),
    }
});

pub fn get_libctx() -> *mut OSSL_LIB_CTX {
    OSSL_CONTEXT.context
}

include! {"ossl/common.rs"}
