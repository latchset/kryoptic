// Copyright 2023 Simo Sorce
// See LICENSE.txt file for terms

#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(dead_code)]
#![allow(non_snake_case)]
include!("hacl/bindings.rs");

use std::sync::Once;

static EVERCRYPT_AUTOCONF: Once = Once::new();

pub fn evercrypt_autoconf() {
    EVERCRYPT_AUTOCONF.call_once(|| unsafe {
        EverCrypt_AutoConfig2_init();
    });
}
