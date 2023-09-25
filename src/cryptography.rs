// Copyright 2023 Simo Sorce
// See LICENSE.txt file for terms

#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(dead_code)]
#![allow(non_snake_case)]
include!("nettle_bindings.rs");

use core::fmt::Error;
use std::fmt::Debug;
use std::fmt::Formatter;

unsafe impl Send for rsa_public_key {}
unsafe impl Sync for rsa_public_key {}
unsafe impl Send for rsa_private_key {}
unsafe impl Sync for rsa_private_key {}

impl Debug for rsa_public_key {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), Error> {
        f.debug_struct("rsa_public_key")
            .field("size", &self.size)
            .field("e", &"e")
            .field("n", &"n")
            .finish()
    }
}

impl Debug for rsa_private_key {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), Error> {
        f.debug_struct("rsa_private_key")
            .field("size", &self.size)
            .field("d", &"d")
            .field("p", &"p")
            .field("q", &"q")
            .field("a", &"a")
            .field("b", &"b")
            .field("c", &"c")
            .finish()
    }
}
