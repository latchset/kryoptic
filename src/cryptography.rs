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

include!("hacl_bindings.rs");

#[derive(Debug)]
pub struct SHA256state {
    s: *mut Hacl_Streaming_SHA2_state_sha2_256,
}

impl SHA256state {
    pub fn new() -> SHA256state {
        SHA256state {
            s: std::ptr::null_mut(),
        }
    }

    pub fn init(&mut self) {
        unsafe {
            self.s = Hacl_Streaming_SHA2_create_in_256();
        }
    }

    pub fn get_state(&mut self) -> *mut Hacl_Streaming_SHA2_state_sha2_256 {
        if self.s.is_null() {
            self.init();
        }
        self.s
    }
}

impl Drop for SHA256state {
    fn drop(&mut self) {
        if !self.s.is_null() {
            unsafe {
                Hacl_Streaming_SHA2_free_256(self.s);
            }
            self.s = std::ptr::null_mut();
        }
    }
}

unsafe impl Send for SHA256state {}
unsafe impl Sync for SHA256state {}

#[derive(Debug)]
pub struct SHA384state {
    s: *mut Hacl_Streaming_SHA2_state_sha2_384,
}

impl SHA384state {
    pub fn new() -> SHA384state {
        SHA384state {
            s: std::ptr::null_mut(),
        }
    }

    pub fn init(&mut self) {
        unsafe {
            self.s = Hacl_Streaming_SHA2_create_in_384();
        }
    }

    pub fn get_state(&mut self) -> *mut Hacl_Streaming_SHA2_state_sha2_384 {
        if self.s.is_null() {
            self.init();
        }
        self.s
    }
}

impl Drop for SHA384state {
    fn drop(&mut self) {
        if !self.s.is_null() {
            unsafe {
                Hacl_Streaming_SHA2_free_384(self.s);
            }
            self.s = std::ptr::null_mut();
        }
    }
}

unsafe impl Send for SHA384state {}
unsafe impl Sync for SHA384state {}

#[derive(Debug)]
pub struct SHA512state {
    s: *mut Hacl_Streaming_SHA2_state_sha2_512,
}

impl SHA512state {
    pub fn new() -> SHA512state {
        SHA512state {
            s: std::ptr::null_mut(),
        }
    }

    pub fn init(&mut self) {
        unsafe {
            self.s = Hacl_Streaming_SHA2_create_in_512();
        }
    }

    pub fn get_state(&mut self) -> *mut Hacl_Streaming_SHA2_state_sha2_512 {
        if self.s.is_null() {
            self.init();
        }
        self.s
    }
}

impl Drop for SHA512state {
    fn drop(&mut self) {
        if !self.s.is_null() {
            unsafe {
                Hacl_Streaming_SHA2_free_512(self.s);
            }
            self.s = std::ptr::null_mut();
        }
    }
}

unsafe impl Send for SHA512state {}
unsafe impl Sync for SHA512state {}
