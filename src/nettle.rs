// Copyright 2023 Simo Sorce
// See LICENSE.txt file for terms

#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(dead_code)]
#![allow(non_snake_case)]
include!("nettle/bindings.rs");

use core::fmt::Error;
use std::fmt::Debug;
use std::fmt::Formatter;
use zeroize::Zeroize;

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

macro_rules! zero_mpz_struct {
    ($field:expr) => {
        let z: &mut [::std::os::raw::c_ulong] = unsafe {
            std::slice::from_raw_parts_mut(
                $field._mp_d,
                $field._mp_alloc as usize,
            )
        };
        z.zeroize();
    };
}

impl Drop for rsa_public_key {
    fn drop(&mut self) {
        unsafe { nettle_rsa_public_key_clear(self) };
    }
}

impl Drop for rsa_private_key {
    fn drop(&mut self) {
        zero_mpz_struct!(self.d[0]);
        zero_mpz_struct!(self.p[0]);
        zero_mpz_struct!(self.q[0]);
        zero_mpz_struct!(self.a[0]);
        zero_mpz_struct!(self.b[0]);
        zero_mpz_struct!(self.c[0]);
        unsafe { nettle_rsa_private_key_clear(self) };
    }
}

impl Debug for __mpz_struct {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), Error> {
        f.debug_struct("__mpz_struct")
            .field("_mp_alloc", &self._mp_alloc)
            .field("_mp_size", &self._mp_size)
            .finish()
    }
}

#[derive(Debug)]
pub struct mpz_wrapper {
    mpz: __mpz_struct,
}

impl mpz_wrapper {
    pub fn new() -> mpz_wrapper {
        let mut x = mpz_wrapper {
            mpz: __mpz_struct::default(),
        };
        unsafe { __gmpz_init(&mut x.mpz) };
        x
    }
    pub fn as_ptr(&self) -> &__mpz_struct {
        &self.mpz
    }
    pub fn as_mut_ptr(&mut self) -> &mut __mpz_struct {
        &mut self.mpz
    }

    pub fn get_len(&mut self) -> usize {
        unsafe { nettle_mpz_sizeinbase_256_u(&mut self.mpz) }
    }

    pub fn import(&mut self, src: &[u8]) {
        unsafe {
            nettle_mpz_set_str_256_u(&mut self.mpz, src.len(), src.as_ptr());
        }
    }

    pub fn as_slice(&self) -> &[mp_limb_t] {
        unsafe {
            std::slice::from_raw_parts(
                self.mpz._mp_d,
                self.mpz._mp_size as usize,
            )
        }
    }
}

impl Drop for mpz_wrapper {
    fn drop(&mut self) {
        zero_mpz_struct!(self.mpz);
        unsafe { __gmpz_clear(&mut self.mpz) };
    }
}
