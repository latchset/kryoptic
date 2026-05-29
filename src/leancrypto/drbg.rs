// Copyright 2026 Stephan Müller
// See LICENSE.txt file for terms

//! This module implements Deterministic Random Bit Generators (DRBGs) based on
//! HMAC, as specified in NIST SP 800-90A, using the OpenSSL EVP_RAND API.

use crate::error::Result;
use crate::mechanism::DRBG;
use crate::pkcs11::{
    CKR_ARGUMENTS_BAD, CKR_RANDOM_NO_RNG, CKR_RANDOM_SEED_NOT_SUPPORTED,
};

use leancrypto_sys::lcr_rng::{lcr_rng, lcr_rng_type};

/// Implements the wrapper around the leancrypto seeded RNG
#[derive(Debug)]
pub struct HmacDrbg {
    /// The ossl EvpRandCtx
    ctx: lcr_rng,
    min_entropy: usize,
    max_entropy: usize,
    max_addin: usize,
}

impl HmacDrbg {
    /// Creates and initializes a new HMAC-DRBG instance.
    pub fn new(hash: &str) -> Result<HmacDrbg> {
        let drbgtype = match hash {
            //TODO The requested DRBG types do not necessarily match with
            //the DRBG type used by the leancrypto - why is a type needed?
            "HMAC DRBG SHA512" => lcr_rng_type::lcr_seeded_rng,
            "HMAC DRBG SHA256" => lcr_rng_type::lcr_seeded_rng,
            _ => return Err(CKR_RANDOM_NO_RNG)?,
        };

        let mut ctx = lcr_rng::new();
        match ctx.set_type(drbgtype) {
            Err(_) => return Err(CKR_RANDOM_NO_RNG)?,
            Ok(v) => v,
        };

        let min_entropy = 32;
        let max_entropy = 1 << 31;
        let max_addin = 1 << 31;

        Ok(HmacDrbg {
            ctx,
            min_entropy,
            max_entropy,
            max_addin,
        })
    }
}

impl DRBG for HmacDrbg {
    /// Reseeds the DRBG state with additional entropy.
    ///
    /// Corresponds to the Reseed operation in NIST SP 800-90A.
    fn reseed(&mut self, entropy: &[u8], addtl: &[u8]) -> Result<()> {
        if entropy.len() < self.min_entropy {
            return Err(CKR_ARGUMENTS_BAD)?;
        }
        if self.max_entropy > 0 && entropy.len() > self.max_entropy {
            return Err(CKR_ARGUMENTS_BAD)?;
        }
        if self.max_addin > 0 && addtl.len() > self.max_addin {
            return Err(CKR_ARGUMENTS_BAD)?;
        }

        match self.ctx.seed(entropy, addtl) {
            Err(_) => return Err(CKR_RANDOM_SEED_NOT_SUPPORTED)?,
            Ok(_) => Ok(()),
        }
    }

    /// Generates random bytes from the DRBG.
    ///
    /// Corresponds to the Generate operation in NIST SP 800-90A.
    /// Can optionally include additional input (`addtl`).
    fn generate(&mut self, addtl: &[u8], output: &mut [u8]) -> Result<()> {
        match self.ctx.generate(addtl, output) {
            Err(_) => return Err(CKR_RANDOM_NO_RNG)?,
            Ok(_) => Ok(()),
        }
    }
}

unsafe impl Send for HmacDrbg {}
unsafe impl Sync for HmacDrbg {}
