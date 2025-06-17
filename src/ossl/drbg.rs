// Copyright 2024 Simo Sorce
// See LICENSE.txt file for terms

//! This module implements Deterministic Random Bit Generators (DRBGs) based on
//! HMAC, as specified in NIST SP 800-90A, using the OpenSSL EVP_RAND API.

use crate::error::Result;
use crate::mechanism::DRBG;
use crate::ossl::common::osslctx;

use ossl::digest::DigestAlg;
use ossl::rand::EvpRandCtx;
use pkcs11::CKR_RANDOM_NO_RNG;

/// Implements HMAC-DRBG using one of the supported SHA digests as the
/// underlying hash function.
#[derive(Debug)]
pub struct HmacDrbg {
    /// The ossl EvpRandCtx
    ctx: EvpRandCtx,
}

impl HmacDrbg {
    /// Creates and initializes a new HMAC-DRBG instance.
    pub fn new(hash: &str) -> Result<HmacDrbg> {
        let digest = match hash {
            "HMAC DRBG SHA256" => DigestAlg::Sha2_256,
            "HMAC DRBG SHA512" => DigestAlg::Sha2_512,
            _ => return Err(CKR_RANDOM_NO_RNG)?,
        };

        Ok(HmacDrbg {
            ctx: EvpRandCtx::new_hmac_drbg(osslctx(), digest, hash.as_bytes())?,
        })
    }
}

impl DRBG for HmacDrbg {
    /// Reseeds the DRBG state with additional entropy.
    ///
    /// Corresponds to the Reseed operation in NIST SP 800-90A.
    fn reseed(&mut self, entropy: &[u8], addtl: &[u8]) -> Result<()> {
        Ok(self.ctx.reseed(entropy, addtl)?)
    }

    /// Generates random bytes from the DRBG.
    ///
    /// Corresponds to the Generate operation in NIST SP 800-90A.
    /// Can optionally include additional input (`addtl`).
    fn generate(&mut self, addtl: &[u8], output: &mut [u8]) -> Result<()> {
        Ok(self.ctx.generate(addtl, output)?)
    }
}

unsafe impl Send for HmacDrbg {}
unsafe impl Sync for HmacDrbg {}
