// Copyright 2024 Simo Sorce
// See LICENSE.txt file for terms

//! This module implements Deterministic Random Bit Generators (DRBGs) based on
//! HMAC, as specified in NIST SP 800-90A, using the OpenSSL EVP_RAND API.

use crate::error::Result;
use crate::mechanism::DRBG;
use crate::ossl::common::osslctx;
use crate::pkcs11::{CKR_ARGUMENTS_BAD, CKR_RANDOM_NO_RNG};

use ossl::digest::DigestAlg;
use ossl::rand::{EvpRandCtx, EvpRandGetParam};

/// Implements HMAC-DRBG using one of the supported SHA digests as the
/// underlying hash function.
#[derive(Debug)]
pub struct HmacDrbg {
    /// The ossl EvpRandCtx
    ctx: EvpRandCtx,
    min_entropy: usize,
    max_entropy: usize,
    max_addin: usize,
}

impl HmacDrbg {
    /// Creates and initializes a new HMAC-DRBG instance.
    pub fn new(hash: &str) -> Result<HmacDrbg> {
        let digest = match hash {
            "HMAC DRBG SHA256" => DigestAlg::Sha2_256,
            "HMAC DRBG SHA512" => DigestAlg::Sha2_512,
            _ => return Err(CKR_RANDOM_NO_RNG)?,
        };

        let ctx =
            EvpRandCtx::new_hmac_drbg(osslctx(), digest, hash.as_bytes())?;

        let mut min_entropy = 0;
        let mut max_entropy = 0;
        let mut max_addin = 0;
        let mut params = [
            EvpRandGetParam::MinEntropyLen(0),
            EvpRandGetParam::MaxEntropyLen(0),
            EvpRandGetParam::MaxAdinLen(0),
        ];
        if ctx.get_ctx_params(&mut params).is_ok() {
            if let EvpRandGetParam::MinEntropyLen(val) = &params[0] {
                min_entropy = *val;
            }
            if let EvpRandGetParam::MaxEntropyLen(val) = &params[1] {
                max_entropy = *val;
            }
            if let EvpRandGetParam::MaxAdinLen(val) = &params[2] {
                max_addin = *val;
            }
        }

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
