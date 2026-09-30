// Copyright 2026
// See LICENSE.txt file for terms

//! Implements the `DRBG` trait using the awslc crate's HMAC_DRBG
//! (NIST SP 800-90A). Mirrors `crate::ossl::drbg`, except the underlying
//! DRBG object is kryoptic's own construction rather than a provider
//! object, since AWS-LC exposes no equivalent to OpenSSL 3's EVP_RAND.

use crate::error::Result;
use crate::mechanism::DRBG;
use crate::pkcs11::{CKR_ARGUMENTS_BAD, CKR_RANDOM_NO_RNG};

use crate::lowlevel::digest::DigestAlg;
use crate::lowlevel::rand::HmacDrbg as AwsLcHmacDrbg;

#[derive(Debug)]
pub struct HmacDrbg {
    ctx: AwsLcHmacDrbg,
    min_entropy: usize,
}

impl HmacDrbg {
    pub fn new(hash: &str) -> Result<HmacDrbg> {
        let digest = match hash {
            "HMAC DRBG SHA256" => DigestAlg::Sha2_256,
            "HMAC DRBG SHA512" => DigestAlg::Sha2_512,
            _ => return Err(CKR_RANDOM_NO_RNG)?,
        };
        let ctx = AwsLcHmacDrbg::new(digest, hash.as_bytes())?;
        let min_entropy = ctx.security_strength_bytes();
        Ok(HmacDrbg { ctx, min_entropy })
    }
}

impl DRBG for HmacDrbg {
    fn reseed(&mut self, entropy: &[u8], addtl: &[u8]) -> Result<()> {
        if entropy.len() < self.min_entropy {
            return Err(CKR_ARGUMENTS_BAD)?;
        }
        Ok(self.ctx.reseed(entropy, addtl)?)
    }

    fn generate(&mut self, addtl: &[u8], output: &mut [u8]) -> Result<()> {
        Ok(self.ctx.generate(addtl, output)?)
    }
}
