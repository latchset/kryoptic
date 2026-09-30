// Copyright 2023 Simo Sorce
// See LICENSE.txt file for terms

//! This module implements interfaces needed to access a Random Number
//! Generator

use crate::error::Result;
use crate::mechanism;
use crate::ossl::drbg;

#[derive(Debug)]
pub struct RNG {
    drbg: Box<dyn mechanism::DRBG>,
}

impl RNG {
    pub fn new(alg: &str) -> Result<RNG> {
        Ok(RNG {
            drbg: Box::new(drbg::HmacDrbg::new(alg)?),
        })
    }

    pub fn generate_random(&mut self, buffer: &mut [u8]) -> Result<()> {
        let noaddtl: [u8; 0] = [];
        self.drbg.generate(&noaddtl, buffer)
    }

    pub fn add_seed(&mut self, buffer: &[u8]) -> Result<()> {
        let noaddtl: [u8; 0] = [];
        self.drbg.reseed(buffer, &noaddtl)
    }
}

#[cfg(test)]
mod tests {
    use super::RNG;

    #[test]
    fn generates_varying_output() {
        let mut rng = RNG::new("HMAC DRBG SHA256").unwrap();
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        rng.generate_random(&mut a).unwrap();
        rng.generate_random(&mut b).unwrap();
        assert_ne!(a, [0u8; 32]);
        assert_ne!(a, b);
    }

    #[test]
    fn add_seed_does_not_error() {
        let mut rng = RNG::new("HMAC DRBG SHA256").unwrap();
        rng.add_seed(b"some caller-supplied seed material").unwrap();
        let mut out = [0u8; 16];
        rng.generate_random(&mut out).unwrap();
        assert_ne!(out, [0u8; 16]);
    }
}
