// HMAC_DRBG per NIST SP 800-90A Rev. 1, Section 10.1.2, built on top of
// this crate's HMAC primitive, plus a thin wrapper over AWS-LC's system
// entropy source (`RAND_bytes`).

use crate::cipher::zeromem;
use crate::digest::DigestAlg;
use crate::error::{Error, ErrorKind};
use crate::ffi;
use crate::mac::Hmac;

/// Fills `buf` with output from AWS-LC's system CSPRNG.
pub fn get_random(buf: &mut [u8]) -> Result<(), Error> {
    let ret = unsafe { ffi::RAND_bytes(buf.as_mut_ptr(), buf.len()) };
    if ret != 1 {
        return Err(Error::new(ErrorKind::BackendError));
    }
    Ok(())
}

#[derive(Debug)]
pub struct HmacDrbg {
    alg: DigestAlg,
    k: Vec<u8>,
    v: Vec<u8>,
}

/// `k`/`v` are this DRBG's internal secret state (SP 800-90A 10.1.2):
/// compromising either lets an attacker predict every future `generate()`
/// output until the next reseed. Scrub them on drop rather than relying
/// on `Vec`'s default deallocation, matching this codebase's convention
/// for every other secret-bearing type.
impl Drop for HmacDrbg {
    fn drop(&mut self) {
        zeromem(&mut self.k);
        zeromem(&mut self.v);
    }
}

impl HmacDrbg {
    /// Core HMAC_DRBG instantiate function (SP 800-90A 10.1.2.3), taking
    /// explicit entropy and nonce. Deterministic given the same inputs —
    /// used directly by tests, and by `new` below.
    pub fn instantiate(
        alg: DigestAlg,
        entropy: &[u8],
        nonce: &[u8],
        personalization: &[u8],
    ) -> Result<HmacDrbg, Error> {
        let outlen = crate::digest::Digest::new(alg)?.size();
        let mut drbg = HmacDrbg {
            alg,
            k: vec![0x00; outlen],
            v: vec![0x01; outlen],
        };
        let mut seed = Vec::with_capacity(
            entropy.len() + nonce.len() + personalization.len(),
        );
        seed.extend_from_slice(entropy);
        seed.extend_from_slice(nonce);
        seed.extend_from_slice(personalization);
        drbg.update(Some(&seed))?;
        Ok(drbg)
    }

    /// Production constructor: draws entropy and nonce from AWS-LC's
    /// system entropy source. The nonce length (half the entropy length)
    /// follows SP 800-90A 8.6.7, which allows drawing the nonce from the
    /// same entropy source as long as it is independent of the entropy
    /// input and at least security_strength/2 bits.
    pub fn new(
        alg: DigestAlg,
        personalization: &[u8],
    ) -> Result<HmacDrbg, Error> {
        let outlen = crate::digest::Digest::new(alg)?.size();
        let mut entropy = vec![0u8; outlen];
        let mut nonce = vec![0u8; outlen / 2];
        get_random(&mut entropy)?;
        get_random(&mut nonce)?;
        Self::instantiate(alg, &entropy, &nonce, personalization)
    }

    /// HMAC_DRBG_Update (SP 800-90A 10.1.2.2).
    fn update(&mut self, provided_data: Option<&[u8]>) -> Result<(), Error> {
        let mut km_input = self.v.clone();
        km_input.push(0x00);
        if let Some(data) = provided_data {
            km_input.extend_from_slice(data);
        }
        self.k = Hmac::mac(self.alg, &self.k, &km_input)?;
        self.v = Hmac::mac(self.alg, &self.k, &self.v)?;

        if let Some(data) = provided_data {
            let mut km_input = self.v.clone();
            km_input.push(0x01);
            km_input.extend_from_slice(data);
            self.k = Hmac::mac(self.alg, &self.k, &km_input)?;
            self.v = Hmac::mac(self.alg, &self.k, &self.v)?;
        }
        Ok(())
    }

    /// HMAC_DRBG_Reseed (SP 800-90A 10.1.2.4). In addition to the
    /// caller-supplied `entropy` (PKCS#11 callers such as C_SeedRandom are
    /// not required to supply full-entropy input), this always mixes in
    /// fresh entropy from AWS-LC's system source, matching the security
    /// posture of `ossl::rand::EvpRandCtx::reseed`, which always sets
    /// OpenSSL's `prediction_resistance` flag.
    pub fn reseed(
        &mut self,
        entropy: &[u8],
        addtl: &[u8],
    ) -> Result<(), Error> {
        let mut fresh = vec![0u8; self.v.len()];
        get_random(&mut fresh)?;
        let mut seed =
            Vec::with_capacity(fresh.len() + entropy.len() + addtl.len());
        seed.extend_from_slice(&fresh);
        seed.extend_from_slice(entropy);
        seed.extend_from_slice(addtl);
        self.update(Some(&seed))
    }

    /// HMAC_DRBG_Generate (SP 800-90A 10.1.2.5).
    pub fn generate(
        &mut self,
        addtl: &[u8],
        output: &mut [u8],
    ) -> Result<(), Error> {
        if !addtl.is_empty() {
            self.update(Some(addtl))?;
        }
        let mut filled = 0;
        while filled < output.len() {
            self.v = Hmac::mac(self.alg, &self.k, &self.v)?;
            let take = std::cmp::min(self.v.len(), output.len() - filled);
            output[filled..filled + take].copy_from_slice(&self.v[..take]);
            filled += take;
        }
        self.update(if addtl.is_empty() { None } else { Some(addtl) })?;
        Ok(())
    }

    /// Approximation of the SP 800-90A minimum entropy input length: the
    /// underlying hash's output length. This is exact for SHA-256 (256-bit
    /// security strength) and conservative (larger than strictly required)
    /// for SHA-512.
    pub fn security_strength_bytes(&self) -> usize {
        self.v.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::digest::DigestAlg;

    #[test]
    fn deterministic_given_same_inputs() {
        let entropy = [0x11u8; 32];
        let nonce = [0x22u8; 16];
        let perso = b"kryoptic-awslc-test";
        let mut a =
            HmacDrbg::instantiate(DigestAlg::Sha2_256, &entropy, &nonce, perso)
                .unwrap();
        let mut b =
            HmacDrbg::instantiate(DigestAlg::Sha2_256, &entropy, &nonce, perso)
                .unwrap();
        let mut out_a = [0u8; 64];
        let mut out_b = [0u8; 64];
        a.generate(&[], &mut out_a).unwrap();
        b.generate(&[], &mut out_b).unwrap();
        assert_eq!(out_a, out_b);
    }

    #[test]
    fn diverges_on_personalization() {
        let entropy = [0x11u8; 32];
        let nonce = [0x22u8; 16];
        let mut a =
            HmacDrbg::instantiate(DigestAlg::Sha2_256, &entropy, &nonce, b"a")
                .unwrap();
        let mut b =
            HmacDrbg::instantiate(DigestAlg::Sha2_256, &entropy, &nonce, b"b")
                .unwrap();
        let mut out_a = [0u8; 32];
        let mut out_b = [0u8; 32];
        a.generate(&[], &mut out_a).unwrap();
        b.generate(&[], &mut out_b).unwrap();
        assert_ne!(out_a, out_b);
    }

    #[test]
    fn successive_generates_differ() {
        let entropy = [0x33u8; 32];
        let nonce = [0x44u8; 16];
        let mut d =
            HmacDrbg::instantiate(DigestAlg::Sha2_256, &entropy, &nonce, b"")
                .unwrap();
        let mut first = [0u8; 32];
        let mut second = [0u8; 32];
        d.generate(&[], &mut first).unwrap();
        d.generate(&[], &mut second).unwrap();
        assert_ne!(first, second);
    }

    #[test]
    fn reseed_changes_output() {
        let entropy = [0x55u8; 32];
        let nonce = [0x66u8; 16];
        let mut d =
            HmacDrbg::instantiate(DigestAlg::Sha2_256, &entropy, &nonce, b"")
                .unwrap();
        let mut before = [0u8; 32];
        d.generate(&[], &mut before).unwrap();
        d.reseed(&[0x77u8; 32], &[]).unwrap();
        let mut after = [0u8; 32];
        d.generate(&[], &mut after).unwrap();
        assert_ne!(before, after);
    }

    #[test]
    fn get_random_fills_buffer() {
        let mut buf = [0u8; 32];
        get_random(&mut buf).unwrap();
        assert_ne!(buf, [0u8; 32]);
    }

    #[test]
    fn new_produces_working_generator() {
        // Uses the system-entropy-seeded constructor end to end.
        let mut d = HmacDrbg::new(DigestAlg::Sha2_256, b"kryoptic").unwrap();
        let mut out = [0u8; 32];
        d.generate(&[], &mut out).unwrap();
        assert_ne!(out, [0u8; 32]);
    }

    /// NIST CAVP HMAC_DRBG known-answer vector (SHA-256, no prediction
    /// resistance, no personalization string, no additional input --
    /// `[SHA-256]` COUNT 0 in NIST's `HMAC_DRBG.rsp`/`HMAC_DRBG.txt`
    /// vector set for `drbgvectors_pr_false`). Unlike every other test in
    /// this module (which only compare this implementation's own outputs
    /// against each other), this pins the actual byte-for-byte output
    /// against an authoritative external source: a subtly wrong Update/
    /// Generate/Reseed construction that happened to still be internally
    /// self-consistent would pass every other test here but fail this
    /// one. Per the CAVP procedure for this vector class: instantiate,
    /// then call Generate twice with no additional input -- the first
    /// call's output is discarded, the second is the vector's
    /// `ReturnedBits`.
    #[test]
    fn hmac_drbg_sha256_matches_nist_cavp_vector() {
        let entropy: [u8; 32] = [
            0xca, 0x85, 0x19, 0x11, 0x34, 0x93, 0x84, 0xbf, 0xfe, 0x89, 0xde,
            0x1c, 0xbd, 0xc4, 0x6e, 0x68, 0x31, 0xe4, 0x4d, 0x34, 0xa4, 0xfb,
            0x93, 0x5e, 0xe2, 0x85, 0xdd, 0x14, 0xb7, 0x1a, 0x74, 0x88,
        ];
        let nonce: [u8; 16] = [
            0x65, 0x9b, 0xa9, 0x6c, 0x60, 0x1d, 0xc6, 0x9f, 0xc9, 0x02, 0x94,
            0x08, 0x05, 0xec, 0x0c, 0xa8,
        ];
        let expected: [u8; 128] = [
            0xe5, 0x28, 0xe9, 0xab, 0xf2, 0xde, 0xce, 0x54, 0xd4, 0x7c, 0x7e,
            0x75, 0xe5, 0xfe, 0x30, 0x21, 0x49, 0xf8, 0x17, 0xea, 0x9f, 0xb4,
            0xbe, 0xe6, 0xf4, 0x19, 0x96, 0x97, 0xd0, 0x4d, 0x5b, 0x89, 0xd5,
            0x4f, 0xbb, 0x97, 0x8a, 0x15, 0xb5, 0xc4, 0x43, 0xc9, 0xec, 0x21,
            0x03, 0x6d, 0x24, 0x60, 0xb6, 0xf7, 0x3e, 0xba, 0xd0, 0xdc, 0x2a,
            0xba, 0x6e, 0x62, 0x4a, 0xbf, 0x07, 0x74, 0x5b, 0xc1, 0x07, 0x69,
            0x4b, 0xb7, 0x54, 0x7b, 0xb0, 0x99, 0x5f, 0x70, 0xde, 0x25, 0xd6,
            0xb2, 0x9e, 0x2d, 0x30, 0x11, 0xbb, 0x19, 0xd2, 0x76, 0x76, 0xc0,
            0x71, 0x62, 0xc8, 0xb5, 0xcc, 0xde, 0x06, 0x68, 0x96, 0x1d, 0xf8,
            0x68, 0x03, 0x48, 0x2c, 0xb3, 0x7e, 0xd6, 0xd5, 0xc0, 0xbb, 0x8d,
            0x50, 0xcf, 0x1f, 0x50, 0xd4, 0x76, 0xaa, 0x04, 0x58, 0xbd, 0xab,
            0xa8, 0x06, 0xf4, 0x8b, 0xe9, 0xdc, 0xb8,
        ];

        let mut drbg =
            HmacDrbg::instantiate(DigestAlg::Sha2_256, &entropy, &nonce, &[])
                .unwrap();
        let mut discard = [0u8; 128];
        drbg.generate(&[], &mut discard).unwrap();
        let mut output = [0u8; 128];
        drbg.generate(&[], &mut output).unwrap();
        assert_eq!(output, expected);
    }
}
