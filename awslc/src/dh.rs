// Finite-field Diffie-Hellman, wrapping AWS-LC's classic DH_* API.

use crate::error::{Error, ErrorKind};
use crate::ffi;

#[derive(Debug)]
pub struct DhKey {
    dh: *mut ffi::DH,
}

impl DhKey {
    fn new_with_pg(
        prime: &[u8],
        generator: &[u8],
    ) -> Result<*mut ffi::DH, Error> {
        let dh = unsafe { ffi::DH_new() };
        if dh.is_null() {
            return Err(Error::new(ErrorKind::NullPtr));
        }
        let p = unsafe {
            ffi::BN_bin2bn(prime.as_ptr(), prime.len(), std::ptr::null_mut())
        };
        let g = unsafe {
            ffi::BN_bin2bn(
                generator.as_ptr(),
                generator.len(),
                std::ptr::null_mut(),
            )
        };
        if p.is_null() || g.is_null() {
            unsafe {
                if !p.is_null() {
                    ffi::BN_free(p);
                }
                if !g.is_null() {
                    ffi::BN_free(g);
                }
                ffi::DH_free(dh);
            }
            return Err(Error::new(ErrorKind::NullPtr));
        }
        // DH_set0_pqg takes ownership of p/g on success (q is optional,
        // null here -- kryoptic's well-known groups are specified as P/G
        // pairs). On failure it does NOT take ownership, so p/g must still
        // be freed by us.
        if unsafe { ffi::DH_set0_pqg(dh, p, std::ptr::null_mut(), g) } != 1 {
            unsafe {
                ffi::BN_free(p);
                ffi::BN_free(g);
                ffi::DH_free(dh);
            }
            return Err(Error::new(ErrorKind::BackendError));
        }
        Ok(dh)
    }

    /// Unlike `RsaKey::generate_with_exponent`/`EcKey::generate`, AWS-LC
    /// has no `DH_generate_key_fips` entry point at all (confirmed
    /// against the vendored `dh.h`: only the plain `DH_generate_key` is
    /// declared), so the FIPS-mandated pairwise consistency test (FIPS
    /// 186-5 §5.6.2 / NIST SP 800-56A Rev. 3 §5.6.2.1.4) has to be done
    /// here instead: recompute the public value independently as `g^x mod
    /// p` from the generated private value (the same computation
    /// `from_private` already performs for a caller-supplied private
    /// value) and confirm it matches what `DH_generate_key` itself
    /// produced. Applied unconditionally (not just under the `fips`
    /// feature): it's a cheap extra check with no behavioral difference
    /// on success, so there's no reason to skip it under plain `awslc`.
    pub fn generate(prime: &[u8], generator: &[u8]) -> Result<DhKey, Error> {
        let dh = Self::new_with_pg(prime, generator)?;
        if unsafe { ffi::DH_generate_key(dh) } != 1 {
            unsafe { ffi::DH_free(dh) };
            return Err(Error::new(ErrorKind::BackendError));
        }
        let key = DhKey { dh };
        let priv_val = key.private_value()?;
        let recomputed = Self::from_private(prime, generator, &priv_val)?;
        if recomputed.public_value()? != key.public_value()? {
            return Err(Error::new(ErrorKind::BackendError));
        }
        Ok(key)
    }

    /// Reconstructs a key from a raw private value (PKCS#11's CKA_VALUE
    /// for CKK_DH private keys).
    ///
    /// AWS-LC's `DH_set0_key(dh, pub_key, priv_key)` does NOT compute
    /// `pub_key` when it is passed as null -- per its own C source
    /// (`crypto/fipsmodule/dh/dh.c`), a null argument simply leaves that
    /// field unchanged. So the public value is computed here manually as
    /// `g^priv mod p`, using the constant-time modexp variant since the
    /// exponent (the private value) is secret.
    pub fn from_private(
        prime: &[u8],
        generator: &[u8],
        private: &[u8],
    ) -> Result<DhKey, Error> {
        let dh = Self::new_with_pg(prime, generator)?;
        let result = (|| -> Result<(), Error> {
            let priv_bn = unsafe {
                ffi::BN_bin2bn(
                    private.as_ptr(),
                    private.len(),
                    std::ptr::null_mut(),
                )
            };
            if priv_bn.is_null() {
                return Err(Error::new(ErrorKind::NullPtr));
            }
            let pub_bn = unsafe { ffi::BN_new() };
            if pub_bn.is_null() {
                unsafe { ffi::BN_clear_free(priv_bn) };
                return Err(Error::new(ErrorKind::NullPtr));
            }
            let ctx = unsafe { ffi::BN_CTX_new() };
            if ctx.is_null() {
                unsafe {
                    ffi::BN_clear_free(priv_bn);
                    ffi::BN_free(pub_bn);
                }
                return Err(Error::new(ErrorKind::NullPtr));
            }
            // p and g are owned by `dh` (set in new_with_pg); borrowed here.
            let p = unsafe { ffi::DH_get0_p(dh) };
            let g = unsafe { ffi::DH_get0_g(dh) };
            let ok = unsafe {
                ffi::BN_mod_exp_mont_consttime(
                    pub_bn,
                    g,
                    priv_bn,
                    p,
                    ctx,
                    std::ptr::null(),
                )
            };
            unsafe { ffi::BN_CTX_free(ctx) };
            if ok != 1 {
                unsafe {
                    ffi::BN_clear_free(priv_bn);
                    ffi::BN_free(pub_bn);
                }
                return Err(Error::new(ErrorKind::BackendError));
            }
            // DH_set0_key takes ownership of pub_bn/priv_bn on success; on
            // failure it does not, so they must still be freed by us.
            if unsafe { ffi::DH_set0_key(dh, pub_bn, priv_bn) } != 1 {
                unsafe {
                    ffi::BN_clear_free(priv_bn);
                    ffi::BN_free(pub_bn);
                }
                return Err(Error::new(ErrorKind::BackendError));
            }
            Ok(())
        })();
        if let Err(e) = result {
            unsafe { ffi::DH_free(dh) };
            return Err(e);
        }
        Ok(DhKey { dh })
    }

    /// Raw, fixed-width big-endian private value (PKCS#11's CKA_VALUE
    /// format for CKK_DH private keys).
    pub fn private_value(&self) -> Result<Vec<u8>, Error> {
        let bn = unsafe { ffi::DH_get0_priv_key(self.dh) };
        bn_to_vec(bn)
    }

    /// Raw, fixed-width big-endian public value (PKCS#11's CKA_VALUE format
    /// for CKK_DH public keys).
    pub fn public_value(&self) -> Result<Vec<u8>, Error> {
        let bn = unsafe { ffi::DH_get0_pub_key(self.dh) };
        bn_to_vec(bn)
    }

    pub fn derive_shared_secret(
        &self,
        peer_public: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let peer_bn = unsafe {
            ffi::BN_bin2bn(
                peer_public.as_ptr(),
                peer_public.len(),
                std::ptr::null_mut(),
            )
        };
        if peer_bn.is_null() {
            return Err(Error::new(ErrorKind::NullPtr));
        }
        let size = unsafe { ffi::DH_size(self.dh) };
        let mut secret = vec![0u8; usize::try_from(size).unwrap()];
        let n = unsafe {
            ffi::DH_compute_key(secret.as_mut_ptr(), peer_bn, self.dh)
        };
        unsafe { ffi::BN_free(peer_bn) };
        if n < 0 {
            return Err(Error::new(ErrorKind::BackendError));
        }
        secret.truncate(usize::try_from(n).unwrap());
        Ok(secret)
    }

    /// Computes the shared secret between `self` and `peer_public`, using
    /// AWS-LC's *padded* variant (`DH_compute_key_padded`) instead of the
    /// plain `DH_compute_key` `derive_shared_secret` above uses.
    ///
    /// Added to support `src/awslc/ffdh.rs`: PKCS#11's
    /// `CKM_DH_PKCS_DERIVE` mechanism needs a fixed-width,
    /// deterministic shared secret (`CKA_VALUE_LEN` bytes taken from the
    /// low-order/rightmost end of the full-width, big-endian shared
    /// value), but `derive_shared_secret`'s `DH_compute_key` strips
    /// leading zero bytes and so returns a *variable*-length result --
    /// confirmed directly from AWS-LC's own vendored header comment for
    /// this sibling function (`aws-lc-sys`'s `include/openssl/dh.h`):
    /// "this function differs from |DH_compute_key| in that it preserves
    /// leading zeros in the secret... Callers that expect a fixed-width
    /// secret should use this function over |DH_compute_key|." Per that
    /// same doc comment, `DH_compute_key_padded` always writes exactly
    /// `DH_size` bytes on success (unlike `DH_compute_key`, whose
    /// returned length `n` can be smaller), so no truncation of the
    /// output buffer is needed here, unlike `derive_shared_secret` above.
    ///
    /// This is purely additive: `derive_shared_secret` and its own
    /// existing tests are unchanged.
    pub fn derive_shared_secret_padded(
        &self,
        peer_public: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let peer_bn = unsafe {
            ffi::BN_bin2bn(
                peer_public.as_ptr(),
                peer_public.len(),
                std::ptr::null_mut(),
            )
        };
        if peer_bn.is_null() {
            return Err(Error::new(ErrorKind::NullPtr));
        }
        let size = unsafe { ffi::DH_size(self.dh) };
        let mut secret = vec![0u8; usize::try_from(size).unwrap()];
        let n = unsafe {
            ffi::DH_compute_key_padded(secret.as_mut_ptr(), peer_bn, self.dh)
        };
        unsafe { ffi::BN_free(peer_bn) };
        if n < 0 {
            return Err(Error::new(ErrorKind::BackendError));
        }
        Ok(secret)
    }
}

/// Converts a `BIGNUM*` to a raw, fixed-width big-endian byte vector.
///
/// Checks `BN_bn2bin_padded`'s return value (0 on failure) rather than
/// assuming success, mirroring `EcKey::sign`'s (`awslc/src/ec.rs`) existing
/// check of the same function -- added for consistency, even though not
/// reachable today: `bn` is always a
/// non-null `BIGNUM*` owned by a live `DhKey` here, and `out` is always
/// sized from `bn`'s own `BN_num_bytes`, so `BN_bn2bin_padded` cannot fail
/// on a length mismatch in practice.
fn bn_to_vec(bn: *const ffi::BIGNUM) -> Result<Vec<u8>, Error> {
    let len = unsafe { ffi::BN_num_bytes(bn) };
    let mut out = vec![0u8; usize::try_from(len).unwrap()];
    let ret = unsafe { ffi::BN_bn2bin_padded(out.as_mut_ptr(), out.len(), bn) };
    if ret != 1 {
        return Err(Error::new(ErrorKind::BackendError));
    }
    Ok(out)
}

impl Drop for DhKey {
    fn drop(&mut self) {
        unsafe { ffi::DH_free(self.dh) };
    }
}

// SAFETY: `DhKey` exclusively owns its `*mut DH` (never aliased by any
// other live reference), so moving it across threads (Send) is sound --
// nothing else retains a pointer to it.
//
// Sync additionally requires that concurrent calls through `&DhKey` from
// multiple threads are race-free. `private_value`/`public_value` only call
// `DH_get0_priv_key`/`DH_get0_pub_key`, which take a `const DH*` and read
// fields that are set once (at construction, before any sharing) and never
// mutated again. `derive_shared_secret` calls `DH_compute_key`, and
// `derive_shared_secret_padded` calls `DH_compute_key_padded`; both
// functions' own doc comments in AWS-LC's `include/openssl/dh.h` state:
// "This function does not mutate |dh| for thread-safety purposes and may
// be used concurrently." So no method reachable from `&self` racily
// mutates the pointee; both impls are justified.
unsafe impl Send for DhKey {}
unsafe impl Sync for DhKey {}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 3526 Group 5 (1536-bit MODP), used here only to validate the
    // DH_* API shape with a real, standard prime -- not a security
    // recommendation for which group kryoptic should actually register
    // (that's `ffdh_groups.rs`'s decision, unaffected by this task).
    // Copied verbatim (spaces stripped) from AWS-LC's own test suite,
    // `crypto/dh_extra/dh_test.cc`, `TEST(DHTest, RFC3526)`, which in turn
    // cites RFC 3526 section 2 -- not retyped from memory, to avoid
    // transcription errors.
    const RFC3526_GROUP5_PRIME_HEX: &str = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF";

    fn group5_prime() -> Vec<u8> {
        hex_decode(RFC3526_GROUP5_PRIME_HEX)
    }

    fn hex_decode(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn dh_shared_secret_agreement() {
        let p = group5_prime();
        let g = vec![2u8];
        let key1 = DhKey::generate(&p, &g).unwrap();
        let key2 = DhKey::generate(&p, &g).unwrap();
        let secret1 = key1
            .derive_shared_secret(&key2.public_value().unwrap())
            .unwrap();
        let secret2 = key2
            .derive_shared_secret(&key1.public_value().unwrap())
            .unwrap();
        assert_eq!(secret1, secret2);
    }

    #[test]
    fn from_private_reproduces_same_public_value() {
        let p = group5_prime();
        let g = vec![2u8];
        let key1 = DhKey::generate(&p, &g).unwrap();
        let key2 = DhKey::from_private(&p, &g, &key1.private_value().unwrap())
            .unwrap();
        assert_eq!(key1.public_value().unwrap(), key2.public_value().unwrap());
    }

    /// `derive_shared_secret_padded` must agree with `derive_shared_secret`
    /// on both sides of an exchange, and must always be exactly `p.len()`
    /// bytes wide (unlike the unpadded variant, which may be shorter when
    /// the raw shared value happens to have a leading zero byte).
    #[test]
    fn dh_shared_secret_padded_agreement_and_width() {
        let p = group5_prime();
        let g = vec![2u8];
        let key1 = DhKey::generate(&p, &g).unwrap();
        let key2 = DhKey::generate(&p, &g).unwrap();
        let secret1 = key1
            .derive_shared_secret_padded(&key2.public_value().unwrap())
            .unwrap();
        let secret2 = key2
            .derive_shared_secret_padded(&key1.public_value().unwrap())
            .unwrap();
        assert_eq!(secret1, secret2);
        assert_eq!(secret1.len(), p.len());

        // Cross-check against the unpadded variant: after stripping any
        // leading zero bytes from the padded result, what remains must be
        // exactly the unpadded result.
        let unpadded = key1
            .derive_shared_secret(&key2.public_value().unwrap())
            .unwrap();
        let first_nonzero = secret1
            .iter()
            .position(|&b| b != 0)
            .unwrap_or(secret1.len());
        assert_eq!(&secret1[first_nonzero..], unpadded.as_slice());
    }
}
