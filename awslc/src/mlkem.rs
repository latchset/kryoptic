// ML-KEM (FIPS 203) key encapsulation, wrapping AWS-LC's generic
// EVP_PKEY/EVP_PKEY_CTX interface (AWS-LC has no dedicated classic API
// for ML-KEM, unlike RSA/EC).

use crate::cipher::zeromem;
use crate::error::{Error, ErrorKind};
use crate::ffi;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MlKemParamSet {
    MlKem512,
    MlKem768,
    MlKem1024,
}

impl MlKemParamSet {
    fn nid(self) -> i32 {
        match self {
            MlKemParamSet::MlKem512 => ffi::NID_MLKEM512,
            MlKemParamSet::MlKem768 => ffi::NID_MLKEM768,
            MlKemParamSet::MlKem1024 => ffi::NID_MLKEM1024,
        }
    }

    /// Byte length of the FIPS 203 encapsulation key (`ek`, i.e. the
    /// public key) for this parameter set. Used by
    /// `MlKemKey::public_key_from_private_key_bytes` below to locate
    /// `ek` inside an expanded decapsulation key (`dk`) blob.
    fn public_key_len(self) -> usize {
        match self {
            MlKemParamSet::MlKem512 => 800,
            MlKemParamSet::MlKem768 => 1184,
            MlKemParamSet::MlKem1024 => 1568,
        }
    }
}

// `#[derive(Debug)]` here only ever prints the raw `*mut EVP_PKEY` pointer
// address, never key material (unlike `X25519Key`/`Ed25519Key`, which hold
// key bytes inline and need a hand-written, redacting `Debug` instead) --
// matches `RsaKey`'s precedent (`awslc/src/rsa.rs`), which derives `Debug`
// for the same reason (holds only a raw pointer).
#[derive(Debug)]
pub struct MlKemKey {
    pkey: *mut ffi::EVP_PKEY,
}

// SAFETY: `MlKemKey` exclusively owns its `*mut EVP_PKEY` (never aliased by
// any other live reference), so moving it across threads (Send) is sound.
//
// Sync additionally requires that concurrent calls through `&MlKemKey` from
// multiple threads are race-free. `public_key`/`private_key` only call
// `EVP_PKEY_get_raw_public_key`/`get_raw_private_key`, which take a `const
// EVP_PKEY *` (per `aws-lc/include/openssl/evp.h`) and never mutate the
// pointee. `encapsulate`/`decapsulate` each construct their own fresh
// `EVP_PKEY_CTX` per call via `EVP_PKEY_CTX_new(self.pkey, ...)`, which
// up-refs `self.pkey` (mirrors `OaepPkeyCtx::new`'s documented `set1`
// up-ref pattern in `awslc/src/rsa.rs`) rather than mutating it in place --
// so no method reachable from `&self` racily mutates the shared pointee.
unsafe impl Send for MlKemKey {}
unsafe impl Sync for MlKemKey {}

impl Drop for MlKemKey {
    fn drop(&mut self) {
        unsafe { ffi::EVP_PKEY_free(self.pkey) };
    }
}

impl MlKemKey {
    pub fn generate(param_set: MlKemParamSet) -> Result<MlKemKey, Error> {
        let ctx = unsafe {
            ffi::EVP_PKEY_CTX_new_id(ffi::EVP_PKEY_KEM, std::ptr::null_mut())
        };
        if ctx.is_null() {
            return Err(Error::new(ErrorKind::NullPtr));
        }
        let ok = unsafe {
            ffi::EVP_PKEY_keygen_init(ctx) == 1
                && ffi::EVP_PKEY_CTX_kem_set_params(ctx, param_set.nid()) == 1
        };
        if !ok {
            unsafe { ffi::EVP_PKEY_CTX_free(ctx) };
            return Err(Error::new(ErrorKind::BackendError));
        }
        let mut pkey: *mut ffi::EVP_PKEY = std::ptr::null_mut();
        let ret = unsafe { ffi::EVP_PKEY_keygen(ctx, &mut pkey) };
        unsafe { ffi::EVP_PKEY_CTX_free(ctx) };
        if ret != 1 || pkey.is_null() {
            return Err(Error::new(ErrorKind::BackendError));
        }
        Ok(MlKemKey { pkey })
    }

    /// Deterministic key generation from a 64-byte FIPS 203 `d‖z` seed.
    /// Uses `EVP_PKEY_keygen_deterministic`, NOT the raw-key constructors
    /// (`EVP_PKEY_kem_new_raw_secret_key` rejects 64-byte input outright
    /// -- verified empirically). The `out_pkey`
    /// argument to the size-probe call below must be a null pointer
    /// itself (`ptr::null_mut()`), not `&mut` a null `EVP_PKEY*`
    /// variable -- the latter makes even the size-probe fail (confirmed
    /// empirically against real AWS-LC while implementing this file; see
    /// the task report for the exact error the broken calling convention
    /// produces).
    pub fn from_seed(
        param_set: MlKemParamSet,
        seed: &[u8; 64],
    ) -> Result<MlKemKey, Error> {
        let ctx = unsafe {
            ffi::EVP_PKEY_CTX_new_id(ffi::EVP_PKEY_KEM, std::ptr::null_mut())
        };
        if ctx.is_null() {
            return Err(Error::new(ErrorKind::NullPtr));
        }
        let ok = unsafe {
            ffi::EVP_PKEY_keygen_init(ctx) == 1
                && ffi::EVP_PKEY_CTX_kem_set_params(ctx, param_set.nid()) == 1
        };
        if !ok {
            unsafe { ffi::EVP_PKEY_CTX_free(ctx) };
            return Err(Error::new(ErrorKind::BackendError));
        }

        // Confirm the seed length AWS-LC expects matches what we were
        // given (defensive -- verified 64 for ML-KEM-768 live; re-checked
        // for 512/1024, see
        // `from_seed_matches_fips203_seed_length_for_all_param_sets`
        // below).
        let mut required_len: usize = 0;
        let probe_ret = unsafe {
            ffi::EVP_PKEY_keygen_deterministic(
                ctx,
                std::ptr::null_mut(), // out_pkey itself must be null
                std::ptr::null(),
                &mut required_len,
            )
        };
        if probe_ret != 1 {
            unsafe { ffi::EVP_PKEY_CTX_free(ctx) };
            return Err(Error::new(ErrorKind::BackendError));
        }
        if required_len != seed.len() {
            unsafe { ffi::EVP_PKEY_CTX_free(ctx) };
            return Err(Error::new(ErrorKind::WrapperError));
        }

        let mut pkey: *mut ffi::EVP_PKEY = std::ptr::null_mut();
        let mut seed_len = seed.len();
        let ret = unsafe {
            ffi::EVP_PKEY_keygen_deterministic(
                ctx,
                &mut pkey,
                seed.as_ptr(),
                &mut seed_len,
            )
        };
        unsafe { ffi::EVP_PKEY_CTX_free(ctx) };
        if ret != 1 || pkey.is_null() {
            return Err(Error::new(ErrorKind::BackendError));
        }
        Ok(MlKemKey { pkey })
    }

    pub fn from_public_key(
        param_set: MlKemParamSet,
        bytes: &[u8],
    ) -> Result<MlKemKey, Error> {
        let pkey = unsafe {
            ffi::EVP_PKEY_kem_new_raw_public_key(
                param_set.nid(),
                bytes.as_ptr(),
                bytes.len(),
            )
        };
        if pkey.is_null() {
            return Err(Error::new(ErrorKind::NullPtr));
        }
        Ok(MlKemKey { pkey })
    }

    pub fn from_private_key(
        param_set: MlKemParamSet,
        bytes: &[u8],
    ) -> Result<MlKemKey, Error> {
        let pkey = unsafe {
            ffi::EVP_PKEY_kem_new_raw_secret_key(
                param_set.nid(),
                bytes.as_ptr(),
                bytes.len(),
            )
        };
        if pkey.is_null() {
            return Err(Error::new(ErrorKind::NullPtr));
        }
        Ok(MlKemKey { pkey })
    }

    pub fn public_key(&self) -> Result<Vec<u8>, Error> {
        let mut len: usize = 0;
        if unsafe {
            ffi::EVP_PKEY_get_raw_public_key(
                self.pkey,
                std::ptr::null_mut(),
                &mut len,
            )
        } != 1
        {
            return Err(Error::new(ErrorKind::BackendError));
        }
        let mut buf = vec![0u8; len];
        let mut len2 = len;
        if unsafe {
            ffi::EVP_PKEY_get_raw_public_key(
                self.pkey,
                buf.as_mut_ptr(),
                &mut len2,
            )
        } != 1
        {
            return Err(Error::new(ErrorKind::BackendError));
        }
        buf.truncate(len2);
        Ok(buf)
    }

    pub fn private_key(&self) -> Result<Vec<u8>, Error> {
        let mut len: usize = 0;
        if unsafe {
            ffi::EVP_PKEY_get_raw_private_key(
                self.pkey,
                std::ptr::null_mut(),
                &mut len,
            )
        } != 1
        {
            return Err(Error::new(ErrorKind::BackendError));
        }
        let mut buf = vec![0u8; len];
        let mut len2 = len;
        if unsafe {
            ffi::EVP_PKEY_get_raw_private_key(
                self.pkey,
                buf.as_mut_ptr(),
                &mut len2,
            )
        } != 1
        {
            zeromem(&mut buf);
            return Err(Error::new(ErrorKind::BackendError));
        }
        buf.truncate(len2);
        Ok(buf)
    }

    /// Extracts the embedded public key (`ek`) from a FIPS 203 expanded
    /// private key (`dk`) blob directly, by byte slicing -- NOT via
    /// `from_private_key(...).public_key()`, which cannot work (see
    /// below).
    ///
    /// FIPS 203's expanded decapsulation key format (Algorithm 16/18,
    /// `ML-KEM.KeyGen`) is `dk = dk_PKE ‖ ek ‖ H(ek) ‖ z`: `ek` (the
    /// encapsulation/public key) is exactly `param_set.public_key_len()`
    /// bytes, immediately followed by a fixed 64-byte suffix (`H(ek)`,
    /// 32 bytes, then `z`, 32 bytes) at the very end of `dk`. This is a
    /// property of the standardized key format itself, not an AWS-LC
    /// implementation detail, so this method does pure byte slicing --
    /// no FFI call, no `MlKemKey` construction needed.
    ///
    /// This exists (forced, narrow addition -- integration work found
    /// this while wiring `MlKemKey` into
    /// kryoptic's `C_CreateObject` path, which must recover a private
    /// key's public component when only `CKA_VALUE`, i.e. `dk`, is
    /// available) because AWS-LC's `EVP_PKEY_kem_new_raw_secret_key`
    /// (which `from_private_key` above wraps) calls
    /// `KEM_KEY_set_raw_secret_key` (`aws-lc/crypto/fipsmodule/kem/
    /// kem.c`), which ONLY `OPENSSL_memdup`s the given bytes into the
    /// key's `secret_key` field and never touches `public_key` -- so a
    /// key built via `from_private_key` structurally has no public key
    /// AWS-LC knows about, and calling `.public_key()` on it always
    /// fails with `ErrorKind::BackendError`
    /// (`EVP_PKEY_get_raw_public_key` returns 0 because the underlying
    /// `KEM_KEY.public_key` is `NULL`) -- confirmed empirically: a
    /// `from_seed`-derived key's own `.public_key()` works fine (its
    /// `KEM_KEY` was populated by `keygen_deterministic`, which sets
    /// both fields directly), but re-deriving the same key via
    /// `private_key()` bytes -> `from_private_key` -> `.public_key()`
    /// reproducibly fails. Encapsulation/decapsulation are unaffected by
    /// this gap (`decapsulate` only needs `secret_key`, never
    /// `public_key`); only public-key *recovery* from a raw private key
    /// blob is.
    pub fn public_key_from_private_key_bytes(
        param_set: MlKemParamSet,
        dk: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let ek_len = param_set.public_key_len();
        // 64 = len(H(ek)) + len(z), the fixed FIPS 203 suffix after `ek`.
        if dk.len() < ek_len + 64 {
            return Err(Error::new(ErrorKind::WrapperError));
        }
        let ek_end = dk.len() - 64;
        let ek_start = ek_end - ek_len;
        Ok(dk[ek_start..ek_end].to_vec())
    }

    pub fn encapsulate(&self) -> Result<(Vec<u8>, Vec<u8>), Error> {
        let ctx =
            unsafe { ffi::EVP_PKEY_CTX_new(self.pkey, std::ptr::null_mut()) };
        if ctx.is_null() {
            return Err(Error::new(ErrorKind::NullPtr));
        }
        let mut ct_len: usize = 0;
        let mut ss_len: usize = 0;
        let probe = unsafe {
            ffi::EVP_PKEY_encapsulate(
                ctx,
                std::ptr::null_mut(),
                &mut ct_len,
                std::ptr::null_mut(),
                &mut ss_len,
            )
        };
        if probe != 1 {
            unsafe { ffi::EVP_PKEY_CTX_free(ctx) };
            return Err(Error::new(ErrorKind::BackendError));
        }
        let mut ct = vec![0u8; ct_len];
        let mut ss = vec![0u8; ss_len];
        let mut ct_len2 = ct_len;
        let mut ss_len2 = ss_len;
        let ret = unsafe {
            ffi::EVP_PKEY_encapsulate(
                ctx,
                ct.as_mut_ptr(),
                &mut ct_len2,
                ss.as_mut_ptr(),
                &mut ss_len2,
            )
        };
        unsafe { ffi::EVP_PKEY_CTX_free(ctx) };
        if ret != 1 {
            zeromem(&mut ss);
            return Err(Error::new(ErrorKind::BackendError));
        }
        ct.truncate(ct_len2);
        ss.truncate(ss_len2);
        Ok((ct, ss))
    }

    pub fn decapsulate(&self, ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
        let ctx =
            unsafe { ffi::EVP_PKEY_CTX_new(self.pkey, std::ptr::null_mut()) };
        if ctx.is_null() {
            return Err(Error::new(ErrorKind::NullPtr));
        }
        let mut ss_len: usize = 0;
        let probe = unsafe {
            ffi::EVP_PKEY_decapsulate(
                ctx,
                std::ptr::null_mut(),
                &mut ss_len,
                ciphertext.as_ptr(),
                ciphertext.len(),
            )
        };
        if probe != 1 {
            unsafe { ffi::EVP_PKEY_CTX_free(ctx) };
            return Err(Error::new(ErrorKind::BackendError));
        }
        let mut ss = vec![0u8; ss_len];
        let mut ss_len2 = ss_len;
        let ret = unsafe {
            ffi::EVP_PKEY_decapsulate(
                ctx,
                ss.as_mut_ptr(),
                &mut ss_len2,
                ciphertext.as_ptr(),
                ciphertext.len(),
            )
        };
        unsafe { ffi::EVP_PKEY_CTX_free(ctx) };
        if ret != 1 {
            zeromem(&mut ss);
            return Err(Error::new(ErrorKind::BackendError));
        }
        ss.truncate(ss_len2);
        Ok(ss)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_encapsulate_decapsulate_round_trip() {
        let key = MlKemKey::generate(MlKemParamSet::MlKem768).unwrap();
        let (ct, ss1) = key.encapsulate().unwrap();
        assert_eq!(ct.len(), 1088);
        assert_eq!(ss1.len(), 32);
        let ss2 = key.decapsulate(&ct).unwrap();
        assert_eq!(ss1, ss2);
    }

    #[test]
    fn public_private_key_sizes_match_spec() {
        let key = MlKemKey::generate(MlKemParamSet::MlKem768).unwrap();
        assert_eq!(key.public_key().unwrap().len(), 1184);
        assert_eq!(key.private_key().unwrap().len(), 2400);
    }

    #[test]
    fn from_public_key_can_encapsulate_but_key_is_public_only() {
        let key = MlKemKey::generate(MlKemParamSet::MlKem768).unwrap();
        let pubkey_bytes = key.public_key().unwrap();
        let pubkey_only =
            MlKemKey::from_public_key(MlKemParamSet::MlKem768, &pubkey_bytes)
                .unwrap();
        let (ct, ss1) = pubkey_only.encapsulate().unwrap();
        // The original key (which has the private half) must be able to
        // decapsulate what the public-only key encapsulated.
        let ss2 = key.decapsulate(&ct).unwrap();
        assert_eq!(ss1, ss2);
    }

    #[test]
    fn from_private_key_round_trip() {
        let key = MlKemKey::generate(MlKemParamSet::MlKem768).unwrap();
        let priv_bytes = key.private_key().unwrap();
        let reconstructed =
            MlKemKey::from_private_key(MlKemParamSet::MlKem768, &priv_bytes)
                .unwrap();
        let (ct, ss1) = key.encapsulate().unwrap();
        let ss2 = reconstructed.decapsulate(&ct).unwrap();
        assert_eq!(ss1, ss2);
    }

    #[test]
    fn from_seed_is_deterministic_and_matches_fips203_seed_length() {
        let seed = [0x42u8; 64];
        let key1 = MlKemKey::from_seed(MlKemParamSet::MlKem768, &seed).unwrap();
        let key2 = MlKemKey::from_seed(MlKemParamSet::MlKem768, &seed).unwrap();
        assert_eq!(key1.public_key().unwrap(), key2.public_key().unwrap());
    }

    #[test]
    fn from_seed_derived_key_encapsulates_and_decapsulates_correctly() {
        let seed = [0x77u8; 64];
        let key = MlKemKey::from_seed(MlKemParamSet::MlKem768, &seed).unwrap();
        let (ct, ss1) = key.encapsulate().unwrap();
        let ss2 = key.decapsulate(&ct).unwrap();
        assert_eq!(ss1, ss2);
    }

    #[test]
    fn decapsulate_rejects_tampered_ciphertext_or_produces_different_secret() {
        // FIPS 203's implicit-rejection property means tampered ciphertext
        // does NOT return an error -- it deterministically returns a
        // *different*, pseudorandom shared secret (Kyber/ML-KEM's CCA
        // security relies on this, not on an explicit failure signal).
        // Confirm this behavior rather than assuming an Err() the way
        // most other primitives in this backend behave on tamper.
        let key = MlKemKey::generate(MlKemParamSet::MlKem768).unwrap();
        let (mut ct, ss1) = key.encapsulate().unwrap();
        ct[0] ^= 0xff;
        let ss2 = key.decapsulate(&ct).unwrap();
        assert_ne!(ss1, ss2);
    }

    #[test]
    fn ml_kem_512_and_1024_round_trip() {
        for ps in [MlKemParamSet::MlKem512, MlKemParamSet::MlKem1024] {
            let key = MlKemKey::generate(ps).unwrap();
            let (ct, ss1) = key.encapsulate().unwrap();
            let ss2 = key.decapsulate(&ct).unwrap();
            assert_eq!(ss1, ss2);
        }
    }

    /// The brief's design research only live-tested `from_seed`'s 64-byte
    /// FIPS 203 `d‖z` seed length against ML-KEM-768. Confirm the same
    /// 64-byte length is accepted (and remains deterministic) for
    /// ML-KEM-512 and ML-KEM-1024 too, rather than assuming it generalizes.
    #[test]
    fn from_seed_matches_fips203_seed_length_for_all_param_sets() {
        for ps in [MlKemParamSet::MlKem512, MlKemParamSet::MlKem1024] {
            let seed = [0x99u8; 64];
            let key1 = MlKemKey::from_seed(ps, &seed).unwrap();
            let key2 = MlKemKey::from_seed(ps, &seed).unwrap();
            assert_eq!(key1.public_key().unwrap(), key2.public_key().unwrap());
            let (ct, ss1) = key1.encapsulate().unwrap();
            let ss2 = key1.decapsulate(&ct).unwrap();
            assert_eq!(ss1, ss2);
        }
    }

    /// Regression test for the gap `public_key_from_private_key_bytes`
    /// fixes: `from_private_key(...).public_key()`
    /// cannot work at all, because `EVP_PKEY_kem_new_raw_secret_key`
    /// never populates the underlying `KEM_KEY`'s public-key field (see
    /// `public_key_from_private_key_bytes`'s doc comment). Confirm that
    /// directly, for all three parameter sets, before relying on the
    /// slicing-based replacement.
    #[test]
    fn from_private_key_then_public_key_fails_for_all_param_sets() {
        for ps in [
            MlKemParamSet::MlKem512,
            MlKemParamSet::MlKem768,
            MlKemParamSet::MlKem1024,
        ] {
            let key = MlKemKey::generate(ps).unwrap();
            let priv_bytes = key.private_key().unwrap();
            let reconstructed =
                MlKemKey::from_private_key(ps, &priv_bytes).unwrap();
            assert!(
                reconstructed.public_key().is_err(),
                "from_private_key(...).public_key() was expected to fail \
                 (AWS-LC never derives the public key from a raw secret \
                 key import) -- if this now succeeds, AWS-LC's behavior \
                 changed and public_key_from_private_key_bytes's doc \
                 comment/existence should be revisited"
            );
        }
    }

    /// `public_key_from_private_key_bytes` must recover exactly the
    /// original public key from a key's exported private key bytes, for
    /// both `generate`- and `from_seed`-derived keys, across all three
    /// parameter sets -- the actual fix this file adds for the
    /// `extract_public_key` integration need.
    #[test]
    fn public_key_from_private_key_bytes_recovers_original_public_key() {
        for ps in [
            MlKemParamSet::MlKem512,
            MlKemParamSet::MlKem768,
            MlKemParamSet::MlKem1024,
        ] {
            let key = MlKemKey::generate(ps).unwrap();
            let expected_pub = key.public_key().unwrap();
            let priv_bytes = key.private_key().unwrap();
            let recovered =
                MlKemKey::public_key_from_private_key_bytes(ps, &priv_bytes)
                    .unwrap();
            assert_eq!(recovered, expected_pub);

            let seed = [0xa5u8; 64];
            let seeded_key = MlKemKey::from_seed(ps, &seed).unwrap();
            let expected_seeded_pub = seeded_key.public_key().unwrap();
            let seeded_priv_bytes = seeded_key.private_key().unwrap();
            let recovered_seeded = MlKemKey::public_key_from_private_key_bytes(
                ps,
                &seeded_priv_bytes,
            )
            .unwrap();
            assert_eq!(recovered_seeded, expected_seeded_pub);
        }
    }

    /// Too-short input (shorter than `public_key_len() + 64`) must be
    /// rejected rather than panicking on the slice arithmetic.
    #[test]
    fn public_key_from_private_key_bytes_rejects_too_short_input() {
        let short = vec![0u8; 10];
        let err = MlKemKey::public_key_from_private_key_bytes(
            MlKemParamSet::MlKem768,
            &short,
        )
        .unwrap_err();
        assert_eq!(err.kind(), ErrorKind::WrapperError);
    }
}
