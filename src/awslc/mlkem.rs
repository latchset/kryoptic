// Copyright 2026
// See LICENSE.txt file for terms

//! ML-KEM (FIPS 203) key encapsulation mechanism, wired to AWS-LC's
//! generic `EVP_PKEY`/`EVP_PKEY_CTX` interface via
//! `awslc::mlkem::{MlKemKey, MlKemParamSet}`.
//! This file supplies the exact functions `src/mlkem.rs` (the
//! backend-agnostic dispatcher) needs from
//! `crate::ossl::mlkem` -- resolved to this module under the `awslc`
//! feature by `src/lib.rs`'s `use awslc as ossl;` alias -- mirroring
//! `crate::ossl::mlkem`'s structure and public surface
//! (`encapsulate`/`decapsulate`/`generate_keypair`/`verify_private_key`).
//!
//! ## The real interface, confirmed from `src/mlkem.rs` (not assumed)
//!
//! `src/mlkem.rs`'s `MlKemMechanism::encapsulate`/`decapsulate`/
//! `generate_keypair` and `mlkem_priv_check_import` call, respectively:
//! - `mlkem::encapsulate(key, ciphertext) -> Result<(Vec<u8>, usize)>`
//! - `mlkem::decapsulate(key, ciphertext) -> Result<Vec<u8>>`
//! - `mlkem::generate_keypair(param_set, &mut pubkey, &mut privkey) ->
//!   Result<()>`
//! - `mlkem::verify_private_key(paramset, seedv, key) ->
//!   Result<Option<Vec<u8>>>`, where `seedv: &Vec<u8>` and
//!   `key: Option<&Vec<u8>>` (matches `Object::get_attr_as_bytes`'s
//!   `Result<&Vec<u8>>` return type exactly, confirmed against
//!   `src/object/mod.rs`'s `attr_as_type!` macro invocation).
//!
//! These four signatures are identical to `crate::ossl::mlkem`'s (the
//! reference), so this file is a straightforward port with the backend
//! primitive swapped from `ossl::pkey::EvpPkey` to `awslc::mlkem::MlKemKey`.
//!
//! ## The real `C_*` entry points (confirmed from `src/fns/keymgmt.rs`)
//!
//! ML-KEM's encapsulate/decapsulate map to PKCS#11 v3.2's dedicated
//! `C_EncapsulateKey`/`C_DecapsulateKey` (`fn_encapsulate_key`/
//! `fn_decapsulate_key` in `src/fns/keymgmt.rs`, wired into
//! `FNLIST_320` in `src/lib.rs`) -- NOT a `Sign`/`Verify`-shaped
//! multi-step operation. `src/mechanism.rs`'s `Mechanism` trait has
//! dedicated `encapsulate`/`decapsulate`/`encapsulate_ciphertext_len`
//! methods (default-`Err`, overridden by `MlKemMechanism` in
//! `src/mlkem.rs`) for exactly this shape: single-shot functions, no
//! operation-state struct, matching the reference's own doc comment
//! ("ML-KEM has no multi-step operation the way sign/verify do").
//!
//! ## Buffer-size negotiation (resolved: handled entirely by the caller)
//!
//! `src/fns/keymgmt.rs`'s `encapsulate_key` (the `C_EncapsulateKey`
//! implementation, ~line 894 at the time of writing) already:
//! 1. Computes the required ciphertext length via
//!    `Mechanism::encapsulate_ciphertext_len` -- implemented in
//!    `src/mlkem.rs` purely from `CKA_PARAMETER_SET`, with no backend
//!    call at all.
//! 2. Returns that length (no-op) when `encrypted_part` is null (the
//!    PKCS#11 two-call size-probe convention).
//! 3. Returns `CKR_BUFFER_TOO_SMALL` *itself*, with the correct required
//!    length written back, whenever the caller's buffer is smaller than
//!    that -- entirely BEFORE `Mechanism::encapsulate` (and therefore
//!    this module's `encapsulate` below) is ever called.
//!
//! So, unlike RSA decrypt (where the output length is data-dependent and
//! only the backend, after doing the work, learns the real length),
//! ML-KEM's ciphertext length is fixed and known in advance
//! per parameter set -- the caller-supplied buffer passed into this
//! module's `encapsulate` is *always* already confirmed large enough by
//! the time this function runs. There is no finalize-before-check
//! ordering hazard to get right here, and no information-leak risk from
//! reporting the wrong length on a too-small buffer either (the length is
//! constant per parameter set, not derived from secret data the way RSA
//! decrypt's padding-dependent plaintext length is). The length check in
//! `encapsulate` below is purely a defensive assertion mirroring the
//! reference's own `ErrorKind::BufferSize` fallback -- not load-bearing
//! for correctness given point 3 above, but cheap insurance against a
//! `Mechanism::encapsulate_ciphertext_len`/`MlKemKey::encapsulate`
//! mismatch.
//!
//! ## Narrow, forced extensions outside this file (flagged prominently)
//!
//! Three extensions were required, all discovered empirically while
//! making this file's tests pass against real AWS-LC (RED confirmed each
//! one; see the task report for the exact failures):
//!
//! 1. **`src/awslc/common.rs`'s `extract_public_key`.**
//!    `src/mlkem.rs`'s `MlKemPrivFactory::create` unconditionally calls
//!    `crate::ossl::common::extract_public_key` (imported at its top,
//!    resolving to `crate::awslc::common::extract_public_key` under this
//!    backend) right after validating a new private key object, to
//!    recover its public key bytes for `CKA_PUBLIC_KEY_INFO`. Before this
//!    task, that function was gated entirely behind
//!    `#[cfg(feature = "ecc")]` and its match only handled `CKK_EC`/
//!    `CKK_EC_EDWARDS`/`CKK_EC_MONTGOMERY` -- it did not exist at all
//!    under `--features awslc,hash,mlkem` (no `ecc`), and even with `ecc`
//!    enabled it fell through to `CKR_GENERAL_ERROR` for `CKK_ML_KEM`.
//!    Fixed narrowly: ungated the function + its `CKA_PUBLIC_KEY_INFO`
//!    fast path so it compiles under `mlkem` alone, added a `CKK_ML_KEM`
//!    arm gated on `feature = "mlkem"`. No existing EC-family behavior
//!    changes: `CKK_EC`/`CKK_EC_EDWARDS`/`CKK_EC_MONTGOMERY` keep their
//!    own feature gates exactly as before.
//!
//! 2. **`awslc::mlkem::MlKemKey::public_key_from_private_key_bytes`
//!    (new).** The obvious implementation of
//!    extension 1's `CKK_ML_KEM` arm -- `MlKemKey::from_private_key(...)
//!    .public_key()` -- reproducibly fails with `ErrorKind::BackendError`
//!    for every parameter set (RED: `seed_based_create_object_both_
//!    directions` below, ckrv 48/`CKR_DEVICE_ERROR`). Root cause,
//!    confirmed against `aws-lc/crypto/fipsmodule/kem/kem.c`:
//!    `EVP_PKEY_kem_new_raw_secret_key` -> `KEM_KEY_set_raw_secret_key`
//!    only `OPENSSL_memdup`s the given bytes into the key's secret-key
//!    field and never touches its public-key field, so
//!    `EVP_PKEY_get_raw_public_key` always fails on such a key -- an
//!    AWS-LC API limitation, not a bug in this wrapper. The fix
//!    doesn't need AWS-LC at all: FIPS 203's expanded private key format
//!    (`dk = dk_PKE ‖ ek ‖ H(ek) ‖ z`) embeds the public key `ek` at a
//!    fixed, known offset, so the new method recovers it by pure byte
//!    slicing. See its doc comment (`awslc/src/mlkem.rs`) for the full
//!    account and the regression tests that pin this down (including a
//!    test that the naive approach really does fail, so this doesn't
//!    silently stop mattering if AWS-LC's behavior ever changes).
//!
//! 3. **`generate_keypair` below samples its own seed rather than calling
//!    `MlKemKey::generate`.** RED: `src/tests/mlkem.rs`'s pre-existing,
//!    backend-agnostic `test_mlkem_seedonly` (which exercises
//!    `C_GenerateKeyPair` then expects `CKA_SEED` to be extractable)
//!    failed with `CKR_ATTRIBUTE_TYPE_INVALID` -- `MlKemKey::generate`
//!    (wrapping AWS-LC's non-deterministic `EVP_PKEY_keygen`) has no way
//!    to report the seed it used, because AWS-LC's C `keygen()` function
//!    has no seed output parameter at all (only `keygen_deterministic`
//!    takes one, as an input). See `generate_keypair`'s doc comment below
//!    for the fix (sample the seed via `awslc::rand::get_random`, derive
//!    via `MlKemKey::from_seed`) and why it's equivalent to
//!    `MlKemKey::generate`, not a behavior change.
//!
//! None of these extend `awslc::mlkem::MlKemKey`'s scope beyond what
//! FIPS 203 and this integration's real callers require, and #2/#3 both
//! reuse primitives (`from_seed`, `awslc::rand::get_random`) already
//! established and reviewed elsewhere in this crate.

use crate::attribute::Attribute;
use crate::error::Result;
use crate::object::Object;
use crate::pkcs11::*;

use crate::lowlevel::mlkem::{MlKemKey, MlKemParamSet};

/// Maps a PKCS#11 ML-KEM parameter set type (`CK_ML_KEM_PARAMETER_SET_TYPE`)
/// to `awslc::mlkem::MlKemParamSet`. Mirrors
/// `crate::ossl::mlkem::mlkem_param_set_to_pkey_type`. `pub(crate)` (not
/// private) because `crate::awslc::common::extract_public_key`'s new
/// `CKK_ML_KEM` arm reuses this exact mapping rather than duplicating it.
pub(crate) fn mlkem_param_set(
    pset: CK_ML_KEM_PARAMETER_SET_TYPE,
) -> Result<MlKemParamSet> {
    match pset {
        CKP_ML_KEM_512 => Ok(MlKemParamSet::MlKem512),
        CKP_ML_KEM_768 => Ok(MlKemParamSet::MlKem768),
        CKP_ML_KEM_1024 => Ok(MlKemParamSet::MlKem1024),
        _ => Err(CKR_ATTRIBUTE_VALUE_INVALID)?,
    }
}

/// Builds an `MlKemKey` from a `CKO_PUBLIC_KEY` object's `CKA_VALUE`.
fn pubkey_from_object(key: &Object) -> Result<MlKemKey> {
    let paramset = mlkem_param_set(key.get_attr_as_ulong(CKA_PARAMETER_SET)?)?;
    let value = key.get_attr_as_bytes(CKA_VALUE)?;
    Ok(MlKemKey::from_public_key(paramset, value)?)
}

/// Builds an `MlKemKey` from a `CKO_PRIVATE_KEY` object's `CKA_VALUE` (the
/// raw expanded private key bytes). `CKA_SEED`, when present on the
/// object, is only relevant to `verify_private_key`'s `C_CreateObject`
/// consistency check below, never here: by the time a private key
/// `Object` reaches `decapsulate`, `mlkem_priv_check_import`
/// (`src/mlkem.rs`) has already guaranteed `CKA_VALUE` is populated
/// regardless of whether the caller originally supplied `CKA_SEED`,
/// `CKA_VALUE`, or both.
fn privkey_from_object(key: &Object) -> Result<MlKemKey> {
    let paramset = mlkem_param_set(key.get_attr_as_ulong(CKA_PARAMETER_SET)?)?;
    let value = key.get_attr_as_bytes(CKA_VALUE)?;
    Ok(MlKemKey::from_private_key(paramset, value)?)
}

/// Performs the ML-KEM key encapsulation operation using the recipient's
/// public key.
///
/// Returns a tuple containing the derived shared secret (`Vec<u8>`) and
/// the actual length of the generated ciphertext written to the
/// `ciphertext` buffer. See this module's doc comment for why the buffer
/// is already guaranteed large enough by the time this function is
/// called -- the length check below is a defensive assertion, not the
/// primary `CKR_BUFFER_TOO_SMALL` enforcement point.
pub fn encapsulate(
    key: &Object,
    ciphertext: &mut [u8],
) -> Result<(Vec<u8>, usize)> {
    let pubkey = pubkey_from_object(key)?;
    let (ct, mut ss) = pubkey.encapsulate()?;
    if ciphertext.len() < ct.len() {
        // Defensive only (see this module's doc comment: the real caller,
        // `src/fns/keymgmt.rs`'s `encapsulate_key`, already guarantees
        // this never trips) -- but `ss`, the freshly-computed shared
        // secret, must still be scrubbed rather than silently dropped on
        // this path, since it isn't being returned to the caller.
        crate::misc::zeromem(&mut ss);
        return Err(CKR_BUFFER_TOO_SMALL)?;
    }
    ciphertext[..ct.len()].copy_from_slice(&ct);
    Ok((ss, ct.len()))
}

/// Performs the ML-KEM key decapsulation operation using the recipient's
/// private key and the received ciphertext.
///
/// Returns the derived shared secret (`Vec<u8>`). Per FIPS 203's implicit
/// rejection property, a tampered/invalid ciphertext does not produce an
/// error here -- it deterministically produces a different, pseudorandom
/// shared secret (see `awslc/src/mlkem.rs`'s
/// `decapsulate_rejects_tampered_ciphertext_or_produces_different_secret`
/// test).
pub fn decapsulate(key: &Object, ciphertext: &[u8]) -> Result<Vec<u8>> {
    let prikey = privkey_from_object(key)?;
    Ok(prikey.decapsulate(ciphertext)?)
}

/// Generates an ML-KEM key pair for the specified parameter set.
///
/// Populates the public key's `CKA_VALUE` and the private key's
/// `CKA_VALUE`/`CKA_SEED`.
///
/// This deliberately does NOT use `MlKemKey::generate` (a
/// non-deterministic constructor, wrapping AWS-LC's `EVP_PKEY_keygen`).
/// FIPS 203's non-deterministic `ML-KEM.KeyGen` (Algorithm 16) is
/// specified as: sample `d, z ←$ B^32` uniformly at random, then derive
/// `(ek, dk) ← ML-KEM.KeyGen_internal(d, z)` deterministically. AWS-LC's
/// `EVP_PKEY_keygen` path performs exactly this internally but never
/// exposes the `d‖z` seed it sampled back to the caller -- its C
/// `keygen()` function (`aws-lc/crypto/fipsmodule/evp/p_kem.c`'s
/// `pkey_kem_keygen`) has no seed output parameter at all (only
/// `keygen_deterministic` takes a seed, as an input). So, to populate
/// `CKA_SEED` on generated private keys -- an attribute this codebase's
/// OpenSSL backend does populate on generation, and which
/// `src/tests/mlkem.rs`'s pre-existing `test_mlkem_seedonly` (confirmed
/// against this backend) requires -- this
/// function instead samples the 64-byte `d‖z` seed itself via AWS-LC's
/// own system RNG (`awslc::rand::get_random`, already used elsewhere in
/// this crate for the same purpose, e.g. `HmacDrbg::new`) and derives the
/// keypair deterministically via `MlKemKey::from_seed`. This is
/// functionally equivalent to `MlKemKey::generate` -- both reduce to the
/// same FIPS 203 algorithm with AWS-LC-sourced entropy -- while also
/// letting this function keep the seed it used.
pub fn generate_keypair(
    param_set: CK_ML_KEM_PARAMETER_SET_TYPE,
    pubkey: &mut Object,
    privkey: &mut Object,
) -> Result<()> {
    let ps = mlkem_param_set(param_set)?;

    // `seed` holds real entropy from the point `get_random` succeeds
    // onward, including on every early-return error path below (e.g.
    // `from_seed`/`public_key`/`private_key`/`set_attr` failing) -- so the
    // whole fallible sequence is wrapped in a closure and `seed` is
    // zeroed exactly once, unconditionally, after it returns, rather than
    // relying on each `?` site to remember to scrub first.
    let mut seed = [0u8; 64];
    let result = (|| -> Result<()> {
        crate::lowlevel::rand::get_random(&mut seed)?;
        let key = MlKemKey::from_seed(ps, &seed)?;

        let pub_bytes = key.public_key()?;
        pubkey.set_attr(Attribute::from_bytes(CKA_VALUE, pub_bytes))?;

        let priv_bytes = key.private_key()?;
        privkey.set_attr(Attribute::from_bytes(CKA_VALUE, priv_bytes))?;
        privkey.set_attr(Attribute::from_bytes(CKA_SEED, seed.to_vec()))?;
        Ok(())
    })();
    crate::misc::zeromem(&mut seed);
    result
}

/// Verifies that a given private key corresponds to a given seed for a
/// specific ML-KEM parameter set.
///
/// If `privkey` is `Some`, compares the provided key against the one
/// derived from the seed in constant time, returning `Ok(None)` on match
/// (nothing needs to change) or an error on mismatch. If `privkey` is
/// `None`, derives and returns the private key from the seed
/// (`Ok(Some(...))`), for `mlkem_priv_check_import` to store as
/// `CKA_VALUE`.
///
/// This mirrors `crate::ossl::mlkem::verify_private_key`'s exact
/// contract, used by `C_CreateObject` (`mlkem_priv_check_import` in
/// `src/mlkem.rs`) to either validate a caller-provided private key
/// against a caller-provided seed, or derive the private key when only
/// the seed is given.
pub fn verify_private_key(
    paramset: CK_ULONG,
    seed: &Vec<u8>,
    privkey: Option<&Vec<u8>>,
) -> Result<Option<Vec<u8>>> {
    let ps = mlkem_param_set(paramset)?;
    let seed_arr: &[u8; 64] = match seed.as_slice().try_into() {
        Ok(a) => a,
        Err(_) => return Err(CKR_ATTRIBUTE_VALUE_INVALID)?,
    };
    let key = MlKemKey::from_seed(ps, seed_arr)?;
    let mut derived_priv = key.private_key()?;

    if let Some(in_priv) = privkey {
        // `derived_priv` is consumed entirely by this comparison (neither
        // outcome returns it to the caller -- `Ok(None)` means "matches,
        // caller keeps what it already had" and the error path returns
        // nothing at all), so it must be scrubbed here before returning,
        // unlike the `else` branch below where ownership moves out to the
        // caller (which stores it as the `Sensitive`-flagged `CKA_VALUE`).
        let matches =
            constant_time_eq::constant_time_eq(in_priv, &derived_priv);
        crate::misc::zeromem(&mut derived_priv);
        if matches {
            Ok(None)
        } else {
            Err(CKR_KEY_INDIGESTIBLE)?
        }
    } else {
        Ok(Some(derived_priv))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mechanism::Mechanisms;
    use crate::object::ObjectFactories;

    fn no_param_mech(mechanism: CK_MECHANISM_TYPE) -> CK_MECHANISM {
        CK_MECHANISM {
            mechanism,
            pParameter: std::ptr::null_mut(),
            ulParameterLen: 0,
        }
    }

    fn ulong_attr(t: CK_ATTRIBUTE_TYPE, v: &CK_ULONG) -> CK_ATTRIBUTE {
        CK_ATTRIBUTE {
            type_: t,
            pValue: v as *const CK_ULONG as CK_VOID_PTR,
            ulValueLen: std::mem::size_of::<CK_ULONG>() as CK_ULONG,
        }
    }

    fn bool_attr(t: CK_ATTRIBUTE_TYPE, v: &CK_BBOOL) -> CK_ATTRIBUTE {
        CK_ATTRIBUTE {
            type_: t,
            pValue: v as *const CK_BBOOL as CK_VOID_PTR,
            ulValueLen: std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
        }
    }

    fn bytes_attr(t: CK_ATTRIBUTE_TYPE, v: &[u8]) -> CK_ATTRIBUTE {
        CK_ATTRIBUTE {
            type_: t,
            pValue: v.as_ptr() as CK_VOID_PTR,
            ulValueLen: v.len() as CK_ULONG,
        }
    }

    /// Registers the real, backend-agnostic ML-KEM mechanisms/factories
    /// from `src/mlkem.rs` (via `crate::mlkem::register`), exactly as
    /// production `C_Initialize`/`C_GenerateKeyPair`/`C_EncapsulateKey`/
    /// `C_DecapsulateKey`/`C_CreateObject` reach them -- so these tests
    /// exercise the real `Mechanism`/`ObjectFactory` trait dispatch, not
    /// just the `awslc::mlkem` primitive layer (already tested in
    /// `awslc/src/mlkem.rs`). Also registers the generic-secret
    /// factory (`crate::object::factory::register`) since `encapsulate`/
    /// `decapsulate`'s `import_from_wrapped` target below is a
    /// `CKO_SECRET_KEY`/`CKK_GENERIC_SECRET` object, which is not part of
    /// `crate::mlkem::register`'s own factory set.
    fn registered() -> (Mechanisms, ObjectFactories) {
        let mut mechs = Mechanisms::new();
        let mut ot = ObjectFactories::new();
        crate::mlkem::register(&mut mechs, &mut ot);
        crate::object::factory::register(&mut mechs, &mut ot);
        (mechs, ot)
    }

    fn generate_keypair(
        mechs: &Mechanisms,
        paramset: CK_ML_KEM_PARAMETER_SET_TYPE,
    ) -> (Object, Object) {
        let ck_true: CK_BBOOL = CK_TRUE;
        let ps = paramset;
        let pubkey_template = [
            ulong_attr(CKA_PARAMETER_SET, &ps),
            bool_attr(CKA_ENCAPSULATE, &ck_true),
        ];
        let prikey_template = [bool_attr(CKA_DECAPSULATE, &ck_true)];
        let mech = no_param_mech(CKM_ML_KEM_KEY_PAIR_GEN);
        let entry = mechs.get(CKM_ML_KEM_KEY_PAIR_GEN).unwrap();
        entry
            .generate_keypair(&mech, &pubkey_template, &prikey_template)
            .expect("generate_keypair")
    }

    /// Full round trip (generate -> encapsulate -> decapsulate) through
    /// the real `Mechanism::encapsulate`/`decapsulate` dispatch, for all
    /// three ML-KEM parameter sets.
    #[test]
    fn round_trip_all_param_sets() {
        let (mechs, ot) = registered();
        for (ps, ct_len) in [
            (CKP_ML_KEM_512, 768usize),
            (CKP_ML_KEM_768, 1088),
            (CKP_ML_KEM_1024, 1568),
        ] {
            let (pubkey, privkey) = generate_keypair(&mechs, ps);
            assert_eq!(
                pubkey.get_attr_as_ulong(CKA_KEY_TYPE).unwrap(),
                CKK_ML_KEM
            );
            assert_eq!(
                privkey.get_attr_as_ulong(CKA_KEY_TYPE).unwrap(),
                CKK_ML_KEM
            );

            let key_type: CK_ULONG = CKK_GENERIC_SECRET;
            let ck_true: CK_BBOOL = CK_TRUE;
            let secret_template = [
                ulong_attr(CKA_CLASS, &CKO_SECRET_KEY),
                ulong_attr(CKA_KEY_TYPE, &key_type),
                bool_attr(CKA_SENSITIVE, &CK_FALSE),
                bool_attr(CKA_EXTRACTABLE, &ck_true),
            ];
            let factory = ot
                .get_obj_factory_from_key_template(&secret_template)
                .expect("generic-secret factory must be registered");

            let mech_entry = mechs.get(CKM_ML_KEM).unwrap();
            assert_eq!(
                mech_entry.encapsulate_ciphertext_len(&pubkey).unwrap(),
                ct_len
            );

            let mut ciphertext = vec![0u8; ct_len];
            let (enc_obj, outlen) = mech_entry
                .encapsulate(
                    &no_param_mech(CKM_ML_KEM),
                    &pubkey,
                    &factory,
                    &secret_template,
                    &mut ciphertext,
                )
                .expect("encapsulate");
            assert_eq!(outlen, ct_len);

            let dec_obj = mech_entry
                .decapsulate(
                    &no_param_mech(CKM_ML_KEM),
                    &privkey,
                    &factory,
                    &secret_template,
                    &ciphertext,
                )
                .expect("decapsulate");

            assert_eq!(
                enc_obj.get_attr_as_bytes(CKA_VALUE).unwrap(),
                dec_obj.get_attr_as_bytes(CKA_VALUE).unwrap()
            );
        }
    }

    /// The seed-based `C_CreateObject` path, both directions of
    /// `verify_private_key`: deriving a private key from a seed alone,
    /// and validating a caller-supplied private key against a
    /// caller-supplied seed (both match and mismatch cases).
    #[test]
    fn seed_based_create_object_both_directions() {
        let (_mechs, ot) = registered();
        let ps: CK_ULONG = CKP_ML_KEM_768;
        let seed = [0x5au8; 64];

        // Direction 1: seed only -> CKA_VALUE derived.
        let template_seed_only = [
            ulong_attr(CKA_CLASS, &CKO_PRIVATE_KEY),
            ulong_attr(CKA_KEY_TYPE, &CKK_ML_KEM),
            ulong_attr(CKA_PARAMETER_SET, &ps),
            bytes_attr(CKA_SEED, &seed),
        ];
        let factory = ot
            .get_obj_factory_from_key_template(&template_seed_only)
            .unwrap();
        let privkey1 = factory
            .create(&template_seed_only)
            .expect("seed-only private key creation must derive CKA_VALUE");
        let derived_value =
            privkey1.get_attr_as_bytes(CKA_VALUE).unwrap().clone();
        assert_eq!(derived_value.len(), 2400); // ML-KEM-768 DK size

        // Direction 2a: seed + matching derived value -> succeeds, and
        // stores the same value.
        let template_matching = [
            ulong_attr(CKA_CLASS, &CKO_PRIVATE_KEY),
            ulong_attr(CKA_KEY_TYPE, &CKK_ML_KEM),
            ulong_attr(CKA_PARAMETER_SET, &ps),
            bytes_attr(CKA_SEED, &seed),
            bytes_attr(CKA_VALUE, &derived_value),
        ];
        let privkey2 = factory
            .create(&template_matching)
            .expect("seed + matching value private key creation must succeed");
        assert_eq!(
            privkey2.get_attr_as_bytes(CKA_VALUE).unwrap(),
            &derived_value
        );

        // Direction 2b: seed + mismatched value -> rejected.
        let mut wrong_value = derived_value.clone();
        wrong_value[0] ^= 0xff;
        let template_mismatch = [
            ulong_attr(CKA_CLASS, &CKO_PRIVATE_KEY),
            ulong_attr(CKA_KEY_TYPE, &CKK_ML_KEM),
            ulong_attr(CKA_PARAMETER_SET, &ps),
            bytes_attr(CKA_SEED, &seed),
            bytes_attr(CKA_VALUE, &wrong_value),
        ];
        let err = factory.create(&template_mismatch).expect_err(
            "seed + mismatched value private key creation must fail",
        );
        assert_eq!(err.rv(), CKR_KEY_INDIGESTIBLE);
    }

    /// Regression test: a seed-only ML-KEM private key import (via the real
    /// `ObjectFactory::create()` path, no `CKA_VALUE` in the template at
    /// all) chained into a REAL encapsulate/decapsulate round trip
    /// through the real `Mechanism::encapsulate`/`decapsulate` dispatch.
    /// `seed_based_create_object_both_directions` above only proves the
    /// derived `CKA_VALUE` is bit-correct in isolation; this test closes
    /// the gap by actually driving that seed-only-imported key through an
    /// operational encapsulate/decapsulate call and checking the shared
    /// secrets agree.
    #[test]
    fn seed_only_import_drives_real_encapsulate_decapsulate() {
        let (mechs, ot) = registered();
        let ps: CK_ULONG = CKP_ML_KEM_768;
        let ck_true: CK_BBOOL = CK_TRUE;
        let seed = [0x99u8; 64];

        let priv_template = [
            ulong_attr(CKA_CLASS, &CKO_PRIVATE_KEY),
            ulong_attr(CKA_KEY_TYPE, &CKK_ML_KEM),
            ulong_attr(CKA_PARAMETER_SET, &ps),
            bytes_attr(CKA_SEED, &seed),
            bool_attr(CKA_DECAPSULATE, &ck_true),
        ];
        let priv_factory = ot
            .get_obj_factory_from_key_template(&priv_template)
            .unwrap();
        let privkey = priv_factory.create(&priv_template).expect(
            "seed-only ML-KEM private key creation via the real \
             ObjectFactory::create() path must succeed",
        );

        // Recover the public key AWS-LC derived at import time (the real
        // `MlKemPrivFactory::create` -> `extract_public_key` ->
        // `MlKemKey::public_key_from_private_key_bytes` path, a forced
        // extension) and build a real `CKO_PUBLIC_KEY` object from
        // it, exactly the shape `C_CreateObject` would produce for a
        // companion public key.
        let pki_der = privkey.get_attr_as_bytes(CKA_PUBLIC_KEY_INFO).unwrap();
        let spki =
            asn1::parse_single::<crate::kasn1::pkcs::SubjectPublicKeyInfo>(
                pki_der.as_slice(),
            )
            .unwrap();
        let pub_bytes = spki.subject_public_key.as_bytes().to_vec();

        let pub_template = [
            ulong_attr(CKA_CLASS, &CKO_PUBLIC_KEY),
            ulong_attr(CKA_KEY_TYPE, &CKK_ML_KEM),
            ulong_attr(CKA_PARAMETER_SET, &ps),
            bytes_attr(CKA_VALUE, &pub_bytes),
            bool_attr(CKA_ENCAPSULATE, &ck_true),
        ];
        let pub_factory =
            ot.get_obj_factory_from_key_template(&pub_template).unwrap();
        let pubkey = pub_factory.create(&pub_template).unwrap();

        let key_type: CK_ULONG = CKK_GENERIC_SECRET;
        let secret_template = [
            ulong_attr(CKA_CLASS, &CKO_SECRET_KEY),
            ulong_attr(CKA_KEY_TYPE, &key_type),
            bool_attr(CKA_SENSITIVE, &CK_FALSE),
            bool_attr(CKA_EXTRACTABLE, &ck_true),
        ];
        let secret_factory = ot
            .get_obj_factory_from_key_template(&secret_template)
            .expect("generic-secret factory must be registered");

        let mech_entry = mechs.get(CKM_ML_KEM).unwrap();
        let ct_len = mech_entry.encapsulate_ciphertext_len(&pubkey).unwrap();
        let mut ciphertext = vec![0u8; ct_len];
        let (enc_obj, outlen) = mech_entry
            .encapsulate(
                &no_param_mech(CKM_ML_KEM),
                &pubkey,
                &secret_factory,
                &secret_template,
                &mut ciphertext,
            )
            .expect("encapsulate");
        assert_eq!(outlen, ct_len);

        let dec_obj = mech_entry
            .decapsulate(
                &no_param_mech(CKM_ML_KEM),
                &privkey,
                &secret_factory,
                &secret_template,
                &ciphertext,
            )
            .expect("decapsulate");

        assert_eq!(
            enc_obj.get_attr_as_bytes(CKA_VALUE).unwrap(),
            dec_obj.get_attr_as_bytes(CKA_VALUE).unwrap(),
            "shared secret from a seed-only-imported private key must \
             match the one produced by encapsulating to its derived \
             public key"
        );
    }

    /// A public-key-only object must be rejected by `decapsulate`'s
    /// `check_key_ops(CKO_PRIVATE_KEY, ...)` gate -- confirms the real
    /// dispatch path, not just that `privkey_from_object` would fail.
    #[test]
    fn public_key_only_object_rejects_decapsulate() {
        let (mechs, ot) = registered();
        let (pubkey, _privkey) = generate_keypair(&mechs, CKP_ML_KEM_512);

        let key_type: CK_ULONG = CKK_GENERIC_SECRET;
        let ck_true: CK_BBOOL = CK_TRUE;
        let secret_template = [
            ulong_attr(CKA_CLASS, &CKO_SECRET_KEY),
            ulong_attr(CKA_KEY_TYPE, &key_type),
            bool_attr(CKA_SENSITIVE, &CK_FALSE),
            bool_attr(CKA_EXTRACTABLE, &ck_true),
        ];
        let factory = ot
            .get_obj_factory_from_key_template(&secret_template)
            .unwrap();

        let mech_entry = mechs.get(CKM_ML_KEM).unwrap();
        let ciphertext = vec![0u8; 768];
        let err = mech_entry
            .decapsulate(
                &no_param_mech(CKM_ML_KEM),
                &pubkey,
                &factory,
                &secret_template,
                &ciphertext,
            )
            .expect_err("decapsulate with a public key must fail");
        assert_eq!(err.rv(), CKR_KEY_TYPE_INCONSISTENT);
    }
}
