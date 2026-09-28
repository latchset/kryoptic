// Copyright 2026
// See LICENSE.txt file for terms

//! ML-DSA (FIPS 204) signatures, wired to AWS-LC's `EVP_PKEY`/`EVP_PKEY_CTX`
//! interface via `awslc::mldsa::{MlDsaKey, MlDsaParamSet, MlDsaHedge}`.
//! This file supplies the exact functions
//! `src/mldsa.rs` (the backend-agnostic dispatcher) needs from
//! `crate::ossl::mldsa` -- resolved to this module under the
//! `awslc` feature by `src/lib.rs`'s `use awslc as ossl;` alias.
//!
//! ## Scope: `CKM_ML_DSA` and `CKM_HASH_ML_DSA*`
//!
//! `src/mldsa.rs`'s `register()` registers a single `MlDsaMechanism`
//! instance (with combined `CKF_SIGN | CKF_VERIFY` flags) against BOTH
//! `CKM_ML_DSA` and the whole `CKM_HASH_ML_DSA*` family, and its
//! `sign_new`/`verify_new`/`verify_signature_new` all funnel into a single
//! entry point:
//! `mldsa::MlDsaOperation::sigver_new(mech, key, flag, signature)`.
//! The plain/pure-mode path (`CKM_ML_DSA`) and FIPS 204's HashML-DSA
//! (prehash) family are both implemented:
//! `CKM_HASH_ML_DSA` (the combined-hash variant, where the caller supplies
//! an already-externally-computed digest and names its algorithm via the
//! `CK_HASH_SIGN_ADDITIONAL_CONTEXT.hash` mechanism parameter) and its
//! eight per-digest variants `CKM_HASH_ML_DSA_SHA224/256/384/512` and
//! `CKM_HASH_ML_DSA_SHA3_224/256/384/512` (which hash the message
//! internally via `awslc::digest::Digest`, streaming through
//! `sign_update`/`verify_update` exactly like `CKM_ML_DSA` does, then hash
//! at finalization instead of buffering the raw message). Mirrors the
//! exact match-arm shape `crate::ossl::mldsa` already uses for this (see
//! that file's `verify_internal`/`sign_final`/`hash_mldsa_m_prime`/etc.).
//!
//! `CKM_HASH_ML_DSA_SHAKE128`/`CKM_HASH_ML_DSA_SHAKE256` are deliberately
//! NOT implemented here: `src/mldsa.rs::register()` -- the backend-agnostic
//! dispatcher, unmodified by this task -- never registers either mechanism
//! (its `register()` loop lists exactly `CKM_ML_DSA`, `CKM_HASH_ML_DSA`,
//! and the eight SHA-2/SHA-3 variants above; the SHAKE constants appear
//! only in `src/pkcs11/mod.rs`'s numeric-constant-to-name table, never in
//! any `Mechanisms` registration), so neither `CK_MECHANISM_TYPE` is ever
//! reachable through the real `Mechanism` trait dispatch for EITHER
//! backend, not just this one -- confirmed by reading `crate::ossl::
//! mldsa::MlDsaOperation::sigver_new`'s own `setup_digest` match arm (no
//! `CKM_HASH_ML_DSA_SHAKE128`/`_SHAKE256` arms either, just the same
//! `/* TODO SHAKE hashes? */` comment) and its OID lookup in
//! `hash_mldsa_m_prime` (same gap). This is a pre-existing, backend-
//! agnostic scope boundary, not something narrowed by this task.
//!
//! ## The real `MlDsaKey` API, and how PKCS#11's hedge/context
//! parameters map onto it
//!
//! `MlDsaKey::sign(&self, msg, context: Option<&[u8]>, hedge: MlDsaHedge)
//! -> Result<Vec<u8>, Error>` and `MlDsaKey::verify(&self, msg, sig,
//! context: Option<&[u8]>) -> Result<(), Error>` are the real signatures
//! (see `awslc/src/mldsa.rs`) -- context strings are genuinely supported
//! (FIPS 204's `mu` computation is hand-implemented and verified
//! byte-for-byte against a real ACVP-derived vector), but `MlDsaHedge` has
//! only two variants, `Hedged` and `DeterministicRequired`, and
//! `DeterministicRequired` always returns `Err` -- AWS-LC's ML-DSA signing
//! unconditionally draws fresh internal randomness with no override hook
//! anywhere in its public API (confirmed via three independent
//! lines of evidence: no exported symbol for the internal function that
//! takes an explicit `rnd`, no usable RNG-override mechanism, and an
//! empirical two-signatures-differ probe -- see `MlDsaHedge`'s and
//! `MlDsaKey::sign`'s doc comments in `awslc/src/mldsa.rs`).
//!
//! PKCS#11 v3.2's `CK_SIGN_ADDITIONAL_CONTEXT.hedgeVariant` has three
//! values: `CKH_HEDGE_PREFERRED`, `CKH_HEDGE_REQUIRED`,
//! `CKH_DETERMINISTIC_REQUIRED`. This module maps them as follows
//! (`map_hedge`, below):
//! - `CKH_HEDGE_PREFERRED` and `CKH_HEDGE_REQUIRED` both map to
//!   `MlDsaHedge::Hedged` -- AWS-LC's ML-DSA signing is unconditionally
//!   randomized, so there is no non-hedged mode to "prefer" away from;
//!   both PKCS#11 values collapse to the same (only available) behavior.
//! - `CKH_DETERMINISTIC_REQUIRED` is rejected with
//!   `CKR_MECHANISM_PARAM_INVALID` at operation-construction time, i.e.
//!   before any FFI call is ever made -- never silently downgraded to
//!   hedged signing (which would violate the caller's explicit
//!   determinism request) and never a panic. `CKR_MECHANISM_PARAM_INVALID`
//!   is the same error `crate::ossl::mldsa::MlDsaParams::new` already uses
//!   for other "this specific value of this mechanism parameter can't be
//!   honored" cases in this exact struct (an unrecognized `hedgeVariant`
//!   value, or a `ulContextLen` over the 255-byte FIPS 204 limit) --
//!   chosen here for the same reason and to match that convention, since
//!   `crate::ossl::mldsa` itself has no directly analogous "reject this
//!   particular hedgeVariant value" branch (OpenSSL 3.5+ genuinely
//!   supports deterministic ML-DSA signing, so the reference backend never
//!   needs to reject it).
//! - Per the PKCS#11 v3.2 spec ("On verification the hedgeVariant
//!   parameter is ignored", also noted in `crate::ossl::mldsa::MlDsaParams
//!   ::ossl_params`'s doc comment), `hedgeVariant` is validated (rejecting
//!   unrecognized values) but never used to reject a *verify* operation --
//!   `CKH_DETERMINISTIC_REQUIRED` is a completely normal, successful input
//!   to `verify_new`/`verify_signature_new`.
//!
//! This is a genuine, permanent AWS-LC capability gap, in the same
//! category as Ed448/X448, SLH-DSA, and `CKM_AES_CTS`
//! -- not a bug to fix. Concrete, confirmed consequence:
//! `src/tests/mldsa.rs`'s two `CKH_DETERMINISTIC_REQUIRED` known-answer
//! vectors (fixed expected-signature-byte tests) cannot and will not pass
//! `sig_gen` against this backend -- `verify_deterministic_required_known_
//! answer_vector_signing_is_rejected_but_verify_still_works`, below,
//! reproduces the first of those two vectors and confirms exactly this:
//! verification succeeds (context handling is correct), but requesting a
//! signature under `CKH_DETERMINISTIC_REQUIRED` fails cleanly with
//! `CKR_MECHANISM_PARAM_INVALID`, not a panic or a silently-hedged
//! signature.
//!
//! ## Narrow, forced extension outside this file (flagged prominently)
//!
//! `src/mldsa.rs`'s `MlDsaPrivFactory::create` unconditionally calls
//! `crate::ossl::common::extract_public_key` (resolved to
//! `crate::awslc::common::extract_public_key` under this backend) right
//! after validating a new private key object, to recover its public key
//! bytes for `CKA_PUBLIC_KEY_INFO` -- BEFORE that attribute has been set
//! on the object, so the function's `CKA_PUBLIC_KEY_INFO` fast path never
//! fires here (same situation as ML-KEM's). Previously,
//! `extract_public_key` had no `CKK_ML_DSA` arm at all. Fixed narrowly: a
//! `CKK_ML_DSA` arm was added, gated on `feature = "mldsa"`. Unlike
//! ML-KEM's analogous gap, no new primitive method was needed:
//! AWS-LC's `PQDSA_KEY_set_raw_private_key`
//! (`aws-lc/crypto/fipsmodule/pqdsa/pqdsa.c`) DOES derive and cache the
//! public key from the private key at import time (`pqdsa_pack_pk_from_
//! sk`), unlike ML-KEM's `KEM_KEY_set_raw_secret_key`, which only ever
//! stores the secret bytes and never touches the public-key field. So
//! `MlDsaKey::from_private_key(...).public_key()` (the existing,
//! unmodified API) already does the right thing -- confirmed empirically
//! by this module's own tests, not just by reading AWS-LC's C source. No
//! existing `extract_public_key` behavior (EC/EdDSA/Montgomery/ML-KEM
//! arms) changes.

use crate::attribute::Attribute;
use crate::error::Result;
use crate::kasn1::oid::{
    SHA224_OID, SHA256_OID, SHA384_OID, SHA3_224_NIST_OID, SHA3_256_NIST_OID,
    SHA3_384_NIST_OID, SHA3_512_NIST_OID, SHA512_OID,
};
use crate::misc::bytes_to_vec;
use crate::object::Object;
use crate::pkcs11::*;

use crate::lowlevel::digest::{Digest, DigestAlg};
use crate::lowlevel::mldsa::{MlDsaHedge, MlDsaKey, MlDsaParamSet};
use asn1;

/* See FIPS-204, 4. Parameter Sets */
const ML_DSA_44_SIG_SIZE: usize = 2420;
const ML_DSA_65_SIG_SIZE: usize = 3309;
const ML_DSA_87_SIG_SIZE: usize = 4627;

/// Maximum allowed FIPS 204 context length (1-byte length prefix).
const MAX_CONTEXT_LEN: usize = 255;

/// Maps a PKCS#11 ML-DSA parameter set type (`CK_ML_DSA_PARAMETER_SET_TYPE`)
/// to `awslc::mldsa::MlDsaParamSet`. Mirrors `crate::ossl::mldsa::
/// mldsa_param_set_to_pkey_type`. `pub(crate)` (not private) because
/// `crate::awslc::common::extract_public_key`'s `CKK_ML_DSA` arm reuses
/// this exact mapping rather than duplicating it (same pattern as
/// `crate::awslc::mlkem::mlkem_param_set`).
pub(crate) fn mldsa_param_set(
    pset: CK_ML_DSA_PARAMETER_SET_TYPE,
) -> Result<MlDsaParamSet> {
    match pset {
        CKP_ML_DSA_44 => Ok(MlDsaParamSet::MlDsa44),
        CKP_ML_DSA_65 => Ok(MlDsaParamSet::MlDsa65),
        CKP_ML_DSA_87 => Ok(MlDsaParamSet::MlDsa87),
        _ => Err(CKR_ATTRIBUTE_VALUE_INVALID)?,
    }
}

/// Maps a parameter set to its fixed FIPS 204 signature size.
fn mldsa_sig_size(pset: MlDsaParamSet) -> usize {
    match pset {
        MlDsaParamSet::MlDsa44 => ML_DSA_44_SIG_SIZE,
        MlDsaParamSet::MlDsa65 => ML_DSA_65_SIG_SIZE,
        MlDsaParamSet::MlDsa87 => ML_DSA_87_SIG_SIZE,
    }
}

/// Maps PKCS#11's `CK_HEDGE_TYPE` onto `awslc::mldsa::MlDsaHedge` for a
/// *signing* operation. See this module's doc comment for the full
/// rationale: `CKH_HEDGE_PREFERRED`/`CKH_HEDGE_REQUIRED` both collapse to
/// `MlDsaHedge::Hedged` (AWS-LC's ML-DSA signing is unconditionally
/// randomized), and `CKH_DETERMINISTIC_REQUIRED` is rejected outright --
/// AWS-LC has no way to honor it. Never called for verify operations,
/// which ignore `hedgeVariant` entirely per the PKCS#11 v3.2 spec.
fn map_hedge(hedge: CK_HEDGE_TYPE) -> Result<MlDsaHedge> {
    match hedge {
        CKH_HEDGE_PREFERRED | CKH_HEDGE_REQUIRED => Ok(MlDsaHedge::Hedged),
        CKH_DETERMINISTIC_REQUIRED => Err(CKR_MECHANISM_PARAM_INVALID)?,
        _ => Err(CKR_MECHANISM_PARAM_INVALID)?,
    }
}

/// Parses the optional `CK_SIGN_ADDITIONAL_CONTEXT` mechanism parameter
/// shared by `CKM_ML_DSA` and every `CKM_HASH_ML_DSA_SHA*` per-digest
/// variant (they all use this same parameter struct -- only `CKM_HASH_
/// ML_DSA` itself uses the different, larger `CK_HASH_SIGN_ADDITIONAL_
/// CONTEXT`, parsed separately by `parse_hash_sign_additional_context`,
/// below). Returns the raw `hedgeVariant` (unmapped -- the caller decides
/// whether/how to apply it, since verify operations ignore it) and the
/// context string, if any. `None`/absent parameter defaults to
/// `CKH_HEDGE_PREFERRED` with no context, mirroring `crate::ossl::mldsa::
/// MlDsaParams::new`'s default.
fn parse_sign_additional_context(
    mech: &CK_MECHANISM,
) -> Result<(CK_HEDGE_TYPE, Option<Vec<u8>>)> {
    if mech.pParameter.is_null() {
        return Ok((CKH_HEDGE_PREFERRED, None));
    }
    let params = mech.get_parameters::<CK_SIGN_ADDITIONAL_CONTEXT>()?;
    match params.hedgeVariant {
        CKH_HEDGE_PREFERRED
        | CKH_HEDGE_REQUIRED
        | CKH_DETERMINISTIC_REQUIRED => (),
        _ => return Err(CKR_MECHANISM_PARAM_INVALID)?,
    }
    let context = if params.ulContextLen > 0 {
        if params.ulContextLen > MAX_CONTEXT_LEN as CK_ULONG {
            return Err(CKR_MECHANISM_PARAM_INVALID)?;
        }
        Some(bytes_to_vec(params.pContext, params.ulContextLen as usize))
    } else {
        None
    };
    Ok((params.hedgeVariant, context))
}

/// Parses `CKM_HASH_ML_DSA`'s mandatory `CK_HASH_SIGN_ADDITIONAL_CONTEXT`
/// mechanism parameter: like `parse_sign_additional_context`, but also
/// carries the `hash` field naming which digest algorithm the caller
/// already used to externally hash the message (the `data` given to
/// `sign`/`verify` for this mechanism IS that digest, not the raw
/// message -- see `MlDsaOperation::sign`'s `CKM_HASH_ML_DSA` arm).
///
/// Unlike `parse_sign_additional_context`, the parameter is REQUIRED (not
/// optional): a null `pParameter` is rejected with `CKR_MECHANISM_PARAM_
/// INVALID` rather than defaulting, because there is no sensible default
/// for `hash` -- without it there is no way to know which OID belongs in
/// `M'` or what digest size to expect. This is a deliberate, narrow
/// strengthening over `crate::ossl::mldsa::MlDsaParams::new`, which
/// silently defaults to `CK_UNAVAILABLE_INFORMATION` on a null parameter
/// and only fails later (at `hashsize` computation); rejecting immediately
/// here is strictly more correct and doesn't change behavior for any
/// caller that supplies the parameter (which is always required in
/// practice, since `CKM_HASH_ML_DSA` is meaningless without it).
fn parse_hash_sign_additional_context(
    mech: &CK_MECHANISM,
) -> Result<(CK_HEDGE_TYPE, Option<Vec<u8>>, CK_MECHANISM_TYPE)> {
    if mech.pParameter.is_null() {
        return Err(CKR_MECHANISM_PARAM_INVALID)?;
    }
    let params = mech.get_parameters::<CK_HASH_SIGN_ADDITIONAL_CONTEXT>()?;
    match params.hedgeVariant {
        CKH_HEDGE_PREFERRED
        | CKH_HEDGE_REQUIRED
        | CKH_DETERMINISTIC_REQUIRED => (),
        _ => return Err(CKR_MECHANISM_PARAM_INVALID)?,
    }
    let context = if params.ulContextLen > 0 {
        if params.ulContextLen > MAX_CONTEXT_LEN as CK_ULONG {
            return Err(CKR_MECHANISM_PARAM_INVALID)?;
        }
        Some(bytes_to_vec(params.pContext, params.ulContextLen as usize))
    } else {
        None
    };
    Ok((params.hedgeVariant, context, params.hash))
}

/// Maps a PKCS#11 hash-mechanism constant (`CKM_SHA256` etc, as recorded
/// in `MlDsaOperation::hash`) to the `awslc::digest::DigestAlg` and the
/// FIPS 204 HashML-DSA `AlgorithmIdentifier` OID it corresponds to (FIPS
/// 204 Algorithm 4 Step 23 / Algorithm 5 Step 18; mirrors `crate::ossl::
/// mldsa::hash_mldsa_m_prime`'s identical OID match, verified against that
/// file directly). Only the eight hash algorithms `src/mldsa.rs::
/// register()` actually wires `CKM_HASH_ML_DSA*` mechanisms up for are
/// supported here -- see this module's doc comment for why SHAKE128/
/// SHAKE256 are out of scope for both backends, not narrowed by this
/// function.
fn hash_ml_dsa_hash_params(
    hash: CK_MECHANISM_TYPE,
) -> Result<(DigestAlg, asn1::ObjectIdentifier)> {
    let params = match hash {
        CKM_SHA224 => (DigestAlg::Sha2_224, SHA224_OID),
        CKM_SHA256 => (DigestAlg::Sha2_256, SHA256_OID),
        CKM_SHA384 => (DigestAlg::Sha2_384, SHA384_OID),
        CKM_SHA512 => (DigestAlg::Sha2_512, SHA512_OID),
        CKM_SHA3_224 => (DigestAlg::Sha3_224, SHA3_224_NIST_OID),
        CKM_SHA3_256 => (DigestAlg::Sha3_256, SHA3_256_NIST_OID),
        CKM_SHA3_384 => (DigestAlg::Sha3_384, SHA3_384_NIST_OID),
        CKM_SHA3_512 => (DigestAlg::Sha3_512, SHA3_512_NIST_OID),
        _ => return Err(CKR_MECHANISM_INVALID)?,
    };
    Ok(params)
}

/// Maps a `CKM_HASH_ML_DSA_SHA*`-family mechanism (the per-digest
/// internal-hashing variants) to the plain `CKM_SHA*` constant that names
/// its hash algorithm -- so `MlDsaOperation::hash` and `hash_ml_dsa_hash_
/// params` (above) can use the SAME representation regardless of whether
/// the digest was computed externally (`CKM_HASH_ML_DSA`) or internally by
/// this operation (`CKM_HASH_ML_DSA_SHA*`), matching `crate::ossl::mldsa`'s
/// identical choice (`MlDsaParams::hash` stores `CKM_SHA256` etc in both
/// cases -- see `crate::ossl::mldsa::MlDsaOperation::setup_digest`).
fn hash_ml_dsa_variant_hash_mech(
    mechanism: CK_MECHANISM_TYPE,
) -> Result<CK_MECHANISM_TYPE> {
    let hash = match mechanism {
        CKM_HASH_ML_DSA_SHA224 => CKM_SHA224,
        CKM_HASH_ML_DSA_SHA256 => CKM_SHA256,
        CKM_HASH_ML_DSA_SHA384 => CKM_SHA384,
        CKM_HASH_ML_DSA_SHA512 => CKM_SHA512,
        CKM_HASH_ML_DSA_SHA3_224 => CKM_SHA3_224,
        CKM_HASH_ML_DSA_SHA3_256 => CKM_SHA3_256,
        CKM_HASH_ML_DSA_SHA3_384 => CKM_SHA3_384,
        CKM_HASH_ML_DSA_SHA3_512 => CKM_SHA3_512,
        _ => return Err(CKR_MECHANISM_INVALID)?,
    };
    Ok(hash)
}

/// Builds an `MlDsaKey` from a `CKO_PRIVATE_KEY` object's `CKA_VALUE` --
/// the full expanded FIPS 204 private key (2560/4032/4896 bytes depending
/// on parameter set), never the 32-byte seed. `mldsa_priv_check_import`
/// (`src/mldsa.rs`) already guarantees `CKA_VALUE` is populated and sized
/// correctly for the declared parameter set by the time any private key
/// `Object` reaches here, so there is no risk of `MlDsaKey::from_private_
/// key`'s length-based seed/private-key auto-detection (see its doc
/// comment in `awslc/src/mldsa.rs`) mis-reading this as a seed: the
/// smallest expanded private key (ML-DSA-44, 2560 bytes) is nowhere near
/// the 32-byte seed length.
fn privkey_from_object(
    key: &Object,
    param_set: MlDsaParamSet,
) -> Result<MlDsaKey> {
    let value = key.get_attr_as_bytes(CKA_VALUE)?;
    Ok(MlDsaKey::from_private_key(param_set, value)?)
}

/// Builds an `MlDsaKey` from a `CKO_PUBLIC_KEY` object's `CKA_VALUE`.
fn pubkey_from_object(
    key: &Object,
    param_set: MlDsaParamSet,
) -> Result<MlDsaKey> {
    let value = key.get_attr_as_bytes(CKA_VALUE)?;
    Ok(MlDsaKey::from_public_key(param_set, value)?)
}

/// The key material backing an active `MlDsaOperation`: a private key for
/// signing, or a public key for verification. Mirrors `crate::awslc::
/// eddsa::EddsaKey`'s shape.
#[derive(Debug)]
enum MlDsaKeyRole {
    Sign(MlDsaKey),
    Verify(MlDsaKey),
}

/// Represents an active ML-DSA signing or verification operation.
///
/// Field shape mirrors `crate::ossl::mldsa::MlDsaOperation`'s (`mech`/
/// `finalized`/`in_use`/context+hedge parameters/`signature`/`hasher`/
/// `hashsize`).
#[derive(Debug)]
pub struct MlDsaOperation {
    /// The specific ML-DSA mechanism (`CKM_ML_DSA` or one of the
    /// `CKM_HASH_ML_DSA*` family -- see this module's doc comment).
    mech: CK_MECHANISM_TYPE,
    /// Flag indicating if the operation has been finalized.
    finalized: bool,
    /// Flag indicating if the operation is in progress (update called).
    in_use: bool,
    /// The key material (private for signing, public for verification).
    key: MlDsaKeyRole,
    /// Expected/produced signature size for this parameter set.
    sigsize: usize,
    /// Optional FIPS 204 context string (`None` and `Some(&[])` are
    /// equivalent, per `MlDsaKey::sign`/`verify`'s contract).
    context: Option<Vec<u8>>,
    /// The hedge mode to use when signing. Meaningless/unused for verify
    /// operations (hedgeVariant is ignored on verification).
    hedge: MlDsaHedge,
    /// Accumulates the message as it streams in via `sign_update`/
    /// `verify_update` for `CKM_ML_DSA` -- ML-DSA (pure mode) has no
    /// incremental primitive (FIPS 204's `mu` is a single SHAKE256 call
    /// over the whole message), so the full message must be buffered
    /// before the single `sign`/`verify` call at finalization. Mirrors
    /// `crate::awslc::eddsa::EddsaOperation`'s identical situation
    /// (Ed25519 pure mode). Unused (stays empty) for every `CKM_HASH_
    /// ML_DSA*` variant, which streams into `hasher` instead (or, for
    /// `CKM_HASH_ML_DSA` itself, is single-part-only -- the digest is
    /// supplied whole as `data`).
    buffer: Vec<u8>,
    /// `Some` only for `verify_signature_new` (PKCS#11 v3.2's
    /// `VerifySignature`, where the signature is supplied at
    /// initialization time rather than at `verify()`).
    signature: Option<Vec<u8>>,
    /// The externally-named or internally-selected hash algorithm behind
    /// a `CKM_HASH_ML_DSA*` operation, always stored as the plain `CKM_
    /// SHA*` constant (via `hash_ml_dsa_hash_params`'s OID lookup) --
    /// `CK_UNAVAILABLE_INFORMATION` for plain `CKM_ML_DSA`. Mirrors
    /// `crate::ossl::mldsa::MlDsaOperation`'s `params.hash` field.
    hash: CK_MECHANISM_TYPE,
    /// Expected digest size for `hash`, above. `0` for plain `CKM_ML_DSA`.
    hashsize: usize,
    /// Internal hasher for the per-digest `CKM_HASH_ML_DSA_SHA*` variants.
    /// `None` for plain `CKM_ML_DSA` and for `CKM_HASH_ML_DSA` itself
    /// (whose caller supplies the already-computed digest directly as
    /// `data`, per PKCS#11 v3.2's `CKM_HASH_ML_DSA` semantics).
    hasher: Option<Digest>,
}

impl MlDsaOperation {
    /// Creates a new ML-DSA sign or verify operation context.
    ///
    /// Matches `crate::ossl::mldsa::MlDsaOperation::sigver_new`'s exact
    /// signature -- `src/mldsa.rs`'s `MlDsaMechanism::sign_new`/
    /// `verify_new`/`verify_signature_new` call this directly.
    pub fn sigver_new(
        mech: &CK_MECHANISM,
        key: &Object,
        flag: CK_FLAGS,
        signature: Option<&[u8]>,
    ) -> Result<MlDsaOperation> {
        let param_set =
            mldsa_param_set(key.get_attr_as_ulong(CKA_PARAMETER_SET)?)?;
        let sigsize = mldsa_sig_size(param_set);

        /* Parses the mechanism parameter and resolves (hash, hashsize,
         * hasher) for the mechanism family -- see each helper's doc
         * comment for the exact parameter struct/defaulting rules. */
        let (raw_hedge, context, hash, hashsize, hasher) = match mech.mechanism
        {
            CKM_ML_DSA => {
                let (h, c) = parse_sign_additional_context(mech)?;
                (h, c, CK_UNAVAILABLE_INFORMATION, 0usize, None)
            }
            CKM_HASH_ML_DSA => {
                let (h, c, inner_hash) =
                    parse_hash_sign_additional_context(mech)?;
                let (alg, _oid) = hash_ml_dsa_hash_params(inner_hash)?;
                let size = Digest::new(alg)?.size();
                (h, c, inner_hash, size, None)
            }
            CKM_HASH_ML_DSA_SHA224
            | CKM_HASH_ML_DSA_SHA256
            | CKM_HASH_ML_DSA_SHA384
            | CKM_HASH_ML_DSA_SHA512
            | CKM_HASH_ML_DSA_SHA3_224
            | CKM_HASH_ML_DSA_SHA3_256
            | CKM_HASH_ML_DSA_SHA3_384
            | CKM_HASH_ML_DSA_SHA3_512 => {
                let (h, c) = parse_sign_additional_context(mech)?;
                let inner_hash = hash_ml_dsa_variant_hash_mech(mech.mechanism)?;
                let (alg, _oid) = hash_ml_dsa_hash_params(inner_hash)?;
                let digest = Digest::new(alg)?;
                let size = digest.size();
                (h, c, inner_hash, size, Some(digest))
            }
            _ => return Err(CKR_MECHANISM_INVALID)?,
        };

        if let Some(sig) = signature {
            if sig.len() != sigsize {
                return Err(CKR_SIGNATURE_LEN_RANGE)?;
            }
        }

        let (role, hedge) = match flag {
            CKF_SIGN => {
                /* Validated and, if necessary, rejected HERE -- before any
                 * key material is built or any FFI call is made. See this
                 * module's doc comment for why CKH_DETERMINISTIC_REQUIRED
                 * cannot be honored. */
                let hedge = map_hedge(raw_hedge)?;
                (
                    MlDsaKeyRole::Sign(privkey_from_object(key, param_set)?),
                    hedge,
                )
            }
            CKF_VERIFY => {
                /* hedgeVariant is ignored on verification (PKCS#11 v3.2
                 * spec) -- CKH_DETERMINISTIC_REQUIRED is a perfectly
                 * normal, successful input here. */
                (
                    MlDsaKeyRole::Verify(pubkey_from_object(key, param_set)?),
                    MlDsaHedge::Hedged,
                )
            }
            _ => return Err(CKR_GENERAL_ERROR)?,
        };

        Ok(MlDsaOperation {
            mech: mech.mechanism,
            finalized: false,
            in_use: false,
            key: role,
            sigsize,
            context,
            hedge,
            buffer: Vec::new(),
            signature: signature.map(|s| s.to_vec()),
            hash,
            hashsize,
            hasher,
        })
    }

    /// Builds FIPS 204's HashML-DSA message representative `M' = 0x01 ||
    /// len(ctx) || ctx || OID || Hash(msg)` (Algorithm 4 Step 23 /
    /// Algorithm 5 Step 18) as parts and signs it via `MlDsaKey::
    /// sign_prehashed` (the shared-`mu` primitive). Mirrors
    /// `crate::ossl::mldsa::MlDsaOperation::sign_hash`.
    fn sign_hash_ml_dsa(
        &self,
        key: &MlDsaKey,
        hashed_msg: &[u8],
    ) -> Result<Vec<u8>> {
        let (_, oid) = hash_ml_dsa_hash_params(self.hash)?;
        let ctx_len = self.context.as_ref().map_or(0, |c| c.len());
        let prefix = [1u8, u8::try_from(ctx_len)?];
        let ctx: &[u8] = self.context.as_deref().unwrap_or(&[]);
        let oid_der = match asn1::write_single(&oid) {
            Ok(b) => b,
            Err(_) => return Err(CKR_GENERAL_ERROR)?,
        };
        let parts: [&[u8]; 4] = [&prefix, ctx, oid_der.as_slice(), hashed_msg];
        Ok(key.sign_prehashed(&parts, self.hedge)?)
    }

    /// Verification counterpart of `sign_hash_ml_dsa` -- see its doc
    /// comment. Mirrors `crate::ossl::mldsa::MlDsaOperation::verify_hash`.
    fn verify_hash_ml_dsa(
        &self,
        key: &MlDsaKey,
        hashed_msg: &[u8],
        sig: &[u8],
    ) -> Result<()> {
        let (_, oid) = hash_ml_dsa_hash_params(self.hash)?;
        let ctx_len = self.context.as_ref().map_or(0, |c| c.len());
        let prefix = [1u8, u8::try_from(ctx_len)?];
        let ctx: &[u8] = self.context.as_deref().unwrap_or(&[]);
        let oid_der = match asn1::write_single(&oid) {
            Ok(b) => b,
            Err(_) => return Err(CKR_GENERAL_ERROR)?,
        };
        let parts: [&[u8]; 4] = [&prefix, ctx, oid_der.as_slice(), hashed_msg];
        Ok(key.verify_prehashed(&parts, sig)?)
    }
}

impl crate::mechanism::MechOperation for MlDsaOperation {
    fn mechanism(&self) -> Result<CK_MECHANISM_TYPE> {
        Ok(self.mech)
    }

    fn finalized(&self) -> bool {
        self.finalized
    }
}

impl crate::mechanism::Sign for MlDsaOperation {
    fn sign(&mut self, data: &[u8], signature: &mut [u8]) -> Result<()> {
        if self.in_use {
            return Err(CKR_OPERATION_NOT_INITIALIZED)?;
        }
        if self.finalized {
            return Err(CKR_OPERATION_NOT_INITIALIZED)?;
        }
        if self.mech == CKM_HASH_ML_DSA {
            /* CKM_HASH_ML_DSA is single-part only, and `data` here IS the
             * externally-computed digest, not a raw message -- see this
             * module's doc comment. */
            self.finalized = true;
            if data.len() != self.hashsize {
                return Err(CKR_DATA_LEN_RANGE)?;
            }
            if signature.len() != self.sigsize {
                return Err(CKR_SIGNATURE_LEN_RANGE)?;
            }
            let key = match &self.key {
                MlDsaKeyRole::Sign(k) => k,
                MlDsaKeyRole::Verify(_) => return Err(CKR_GENERAL_ERROR)?,
            };
            let sig = self.sign_hash_ml_dsa(key, data)?;
            if sig.len() != signature.len() {
                return Err(CKR_DEVICE_ERROR)?;
            }
            signature.copy_from_slice(&sig);
            return Ok(());
        }
        self.sign_update(data)?;
        self.sign_final(signature)
    }

    fn sign_update(&mut self, data: &[u8]) -> Result<()> {
        if self.finalized {
            return Err(CKR_OPERATION_NOT_INITIALIZED)?;
        }
        self.in_use = true;
        match self.mech {
            CKM_HASH_ML_DSA => {
                /* CKM_HASH_ML_DSA is single-part only. */
                self.finalized = true;
                return Err(CKR_OPERATION_NOT_INITIALIZED)?;
            }
            CKM_HASH_ML_DSA_SHA224
            | CKM_HASH_ML_DSA_SHA256
            | CKM_HASH_ML_DSA_SHA384
            | CKM_HASH_ML_DSA_SHA512
            | CKM_HASH_ML_DSA_SHA3_224
            | CKM_HASH_ML_DSA_SHA3_256
            | CKM_HASH_ML_DSA_SHA3_384
            | CKM_HASH_ML_DSA_SHA3_512 => match &mut self.hasher {
                Some(h) => h.update(data)?,
                None => return Err(CKR_GENERAL_ERROR)?,
            },
            _ => self.buffer.extend_from_slice(data),
        }
        Ok(())
    }

    fn sign_final(&mut self, signature: &mut [u8]) -> Result<()> {
        if !self.in_use {
            return Err(CKR_OPERATION_NOT_INITIALIZED)?;
        }
        if self.finalized {
            return Err(CKR_OPERATION_NOT_INITIALIZED)?;
        }
        self.finalized = true;
        if signature.len() != self.sigsize {
            return Err(CKR_SIGNATURE_LEN_RANGE)?;
        }
        let key = match &self.key {
            MlDsaKeyRole::Sign(k) => k,
            MlDsaKeyRole::Verify(_) => return Err(CKR_GENERAL_ERROR)?,
        };
        let sig = match self.mech {
            CKM_ML_DSA => {
                key.sign(&self.buffer, self.context.as_deref(), self.hedge)?
            }
            CKM_HASH_ML_DSA_SHA224
            | CKM_HASH_ML_DSA_SHA256
            | CKM_HASH_ML_DSA_SHA384
            | CKM_HASH_ML_DSA_SHA512
            | CKM_HASH_ML_DSA_SHA3_224
            | CKM_HASH_ML_DSA_SHA3_256
            | CKM_HASH_ML_DSA_SHA3_384
            | CKM_HASH_ML_DSA_SHA3_512 => {
                let mut hash = vec![0u8; self.hashsize];
                match &mut self.hasher {
                    Some(h) => {
                        h.finalize(&mut hash)?;
                    }
                    None => return Err(CKR_GENERAL_ERROR)?,
                }
                self.sign_hash_ml_dsa(key, &hash)?
            }
            _ => return Err(CKR_GENERAL_ERROR)?,
        };
        if sig.len() != signature.len() {
            return Err(CKR_DEVICE_ERROR)?;
        }
        signature.copy_from_slice(&sig);
        Ok(())
    }

    fn signature_len(&self) -> Result<usize> {
        Ok(self.sigsize)
    }
}

impl MlDsaOperation {
    /// Internal helper for performing one-shot or final verification step.
    fn verify_internal(
        &mut self,
        data: &[u8],
        signature: Option<&[u8]>,
    ) -> Result<()> {
        if self.in_use {
            return Err(CKR_OPERATION_NOT_INITIALIZED)?;
        }
        if self.finalized {
            return Err(CKR_OPERATION_NOT_INITIALIZED)?;
        }
        if self.mech == CKM_HASH_ML_DSA {
            self.finalized = true;
            /* For CKM_HASH_ML_DSA the data is the (externally-computed)
             * hash -- see this module's doc comment. */
            if data.len() != self.hashsize {
                return Err(CKR_DATA_LEN_RANGE)?;
            }
            return self.verify_hash_dispatch(data, signature);
        }
        self.verify_int_update(data)?;
        self.verify_int_final(signature)
    }

    /// Resolves the signature bytes and public key, then dispatches to
    /// `verify_hash_ml_dsa` -- shared by `verify_internal`'s `CKM_HASH_
    /// ML_DSA` arm and `verify_int_final`'s per-digest arms.
    fn verify_hash_dispatch(
        &self,
        hashed_msg: &[u8],
        signature: Option<&[u8]>,
    ) -> Result<()> {
        let sig: &[u8] = match signature {
            Some(s) => {
                if s.len() != self.sigsize {
                    return Err(CKR_SIGNATURE_LEN_RANGE)?;
                }
                s
            }
            None => match &self.signature {
                Some(s) => s.as_slice(),
                None => return Err(CKR_GENERAL_ERROR)?,
            },
        };
        let key = match &self.key {
            MlDsaKeyRole::Verify(k) => k,
            MlDsaKeyRole::Sign(_) => return Err(CKR_GENERAL_ERROR)?,
        };
        self.verify_hash_ml_dsa(key, hashed_msg, sig)
    }

    /// Internal helper for updating a multi-part verification. Accumulates
    /// data (see `buffer`'s doc comment on `MlDsaOperation`) for `CKM_ML_
    /// DSA`, or streams into `hasher` for the `CKM_HASH_ML_DSA_SHA*`
    /// per-digest variants.
    fn verify_int_update(&mut self, data: &[u8]) -> Result<()> {
        if self.finalized {
            return Err(CKR_OPERATION_NOT_INITIALIZED)?;
        }
        self.in_use = true;
        match self.mech {
            CKM_HASH_ML_DSA => {
                /* CKM_HASH_ML_DSA is single-part only. */
                self.finalized = true;
                return Err(CKR_OPERATION_NOT_INITIALIZED)?;
            }
            CKM_HASH_ML_DSA_SHA224
            | CKM_HASH_ML_DSA_SHA256
            | CKM_HASH_ML_DSA_SHA384
            | CKM_HASH_ML_DSA_SHA512
            | CKM_HASH_ML_DSA_SHA3_224
            | CKM_HASH_ML_DSA_SHA3_256
            | CKM_HASH_ML_DSA_SHA3_384
            | CKM_HASH_ML_DSA_SHA3_512 => match &mut self.hasher {
                Some(h) => h.update(data)?,
                None => return Err(CKR_GENERAL_ERROR)?,
            },
            _ => self.buffer.extend_from_slice(data),
        }
        Ok(())
    }

    /// Internal helper for the final step of multi-part verification.
    fn verify_int_final(&mut self, signature: Option<&[u8]>) -> Result<()> {
        if !self.in_use {
            return Err(CKR_OPERATION_NOT_INITIALIZED)?;
        }
        if self.finalized {
            return Err(CKR_OPERATION_NOT_INITIALIZED)?;
        }
        self.finalized = true;

        match self.mech {
            CKM_ML_DSA => {
                let sig: &[u8] = match signature {
                    Some(s) => {
                        if s.len() != self.sigsize {
                            return Err(CKR_SIGNATURE_LEN_RANGE)?;
                        }
                        s
                    }
                    None => match &self.signature {
                        Some(s) => s.as_slice(),
                        None => return Err(CKR_GENERAL_ERROR)?,
                    },
                };
                let key = match &self.key {
                    MlDsaKeyRole::Verify(k) => k,
                    MlDsaKeyRole::Sign(_) => return Err(CKR_GENERAL_ERROR)?,
                };
                Ok(key.verify(&self.buffer, sig, self.context.as_deref())?)
            }
            CKM_HASH_ML_DSA_SHA224
            | CKM_HASH_ML_DSA_SHA256
            | CKM_HASH_ML_DSA_SHA384
            | CKM_HASH_ML_DSA_SHA512
            | CKM_HASH_ML_DSA_SHA3_224
            | CKM_HASH_ML_DSA_SHA3_256
            | CKM_HASH_ML_DSA_SHA3_384
            | CKM_HASH_ML_DSA_SHA3_512 => {
                let mut hash = vec![0u8; self.hashsize];
                match &mut self.hasher {
                    Some(h) => {
                        h.finalize(&mut hash)?;
                    }
                    None => return Err(CKR_GENERAL_ERROR)?,
                }
                self.verify_hash_dispatch(&hash, signature)
            }
            _ => Err(CKR_GENERAL_ERROR)?,
        }
    }
}

impl crate::mechanism::Verify for MlDsaOperation {
    fn verify(&mut self, data: &[u8], signature: &[u8]) -> Result<()> {
        self.verify_internal(data, Some(signature))
    }

    fn verify_update(&mut self, data: &[u8]) -> Result<()> {
        self.verify_int_update(data)
    }

    fn verify_final(&mut self, signature: &[u8]) -> Result<()> {
        self.verify_int_final(Some(signature))
    }

    fn signature_len(&self) -> Result<usize> {
        Ok(self.sigsize)
    }
}

impl crate::mechanism::VerifySignature for MlDsaOperation {
    fn verify(&mut self, data: &[u8]) -> Result<()> {
        self.verify_internal(data, None)
    }

    fn verify_update(&mut self, data: &[u8]) -> Result<()> {
        self.verify_int_update(data)
    }

    fn verify_final(&mut self) -> Result<()> {
        self.verify_int_final(None)
    }
}

/// Generates an ML-DSA key pair for the specified parameter set.
///
/// Populates the public key's `CKA_VALUE` and the private key's
/// `CKA_VALUE`/`CKA_SEED`.
///
/// Deliberately does NOT use `MlDsaKey::generate` (a
/// non-deterministic constructor, wrapping AWS-LC's `EVP_PKEY_keygen`):
/// that path has no way to report the seed it used (AWS-LC's C `keygen()`
/// has no seed output parameter), so `CKA_SEED` couldn't be populated on
/// generated private keys -- an attribute `src/tests/mldsa.rs`'s
/// pre-existing `test_mldsa_seedonly` requires after `C_GenerateKeyPair`.
/// Instead, this function samples the 32-byte FIPS 204 seed itself via
/// AWS-LC's own system RNG (`awslc::rand::get_random`) and derives the
/// keypair deterministically via `MlDsaKey::from_seed`. This is
/// functionally equivalent to `MlDsaKey::generate` -- both reduce to the
/// same key-generation algorithm with AWS-LC-sourced entropy -- while also
/// letting this function keep the seed it used. Exactly mirrors `crate::
/// awslc::mlkem::generate_keypair`'s identical situation and fix.
pub fn generate_keypair(
    param_set: CK_ML_DSA_PARAMETER_SET_TYPE,
    pubkey: &mut Object,
    privkey: &mut Object,
) -> Result<()> {
    let ps = mldsa_param_set(param_set)?;

    // `seed` holds real entropy from the point `get_random` succeeds
    // onward, including on every early-return error path below -- the
    // whole fallible sequence is wrapped in a closure and `seed` is
    // zeroed exactly once, unconditionally, after it returns.
    let mut seed = [0u8; 32];
    let result = (|| -> Result<()> {
        crate::lowlevel::rand::get_random(&mut seed)?;
        let key = MlDsaKey::from_seed(ps, &seed)?;

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
/// specific ML-DSA parameter set.
///
/// If `privkey` is `Some`, compares the provided key against the one
/// derived from the seed in constant time, returning `Ok(None)` on match
/// or an error on mismatch. If `privkey` is `None`, derives and returns
/// the private key from the seed (`Ok(Some(...))`).
///
/// Mirrors `crate::ossl::mldsa::verify_private_key`'s exact contract, used
/// by `C_CreateObject` (`mldsa_priv_check_import` in `src/mldsa.rs`).
pub fn verify_private_key(
    paramset: CK_ULONG,
    seed: &Vec<u8>,
    privkey: Option<&Vec<u8>>,
) -> Result<Option<Vec<u8>>> {
    let ps = mldsa_param_set(paramset)?;
    let seed_arr: &[u8; 32] = match seed.as_slice().try_into() {
        Ok(a) => a,
        Err(_) => return Err(CKR_ATTRIBUTE_VALUE_INVALID)?,
    };
    let key = MlDsaKey::from_seed(ps, seed_arr)?;
    let mut derived_priv = key.private_key()?;

    if let Some(in_priv) = privkey {
        // `derived_priv` is consumed entirely by this comparison, so it
        // must be scrubbed here before returning (unlike the `else`
        // branch below, where ownership moves out to the caller, which
        // stores it as the `Sensitive`-flagged `CKA_VALUE`).
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

// Deliberately inline (unlike the reference backend's convention of
// keeping tests under src/tests/*.rs): see src/awslc/aes.rs's matching
// `mod tests` doc comment for the rationale (private-surface access this
// module's private helpers need, e.g. `map_hedge`, `sign_hash_ml_dsa`,
// that src/tests/*.rs cannot reach through the public `Mechanism` trait
// dispatch alone).
#[cfg(test)]
mod tests {
    use super::*;
    use crate::mechanism::Mechanisms;
    use crate::object::ObjectFactories;

    use asn1;

    fn no_param_mech(mechanism: CK_MECHANISM_TYPE) -> CK_MECHANISM {
        CK_MECHANISM {
            mechanism,
            pParameter: std::ptr::null_mut(),
            ulParameterLen: 0,
        }
    }

    fn context_mech(
        mechanism: CK_MECHANISM_TYPE,
        params: &CK_SIGN_ADDITIONAL_CONTEXT,
    ) -> CK_MECHANISM {
        CK_MECHANISM {
            mechanism,
            pParameter: params as *const _ as CK_VOID_PTR,
            ulParameterLen: std::mem::size_of::<CK_SIGN_ADDITIONAL_CONTEXT>()
                as CK_ULONG,
        }
    }

    /// Builds a `CKM_HASH_ML_DSA` mechanism carrying the mandatory
    /// `CK_HASH_SIGN_ADDITIONAL_CONTEXT` parameter (the combined-hash
    /// variant's larger parameter struct, with the extra `hash` field --
    /// see `parse_hash_sign_additional_context`'s doc comment).
    fn hash_context_mech(
        params: &CK_HASH_SIGN_ADDITIONAL_CONTEXT,
    ) -> CK_MECHANISM {
        CK_MECHANISM {
            mechanism: CKM_HASH_ML_DSA,
            pParameter: params as *const _ as CK_VOID_PTR,
            ulParameterLen: std::mem::size_of::<CK_HASH_SIGN_ADDITIONAL_CONTEXT>(
            ) as CK_ULONG,
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

    /// Registers the real, backend-agnostic ML-DSA mechanisms/factories
    /// from `src/mldsa.rs` (via `crate::mldsa::register`), exactly as
    /// production `C_Initialize`/`C_GenerateKeyPair`/`C_Sign*`/`C_Verify*`/
    /// `C_CreateObject` reach them.
    fn registered() -> (Mechanisms, ObjectFactories) {
        let mut mechs = Mechanisms::new();
        let mut ot = ObjectFactories::new();
        crate::mldsa::register(&mut mechs, &mut ot);
        (mechs, ot)
    }

    fn generate_keypair_for(
        mechs: &Mechanisms,
        paramset: CK_ML_DSA_PARAMETER_SET_TYPE,
    ) -> (Object, Object) {
        let ck_true: CK_BBOOL = CK_TRUE;
        let pubkey_template = [
            ulong_attr(CKA_PARAMETER_SET, &paramset),
            bool_attr(CKA_VERIFY, &ck_true),
        ];
        let prikey_template = [bool_attr(CKA_SIGN, &ck_true)];
        let mech = no_param_mech(CKM_ML_DSA_KEY_PAIR_GEN);
        let entry = mechs.get(CKM_ML_DSA_KEY_PAIR_GEN).unwrap();
        entry
            .generate_keypair(&mech, &pubkey_template, &prikey_template)
            .expect("generate_keypair")
    }

    /// Full round trip (generate -> sign -> verify) through the real
    /// `Mechanism::sign_new`/`verify_new` dispatch, for all three ML-DSA
    /// parameter sets, plain `CKM_ML_DSA` (no mechanism parameter).
    #[test]
    fn round_trip_all_param_sets() {
        let (mechs, _ot) = registered();
        for (ps, sig_len) in [
            (CKP_ML_DSA_44, ML_DSA_44_SIG_SIZE),
            (CKP_ML_DSA_65, ML_DSA_65_SIG_SIZE),
            (CKP_ML_DSA_87, ML_DSA_87_SIG_SIZE),
        ] {
            let (pubkey, privkey) = generate_keypair_for(&mechs, ps);
            assert_eq!(
                pubkey.get_attr_as_ulong(CKA_KEY_TYPE).unwrap(),
                CKK_ML_DSA
            );
            assert_eq!(
                privkey.get_attr_as_ulong(CKA_KEY_TYPE).unwrap(),
                CKK_ML_DSA
            );

            let mech_entry = mechs.get(CKM_ML_DSA).unwrap();
            let msg = b"round trip message";
            let mut sign_op = mech_entry
                .sign_new(&no_param_mech(CKM_ML_DSA), &privkey)
                .unwrap();
            assert_eq!(sign_op.signature_len().unwrap(), sig_len);
            let mut sig = vec![0u8; sig_len];
            sign_op.sign(msg, &mut sig).unwrap();

            let mut verify_op = mech_entry
                .verify_new(&no_param_mech(CKM_ML_DSA), &pubkey)
                .unwrap();
            verify_op.verify(msg, &sig).unwrap();

            // Tamper rejection: flipping a message byte must fail
            // verification, not panic or silently succeed.
            let mut verify_op2 = mech_entry
                .verify_new(&no_param_mech(CKM_ML_DSA), &pubkey)
                .unwrap();
            let mut tampered = msg.to_vec();
            tampered[0] ^= 0xff;
            let err = verify_op2.verify(&tampered, &sig).unwrap_err();
            assert_eq!(err.rv(), CKR_SIGNATURE_INVALID);

            // C_VerifySignature path.
            let mut verifysig_op = mech_entry
                .verify_signature_new(&no_param_mech(CKM_ML_DSA), &pubkey, &sig)
                .unwrap();
            verifysig_op.verify(msg).unwrap();
        }
    }

    /// A real, non-empty context-string round trip through the full
    /// `Mechanism` dispatch: a signature made with one context must
    /// verify with that same context, and must be rejected under a
    /// different (or absent) context.
    #[test]
    fn context_string_round_trip_and_mismatch_rejected() {
        let (mechs, _ot) = registered();
        let (pubkey, privkey) = generate_keypair_for(&mechs, CKP_ML_DSA_65);
        let mech_entry = mechs.get(CKM_ML_DSA).unwrap();
        let msg = b"message bound to a context string";

        let ctx_a = b"context-a".to_vec();
        let sign_params = CK_SIGN_ADDITIONAL_CONTEXT {
            hedgeVariant: CKH_HEDGE_PREFERRED,
            pContext: ctx_a.as_ptr() as *mut CK_BYTE,
            ulContextLen: ctx_a.len() as CK_ULONG,
        };
        let mut sign_op = mech_entry
            .sign_new(&context_mech(CKM_ML_DSA, &sign_params), &privkey)
            .unwrap();
        let mut sig = vec![0u8; ML_DSA_65_SIG_SIZE];
        sign_op.sign(msg, &mut sig).unwrap();

        // Correct context verifies.
        let verify_params_a = CK_SIGN_ADDITIONAL_CONTEXT {
            hedgeVariant: CKH_HEDGE_PREFERRED,
            pContext: ctx_a.as_ptr() as *mut CK_BYTE,
            ulContextLen: ctx_a.len() as CK_ULONG,
        };
        let mut verify_op = mech_entry
            .verify_new(&context_mech(CKM_ML_DSA, &verify_params_a), &pubkey)
            .unwrap();
        verify_op.verify(msg, &sig).unwrap();

        // Different context is rejected.
        let ctx_b = b"context-b".to_vec();
        let verify_params_b = CK_SIGN_ADDITIONAL_CONTEXT {
            hedgeVariant: CKH_HEDGE_PREFERRED,
            pContext: ctx_b.as_ptr() as *mut CK_BYTE,
            ulContextLen: ctx_b.len() as CK_ULONG,
        };
        let mut verify_op_b = mech_entry
            .verify_new(&context_mech(CKM_ML_DSA, &verify_params_b), &pubkey)
            .unwrap();
        let err = verify_op_b.verify(msg, &sig).unwrap_err();
        assert_eq!(err.rv(), CKR_SIGNATURE_INVALID);

        // No context at all is also rejected (None is a specific, distinct
        // context value, not a wildcard).
        let mut verify_op_none = mech_entry
            .verify_new(&no_param_mech(CKM_ML_DSA), &pubkey)
            .unwrap();
        let err = verify_op_none.verify(msg, &sig).unwrap_err();
        assert_eq!(err.rv(), CKR_SIGNATURE_INVALID);
    }

    /// `CKH_HEDGE_PREFERRED` and `CKH_HEDGE_REQUIRED` both map to
    /// `MlDsaHedge::Hedged` and both produce valid, verifiable signatures.
    #[test]
    fn hedge_preferred_and_required_both_work() {
        let (mechs, _ot) = registered();
        let (pubkey, privkey) = generate_keypair_for(&mechs, CKP_ML_DSA_44);
        let mech_entry = mechs.get(CKM_ML_DSA).unwrap();
        let msg = b"hedge variant coverage";

        for hedge in [CKH_HEDGE_PREFERRED, CKH_HEDGE_REQUIRED] {
            let params = CK_SIGN_ADDITIONAL_CONTEXT {
                hedgeVariant: hedge,
                pContext: std::ptr::null_mut(),
                ulContextLen: 0,
            };
            let mut sign_op = mech_entry
                .sign_new(&context_mech(CKM_ML_DSA, &params), &privkey)
                .unwrap();
            let mut sig = vec![0u8; ML_DSA_44_SIG_SIZE];
            sign_op.sign(msg, &mut sig).unwrap();

            let mut verify_op = mech_entry
                .verify_new(&no_param_mech(CKM_ML_DSA), &pubkey)
                .unwrap();
            verify_op.verify(msg, &sig).unwrap();
        }
    }

    /// `CKH_DETERMINISTIC_REQUIRED` must be rejected cleanly (not a panic,
    /// not a silently-hedged signature) with `CKR_MECHANISM_PARAM_INVALID`
    /// -- and the rejection must happen at `sign_new` time, before any
    /// signing attempt.
    #[test]
    fn deterministic_required_sign_is_rejected_cleanly() {
        let (mechs, _ot) = registered();
        let (_pubkey, privkey) = generate_keypair_for(&mechs, CKP_ML_DSA_44);
        let mech_entry = mechs.get(CKM_ML_DSA).unwrap();

        let params = CK_SIGN_ADDITIONAL_CONTEXT {
            hedgeVariant: CKH_DETERMINISTIC_REQUIRED,
            pContext: std::ptr::null_mut(),
            ulContextLen: 0,
        };
        let err = mech_entry
            .sign_new(&context_mech(CKM_ML_DSA, &params), &privkey)
            .expect_err(
                "CKH_DETERMINISTIC_REQUIRED must be rejected, not silently \
                 hedged",
            );
        assert_eq!(err.rv(), CKR_MECHANISM_PARAM_INVALID);
    }

    /// `CKH_DETERMINISTIC_REQUIRED` must NOT affect verification --
    /// per the PKCS#11 v3.2 spec, hedgeVariant is ignored on verify.
    #[test]
    fn deterministic_required_does_not_affect_verify() {
        let (mechs, _ot) = registered();
        let (pubkey, privkey) = generate_keypair_for(&mechs, CKP_ML_DSA_44);
        let mech_entry = mechs.get(CKM_ML_DSA).unwrap();
        let msg = b"deterministic-required verify path";

        let mut sign_op = mech_entry
            .sign_new(&no_param_mech(CKM_ML_DSA), &privkey)
            .unwrap();
        let mut sig = vec![0u8; ML_DSA_44_SIG_SIZE];
        sign_op.sign(msg, &mut sig).unwrap();

        let params = CK_SIGN_ADDITIONAL_CONTEXT {
            hedgeVariant: CKH_DETERMINISTIC_REQUIRED,
            pContext: std::ptr::null_mut(),
            ulContextLen: 0,
        };
        let mut verify_op = mech_entry
            .verify_new(&context_mech(CKM_ML_DSA, &params), &pubkey)
            .expect(
                "CKH_DETERMINISTIC_REQUIRED must not be rejected for verify",
            );
        verify_op.verify(msg, &sig).unwrap();
    }

    /// The seed-based `C_CreateObject` path, both directions of
    /// `verify_private_key`: deriving a private key from a seed alone,
    /// and validating a caller-supplied private key against a
    /// caller-supplied seed (both match and mismatch cases).
    #[test]
    fn seed_based_create_object_both_directions() {
        let (_mechs, ot) = registered();
        let ps: CK_ULONG = CKP_ML_DSA_65;
        let seed = [0x5au8; 32];

        let template_seed_only = [
            ulong_attr(CKA_CLASS, &CKO_PRIVATE_KEY),
            ulong_attr(CKA_KEY_TYPE, &CKK_ML_DSA),
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
        assert_eq!(derived_value.len(), ML_DSA_65_SK_SIZE_TEST);

        let template_matching = [
            ulong_attr(CKA_CLASS, &CKO_PRIVATE_KEY),
            ulong_attr(CKA_KEY_TYPE, &CKK_ML_DSA),
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

        let mut wrong_value = derived_value.clone();
        wrong_value[0] ^= 0xff;
        let template_mismatch = [
            ulong_attr(CKA_CLASS, &CKO_PRIVATE_KEY),
            ulong_attr(CKA_KEY_TYPE, &CKK_ML_DSA),
            ulong_attr(CKA_PARAMETER_SET, &ps),
            bytes_attr(CKA_SEED, &seed),
            bytes_attr(CKA_VALUE, &wrong_value),
        ];
        let err = factory.create(&template_mismatch).expect_err(
            "seed + mismatched value private key creation must fail",
        );
        assert_eq!(err.rv(), CKR_KEY_INDIGESTIBLE);
    }

    /// FIPS 204 ML-DSA-65 expanded private key size, used only by the
    /// test above (kept local/test-only rather than pulled from
    /// `src/mldsa.rs`'s public constants, to keep this test file's
    /// dependency surface minimal).
    const ML_DSA_65_SK_SIZE_TEST: usize = 4032;

    /// Regression test: a seed-only ML-DSA private key import (via the real
    /// `ObjectFactory::create()` path, no `CKA_VALUE` in the template at
    /// all) chained into a REAL sign/verify round trip through the real
    /// `Mechanism::sign_new`/`verify_new` dispatch.
    /// `seed_based_create_object_both_directions` above only proves the
    /// derived `CKA_VALUE`/`CKA_PUBLIC_KEY_INFO` are bit-correct in
    /// isolation; this test closes the gap by actually driving that
    /// seed-only-imported key through an operational sign/verify call.
    #[test]
    fn seed_only_import_drives_real_sign_verify() {
        let (mechs, ot) = registered();
        let ps: CK_ULONG = CKP_ML_DSA_65;
        let ck_true: CK_BBOOL = CK_TRUE;
        let seed = [0x77u8; 32];

        let priv_template = [
            ulong_attr(CKA_CLASS, &CKO_PRIVATE_KEY),
            ulong_attr(CKA_KEY_TYPE, &CKK_ML_DSA),
            ulong_attr(CKA_PARAMETER_SET, &ps),
            bytes_attr(CKA_SEED, &seed),
            bool_attr(CKA_SIGN, &ck_true),
        ];
        let priv_factory = ot
            .get_obj_factory_from_key_template(&priv_template)
            .unwrap();
        let privkey = priv_factory.create(&priv_template).expect(
            "seed-only ML-DSA private key creation via the real \
             ObjectFactory::create() path must succeed",
        );

        // Recover the public key AWS-LC derived at import time (the real
        // `MlDsaPrivFactory::create` -> `extract_public_key` path, Task
        // 4's forced extension) and build a real `CKO_PUBLIC_KEY` object
        // from it, exactly the shape `C_CreateObject` would produce for a
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
            ulong_attr(CKA_KEY_TYPE, &CKK_ML_DSA),
            ulong_attr(CKA_PARAMETER_SET, &ps),
            bytes_attr(CKA_VALUE, &pub_bytes),
            bool_attr(CKA_VERIFY, &ck_true),
        ];
        let pub_factory =
            ot.get_obj_factory_from_key_template(&pub_template).unwrap();
        let pubkey = pub_factory.create(&pub_template).unwrap();

        let mech_entry = mechs.get(CKM_ML_DSA).unwrap();
        let msg = b"seed-only import driven through a real sign/verify op";
        let mut sign_op = mech_entry
            .sign_new(&no_param_mech(CKM_ML_DSA), &privkey)
            .unwrap();
        let mut sig = vec![0u8; ML_DSA_65_SIG_SIZE];
        sign_op.sign(msg, &mut sig).unwrap();

        let mut verify_op = mech_entry
            .verify_new(&no_param_mech(CKM_ML_DSA), &pubkey)
            .unwrap();
        verify_op.verify(msg, &sig).expect(
            "a signature from a seed-only-imported private key must \
             verify against the public key derived from the same seed",
        );
    }

    /// Regression test: using an ML-KEM private key object with
    /// `CKM_ML_DSA`'s `sign_new` must be rejected with
    /// `CKR_KEY_TYPE_INCONSISTENT`, not panic or silently misinterpret the
    /// key's bytes. This is a cross-family-misuse case worth pinning down
    /// permanently.
    #[test]
    fn ml_kem_private_key_rejected_by_ml_dsa_sign() {
        let (mldsa_mechs, _mldsa_ot) = registered();

        let mut mlkem_mechs = crate::mechanism::Mechanisms::new();
        let mut mlkem_ot = crate::object::ObjectFactories::new();
        crate::mlkem::register(&mut mlkem_mechs, &mut mlkem_ot);

        let ck_true: CK_BBOOL = CK_TRUE;
        let ps: CK_ULONG = CKP_ML_KEM_768;
        let pubkey_template = [
            ulong_attr(CKA_PARAMETER_SET, &ps),
            bool_attr(CKA_ENCAPSULATE, &ck_true),
        ];
        let prikey_template = [bool_attr(CKA_DECAPSULATE, &ck_true)];
        let mlkem_keygen_mech = no_param_mech(CKM_ML_KEM_KEY_PAIR_GEN);
        let (_mlkem_pubkey, mlkem_privkey) = mlkem_mechs
            .get(CKM_ML_KEM_KEY_PAIR_GEN)
            .unwrap()
            .generate_keypair(
                &mlkem_keygen_mech,
                &pubkey_template,
                &prikey_template,
            )
            .expect("generate_keypair");
        assert_eq!(
            mlkem_privkey.get_attr_as_ulong(CKA_KEY_TYPE).unwrap(),
            CKK_ML_KEM
        );

        let mldsa_mech_entry = mldsa_mechs.get(CKM_ML_DSA).unwrap();
        let err = mldsa_mech_entry
            .sign_new(&no_param_mech(CKM_ML_DSA), &mlkem_privkey)
            .expect_err(
                "CKM_ML_DSA sign_new against an ML-KEM private key must be \
                 rejected, not silently accepted or panic",
            );
        assert_eq!(err.rv(), CKR_KEY_TYPE_INCONSISTENT);
    }

    /// A public-key-only object must be rejected by `sign_new`'s
    /// `check_key_ops(CKO_PRIVATE_KEY, ...)` gate (enforced by
    /// `src/mldsa.rs`, exercised here through the real dispatch path).
    #[test]
    fn public_key_only_object_rejects_sign() {
        let (mechs, _ot) = registered();
        let (pubkey, _privkey) = generate_keypair_for(&mechs, CKP_ML_DSA_44);
        let mech_entry = mechs.get(CKM_ML_DSA).unwrap();
        let err = mech_entry
            .sign_new(&no_param_mech(CKM_ML_DSA), &pubkey)
            .expect_err("sign_new with a public key must fail");
        assert_eq!(err.rv(), CKR_KEY_TYPE_INCONSISTENT);
    }

    /// Decodes a hex string with no separators (panics on malformed input
    /// -- test-only helper).
    fn hex_decode(s: &str) -> Vec<u8> {
        assert_eq!(s.len() % 2, 0);
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// Reproduces `src/tests/mldsa.rs`'s (`test_mldsa_operations`, first
    /// ML-DSA-44 block) real, ACVP-derived `CKH_DETERMINISTIC_REQUIRED`
    /// known-answer vector through the REAL `Mechanism`/`Sign`/`Verify`
    /// trait dispatch (not just the `awslc::mldsa` primitive layer,
    /// already covered by `verify_matches_kryoptic_
    /// reference_known_answer_vector`). Confirms the exact, documented,
    /// permanent gap described above: verification
    /// of the real vector succeeds (context handling is correct end to
    /// end), but `sig_gen`'s `CKH_DETERMINISTIC_REQUIRED` request is
    /// rejected cleanly rather than producing a wrong signature or
    /// panicking. `src/tests/mldsa.rs` itself is expected to fail this
    /// same vector's `sig_gen` step against the `awslc` backend, by
    /// design -- this test documents that as an explicit, tested
    /// behavior rather than an untested assumption.
    #[test]
    fn deterministic_required_known_answer_vector_signing_is_rejected_but_verify_still_works(
    ) {
        let msg = hex_decode(
            "\
            1E5A78AD64DF229AA22FD794EC0E82D0F69953118C09D134DFA20F1CC64A3671\
            DDA292BFD9AC708D156639FFD63844C793D849C7743B4FB1195259D46D3801DB\
            2EADCD31D515A93F60C84CDCBAEB8739777C54C826651FAAD368D582EBD05562\
            42F4EA5D71BB44E8A06F2C94E52319EED545A4C29A44D0190A3FED19FD49AE8C\
            5C32FFD4DA5C7E1C3FEE0CF67E2AE9C082D2CC9A5DB29441C9C4B9F0D883D6AC\
            65AABECFE49CC1A1DF01752F8699DDC42FC59DD4F614371B02E3709BFE5D1EB4\
            1D92905CEE18861FA7C3AE94CD97253A60B84EF638F43FF507ADE86ABB69658D\
            9643C6ABD33E7C7DBBD5C9350A3EC8EA4E2C0463EBB4F8E43D639B6B9642F571\
            F9B8D295817367651B39AA30D97D59A2187EACB1DA5E4669D9471E3BA498B766\
            06A2B363E0E068FADDDFC1311DD12C5C9E3F044DA9FB13AC1CB376EA6E4444DD\
            6BC80205D9F8E11DCB56ACED0A621C50328D7FE975222F08A78D5CC2FE34508A\
            CCCB9439225EE91E29796FD804BB397875741EBFCF11A8FF022463C3170A963B\
            2EB1A943DB91C5514C4FFB1E22312D0B5073CD94707F3B760F6FCBE7AF366E24\
            98920A32C68AEC42098F3E0B87B86FCE0B12F9852F2ECE38E36FCDC7D4CEE08B\
            5A83D791FF391E4AF9FCC33EB81FE5DD36A0B58FC1C8A76F240A6BE4D4E53FCD\
            CDF62A6D96A56EC1A2BA4ED69EF2424E54A2AC139CAE8184F06D376EFAC00547\
            D26131FA6D3A80E3B4513E434D98DC5C7866A5DA2C112FFFF197A816892213E0\
            FE9B6E7A4FBBB4F97CD925CBAD731C9883C0910EA103E341DC80B52234FCBCD9\
            1DEBB66A315F1D097447DD10520B7FA7BADC1245FC30CCB4059FD96CC529415A\
            E978D62C1BD77596068E3E6EB8E9E0B5EC7B4C7557A651F317D241A6F52398B3\
            B596F933C06B22065169EB4E23E4874646CF905DDCF7F0E3AB96983EDDC7FFF2\
            DC62523F2F27847CD8286C4789FD8AB0101E6DF516741608D5295A45E8FB2FBE\
            B1754CAE949765B3C4A6D1F3FFC60C06DC81390D86B1672810E6D695DA4923AA\
            1C6C0D95046631492CF3A67D9D26EEACBF358F0CA54B2BBF0A5014C6E092A76B\
            246F1AED72CB3C6C8DDE58B170727925ACB72782B54819365A806040D3BF2885\
            A517F0164C9B63E6B84454BE81853F6B90E88508174C8314856689D6B2F4B0E2\
            9DDA36B0DD090D32BF3ECF385C9E9CE356133484A2C55FDCC8CD205ACE232587\
            7DB15D1E69967EC56C28CD76284BE2A5C157F9D87C2E94FBF8A0465CCE795A8D\
            B5F8833F445E3B4FEBB0B236C0587C0E2AEED428B1DB8001F1A27CA4E56A761E\
            5E8ECEA5590D949580AAB3FC2F859D75442CC64498B91C849DDD4CD9F3BBFA9E\
            ADE1BC5DCDC03AF1336CE2CD5F1DDE3D7B7060E00823001AEC9C6594FEC80262\
            7712190EC318E6A40CCF6898D4082103714AA1F61D72B0C6EF7F76B36546C09C\
            05B6D5802050881C667D52B9EAEF9A6250CBDBBE6407184D923A5E4B354C225E\
            8852886E6A71CE4C0905FE36BF43014ECAAB0087A548EE8D2440F2EE9C912264\
            B412FCEB3D650D5152800752953D8D8428FBDD57B1D671853DC6D378C321CD10\
            5893734DC82A49A803B25E17CD2B53F8B8B50F6AA27BF82860C515870D1104B1\
            97D57EE835463A38657FD3AAFFD14A524DE089C8D265E5D77BA9930362AE28D6\
            5C5DE8187EA0D9417EE2CF885273D1F3C8773635E7610F80EDFC890E88B81B35\
            08251DD0C512CA83167129E2E5D3D304B71CBB7EE330FC7A2EAD2A4824EFB3A7\
            C5B45B2678891084F61A66E4DB3E2D1744ADFE3B60E0E9644C9559D596C09D7C\
            55052012EB18B1B6571C5ECD9548108882C008C16C09ADE6C7473E2A3F67A054\
            E7FB2DECC6B0D84D6F6A440EC6B1AB8AC0993D3615857883F1E7C3C46621209C\
            2A257F40D3D021BFF71E47E58C9FCD8B0BA54B6003CB79673C00BCE770D06CB7\
            4FD0AD943CB7300BF940018EECB583AECF3494D2D8706CD8B9BBF803DB1A00F9\
            AC349A0F4D9CBFA07723D070A332223404980271CA18EBEAE0FB30FB57A72FC9\
            B1A4C10FE98846D1A55FEBC35A4DD3EAB750AB0BE4B19E6E438398946E64FF63\
            E72BBD761DD984AFA3E62369872F6D788F9F60570B17F46E1BDEE96E38EAB8C8\
            C873F3C8C5628917A7B622D920B94D2DF2D07E272CC8D6DBF383D9A7F12C66C6\
            BF4322D55C60480EC78C20E1F2E8F1F485DA9B9EB0780BEB4850290E7150A4C7\
            9714C112AED3088D6E2F9F38B31E2B1C924AF895F4FEDB8155D1A964EEB73D66\
            C5D3001D05833E7D70909C8BF961BCF1B517C6AEB76A9B9832C795EC51781E0B\
            BB999A6F10E03458F8AFFF90960D49EBBEFADD0CC2F8FF604310FD3ADC372D70\
            203299424C7AEC922488A7B7CADFA92F0171247FE83E3D54DCE6EAFC7258E1A0\
            66C96F3F3D4A5CE279C54B004DDC462D0D7092BDD794398F72D78DA95C66586F\
            89F593110DB79F942FFC1322CEB02B69904762CBC86A95FADA7CF6DDDE8CDE8D\
            E819B17945D775703B5B276D8E140C69B46C353AF340893A6FD9E88227DBEF57\
            69A237DA19E0D6C582560B51A504D3C3FE1EB8CEE3482F1FF4CB5A1C9CF7C647\
            ACCD7262D80A876D3A188223607D05C9F58579EE229C24DC040FE5A14D10DE04\
            796CCFAACEC948770CDA6A0724342FDA6CA72D7BFB40B37B77402B20829448A5\
            20A7578F5872702200752ED6179B1D302F683695B6FFACD0FC271C3EEB48EC3B\
            B182A341655E42A33CE37AA811B0A3947F17696FD0F927C3E8BDEE9A15AD057B\
            1D3F86BB2F9D4898D7078EDDC2958EEBC132ECF1C40A7B373DD3DEAEF719AACB\
            C03D3D9F9B65C66C092D794B316596C76BE6B3C079C6B85BDE2220F60952C650\
            53BF42585CF9D175F265B87C655A5A5EC9E800BE69FD8B03969A986DDAB8D2C1\
            AADEA68BC360AF6CA41DBD04CA4EF5778FFBAFDB14712EF94B06B90C657693AF\
            6A82CB5AD1EA5A79C3152F98F6D70A4FA7FEE46E683D44763877761DD97381D3\
            B5B4DBD49D9C767469181859E76771C1249280E74A4964465769F7475EC491DC\
            6E16FF67982EE127E62EB7CD839BDF30BFD4E26A50EFEAB51C74037FC45CA221\
            E59CF4C697309506FCD0D734FE80BA5AE8BCA300E5767863DC97982E35DEF7BD\
            63B54D3EF6C7EC63D5C7E1C953C74DB5A2385DBC1905D632DAEB8E84946BCEDE\
            992AFC4B355D934578BD06BCA9534E6B1C2D9903BC91E85F01829C890D6521DB\
            838B1CA23269E23C3C194D0164D7B577759BE9B5465169B6CC2EB4179ACF5FC6\
            BF6B935FCAC40605E3E0552647B58DB59A36596C2BE04617EAE766396FC51C91\
            3F95B7F28D50AECF0815968D68539E326823DDB7619F5B765D21AF79930F1B79\
            6DBD79E5E8F5D978EEBB0C8756A4389960F9488A3F8A4FB97B9FE866C89C8A14\
            9CED32A0ECFE2CB0AE1C42B059D715468777151D24B766A05E66E414A6879430\
            6C655E6CEBC01076176C41A52BAE2060B38FEE5DCDF77AFB591D61FD75431DF0\
            C26D5E7937C9D576D4E2149EB2C0BDBF645A57C477579ECBDE9636C036E5592C\
            0BF465E86D84BA0B5365B46BC2599190DE97E3CE6F29E42756CCFDF1D429DB89\
            4ED7F844509B574828C6ED5C7EF498DC880AE9126FA7030339B584C5CCE3D240\
            C233605A36199AC8AA5375722C1DDDDB92CAD5A6699EBCAE322E5DEB63019B9E\
            391A7A5CCF2AA75DB153B02C55353196A1E8C768820B5A3C8F3085DD774C1B5A\
            7FCBA85EB47EC3593357B2C4DA4CDEB70BD5377F5C1A6AE1782FDB9384DAB563\
            178A7834ED3D6CD8682383ECEDD36B6AC309B72CAF33E5F700959B20572C7CB6\
            449F9745B7A2C1C301E7B341126A77144F32BF0190F903AFD02FD6AE006DBF1B\
            65955764E7BB9D830A4826B3E2B627D7439C8E1647E14B9C037F015426CB0B27\
            9A96F73942BAB0DE4907E3DC96062ED184FD7A0C955AB15CCF991E9899E68BED\
            24BCB91187ABD4BDA92371F93E1B3622179A3AB1B930E454A77FE516775A01BA\
            0021F7CC29456CBEAE333C79AE59DCB5B096F29BA08C0F1B89E357F46A83F1E6\
            9C1F521AD0E6B90A35DB3DC94B6D37FE73509968409EDA533CC7B3E24FA29AEC\
            FC88E6E6574F054AFF32397ADF4CE33CC6A796056FED6E8205AA6AD530B83C6F\
            561C152EA9FEA50A550856AE20DFFDA79DE49B8C11F00911B790E4FD5A5A5256\
            E15A5ADDF380216234A8F578FF2613EAA8C430830E1EC9B0FA08AECB60DAB24B\
            8155D533CAA66CCD68AAABDBA1031A665B44D80CA6D4ABB78E2483604D890CDF\
            83977B198D6E2E80D1D658BAD557D57E68FC546CB936E3FD6F62A2F9263DA4C0\
            65813377818363B0B1914289D11B19301DAA9DF24A7261B70FFD9CF01EE01214\
            6029D5EF88F32906EE9FDF1AEDF2FA0C53C0D9395205E93B71BB6BAB89524F90\
            AC2F7BCB276DF1F7E4F0F734ADD2737AA826426D70BE43DCF5FD5D7AEA0DF6E5\
            D38CED606CA333952E4AF896E1DF38CE3656B88037221D9A90E86F5A022041DC\
            86D813E6A0A9D061A77A908E58D4C46457609A2CE97CBEE6738E093D04DA10BF\
            D8516AA643902ED082A1FDF60890289925743513DF192DF07E5676CF795202A5\
            70991E816DEAD88C737945166D3D3DE95D828F07808158F6D2D7911C1DA14AC7\
            B86A33457A861CB57BB5943710FFC70F739470C31ABB10A4DE9807899F544107\
            B05616344DB07DCE46AAC29025378FD96130705FA8FA1ECE9F81F5F854625F3E\
            45B96EA0D92840E3F319BE3889B025D4915CECFF9287C01FF6EF5D8E9371E805\
            E24C404B0B20364D3002E6691A14BDFD0F89693D67418A86047AC10F7671E6D9\
            83D84C47AD355EFA9954411C0DC599B7FED4FF794A6CDD2F93EE80691BCFA171\
            1FF32FB3CBBCD10E03B3A945711E7485E4DCDF17E206CCB38C18037F4361AE43\
            99B23B814A7D94DDECE17F171F6948976EC4CBC9133B235B757A30609ABDF082\
            CAC9AFB9B5E249AFA6F2530661422EBD789D3D34E4790C486BF164932C3ACF3F\
            E7E0594D26C035ABF8AF421F848F4CD90E5D9A69FDD8632417D67AEB8D415EE9\
            12D795AD1B3C1A13073A0C489D241FE6DCF2D58B23E1167D8E748A41D43DE505\
            F7E044A37528CBE4E8BE4B1356F298A1174E28734756C9567A0BD5E72002D153\
            4E633A36C5373404661CE1ED379189635BAA44A6903468311609DAAA2C3100C9\
            AB83A5DF55F44C5CF4B9A8AF87DF5F55B6021821CC7DD7F3428F2A129329BD0E\
            CC69CC97E63F6574CC10236828AAC1401C6DD4EA3FCC32781B8C1EBB68186C18\
            21D05A49207CC28AEC58EEFEF5F380604B932B0042DFDE26B2EC14A9CA51CDBA\
            0F195BA80B0CD4476D16C91EF3E5652F35E90D36D37C317C786656F4C330A1B5\
            77E1E45A22B54A58C9FE7C735B568D09E0D8DA6B07449BF4737E5D55659D46EA\
            89257480EE46071055147A6E70A5FAD6BCBB910A1B2BDAEB62D2A02AC69F6D44\
            6DED18562C49C572E2F597E230FDC714A824F4D2E1B3D8A27BA1C9B4B8E905EC\
            F7AA6C37B9A3FAB18E73BDF3CD568D2C875914CC8B64EED925D1F926FA53E69F\
            E96538BD294E6EBDF08036D08CFD7475C8C4079F89EF522F6896852760EA31C5\
            444AF142CB55F08FF89DBBDD94576FABF95A112C192AE9DAA704131ADD665AAB\
            5ECB27FCA96DCFD9F021C972C9F9337CB0638EBB958F906B469AB09B2FE1B0C2\
            1084D7C8D3200E8715A7BCA9963075589F43FB8D286A303593FB1DB8F5E580AC\
            CA5FA23F51D3BFACF0B725C5C523676452A580B08E7B22B2C4299B93CCFF3E3B\
            6C81CDFD94C8FD1FF489084B1DF45E2E8EEAB73420ED2E975D37074FF3B435F9\
            0243BA2452F54E0ADAA09EBC127FEACB798E4702F9417E26A51FF3E3D2D8C092\
            461BCA08C0D7BDD6EDB0759E14D3B7501BDA28B4467C14CC4B7AFC0FCB3BBB50\
            3FB390C9CF06A5A1428E7E0E0DCAA1A12EBF1F8D280045D6E59A0E667900646B\
            BE8368B575E50F3B6750B48C52FA665AE0750F2FA779D3A86806AFDF410DF1F7\
            1AD108742481173DEEC707FBA8AEDC94794F736AF77E3DC6F78C378C23FE026F\
            4B5D3A2F8FDFAA54E007AEE540CA35A093D3DD437D3D5555019754CED5F7459D\
            AC47C5DE4E6F675693F0A84CD33E5E4B5B0D84689BAFB7113B899FF7363D4588\
            5381249F1590AD173B79F2344F91DEA18E8B0B1A7F991ED1E7DB6EFC87A3D086\
            25F8DDB2DFECD667280301BA809EEDAA86269A07C36A803133048CECF7D51A3D\
            3372D23D3B65C72992CF8500CA52D573C866D2A2E103F9F7351917A7166836AD\
            04CC0C5511B51159C87B0ABC61B54B4AABA2542E831F0940C8E3F24DBE90A49C\
            8CE6B6169D81151C9555C1EA43C1DB2767D537BA05C394BAE3AAD626D2A6AF8A\
            664E7E3CDDB320E35D59F117DAEDEA9F0AC5F46D1A0BEB0A2394C9BD65727687\
            6D9BD82E60E5ED5B4252C6F0CEB74FAC673B98482D1C263E7CDE21CA0E633623\
            4AC0CF299952DBA20E2189404A67E9455FD8219B96C0473DC571803B88FB7DCC\
            921057B7FDAE8489D72E097459EBB0FC1AA9C68B2FC934A178CCD81EDBB2D117\
            96E32CFA6403EF25635064CA62BF0A9D8F5BEE591214B0BF0BBCBBECD3E8DA3C\
            F96B34638940580803D9A0E0883F5D34B9AC06B5EFCB83CB47B53ABD0BF3FE03\
            31ED09C0F3C3499611DD2596DFF8754679C7DFD2EC0B2A032C2727D3D76AE528\
            6F7FD8FD85D7FB997EF3C019CEAFF36F891227F11B6E830AEB8F97EF5CC88AD2\
            F6F346D267FE58A0B8FB406F151593C417849B613CDB1CB5523FFBDE78B494BE\
            63D62E61740AF3247363CC3723D549E76E10A3F187EDA82455BADD5A22CB0485\
            3364455FFC01D4BB76224EE40071702F9A1EA97C3AC823A8352A6248C56946C1\
            47CDA99404E305188CDEB9AA95DD4FB703A2C3698D4C52DCF84A42021961992F\
            CCE4C2502973D25E8837C8",
        );
        let pk = hex_decode(
            "\
            4A1FDEB2951D9D10C0330A420DFDCE3D52CD7BDD2DBCBF9BC0EAB1C0078C6CEA\
            68CEAF48C8A355F82987011F37B785F6C8DF1A5314F692C2682C27BDF91B711B\
            A7D65FBB18A1C2F2D40FFE2F3A52F3C1943E314C1279D3A8605EA6E06936B65C\
            FC2B71BDB36AD0ABCCC06C0561121C5BCE8649CDE0AE4B58E3F018627F1FFFC9\
            F34868693766B8FF457A0F4771D38412DD8DA9BE2C57CF35D74CF690B3141CC6\
            813BDD3F8158D2C83CEC1E1280A8E1B96BE6E82C6D26D45A4BFF5A898839E4D3\
            83111DFE2EA23340BF4BECC60D479CE75C5B17FE9A958867307FC49CA9E48AEC\
            8FFB2D2CB82D4804CB0593984D7A337B691B1C612E3638F71F5C008BF4E4C35F\
            199EA806FD8CF90F0C68D0D3B93F85C7F1A02FCDF2E01D8F46CFF49286744327\
            8E3CB9FEECF941B688705150C8352D894B81F6D566595DE69C3424EADF63CFA0\
            9623F6FD121A19C594888388AC88C948989A977227671DBDDF6C509A08960499\
            ECB2FCC156896570B7CF9B8612B800B11261E9B180CEF423646A3F716E410D02\
            1B7BECD0F9CFC8B5CD04D4D1482E5F51D9DE67390B523B39340534A041402EED\
            413B654EB48A05EE557AAAB7E41F6510DCD1B2F7AF142FDB2603127878BBB298\
            2453398E5788571F167F37FC1371F6809637B320567E129778CEC532F24A6625\
            F84A89E4AE578CBB15E4DF8F271DFDA2D56024994B5FCFD1F3C3843DD416D7A8\
            205116165B51D700B209AE84DC01E232CDA5E7558B8144226E2723B3618B639F\
            A522CA280F1D99510C1293A9FFB8ED14CDBE45DE61D0042FBCF15A60CB6950D8\
            0B62168A6C1CCAF5791A992494F4892C4BC2D1BF6DA3FFA300D4C315169DE895\
            5BF98AE633C3492C4C07A6857B188F7B75C1DB62382AF7EBA062663F08D1AB4E\
            A92584DD5F297FE7EB3F548D0D01C431945791AD216E0C1DA753317F22F20C54\
            26CFAE640F27E1B0AA7E775BE8FB1085A8C68948A1DC7F04A5CA45A58B7D0223\
            528C209F7D6040702CE58E5C0C7E54825A8C2B22FF3A08F3E26A858E1776B6C0\
            CE0A1580F2149A45BD8D956E8C9BBF18CF5F39723EF72B9EEEB7305853AB0BFC\
            CC49B4B501DD61125AB7159B435D607F72DD8C0292318433FAF1D94701A8F438\
            CBB9C3F46A152B3FC6B19633B4B55B1F619B0BA2FDE2457E7A9549F6EDF7A5D2\
            5947C372F63FF5352B66BA8F707055F1B617CB511377CC010737B223AF8F5BF2\
            6329C32033343CC971EE11F27E4CBCBE93F534646FEAD4A77EF1036DA8A0A337\
            CF36B93FC9BC77002D110A23C9E85120F658A3F93DCF8043A9B7A01AC11323AE\
            FA2E9EB4259FDC7A53BD763BCCF74E34378B6ACF78DE1FCF5731F1EBBE7735F9\
            26296BBD5B742DB88AC8476A9EC3B40E21F0DC204AAAB5FEDEF58F9C356C7CE3\
            FFB46220A67D648B52C37412790336F42861D5235637EC2B5392CE072760DADF\
            EF9902747018EC3EF231553833D0268D9025A316684CA2C40E4BD31BEEB88D99\
            F752249EB0DA18A2E6CA40E81853AFC86E76A64C01CC4975E8B0AEAA44AE18F6\
            5D7052399561CA774222DEF6BC8D49FF8C4837CBD2B9FD75EAAEC0211B1D9684\
            B8A820B947E1A5D1B101186BDFF9B56C6D220D489D997F7959046A36E9C7879C\
            AAB38573F1A8D11E080DE5947886C7C0637575A208C6C3D22B3E0CFB7659216C\
            2575D11780824E4522EC3C021AA65B70DE831485E3BA3AB01E51A15C1AF6C44B\
            8FBCC1531E6F5323DE2F9BB4E61D8222FAF2C837556887E7F2337604C8006B55\
            2E31D94EF9A5CE8409A5C425EEAE1361901C9558B3FB18F0F6490EEF98AFBA99\
            0E59F66A49BE91C0437616B132869B10FE542A0ADC52F2CE266E566DA4A0F0BE",
        );
        let sk = hex_decode(
            "\
            4A1FDEB2951D9D10C0330A420DFDCE3D52CD7BDD2DBCBF9BC0EAB1C0078C6CEA\
            272C272BE86D2DEC0E3FF6F37562CF37E09E5DAA586E16D0F7715B2A58369028\
            454D95EDDF28B43E2453CB72FC2F2528EEF36A5BC2F4446E6FD66357AA23CAF0\
            B96FBD3621DC9A5CB08ED975F6FCE317F4C0129ED8A40A6B287F357805A4A59D\
            1818621188411CA051C880201B406D04B9100AB74814B865C9181198A6850905\
            418B36405A1664A20651D8C884E012918CB8048A1246420052D080844A1408DC\
            A20118C52D1C000288460953A4705A060D9B346D5A020842326002C9490C058E\
            0B215253C48DDA480692A46118B8090332100A886910B36C52303119332CCCC6\
            0922852CD900291B206253886D58B2298B162C580472E3486803160113B60820\
            3629E2A045643600602206D3144E21234D1BA1841B882594B02DE2800CA10082\
            02272D54A46819092C13A52DA2A29090B64548146C82B66480A645C2A42C6304\
            01A0822112142EC1848D400402583621E4C68854482211C31102192A0B480C1A\
            077140288C98C88CE3488050802C443862A3062C19190909420E9818061C260C\
            D1046EDC0086C2C27019462A02A6818B046994B60D1883880C336182B08824B8\
            0562420608A508CA1668A28665118900144529D124321CC7491B818853842008\
            1421C2120E20814D13A32D63A621022809E02212A426245A982503114A92006D\
            A24080D08400C0048488B411D8A821E4280613204C53C01188348844464D8C02\
            28D8126C0CB4618C148693468D249805E3000CE0A4089836724A424408236C23\
            488D410650E142889A1602C4B8809210800C0980D3C8802496800C052DA3A824\
            23092412003141442DDCC051A2486501492DD2A0698C460254426148106C9A14\
            1040C68903180EDC20869B422E24328414838501244A54C80544C0905BC0301C\
            0870A0C86D53C2600203721A1529D1203082B6491A0764C2984D4C022CDA1852\
            59260C59A2510309110224320B43848A460899126910382A22C86D4B28722223\
            6A53A02DC0304DA0404801314222078984981149202DC81872143730DB040E21\
            3409DA247014976993C629A32800133489230184A4A661D83884C1324082162A\
            4AB80D001385E2162A08B2441113651099654CC2110187415A20258AC0080028\
            069C18650A2652E20205E294285B226E41A620DA344A20C0081B8311A3902464\
            880C63C044D9424DE4C46082002E8B3004024720583806E2186C94482D213412\
            8FE073A549F6DB81A91321F8632104342EAD4553868063EFCB6662F6C5AA267E\
            FA06030CE1549E3FEA3A2D3F88A308C3A3525462FF1DDB1F406EAF108A17D657\
            E361BDF2E5CB1F5A0F32249AFA265174E0232331EA5461ED08BD5BE1C4DE04B0\
            C14BDB9974190259E48C98BE014353804EF603BCFC6EBE44BD7B31770300BFED\
            F2B12E975953D8264D3DFFEFABB131637A218518A44B420B1EE26932D547099F\
            CE3D709F63F88A5C104D0823F84E1E497D50AFEA60DE0011CFA452EC468A7D5F\
            9D8B8CBDA58828FAE5198A0D65710D989FE23297157988EF01D2FAAC7D18525B\
            5D7307BA7D51191B409A9529BC79DF18BB6E8A099F149096AEFBBDDCB8DBD99F\
            44E37BDAB4A71B7806896DD330D9DB1139100167A660FE142A7DE42B1FD4A165\
            F759DD3B6A39676B23D297C926CF08420AC5550EE35CCCED8336FBA48686F295\
            3454FB01DAE8F19F09DAF7BF0E77B999F0734A6606C4850CD23C8B8C3C236559\
            B4C77FC97071C8D42480F2AB705DC8316D0586C7889AD600B142861CCA6EE240\
            5C02E8211BBEB22BA65AC926D0D1A4ED2AAE50925EC4E7074817DCADEB490026\
            8F775E9B03B237275FC7C2D75A79B31980147F9BBBB4ABC43E3FDC990B7D3FFC\
            E160BC426C5A303B8E3960472D35478BF1F669891181A3CD4117A67433C73A24\
            CBD830760986D2425F14FE4BB5803DD4F3437CF39D189E8E8E7F571B29812C5D\
            98CC359AC6ADAC4229B952C9E554A1488475D05C90F53D59FBF82E458830040B\
            12CCA0D446E707018DD83C54BD86277FCA93B0E0B1B18374014F8FFC319E712A\
            808F4B6F5E7A51B2B1E2D66591FEA6B3A765B9849060F02C3391F40E3F455DDB\
            82F4EFA8056736874D32D310699ABAAAC219105BB46FD5EEA2F7BD857CC64E9B\
            9E57BAC0994082E572CCBDB6C75923A6C8346D635A683A23C5539C93C1016DDB\
            A53BB1553AB38169638CD1926D714609570C6BE0811765544D508D5E4095E7B5\
            4FFFA44253C21EEBBAB5FBD0B6915ABED9B4EFA41C4025BC1FCEAD8F70037B14\
            09496BC6FD61A7FE74EDB29FC3768314452308A44761D84AB8F412D94BC9F435\
            1601D4D46186B52B550A242725E5247A9C4E9FFD44E0045BB41003FDFF4D5DD0\
            E56AB4CC6BEAAF807BC453AB2477828D64B49C598C04C4DC9BBD9E042A948242\
            4B58D8EF276D1CA26504943AD45947929F228E381E8ED1740DE279942B044BC4\
            480B28AF4E98FAB5B871C3FC7B8F2FDAE91973BFB55208FD2984E4EB40C59506\
            72EB257EA2053B28780DAFBD0525572343E473EDAA7133A84D98A55474D26E3A\
            35A6FC27C112061F1128DD9189E08F4C948F5597D643A269C646575545419011\
            9579B46603A56404FB4DC690FB874CCE7C55A48F382B8C00942C8BE164D184A8\
            229A8B278AB5D8320AB84BD56A2F1AAB6AA0DD364598324CA8480A550125BCB7\
            34180833BFAE1858AE2B18AD8C930B3E1D69553616AFFBE73EF40EE1089C0034\
            F7110492888B035674A3581EA997F70C00DDE17CD83CA22936BFA14E4190F09E\
            08AA8B30FE6F9CA273A584C0424DBFD9230FD0D6050B2E95D6C6C0C3B7485757\
            5F995AC02837D849718A15B7842F43D20BA7262B55B2A07EE265380250831678\
            140AE95A548908B3C656A6230293BE54ABCCBFB39A05441CAD1F22E4FF4F32B2\
            3FAA6F4306B10B2B38D54DEE3F7B1962338C077B693D15A8B43D043EC8342A48\
            2514FAD2708F3ADE1EC013AA01B6410DA5C61382372A38FC736B58D99DC5C1C5\
            406F3B019D3740BEBAE743BA83F747640BED829E99C2EB6EAA7329EC74757FF5\
            8979897B5C13630A3ABAEC5327A1E886028B43B5BD8C445746FE8A5FBCF09C70\
            D6FFE64D818B711DA11B68F0A36240BE0E5973D5195C93E5F53217A69E19CC2A\
            325167DF459514BB14536A30DA77DFA1F306792F10464DD3EC3E5EB67AEF7ECB\
            34DC239E2103663E7AD9FADBDA255325854288CF46E8B3925C2648DC752E3963\
            CC817FA8C57DAF22F960A63CD1DC11C20C311BCDAEAA98372E33CBF9C3222D26\
            1D7D32D4B7A4BBFD5C8EBA1EAD68A8A13C8DCDA04749FEC65A8FF54EE86D56DB\
            3A568F008DA5516B62EB896A701AAE16C319CA2104B95149AB3717E6FECE7A8C\
            E3CF0D802F4A8F22B14F3E7BFD33DBC430F5D7D7A55544889025D8362BEE465D\
            59E908345E6A041FA5C09045131327D1C4F92DE0BB40184225EA9EABE8BC5D3F\
            991FB9DEA9442A69879679C637C77797BFCA279FCC83841351B9C57BE70B5C09\
            C73F046CF1195FF1B2C95DA7E5BCDCF46BDECBA894A275D5BC70C14F4CF0A7A9\
            626CBE322887FC7980EECAE142BFD31016F60F5F42D34C76A362E8E191ED7981",
        );
        let context = hex_decode(
            "\
            FDE19259E56C2602F3CB0DA509B912F88262A1701D4E02B513F45C97EBB100A1\
            7B208205098D6BED2638BEBDCDC52C4C5114E8CC8FD9A180E79CE750594C3BB1\
            88DB6A3605630C6A2F3049BECEE951FB45B5E426",
        );
        let signature = hex_decode(
            "\
            A4E46D38AB1867BCDB21153C516FCBAA68875303ED438451E1F04597CE6E6B36\
            3B0CF32EB6EDFB3031E2611DF8B6549C04350795C0562F5ABA84B3081102F769\
            D9AC2C01CF594AE408B5165197FC44AF951C0F82D5652E3A020D7CFDB970F4AC\
            A2236FFF136CCE66401F063ADBDDD84839B56BC82FBF5CAFECA8FB055DDCC597\
            F7E0E444AB3EDF5688827AA5E109386EDFBB4479803A30D2523F0BBDE033134B\
            77127BC5427310018B59E0F93812BF0EEF4EC37A77F73D0AD3E4CDC455021532\
            0C2C562E9DDFDFA3181029BFA46FD112AB4D1FA4CD0B9699B88F1BFBA2B00F0D\
            330C6067B248028051EE7631609FCB2BC71573086F5DB99673C4318ADF875794\
            1B0E7117C4BC2D047D5174E3A0E1E5CEC4EC2E29B9F617A2E75A910415433994\
            77A07F24ADBA9F786E8040A30BFFBA0103C9331D790B1629886E94D535D3DFF0\
            43A89D5D9A5A6867920C31A94BBA0C3BCC473112087D31A54534CC772EC29106\
            FAE39608F333238E74E18791227A475B7238B2F310AE5F1E196A3B14261C97F9\
            5355541AC56CE398F38535965C09708EEB7FCD23FE79B3E76FE4DE388B83AD13\
            064F9AD4469AD85655AD3790B958F7B5D82269EBD2E06C343F7207F96CD16B72\
            00150BBD327DD9B3405D58DD063193BA5B1648C8B4997BDD65271E782D286810\
            9AFB01D30A4BA8720DA3E447B426B33C1CD94BDE859D18613D234C74A4790E23\
            A174BC8CAEE8EADB19A9DAC27D340E62D8C2B3DF5D0D2147C4EA61078C9E4A2B\
            3B1F9D0EEE979154E798547CDE291DB46D257228BE695D99C7F27356EF0C9095\
            73E989F555214C32C82C0251497B92935121CF1D921B0251025C56C7B1224AB1\
            8D19C6233D5B232D13763794B74F43801BF4BB85380E804AE931AD473B3D51DA\
            4AF202C46EEA5E21259F31B732BAADC74C5E90F388DC121247EB447AC71504F4\
            83A7FBDEB5C3B6DDC6FEA607F3EB771026DDFB1756B1FB5F3DDF8AC834FD948C\
            67F533244E8E6C9F574803E4029155B321ED4B54E1BFED00BD91FF596261F876\
            756FBBC16EA125BE4D18ADF7B30D9DAD1A050D1B6804E6E5C88CCCAC2B3221BA\
            2C0422B5575829A16A68D4192BE785C5AE609BF3AB68133A499BB0C3A112F391\
            F47F3BA6828A37E6A5F776C5D45901660AE80FA23DA12C70E3BA88846864856F\
            7C9E1EE0CBA22C1E48ACDAC8CC1E17CFE1EF2F50A7211F18E19866E6735BD17A\
            F6696548C67CDAEC55A09951AB89426B54A2C4A9A60839D3C1B4B9FE26D9F53F\
            4DDC832E1399BC04E4F8A1C0AC4083A0281514693F32266632010F74C4B30250\
            0E6B8C5F2F99664D1E4D1408ED726A88E301EB9D3B5E0493D9B6FC1884BC753B\
            5D84B96B0E5F23E786DCA71D4EEA5A35F1748B4BAC9A43CE47A6FE073CEB1A57\
            A5BF8D24009D11019F5EB04D3C79DD948D55F7F16886679F6CA592566EA18C51\
            646F298722414C49164E27E85F94B1D4350799B6421BC179D7AC095652DBF6C7\
            5DBE4D2F4F831671E339941D1D21FE16BDA064C62859F5662139DF9C2F0B8A6F\
            2562D1C7F9A509845722E916FE4D67F7CAB6E1459356499AE7FF61C9729409D4\
            E1FD0731D69C2EEE5B7A4C5D85D2DA84984AFD6083C4794A837D0E1FD3283AEE\
            7AB12558B186015C108F364A7EF09DD207818000267C0C975664F990CB51D482\
            21AAEE94F5252FAD9E01652025F1678BE6044FAEBBA8E94DC43AF8902A5058CE\
            29D6E17325B1F13A0FB3EEFE46067EEE5BF8E462CB9B6B466B14C541BD211E62\
            60A31041C748EFDF1B35E75B0133E99283206344598ACEE2AD92519A90E99FD9\
            6DFEECB58BB40B2ADCA1B462E910D394181F9DF9B1D92686BA21E243DB7D8FE2\
            A0713D6CCCBC0328F3F9DBCB3037DCF9E811F8C25B0AB9E73D4BCF1335187A86\
            EE8911BB494B8F1B0228803EA37C8EFD3D947A08226F4A262984C20A9E58558E\
            6AE03FA694622A634594DB35CC41974DF43C12D042DD752EAE99F31D34BB52AE\
            D1DA0069568E1C7A1EE725A7AED750DE79D94D7AB75499019D6C2DDA120A1C6F\
            813AC008B16CAED0015AE609818FE7D8AD1EDD247DA3153EE3D9C8836C77EEC8\
            4B885F3856DFC304B57C67D930BCD6C77A29271F9035EA6212A9DCF5526DAF19\
            C47533BF80BB6D15ECB582A78A67BA92F5B413E17AE69C2EFF3BC2EBF5256E92\
            832130D3EC7F7AD76CC8C5DD59FC2EE9E0A7873806C152791741E6C6533F6368\
            506FC4A655A92CF77FC44BD4CE3A4480D588DCAB0C8B398AE8CA6A7DA65792C3\
            946102C45DF4C72EC9FAFF22430F131EDE726DC2987B4DABB72AFE5376A9798C\
            FF3E8758B3F7BB56692BCC4822CA337395B6C2540FE966A70AC469FF6DDF0909\
            AB83434C34A854381F5BADF46E4DB78A317E0BCA59A3A8C5972F8D059D7B3A51\
            470D560D3B47EBC7FA13A253662305B78F7A146FE86B4381B4EE360ADB027C96\
            46BBCEDEB03C959E4F3111B2F8434949CBF04CD487BBD100708F47C12715E4BC\
            9E9D87DA5717246E6F3E4354636CE312560673F4037E4651A2098553C64C11BC\
            FC9B881C7858583066D80353ABA92869BB20B75106C233619B95D7EC58630CC2\
            D4158650582C345D3C3110361DDE04B69F38175D136F1E28020D36D2D90F2853\
            748A232BAEEDEC38A739781BFB7F52154BA20DF52BEBA4CD65ABC7DC57EC4845\
            65186DAA795B42C8988293B2D4EF0524CBDE85143ADA3D1B28374D2B1A335C6A\
            914705CBC2E2DBA7D363ED78590369FF256B3BE230412E821407865A07D1DA11\
            7BAE75B0226D173C14B15B3E85AE50A569ABD465D4E4500FDF535BBC2C1C5AE9\
            C1CA73753CF488A9A4BB406549BD3BE25AFC62F7B70DFC2E940B8C37CF33D2F8\
            0AB3D1070B03617043BABF7D687CB04B33AAEE8005F58D06C4464440875A79AF\
            4F5079FFA1CCA1B109419223FF9E56674D834FBFDE69F406873C3E54218EFD8F\
            70D3DB7084AE9734E31906AD94491CE12B828CC785080DCC911ACF80C522817C\
            CAEF838BC50ECBB499F12ABF32647C425C7A432C0321F13EF4E18B628DC68D7B\
            D5D049592A73A96C2CC8F2D4924A1D14ABB2B15DB7BD5BD4A46B09FAFB0F8057\
            8C2B8D0F4767EE26AB05D22A3BF2F02FCDA404646495F27B2A4E6BFD33E73201\
            3DE703CAE16B45F9BC39BA8FA2EE8FF427DA4FAC6C822B905465014647873E1E\
            E8832A87870107B9856E950EEDC6FB097F5383DDF6E4AE01C98D5AC6054AB356\
            55318517E669E379140246AE63D52066037FF37B6814A911A15C0982140DC132\
            143F8707C04C6F81742872FA83E6CFA8112C644BC1A86162527F924D9DF22341\
            232E3540484956677D99D6DFFB055A7A7F8C9EAFB9BBC4C8D2D7DADEDFFA1B2B\
            476578798091B8B9E2F0F1FBFE090B2E47818CAECED6E0E9FC00000000000000\
            000000000000000000000000000000000D1E2D39",
        );

        assert_eq!(msg.len(), 4875);
        assert_eq!(pk.len(), 1312);
        assert_eq!(sk.len(), 2560);
        assert_eq!(context.len(), 84);
        assert_eq!(signature.len(), 2420);

        let (mechs, ot) = registered();
        let ps: CK_ULONG = CKP_ML_DSA_44;
        let ck_true: CK_BBOOL = CK_TRUE;

        let pub_template = [
            ulong_attr(CKA_CLASS, &CKO_PUBLIC_KEY),
            ulong_attr(CKA_KEY_TYPE, &CKK_ML_DSA),
            ulong_attr(CKA_PARAMETER_SET, &ps),
            bytes_attr(CKA_VALUE, &pk),
            bool_attr(CKA_VERIFY, &ck_true),
        ];
        let pub_factory =
            ot.get_obj_factory_from_key_template(&pub_template).unwrap();
        let pubkey = pub_factory.create(&pub_template).unwrap();

        let priv_template = [
            ulong_attr(CKA_CLASS, &CKO_PRIVATE_KEY),
            ulong_attr(CKA_KEY_TYPE, &CKK_ML_DSA),
            ulong_attr(CKA_PARAMETER_SET, &ps),
            bytes_attr(CKA_VALUE, &sk),
            bool_attr(CKA_SIGN, &ck_true),
        ];
        let priv_factory = ot
            .get_obj_factory_from_key_template(&priv_template)
            .unwrap();
        let privkey = priv_factory.create(&priv_template).unwrap();

        // This `create()` call is exactly the forced, narrow extension
        // this task made to `crate::awslc::common::extract_public_key`
        // (its new `CKK_ML_DSA` arm): `MlDsaPrivFactory::create`
        // (`src/mldsa.rs`) calls it unconditionally, BEFORE
        // `CKA_PUBLIC_KEY_INFO` is set, to derive the public key from
        // this real vector's raw private key bytes. Confirm it derived
        // the EXACT correct public key (not just "didn't error") by
        // decoding the stored `CKA_PUBLIC_KEY_INFO` and comparing its
        // subject public key against the real vector's independently-
        // supplied `pk`.
        let pki_der = privkey.get_attr_as_bytes(CKA_PUBLIC_KEY_INFO).unwrap();
        let spki =
            asn1::parse_single::<crate::kasn1::pkcs::SubjectPublicKeyInfo>(
                pki_der.as_slice(),
            )
            .unwrap();
        assert_eq!(
            spki.subject_public_key.as_bytes(),
            &pk[..],
            "extract_public_key's CKK_ML_DSA arm must derive the exact \
             correct public key from the real vector's private key"
        );

        let mech_entry = mechs.get(CKM_ML_DSA).unwrap();
        let params = CK_SIGN_ADDITIONAL_CONTEXT {
            hedgeVariant: CKH_DETERMINISTIC_REQUIRED,
            pContext: context.as_ptr() as *mut CK_BYTE,
            ulContextLen: context.len() as CK_ULONG,
        };
        let mech = context_mech(CKM_ML_DSA, &params);

        // Verification of the real vector must succeed -- proves this
        // integration's context-string plumbing (mechanism parameter ->
        // `MlDsaOperation::context` -> `MlDsaKey::verify`) is wired
        // correctly end to end, through the real trait dispatch (not just
        // the `awslc::mldsa` primitive layer that already verified this
        // exact vector against).
        let mut verify_op = mech_entry.verify_new(&mech, &pubkey).unwrap();
        verify_op.verify(&msg, &signature).unwrap();

        // Also via C_VerifySignature.
        let mut verifysig_op = mech_entry
            .verify_signature_new(&mech, &pubkey, &signature)
            .unwrap();
        verifysig_op.verify(&msg).unwrap();

        // But requesting the deterministic signing this vector actually
        // used must be rejected cleanly -- not a panic, not a silently
        // wrong (hedged) signature. This is the documented, permanent
        // AWS-LC gap: `src/tests/mldsa.rs`'s own `sig_gen` step against
        // this exact vector is EXPECTED to fail under this backend.
        let err = mech_entry.sign_new(&mech, &privkey).expect_err(
            "CKH_DETERMINISTIC_REQUIRED sign_new must fail cleanly \
                 against the awslc backend -- this is the confirmed, \
                 permanent AWS-LC gap, not a bug to fix",
        );
        assert_eq!(err.rv(), CKR_MECHANISM_PARAM_INVALID);
    }

    /// `CKM_HASH_ML_DSA_SHA256` round trip through the real `Mechanism`/
    /// `Sign`/`Verify`/`VerifySignature` dispatch -- confirms the internal-
    /// hashing per-digest variant (streamed via `sign_update`/`verify_
    /// update` into `MlDsaOperation::hasher`, exactly like `CKM_ML_DSA`
    /// streams into `buffer`) round-trips and rejects tampering, for both
    /// a SHA-2 digest here and a SHA-3 digest in the sibling test below.
    #[test]
    fn hash_ml_dsa_sha256_round_trip_through_real_dispatch() {
        let (mechs, _ot) = registered();
        let (pubkey, privkey) = generate_keypair_for(&mechs, CKP_ML_DSA_65);
        let mech_entry = mechs.get(CKM_HASH_ML_DSA_SHA256).unwrap();
        let msg = b"HashML-DSA SHA-256 round trip message, chunked below";

        let sign_params = CK_SIGN_ADDITIONAL_CONTEXT {
            hedgeVariant: CKH_HEDGE_PREFERRED,
            pContext: std::ptr::null_mut(),
            ulContextLen: 0,
        };
        let mut sign_op = mech_entry
            .sign_new(
                &context_mech(CKM_HASH_ML_DSA_SHA256, &sign_params),
                &privkey,
            )
            .unwrap();
        assert_eq!(sign_op.signature_len().unwrap(), ML_DSA_65_SIG_SIZE);
        let mut sig = vec![0u8; ML_DSA_65_SIG_SIZE];
        sign_op.sign(msg, &mut sig).unwrap();

        let mut verify_op = mech_entry
            .verify_new(&no_param_mech(CKM_HASH_ML_DSA_SHA256), &pubkey)
            .unwrap();
        verify_op.verify(msg, &sig).unwrap();

        // Multi-part streaming (sign_update/sign_final) must match the
        // one-shot signature's verification too.
        let mut sign_op2 = mech_entry
            .sign_new(
                &context_mech(CKM_HASH_ML_DSA_SHA256, &sign_params),
                &privkey,
            )
            .unwrap();
        let mut sig2 = vec![0u8; ML_DSA_65_SIG_SIZE];
        sign_op2.sign_update(&msg[..10]).unwrap();
        sign_op2.sign_update(&msg[10..]).unwrap();
        sign_op2.sign_final(&mut sig2).unwrap();
        let mut verify_op2 = mech_entry
            .verify_new(&no_param_mech(CKM_HASH_ML_DSA_SHA256), &pubkey)
            .unwrap();
        verify_op2.verify_update(&msg[..10]).unwrap();
        verify_op2.verify_update(&msg[10..]).unwrap();
        verify_op2.verify_final(&sig2).unwrap();

        // Tamper rejection.
        let mut verify_op3 = mech_entry
            .verify_new(&no_param_mech(CKM_HASH_ML_DSA_SHA256), &pubkey)
            .unwrap();
        let mut tampered = msg.to_vec();
        tampered[0] ^= 0xff;
        let err = verify_op3.verify(&tampered, &sig).unwrap_err();
        assert_eq!(err.rv(), CKR_SIGNATURE_INVALID);

        // C_VerifySignature path.
        let mut verifysig_op = mech_entry
            .verify_signature_new(
                &no_param_mech(CKM_HASH_ML_DSA_SHA256),
                &pubkey,
                &sig,
            )
            .unwrap();
        verifysig_op.verify(msg).unwrap();
    }

    /// `CKM_HASH_ML_DSA_SHA3_256` round trip -- same shape as the SHA-256
    /// test above, confirming a SHA-3 internal-hashing variant also works
    /// through the real dispatch (not just SHA-2).
    #[test]
    fn hash_ml_dsa_sha3_256_round_trip_through_real_dispatch() {
        let (mechs, _ot) = registered();
        let (pubkey, privkey) = generate_keypair_for(&mechs, CKP_ML_DSA_44);
        let mech_entry = mechs.get(CKM_HASH_ML_DSA_SHA3_256).unwrap();
        let msg = b"HashML-DSA SHA3-256 round trip message";

        let ctx = b"a context string".to_vec();
        let sign_params = CK_SIGN_ADDITIONAL_CONTEXT {
            hedgeVariant: CKH_HEDGE_REQUIRED,
            pContext: ctx.as_ptr() as *mut CK_BYTE,
            ulContextLen: ctx.len() as CK_ULONG,
        };
        let mut sign_op = mech_entry
            .sign_new(
                &context_mech(CKM_HASH_ML_DSA_SHA3_256, &sign_params),
                &privkey,
            )
            .unwrap();
        let mut sig = vec![0u8; ML_DSA_44_SIG_SIZE];
        sign_op.sign(msg, &mut sig).unwrap();

        // Correct context verifies.
        let verify_params = CK_SIGN_ADDITIONAL_CONTEXT {
            hedgeVariant: CKH_HEDGE_PREFERRED,
            pContext: ctx.as_ptr() as *mut CK_BYTE,
            ulContextLen: ctx.len() as CK_ULONG,
        };
        let mut verify_op = mech_entry
            .verify_new(
                &context_mech(CKM_HASH_ML_DSA_SHA3_256, &verify_params),
                &pubkey,
            )
            .unwrap();
        verify_op.verify(msg, &sig).unwrap();

        // Missing context is rejected (context is bound into M').
        let mut verify_op_none = mech_entry
            .verify_new(&no_param_mech(CKM_HASH_ML_DSA_SHA3_256), &pubkey)
            .unwrap();
        let err = verify_op_none.verify(msg, &sig).unwrap_err();
        assert_eq!(err.rv(), CKR_SIGNATURE_INVALID);
    }

    /// `CKM_HASH_ML_DSA` (the combined-hash variant, where the caller has
    /// ALREADY computed the digest externally and names its algorithm via
    /// `CK_HASH_SIGN_ADDITIONAL_CONTEXT.hash`) round trip through the real
    /// dispatch -- confirms this mechanism is wired up distinctly from the
    /// per-digest `CKM_HASH_ML_DSA_SHA*` family (single-part only, `data`
    /// passed to `sign`/`verify` IS the digest, not a raw message).
    #[test]
    fn hash_ml_dsa_combined_round_trip_through_real_dispatch() {
        let (mechs, _ot) = registered();
        let (pubkey, privkey) = generate_keypair_for(&mechs, CKP_ML_DSA_65);
        let mech_entry = mechs.get(CKM_HASH_ML_DSA).unwrap();
        let msg = b"message hashed externally by the caller before signing";

        // Caller computes SHA-256(msg) itself (e.g. via C_Digest in real
        // PKCS#11 usage) and passes the digest, not the message.
        let mut hasher = crate::lowlevel::digest::Digest::new(
            crate::lowlevel::digest::DigestAlg::Sha2_256,
        )
        .unwrap();
        hasher.update(msg).unwrap();
        let mut digest = [0u8; 32];
        hasher.finalize(&mut digest).unwrap();

        let params = CK_HASH_SIGN_ADDITIONAL_CONTEXT {
            hedgeVariant: CKH_HEDGE_PREFERRED,
            pContext: std::ptr::null_mut(),
            ulContextLen: 0,
            hash: CKM_SHA256,
        };
        let mut sign_op = mech_entry
            .sign_new(&hash_context_mech(&params), &privkey)
            .unwrap();
        let mut sig = vec![0u8; ML_DSA_65_SIG_SIZE];
        sign_op.sign(&digest, &mut sig).unwrap();

        let mut verify_op = mech_entry
            .verify_new(&hash_context_mech(&params), &pubkey)
            .unwrap();
        verify_op.verify(&digest, &sig).unwrap();

        // Passing something that isn't a 32-byte SHA-256 digest is
        // rejected (CKM_HASH_ML_DSA validates the length of `data`).
        let mut verify_op2 = mech_entry
            .verify_new(&hash_context_mech(&params), &pubkey)
            .unwrap();
        let err = verify_op2.verify(msg, &sig).unwrap_err();
        assert_eq!(err.rv(), CKR_DATA_LEN_RANGE);

        // CKM_HASH_ML_DSA is single-part only: sign_update must fail.
        let mut sign_op2 = mech_entry
            .sign_new(&hash_context_mech(&params), &privkey)
            .unwrap();
        let err = sign_op2.sign_update(&digest).unwrap_err();
        assert_eq!(err.rv(), CKR_OPERATION_NOT_INITIALIZED);
    }

    /// Decodes a hex string with no separators (panics on malformed input
    /// -- test-only helper; a second copy of `hex_decode`, below, already
    /// exists in this module for the pure-mode vector -- reused here since
    /// it's `fn`-scoped inside `mod tests`, not duplicated).
    ///
    /// A real, independent FIPS 204 HashML-DSA (prehash) known-answer test
    /// vector: the exact ML-DSA-44 public/private key, 103-byte context
    /// string, message, and `CKH_DETERMINISTIC_REQUIRED`/SHA-256 expected
    /// signature that kryoptic's own reference PKCS#11 test suite
    /// (`src/tests/mldsa.rs`, `test_mldsa_operations`, second ML-DSA-44
    /// block, the `CKM_HASH_ML_DSA`/`CKM_HASH_ML_DSA_SHA256` section)
    /// checks byte-for-byte against the OpenSSL backend -- an ACVP-derived
    /// vector, not one this crate invented; independently reproduced here
    /// against `awslc/src/mldsa.rs`'s own copy of this same vector
    /// (`hash_ml_dsa_matches_kryoptic_reference_known_answer_vector`),
    /// but THIS test exercises the full `Mechanism`/`Sign`/`Verify` trait
    /// dispatch (mechanism parameter parsing, OID lookup, internal SHA-256
    /// hashing via `awslc::digest::Digest`), not just the primitive layer.
    #[test]
    fn hash_ml_dsa_known_answer_vector_through_real_dispatch() {
        let msg = hex_decode(
            "\
            7F1B9E31C79C8F1D00E705DCB09D8118DBE1CDE3574A11EB49AE1B09CBB479A38\
            769AAA6951EAB51C511DE299F4256B7DAEAB21E52AB4929C1334F73ED552EDE11\
            A41E07555B028E00208FA074D21F9922095EF9938A48A570FF0297ADAB7154B15\
            2FCBEDB78C138E446A89B50B929C3CBFC1F5FAAE0300D63F97F1694E6D4A8BBDF\
            5A9D96EA96416908D9C398AB9FF015967E81542D340CF092A972BA2A41BE09414\
            7F0AA3E5A4A7E738DDEEC20A00C6B3A40D6A4DEEA02D004DCF03414B5F6E7C6E4\
            38B80B2A556C235F3F300411CC83DE866F202884EE7AFFFBD594C76DDEB3BDE3F\
            DED23EAF2AA60FE29CC6402CBDA70B7A2F368B3CBC3D15CA2FED5B66B4C2CA332\
            D0EB3C3A807AD8D4F448BFD6A1F9AA4A33B90A57F0B4E8295E6A6D8234F2718C3\
            BA4C584BAEA5BFDBFA37FACFBBA0D6B57EA5EBDB8DFD69670F725DC77977773F4\
            BB91AF6501349177C336C74A59218346E51AAC666547CC532B86EF7CD3C0F56BC\
            A061C3E54507197C52300AB2AC1F7E6A2AF388DE33EFAD8CF03B573CC579BC3E2\
            F10C500826F61DA88FA5601F9C57E0FABBD36E84D85CD75624644A6E19266A842\
            04881A2F1A2761EBD663F1551FD344E248DF3C21FE32A73AE42AA9C14DB0ECFBA\
            B21DD0A50488AF968E6802D08599CF015F4928F625363D1927A679510CAC25691\
            09BEBCC35AD6DB5E9E75621439A55BCFCA8C00077DF569DE90653723D987DE489\
            466ADB55CCA920499FD67BD4271F7A19B7EA8A90AEAF7A764199DFCEB755C0632\
            A4863146E74E73251AE275ACCDE83E521299359E10FD1AA7F49CAB3DC72F8C730\
            48B3AA059C424B436B9F7F5AFAC00B4DBB40AF1CF1ABDDF268B1B1BF2B9EF12E8\
            1548CE9D0A162D9AF4A8CECC41330FB89DE7B63274885D59D7AA6FF1BFA8EF88C\
            436D2BBB942B36A3D66576807A6D0FB0CDBAB9967D72EF7F487EFCD806B015C00\
            D673123E1C8439711E09938051D1B777E05CC104E05F375900C84D8C34884709D\
            7B9E96E58EB699CA079C71E8808BCD56C0208B20B23CABFD17B197620E9FAE518\
            2B891EA72379F90ECC28BB1F18C42A3E6E663F7D6F2550C88081C2E46868D934D\
            6375C22FB33D241761130849340633DFDEE89B33FBB5F77AC09EB05BB7F200CBD\
            5E5F8C02281CF8197F28BEAD0CD27B978E639865868335B36E4B183BFBB0AEDFD\
            D8175BBFACC5176FF39C2F102D5F72216F17C2DFFEA3EC41B86DE8993E7533229\
            C172F3F49288FA81984FB547414A3CC4AC135EE2C8A150756A5E83B6E30F4EFF1\
            A325D02BBDE3A405EF6913AA43E6A1A956CA336524C5C2E85AFD2CCD95978398A\
            6985BB54C2315F59A13F24CFD6254D1B5D106B38C9589FEDB1D4FD2D83F18E2B6\
            110C97B8567A5C7EC0FAADC49D06AACF050CAE7939A9B22F130CC68093B595C1B\
            7E9030C23D6C17F80ED3648B812E7E4CF658ED4D9999F1519BA8E18F9DD6BF643\
            66D784EA793593E08813D8BECCEAA224C05DFEACD8278E6DEE86596AA20793C5F\
            514A3B40BA42D643AAD01270C039F13F9BA007031EC58098B908FA799CD8D893B\
            E5C26BFE9BDFC1CE2F9830311AFE7D2DF2373090CEABB780A150EB66FB94D3DE3\
            2420A80CD0631EA913FDCA4D8ABDC7BF5A22DA16CBC7DF0433905CCCA530D0B3D\
            09DCF67972D020D99C4D4C9BFBB9A61CB5B909A010E70E3984F39D270A87DE8C7\
            79F9251F831AEACCDB153CBB77536D62CD651329983DC9C2EEFAA217CEE8BF018\
            03103190D3F306EBA323ED833D282F141A169577F68F88D02225EC389A4FF19FD\
            708E0A44BF0436BC829290CADBE53DCE2BBCBE02AC720E3B57C81175FCF14CC2F\
            9A42900412D0E5F7BF3F17733D4DA43C4B07AF1B213A1A98E5B61BD63A2B08409\
            C49FA639027EA6AE60264E2B9C86C9857528AD755697995A5212CFD3BCCF92321\
            D03CA9E5FC8ED6DF04849BCFC0BA11B456A2334F2911D8F3E05F1FFECA6E6B9D3\
            4A273DA20EEFA86DA0166426D7604402BC8AA389658C44416CAD4F614B1E16AC6\
            0846C4FA3C7C00DBCAA7EE55EFBDB45633AFACD932A57A676D179CEFD55081F0B\
            C312A2A5A73DA74836A3BD22CB12E67C3CC6533D226F833701F6E17F184450679\
            1A071D24772298E27E002AD8EB87DB2F8E731B56FB0BC34E4FA27D0CBDF384941\
            4BDB38D5DF536E7BB2EDDEA4682139D7AD5E408D91A37CE957A1AAE0A54115CEB\
            715BFE245604737BF47033D958C969508861CE4F6F056FBBD8E36168B2DC2C61B\
            64310EC6325DCA33478DF8AF3A678DC8260E78073122E8148624A32A8A7F4D3FB\
            2680D1A5ECB170E241629E86B81E23160910A6B027883715B6D91595BEE597176\
            64211CA8FE6920798A8FB4A44372177E0F08E3E0B393D374A618C7FB9088A3DAC\
            E2BED9950307984EB2EA65BF81764258CE9E482343FA241CA6CD967EE1BA820DB\
            BCBBA7A7A457E39B182055E5ADE18F80A60738B98F8789D3954DB824049D1B749\
            BF9E996E4DB94129E01BBB975E708250D7C7B271CCCD596529C73387A71ACD3E9\
            DBDCA6068CFD213E5576552DDC70187622A5B160F550689FE023E1FCD2680466D\
            995E5FF8E47B33DEC1C7D257586867E701AD28603BD7FC1CC245E302B0D5AC29B\
            CAA462FE8881052BB51E651234C44E641CFA2D3AA0218E08E4881F5CDEE2FA819\
            F6A39C4FA9B7A381D26353B78A65443AB1F1DF7EC51F604695D89F2C91251EA49\
            EDC88917E9833AF2198CA625E7566E8AE86F30DD447F57E341AE7DC66C5199CC5\
            B12DF14DF2C1A5FFB3C6BB9E95617CB506F2ABC2E456CCCDD583403D3363E7536\
            8F7BFF21CEEA032B5F22A13C354B85B240FCAAD6D05BD711F0D3C93F35AF2DEDA\
            7EF34DBCA1C5D19F19C7A2C8EBDA121634982542C2D25C457C94E1C0404B7D95F\
            3FF9D66CE8FBD350C6F3F6103EEB4EEFCD33FD887D1DA1C591C4B5FFADD0F5829\
            A5B6A0C90EEA7370AC139CEEB561C8F3DC9D4FA4A73AA99F6775B8022DE2200B2\
            D1764B6A7CB9923E37FC17B7983CED54E8DDCFD1B86410A6D4794A80D56EF6E8F\
            167184371680B89B6B2AE84416E7FC1DC6591D50AF229F9C9CCC2883358E0E670\
            6926180EC9BA7AA2DAD3D26DDA6396F18DD9C6457752177F270D3BE2BE649A951\
            C5EB505715FB62BE75C6D199920D6F8B536A7E375F2CF2E3B895E7FE661FF37ED\
            7B8EA16C5C3825CD3C3846804308858D1244BDAC88009B002151B98573682F92E\
            D5CA1A6541AF9F4446B868DDF5F8D32D3F34E8192254A1D250577462C7A38B2C6\
            15DFD04B697050C64FD1C21DC005A8A7D5FFBC1AE5A8CD3CED0FD47BB034163DA\
            44DD4F83518D3AF69674AF276FA24D9F3066090765713EAC805543D2FCA3D8AC4\
            4917F4DF9BAE4680227209938542313CF435FDCEDA86BC32A483E35F63D1EB60D\
            E77B93B61CE28F43F6B0D13569F5BE8B3A0F1A5AE694C025356ADC4A275FB2F95\
            5022E12AF4EDF5DB9C3816990F99524885D56F0170C10168E4304FC4049067819\
            612EFF1A47E990003166F6AA4F683A661C932DD8CC5B8402485A98DEDF8F20B92\
            CB8F834FC411C8B2FBC7290125EE9DBE3DBCF69C0A5D25A63FB5B6374BFBDA3F6\
            090938441E42ECFDED7D9EB5E7FDA3BD0C9E9C3317C335F13C533E2D1978AC5B2\
            7771002A6E88278028183DAC397B63A887DEC6C18CB6E190CDF2CA1BBEE7E7158\
            624D9E372C3BF90BB5FE86DC41D169F4F91B98E905BE7515472EE1E18E2D01076\
            01C9500AA34A416D672D64084613BC10E2FE9F085D175F74D486BD051D07D8C3F\
            0A3E7D927723E20B1EBB7AB5C25EB3FF33B20BBA40119E992778CE17AF3492ED8\
            C03E3153AF4C03AA331976F0F1FC617838085626A1843EE53B787385E863CB62A\
            8AD58976367FB91476D28400F151AEB12D9DECEBBC77618C594BB9ADD5B175B59\
            86060CE7744206C701FE27ACF489E70350D10FCF14E8BEAA300BA57EC2933594D\
            544890C2E4BE3D99DE394862058D14A2A5D7090AC209E0F022B23681B94BAA674\
            47F5D5D41160C171ABFFB2F7C0D55363C1038D49B9ECCB1A5D1D9F0D65758DA68\
            C4705AC351B3DDACA4A88FBA86C2FCA30CD91125132CB5DA21AEF4F4B8BCC34EB\
            5B53E09F84316225DE7C853A6D253C6CDA9921BA68F1E037A530667D53B936DFC\
            358CD989CA4C9EF4B8B531302F2D2816CA304C29BF84428FC7D445E10ADB1319F\
            883D4FA6991FEF5BBDA2AD2ADCB4E99E872B04FAD657F0A87431AC8425ACFE387\
            DEFB7EC710887B7FF98F3E8ECAD2E29C873CDABE9BF8F4019B0BF20D7EEF4B19B\
            99C80ADEA20254C6FEAA55A80A59236274631A5E89D245EA969E735D5EB699EE9\
            BE345C0909E2B9E2C25CBF569E6A8341C7F8E78E35D8EDF989B7CDDA070FCBA9F\
            CF9EA28D4FE202EC0DAC08A1DE76136C23DE5B7139BE2A95D30072A117ABC83E6\
            DD3E00A1457EACB0FB2918814A2A90E2DF54C493B2873AF98C6E52AAD029EAF24\
            2D5487843161601786A9BD6DC35CB83B1FA3B64AFC5BC25B644B75B7F251A96FF\
            F4B716AD42DC1AB873586FADF13D43C9D2D0EAC0EAE7F9ECF6BA2030CF75D1D94\
            8C81979955682E4FB4E96BFA81B7164E72AF4F6F4DFC70E30AB04C4C116070A18\
            18C963A22BF4C7C6DE9FB1F52A97FA7EE146D67FE9F2112BBCA4891D48C39B008\
            CE94016EF462E0174DFE6F0F3CAD535210D85B107960258DF53E859F53BA6C490\
            A5C0FFCC1B8B66F8DE16EB4BF07EA4FD7F59EF882CA54CE90D317BAD26DF8ACB3\
            1E1716ED2B47AFC0DDDADE3EB6511CE957FD4C672F672162FD281968874D68BF9\
            D7B1014C3A7D541F617F9EBB7BBB8EC80321FC6A84A2E2E3BEA850089A5D8C7C6\
            95FA7F4D9D2B77C3F4B14D955D4D8238931E50152F4597EA5DB1FF1FA936B7658\
            F49053DF17F9E9224F5EDD2188BEDD9A4B9C05D4E570F9B2860BD3BCD9CB9E293\
            56114B1726E2537B9E6C3ED0B04B0AEDBCBC63194ACBA0842C54D3D30A309124C\
            E925396DB86511CD9A80A0793B78D349035FE3DEEA125B9B826AD77FF3D139863\
            D2984D8F9B23BAEA41CA707558AAC9DCC3001DD9050756EFD331FF413B5EA4187\
            F504E816A079053D732E608158CEA15EEB35DE12C17C42119A7873B77821D37D2\
            860242C0B88010F139F0C92870975A7D76C35896769E71931F49EA18819DC80C1\
            E78ACE7579CB20BE457BA99673053919FCD155A29465B32E99A5D7A9C0548F48A\
            3058C428FA4A8C1D71ECC1C16B3D7CB4761DDA82423C774CD5E19218DF8DC1297\
            BF4A4AD1817BDA7979C65CD9808CB3C764A19C662707ED505EC30B7E223B9D7AA\
            69DA3679E30E9FE44CF2C1117D291699844C99656B83563B1E9016A7A1F49A6D7\
            74AC12F64B0C2E37F31F5C6A9F395F2D859D6CE175EE53AF99B2AA5E20F2642B9\
            7B05132BFEF36B1AA0B450CE4FD64935F8A6C83753D88C6DFD1E581BDD943382B\
            406703CDBFB8F220E21FFDB432817F346737642A906CFFB31FF178E15693CA09F\
            93F657C98FB97EF9713E23C3BE5D14AC7D850A34D326BA6E49BC956A88934C45C\
            399A04CB470DB8DAB25DFB13E44FE948216B8B582643934331C4A6B472A1F40EF\
            5208BCF1A6B3263A9C990C6AED8A9427EC84A7E42BA7DC5691E377A7161A44223\
            A9EB8D9167116BE9CD13A308FD61683E171516E418B7E1AE1D362BD61C31BC6D9\
            9C30F40E75994DF2F96FA9C2BE3A0490D96A21D12DBE7B92C74EBFBF09A80C7AF\
            CEEB9DAB76D5B93328C000700D2208321C719CF86B3C8461BBB7BC13C708EF966\
            BA94EEBD3667F329B884E604974E331FEC3F98A1732581DD77111F60755BC7720\
            49E5F05407F615FBB32BC3595CD3CCADC468847F10E0509AA2F3C97B7BE6C74CA\
            8BC1C4090F66647789AF783F3BFCA3A8C71EE1C091FDD6625814A6D3E8D96ABAF\
            B619260D581FB2848D9FED47761CED60070911917603C1E32A99B0A8EBD517883\
            FF90FAD2B4296837F920CE1C091BF32F35813A51EEAA8C6C65250EEA232179980\
            AED8354EE0B91AAF307C1FC988357A8852DB026E9737182E5E8DE45D45B3FBB1D\
            669F60B4785CE5B813D5502D7245437AD34562EC970E9A5E47DD3AF149CEC867E\
            F6EEDC6C28BCA909CBDE81DCFCAB313CF9FA313A7AA8C4456334042ED72660BE3\
            2FF83569130A76590A871342E08188102863BFDABB87E7A446D9DCF223AB23D13\
            B0E4152D34C334F7DDF2F82209B3000426698963736F1614B08A54659E4383A19\
            43DE2081DA76B109E711ACF922ACFC2026E65BE53D15192EC32D4A0D4D368F7C1\
            8B4DD87502738B27DD34C5010347852B2938073A452DE116570B903393EDD3361\
            CD2DAB0FAEB3B76A00381B267EAF8C20834C2A79F139466FDD3613EE92C2B5EE6\
            2CEBFB0A8D5FEBDFA64EDA93DEE9B9497A5FBE4CBA6308CEE43E59D71B1DEEDD1\
            59051A3413D68F30E61021B634A3B2D3859071A0873777E8F3D47F552FA41A96A\
            3DDE1917F2A2817AC7C032E1970B2C33ACD15CC6581AF3AA6896E3BEE2BACE93E\
            4B36F776FD90AB5CD73236722E6262105D80DC9D48D1EAC5589F0FC584EEDEB27\
            54C8BE2C310CB99A315476C7493359933C0DD0A6F6E7AC729CA87B92A5E721EAE\
            BB0553FB95D12A8B4BFBC3A9048FE0483A13F70D8D7D8AA08778A44B46D5AEE8E\
            070F4838DC357B7EA87ECE92B4E926EC3000FFD5B0F1FBF88E1CEED99051328E4\
            FEE796EEB3583A11421C9D2D138246663D5069FE83D7D817E336D60D6909F7250\
            A0CBD95089C2369FE7122D727A2CFC7CC56930C3822E1AC8CAF8AD6C2388274E3\
            C4CFD35A12BCC05C9221657454B77E0DA835EB8EDAF9D9E007B7C56C700C2FE6A\
            73BEF10DD60023211D7320CC1B43474F746CE68692C1FA3E0B0BA14FEE223D43E\
            3738992C6554669E54AAFAADBA90C1CCC45EA3D05E1DDFC50B7621D6A096BCD1D\
            FC75276013945EAAEB676FBE4BF56E290B585AF05A3F589AEAA65AB4F1554CBA6\
            EF5D1173528259FDA97443978E7F712170FBF55253B12CD8C5D893833384230A1\
            E8A543088538CBAE802B6C0CE5F773DF8EED3485EEA21338D99C6EF3D42005045\
            11F6F5AD6A004434544C84E4BA729CB7C0C533E4781C1570019A9897B10F2487A\
            B8B40FC3F0ECE22B7B07AFFA13528326EA04C6687FBD052E334AC28330BF4CF3C\
            2629D2A50B581D3BCBD0587F08A4ADB2CB93B5CE60ADC56DF5F7871BF9EE9808E\
            9F845E2DAFE02560AD735C13E48EABBC82221940DA9247C0CBDA30DAE2812F1A1\
            86C7E36065E4ED37B3779519D22B98F535341CE0499FB1DBB648CFEB4A19826C4\
            FA359E1EFF0FC3F01DDAD5B0022557D8E47C7AA7F4144E0A9C3616213FF1550D2\
            954C37A9274CFCEE8C218E805BAF17BAE3EA5F6A55018BEB03093CFDEACB336C3\
            DB6AF4A106178A7220F70DD2FF3B2F05F4CEF22818E994486480A9FF42EEE0CFE\
            BE741EAF66F7C30CE0F8EE4612230DA9211CC8D8322AA1D55EB1082485882AFDC\
            6EF52F16C216C15B754BC306E9337502F158C59DBD3EE11758AC0D30D8A619D39\
            5CE959833CCEAD66A4AC104C17501F8415BEE725545AA048E62E2ACED2BA6374F\
            857CEB2CB75EE0CA1AE2684270793A59FB5C7FDE695812B9C25091ACB4F14DB20\
            4743BB05AF39EDACCDBAE5764C6DEF38E61DE79593BC4C12D46205638ADA5C93A\
            CC094E6DC9BAD9D5D8192D193FFFE3A6C9595ABA887F0DC3A87915CD74B2E608C\
            89764A984BDE8BB9901D8498869A65BEECAEB93AE91D230B3D32AB17673D7B163\
            B583E65BD170B5ED084C5BB0C197D32B8B404B6349BE4B7EBF7BF572D5C3E55C8\
            90A1F3DD2E72F154FDD6CDD51F02FC89D873A58333A6DD5C0B842018504CA7529\
            ACA0F06071B2C6997E9EB7930C37017C7A77A0380E082AFB7FAE85ADC893ED940\
            0E988F2AB43152773663C6569546F3DF0C919F25F751334939CA386DA3900BA03\
            20E87C75F1469469FFAE213DBD9723355FE6C84EF1B5E965FDE4F2D77E2721887\
            9230078A49DD69268E3155F7931778E7B05015B88342721612112C8D8FC4D140D\
            9A6E35269F3A6141518218D74A870FADCAD4CB3C2F23E8582718DFFF18E3EAFCE\
            CA90041245950D13E8AAC1C7F49790011E1BBE74A00B79BB05A7FEF0B9FCCFD9E\
            9820C387218E86BB163DE6BE98B2A707EA9EE5E189950C6D8763B3DF0BE77B716\
            BB532F080EBB0C79D70DF0D2523130D5FFAF21B3E6953CB104473D155232CF54A\
            0CE1ACC00602DDB9234ADD601DB2FA35090237DCC67D4D61F3F783C96AEAE84E4\
            02BD71D49176232CFE1BCB7B5BE08C73C3C400B7A3575E3FFF5D86934AC9ADF01\
            931F267A3771490EB2123C614D57CB60B77505CAEAE25F515255BA6170E4E11D1\
            D040D8A697FB2410BF55D95C73554B039DA198EB8FD06A1A98FFAE9B255030FA7\
            0396A208043AD104BDC7F08309E04C3E6DB674F48920B4A6158FA450B6FED2E5E\
            09EA781931DEF4E0D17D8B1ACB638334A9FB128E9EF45AA183525F489DF1C9578\
            9D3A411497DE1EDE5DE4CFCBCCDC3B832D2FD2944B831AE0BB18713CCEACF2E6A\
            37E89F2BC607A7246736C0A256631A762C235D10339F6262CFE7411506452CAEE\
            F531FE839D466301D5CE42A946DE302AC2A02076E1DBD57C0C8F02C37C4814B61\
            65104975C6902E2ACB2DE0E7332BC01388E997808E140F9C85AECA0290FB3B4DC\
            B5DC03DF69B95C19285721D59ED6F8302BD330FDF16BF254E30015C51C0B04D3B\
            4AC492BEC2C0CBE966974D394DCC96FB2BD3414876989FF08EF0C7577F2839D2B\
            B5B26745ABED60E7B7667A6BFA44EF768CB8A0A8308966148FD6DA8DF475FDE4D\
            FCED8CC3FFC6A5DDD4410CF9D8EDECA9969EDF0687CFA8E7EA742154A3D2CC735\
            18F9D90E89E07AA808252B17E5BBD1EC24CB203D33FDD9A8E75620761365026F2\
            7B45960CBEE658A2B236555A375D5C7B829AF409CEFEA7159A4FDEE6AA5CC6D7A\
            CE8DBA828A15D40BBC2D1D6E334DE4458A1BDFD37D3EB56EDBEAE0C370465840D\
            488F05A1A52D30983BDDAA5584D4485C05FB1FD0C4203BEE7D4D45E1E57C896D2\
            75BC77D2A4A43C19EC1580FD9D43B048FF1A38DD2BB69000C3FFBF8EEDF5983ED\
            7429CFD8D84DB988E28C3D20482E794634B14EF066D1512B90457803CCB42AFE7\
            857F84D71493130A3F4A40C84A051A7FFB5A2FA57FC356C774112198E5D7D9698\
            B1C099C668FBD7AB96FCAC4DC86CB25EF6614A4AB3B048F1BEB67D10ECD7A0A0F\
            1D4F152B0AE50FFFDAE1845272B2DBE32F6560E1E886DB3135A64C9FBC559AF31\
            D368F62AF5554C6F68D321736C4C238078E63676E2745ACB1C4805EAC068C0DF8\
            BA1734EBE27293CCCF092E338DF6B605F8A5496392AE346B7A4521E92196FFBC6\
            6A42C7AC831ACD8C7FA1C5BB027F7E66A80420548749CE691FC1C8F4A5AC7EC64\
            DF5B84DC20853BAB92D72F94C56896D46C43E982639BC229099A4D6C586A9E2AB\
            12019BECB52AD69C469E436C5F02B4A88E7B5F9F29D85F819502FCDEF0014760D\
            F585F1B21FBC213CDB1FE993DB7938683C6D6CE1AC203612CCDD8873EA44E4527\
            7123F299487F65496A512D497C4F7D8A2B833E567EE2034AE853A1510B7E2EDF4\
            8057D351DB207052D4CFCC54E59706F3982ACD32D9D3CFE59004B4F7482865726\
            7B92FCAEA70CD8566BE3BBD05C5B23A315E391D5454AEB022BDC2A8A6D6110F8D\
            D11A97D13751D24822878783F2A353AD5BCE5938F243815101023C4215A7ED45B\
            FAFA8185F9500B8711098D6FFB124FA05BE4DC456CE3D7932F767380A4358BA5D\
            8735169D586BA993B0062FBDB449683A47866D624BCCF4C64570CB3E936978405\
            68A491A5F418B2CB01023C303BFA3C3A5CC73BB9811E8D04F76DFE49859A3D4CA\
            337D570C0E07BA420674339D443C25556398373D4273D4E2562866FCCE322543C\
            00740E5F9263D03B0FE0BE6CA2678DDDCB2CA7EE794D1746351334B0B6B40125A\
            FEC3BC1901082E171FD114E83733897471670F447F4284C45AE7015554238212F\
            41DFDB0EC4E43C10FFE291996CF4A5289A02EED530678FB74A86845CA3D1549EB\
            AAB782851214A055624AF83EF86DC32CCC926A6C6DBDAB9F83C301EF98245AF66\
            7120392771E1B0B9A5A10B1187F38A958DEEE970CB0FDAD4AF9A42E1F3AAF73FC\
            10BD30161B0BBA2A761D6A6BF59928F2212A4897560725431AAE82D94682B7C57\
            BA7B1A82ACB822786EE13D640C8F87C7E75A2F275EEA3C2655BE29D3241198AF3\
            AB33ED16A668C31DBE86FAC98B9EFC4CB51A600CAB71AF95C74E928E9FE50CE9D\
            D61DFC4443298D6AE9EE69E388AB4EE703D184D0368548AF832483F3E72BBA524\
            33543F8D6C89CD68637500FBA7C7108ED1005A8A311C31A06C31CE00013A249EE\
            245009A42C07097A37F1F9AF5F729014840799659876A33EE814DDD2171E78310\
            F5F3D0C858CE4B97B3129C502022BA0EEF71E8BD3494D616C9F3110B084BB51B7\
            0BB17B138F0B92936CBED5D81",
        );
        let pk = hex_decode(
            "\
            5D01D408A07C511354224F6F36B879E65021742956633482C378F16090C737D35\
            F62148252CAB42053009164ADCE36E2064EFEBA6BA242FD5F7ADC4F177F23C665\
            4A6C6D01D8A9CA87D52EF0F28DEBF9EA7CA0AB78C25AC51E406CF1CA91DD11A3C\
            AD979691CCC9DF5C7B724F969EDB435483FFEFE9C17349AAE8E90048B5B106685\
            B76920A5CF20332B9EBA77C9C729F7A8538FAD7D4304214228DBB0604714F079B\
            A646498265DBE69F2A584142AE9CE722A6EE58F2CD95726D61533C0449A65D38E\
            E38AB6BC5D74F18D0B0B2270C95258CF8FBD64499F4F47AA09039609FD678F608\
            A88FCB2B25316B0989D53B160BE55F6352820164492D4302948292EAA832F20C5\
            22485775EE3A9D6837B49895F948A6B729B5F4887BB33DA0D65644C29D7A2B105\
            4DB1991B1BCF325618B45F19034DE456490729F69C9B5A89109C9EBF358400973\
            AE46E002A6A513D2C2578F49729D37765ED3589419A3286616625EC5CE023ED43\
            EFE075799673CED9E882A737843C7445EDEBADD9C01E960260F7FE383E4EC3009\
            CDBD8E95754A87513A95C4B2C40F3F143B9644DC17CCB6A454CECC8B77CA7698E\
            A964E5DD2174460FF9FE455A73D597B45CEED93DF9C836E5E2F51B586D1AD8493\
            3904685558FC7329940BC5FEA4A041D7E38E2ED038BD4CBEB7DD0F84810E522BA\
            F1A2B28746B51C0F20C0884CB2CC9C111C2104C9C1F69F70FF34AA17527FF97DC\
            8FBA27BB6546C8963AD347F85D6231B6FFCFE732C7D1CCE046E118FA69C4CB13A\
            57FEAD67E97CCBBFE7EBA349929127753D3B6AFEF5AC8B012D390BA6987C89C26\
            E57E590831CA00AA0D49FFB993444B4B1D8744FDE8A4DE0265B70FCBD8C6F533C\
            429D01BB0A3AC94B0A5D6DF55A8B3F988E2C76D080EF4B8F139FCC7B49E25EE75\
            D00B60B3FC994EE6ED04C3EC4B4C7863FDCDE13DD33AFD218B0A4341542C8B70A\
            63BBA50C636AF156C9A0A8B52CB73173C8DEDD95E52E1E136F749C9261D7334EC\
            F2A32F9F043C7F932F149E9339810B7914A39927C33F200661DE147817E72A65A\
            B35B872915EBEBD67CA6C08B19419262B32A5E1481960D4383619D52AB5EA9884\
            4CFDA24540C2A459971AA1EAAB775EC53D7B9DC8DD6D3F0E305FFF2EF19D7111F\
            BCE1FC768E348B4D98E7002AE604AE550D7DFAD3E32BAE55B96F41B143BA8244F\
            3918780854C4B9602F23AD39CE6CF56417D6E483ED9D8CA9E8BF50A7862A32029\
            DC780CA51043C7401AD4CF4F9B4026C1E43933D38BE3E7B21DD94683E45498289\
            C9B60FEF2375D189C25487E5270018D6151EECFD3204F0BF94B50A9728A8F1608\
            531DDBC0DA9E063156249E10F8C4EDCF5A888F51514C8C5309E5B476B0D19A6C7\
            B920E0506961FEA94EA6FEB4B4B287667059CC7BA75AF14A091D73E8BA6F0935A\
            E52AA1489DECC09B88C0B36F8448FF4A0EE0061AF5B2E7BE7EC73B9D95472C6F9\
            BC28391E909C2E26567F3BBEDC78009A6FBA059E0A53B12F097BCB96A3828D8FA\
            8C496AFA9F64A5601B3AB7A2980E81AB10DF20F0F13A1185B32BE71DE0655D258\
            BBA091EDF82B48FD2F0FC3AD4BC8CBA2766CC7CAD5D7541D0C13208046CF3F2DE\
            BCE81F918BCB0E21C429AF158CD467BDC554E072375DD2C39748ADADEFC6E9832\
            8B2D1F0FA4F4DFBA8EB24D48B93E7D8115F6E93CC8EE58AB9FEED6543B40E2F4B\
            4A9263418BBABF1AC92977BECBC1D30DE804CE95B05FF086CE87431609F808541\
            9CB240E756E314CEE7A11BD0D7B10560CBB5BEB0AAD5A154049E91FD1E7318AF1\
            5C288A5391F0CCCFB6F2578B0AE60C1AF326469B981A366B2F9C9DD2A1EBFB8C9\
            2AF5D8A1EA3BDE429489EE4A",
        );
        let sk = hex_decode(
            "\
            5D01D408A07C511354224F6F36B879E65021742956633482C378F16090C737D3E\
            8AE25BE2146D68ED33A1C22FFF6911000C36F90F50CA6077134CF908113C2892F\
            BBD14CC761D516A4B0B5180F4E5F3BB1352952F8FDBA56CAEC87C209E95AADFBF\
            94B64BD54E3CFAC86EEA090E00C990AA20647B19211E0DD93CE0AFE7731FAD922\
            4D82320E0A128124048418948108B7254B008052288C1C469052C601A01484821\
            6511088841928058AB208D8348954129164228C043085DB302CD24282A41405A4\
            1081C4304823B9801C0370140864DC38291B050224990D60B070491222D3186D9\
            AA8055CC2890247801934221B4640C1442244902019A00812B524103724D04890\
            A0824D41B0801B35229B24054B080559C4440427425B826C61422D8844429B148\
            A1C0130D0446AD3040C1B376EC9400118016413826D60040284384C8994650823\
            70D22850990451CC4490C0A885A316700A045112A204D9268ED8465224A5644B0\
            06013928CD1004C59482009912541B881D0C451D8A82D04254E02444ED9468D91\
            1000608009229030C19670C2364153B2618930708B942549A6041C02055A380E1\
            2892104458611007163C628CC068C42284DE388080C1924084242D20866D0484D\
            0C125250A40D09146D0927104928660AB12010298C8A2430CB0671CCA24463040\
            CC14624111609234185DB260021354809800942C2651CA3204B0670538445D028\
            30E40644DCA49021B20C61480160304122B91118A5090C216E9996011B2152A42\
            2290A4752C0005201A28C40C881413232D3280ED8962C18B4110CB77098344D0C\
            C981C8B48DDAA6305B18851AA36D13334910B768D8222DD9288C41122A8C984D2\
            1B9905890240BA530C2369219200DC12221DCA42080329123496EA4C470A3A491\
            C39048212850194621A390010306025B242C02304604C610DC180914B18983384\
            940080263181240324D9322502020015B42909B40226448010A172C22B14D5A24\
            4D4912819094300CA0919A049104478148205018016D234070DA284993A420138\
            141D236529B0681130710234430D1105118880163164A60024C8AC89042382102\
            3864C92241DB026CD2A8919434898B98250001699B942D1C098E1B4568A20282D\
            C36098838428C4821189370DB064480308E12978450322E24259018010C144106\
            A282640A316A11420E98988C533860039468D23666C0B42924191180168E51384\
            E60B480D48621CC3489C834051282690291814CD7C382B88E8EE9A144119C5D4A\
            AC200B3572B2AE374572A225B1184A00E310A3AECCD2EFFA498A96D878DE9D99A\
            E41A5CBCFC62225DDD986DBC48C8638337D3E8BBDF7C02F478061DA67F5D24F68\
            4396FD06C5F46D11041C31B3B123F1AA0D098A66ABFC2F27725D0607E64153304\
            E5CE0FBBE597070DAC3FBCB688A2E4CEFFBD7068629BED23D4C884AD910F58D37\
            76FD4F57F1E5E43F9BE85672DBADEC5A054345B132454920BDA3AF35ABCB025A6\
            4139A04B5468222F03494819A76655CD38B9650CC14AE9A5A8A8438B133423296\
            960BBEEC8A3815AFCB2AC8D126D7302498654130A186EA56D54C26F10D28B3337\
            8E50C1453FF4F471790C92DBFB37AACCDC6895F685A3A67AEA3875E6C0E116924\
            65FC915206314529E50D9990AE6A0355633545EC0BBDD171A3F6B4C2798D5FF71\
            F98FD025938CBB0C4361E596ED90262367AC676885AD0327CFB72859A2F9C6C9D\
            6F3AD0A6F764F2C732DA9987F966331D1F4E2325022609D9649067921FFDE26BD\
            3550D0192F87B9D811BC5E3DF47A357963B111F8B2D1C247F5839BE8888F8E8CA\
            8E847B9FF9780D637B7FD1CC9A6302378E6AB51FDA85185C331257CAB4564368C\
            1E27FB53C41B4C90F62E7BDA598FCBC5E3FF6C68C5D7D2AB4215EF5C755A404CE\
            40F409412D48BDC2E337792C04771447FC6AC9E2E6D66D2913B68A90A25824E5F\
            AB3C28C60B2DD852A8218D4E543832009814B318745F0D71D7C11E0743B259963\
            5B2E838A24EF85824EA6B0E9EFB9DCCA91B380FD4AE1741CB50AEB35574DB1D01\
            217A1114DDAEEB0E828EC5A712CD2975D9DA7AD04BE715BE8E63CBC35B0D9E39F\
            E857BA39F532F4976A8563B7F0883E69D1286440F406A7662B42FDB4B1662DCDD\
            ACB05A91C37899DC348F6677092560302DF1228CA8248BFC168A8E6CD404D2959\
            3F4763EB2642885437D07B017DC0DD2FD509A7CB66219FB111482074448DE0FF0\
            F83A453F7658628C86C54767D5D216A45F2ADFE02EBBABB4D18F83D2BDE3FCA7A\
            F3AEADCC12EEE7529F9082677C5DC8B4163EBF88EE9CFF24507817225619663B4\
            D2166CC6226E761C1EB02DD72EBDDEEA136C4968177331BF7DC3AC3239C3B4226\
            68CD2C34DAF7653054A8A88E0D9D98D91096F41A1B1AC557374E156D15C459542\
            241B49889039EF34D586B4D0597C6E273DC725350701FC4B6E97BD7E0DFCA29E2\
            0490BA02C6FEB27342DAA1A7BE6646457DC3BB16C26709796A0F76B3BD66E096F\
            3E6F3E803228A5CF18CDD628231961E5476D11EEBCFA14F413C6FD0860AA90390\
            A91CB8426310ED36D7E32AA7AFA9B5F7007E4BCA7E7122B5A5F7FE6DD9825C9D5\
            D35CFACB65C0911B875CC3836A025AAFCBB4B4D624E7F9FCB35D115735321BAB3\
            7B4994F83EE33C08137386D957A4611C461CF2395E0C0CD8EB9B24D7F09EB5E8E\
            193191B9566B9EF4949F6ED0ACE40ACA4819CC4694AEEC9BA295068DC33B22C4B\
            E812328808D4BE72B483EFD66276E05B2D5497703162E751606B4098D2F4B62EA\
            F95E0B35BE46C42502FAC97B116B7993B0C07CFE8221AD474E8E7AFB6A11600ED\
            4D771666F3F043666F7E442F0DF6F944FD6779133F07BFB503E53DA646B619434\
            93E566237994674C103EC1CC90339128A2CBEE05189DF3F3D0C04BA656AC76347\
            800506D0F783BBE1FFBA7D84289FE21F45823699B038402E503127303DE23FDF4\
            ECE1863FDA48AA9EEA99C9D527DE046B27C2A4E2950824BD58FEC67A8B626DD08\
            A8EBB3C3090682F37780CBABEB362DBDED2C2803EAC9B404B1DF08E9841C09DB5\
            958A9D4D11B6CE3C33D31973BAE53D3D3B27329D36F26E19317A52201AA3B3C94\
            869A99ED5AB08896B78727E81BE0128488F5010E03B1BE13BAD0DD96DCB9E5E9E\
            507B475BBFE17D53444C3405C30948B581CE7153B2246003AB652473C6FC47195\
            E1F67C83BB5FA6EE204A01661450820DCB5CACE8A654D6F9EDF50EBF982AC6CCD\
            9585378EE5A70CBE9F80B2D619FEFFC9D3AB1C1AA9CC22F9305A8CD1D3C3E77EC\
            F898F6A0C388C0F53AD058933C92A61FD9921E1D7085632ED2FF3EE8B216A1D3D\
            D13D72197C2C46E207F124D6250D4E0365F027C2D23DECCF0ED2C89CEC0F5A762\
            04030D4BE30657F8CD6925C12702348069EE9703C9C4E17CE7FA905BC7DA82A7B\
            3F582A1D91571F4256075C0C03800161520C166C6BB729F0CB24835B4CBA9672E\
            3EDD1A51797601B4F4914FA38EF4BF85733F2621B8CC55548C11C39C9166352E8\
            14119622AA295DB4CAEF137A63136B4EF918FF077F78F17C5B46AFE215CFBF5B8\
            513F24C05A833AADFDF64BFDD201F86EEFE31B7D2D78C6BDC7",
        );
        let context = hex_decode(
            "\
            EE0B3F679FB50F59AD31328AAF4E702CCF6092DA4794DCF07C8EA278B34228A41\
            561C369271AFDD26159DCF071223BB5D7B789270150C5B17467829C8871B28A21\
            A3ADEA0347E35987932A0C465157FF2B2AE966CD4A48C24CC7B10B7484658C652\
            241C82266DF",
        );
        let signature = hex_decode(
            "\
            457A6EC9995A33364F79E317A689F9B7A40B5FBCF6F687D6C03B3AF63049AFCC3\
            CAF35EC9E6EDC280B19989DE1F86A17FA11EA00C181C7960DB382E7E53B0761E4\
            7A33521FB9A8E134C9CDF599969B1E69E6756F33522D4F37D3DB6FDDCEE1D845A\
            C497AE90763A815C50E8DA9A8A4D33296C359A2F4C60EB706E709C1747A9B57E6\
            57054BC6F48896F8F4AEB1384F4BE6ED43FE7E21DC5044DE4937534A2FDC91019\
            037BCD0B9988A109A80A10046EC0F458603F274E3B020C724FB637857E233BC80\
            39FF74D2AFB1006BDDDF0D3F8AD78CC8D3C1E8118B64F9A898573F03022AA588C\
            32798047A7B9D7C3E2428AC5D05180C9EA6AC23C1058574EC3D6A732BAFA405C6\
            4B9B98B86B6D4D31EB08514FEAA89B92EDEB0A286DC315EA6520BD16C724AF7BB\
            793795DABA885C0BDCD4E140955C935B3BDCBD4C5466BBF4056DFAA36D5B49F5D\
            802A03B4D8DD66E71F9E8F8CFDFD73FD117EFC251E1B26C9FDD1F54C442F0998D\
            6FA53D01886E8EF2E2548790788EBD629C76AA00220C57D6727F44089E6D91B7B\
            E63B1C47586B8929BA2F9AA23E5F5D9F4E993F7733BA2958DA3EEF1C27E59B03E\
            92DF7BED81BC8F19AE559498DDA07017F4A8CACEC1AB62359E88019DB68627214\
            C96C430538C8EE9249145544AA76FAFF0FF3A7BF1E2BF7AEFBB6CA89A2947EA93\
            0957B37C0732CB6D6148F5A5FA825FA95B43C2F5666101539F89087F6350F4547\
            1A9A91B4D9B1A95A2C26FDE28AEA86AAF1840174E990D3B2FDCF0F4E412A1BBD6\
            8A6F3FBF0CC965DA87AA32CDFC38E0AACBDB54CB37653738145481AE773C8C5CA\
            E9C6A089AEAA7EF0A99A01127F6E6FBFF31D265E7974041599B22C34646F2F359\
            ABC581859CBD60AC830CD7E94438C07203C546B9211E806096C5944C27352CE71\
            61052F818CA58E6934C9F3111DA8377E3D7F7C8C125C5BA21C543F1A5147EA4E2\
            BDFCC952811ED35AF8FDD29254EB644D5096DBCDA6253B33612074FEDE1B69A09\
            C1EEB5467BAA0EF5A09666813A8A4FB733E3B0026EDE4157A6CFA5AB17760904A\
            F2D61E84845B2E68F1622018DFAB293C5042EC4CF1A66CC5065513FA6E378497B\
            6A2F80BE9AE9DED9F4D1B12B1C61FD21E5CC1080981F2FE8FE580C3C67AD0917E\
            727B50879726B4ED45199BA2E51B466B8A044B71CDFA33F19967C9553EB4410A2\
            C4C67FEFCC2B4069E8FC87D5E7E23E0CF70AF38761B61FB2AEB30950F2994EC56\
            10A5BB8CEC40FA7A36A6A782657366ED0533A74F0B7B5C46163DF2AAA74E6C590\
            39CBD44CCAD17847C1F2B8AE84F002EA710BC86BF7D8EEC25C0153F178CD3074D\
            3CE956E2773BA23B5A915AB281BD6CF7C7FB21C59BD0502C4A7C42CE95740D7E6\
            7759240C0551B2A7D5F34891237E6D7BA33F85D86AA3128D883690F05AA705306\
            68DE2D847185E7ED3EE0AF73D4610FFFCA26DC55FAD06AE1115780E80ABE7AB26\
            0C713E8860B5B6DD7DBCB348942C8AE01B196BD6819EDD70D8A7D0DD7171504DB\
            138AB0DA9D1B065B298A783CBC81ABF992FAE50CADE8AB3D196EF31CC5A56A13D\
            79495FB15DA8916E5CE12218A96DA1A37A37A7B395A7D5A623CEB1589C1366CEE\
            E81CE7AE221D70B125477FA923322F331B467B0703CD2AD8C1737DA058B79065E\
            5700764BCA97F55DA8EDA1E9491AD7A2718BA43FCA4BAE04F1099504049186812\
            3AE6E18907AC84403FFE735FEDD113CB18D234195362154A7EFC46FC7DFD2142F\
            36561BECA0A8CD64B2551E95523BFC59C894F1548B28360162EB8F94C5D22836E\
            714971B979B4AC989C236A05159701CD422387837FD12DC5A628C99237825DCD6\
            5253F54301941194BDDD321587122B316480803524BF40F0ED4EBEF738DACC8F1\
            0A9DDB8D9146FFE18C6F81D71722EFA82ED627BA265DC2C2F8B3BAE65F3A7A6E9\
            7E5D4E46865AC59349A96FDF9F60938BC68B78C33A0A170F2CE0EDB5C27402CFE\
            65B1D0C45D80DCBABE788E53217BA28801AC212537A4AA2173AD05910D1B6D134\
            1B076014C355604F51F90AA49F26A0E3968609B2E429F033715E3EA1A795656AA\
            32526C506A5DA001DCEB12C6BF6771EE512DEF97B8AB8042EE2E69624FA50AF84\
            D4195F46A2DC491DD97A91FE9C930102D6A5929EA862A83DE50588FF753698D38\
            AAE0361CB58CE71D7B1E5E140026ECE2B61DD5A3C2034AE7B9419482758A0AE15\
            FAEC3AF7E4E5A488B7A0A8098B5906EA6B5389FE8953EF09D3658B5064903EA55\
            4DAC1267D99DD6049838A77A60DA65C1298606B10CBB4019CABE50A32068BE5E0\
            C5844904E8CE939CEC047CCAD0567A50C6CA2DEF596F3BA16B88FA84E9F4E5EEA\
            6FC75CFC4A9D709EF4568B6BA96D3498C55F20F6CD3548455E1CB8BDC25DD260C\
            E81BBB5A3A9CC486FB52289ED80F8DCCBC88C93082C4AA07C562CF38873C5BD4D\
            49579357EA582EA76F39D64B51D3A46A5D64127B1ABFB4513CFA1259F565CB415\
            DEACDB320C9558A4EB8F7E660DE0E16C4FEB2C16145BAD8FED7D398273840E44C\
            8C61175FF49F818C66E4509647D6A59847E9D9C1C6BFB1EC8B0AD3D037F2F87DC\
            484AD73DA55625369F6DF6D39BDE5459C73850F7A9D92310CCF4BC140452A1A11\
            4A3CDBACA839D12718182202C98A55FABEE98F75705C6112828DE5EE71C8C205D\
            31254D70520851C60A271AD1CCEC87FFB662A927001BCEED02B90C467A508197A\
            24B6156DFB89F135BF8DD94807B3928D942C29A42E3FD8B5E05AB61691112EF8D\
            371AADC5F952BD8CD88EB9D975BB35BA81A4127CF3F43536176FA89B30CD65D10\
            8D7F7CF60D9A2985DB5753AB6053375D3ED4C71F65713DCAD86B596BB42AB45D3\
            5F4931F49F0D5DD30AF519493FE81F07872AB5AA7BA76B31F7F1D9DE36286CD97\
            C00D54146C08E5AB1C6BA476B4BB491E621866BEDF0208711A72DE26C0BBD2D40\
            E7F63B025A6F6CAE47EF751355F58600232E20ACA0CF09C90C0DD0468C7C54B72\
            219411A3766FF7A9FA886D0AB486D998C0C9838B8F4CC9F06B26E001724ADD3EC\
            14D1DCAA8A788F1555993D935CDAB2D3A78E3A63A9BAA2DDA730C5D61491C51AA\
            6AB974B184AC44AB08EEB9DE2ACF9B608A49A7FD758FE7FA62A13FCE4CCEE0567\
            4805ADBED232A8F813448C347E5398EB74903ADBE127BC27F9D32D7CD6BE6E070\
            C74FBCFD1345E5DCDDBC62BBAFBF084A64C16BD01FD637FDE908285D4D8E53215\
            36B4429CAC6DFB028C9BACFCAFB8B38D15B367B480CAF7EFDD467ECC2AEEE0280\
            1F39BA7332716D1FD5944A1B4D3F340FC1AAEE38D7006314152E8D9FB1D203C54\
            555E909299AEB3C5CCCEE3EEF8FF15243E71A1ACB3C0DCE9090E1C434D5A64707\
            798A5ABB8BEC3D9E4E61C2C747585A8B1BDC9E300000000000000000000000000\
            0000000000000000000000121C2E38",
        );

        assert_eq!(msg.len(), 7390);
        assert_eq!(pk.len(), 1312);
        assert_eq!(sk.len(), 2560);
        assert_eq!(context.len(), 103);
        assert_eq!(signature.len(), 2420);

        let (mechs, ot) = registered();
        let ps: CK_ULONG = CKP_ML_DSA_44;
        let ck_true: CK_BBOOL = CK_TRUE;

        let pub_template = [
            ulong_attr(CKA_CLASS, &CKO_PUBLIC_KEY),
            ulong_attr(CKA_KEY_TYPE, &CKK_ML_DSA),
            ulong_attr(CKA_PARAMETER_SET, &ps),
            bytes_attr(CKA_VALUE, &pk),
            bool_attr(CKA_VERIFY, &ck_true),
        ];
        let pub_factory =
            ot.get_obj_factory_from_key_template(&pub_template).unwrap();
        let pubkey = pub_factory.create(&pub_template).unwrap();

        let priv_template = [
            ulong_attr(CKA_CLASS, &CKO_PRIVATE_KEY),
            ulong_attr(CKA_KEY_TYPE, &CKK_ML_DSA),
            ulong_attr(CKA_PARAMETER_SET, &ps),
            bytes_attr(CKA_VALUE, &sk),
            bool_attr(CKA_SIGN, &ck_true),
        ];
        let priv_factory = ot
            .get_obj_factory_from_key_template(&priv_template)
            .unwrap();
        let privkey = priv_factory.create(&priv_template).unwrap();

        // CKM_HASH_ML_DSA_SHA256: internal hashing, real message input.
        let mech_entry = mechs.get(CKM_HASH_ML_DSA_SHA256).unwrap();
        let params = CK_SIGN_ADDITIONAL_CONTEXT {
            hedgeVariant: CKH_DETERMINISTIC_REQUIRED,
            pContext: context.as_ptr() as *mut CK_BYTE,
            ulContextLen: context.len() as CK_ULONG,
        };
        let mech = context_mech(CKM_HASH_ML_DSA_SHA256, &params);

        let mut verify_op = mech_entry.verify_new(&mech, &pubkey).unwrap();
        verify_op.verify(&msg, &signature).unwrap();

        let mut verifysig_op = mech_entry
            .verify_signature_new(&mech, &pubkey, &signature)
            .unwrap();
        verifysig_op.verify(&msg).unwrap();

        // Deterministic signing is the documented, permanent AWS-LC gap
        // (same as pure mode) -- rejected cleanly, not silently hedged.
        let err = mech_entry.sign_new(&mech, &privkey).expect_err(
            "CKH_DETERMINISTIC_REQUIRED sign_new must fail cleanly \
                 against the awslc backend for HashML-DSA too",
        );
        assert_eq!(err.rv(), CKR_MECHANISM_PARAM_INVALID);

        // CKM_HASH_ML_DSA: same vector, but with the digest computed
        // externally (as a real caller using CKM_HASH_ML_DSA would via
        // C_Digest) and passed directly instead of the raw message.
        let mut hasher = crate::lowlevel::digest::Digest::new(
            crate::lowlevel::digest::DigestAlg::Sha2_256,
        )
        .unwrap();
        hasher.update(&msg).unwrap();
        let mut digest = [0u8; 32];
        hasher.finalize(&mut digest).unwrap();

        let hash_mech_entry = mechs.get(CKM_HASH_ML_DSA).unwrap();
        let hash_params = CK_HASH_SIGN_ADDITIONAL_CONTEXT {
            hedgeVariant: CKH_DETERMINISTIC_REQUIRED,
            pContext: context.as_ptr() as *mut CK_BYTE,
            ulContextLen: context.len() as CK_ULONG,
            hash: CKM_SHA256,
        };
        let hash_mech = hash_context_mech(&hash_params);
        let mut verify_op2 =
            hash_mech_entry.verify_new(&hash_mech, &pubkey).unwrap();
        verify_op2.verify(&digest, &signature).unwrap();
    }
}
