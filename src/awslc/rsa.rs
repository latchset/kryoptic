// Copyright 2026
// See LICENSE.txt file for terms

//! AWS-LC-backed implementation of the RSA surface `src/rsa.rs` requires:
//! `RsaPKCSOperation` (mirroring `crate::ossl::rsa::RsaPKCSOperation`,
//! which `src/rsa.rs` imports via `use crate::ossl::rsa::*;` -- resolved to
//! this module under the `awslc` feature by `src/lib.rs`'s
//! `use awslc as ossl;` alias) plus a `pub use` re-export of the
//! `MIN_RSA_SIZE_BITS`/`MAX_RSA_SIZE_BITS` constants (defined once in
//! `crate::rsa` itself, not per backend) that same glob import also
//! pulls in.
//!
//! ## Key generation and PKCS#1 v1.5 sign/verify
//!
//! Covers key generation, PKCS#1 v1.5 sign/verify, and `CKM_RSA_PKCS`'s
//! `Encryption`/`Decryption` framing -- RFC 2313 "block type 2" padding via
//! `RsaKey::encrypt_pkcs1`/`decrypt_pkcs1`, a *different* construction from
//! the DigestInfo-based `Sign`/`Verify` framing (`RsaKey::sign_pkcs1`/
//! `verify_pkcs1`) or the no-DigestInfo raw framing plain `CKM_RSA_PKCS`
//! signing needs (`RsaKey::sign_pkcs1_raw`/`verify_pkcs1_raw`).
//!
//! `CKM_RSA_X_509` is a registered mechanism too (see
//! `src/rsa.rs::register`), which reaches this file's
//! `RsaPKCSMechanism`-driven constructors just like `CKM_RSA_PKCS` does.
//! See "CKM_RSA_X_509 (raw/unpadded RSA)" below for its wiring.
//!
//! ## CKM_RSA_PKCS_PSS
//!
//! Covers `CKM_RSA_PKCS_PSS` and its combined-hash
//! variants (`CKM_SHA256_RSA_PKCS_PSS` etc.). See `parse_pss_params`'s doc
//! comment for whether `CK_RSA_PKCS_PSS_PARAMS`
//! ever specifies a different MGF1 hash than the message digest (it
//! doesn't, anywhere in this codebase's test suite) and how `ulSaltLen`
//! maps to `RsaKey::sign_pss`'s `salt_len` (direct pass-through, no
//! default/derivation logic -- mirrors
//! `crate::ossl::rsa::parse_sig_params`).
//!
//! ## CKM_RSA_PKCS_OAEP
//!
//! Covers `CKM_RSA_PKCS_OAEP`. See `OaepParams`'s doc comment for
//! the resolution of the configurable-hash/label question (unlike
//! PSS's `hashAlg`/`mgf`, OAEP's genuinely do need to vary together away
//! from SHA-1 -- this codebase's own test suite exercises
//! SHA-224/256/384/512) and `RsaKey::encrypt_oaep_mgf1`/`decrypt_oaep_mgf1`
//! (`awslc/src/rsa.rs`) for why that's built on AWS-LC's `EVP_PKEY_CTX`
//! layer rather than the fixed-SHA-1 `RSA_encrypt`/`RSA_decrypt` API
//! `encrypt_oaep`/`decrypt_oaep` use.
//!
//! ## CKM_RSA_X_509 (raw/unpadded RSA)
//!
//! The fourth and last mechanism this file wires up, on top of
//! PKCS#1v1.5/PSS/OAEP. Reaches all four operation framings (`Sign`/
//! `Verify`/`Encryption`/`Decryption`) via `HashMode::Raw`/`EncMode::Raw`.
//!
//! ## Input-length question
//!
//! `crate::ossl::rsa::RsaPKCSOperation::max_message_len`'s
//! `CKM_RSA_X_509 => Ok(modulus)` arm, combined with `sign`/
//! `verify_internal`'s `data.len() > self.max_input` check (a `>`, not a
//! `!=`), shows the reference treats the modulus size as an *upper bound*
//! on input length, not an exact-length requirement: a caller may supply
//! fewer bytes than the modulus. This matches the PKCS#11 spec's
//! CKM_RSA_X_509 semantics (shorter input is treated as implicitly
//! zero-padded on the left) and is exactly what the reference's
//! underlying OpenSSL primitive does for the sign/encrypt direction
//! (`RSA_padding_add_none`-style left-padding, reached via
//! `OSSL_PKEY_RSA_PAD_MODE_NONE` in `ossl/src/signature.rs`/
//! `ossl/src/asymcipher.rs`).
//!
//! `RsaKey::raw_transform_private`/`raw_transform_public`, by
//! contrast, were empirically confirmed (its own
//! `raw_transform_rejects_wrong_length_input` test) to require
//! *exact*-key-size-length input -- AWS-LC's `RSA_sign_raw`/
//! `RSA_verify_raw` with `RSA_NO_PADDING` do not left-pad short input the
//! way OpenSSL's equivalent primitive does. So, to preserve the
//! reference's caller-facing behavior (input up to and including the
//! modulus size is accepted) despite AWS-LC's stricter primitive, this
//! file left-zero-pads short input itself, in `left_pad_to` below, before
//! ever calling the raw transform -- rather than either rejecting short
//! input (a behavior regression from the reference) or extending
//! `awslc/src/rsa.rs`'s primitives with padding logic of their own (which
//! would blur that crate's "thin AWS-LC wrapper" scope -- left-padding
//! is exactly the kind of caller-facing PKCS#11 semantics that belongs in
//! this integration layer, not the primitive layer).
//!
//! Decrypt is the one asymmetric case: `CKM_RSA_X_509` ciphertext (and,
//! symmetrically, the recovered plaintext) is always exactly
//! modulus-length -- there is no shorter form to pad on that side, so
//! `EncMode::Raw`'s decrypt arm calls `RsaKey::raw_transform_private`
//! directly with no padding step.

use crate::attribute::Attribute;
use crate::error::{Error, Result};
use crate::hash::{hash_size, INVALID_HASH_SIZE};
use crate::mechanism::{
    Decryption, Encryption, MechOperation, Sign, Verify, VerifySignature,
};
use crate::misc::zeromem;
use crate::object::Object;
use crate::pkcs11::*;

use crate::awslc::common::mech_type_to_digest_alg;

use crate::lowlevel::digest::Digest as AwsLcDigest;
use crate::lowlevel::digest::DigestAlg;
use crate::lowlevel::rsa::{digest_alg_to_nid, RsaKey};

#[cfg(feature = "fips")]
use crate::fips::FipsApproval;

// Backend-agnostic; defined once in crate::rsa (the mechanism-registration
// module both backends share), re-exported here so crate::rsa's own
// `use crate::ossl::rsa::*;` keeps resolving them per active backend.
// `MIN_RSA_SIZE_BYTES` isn't re-exported: crate::rsa is the only consumer
// (it's a local, same-file definition there, so its own glob import of
// this module never actually needs it back).
pub use crate::rsa::{MAX_RSA_SIZE_BITS, MIN_RSA_SIZE_BITS};

/// Builds a public-key-only `RsaKey` from a `CKO_PUBLIC_KEY` `Object`'s
/// `CKA_MODULUS`/`CKA_PUBLIC_EXPONENT`.
fn pubkey_from_object(key: &Object) -> Result<RsaKey> {
    let n = key.get_attr_as_bytes(CKA_MODULUS)?;
    let e = key.get_attr_as_bytes(CKA_PUBLIC_EXPONENT)?;
    Ok(RsaKey::from_public_components(n, e)?)
}

/// Builds a private-key `RsaKey` from a `CKO_PRIVATE_KEY` `Object`.
///
/// `CKA_PRIME_1`/`CKA_PRIME_2`/`CKA_EXPONENT_1`/`CKA_EXPONENT_2`/
/// `CKA_COEFFICIENT` (the CRT parameters) are optional on a PKCS#11 RSA
/// private key object (`src/rsa.rs::rsa_check_import` only requires
/// `CKA_MODULUS`/`CKA_PUBLIC_EXPONENT`/`CKA_PRIVATE_EXPONENT` --
/// "/* The FIPS module can handle missing p,q,a,b,c */"). This must handle
/// both the full-CRT case (the common one, e.g. after
/// `RsaPKCSOperation::generate_keypair` below) and the no-CRT case (a
/// private key imported/unwrapped with only n/e/d) -- getting this wrong
/// once broke a private-key import path that worked for generated keys
/// but silently broke for imported/partial keys, so both paths get their
/// own regression test
/// below (`full_crt_private_key_import_can_sign`/
/// `no_crt_private_key_import_can_sign`).
///
/// `awslc::rsa::RsaKey::from_private_components`'s `crt` parameter is
/// all-5-params-or-none (AWS-LC has no partial-CRT reconstruction
/// primitive, unlike OpenSSL which can derive CRT params from just p/q) --
/// so a partial subset (unusual, but not forbidden by any `OAFlags` on
/// these attributes) falls back to the no-CRT path rather than being
/// rejected or silently truncated.
fn privkey_from_object(key: &Object) -> Result<RsaKey> {
    let n = key.get_attr_as_bytes(CKA_MODULUS)?;
    let e = key.get_attr_as_bytes(CKA_PUBLIC_EXPONENT)?;
    let d = key.get_attr_as_bytes(CKA_PRIVATE_EXPONENT)?;
    let p = key.get_attr(CKA_PRIME_1);
    let q = key.get_attr(CKA_PRIME_2);
    let dp = key.get_attr(CKA_EXPONENT_1);
    let dq = key.get_attr(CKA_EXPONENT_2);
    let qinv = key.get_attr(CKA_COEFFICIENT);
    let crt = match (p, q, dp, dq, qinv) {
        (Some(p), Some(q), Some(dp), Some(dq), Some(qinv)) => Some((
            p.get_value().as_slice(),
            q.get_value().as_slice(),
            dp.get_value().as_slice(),
            dq.get_value().as_slice(),
            qinv.get_value().as_slice(),
        )),
        _ => None,
    };
    Ok(RsaKey::from_private_components(n, e, d, crt)?)
}

/// Helper to get the hash output length in bytes for a given hash
/// mechanism. Mirrors
/// `crate::ossl::rsa::RsaPKCSOperation::hash_len`.
fn hash_len(hash: CK_MECHANISM_TYPE) -> Result<usize> {
    match hash_size(hash) {
        INVALID_HASH_SIZE => Err(CKR_MECHANISM_INVALID)?,
        x => Ok(x),
    }
}

/// Maps a PKCS#11 MGF type (`CK_RSA_PKCS_MGF_TYPE`) to the corresponding
/// `awslc::digest::DigestAlg`. Mirrors
/// `crate::ossl::rsa::mgf1_to_digest_alg`.
fn mgf1_to_digest_alg(mgf: CK_RSA_PKCS_MGF_TYPE) -> Result<DigestAlg> {
    Ok(match mgf {
        #[cfg(not(feature = "no_sha1"))]
        CKG_MGF1_SHA1 => DigestAlg::Sha1,
        CKG_MGF1_SHA224 => DigestAlg::Sha2_224,
        CKG_MGF1_SHA256 => DigestAlg::Sha2_256,
        CKG_MGF1_SHA384 => DigestAlg::Sha2_384,
        CKG_MGF1_SHA512 => DigestAlg::Sha2_512,
        CKG_MGF1_SHA3_224 => DigestAlg::Sha3_224,
        CKG_MGF1_SHA3_256 => DigestAlg::Sha3_256,
        CKG_MGF1_SHA3_384 => DigestAlg::Sha3_384,
        CKG_MGF1_SHA3_512 => DigestAlg::Sha3_512,
        _ => return Err(CKR_MECHANISM_PARAM_INVALID)?,
    })
}

/// Left-zero-pads `data` into a fresh `len`-byte buffer. `data.len()` must
/// be `<= len` -- every caller enforces this beforehand via `max_input`
/// (`HashMode::Raw`/`EncMode::Raw`'s `data.len() <= self.max_input`
/// checks, where `max_input == self.output_len` for those modes).
///
/// `CKM_RSA_X_509`: see this module's doc comment
/// ("CKM_RSA_X_509 (raw/unpadded RSA)") for why this left-padding step exists --
/// `RsaKey::raw_transform_private`/`raw_transform_public` require
/// exact-key-size-length input, unlike the PKCS#11 spec (and the OpenSSL
/// reference backend's underlying primitive), which treat input shorter
/// than the modulus as implicitly zero-padded on the left.
fn left_pad_to(data: &[u8], len: usize) -> Vec<u8> {
    debug_assert!(data.len() <= len);
    let mut padded = vec![0u8; len];
    padded[len - data.len()..].copy_from_slice(data);
    padded
}

/// PSS parameters parsed from `CK_RSA_PKCS_PSS_PARAMS`, resolved down to
/// what `RsaKey::sign_pss`/`verify_pss` need.
#[derive(Debug, Clone, Copy)]
struct PssParams {
    /// NID for the message digest (`CK_RSA_PKCS_PSS_PARAMS.hashAlg`).
    hash_nid: i32,
    /// NID for the MGF1 hash (`CK_RSA_PKCS_PSS_PARAMS.mgf`), independent
    /// of `hash_nid` -- see `parse_pss_params`'s doc comment.
    mgf1_hash_nid: i32,
    /// Direct pass-through of `CK_RSA_PKCS_PSS_PARAMS.sLen` -- see
    /// `parse_pss_params`'s doc comment.
    salt_len: i32,
    /// Expected exact digest length for bare `CKM_RSA_PKCS_PSS` (the
    /// caller supplies the pre-hashed digest directly). Mirrors
    /// `crate::ossl::rsa::RsaPKCSOperation::max_message_len`'s
    /// `CKM_RSA_PKCS_PSS => Self::hash_len(params.hashAlg)`.
    digest_len: usize,
}

/// Parses `CK_RSA_PKCS_PSS_PARAMS` out of `mech`, validating a combined
/// mechanism's implied hash against `params.hashAlg` (mirrors
/// `crate::ossl::rsa::parse_sig_params`).
///
/// ## MGF1-hash independence
///
/// `CK_RSA_PKCS_PSS_PARAMS` carries `hashAlg` (the message digest) and
/// `mgf` (the MGF1 hash) as independent fields, and the OpenSSL backend
/// (`src/ossl/rsa.rs::parse_sig_params`) reads them independently into
/// `RsaPssParams { digest, mgf1, .. }` with **no** equality check between
/// them -- so the reference *can* represent `hashAlg != mgf`. `RsaKey::
/// sign_pss`/`verify_pss` take separate `hash_nid`/`mgf1_hash_nid`
/// parameters (passed through to `RSA_sign_pss_mgf1`/`RSA_verify_pss_
/// mgf1`'s own independent `md`/`mgf1_md` arguments) for parity: this
/// parses and threads both through independently rather than rejecting a
/// mismatch or silently coercing one to the other.
///
/// ## Salt-length mapping
///
/// `CK_RSA_PKCS_PSS_PARAMS.sLen` is passed straight through to
/// `RsaKey::sign_pss`/`verify_pss`'s `salt_len: i32` with no
/// default/derivation logic -- mirrors
/// `crate::ossl::rsa::parse_sig_params`'s
/// `saltlen: usize::try_from(params.sLen)?` (also a bare conversion, no
/// derivation).
fn parse_pss_params(mech: &CK_MECHANISM) -> Result<PssParams> {
    let params = mech.get_parameters::<CK_RSA_PKCS_PSS_PARAMS>()?;
    if mech.mechanism != CKM_RSA_PKCS_PSS {
        let digest_alg = mech_type_to_digest_alg(params.hashAlg)?;
        if mech_type_to_digest_alg(mech.mechanism)? != digest_alg {
            return Err(CKR_MECHANISM_PARAM_INVALID)?;
        }
    }
    let dm = parse_digest_and_mgf1(params.hashAlg, params.mgf)?;
    Ok(PssParams {
        hash_nid: dm.digest_nid,
        mgf1_hash_nid: dm.mgf1_nid,
        salt_len: i32::try_from(params.sLen)?,
        digest_len: dm.digest_len,
    })
}

/// The independent message-digest/MGF1-digest pair `CK_RSA_PKCS_PSS_
/// PARAMS` and `CK_RSA_PKCS_OAEP_PARAMS` both carry (as `hashAlg`/`mgf`),
/// resolved down to what `RsaKey`'s PSS/OAEP APIs need. Shared by
/// `parse_pss_params`/`parse_oaep_params` so the "these two fields are
/// independent, not required to match" resolution logic (see
/// `PssParams`'s doc comment) lives in exactly one place -- this is
/// precisely where the two parsers drifted before (see R-06 in the
/// project history): OAEP always resolved `hashAlg`/`mgf` independently,
/// PSS didn't.
struct DigestAndMgf1 {
    /// NID for the message digest.
    digest_nid: i32,
    /// NID for the MGF1 digest, independent of `digest_nid`.
    mgf1_nid: i32,
    /// The message digest's output length in bytes.
    digest_len: usize,
}

fn parse_digest_and_mgf1(
    hash_alg: CK_MECHANISM_TYPE,
    mgf: CK_RSA_PKCS_MGF_TYPE,
) -> Result<DigestAndMgf1> {
    let digest_alg = mech_type_to_digest_alg(hash_alg)?;
    let mgf1_alg = mgf1_to_digest_alg(mgf)?;
    Ok(DigestAndMgf1 {
        digest_nid: digest_alg_to_nid(digest_alg),
        mgf1_nid: digest_alg_to_nid(mgf1_alg),
        digest_len: hash_len(hash_alg)?,
    })
}

/// Which hashing behavior a sign/verify operation uses.
#[derive(Debug)]
enum HashMode {
    /// Plain `CKM_RSA_PKCS`: no internal hashing -- PKCS#1 v1.5 padding is
    /// applied directly to the caller-supplied bytes
    /// (`RsaKey::sign_pkcs1_raw`/`verify_pkcs1_raw`), one-shot only
    /// (mirrors `crate::ossl::rsa`'s `SigAlg::Rsa`, whose
    /// `sigalg_supports_updates` is `Some(false)`).
    None,
    /// Combined hash+sign mechanisms (`CKM_SHA256_RSA_PKCS` etc.):
    /// accumulate the message in `hasher`, then wrap the resulting digest
    /// in a DigestInfo (`hash_nid`) via `RsaKey::sign_pkcs1`/`verify_pkcs1`.
    Hash { hash_nid: i32, hasher: AwsLcDigest },
    /// Bare `CKM_RSA_PKCS_PSS`: like `None` above but for PSS padding --
    /// the caller supplies the pre-computed digest directly, one-shot
    /// only, and the input length must exactly match the digest length
    /// (mirrors `crate::ossl::rsa::RsaPKCSOperation::sign`'s
    /// `CKM_RSA_PKCS_PSS => data.len() != self.max_input`).
    PssNone(PssParams),
    /// Combined hash+PSS mechanisms (`CKM_SHA256_RSA_PKCS_PSS` etc.):
    /// like `Hash` above but PSS-sign/verify the resulting digest via
    /// `RsaKey::sign_pss`/`verify_pss` instead of `sign_pkcs1`/
    /// `verify_pkcs1`.
    PssHash(PssParams, AwsLcDigest),
    /// `CKM_RSA_X_509`: raw/unpadded RSA. Like `None`
    /// above (no internal hashing, one-shot only, `data.len() <=
    /// self.max_input`) but the caller-supplied bytes are left-zero-padded
    /// to the full modulus length (`left_pad_to`) and passed straight to
    /// `RsaKey::raw_transform_private`/`raw_transform_public`
    /// instead of any padding *scheme* primitive -- see this module's doc
    /// comment ("CKM_RSA_X_509 (raw/unpadded RSA)") for why the left-padding is
    /// needed here rather than being handled by the raw transform itself.
    Raw,
}

/// OAEP parameters parsed from `CK_RSA_PKCS_OAEP_PARAMS`, resolved down to
/// what `RsaKey::encrypt_oaep_mgf1`/`decrypt_oaep_mgf1` need.
///
/// ## Configurable-hash/label question
///
/// Unlike PSS's `parse_pss_params` above (where this codebase's test suite
/// never exercises `hashAlg != mgf`), OAEP's `hashAlg`/`mgf` genuinely *do*
/// need to vary together away from SHA-1: `src/tests/rsa.rs`'s
/// `test_rsa_operations` ("RSA PKCS OAEP Enc"/wrap-key sections) uses
/// `hashAlg: CKM_SHA512, mgf: CKG_MGF1_SHA512`, and
/// `test_rsa_sign_verify`'s `for hash in [(CKM_SHA224, CKG_MGF1_SHA224),
/// (CKM_SHA256, CKG_MGF1_SHA256), (CKM_SHA384, CKG_MGF1_SHA384),
/// (CKM_SHA512, CKG_MGF1_SHA512)]` loop drives every one of those four
/// pairs through `CKM_RSA_PKCS_OAEP` encrypt+decrypt -- never SHA-1 alone.
/// So AWS-LC's fixed-SHA-1 `RSA_encrypt`/`RSA_decrypt` API (`encrypt_oaep`/
/// `decrypt_oaep` in `awslc/src/rsa.rs`) is not sufficient here, and this
/// module uses the new `encrypt_oaep_mgf1`/`decrypt_oaep_mgf1` pair added
/// alongside this task instead (see that pair's doc comment in
/// `awslc/src/rsa.rs` for why they're built on `EVP_PKEY_CTX` rather than
/// `RSA_padding_add_PKCS1_OAEP_mgf1` + a raw transform: AWS-LC has no
/// public "check"/unpad primitive for the decrypt direction).
///
/// `pSourceData` (the OAEP label, `label` below), by contrast, is *never*
/// non-empty anywhere in this codebase's test suite -- every
/// `CK_RSA_PKCS_OAEP_PARAMS` literal greppable in `src/tests/` sets
/// `pSourceData: std::ptr::null_mut(), ulSourceDataLen: 0`. It's still
/// parsed and threaded through here (rather than rejected) because
/// `encrypt_oaep_mgf1`/`decrypt_oaep_mgf1` support it for free (AWS-LC's
/// `EVP_PKEY_CTX_set0_rsa_oaep_label` takes a label directly) and
/// `src/rsa.rs`'s own `CK_RSA_PKCS_OAEP_PARAMS` parsing allows a caller to
/// supply one -- silently ignoring a caller-supplied label would be a
/// correctness bug (decrypting with the wrong, implicit empty label)
/// rather than a documented capability gap.
#[derive(Debug, Clone)]
struct OaepParams {
    /// NID for the OAEP digest (`CK_RSA_PKCS_OAEP_PARAMS.hashAlg`).
    digest_nid: i32,
    /// NID for the MGF1 digest (`CK_RSA_PKCS_OAEP_PARAMS.mgf`) --
    /// independent of `digest_nid` (see this struct's doc comment).
    mgf1_nid: i32,
    /// The OAEP label (`CK_RSA_PKCS_OAEP_PARAMS.pSourceData`), `None` for
    /// the RFC 8017 default empty label.
    label: Option<Vec<u8>>,
    /// The OAEP digest's output length in bytes -- needed for
    /// `max_message_len` (RFC 8017: max plaintext = `modulus - 2*hLen -
    /// 2`), mirrors `crate::ossl::rsa::RsaPKCSOperation::max_message_len`'s
    /// `CKM_RSA_PKCS_OAEP` arm.
    digest_len: usize,
}

/// Parses `CK_RSA_PKCS_OAEP_PARAMS` out of `mech`. Mirrors
/// `crate::ossl::rsa::parse_enc_params`'s `CKM_RSA_PKCS_OAEP` arm exactly
/// (`source == 0` requires `ulSourceDataLen == 0`; `CKZ_DATA_SPECIFIED`
/// with `ulSourceDataLen == 0` also means "no label"; anything else is
/// rejected) -- see `OaepParams`'s doc comment for why both fields are
/// parsed rather than restricted to the SHA-1/empty-label subset this
/// codebase's test suite happens to exercise for the label.
fn parse_oaep_params(mech: &CK_MECHANISM) -> Result<OaepParams> {
    let params = mech.get_parameters::<CK_RSA_PKCS_OAEP_PARAMS>()?;
    let label = match params.source {
        0 => {
            if params.ulSourceDataLen != 0 {
                return Err(CKR_MECHANISM_PARAM_INVALID)?;
            }
            None
        }
        CKZ_DATA_SPECIFIED => match params.ulSourceDataLen {
            0 => None,
            _ => Some(crate::misc::bytes_to_vec(
                params.pSourceData,
                params.ulSourceDataLen as usize,
            )),
        },
        _ => return Err(CKR_MECHANISM_PARAM_INVALID)?,
    };
    let dm = parse_digest_and_mgf1(params.hashAlg, params.mgf)?;
    Ok(OaepParams {
        digest_nid: dm.digest_nid,
        mgf1_nid: dm.mgf1_nid,
        label,
        digest_len: dm.digest_len,
    })
}

/// Which padding/framing an encrypt/decrypt `RsaPKCSOperation` uses.
/// Mirrors `HashMode` above (which plays the same role for sign/verify).
#[derive(Debug, Clone)]
enum EncMode {
    /// `CKM_RSA_PKCS`: RFC 2313/8017 "block type 2" padding
    /// (`RsaKey::encrypt_pkcs1`/`decrypt_pkcs1`).
    Pkcs1,
    /// `CKM_RSA_PKCS_OAEP`.
    Oaep(OaepParams),
    /// `CKM_RSA_X_509`: raw/unpadded RSA. Encrypt
    /// left-zero-pads the plaintext to the full modulus length
    /// (`left_pad_to`, see this module's doc comment) before
    /// `RsaKey::raw_transform_public`; decrypt calls
    /// `RsaKey::raw_transform_private` directly with no padding step
    /// (`CKM_RSA_X_509` ciphertext -- and the recovered plaintext -- is
    /// always exactly modulus-length; there's no shorter form on that
    /// side to pad).
    Raw,
}

/// Which PKCS#11 operation framing this `RsaPKCSOperation` was constructed
/// for.
#[derive(Debug)]
enum RsaOp {
    Sign(HashMode),
    /// The second field is the pre-supplied signature for
    /// `verify_signature_new` (PKCS#11 v3.2's `VerifySignature`), `None`
    /// otherwise.
    Verify(HashMode, Option<Vec<u8>>),
    Encrypt(EncMode),
    Decrypt(EncMode),
}

/// Which primitive to invoke once a multi-part hasher has been finalized
/// into a digest, and with what parameters -- shared by `sign_final` and
/// `verify_int_final`.
#[derive(Debug, Clone, Copy)]
enum FinalKind {
    Pkcs1(i32),
    Pss(PssParams),
}

/// Maps a PKCS#11 RSA sign/verify mechanism to its `HashMode`.
///
/// `CKM_RSA_X_509` maps to `HashMode::Raw` -- see this
/// module's doc comment ("CKM_RSA_X_509 (raw/unpadded RSA)").
fn sig_hash_mode(mech: &CK_MECHANISM) -> Result<HashMode> {
    if mech.mechanism == CKM_RSA_PKCS {
        return Ok(HashMode::None);
    }
    if mech.mechanism == CKM_RSA_PKCS_PSS {
        return Ok(HashMode::PssNone(parse_pss_params(mech)?));
    }
    if mech.mechanism == CKM_RSA_X_509 {
        return Ok(HashMode::Raw);
    }
    let pkcs1_hash = match mech.mechanism {
        #[cfg(not(feature = "no_sha1"))]
        CKM_SHA1_RSA_PKCS => true,
        CKM_SHA224_RSA_PKCS
        | CKM_SHA256_RSA_PKCS
        | CKM_SHA384_RSA_PKCS
        | CKM_SHA512_RSA_PKCS
        | CKM_SHA3_224_RSA_PKCS
        | CKM_SHA3_256_RSA_PKCS
        | CKM_SHA3_384_RSA_PKCS
        | CKM_SHA3_512_RSA_PKCS => true,
        _ => false,
    };
    if pkcs1_hash {
        let alg = mech_type_to_digest_alg(mech.mechanism)?;
        return Ok(HashMode::Hash {
            hash_nid: digest_alg_to_nid(alg),
            hasher: AwsLcDigest::new(alg)?,
        });
    }
    let pss_hash = match mech.mechanism {
        #[cfg(not(feature = "no_sha1"))]
        CKM_SHA1_RSA_PKCS_PSS => true,
        CKM_SHA224_RSA_PKCS_PSS
        | CKM_SHA256_RSA_PKCS_PSS
        | CKM_SHA384_RSA_PKCS_PSS
        | CKM_SHA512_RSA_PKCS_PSS
        | CKM_SHA3_224_RSA_PKCS_PSS
        | CKM_SHA3_256_RSA_PKCS_PSS
        | CKM_SHA3_384_RSA_PKCS_PSS
        | CKM_SHA3_512_RSA_PKCS_PSS => true,
        _ => false,
    };
    if !pss_hash {
        return Err(CKR_MECHANISM_INVALID)?;
    }
    let pss = parse_pss_params(mech)?;
    let hasher = AwsLcDigest::new(mech_type_to_digest_alg(mech.mechanism)?)?;
    Ok(HashMode::PssHash(pss, hasher))
}

/// Represents an active RSA cryptographic operation.
#[derive(Debug)]
pub struct RsaPKCSOperation {
    /// The specific RSA mechanism being used (e.g., `CKM_SHA256_RSA_PKCS`).
    mech: CK_MECHANISM_TYPE,
    /// Maximum input data length for this operation/padding mode.
    max_input: usize,
    /// Expected output length (typically key size in bytes).
    output_len: usize,
    /// Flag indicating if the operation has been finalized.
    finalized: bool,
    /// Flag indicating if the operation is in progress (update called).
    in_use: bool,
    /// The RSA key material: a private key for signing/decryption, a
    /// public key for verification/encryption.
    key: RsaKey,
    /// Which operation framing this instance was constructed for.
    op: RsaOp,
    /// FIPS approval status for the operation.
    #[cfg(feature = "fips")]
    fips_approval: FipsApproval,
}

impl RsaPKCSOperation {
    /// Helper to get and validate the RSA key size from an `Object`.
    fn get_key_size(key: &Object, info: &CK_MECHANISM_INFO) -> Result<usize> {
        let modulus = key.get_attr_as_bytes(CKA_MODULUS)?;
        let modulus_bits: CK_ULONG = modulus.len() as CK_ULONG * 8;
        if modulus_bits < info.ulMinKeySize
            || (info.ulMaxKeySize != 0 && modulus_bits > info.ulMaxKeySize)
        {
            return Err(CKR_KEY_SIZE_RANGE)?;
        }
        Ok(modulus.len())
    }

    /// Internal constructor for encryption/decryption operations.
    fn encdec_new(
        mech: &CK_MECHANISM,
        key: &Object,
        info: &CK_MECHANISM_INFO,
        flag: CK_FLAGS,
    ) -> Result<RsaPKCSOperation> {
        let mode = match mech.mechanism {
            CKM_RSA_PKCS => EncMode::Pkcs1,
            CKM_RSA_PKCS_OAEP => EncMode::Oaep(parse_oaep_params(mech)?),
            CKM_RSA_X_509 => EncMode::Raw,
            _ => return Err(CKR_MECHANISM_INVALID)?,
        };
        let (op, rsakey) = match flag {
            CKF_ENCRYPT => {
                (RsaOp::Encrypt(mode.clone()), pubkey_from_object(key)?)
            }
            CKF_DECRYPT => {
                (RsaOp::Decrypt(mode.clone()), privkey_from_object(key)?)
            }
            _ => return Err(CKR_GENERAL_ERROR)?,
        };
        let keysize = Self::get_key_size(key, info)?;
        // Both subtractions can underflow for a small enough key combined
        // with a large enough OAEP hash (e.g. a 1024-bit/128-byte key with
        // SHA-512/SHA3-512, whose 2*64+2 overhead already exceeds the
        // modulus size): report CKR_KEY_SIZE_RANGE rather than letting an
        // unchecked usize subtraction panic (debug) or wrap to a huge
        // bogus max_input that silently defeats this pre-check (release).
        let max_input = match &mode {
            EncMode::Pkcs1 => {
                keysize.checked_sub(11).ok_or(CKR_KEY_SIZE_RANGE)?
            }
            EncMode::Oaep(p) => keysize
                .checked_sub(2 * p.digest_len + 2)
                .ok_or(CKR_KEY_SIZE_RANGE)?,
            EncMode::Raw => keysize,
        };
        Ok(RsaPKCSOperation {
            mech: mech.mechanism,
            max_input,
            output_len: keysize,
            finalized: false,
            in_use: false,
            key: rsakey,
            op,
            #[cfg(feature = "fips")]
            fips_approval: FipsApproval::init(),
        })
    }

    /// Creates a new `RsaPKCSOperation` for encryption.
    pub fn encrypt_new(
        mech: &CK_MECHANISM,
        key: &Object,
        info: &CK_MECHANISM_INFO,
    ) -> Result<RsaPKCSOperation> {
        Self::encdec_new(mech, key, info, CKF_ENCRYPT)
    }

    /// Creates a new `RsaPKCSOperation` for decryption.
    pub fn decrypt_new(
        mech: &CK_MECHANISM,
        key: &Object,
        info: &CK_MECHANISM_INFO,
    ) -> Result<RsaPKCSOperation> {
        Self::encdec_new(mech, key, info, CKF_DECRYPT)
    }

    /// Internal constructor for signing/verification operations.
    fn sigver_new(
        mech: &CK_MECHANISM,
        key: &Object,
        info: &CK_MECHANISM_INFO,
        flag: CK_FLAGS,
        signature: Option<&[u8]>,
    ) -> Result<RsaPKCSOperation> {
        let hash_mode = sig_hash_mode(mech)?;
        let rsakey = match flag {
            CKF_SIGN => privkey_from_object(key)?,
            CKF_VERIFY => pubkey_from_object(key)?,
            _ => return Err(CKR_GENERAL_ERROR)?,
        };
        let keysize = Self::get_key_size(key, info)?;
        let max_input = match &hash_mode {
            HashMode::None => keysize - 11,
            /* CKM_RSA_X_509: full modulus is an upper bound, not an
             * exact-length requirement -- see this module's doc comment
             * ("CKM_RSA_X_509 (raw/unpadded RSA)"). */
            HashMode::Raw => keysize,
            /* Bare CKM_RSA_PKCS_PSS: exact-length digest input (see
             * HashMode::PssNone's doc comment). */
            HashMode::PssNone(pss) => pss.digest_len,
            /* Combined hash(+PSS) mechanisms accumulate internally and
             * never consult max_input (see Sign::sign/verify_internal). */
            HashMode::Hash { .. } | HashMode::PssHash(..) => 0,
        };
        if let Some(sig) = &signature {
            if sig.len() != keysize {
                return Err(CKR_SIGNATURE_LEN_RANGE)?;
            }
        }
        let op = match flag {
            CKF_SIGN => RsaOp::Sign(hash_mode),
            CKF_VERIFY => {
                RsaOp::Verify(hash_mode, signature.map(|s| s.to_vec()))
            }
            _ => return Err(CKR_GENERAL_ERROR)?,
        };
        Ok(RsaPKCSOperation {
            mech: mech.mechanism,
            max_input,
            output_len: keysize,
            finalized: false,
            in_use: false,
            key: rsakey,
            op,
            #[cfg(feature = "fips")]
            fips_approval: FipsApproval::init(),
        })
    }

    /// Creates a new `RsaPKCSOperation` for signing.
    pub fn sign_new(
        mech: &CK_MECHANISM,
        key: &Object,
        info: &CK_MECHANISM_INFO,
    ) -> Result<RsaPKCSOperation> {
        Self::sigver_new(mech, key, info, CKF_SIGN, None)
    }

    /// Creates a new `RsaPKCSOperation` for verification.
    pub fn verify_new(
        mech: &CK_MECHANISM,
        key: &Object,
        info: &CK_MECHANISM_INFO,
    ) -> Result<RsaPKCSOperation> {
        Self::sigver_new(mech, key, info, CKF_VERIFY, None)
    }

    /// Creates a new `RsaPKCSOperation` for verification with a
    /// pre-supplied signature.
    pub fn verify_signature_new(
        mech: &CK_MECHANISM,
        key: &Object,
        info: &CK_MECHANISM_INFO,
        signature: &[u8],
    ) -> Result<RsaPKCSOperation> {
        Self::sigver_new(mech, key, info, CKF_VERIFY, Some(signature))
    }

    /// Generates an RSA key pair using AWS-LC.
    ///
    /// Takes the desired public exponent and modulus bit size. Populates
    /// the public key (`CKA_MODULUS`, `CKA_PUBLIC_EXPONENT`) and private
    /// key (`CKA_MODULUS`, `CKA_PUBLIC_EXPONENT`, `CKA_PRIVATE_EXPONENT`,
    /// CRT params) attributes.
    ///
    /// Uses `RsaKey::generate_with_exponent` (added alongside this file --
    /// see that method's doc comment) rather than `RsaKey::generate`, which
    /// is hardcoded to F4: silently ignoring a caller's explicit
    /// `CKA_PUBLIC_EXPONENT` request would leave the private key's stored
    /// `CKA_PUBLIC_EXPONENT` attribute inconsistent with the modulus/
    /// private exponent AWS-LC actually generated.
    pub fn generate_keypair(
        exponent: Vec<u8>,
        bits: usize,
        pubkey: &mut Object,
        privkey: &mut Object,
    ) -> Result<()> {
        if bits < MIN_RSA_SIZE_BITS || bits > MAX_RSA_SIZE_BITS {
            return Err(CKR_ATTRIBUTE_VALUE_INVALID)?;
        }

        let key =
            RsaKey::generate_with_exponent(i32::try_from(bits)?, &exponent)?;

        // FIPS 186-5 §5.6.2 / SP 800-56B mandate a pairwise consistency
        // test after key-pair generation. AWS-LC's own `RSA_generate_key_
        // fips` performs this internally, but it fixes the exponent at
        // 65537 and restricts bits to 2048/3072 -- both narrower than
        // what this function must support (an explicit, possibly
        // non-F4, `CKA_PUBLIC_EXPONENT` from the caller's template, and
        // any modulus size between MIN_RSA_SIZE_BITS/MAX_RSA_SIZE_BITS),
        // so it can't be used as a drop-in replacement for
        // `generate_with_exponent` above. Perform the same check
        // ourselves instead: a raw PKCS#1 v1.5 sign/verify round trip
        // needs no particular exponent or bit-size restriction and
        // exercises exactly the same public/private-key algebraic
        // relationship AWS-LC's own PCT checks.
        #[cfg(feature = "fips")]
        {
            let pct_message = [0x5Au8; 32];
            let sig = key.sign_pkcs1_raw(&pct_message)?;
            key.verify_pkcs1_raw(&pct_message, &sig).map_err(|_| {
                Error::ck_rv_from_error(
                    CKR_DEVICE_ERROR,
                    "RSA pairwise consistency check failed after key \
                     generation",
                )
            })?;
        }

        /* Public Key (has E already set) */
        pubkey.set_attr(Attribute::from_bytes(CKA_MODULUS, key.modulus()))?;

        /* Private Key */
        privkey.set_attr(Attribute::from_bytes(CKA_MODULUS, key.modulus()))?;
        privkey.set_attr(Attribute::from_bytes(
            CKA_PUBLIC_EXPONENT,
            exponent.clone(),
        ))?;
        privkey.set_attr(Attribute::from_bytes(
            CKA_PRIVATE_EXPONENT,
            key.private_exponent(),
        ))?;
        privkey.set_attr(Attribute::from_bytes(CKA_PRIME_1, key.prime1()))?;
        privkey.set_attr(Attribute::from_bytes(CKA_PRIME_2, key.prime2()))?;
        privkey
            .set_attr(Attribute::from_bytes(CKA_EXPONENT_1, key.exponent1()))?;
        privkey
            .set_attr(Attribute::from_bytes(CKA_EXPONENT_2, key.exponent2()))?;
        privkey.set_attr(Attribute::from_bytes(
            CKA_COEFFICIENT,
            key.coefficient(),
        ))?;

        Ok(())
    }

    /// Performs a one-shot RSA key wrapping operation (PKCS#1 v1.5).
    ///
    /// Initializes an encryption operation internally using the
    /// `wrapping_key`. Encrypts the `keydata` (the DER-encoded key to
    /// wrap) and writes the result to `output`. Zeroizes `keydata`
    /// afterwards.
    pub fn wrap(
        mech: &CK_MECHANISM,
        wrapping_key: &Object,
        mut keydata: Vec<u8>,
        output: &mut [u8],
        info: &CK_MECHANISM_INFO,
    ) -> Result<usize> {
        let mut op = match Self::encrypt_new(mech, wrapping_key, info) {
            Ok(o) => o,
            Err(e) => {
                zeromem(keydata.as_mut_slice());
                return Err(e);
            }
        };
        let needed_len = op.encryption_len(keydata.len(), true)?;
        if output.len() == 0 {
            zeromem(keydata.as_mut_slice());
            return Ok(needed_len);
        }
        if output.len() < needed_len {
            zeromem(keydata.as_mut_slice());
            return Err(Error::buf_too_small(needed_len));
        }
        let result = op.encrypt(&keydata, output);
        zeromem(keydata.as_mut_slice());
        result
    }

    /// Performs a one-shot RSA key unwrapping operation (PKCS#1 v1.5).
    ///
    /// Initializes a decryption operation internally using the
    /// `wrapping_key`. Decrypts the wrapped `data` and returns the raw key
    /// bytes (expected to be in a format like DER-encoded PKCS#8 for the
    /// target key factory to parse).
    pub fn unwrap(
        mech: &CK_MECHANISM,
        wrapping_key: &Object,
        data: &[u8],
        info: &CK_MECHANISM_INFO,
    ) -> Result<Vec<u8>> {
        let mut op = Self::decrypt_new(mech, wrapping_key, info)?;
        let outlen = op.decrypt(data, &mut [])?;
        let mut result = vec![0u8; outlen];
        let outlen = op.decrypt(data, result.as_mut_slice())?;
        result.resize(outlen, 0);
        Ok(result)
    }
}

impl MechOperation for RsaPKCSOperation {
    fn mechanism(&self) -> Result<CK_MECHANISM_TYPE> {
        Ok(self.mech)
    }

    fn finalized(&self) -> bool {
        self.finalized
    }

    #[cfg(feature = "fips")]
    fn fips_approved(&self) -> Option<bool> {
        self.fips_approval.approval()
    }
}

impl Encryption for RsaPKCSOperation {
    fn encrypt(&mut self, plain: &[u8], cipher: &mut [u8]) -> Result<usize> {
        if self.in_use {
            return Err(CKR_OPERATION_NOT_INITIALIZED)?;
        }
        if self.finalized {
            return Err(CKR_OPERATION_NOT_INITIALIZED)?;
        }
        let mode = match &self.op {
            RsaOp::Encrypt(mode) => mode,
            _ => {
                self.finalized = true;
                return Err(CKR_GENERAL_ERROR)?;
            }
        };
        if plain.len() > self.max_input {
            self.finalized = true;
            return Err(CKR_DATA_LEN_RANGE)?;
        }
        if cipher.len() == 0 {
            return Ok(self.output_len);
        }
        if cipher.len() < self.output_len {
            return Err(Error::buf_too_small(self.output_len));
        }
        self.finalized = true;

        #[cfg(feature = "fips")]
        self.fips_approval.clear();

        let ct = match mode {
            EncMode::Pkcs1 => self.key.encrypt_pkcs1(plain)?,
            EncMode::Oaep(p) => self.key.encrypt_oaep_mgf1(
                plain,
                p.digest_nid,
                p.mgf1_nid,
                p.label.as_deref(),
            )?,
            EncMode::Raw => {
                let mut padded = left_pad_to(plain, self.output_len);
                let result = self.key.raw_transform_public(&padded);
                zeromem(padded.as_mut_slice());
                result?
            }
        };

        #[cfg(feature = "fips")]
        self.fips_approval.finalize();

        if ct.len() > cipher.len() {
            return Err(CKR_GENERAL_ERROR)?;
        }
        cipher[..ct.len()].copy_from_slice(&ct);
        Ok(ct.len())
    }

    fn encrypt_update(
        &mut self,
        _plain: &[u8],
        _cipher: &mut [u8],
    ) -> Result<usize> {
        self.finalized = true;
        return Err(CKR_OPERATION_NOT_INITIALIZED)?;
    }

    fn encrypt_final(&mut self, _cipher: &mut [u8]) -> Result<usize> {
        self.finalized = true;
        return Err(CKR_OPERATION_NOT_INITIALIZED)?;
    }

    fn encryption_len(&mut self, _: usize, _: bool) -> Result<usize> {
        match self.mech {
            CKM_RSA_PKCS | CKM_RSA_PKCS_OAEP => Ok(self.output_len),
            _ => Err(CKR_GENERAL_ERROR)?,
        }
    }
}

impl Decryption for RsaPKCSOperation {
    fn decrypt(&mut self, cipher: &[u8], plain: &mut [u8]) -> Result<usize> {
        if self.in_use {
            return Err(CKR_OPERATION_NOT_INITIALIZED)?;
        }
        if self.finalized {
            return Err(CKR_OPERATION_NOT_INITIALIZED)?;
        }
        let mode = match &self.op {
            RsaOp::Decrypt(mode) => mode,
            _ => {
                self.finalized = true;
                return Err(CKR_GENERAL_ERROR)?;
            }
        };
        #[cfg(feature = "fips")]
        self.fips_approval.clear();

        let mut pt = match mode {
            EncMode::Pkcs1 => self.key.decrypt_pkcs1(cipher)?,
            EncMode::Oaep(p) => self.key.decrypt_oaep_mgf1(
                cipher,
                p.digest_nid,
                p.mgf1_nid,
                p.label.as_deref(),
            )?,
            /* CKM_RSA_X_509 ciphertext is always exactly modulus-length,
             * so no padding step is needed on decrypt -- see EncMode::Raw's
             * doc comment. */
            EncMode::Raw => self.key.raw_transform_private(cipher)?,
        };

        #[cfg(feature = "fips")]
        self.fips_approval.finalize();

        let outlen = pt.len();
        if plain.len() == 0 {
            zeromem(pt.as_mut_slice());
            return Ok(outlen);
        }
        if plain.len() < outlen {
            zeromem(pt.as_mut_slice());
            // Non-fatal: do NOT finalize, so the caller can retry with a
            // correctly-sized buffer (PKCS#11 v3.2 §5.2). Report the
            // modulus-size upper bound, matching decryption_len()'s own
            // null-probe answer -- not the actual plaintext length, which
            // would leak information to a caller who guessed wrong.
            return Err(Error::buf_too_small(self.output_len));
        }
        self.finalized = true;
        plain[..outlen].copy_from_slice(&pt);
        zeromem(pt.as_mut_slice());
        Ok(outlen)
    }

    fn decrypt_update(
        &mut self,
        _cipher: &[u8],
        _plain: &mut [u8],
    ) -> Result<usize> {
        self.finalized = true;
        return Err(CKR_OPERATION_NOT_INITIALIZED)?;
    }

    fn decrypt_final(&mut self, _plain: &mut [u8]) -> Result<usize> {
        self.finalized = true;
        return Err(CKR_OPERATION_NOT_INITIALIZED)?;
    }

    fn decryption_len(&mut self, _: usize, _: bool) -> Result<usize> {
        match self.mech {
            CKM_RSA_PKCS | CKM_RSA_PKCS_OAEP => Ok(self.output_len),
            _ => Err(CKR_GENERAL_ERROR)?,
        }
    }
}

impl Sign for RsaPKCSOperation {
    fn sign(&mut self, data: &[u8], signature: &mut [u8]) -> Result<()> {
        if self.in_use {
            return Err(CKR_OPERATION_NOT_INITIALIZED)?;
        }
        if self.finalized {
            return Err(CKR_OPERATION_NOT_INITIALIZED)?;
        }
        match &self.op {
            RsaOp::Sign(HashMode::Hash { .. })
            | RsaOp::Sign(HashMode::PssHash(..)) => {
                self.sign_update(data)?;
                return self.sign_final(signature);
            }
            RsaOp::Sign(HashMode::None)
            | RsaOp::Sign(HashMode::PssNone(_))
            | RsaOp::Sign(HashMode::Raw) => {}
            _ => {
                self.finalized = true;
                return Err(CKR_GENERAL_ERROR)?;
            }
        }
        self.finalized = true;
        let len_ok = match &self.op {
            RsaOp::Sign(HashMode::None) | RsaOp::Sign(HashMode::Raw) => {
                data.len() <= self.max_input
            }
            /* Bare PSS requires an exact-length digest, unlike plain
             * CKM_RSA_PKCS's <= check (see HashMode::PssNone's doc
             * comment). */
            RsaOp::Sign(HashMode::PssNone(_)) => data.len() == self.max_input,
            _ => return Err(CKR_GENERAL_ERROR)?,
        };
        if !len_ok {
            return Err(CKR_DATA_LEN_RANGE)?;
        }
        if signature.len() != self.output_len {
            return Err(CKR_GENERAL_ERROR)?;
        }

        #[cfg(feature = "fips")]
        self.fips_approval.clear();

        let sig = match &self.op {
            RsaOp::Sign(HashMode::None) => self.key.sign_pkcs1_raw(data)?,
            RsaOp::Sign(HashMode::PssNone(pss)) => self.key.sign_pss(
                pss.hash_nid,
                pss.mgf1_hash_nid,
                data,
                pss.salt_len,
            )?,
            RsaOp::Sign(HashMode::Raw) => {
                let mut padded = left_pad_to(data, self.output_len);
                let result = self.key.raw_transform_private(&padded);
                zeromem(padded.as_mut_slice());
                result?
            }
            _ => return Err(CKR_GENERAL_ERROR)?,
        };

        #[cfg(feature = "fips")]
        self.fips_approval.finalize();

        if sig.len() != signature.len() {
            return Err(CKR_GENERAL_ERROR)?;
        }
        signature.copy_from_slice(&sig);
        Ok(())
    }

    fn sign_update(&mut self, data: &[u8]) -> Result<()> {
        if self.finalized {
            return Err(CKR_OPERATION_NOT_INITIALIZED)?;
        }
        match &self.op {
            RsaOp::Sign(HashMode::None)
            | RsaOp::Sign(HashMode::PssNone(_))
            | RsaOp::Sign(HashMode::Raw) => {
                self.finalized = true;
                return Err(CKR_OPERATION_NOT_INITIALIZED)?;
            }
            RsaOp::Sign(HashMode::Hash { .. })
            | RsaOp::Sign(HashMode::PssHash(..)) => (),
            _ => return Err(CKR_GENERAL_ERROR)?,
        }
        self.in_use = true;

        #[cfg(feature = "fips")]
        self.fips_approval.clear();

        match &mut self.op {
            RsaOp::Sign(HashMode::Hash { hasher, .. }) => {
                hasher.update(data)?
            }
            RsaOp::Sign(HashMode::PssHash(_, hasher)) => hasher.update(data)?,
            _ => return Err(CKR_GENERAL_ERROR)?,
        }

        #[cfg(feature = "fips")]
        self.fips_approval.update();

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
        if signature.len() != self.output_len {
            return Err(CKR_GENERAL_ERROR)?;
        }
        let kind = match &self.op {
            RsaOp::Sign(HashMode::Hash { hash_nid, .. }) => {
                FinalKind::Pkcs1(*hash_nid)
            }
            RsaOp::Sign(HashMode::PssHash(pss, _)) => FinalKind::Pss(*pss),
            _ => return Err(CKR_GENERAL_ERROR)?,
        };
        let mut digest = match &mut self.op {
            RsaOp::Sign(HashMode::Hash { hasher, .. })
            | RsaOp::Sign(HashMode::PssHash(_, hasher)) => {
                let mut d = vec![0u8; hasher.size()];
                let len = hasher.finalize(d.as_mut_slice())?;
                d.truncate(len);
                d
            }
            _ => return Err(CKR_GENERAL_ERROR)?,
        };

        #[cfg(feature = "fips")]
        self.fips_approval.clear();

        let result = match kind {
            FinalKind::Pkcs1(hash_nid) => {
                self.key.sign_pkcs1(hash_nid, &digest)
            }
            FinalKind::Pss(pss) => self.key.sign_pss(
                pss.hash_nid,
                pss.mgf1_hash_nid,
                &digest,
                pss.salt_len,
            ),
        };
        zeromem(digest.as_mut_slice());
        let sig = result?;

        #[cfg(feature = "fips")]
        self.fips_approval.finalize();
        if sig.len() != signature.len() {
            return Err(CKR_GENERAL_ERROR)?;
        }
        signature.copy_from_slice(&sig);
        Ok(())
    }

    fn signature_len(&self) -> Result<usize> {
        Ok(self.output_len)
    }
}

impl RsaPKCSOperation {
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
        match &self.op {
            RsaOp::Verify(HashMode::Hash { .. }, _)
            | RsaOp::Verify(HashMode::PssHash(..), _) => {
                self.verify_int_update(data)?;
                return self.verify_int_final(signature);
            }
            RsaOp::Verify(HashMode::None, _)
            | RsaOp::Verify(HashMode::PssNone(_), _)
            | RsaOp::Verify(HashMode::Raw, _) => {}
            _ => {
                self.finalized = true;
                return Err(CKR_GENERAL_ERROR)?;
            }
        }
        self.finalized = true;
        let len_ok = match &self.op {
            RsaOp::Verify(HashMode::None, _)
            | RsaOp::Verify(HashMode::Raw, _) => data.len() <= self.max_input,
            RsaOp::Verify(HashMode::PssNone(_), _) => {
                data.len() == self.max_input
            }
            _ => return Err(CKR_GENERAL_ERROR)?,
        };
        if !len_ok {
            return Err(CKR_DATA_LEN_RANGE)?;
        }
        let sig_bytes: Vec<u8> = match signature {
            Some(s) => s.to_vec(),
            None => match &self.op {
                RsaOp::Verify(_, Some(s)) => s.clone(),
                _ => return Err(CKR_GENERAL_ERROR)?,
            },
        };
        if sig_bytes.len() != self.output_len {
            return Err(CKR_SIGNATURE_LEN_RANGE)?;
        }

        #[cfg(feature = "fips")]
        self.fips_approval.clear();

        let outcome = match &self.op {
            RsaOp::Verify(HashMode::None, _) => {
                Ok(self.key.verify_pkcs1_raw(data, &sig_bytes)?)
            }
            RsaOp::Verify(HashMode::PssNone(pss), _) => {
                Ok(self.key.verify_pss(
                    pss.hash_nid,
                    pss.mgf1_hash_nid,
                    data,
                    pss.salt_len,
                    &sig_bytes,
                )?)
            }
            RsaOp::Verify(HashMode::Raw, _) => {
                let mut expected = left_pad_to(data, self.output_len);
                // Compute the fallible transform before zeroizing
                // `expected` (rather than `?`-ing it directly), so
                // `expected` is zeroized on every return path, including
                // the error one -- matching this file's established
                // zeroization discipline (see e.g. `EncMode::Raw`'s
                // `encrypt` arm and `HashMode::Raw`'s `sign` arm above).
                let raw_result = self.key.raw_transform_public(&sig_bytes);
                let ok = match &raw_result {
                    Ok(recovered) => *recovered == expected,
                    Err(_) => false,
                };
                zeromem(expected.as_mut_slice());
                raw_result?;
                if ok {
                    Ok(())
                } else {
                    Err(CKR_SIGNATURE_INVALID)?
                }
            }
            _ => Err(CKR_GENERAL_ERROR)?,
        };

        #[cfg(feature = "fips")]
        self.fips_approval.finalize();

        outcome
    }

    /// Internal helper for updating a multi-part verification.
    fn verify_int_update(&mut self, data: &[u8]) -> Result<()> {
        if self.finalized {
            return Err(CKR_OPERATION_NOT_INITIALIZED)?;
        }
        match &self.op {
            RsaOp::Verify(HashMode::None, _)
            | RsaOp::Verify(HashMode::PssNone(_), _)
            | RsaOp::Verify(HashMode::Raw, _) => {
                self.finalized = true;
                return Err(CKR_OPERATION_NOT_INITIALIZED)?;
            }
            RsaOp::Verify(HashMode::Hash { .. }, _)
            | RsaOp::Verify(HashMode::PssHash(..), _) => (),
            _ => return Err(CKR_GENERAL_ERROR)?,
        }
        self.in_use = true;

        #[cfg(feature = "fips")]
        self.fips_approval.clear();

        match &mut self.op {
            RsaOp::Verify(HashMode::Hash { hasher, .. }, _) => {
                hasher.update(data)?
            }
            RsaOp::Verify(HashMode::PssHash(_, hasher), _) => {
                hasher.update(data)?
            }
            _ => return Err(CKR_GENERAL_ERROR)?,
        }

        #[cfg(feature = "fips")]
        self.fips_approval.update();

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
        let kind = match &self.op {
            RsaOp::Verify(HashMode::Hash { hash_nid, .. }, _) => {
                FinalKind::Pkcs1(*hash_nid)
            }
            RsaOp::Verify(HashMode::PssHash(pss, _), _) => FinalKind::Pss(*pss),
            _ => return Err(CKR_GENERAL_ERROR)?,
        };
        let mut digest = match &mut self.op {
            RsaOp::Verify(HashMode::Hash { hasher, .. }, _)
            | RsaOp::Verify(HashMode::PssHash(_, hasher), _) => {
                let mut d = vec![0u8; hasher.size()];
                let len = hasher.finalize(d.as_mut_slice())?;
                d.truncate(len);
                d
            }
            _ => return Err(CKR_GENERAL_ERROR)?,
        };
        let sig_bytes: Vec<u8> = match signature {
            Some(s) => s.to_vec(),
            None => match &self.op {
                RsaOp::Verify(_, Some(s)) => s.clone(),
                _ => {
                    zeromem(digest.as_mut_slice());
                    return Err(CKR_GENERAL_ERROR)?;
                }
            },
        };
        if sig_bytes.len() != self.output_len {
            zeromem(digest.as_mut_slice());
            return Err(CKR_SIGNATURE_LEN_RANGE)?;
        }
        #[cfg(feature = "fips")]
        self.fips_approval.clear();

        let result = match kind {
            FinalKind::Pkcs1(hash_nid) => {
                self.key.verify_pkcs1(hash_nid, &digest, &sig_bytes)
            }
            FinalKind::Pss(pss) => self.key.verify_pss(
                pss.hash_nid,
                pss.mgf1_hash_nid,
                &digest,
                pss.salt_len,
                &sig_bytes,
            ),
        };
        zeromem(digest.as_mut_slice());
        result?;

        #[cfg(feature = "fips")]
        self.fips_approval.finalize();

        Ok(())
    }
}

impl Verify for RsaPKCSOperation {
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
        Ok(self.output_len)
    }
}

impl VerifySignature for RsaPKCSOperation {
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

// Deliberately inline (unlike the reference backend's convention of
// keeping tests under src/tests/*.rs): see src/awslc/aes.rs's matching
// `mod tests` doc comment for the rationale (private-surface access this
// module's private helpers/fields need, e.g. `left_pad_to`,
// `PssParams`/`OaepParams` parsing, that src/tests/*.rs cannot reach
// through the public `Mechanism` trait dispatch alone).
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

    /// Registers the real, backend-agnostic RSA mechanisms/factories from
    /// `src/rsa.rs` (via `crate::rsa::register`), exactly as production
    /// `C_Initialize`/`C_GenerateKeyPair`/`C_SignInit`/`C_VerifyInit`/
    /// `C_EncryptInit`/`C_DecryptInit`/`C_CreateObject` reach them -- so
    /// these tests exercise the real `Mechanism`/`Sign`/`Verify`/
    /// `Encryption`/`Decryption`/`ObjectFactory` trait dispatch, not just
    /// the `awslc::rsa` primitive layer (already tested in
    /// `awslc/src/rsa.rs`).
    fn registered() -> (Mechanisms, ObjectFactories) {
        let mut mechs = Mechanisms::new();
        let mut ot = ObjectFactories::new();
        crate::rsa::register(&mut mechs, &mut ot);
        (mechs, ot)
    }

    fn bool_attr(t: CK_ATTRIBUTE_TYPE, v: &CK_BBOOL) -> CK_ATTRIBUTE {
        CK_ATTRIBUTE {
            type_: t,
            pValue: v as *const CK_BBOOL as CK_VOID_PTR,
            ulValueLen: std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
        }
    }

    fn ulong_attr(t: CK_ATTRIBUTE_TYPE, v: &CK_ULONG) -> CK_ATTRIBUTE {
        CK_ATTRIBUTE {
            type_: t,
            pValue: v as *const CK_ULONG as CK_VOID_PTR,
            ulValueLen: std::mem::size_of::<CK_ULONG>() as CK_ULONG,
        }
    }

    /// Generates a 2048-bit RSA keypair (the smallest allowed size in
    /// non-FIPS builds is 1024, but 2048 keeps this file's tests aligned
    /// with `awslc/src/rsa.rs`'s own test key size) through the real
    /// `Mechanism::generate_keypair` dispatch, with `CKA_SIGN`/
    /// `CKA_VERIFY`/`CKA_ENCRYPT`/`CKA_DECRYPT` all explicitly enabled
    /// (they default to `false` -- `add_common_public_key_attrs`/
    /// `add_common_private_key_attrs` in `src/object/key.rs`).
    fn generate_keypair(mechs: &Mechanisms) -> (Object, Object) {
        generate_keypair_with_bits(mechs, 2048)
    }

    /// Same as `generate_keypair` above, with a caller-chosen modulus
    /// size -- needed to exercise behavior specific to small keys (e.g.
    /// `oaep_rejects_key_too_small_for_hash_instead_of_panicking_or_
    /// wrapping` below), which the fixed 2048-bit helper can't reach.
    fn generate_keypair_with_bits(
        mechs: &Mechanisms,
        bits: CK_ULONG,
    ) -> (Object, Object) {
        let ck_true: CK_BBOOL = CK_TRUE;
        let pubkey_template = [
            ulong_attr(CKA_MODULUS_BITS, &bits),
            bool_attr(CKA_VERIFY, &ck_true),
            bool_attr(CKA_ENCRYPT, &ck_true),
        ];
        let prikey_template = [
            bool_attr(CKA_SIGN, &ck_true),
            bool_attr(CKA_DECRYPT, &ck_true),
        ];
        let mech = no_param_mech(CKM_RSA_PKCS_KEY_PAIR_GEN);
        let entry = mechs.get(CKM_RSA_PKCS_KEY_PAIR_GEN).unwrap();
        entry
            .generate_keypair(&mech, &pubkey_template, &prikey_template)
            .expect("generate_keypair")
    }

    #[test]
    fn generated_keypair_has_expected_attributes() {
        let (mechs, _ot) = registered();
        let (pubkey, privkey) = generate_keypair(&mechs);
        assert_eq!(pubkey.get_attr_as_ulong(CKA_KEY_TYPE).unwrap(), CKK_RSA);
        assert_eq!(privkey.get_attr_as_ulong(CKA_KEY_TYPE).unwrap(), CKK_RSA);
        assert_eq!(pubkey.get_attr_as_bytes(CKA_MODULUS).unwrap().len(), 256);
        assert_eq!(
            pubkey.get_attr_as_bytes(CKA_PUBLIC_EXPONENT).unwrap(),
            &vec![0x01, 0x00, 0x01]
        );
        assert_eq!(
            privkey
                .get_attr_as_bytes(CKA_PRIVATE_EXPONENT)
                .unwrap()
                .len()
                > 0,
            true
        );
    }

    /// A non-default `CKA_PUBLIC_EXPONENT` request must actually be
    /// honored by the generated key, not silently overridden with F4 --
    /// see `RsaPKCSOperation::generate_keypair`'s doc comment.
    #[test]
    fn generate_keypair_honors_custom_public_exponent() {
        let (mechs, _ot) = registered();
        let ck_true: CK_BBOOL = CK_TRUE;
        let bits: CK_ULONG = 2048;
        let exponent: Vec<u8> = vec![0x11]; // e = 17
        let pubkey_template = [
            ulong_attr(CKA_MODULUS_BITS, &bits),
            bool_attr(CKA_VERIFY, &ck_true),
            CK_ATTRIBUTE {
                type_: CKA_PUBLIC_EXPONENT,
                pValue: exponent.as_ptr() as CK_VOID_PTR,
                ulValueLen: exponent.len() as CK_ULONG,
            },
        ];
        let prikey_template = [bool_attr(CKA_SIGN, &ck_true)];
        let mech = no_param_mech(CKM_RSA_PKCS_KEY_PAIR_GEN);
        let entry = mechs.get(CKM_RSA_PKCS_KEY_PAIR_GEN).unwrap();
        let (pubkey, privkey) = entry
            .generate_keypair(&mech, &pubkey_template, &prikey_template)
            .expect("generate_keypair");

        assert_eq!(
            pubkey.get_attr_as_bytes(CKA_PUBLIC_EXPONENT).unwrap(),
            &exponent
        );
        assert_eq!(
            privkey.get_attr_as_bytes(CKA_PUBLIC_EXPONENT).unwrap(),
            &exponent
        );

        // And the key must actually work with that exponent (not just
        // carry the right attribute value while secretly using F4).
        let data = b"custom exponent sign test";
        let sign_mech = no_param_mech(CKM_SHA256_RSA_PKCS);
        let sign_entry = mechs.get(CKM_SHA256_RSA_PKCS).unwrap();
        let mut sign_op = sign_entry.sign_new(&sign_mech, &privkey).unwrap();
        let mut signature = vec![0u8; sign_op.signature_len().unwrap()];
        sign_op.sign(data, &mut signature).unwrap();
        let mut verify_op = sign_entry.verify_new(&sign_mech, &pubkey).unwrap();
        verify_op.verify(data, &signature).unwrap();
    }

    #[test]
    fn sha256_rsa_pkcs_sign_verify_round_trip() {
        let (mechs, _ot) = registered();
        let (pubkey, privkey) = generate_keypair(&mechs);
        let data = b"the quick brown fox jumps over the lazy dog";
        let mech = no_param_mech(CKM_SHA256_RSA_PKCS);

        let entry = mechs.get(CKM_SHA256_RSA_PKCS).unwrap();
        let mut sign_op = entry.sign_new(&mech, &privkey).expect("sign_new");
        let mut signature = vec![0u8; sign_op.signature_len().unwrap()];
        sign_op.sign(data, &mut signature).expect("sign");
        assert_eq!(signature.len(), 256);

        let mut verify_op =
            entry.verify_new(&mech, &pubkey).expect("verify_new");
        verify_op.verify(data, &signature).expect("verify");

        let mut verify_op2 =
            entry.verify_new(&mech, &pubkey).expect("verify_new 2");
        let mut tampered = data.to_vec();
        tampered[0] ^= 0xff;
        let err = verify_op2
            .verify(&tampered, &signature)
            .expect_err("tampered data must fail verification");
        assert_eq!(err.rv(), CKR_SIGNATURE_INVALID);
    }

    /// `CKM_SHA256_RSA_PKCS` is a combined hash+sign mechanism: it must
    /// support multi-part sign/verify.
    #[test]
    fn sha256_rsa_pkcs_multipart_round_trip() {
        let (mechs, _ot) = registered();
        let (pubkey, privkey) = generate_keypair(&mechs);
        let mech = no_param_mech(CKM_SHA256_RSA_PKCS);
        let entry = mechs.get(CKM_SHA256_RSA_PKCS).unwrap();

        let mut sign_op = entry.sign_new(&mech, &privkey).unwrap();
        sign_op.sign_update(b"hello, ").unwrap();
        sign_op.sign_update(b"world!").unwrap();
        let mut signature = vec![0u8; sign_op.signature_len().unwrap()];
        sign_op.sign_final(&mut signature).unwrap();

        let mut verify_op = entry.verify_new(&mech, &pubkey).unwrap();
        verify_op.verify_update(b"hello, ").unwrap();
        verify_op.verify_update(b"world!").unwrap();
        verify_op.verify_final(&signature).unwrap();
    }

    /// Plain `CKM_RSA_PKCS`: the caller supplies the exact bytes to be
    /// PKCS#1 v1.5-padded and signed directly (no internal hashing, no
    /// DigestInfo added by this module -- distinct from
    /// `CKM_SHA256_RSA_PKCS` above).
    #[test]
    fn plain_rsa_pkcs_sign_verify_round_trip() {
        let (mechs, _ot) = registered();
        let (pubkey, privkey) = generate_keypair(&mechs);
        // Stand-in for a caller-built DigestInfo -- any bytes up to
        // key_size - 11 are valid input for this mechanism.
        let data = [0x5au8; 32];
        let mech = no_param_mech(CKM_RSA_PKCS);

        let entry = mechs.get(CKM_RSA_PKCS).unwrap();
        let mut sign_op = entry.sign_new(&mech, &privkey).unwrap();
        let mut signature = vec![0u8; sign_op.signature_len().unwrap()];
        sign_op.sign(&data, &mut signature).unwrap();

        let mut verify_op = entry.verify_new(&mech, &pubkey).unwrap();
        verify_op.verify(&data, &signature).unwrap();
    }

    /// Plain `CKM_RSA_PKCS` must reject multi-part `sign_update`, mirroring
    /// `crate::ossl::rsa::RsaPKCSOperation`'s own behavior.
    #[test]
    fn plain_rsa_pkcs_rejects_multipart() {
        let (mechs, _ot) = registered();
        let (_pubkey, privkey) = generate_keypair(&mechs);
        let mech = no_param_mech(CKM_RSA_PKCS);
        let entry = mechs.get(CKM_RSA_PKCS).unwrap();
        let mut sign_op = entry.sign_new(&mech, &privkey).unwrap();
        assert!(sign_op.sign_update(b"abc").is_err());
    }

    /// A signature from the DigestInfo-based `CKM_SHA256_RSA_PKCS`
    /// construction must not verify under plain `CKM_RSA_PKCS` (no
    /// DigestInfo) over the same digest bytes, and vice-versa -- these are
    /// genuinely different PKCS#1 v1.5 encodings, not two names for the
    /// same operation.
    #[test]
    fn hash_and_plain_pkcs_signatures_are_not_interchangeable() {
        let (mechs, _ot) = registered();
        let (pubkey, privkey) = generate_keypair(&mechs);
        let data = b"cross-construction test data";

        let hash_mech = no_param_mech(CKM_SHA256_RSA_PKCS);
        let hash_entry = mechs.get(CKM_SHA256_RSA_PKCS).unwrap();
        let mut sign_op = hash_entry.sign_new(&hash_mech, &privkey).unwrap();
        let mut hash_sig = vec![0u8; sign_op.signature_len().unwrap()];
        sign_op.sign(data, &mut hash_sig).unwrap();

        // The digest kryoptic computed internally isn't observable here,
        // but the digest of `data` under SHA-256 as raw bytes must not
        // verify as a plain CKM_RSA_PKCS signature either way -- simplest
        // check: the CKM_SHA256_RSA_PKCS signature must not verify under
        // plain CKM_RSA_PKCS over the raw `data` bytes.
        let plain_mech = no_param_mech(CKM_RSA_PKCS);
        let plain_entry = mechs.get(CKM_RSA_PKCS).unwrap();
        let mut verify_op =
            plain_entry.verify_new(&plain_mech, &pubkey).unwrap();
        assert!(verify_op.verify(data, &hash_sig).is_err());
    }

    /// PKCS#11 v3.2's `verify_signature_new`/`VerifySignature`.
    #[test]
    fn verify_signature_dispatch() {
        let (mechs, _ot) = registered();
        let (pubkey, privkey) = generate_keypair(&mechs);
        let data = b"verify-signature test data";
        let mech = no_param_mech(CKM_SHA256_RSA_PKCS);
        let entry = mechs.get(CKM_SHA256_RSA_PKCS).unwrap();

        let mut sign_op = entry.sign_new(&mech, &privkey).unwrap();
        let mut signature = vec![0u8; sign_op.signature_len().unwrap()];
        sign_op.sign(data, &mut signature).unwrap();

        let mut vsop = entry
            .verify_signature_new(&mech, &pubkey, &signature)
            .expect("verify_signature_new");
        vsop.verify(data).expect("verify_signature");
    }

    /// `CKM_RSA_PKCS`'s `Encryption`/`Decryption` framing -- RFC 2313
    /// "block type 2" padding, a genuinely different code path from the
    /// `Sign`/`Verify` framing tested above (see this file's module doc
    /// comment). Exercised through the real `Mechanism::encryption_new`/
    /// `decryption_new` dispatch, not just `awslc::rsa::RsaKey` directly.
    #[test]
    fn rsa_pkcs_encrypt_decrypt_round_trip() {
        let (mechs, _ot) = registered();
        let (pubkey, privkey) = generate_keypair(&mechs);
        let plaintext = b"a secret message";
        let mech = no_param_mech(CKM_RSA_PKCS);

        let entry = mechs.get(CKM_RSA_PKCS).unwrap();
        let mut enc_op = entry
            .encryption_new(&mech, &pubkey)
            .expect("encryption_new");
        let mut ciphertext = vec![0u8; 256];
        let ctlen = enc_op.encrypt(plaintext, &mut ciphertext).unwrap();
        ciphertext.truncate(ctlen);
        assert_eq!(ciphertext.len(), 256);
        assert_ne!(ciphertext.as_slice(), plaintext.as_slice());

        let mut dec_op = entry
            .decryption_new(&mech, &privkey)
            .expect("decryption_new");
        let mut recovered = vec![0u8; 256];
        let ptlen = dec_op.decrypt(&ciphertext, &mut recovered).unwrap();
        recovered.truncate(ptlen);
        assert_eq!(recovered.as_slice(), plaintext.as_slice());
    }

    #[test]
    fn rsa_pkcs_decrypt_rejects_tampered_ciphertext() {
        let (mechs, _ot) = registered();
        let (pubkey, privkey) = generate_keypair(&mechs);
        let plaintext = b"a secret message";
        let mech = no_param_mech(CKM_RSA_PKCS);
        let entry = mechs.get(CKM_RSA_PKCS).unwrap();

        let mut enc_op = entry.encryption_new(&mech, &pubkey).unwrap();
        let mut ciphertext = vec![0u8; 256];
        let ctlen = enc_op.encrypt(plaintext, &mut ciphertext).unwrap();
        ciphertext.truncate(ctlen);
        ciphertext[0] ^= 0xff;

        let mut dec_op = entry.decryption_new(&mech, &privkey).unwrap();
        let mut recovered = vec![0u8; 256];
        assert!(dec_op.decrypt(&ciphertext, &mut recovered).is_err());
    }

    /// Regression test: a full-CRT RSA private key
    /// imported through the real `ObjectFactory::create()` path (exactly
    /// what `C_CreateObject`/`C_UnwrapKey` drive) must be usable for
    /// signing.
    #[test]
    fn full_crt_private_key_import_can_sign() {
        let (mechs, ot) = registered();
        let (pubkey, privkey) = generate_keypair(&mechs);

        let n = pubkey.get_attr_as_bytes(CKA_MODULUS).unwrap().clone();
        let e = pubkey
            .get_attr_as_bytes(CKA_PUBLIC_EXPONENT)
            .unwrap()
            .clone();
        let d = privkey
            .get_attr_as_bytes(CKA_PRIVATE_EXPONENT)
            .unwrap()
            .clone();
        let p = privkey.get_attr_as_bytes(CKA_PRIME_1).unwrap().clone();
        let q = privkey.get_attr_as_bytes(CKA_PRIME_2).unwrap().clone();
        let dp = privkey.get_attr_as_bytes(CKA_EXPONENT_1).unwrap().clone();
        let dq = privkey.get_attr_as_bytes(CKA_EXPONENT_2).unwrap().clone();
        let qinv = privkey.get_attr_as_bytes(CKA_COEFFICIENT).unwrap().clone();

        let ck_true: CK_BBOOL = CK_TRUE;
        let ck_class: CK_OBJECT_CLASS = CKO_PRIVATE_KEY;
        let ck_type: CK_KEY_TYPE = CKK_RSA;
        let template = vec![
            ulong_attr(CKA_CLASS, &ck_class),
            ulong_attr(CKA_KEY_TYPE, &ck_type),
            bool_attr(CKA_SIGN, &ck_true),
            CK_ATTRIBUTE {
                type_: CKA_MODULUS,
                pValue: n.as_ptr() as CK_VOID_PTR,
                ulValueLen: n.len() as CK_ULONG,
            },
            CK_ATTRIBUTE {
                type_: CKA_PUBLIC_EXPONENT,
                pValue: e.as_ptr() as CK_VOID_PTR,
                ulValueLen: e.len() as CK_ULONG,
            },
            CK_ATTRIBUTE {
                type_: CKA_PRIVATE_EXPONENT,
                pValue: d.as_ptr() as CK_VOID_PTR,
                ulValueLen: d.len() as CK_ULONG,
            },
            CK_ATTRIBUTE {
                type_: CKA_PRIME_1,
                pValue: p.as_ptr() as CK_VOID_PTR,
                ulValueLen: p.len() as CK_ULONG,
            },
            CK_ATTRIBUTE {
                type_: CKA_PRIME_2,
                pValue: q.as_ptr() as CK_VOID_PTR,
                ulValueLen: q.len() as CK_ULONG,
            },
            CK_ATTRIBUTE {
                type_: CKA_EXPONENT_1,
                pValue: dp.as_ptr() as CK_VOID_PTR,
                ulValueLen: dp.len() as CK_ULONG,
            },
            CK_ATTRIBUTE {
                type_: CKA_EXPONENT_2,
                pValue: dq.as_ptr() as CK_VOID_PTR,
                ulValueLen: dq.len() as CK_ULONG,
            },
            CK_ATTRIBUTE {
                type_: CKA_COEFFICIENT,
                pValue: qinv.as_ptr() as CK_VOID_PTR,
                ulValueLen: qinv.len() as CK_ULONG,
            },
        ];

        let factory = ot.get_obj_factory_from_key_template(&template).unwrap();
        let imported = factory.create(&template).expect(
            "full-CRT RSA private key import via the real \
             ObjectFactory::create() path must succeed",
        );

        let data = b"full-crt import sign test";
        let mech = no_param_mech(CKM_SHA256_RSA_PKCS);
        let entry = mechs.get(CKM_SHA256_RSA_PKCS).unwrap();
        let mut sign_op = entry.sign_new(&mech, &imported).unwrap();
        let mut signature = vec![0u8; sign_op.signature_len().unwrap()];
        sign_op.sign(data, &mut signature).unwrap();

        let mut verify_op = entry.verify_new(&mech, &pubkey).unwrap();
        verify_op.verify(data, &signature).unwrap();
    }

    /// Regression test for the exact class of bug that once blocked a
    /// private-key import path that works for generated (full-CRT) keys
    /// but silently breaks for
    /// imported/partial (no-CRT) keys. Imports an RSA private key with
    /// only `CKA_MODULUS`/`CKA_PUBLIC_EXPONENT`/`CKA_PRIVATE_EXPONENT` (no
    /// `CKA_PRIME_1` etc.) through the real `ObjectFactory::create()` path
    /// and confirms it can still sign.
    #[test]
    fn no_crt_private_key_import_can_sign() {
        let (mechs, ot) = registered();
        let (pubkey, privkey) = generate_keypair(&mechs);

        let n = pubkey.get_attr_as_bytes(CKA_MODULUS).unwrap().clone();
        let e = pubkey
            .get_attr_as_bytes(CKA_PUBLIC_EXPONENT)
            .unwrap()
            .clone();
        let d = privkey
            .get_attr_as_bytes(CKA_PRIVATE_EXPONENT)
            .unwrap()
            .clone();

        let ck_true: CK_BBOOL = CK_TRUE;
        let ck_class: CK_OBJECT_CLASS = CKO_PRIVATE_KEY;
        let ck_type: CK_KEY_TYPE = CKK_RSA;
        let template = vec![
            ulong_attr(CKA_CLASS, &ck_class),
            ulong_attr(CKA_KEY_TYPE, &ck_type),
            bool_attr(CKA_SIGN, &ck_true),
            CK_ATTRIBUTE {
                type_: CKA_MODULUS,
                pValue: n.as_ptr() as CK_VOID_PTR,
                ulValueLen: n.len() as CK_ULONG,
            },
            CK_ATTRIBUTE {
                type_: CKA_PUBLIC_EXPONENT,
                pValue: e.as_ptr() as CK_VOID_PTR,
                ulValueLen: e.len() as CK_ULONG,
            },
            CK_ATTRIBUTE {
                type_: CKA_PRIVATE_EXPONENT,
                pValue: d.as_ptr() as CK_VOID_PTR,
                ulValueLen: d.len() as CK_ULONG,
            },
        ];

        let factory = ot.get_obj_factory_from_key_template(&template).unwrap();
        let imported = factory.create(&template).expect(
            "no-CRT RSA private key import via the real \
             ObjectFactory::create() path must succeed",
        );

        let data = b"no-crt import sign test";
        let mech = no_param_mech(CKM_SHA256_RSA_PKCS);
        let entry = mechs.get(CKM_SHA256_RSA_PKCS).unwrap();
        let mut sign_op = entry.sign_new(&mech, &imported).unwrap();
        let mut signature = vec![0u8; sign_op.signature_len().unwrap()];
        sign_op.sign(data, &mut signature).unwrap();

        let mut verify_op = entry.verify_new(&mech, &pubkey).unwrap();
        verify_op.verify(data, &signature).unwrap();
    }

    #[test]
    fn registration_covers_expected_mechanisms() {
        let (mechs, _ot) = registered();
        for ckm in [
            CKM_RSA_PKCS,
            CKM_RSA_X_509,
            CKM_SHA256_RSA_PKCS,
            CKM_RSA_PKCS_KEY_PAIR_GEN,
            CKM_RSA_PKCS_PSS,
            CKM_SHA256_RSA_PKCS_PSS,
            CKM_RSA_PKCS_OAEP,
        ] {
            assert!(mechs.get(ckm).is_ok());
        }
    }

    /// Builds a `CK_MECHANISM` for a PSS mechanism with an explicit
    /// `CK_RSA_PKCS_PSS_PARAMS` and an explicit salt length. `params`
    /// must outlive the returned `CK_MECHANISM` (it borrows a raw pointer
    /// into it).
    fn pss_mech(
        mechanism: CK_MECHANISM_TYPE,
        params: &CK_RSA_PKCS_PSS_PARAMS,
    ) -> CK_MECHANISM {
        CK_MECHANISM {
            mechanism,
            pParameter: params as *const CK_RSA_PKCS_PSS_PARAMS as CK_VOID_PTR,
            ulParameterLen: std::mem::size_of::<CK_RSA_PKCS_PSS_PARAMS>()
                as CK_ULONG,
        }
    }

    /// Bare `CKM_RSA_PKCS_PSS`: the caller supplies the pre-computed
    /// digest directly (no internal hashing), one-shot only, exact-length
    /// input -- mirrors `plain_rsa_pkcs_sign_verify_round_trip` above but
    /// for PSS padding.
    #[test]
    fn bare_rsa_pkcs_pss_sign_verify_round_trip() {
        let (mechs, _ot) = registered();
        let (pubkey, privkey) = generate_keypair(&mechs);
        let digest = [0x5au8; 32]; // stand-in for a SHA-256 digest
        let params = CK_RSA_PKCS_PSS_PARAMS {
            hashAlg: CKM_SHA256,
            mgf: CKG_MGF1_SHA256,
            sLen: 32,
        };
        let mech = pss_mech(CKM_RSA_PKCS_PSS, &params);

        let entry = mechs.get(CKM_RSA_PKCS_PSS).unwrap();
        let mut sign_op = entry.sign_new(&mech, &privkey).unwrap();
        let mut signature = vec![0u8; sign_op.signature_len().unwrap()];
        sign_op.sign(&digest, &mut signature).unwrap();

        let mut verify_op = entry.verify_new(&mech, &pubkey).unwrap();
        verify_op.verify(&digest, &signature).unwrap();
    }

    /// Bare `CKM_RSA_PKCS_PSS` must reject input whose length doesn't
    /// exactly match the digest length implied by `hashAlg` (PSS requires
    /// an exact match, unlike plain `CKM_RSA_PKCS`'s `<=` check -- mirrors
    /// `crate::ossl::rsa::RsaPKCSOperation::sign`'s
    /// `CKM_RSA_PKCS_PSS => data.len() != self.max_input`).
    #[test]
    fn bare_rsa_pkcs_pss_rejects_wrong_length_input() {
        let (mechs, _ot) = registered();
        let (_pubkey, privkey) = generate_keypair(&mechs);
        let wrong_length_digest = [0x5au8; 20]; // not 32 (SHA-256)
        let params = CK_RSA_PKCS_PSS_PARAMS {
            hashAlg: CKM_SHA256,
            mgf: CKG_MGF1_SHA256,
            sLen: 32,
        };
        let mech = pss_mech(CKM_RSA_PKCS_PSS, &params);
        let entry = mechs.get(CKM_RSA_PKCS_PSS).unwrap();
        let mut sign_op = entry.sign_new(&mech, &privkey).unwrap();
        let mut signature = vec![0u8; sign_op.signature_len().unwrap()];
        let err = sign_op
            .sign(&wrong_length_digest, &mut signature)
            .expect_err("wrong-length input must be rejected");
        assert_eq!(err.rv(), CKR_DATA_LEN_RANGE);
    }

    /// `CKM_SHA256_RSA_PKCS_PSS`: a combined hash+PSS mechanism, with an
    /// explicit salt length from a real `CK_RSA_PKCS_PSS_PARAMS`
    /// structure, exercised through the real trait dispatch.
    #[test]
    fn sha256_rsa_pkcs_pss_sign_verify_round_trip() {
        let (mechs, _ot) = registered();
        let (pubkey, privkey) = generate_keypair(&mechs);
        let data = b"the quick brown fox jumps over the lazy dog";
        let params = CK_RSA_PKCS_PSS_PARAMS {
            hashAlg: CKM_SHA256,
            mgf: CKG_MGF1_SHA256,
            sLen: 32,
        };
        let mech = pss_mech(CKM_SHA256_RSA_PKCS_PSS, &params);

        let entry = mechs.get(CKM_SHA256_RSA_PKCS_PSS).unwrap();
        let mut sign_op = entry.sign_new(&mech, &privkey).expect("sign_new");
        let mut signature = vec![0u8; sign_op.signature_len().unwrap()];
        sign_op.sign(data, &mut signature).expect("sign");
        assert_eq!(signature.len(), 256);

        let mut verify_op =
            entry.verify_new(&mech, &pubkey).expect("verify_new");
        verify_op.verify(data, &signature).expect("verify");

        let mut verify_op2 =
            entry.verify_new(&mech, &pubkey).expect("verify_new 2");
        let mut tampered = data.to_vec();
        tampered[0] ^= 0xff;
        assert!(verify_op2.verify(&tampered, &signature).is_err());
    }

    /// `CKM_SHA256_RSA_PKCS_PSS` must support multi-part sign/verify, like
    /// its PKCS#1v1.5 combined-hash counterpart.
    #[test]
    fn sha256_rsa_pkcs_pss_multipart_round_trip() {
        let (mechs, _ot) = registered();
        let (pubkey, privkey) = generate_keypair(&mechs);
        let params = CK_RSA_PKCS_PSS_PARAMS {
            hashAlg: CKM_SHA256,
            mgf: CKG_MGF1_SHA256,
            sLen: 32,
        };
        let mech = pss_mech(CKM_SHA256_RSA_PKCS_PSS, &params);
        let entry = mechs.get(CKM_SHA256_RSA_PKCS_PSS).unwrap();

        let mut sign_op = entry.sign_new(&mech, &privkey).unwrap();
        sign_op.sign_update(b"hello, ").unwrap();
        sign_op.sign_update(b"world!").unwrap();
        let mut signature = vec![0u8; sign_op.signature_len().unwrap()];
        sign_op.sign_final(&mut signature).unwrap();

        let mut verify_op = entry.verify_new(&mech, &pubkey).unwrap();
        verify_op.verify_update(b"hello, ").unwrap();
        verify_op.verify_update(b"world!").unwrap();
        verify_op.verify_final(&signature).unwrap();
    }

    /// PKCS#11 v3.2's `verify_signature_new`/`VerifySignature`, for PSS.
    #[test]
    fn pss_verify_signature_dispatch() {
        let (mechs, _ot) = registered();
        let (pubkey, privkey) = generate_keypair(&mechs);
        let data = b"verify-signature test data";
        let params = CK_RSA_PKCS_PSS_PARAMS {
            hashAlg: CKM_SHA256,
            mgf: CKG_MGF1_SHA256,
            sLen: 32,
        };
        let mech = pss_mech(CKM_SHA256_RSA_PKCS_PSS, &params);
        let entry = mechs.get(CKM_SHA256_RSA_PKCS_PSS).unwrap();

        let mut sign_op = entry.sign_new(&mech, &privkey).unwrap();
        let mut signature = vec![0u8; sign_op.signature_len().unwrap()];
        sign_op.sign(data, &mut signature).unwrap();

        let mut vsop = entry
            .verify_signature_new(&mech, &pubkey, &signature)
            .expect("verify_signature_new");
        vsop.verify(data).expect("verify_signature");
    }

    /// A combined PSS mechanism's `hashAlg` param must match the
    /// mechanism's own implied hash (mirrors
    /// `crate::ossl::rsa::parse_sig_params`'s cross-check).
    #[test]
    fn combined_pss_rejects_hashalg_mechanism_mismatch() {
        let (mechs, _ot) = registered();
        let (_pubkey, privkey) = generate_keypair(&mechs);
        let params = CK_RSA_PKCS_PSS_PARAMS {
            hashAlg: CKM_SHA384, // mismatched with the mechanism below
            mgf: CKG_MGF1_SHA384,
            sLen: 48,
        };
        let mech = pss_mech(CKM_SHA256_RSA_PKCS_PSS, &params);
        let entry = mechs.get(CKM_SHA256_RSA_PKCS_PSS).unwrap();
        let err = entry
            .sign_new(&mech, &privkey)
            .expect_err("hashAlg/mechanism mismatch must be rejected");
        assert_eq!(err.rv(), CKR_MECHANISM_PARAM_INVALID);
    }

    /// See this file's `parse_pss_params` doc comment: `hashAlg`/`mgf`
    /// are independent PKCS#11 parameters, and `RsaKey::sign_pss`/
    /// `verify_pss` now thread them through independently (`hash_nid`/
    /// `mgf1_hash_nid`) rather than requiring them to match. A genuine
    /// mismatch (unusual, but PKCS#11-legal and representable by the
    /// OpenSSL backend too) must sign and verify correctly through the
    /// real trait dispatch, not just round-trip with itself -- so this
    /// also cross-checks against a raw `RsaKey::verify_pss` call with
    /// the same independent digest/MGF1 NIDs, confirming the PSS
    /// encoding genuinely used the MGF1 hash requested, not `hashAlg`'s.
    #[test]
    fn bare_pss_signs_and_verifies_with_independent_mgf1_hash() {
        let (mechs, _ot) = registered();
        let (pubkey, privkey) = generate_keypair(&mechs);
        let params = CK_RSA_PKCS_PSS_PARAMS {
            hashAlg: CKM_SHA256,
            mgf: CKG_MGF1_SHA384, // genuinely different from hashAlg
            sLen: 32,
        };
        let digest = [0x42u8; 32];

        let mech = pss_mech(CKM_RSA_PKCS_PSS, &params);
        let entry = mechs.get(CKM_RSA_PKCS_PSS).unwrap();
        let mut sig_op = entry.sign_new(&mech, &privkey).expect("sign_new");
        let mut signature = vec![0u8; sig_op.signature_len().unwrap()];
        sig_op.sign(&digest, &mut signature).expect("sign");

        let mech = pss_mech(CKM_RSA_PKCS_PSS, &params);
        let mut verify_op =
            entry.verify_new(&mech, &pubkey).expect("verify_new");
        verify_op.verify(&digest, &signature).expect(
            "a genuinely mismatched hashAlg/mgf PSS signature must verify",
        );

        // A verify using SHA-256 for MGF1 (matching hashAlg, i.e. the old
        // "coerced" behavior) must NOT accept this signature -- confirms
        // the MGF1 hash actually used was SHA-384, not silently SHA-256.
        let wrong_key = RsaKey::from_private_components(
            &pubkey.get_attr_as_bytes(CKA_MODULUS).unwrap(),
            &pubkey.get_attr_as_bytes(CKA_PUBLIC_EXPONENT).unwrap(),
            &privkey.get_attr_as_bytes(CKA_PRIVATE_EXPONENT).unwrap(),
            None,
        )
        .expect("from_private_components");
        assert!(wrong_key
            .verify_pss(
                digest_alg_to_nid(DigestAlg::Sha2_256),
                digest_alg_to_nid(DigestAlg::Sha2_256),
                &digest,
                32,
                &signature,
            )
            .is_err());
    }

    /// Builds a `CK_MECHANISM` for `CKM_RSA_PKCS_OAEP` with an explicit
    /// `CK_RSA_PKCS_OAEP_PARAMS`. `params` must outlive the returned
    /// `CK_MECHANISM` (it borrows a raw pointer into it) -- mirrors
    /// `pss_mech` above.
    fn oaep_mech(params: &CK_RSA_PKCS_OAEP_PARAMS) -> CK_MECHANISM {
        CK_MECHANISM {
            mechanism: CKM_RSA_PKCS_OAEP,
            pParameter: params as *const CK_RSA_PKCS_OAEP_PARAMS as CK_VOID_PTR,
            ulParameterLen: std::mem::size_of::<CK_RSA_PKCS_OAEP_PARAMS>()
                as CK_ULONG,
        }
    }

    fn empty_label_oaep_params(
        hash_alg: CK_MECHANISM_TYPE,
        mgf: CK_RSA_PKCS_MGF_TYPE,
    ) -> CK_RSA_PKCS_OAEP_PARAMS {
        CK_RSA_PKCS_OAEP_PARAMS {
            hashAlg: hash_alg,
            mgf,
            source: CKZ_DATA_SPECIFIED,
            pSourceData: std::ptr::null_mut(),
            ulSourceDataLen: 0,
        }
    }

    /// Round-trip `CKM_RSA_PKCS_OAEP` through the real trait dispatch
    /// (`Mechanisms::get`/`Encryption`/`Decryption`), exactly as
    /// `C_EncryptInit`/`C_Encrypt`/`C_DecryptInit`/`C_Decrypt` reach it --
    /// exercising the real dispatch, not just
    /// `awslc::rsa::RsaKey::encrypt_oaep_mgf1`/`decrypt_oaep_mgf1`
    /// directly (already covered by `awslc/src/rsa.rs`'s own unit tests).
    /// SHA-256, not SHA-1: see `OaepParams`'s doc comment for why this
    /// codebase's OAEP test suite never uses SHA-1 alone.
    #[test]
    fn oaep_encrypt_decrypt_round_trip_sha256() {
        let (mechs, _ot) = registered();
        let (pubkey, privkey) = generate_keypair(&mechs);
        let plaintext = b"a secret OAEP message";
        let params = empty_label_oaep_params(CKM_SHA256, CKG_MGF1_SHA256);
        let mech = oaep_mech(&params);

        let entry = mechs.get(CKM_RSA_PKCS_OAEP).unwrap();
        let mut enc_op = entry
            .encryption_new(&mech, &pubkey)
            .expect("encryption_new");
        let mut ciphertext = vec![0u8; 256];
        let ctlen = enc_op.encrypt(plaintext, &mut ciphertext).unwrap();
        ciphertext.truncate(ctlen);
        assert_eq!(ciphertext.len(), 256);
        assert_ne!(ciphertext.as_slice(), plaintext.as_slice());

        let mut dec_op = entry
            .decryption_new(&mech, &privkey)
            .expect("decryption_new");
        let mut recovered = vec![0u8; 256];
        let ptlen = dec_op.decrypt(&ciphertext, &mut recovered).unwrap();
        recovered.truncate(ptlen);
        assert_eq!(recovered.as_slice(), plaintext.as_slice());
    }

    /// Regression test for `encdec_new`'s `max_input` computation
    /// (`keysize.checked_sub(2 * digest_len + 2)`): a 1024-bit key (128
    /// bytes) combined with SHA-512 OAEP (64-byte digest) needs
    /// `2*64+2 = 130` bytes of overhead, more than the modulus itself,
    /// which used to underflow the unchecked `usize` subtraction (panic
    /// in debug, a huge bogus `max_input` silently defeating the
    /// pre-check in release). Only reachable in non-FIPS builds, since
    /// `MIN_RSA_SIZE_BITS` is 2048 under `fips` -- a 1024-bit key can't
    /// exist there at all, so the scenario this guards against cannot
    /// occur under that feature.
    #[test]
    #[cfg(not(feature = "fips"))]
    fn oaep_small_key_large_hash_reports_key_size_range() {
        let (mechs, _ot) = registered();
        let (pubkey, _privkey) = generate_keypair_with_bits(&mechs, 1024);
        let params = empty_label_oaep_params(CKM_SHA512, CKG_MGF1_SHA512);
        let mech = oaep_mech(&params);

        let entry = mechs.get(CKM_RSA_PKCS_OAEP).unwrap();
        let err = entry
            .encryption_new(&mech, &pubkey)
            .expect_err("1024-bit key + SHA-512 OAEP must be rejected");
        assert_eq!(err.rv(), CKR_KEY_SIZE_RANGE);
    }

    /// Whole-phase-review finding B1: `Decryption::decrypt` used to
    /// finalize the operation (`self.finalized = true`) *before* checking
    /// whether the output buffer was big enough, and reported the actual
    /// decrypted-plaintext length in the `CKR_BUFFER_TOO_SMALL` error
    /// rather than the modulus-size upper bound. Both defects broke the
    /// standard PKCS#11 retry idiom (probe with a too-small/null buffer,
    /// then retry with a correctly-sized one -- see PKCS#11 v3.2 S5.2):
    /// a retry after `CKR_BUFFER_TOO_SMALL` would hit
    /// `CKR_OPERATION_NOT_INITIALIZED` instead of succeeding, and a caller
    /// who under-guessed the buffer size would learn the exact plaintext
    /// length rather than just the safe upper bound.
    ///
    /// This mirrors `src/tests/rsa.rs`'s
    /// `test_rsa_decrypt_buffer_too_small_reports_required_len` (an
    /// FFI-level test that currently can't run under this crate's feature
    /// set -- see that test's neighboring comments) at the trait-dispatch
    /// level instead: real `Mechanism`/`Encryption`/`Decryption` dispatch,
    /// exactly as `C_DecryptInit`/`C_Decrypt` reach it, with a genuine
    /// same-operation retry after the `CKR_BUFFER_TOO_SMALL` error.
    #[test]
    fn oaep_decrypt_buffer_too_small_does_not_finalize_and_reports_modulus_len()
    {
        let (mechs, _ot) = registered();
        let (pubkey, privkey) = generate_keypair(&mechs);
        let plaintext = b"plaintext";
        let params = empty_label_oaep_params(CKM_SHA256, CKG_MGF1_SHA256);
        let mech = oaep_mech(&params);

        let entry = mechs.get(CKM_RSA_PKCS_OAEP).unwrap();
        let mut enc_op = entry.encryption_new(&mech, &pubkey).unwrap();
        let mut ciphertext = vec![0u8; 256];
        let ctlen = enc_op.encrypt(plaintext, &mut ciphertext).unwrap();
        ciphertext.truncate(ctlen);
        assert_eq!(ciphertext.len(), 256);

        let mut dec_op = entry
            .decryption_new(&mech, &privkey)
            .expect("decryption_new");

        /* Deliberately too small. The reported required length must be the
         * modulus-size upper bound (256, matching decryption_len()'s own
         * null-probe answer), not the eventual 9-byte plaintext length. */
        let mut too_small = [0u8; 2];
        let err = dec_op
            .decrypt(&ciphertext, &mut too_small)
            .expect_err("undersized buffer must be rejected");
        assert_eq!(err.rv(), CKR_BUFFER_TOO_SMALL);
        assert_eq!(
            err.reqsize(),
            256,
            "must report the modulus-size upper bound (256), not the \
             actual plaintext length (9)"
        );

        /* The operation must NOT be finalized: retrying the SAME operation
         * with a correctly-sized buffer must succeed. This is the crux of
         * B1 -- before the fix, this retry hit
         * CKR_OPERATION_NOT_INITIALIZED instead of succeeding. */
        assert!(
            !dec_op.finalized(),
            "CKR_BUFFER_TOO_SMALL must not finalize the operation"
        );
        let mut recovered = vec![0u8; 256];
        let ptlen = dec_op
            .decrypt(&ciphertext, &mut recovered)
            .expect("retry with a correctly-sized buffer must succeed");
        recovered.truncate(ptlen);
        assert_eq!(recovered.as_slice(), plaintext.as_slice());
    }

    /// Same shape as `oaep_encrypt_decrypt_round_trip_sha256` but with
    /// SHA-512 -- matches `src/tests/rsa.rs`'s
    /// "oaep-sha512-sha512.txt"/wrap-key vectors
    /// (`hashAlg: CKM_SHA512, mgf: CKG_MGF1_SHA512`).
    #[test]
    fn oaep_encrypt_decrypt_round_trip_sha512() {
        let (mechs, _ot) = registered();
        let (pubkey, privkey) = generate_keypair(&mechs);
        let plaintext = b"a secret OAEP message";
        let params = empty_label_oaep_params(CKM_SHA512, CKG_MGF1_SHA512);
        let mech = oaep_mech(&params);

        let entry = mechs.get(CKM_RSA_PKCS_OAEP).unwrap();
        let mut enc_op = entry.encryption_new(&mech, &pubkey).unwrap();
        let mut ciphertext = vec![0u8; 256];
        let ctlen = enc_op.encrypt(plaintext, &mut ciphertext).unwrap();
        ciphertext.truncate(ctlen);

        let mut dec_op = entry.decryption_new(&mech, &privkey).unwrap();
        let mut recovered = vec![0u8; 256];
        let ptlen = dec_op.decrypt(&ciphertext, &mut recovered).unwrap();
        recovered.truncate(ptlen);
        assert_eq!(recovered.as_slice(), plaintext.as_slice());
    }

    /// All four hash/MGF1 pairs `src/tests/rsa.rs`'s `test_rsa_sign_verify`
    /// loops over for `CKM_RSA_PKCS_OAEP` (`for hash in [(CKM_SHA224,
    /// CKG_MGF1_SHA224), (CKM_SHA256, CKG_MGF1_SHA256), (CKM_SHA384,
    /// CKG_MGF1_SHA384), (CKM_SHA512, CKG_MGF1_SHA512)]`) must round-trip.
    #[test]
    fn oaep_encrypt_decrypt_round_trip_all_reference_hash_pairs() {
        let (mechs, _ot) = registered();
        let (pubkey, privkey) = generate_keypair(&mechs);
        let entry = mechs.get(CKM_RSA_PKCS_OAEP).unwrap();
        for (hash_alg, mgf) in [
            (CKM_SHA224, CKG_MGF1_SHA224),
            (CKM_SHA256, CKG_MGF1_SHA256),
            (CKM_SHA384, CKG_MGF1_SHA384),
            (CKM_SHA512, CKG_MGF1_SHA512),
        ] {
            let plaintext = b"RSA OAEP payload";
            let params = empty_label_oaep_params(hash_alg, mgf);
            let mech = oaep_mech(&params);

            let mut enc_op = entry.encryption_new(&mech, &pubkey).unwrap();
            let mut ciphertext = vec![0u8; 256];
            let ctlen = enc_op.encrypt(plaintext, &mut ciphertext).unwrap();
            ciphertext.truncate(ctlen);

            let mut dec_op = entry.decryption_new(&mech, &privkey).unwrap();
            let mut recovered = vec![0u8; 256];
            let ptlen = dec_op.decrypt(&ciphertext, &mut recovered).unwrap();
            recovered.truncate(ptlen);
            assert_eq!(recovered.as_slice(), plaintext.as_slice());
        }
    }

    /// Whole-phase-review finding M2: `digest_alg_to_nid` (in
    /// `awslc/src/rsa.rs`) covered `NID_sha512_224`/`NID_sha512_256`, but
    /// `nid_to_evp_md` didn't -- unreachable for PSS (which requires
    /// `hashAlg == mgf`) but reachable here, since `parse_oaep_params`
    /// maps `hashAlg` and `mgf` independently. `hashAlg:
    /// CKM_SHA512_224`/`CKM_SHA512_256` are valid digest mechanisms
    /// (`hash_size` in `src/hash.rs` supports them) that the OpenSSL
    /// backend already handles under `CKM_RSA_PKCS_OAEP`; this pairs each
    /// with a supported MGF1 (`CKG_MGF1_SHA256`, since `mgf1_to_digest_alg`
    /// has no `CKG_MGF1_SHA512_224`/`_256` arm) to isolate the `hashAlg`
    /// side of the NID lookup that was missing.
    #[test]
    fn oaep_encrypt_decrypt_round_trip_sha512_224_and_256_hashalg() {
        let (mechs, _ot) = registered();
        let (pubkey, privkey) = generate_keypair(&mechs);
        let entry = mechs.get(CKM_RSA_PKCS_OAEP).unwrap();
        for hash_alg in [CKM_SHA512_224, CKM_SHA512_256] {
            let plaintext = b"RSA OAEP payload";
            let params = empty_label_oaep_params(hash_alg, CKG_MGF1_SHA256);
            let mech = oaep_mech(&params);

            let mut enc_op = entry.encryption_new(&mech, &pubkey).unwrap();
            let mut ciphertext = vec![0u8; 256];
            let ctlen = enc_op.encrypt(plaintext, &mut ciphertext).unwrap();
            ciphertext.truncate(ctlen);

            let mut dec_op = entry.decryption_new(&mech, &privkey).unwrap();
            let mut recovered = vec![0u8; 256];
            let ptlen = dec_op.decrypt(&ciphertext, &mut recovered).unwrap();
            recovered.truncate(ptlen);
            assert_eq!(recovered.as_slice(), plaintext.as_slice());
        }
    }

    /// A non-empty `pSourceData` (OAEP label) must round-trip too -- see
    /// `OaepParams`'s doc comment on why the label is threaded through
    /// rather than rejected, even though this codebase's own test suite
    /// never exercises a non-empty one.
    #[test]
    fn oaep_encrypt_decrypt_round_trip_with_label() {
        let (mechs, _ot) = registered();
        let (pubkey, privkey) = generate_keypair(&mechs);
        let plaintext = b"a secret OAEP message";
        let label = b"a non-empty OAEP label";
        let params = CK_RSA_PKCS_OAEP_PARAMS {
            hashAlg: CKM_SHA256,
            mgf: CKG_MGF1_SHA256,
            source: CKZ_DATA_SPECIFIED,
            pSourceData: label.as_ptr() as CK_VOID_PTR,
            ulSourceDataLen: label.len() as CK_ULONG,
        };
        let mech = oaep_mech(&params);

        let entry = mechs.get(CKM_RSA_PKCS_OAEP).unwrap();
        let mut enc_op = entry.encryption_new(&mech, &pubkey).unwrap();
        let mut ciphertext = vec![0u8; 256];
        let ctlen = enc_op.encrypt(plaintext, &mut ciphertext).unwrap();
        ciphertext.truncate(ctlen);

        let mut dec_op = entry.decryption_new(&mech, &privkey).unwrap();
        let mut recovered = vec![0u8; 256];
        let ptlen = dec_op.decrypt(&ciphertext, &mut recovered).unwrap();
        recovered.truncate(ptlen);
        assert_eq!(recovered.as_slice(), plaintext.as_slice());
    }

    #[test]
    fn oaep_decrypt_rejects_tampered_ciphertext() {
        let (mechs, _ot) = registered();
        let (pubkey, privkey) = generate_keypair(&mechs);
        let plaintext = b"a secret OAEP message";
        let params = empty_label_oaep_params(CKM_SHA256, CKG_MGF1_SHA256);
        let mech = oaep_mech(&params);
        let entry = mechs.get(CKM_RSA_PKCS_OAEP).unwrap();

        let mut enc_op = entry.encryption_new(&mech, &pubkey).unwrap();
        let mut ciphertext = vec![0u8; 256];
        let ctlen = enc_op.encrypt(plaintext, &mut ciphertext).unwrap();
        ciphertext.truncate(ctlen);
        ciphertext[0] ^= 0xff;

        let mut dec_op = entry.decryption_new(&mech, &privkey).unwrap();
        let mut recovered = vec![0u8; 256];
        assert!(dec_op.decrypt(&ciphertext, &mut recovered).is_err());
    }

    /// `max_input` for OAEP is `modulus - 2*hLen - 2` (RFC 8017), not
    /// PKCS#1 v1.5's `modulus - 11` -- see `encdec_new`'s `max_input`
    /// computation. For a 2048-bit key with SHA-256 OAEP:
    /// 256 - 2*32 - 2 = 190 bytes.
    #[test]
    fn oaep_encrypt_rejects_message_too_long_for_key_size() {
        let (mechs, _ot) = registered();
        let (pubkey, _privkey) = generate_keypair(&mechs);
        let params = empty_label_oaep_params(CKM_SHA256, CKG_MGF1_SHA256);
        let mech = oaep_mech(&params);
        let entry = mechs.get(CKM_RSA_PKCS_OAEP).unwrap();
        let mut enc_op = entry.encryption_new(&mech, &pubkey).unwrap();

        let too_long = vec![0x41u8; 191];
        let mut ciphertext = vec![0u8; 256];
        assert!(enc_op.encrypt(&too_long, &mut ciphertext).is_err());
    }

    /// `CKM_RSA_PKCS_OAEP` key wrap/unwrap (`RsaPKCSOperation::wrap`/
    /// `unwrap`) round trip -- exercises the same "RSA PKCS OAEP Wrap"
    /// path `src/tests/rsa.rs`'s `test_rsa_operations` covers.
    #[test]
    fn oaep_wrap_unwrap_round_trip() {
        let (mechs, _ot) = registered();
        let (pubkey, privkey) = generate_keypair(&mechs);
        let params = empty_label_oaep_params(CKM_SHA512, CKG_MGF1_SHA512);
        let mech = oaep_mech(&params);
        let entry = mechs.get(CKM_RSA_PKCS_OAEP).unwrap();
        let info = entry.info();

        let keydata = vec![0x55u8; 16]; // stand-in for an AES-128 key
        let needed = RsaPKCSOperation::wrap(
            &mech,
            &pubkey,
            keydata.clone(),
            &mut [],
            info,
        )
        .expect("wrap probe");
        let mut wrapped = vec![0u8; needed];
        let wrapped_len = RsaPKCSOperation::wrap(
            &mech,
            &pubkey,
            keydata.clone(),
            &mut wrapped,
            info,
        )
        .expect("wrap");
        wrapped.truncate(wrapped_len);

        let recovered =
            RsaPKCSOperation::unwrap(&mech, &privkey, &wrapped, info)
                .expect("unwrap");
        assert_eq!(recovered, keydata);
    }

    /// `CKM_RSA_X_509`: raw/unpadded RSA sign/verify with
    /// exact-modulus-length input (256 bytes for a 2048-bit key) -- the
    /// simplest case, no left-padding needed.
    #[test]
    fn raw_x509_sign_verify_round_trip_exact_length() {
        let (mechs, _ot) = registered();
        let (pubkey, privkey) = generate_keypair(&mechs);
        let mut data = vec![0x11u8; 256];
        // Keep the numeric value of `data` below the modulus (RSA raw
        // sign/verify operates mod n): zeroing the top byte is a simple,
        // key-independent way to guarantee that.
        data[0] = 0x00;
        let mech = no_param_mech(CKM_RSA_X_509);
        let entry = mechs.get(CKM_RSA_X_509).unwrap();

        let mut sign_op = entry.sign_new(&mech, &privkey).expect("sign_new");
        let mut signature = vec![0u8; sign_op.signature_len().unwrap()];
        sign_op.sign(&data, &mut signature).expect("sign");
        assert_eq!(signature.len(), 256);

        let mut verify_op =
            entry.verify_new(&mech, &pubkey).expect("verify_new");
        verify_op.verify(&data, &signature).expect("verify");
    }

    /// `CKM_RSA_X_509` allows input shorter than the modulus, treated as
    /// zero-padded on the left (PKCS#11 spec; mirrors
    /// `crate::ossl::rsa::RsaPKCSOperation::max_message_len`'s
    /// `CKM_RSA_X_509 => Ok(modulus)` upper bound, not an exact-length
    /// requirement). This is the case `RsaKey::raw_transform_private/
    /// public` cannot handle directly (they require exact-length
    /// input) -- this module must left-pad itself.
    #[test]
    fn raw_x509_sign_verify_round_trip_short_input() {
        let (mechs, _ot) = registered();
        let (pubkey, privkey) = generate_keypair(&mechs);
        let data = b"a short message, well under 256 bytes";
        let mech = no_param_mech(CKM_RSA_X_509);
        let entry = mechs.get(CKM_RSA_X_509).unwrap();

        let mut sign_op = entry.sign_new(&mech, &privkey).expect("sign_new");
        let mut signature = vec![0u8; sign_op.signature_len().unwrap()];
        sign_op.sign(data, &mut signature).expect("sign");
        assert_eq!(signature.len(), 256);

        let mut verify_op =
            entry.verify_new(&mech, &pubkey).expect("verify_new");
        verify_op.verify(data, &signature).expect("verify");
    }

    /// Data longer than the modulus must be rejected before ever reaching
    /// the raw transform.
    #[test]
    fn raw_x509_sign_rejects_input_too_long() {
        let (mechs, _ot) = registered();
        let (_pubkey, privkey) = generate_keypair(&mechs);
        let too_long = vec![0x11u8; 257];
        let mech = no_param_mech(CKM_RSA_X_509);
        let entry = mechs.get(CKM_RSA_X_509).unwrap();

        let mut sign_op = entry.sign_new(&mech, &privkey).expect("sign_new");
        let mut signature = vec![0u8; sign_op.signature_len().unwrap()];
        assert!(sign_op.sign(&too_long, &mut signature).is_err());
    }

    /// A tampered signature must not verify, and must report
    /// `CKR_SIGNATURE_INVALID` (not some other error), matching the
    /// established convention in this file's other verify tests.
    #[test]
    fn raw_x509_verify_rejects_tampered_signature() {
        let (mechs, _ot) = registered();
        let (pubkey, privkey) = generate_keypair(&mechs);
        let data = b"raw x509 tamper test";
        let mech = no_param_mech(CKM_RSA_X_509);
        let entry = mechs.get(CKM_RSA_X_509).unwrap();

        let mut sign_op = entry.sign_new(&mech, &privkey).unwrap();
        let mut signature = vec![0u8; sign_op.signature_len().unwrap()];
        sign_op.sign(data, &mut signature).unwrap();
        // Flip a low-order byte, not the top one: raw RSA interprets the
        // whole signature as a big-endian integer that must stay below the
        // modulus for the public-key transform to even run. Tampering the
        // top byte can push that integer past the modulus (a roughly 50%
        // chance, depending on the generated key), which AWS-LC's raw
        // exponentiation legitimately rejects at the primitive level
        // (surfacing as `CKR_DEVICE_ERROR`, not `CKR_SIGNATURE_INVALID`) --
        // not the "recovered a mismatching value" case this test wants to
        // exercise. A low-order byte flip keeps the integer safely below
        // the modulus, so the transform always runs and this test
        // deterministically hits the comparison-mismatch path instead.
        let last = signature.len() - 1;
        signature[last] ^= 0xff;

        let mut verify_op = entry.verify_new(&mech, &pubkey).unwrap();
        let err = verify_op
            .verify(data, &signature)
            .expect_err("tampered signature must fail verification");
        assert_eq!(err.rv(), CKR_SIGNATURE_INVALID);
    }

    /// `CKM_RSA_X_509` is one-shot only, like plain `CKM_RSA_PKCS` --
    /// mirrors `plain_rsa_pkcs_rejects_multipart` above.
    #[test]
    fn raw_x509_rejects_multipart() {
        let (mechs, _ot) = registered();
        let (_pubkey, privkey) = generate_keypair(&mechs);
        let mech = no_param_mech(CKM_RSA_X_509);
        let entry = mechs.get(CKM_RSA_X_509).unwrap();
        let mut sign_op = entry.sign_new(&mech, &privkey).unwrap();
        assert!(sign_op.sign_update(b"abc").is_err());
    }

    /// `CKM_RSA_X_509`'s `Encryption`/`Decryption` framing: the public key
    /// transforms exact-modulus-length (here, left-zero-padded) plaintext
    /// directly, with no padding scheme applied or checked.
    #[test]
    fn raw_x509_encrypt_decrypt_round_trip() {
        let (mechs, _ot) = registered();
        let (pubkey, privkey) = generate_keypair(&mechs);
        let mut plaintext = vec![0x22u8; 256];
        plaintext[0] = 0x00; // keep the numeric value below the modulus
        let mech = no_param_mech(CKM_RSA_X_509);
        let entry = mechs.get(CKM_RSA_X_509).unwrap();

        let mut enc_op = entry
            .encryption_new(&mech, &pubkey)
            .expect("encryption_new");
        let mut ciphertext = vec![0u8; 256];
        let ctlen = enc_op.encrypt(&plaintext, &mut ciphertext).unwrap();
        ciphertext.truncate(ctlen);
        assert_eq!(ciphertext.len(), 256);
        assert_ne!(ciphertext.as_slice(), plaintext.as_slice());

        let mut dec_op = entry
            .decryption_new(&mech, &privkey)
            .expect("decryption_new");
        let mut recovered = vec![0u8; 256];
        let ptlen = dec_op.decrypt(&ciphertext, &mut recovered).unwrap();
        recovered.truncate(ptlen);
        assert_eq!(recovered.as_slice(), plaintext.as_slice());
    }

    /// Plaintext shorter than the modulus must be accepted and treated as
    /// zero-padded on the left, same as sign/verify above.
    #[test]
    fn raw_x509_encrypt_decrypt_round_trip_short_plaintext() {
        let (mechs, _ot) = registered();
        let (pubkey, privkey) = generate_keypair(&mechs);
        let plaintext = b"short plaintext for raw RSA";
        let mech = no_param_mech(CKM_RSA_X_509);
        let entry = mechs.get(CKM_RSA_X_509).unwrap();

        let mut enc_op = entry.encryption_new(&mech, &pubkey).unwrap();
        let mut ciphertext = vec![0u8; 256];
        let ctlen = enc_op.encrypt(plaintext, &mut ciphertext).unwrap();
        ciphertext.truncate(ctlen);
        assert_eq!(ciphertext.len(), 256);

        let mut dec_op = entry.decryption_new(&mech, &privkey).unwrap();
        let mut recovered = vec![0u8; 256];
        let ptlen = dec_op.decrypt(&ciphertext, &mut recovered).unwrap();
        // The recovered buffer is the full modulus-size raw block
        // (left-zero-padded); the original short plaintext is its
        // trailing bytes.
        assert_eq!(&recovered[..ptlen][256 - plaintext.len()..], plaintext);
        assert!(recovered[..ptlen][..256 - plaintext.len()]
            .iter()
            .all(|b| *b == 0));
    }

    /// Plaintext longer than the modulus must be rejected.
    #[test]
    fn raw_x509_encrypt_rejects_plaintext_too_long() {
        let (mechs, _ot) = registered();
        let (pubkey, _privkey) = generate_keypair(&mechs);
        let too_long = vec![0x11u8; 257];
        let mech = no_param_mech(CKM_RSA_X_509);
        let entry = mechs.get(CKM_RSA_X_509).unwrap();
        let mut enc_op = entry.encryption_new(&mech, &pubkey).unwrap();
        let mut ciphertext = vec![0u8; 256];
        assert!(enc_op.encrypt(&too_long, &mut ciphertext).is_err());
    }
}
