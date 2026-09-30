// Copyright 2026
// See LICENSE.txt file for terms

//! Common utilities for the awslc backend, mirroring
//! `crate::ossl::common`.

use crate::error::Result;
#[cfg(feature = "ecc")]
use crate::kasn1::oid;
#[cfg(any(feature = "ecc", feature = "mlkem", feature = "mldsa"))]
use crate::kasn1::pkcs;
#[cfg(any(feature = "ecc", feature = "mlkem", feature = "mldsa"))]
use crate::object::Object;
use crate::pkcs11::*;

use crate::lowlevel::digest::DigestAlg;
#[cfg(feature = "ecc")]
use crate::lowlevel::ec::{EcCurve, EcKey};
#[cfg(feature = "eddsa")]
use crate::lowlevel::eddsa::Ed25519Key;
// See src/enabled.rs's mldsa mod-inclusion gate for why awslc-fips is
// excluded here specifically.
#[cfg(all(feature = "mldsa", not(feature = "awslc-fips")))]
use crate::lowlevel::mldsa::MlDsaKey;
#[cfg(feature = "mlkem")]
use crate::lowlevel::mlkem::MlKemKey;
#[cfg(feature = "ec_montgomery")]
use crate::lowlevel::x25519::X25519Key;

#[cfg(any(feature = "ecc", feature = "mlkem", feature = "mldsa"))]
use asn1;

/// Maps a PKCS#11 mechanism type involving a hash to the corresponding
/// awslc DigestAlg. Mirrors `crate::ossl::common::mech_type_to_digest_alg`.
pub fn mech_type_to_digest_alg(mech: CK_MECHANISM_TYPE) -> Result<DigestAlg> {
    Ok(match mech {
        #[cfg(not(feature = "no_sha1"))]
        CKM_SHA1_RSA_PKCS
        | CKM_ECDSA_SHA1
        | CKM_SHA1_RSA_PKCS_PSS
        | CKM_SHA_1_HMAC
        | CKM_SHA_1_HMAC_GENERAL
        | CKM_SHA_1 => DigestAlg::Sha1,
        CKM_SHA224_RSA_PKCS
        | CKM_ECDSA_SHA224
        | CKM_SHA224_RSA_PKCS_PSS
        | CKM_SHA224_HMAC
        | CKM_SHA224_HMAC_GENERAL
        | CKM_SHA224 => DigestAlg::Sha2_224,
        CKM_SHA256_RSA_PKCS
        | CKM_ECDSA_SHA256
        | CKM_SHA256_RSA_PKCS_PSS
        | CKM_SHA256_HMAC
        | CKM_SHA256_HMAC_GENERAL
        | CKM_SHA256 => DigestAlg::Sha2_256,
        CKM_SHA384_RSA_PKCS
        | CKM_ECDSA_SHA384
        | CKM_SHA384_RSA_PKCS_PSS
        | CKM_SHA384_HMAC
        | CKM_SHA384_HMAC_GENERAL
        | CKM_SHA384 => DigestAlg::Sha2_384,
        CKM_SHA512_RSA_PKCS
        | CKM_ECDSA_SHA512
        | CKM_SHA512_RSA_PKCS_PSS
        | CKM_SHA512_HMAC
        | CKM_SHA512_HMAC_GENERAL
        | CKM_SHA512 => DigestAlg::Sha2_512,
        CKM_SHA3_224_RSA_PKCS
        | CKM_ECDSA_SHA3_224
        | CKM_SHA3_224_RSA_PKCS_PSS
        | CKM_SHA3_224_HMAC
        | CKM_SHA3_224_HMAC_GENERAL
        | CKM_SHA3_224 => DigestAlg::Sha3_224,
        CKM_SHA3_256_RSA_PKCS
        | CKM_ECDSA_SHA3_256
        | CKM_SHA3_256_RSA_PKCS_PSS
        | CKM_SHA3_256_HMAC
        | CKM_SHA3_256_HMAC_GENERAL
        | CKM_SHA3_256 => DigestAlg::Sha3_256,
        CKM_SHA3_384_RSA_PKCS
        | CKM_ECDSA_SHA3_384
        | CKM_SHA3_384_RSA_PKCS_PSS
        | CKM_SHA3_384_HMAC
        | CKM_SHA3_384_HMAC_GENERAL
        | CKM_SHA3_384 => DigestAlg::Sha3_384,
        CKM_SHA3_512_RSA_PKCS
        | CKM_ECDSA_SHA3_512
        | CKM_SHA3_512_RSA_PKCS_PSS
        | CKM_SHA3_512_HMAC
        | CKM_SHA3_512_HMAC_GENERAL
        | CKM_SHA3_512 => DigestAlg::Sha3_512,
        CKM_SHA512_224_HMAC | CKM_SHA512_224_HMAC_GENERAL | CKM_SHA512_224 => {
            DigestAlg::Sha2_512_224
        }
        CKM_SHA512_256_HMAC | CKM_SHA512_256_HMAC_GENERAL | CKM_SHA512_256 => {
            DigestAlg::Sha2_512_256
        }
        _ => return Err(CKR_MECHANISM_INVALID)?,
    })
}

/// Maps a curve OID (from `CKA_EC_PARAMS`) to `awslc::ec::EcCurve`,
/// mirroring `crate::ossl::common::get_evp_pkey_type_from_obj`'s role for
/// this backend (also reused directly by `crate::awslc::ecdsa`, so the
/// mapping only lives in one place). Only handles `CKK_EC`'s 3 supported
/// curves -- Ed25519/Ed448/X25519/X448 are a different `CKA_KEY_TYPE`
/// entirely (`CKK_EC_EDWARDS`/`CKK_EC_MONTGOMERY`) and are handled by their
/// own dedicated modules (`crate::awslc::eddsa`/`crate::awslc::montgomery`),
/// never by this function. An OID this function doesn't recognize is, from
/// a caller's perspective, the same "the token can't do this curve"
/// condition `ensure_x25519`/`ensure_ed25519` report with
/// `CKR_CURVE_NOT_SUPPORTED` -- matched here for consistency.
#[cfg(feature = "ecc")]
pub(crate) fn ec_curve_from_oid(
    oid: &asn1::ObjectIdentifier,
) -> Result<EcCurve> {
    match oid {
        &oid::EC_SECP256R1 => Ok(EcCurve::P256),
        &oid::EC_SECP384R1 => Ok(EcCurve::P384),
        &oid::EC_SECP521R1 => Ok(EcCurve::P521),
        _ => Err(CKR_CURVE_NOT_SUPPORTED)?,
    }
}

/// Extracts the public key point from a private key object.
///
/// Mirrors `crate::ossl::common::extract_public_key`, which
/// `src/ec/ecdsa.rs`'s `PubKeyFactory::pub_from_private` and
/// `ECDSAPrivFactory::create` both call (via the `crate::ossl::common`
/// alias, resolved to this module under the `awslc` feature) to recover a
/// private key object's public point -- needed e.g. when a private key is
/// imported/unwrapped without an explicit public key ever being created
/// alongside it. Tries `CKA_PUBLIC_KEY_INFO` first (backend-agnostic ASN.1
/// parsing, identical to the reference), then falls back to deriving the
/// point straight from the private key material.
///
/// Handles `CKK_EC` (the 3 NIST curves, via `awslc::ec::EcKey`),
/// `CKK_EC_EDWARDS` (Ed25519, via `awslc::eddsa::Ed25519Key`, gated on the
/// `eddsa` feature) and `CKK_EC_MONTGOMERY` (X25519, via
/// `awslc::x25519::X25519Key`, gated on the `ec_montgomery` feature) --
/// exactly the EC-family key types `EDDSAPrivFactory::create`/
/// `pub_from_private` (`src/ec/eddsa.rs`) and `ECMontgomeryPrivFactory::
/// create`/`pub_from_private` (`src/ec/montgomery.rs`) unconditionally call
/// this function on. Prior to a fix, Ed25519/X25519 private-key
/// import/unwrap under this backend silently failed with
/// `CKR_GENERAL_ERROR` because only `CKK_EC` was handled here. If the
/// corresponding feature is disabled, the key type falls through to the
/// catch-all `CKR_GENERAL_ERROR` below (there is no other reasonable error
/// for "this backend build doesn't have this key type at all").
///
/// Also handles `CKK_ML_KEM`, via
/// `awslc::mlkem::MlKemKey::public_key_from_private_key_bytes` -- needed
/// by `src/mlkem.rs`'s `MlKemPrivFactory::create`, which unconditionally
/// calls this function right after validating a new ML-KEM private key
/// object (before `CKA_PUBLIC_KEY_INFO` has been set on it yet, so this
/// arm -- not the fast path above -- is what actually runs on that call
/// site; see `src/awslc/mlkem.rs`'s module doc comment for the full
/// account of why this extension was forced and narrow).
///
/// Not gated on `ecc`: this function's `CKA_PUBLIC_KEY_INFO` fast path
/// and its `CKK_ML_KEM` arm are both
/// needed under `--features awslc,hash,mlkem` alone (no `ecc`) --
/// `src/mlkem.rs` imports and unconditionally calls this function the
/// same way `src/ec/eddsa.rs`/`src/ec/montgomery.rs` do. Only the
/// `CKK_EC` arm itself still needs `ecc` (it calls into `crate::ec`,
/// which only exists when `ecc` is enabled, per `src/enabled.rs`) --
/// gated individually below, the same pattern already used for the
/// `eddsa`/`ec_montgomery` arms. A key type whose feature is disabled
/// falls through to the catch-all `CKR_GENERAL_ERROR` below, same as
/// before this change.
#[cfg(any(feature = "ecc", feature = "mlkem", feature = "mldsa"))]
pub fn extract_public_key(privkey: &Object) -> Result<Vec<u8>> {
    // Optimize by trying to extract from CKA_PUBLIC_KEY_INFO first.
    if let Some(pki_attr) = privkey.get_attr(CKA_PUBLIC_KEY_INFO) {
        let spki_der = pki_attr.get_value();
        if !spki_der.is_empty() {
            let spki =
                asn1::parse_single::<pkcs::SubjectPublicKeyInfo>(spki_der)
                    .map_err(|_| CKR_GENERAL_ERROR)?;
            return Ok(spki.subject_public_key.as_bytes().to_vec());
        }
    }

    match privkey.get_attr_as_ulong(CKA_KEY_TYPE)? {
        #[cfg(feature = "ecc")]
        CKK_EC => {
            let curve_oid = crate::ec::get_oid_from_obj(privkey)?;
            let curve = ec_curve_from_oid(&curve_oid)?;
            let scalar = privkey.get_attr_as_bytes(CKA_VALUE)?;
            // AWS-LC's EC_KEY_set_private_key validates 0 < d < order (a
            // stricter check than OpenSSL's own equivalent, which stores
            // the scalar unchecked and only fails, if at all, once it's
            // actually used) -- so a syntactically well-formed but
            // out-of-range scalar (e.g. a deliberately-invalid CAVP test
            // vector) fails here. `CKR_KEY_UNEXTRACTABLE` is the same
            // tolerated error `ECDSAPrivFactory::create`/`EDDSAPrivFactory::
            // create`/`ECMontgomeryPrivFactory::create` (src/ec/*.rs) already
            // special-case and continue past for the pre-existing "older
            // OpenSSL can't extract this key" gap -- reusing it here lets
            // import succeed and defers the actual invalidity to first use
            // (signing/deriving), matching the reference backend's behavior.
            let key = EcKey::from_private_scalar(curve, scalar.as_slice())
                .map_err(|_| CKR_KEY_UNEXTRACTABLE)?;
            Ok(key.public_point())
        }
        #[cfg(feature = "eddsa")]
        CKK_EC_EDWARDS => {
            /* PKCS#11's EdDSA private key storage convention is the raw
             * 32-byte seed (RFC 8032) -- see
             * `crate::awslc::eddsa::privkey_from_object`, whose exact
             * OID check + fixed-size-array conversion pattern is mirrored
             * here (including rejecting Ed448 -- a distinct OID under the
             * same CKK_EC_EDWARDS key type -- with CKR_CURVE_NOT_SUPPORTED
             * rather than mis-reading its 57-byte value as a truncated/
             * oversized Ed25519 seed). */
            crate::awslc::eddsa::ensure_ed25519(privkey)?;
            let value = privkey.get_attr_as_bytes(CKA_VALUE)?;
            if value.len() != crate::awslc::eddsa::KEYLEN_ED25519 {
                return Err(CKR_KEY_SIZE_RANGE)?;
            }
            let mut seed = [0u8; crate::awslc::eddsa::KEYLEN_ED25519];
            seed.copy_from_slice(value.as_slice());
            let result = Ed25519Key::from_seed(&seed);
            crate::misc::zeromem(&mut seed);
            Ok(result?.public_key().to_vec())
        }
        #[cfg(feature = "ec_montgomery")]
        CKK_EC_MONTGOMERY => {
            /* PKCS#11's Montgomery private key storage convention is the
             * raw 32-byte scalar (RFC 7748) -- see
             * `crate::awslc::montgomery::privkey_from_object`, whose exact
             * OID check + fixed-size-array conversion pattern is mirrored
             * here (including rejecting X448 -- a distinct OID under the
             * same CKK_EC_MONTGOMERY key type -- with
             * CKR_CURVE_NOT_SUPPORTED rather than mis-reading its 56-byte
             * value as a truncated/oversized X25519 scalar). */
            crate::awslc::montgomery::ensure_x25519(privkey)?;
            let value = privkey.get_attr_as_bytes(CKA_VALUE)?;
            if value.len() != crate::awslc::montgomery::KEYLEN_X25519 {
                return Err(CKR_KEY_SIZE_RANGE)?;
            }
            let mut scalar = [0u8; crate::awslc::montgomery::KEYLEN_X25519];
            scalar.copy_from_slice(value.as_slice());
            let result = X25519Key::from_private(&scalar);
            crate::misc::zeromem(&mut scalar);
            Ok(result?.public_key().to_vec())
        }
        #[cfg(feature = "mlkem")]
        CKK_ML_KEM => {
            // NOT `MlKemKey::from_private_key(...).public_key()`: AWS-LC's
            // raw-secret-key import never populates a public key (see
            // `awslc::mlkem::MlKemKey::public_key_from_private_key_bytes`'s
            // doc comment, added by this same task, for the confirmed
            // root cause and why byte-slicing the FIPS 203 `dk` format
            // directly is the correct fix instead).
            let paramset = crate::awslc::mlkem::mlkem_param_set(
                privkey.get_attr_as_ulong(CKA_PARAMETER_SET)?,
            )?;
            let value = privkey.get_attr_as_bytes(CKA_VALUE)?;
            Ok(MlKemKey::public_key_from_private_key_bytes(
                paramset, value,
            )?)
        }
        // Excluded under awslc-fips: see src/enabled.rs's mldsa
        // mod-inclusion gate for the FIPS-validation-boundary rationale.
        #[cfg(all(feature = "mldsa", not(feature = "awslc-fips")))]
        CKK_ML_DSA => {
            // Unlike ML-KEM's raw-secret-key import, AWS-LC's ML-DSA/PQDSA
            // raw-private-key import (`PQDSA_KEY_set_raw_private_key`,
            // `aws-lc/crypto/fipsmodule/pqdsa/pqdsa.c`) DOES derive and
            // cache the public key from the private key at import time
            // (`pqdsa_pack_pk_from_sk`), so the straightforward
            // `from_private_key(...).public_key()` composition works here
            // -- confirmed by this module's own tests, not just by reading
            // AWS-LC's C source. Needed because
            // `src/mldsa.rs`'s `MlDsaPrivFactory::create` calls this
            // function before `CKA_PUBLIC_KEY_INFO` is ever set on the new
            // object, so the fast path above never fires here (same
            // situation as the `CKK_ML_KEM` arm above).
            let paramset = crate::awslc::mldsa::mldsa_param_set(
                privkey.get_attr_as_ulong(CKA_PARAMETER_SET)?,
            )?;
            let value = privkey.get_attr_as_bytes(CKA_VALUE)?;
            Ok(MlDsaKey::from_private_key(paramset, value)?.public_key()?)
        }
        _ => Err(CKR_GENERAL_ERROR)?,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mechanism::Mechanisms;
    use crate::object::ObjectFactories;

    /// Builds a minimal `CKO_PRIVATE_KEY` template for `key_type`/`params`/
    /// `value` -- deliberately *without* `CKA_PUBLIC_KEY_INFO`, the exact
    /// shape a real `C_CreateObject`/`C_UnwrapKey` import produces when no
    /// explicit public key is ever created alongside the private one. This
    /// is what forces `EDDSAPrivFactory::create`/`ECMontgomeryPrivFactory::
    /// create` to actually call `extract_public_key` below rather than
    /// taking the `CKA_PUBLIC_KEY_INFO`-already-present short-circuit
    /// (which every existing `awslc::eddsa`/`awslc::montgomery` test uses
    /// to sidestep this exact gap -- see e.g. `eddsa.rs`'s
    /// `ed448_sign_new_is_rejected` doc comment).
    /// `key_type` is taken by reference, not by value: `CK_ATTRIBUTE.pValue`
    /// is an untracked raw pointer, so a by-value parameter's address would
    /// dangle the moment this function returns (its stack slot is gone,
    /// unlike `params`/`value`, which point into the *caller's* storage).
    /// Debug builds mostly don't reuse that slot before the caller reads
    /// it, but release builds' optimizer does, corrupting the returned
    /// template -- confirmed by CI failures specific to `--release` (`cargo
    /// test` never exercises the old build-only job's release configs).
    /// Callers pass `&CKK_EC_EDWARDS`/`&CKK_EC_MONTGOMERY` directly, whose
    /// storage is the constant itself (`'static`), not a stack frame.
    fn raw_privkey_template(
        key_type: &CK_KEY_TYPE,
        params: &[u8],
        value: &[u8],
    ) -> Vec<CK_ATTRIBUTE> {
        vec![
            CK_ATTRIBUTE {
                type_: CKA_CLASS,
                pValue: &CKO_PRIVATE_KEY as *const _ as CK_VOID_PTR,
                ulValueLen: std::mem::size_of::<CK_OBJECT_CLASS>() as CK_ULONG,
            },
            CK_ATTRIBUTE {
                type_: CKA_KEY_TYPE,
                pValue: key_type as *const _ as CK_VOID_PTR,
                ulValueLen: std::mem::size_of::<CK_KEY_TYPE>() as CK_ULONG,
            },
            CK_ATTRIBUTE {
                type_: CKA_EC_PARAMS,
                pValue: params.as_ptr() as CK_VOID_PTR,
                ulValueLen: params.len() as CK_ULONG,
            },
            CK_ATTRIBUTE {
                type_: CKA_VALUE,
                pValue: value.as_ptr() as CK_VOID_PTR,
                ulValueLen: value.len() as CK_ULONG,
            },
        ]
    }

    /// Regression test: importing a raw Ed25519 private key through the real
    /// `ObjectFactories`/`ObjectFactory::create()` path (exactly what
    /// `C_CreateObject`/`C_UnwrapKey` drive, via `EDDSAPrivFactory::
    /// create`'s unconditional call to `extract_public_key` above) must
    /// succeed and produce the correct public key, not
    /// `CKR_GENERAL_ERROR`.
    #[cfg(feature = "eddsa")]
    #[test]
    fn ed25519_private_key_import_via_object_factory_extracts_public_key() {
        let mut mechs = Mechanisms::new();
        let mut ot = ObjectFactories::new();
        crate::ec::eddsa::register(&mut mechs, &mut ot);

        let params =
            crate::ec::curvename_to_ec_params(crate::ec::EDWARDS25519).unwrap();
        let seed = [0x42u8; 32];
        let template = raw_privkey_template(&CKK_EC_EDWARDS, &params, &seed);

        let factory = ot.get_obj_factory_from_key_template(&template).unwrap();
        let privkey = factory.create(&template).expect(
            "Ed25519 private key import via the real ObjectFactory::create() \
             path must succeed",
        );

        let expected_public =
            Ed25519Key::from_seed(&seed).unwrap().public_key();
        let pki_der = privkey.get_attr_as_bytes(CKA_PUBLIC_KEY_INFO).unwrap();
        let spki = asn1::parse_single::<pkcs::SubjectPublicKeyInfo>(
            pki_der.as_slice(),
        )
        .unwrap();
        assert_eq!(spki.subject_public_key.as_bytes(), &expected_public[..]);
    }

    /// Regression test: the X25519 counterpart of the Ed25519 test above,
    /// through
    /// `ECMontgomeryPrivFactory::create`.
    #[cfg(feature = "ec_montgomery")]
    #[test]
    fn x25519_private_key_import_via_object_factory_extracts_public_key() {
        let mut mechs = Mechanisms::new();
        let mut ot = ObjectFactories::new();
        crate::ec::montgomery::register(&mut mechs, &mut ot);

        let params =
            crate::ec::curvename_to_ec_params(crate::ec::CURVE25519).unwrap();
        let scalar = [0x24u8; 32];
        let template =
            raw_privkey_template(&CKK_EC_MONTGOMERY, &params, &scalar);

        let factory = ot.get_obj_factory_from_key_template(&template).unwrap();
        let privkey = factory.create(&template).expect(
            "X25519 private key import via the real ObjectFactory::create() \
             path must succeed",
        );

        let expected_public =
            X25519Key::from_private(&scalar).unwrap().public_key();
        let pki_der = privkey.get_attr_as_bytes(CKA_PUBLIC_KEY_INFO).unwrap();
        let spki = asn1::parse_single::<pkcs::SubjectPublicKeyInfo>(
            pki_der.as_slice(),
        )
        .unwrap();
        assert_eq!(spki.subject_public_key.as_bytes(), &expected_public[..]);
    }

    /// Regression test for a correctness detail this fix must preserve:
    /// `extract_public_key`'s new `CKK_EC_EDWARDS` arm must still reject
    /// Ed448 (a distinct OID under the same key type, for which AWS-LC has
    /// no primitive at all -- see `crate::awslc::eddsa`'s module doc
    /// comment) with `CKR_CURVE_NOT_SUPPORTED`, exactly like
    /// `crate::awslc::eddsa::privkey_from_object` does via the same
    /// `ensure_ed25519` check -- not silently mis-read its 57-byte value as
    /// a malformed Ed25519 seed.
    #[cfg(feature = "eddsa")]
    #[test]
    fn ed448_private_key_import_via_object_factory_is_rejected() {
        let mut mechs = Mechanisms::new();
        let mut ot = ObjectFactories::new();
        crate::ec::eddsa::register(&mut mechs, &mut ot);

        let params =
            crate::ec::curvename_to_ec_params(crate::ec::EDWARDS448).unwrap();
        let value = vec![0u8; crate::ec::ec_key_size(&oid::ED448_OID).unwrap()];
        let template = raw_privkey_template(&CKK_EC_EDWARDS, &params, &value);

        let factory = ot.get_obj_factory_from_key_template(&template).unwrap();
        let err = factory.create(&template).expect_err(
            "Ed448 private key import must be rejected: no AWS-LC primitive",
        );
        assert_eq!(err.rv(), CKR_CURVE_NOT_SUPPORTED);
    }

    /// The X448 counterpart of the Ed448 rejection test above, through
    /// `ECMontgomeryPrivFactory::create` / `ensure_x25519`.
    #[cfg(feature = "ec_montgomery")]
    #[test]
    fn x448_private_key_import_via_object_factory_is_rejected() {
        let mut mechs = Mechanisms::new();
        let mut ot = ObjectFactories::new();
        crate::ec::montgomery::register(&mut mechs, &mut ot);

        let params =
            crate::ec::curvename_to_ec_params(crate::ec::CURVE448).unwrap();
        let value = vec![0u8; crate::ec::ec_key_size(&oid::X448_OID).unwrap()];
        let template =
            raw_privkey_template(&CKK_EC_MONTGOMERY, &params, &value);

        let factory = ot.get_obj_factory_from_key_template(&template).unwrap();
        let err = factory.create(&template).expect_err(
            "X448 private key import must be rejected: no AWS-LC primitive",
        );
        assert_eq!(err.rv(), CKR_CURVE_NOT_SUPPORTED);
    }
}
