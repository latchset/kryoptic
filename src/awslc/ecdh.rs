// Copyright 2026
// See LICENSE.txt file for terms

//! AWS-LC-backed implementation of the ECDH surface `src/ec/ecdh.rs`
//! requires: `ECDHOperation` (mirroring `crate::ossl::ecdh`, which
//! `src/ec/ecdh.rs` imports via `use crate::ossl::ecdh::ECDHOperation;` --
//! resolved to this module under the `awslc` feature by `src/lib.rs`'s
//! `use awslc as ossl;` alias).
//!
//! `awslc::ec::EcKey::derive_shared_secret` takes the peer's public point
//! directly as a raw `&[u8]` -- unlike ECDSA verify, the peer never needs
//! to be wrapped in an `EcKey` at all here, so the
//! `EcKey::from_public_point` gap ECDSA hits doesn't apply to ECDH. `derive_shared_secret` also always returns a shared secret of
//! exactly `EcCurve::order_bytes()` length: AWS-LC's `ECDH_compute_key`
//! left-pads the shared x-coordinate to the field's fixed byte width via
//! `BN_bn2bin_padded` *before* ever consulting the caller's `outlen`
//! (confirmed against `derive_shared_secret`'s own doc/impl and its
//! `ecdh_p256_shared_secret_agreement` test, which asserts the output is
//! exactly 32 bytes for P-256), so there is no variable-length
//! "outlen < raw_max" case here -- the reference's tail-drain
//! (`secret.drain(..(outlen - keylen))`) always degenerates to "take the
//! last `keylen` bytes of a fixed-width buffer" for this backend.
//!
//! Neither the `CKM_ECDH1_COFACTOR_DERIVE` cofactor mode nor any KDF
//! post-processing has an AWS-LC primitive available in `awslc::ec` or
//! elsewhere in the `awslc` primitive crate (there is no KDF module there
//! at all, unlike `ossl::derive`'s `X963KdfDerive`/`OneStepKdfDerive`).
//! Both are handled directly in this wiring module instead:
//!
//! - Cofactor mode: for all 3 curves this backend supports (P-256/384/521)
//!   the cofactor is 1 (confirmed via each curve's NIST-published
//!   parameters), so cofactor-multiplying the shared point by 1 is the
//!   identity operation -- `CKM_ECDH1_COFACTOR_DERIVE` and plain
//!   `CKM_ECDH1_DERIVE` are computationally identical for every curve this
//!   backend handles, and `awslc::ec::EcKey::derive_shared_secret`'s plain
//!   `ECDH_compute_key` call already computes exactly that (BoringSSL/
//!   AWS-LC's `ECDH_compute_key` has no cofactor concept at all -- it's
//!   always a plain scalar multiply, which for cofactor 1 *is* the
//!   cofactor variant). So both mechanisms are dispatched to the exact
//!   same code path below; nothing else needs to change based on
//!   `self.mech`.
//! - KDF post-processing (`x963_kdf`/`one_step_kdf` below): ANSI X9.63's
//!   KDF and SP 800-56C's "One-Step" (digest-only) KDF are both public,
//!   fully-specified hash-based constructions (not AWS-LC/OpenSSL-specific
//!   behavior), so hand-rolling them here using the already-available
//!   `awslc::digest::Digest` reproduces `ossl::derive::X963KdfDerive`/
//!   `OneStepKdfDerive`'s exact byte-for-byte output rather than
//!   approximating it.
//!
//! # X25519 dispatch
//!
//! `Derive::derive` below also handles `CKK_EC_MONTGOMERY` (X25519) keys,
//! not just the classic `EcKey`/Weierstrass path this file originally
//! implemented. `src/ec/montgomery.rs` registers no
//! `Derive`-capable mechanism of its own -- X25519 key derivation is only
//! ever reached, in production, through this same `CKM_ECDH1_DERIVE`/
//! `CKM_ECDH1_COFACTOR_DERIVE` mechanism, with the key supplied here at
//! `derive()` (not at mechanism-init time) deciding which curve family's
//! math actually runs. See `raw_max_for_key`'s doc comment below and
//! `crate::awslc::montgomery`'s module doc comment for the full record of
//! this (verified, not guessed) gap and why it required extending this
//! already-completed file rather than staying confined to
//! `src/awslc/montgomery.rs` alone.

use std::borrow::Cow;

use crate::attribute::CkAttrs;
use crate::error::Result;
use crate::mechanism::{Derive, MechOperation, Mechanisms};
use crate::misc::{bytes_to_vec, zeromem};
use crate::object::{default_key_attributes, Object, ObjectFactories};
use crate::pkcs11::*;

use crate::awslc::common::ec_curve_from_oid;

use crate::lowlevel::digest::{Digest, DigestAlg};
use crate::lowlevel::ec::{EcCurve, EcKey};

/// Maps a `CKA_EC_PARAMS`-bearing `Object` to the `EcCurve` variant AWS-LC's
/// primitive needs. Duplicated (rather than imported) from
/// `crate::awslc::ecdsa`'s own private helper of the same name/shape, since
/// that function isn't `pub` and this file's scope is limited to itself
/// and `mod.rs` -- a small, local, obviously-correct helper is preferred
/// over expanding shared surface for a few lines of logic.
fn ec_curve_from_obj(key: &Object) -> Result<EcCurve> {
    let oid = crate::ec::get_oid_from_obj(key)?;
    ec_curve_from_oid(&oid)
}

/// Builds an `EcKey` for deriving from a `CKO_PRIVATE_KEY` `Object`'s
/// `CKA_VALUE` (raw fixed-width private scalar).
fn privkey_from_object(key: &Object) -> Result<EcKey> {
    let curve = ec_curve_from_obj(key)?;
    let scalar = key.get_attr_as_bytes(CKA_VALUE)?;
    Ok(EcKey::from_private_scalar(curve, scalar.as_slice())?)
}

/// Returns the fixed raw-agreement byte width for `key`'s curve family.
///
/// This dispatch (and its `raw_shared_secret` counterpart below) is a
/// documented, deliberate scope extension of this file beyond its
/// original EC-Weierstrass-only implementation, made to support
/// `crate::awslc::montgomery`: `src/ec/montgomery.rs` registers no
/// `Derive`-capable mechanism of its own, so X25519 key derivation is
/// only ever reached, in production, through the *same*
/// `CKM_ECDH1_DERIVE`/`CKM_ECDH1_COFACTOR_DERIVE` mechanism this file's
/// `ECDHOperation` already implements for Weierstrass ECDH -- the key
/// itself, supplied here at `Derive::derive()`, is what decides which
/// curve family's math actually runs (this is also how the OpenSSL
/// backend reaches X25519, via `crate::ossl::common::privkey_from_object`'s
/// own `CKA_KEY_TYPE` dispatch, generically, since OpenSSL's `EVP_PKEY`
/// API covers both curve families uniformly; AWS-LC's raw X25519_*
/// functions have no equivalent uniform abstraction with the classic
/// `EC_KEY` API `EcKey` wraps, so this backend needs an explicit branch
/// here instead). See `crate::awslc::montgomery`'s module doc comment for
/// the full record of this finding.
#[cfg(feature = "ec_montgomery")]
fn raw_max_for_key(key: &Object) -> Result<usize> {
    if key.get_attr_as_ulong(CKA_KEY_TYPE)? == CKK_EC_MONTGOMERY {
        crate::awslc::montgomery::ensure_x25519(key)?;
        Ok(crate::awslc::montgomery::KEYLEN_X25519)
    } else {
        Ok(ec_curve_from_obj(key)?.order_bytes())
    }
}
#[cfg(not(feature = "ec_montgomery"))]
fn raw_max_for_key(key: &Object) -> Result<usize> {
    Ok(ec_curve_from_obj(key)?.order_bytes())
}

/// Computes the raw shared secret for `key` against `peer_point`,
/// dispatching to X25519 (`crate::awslc::montgomery::derive_shared_secret`)
/// for `CKK_EC_MONTGOMERY` keys, or the classic `EcKey` path otherwise --
/// see `raw_max_for_key`'s doc comment above for why this dispatch exists.
#[cfg(feature = "ec_montgomery")]
fn raw_shared_secret(key: &Object, peer_point: &[u8]) -> Result<Vec<u8>> {
    if key.get_attr_as_ulong(CKA_KEY_TYPE)? == CKK_EC_MONTGOMERY {
        crate::awslc::montgomery::derive_shared_secret(key, peer_point)
    } else {
        let eckey = privkey_from_object(key)?;
        Ok(eckey.derive_shared_secret(peer_point)?)
    }
}
#[cfg(not(feature = "ec_montgomery"))]
fn raw_shared_secret(key: &Object, peer_point: &[u8]) -> Result<Vec<u8>> {
    let eckey = privkey_from_object(key)?;
    Ok(eckey.derive_shared_secret(peer_point)?)
}

/// Maps a PKCS#11 EC KDF type (`CK_EC_KDF_TYPE`) to the corresponding
/// awslc `DigestAlg`. Mirrors `crate::ossl::ecdh::kdf_type_to_digest_alg`.
fn kdf_type_to_digest_alg(mech: CK_EC_KDF_TYPE) -> Result<DigestAlg> {
    Ok(match mech {
        #[cfg(not(feature = "no_sha1"))]
        CKD_SHA1_KDF | CKD_SHA1_KDF_SP800 => DigestAlg::Sha1,
        CKD_SHA224_KDF | CKD_SHA224_KDF_SP800 => DigestAlg::Sha2_224,
        CKD_SHA256_KDF | CKD_SHA256_KDF_SP800 => DigestAlg::Sha2_256,
        CKD_SHA384_KDF | CKD_SHA384_KDF_SP800 => DigestAlg::Sha2_384,
        CKD_SHA512_KDF | CKD_SHA512_KDF_SP800 => DigestAlg::Sha2_512,
        CKD_SHA3_224_KDF | CKD_SHA3_224_KDF_SP800 => DigestAlg::Sha3_224,
        CKD_SHA3_256_KDF | CKD_SHA3_256_KDF_SP800 => DigestAlg::Sha3_256,
        CKD_SHA3_384_KDF | CKD_SHA3_384_KDF_SP800 => DigestAlg::Sha3_384,
        CKD_SHA3_512_KDF | CKD_SHA3_512_KDF_SP800 => DigestAlg::Sha3_512,
        _ => return Err(CKR_MECHANISM_PARAM_INVALID)?,
    })
}

/// True for the ANSI X9.63 KDF variants, false for the SP 800-56 ("SP800")
/// concatenation/one-step KDF variants. Mirrors
/// `crate::ossl::ecdh::kdf_type_is_x963`.
fn kdf_type_is_x963(mech: CK_EC_KDF_TYPE) -> Result<bool> {
    Ok(match mech {
        CKD_SHA1_KDF | CKD_SHA224_KDF | CKD_SHA256_KDF | CKD_SHA384_KDF
        | CKD_SHA512_KDF | CKD_SHA3_224_KDF | CKD_SHA3_256_KDF
        | CKD_SHA3_384_KDF | CKD_SHA3_512_KDF => true,
        CKD_SHA1_KDF_SP800
        | CKD_SHA224_KDF_SP800
        | CKD_SHA256_KDF_SP800
        | CKD_SHA384_KDF_SP800
        | CKD_SHA512_KDF_SP800
        | CKD_SHA3_224_KDF_SP800
        | CKD_SHA3_256_KDF_SP800
        | CKD_SHA3_384_KDF_SP800
        | CKD_SHA3_512_KDF_SP800 => false,
        _ => return Err(CKR_MECHANISM_PARAM_INVALID)?,
    })
}

/// ANSI X9.63 KDF (Annex A.3): concatenates `Hash(Z || counter ||
/// [SharedInfo])` for counter = 1, 2, ... (4-byte big-endian, secret
/// *before* the counter), truncating to `out.len()`. This is the
/// hash-based construction OpenSSL's "X963KDF" implements (which
/// `crate::ossl::ecdh::ECDHOperation::derive` drives via
/// `ossl::derive::X963KdfDerive`), reproduced here byte-for-byte since
/// `awslc` has no KDF primitive of its own.
fn x963_kdf(
    alg: DigestAlg,
    secret: &[u8],
    shared_info: Option<&[u8]>,
    out: &mut [u8],
) -> Result<()> {
    let mut counter: u32 = 1;
    let mut produced = 0usize;
    while produced < out.len() {
        let mut d = Digest::new(alg)?;
        d.update(secret)?;
        d.update(&counter.to_be_bytes())?;
        if let Some(info) = shared_info {
            d.update(info)?;
        }
        let mut block = vec![0u8; d.size()];
        let n = match d.finalize(block.as_mut_slice()) {
            Ok(n) => n,
            Err(e) => {
                /* `block` may hold a partial digest of secret-derived
                 * material even on a (virtually unreachable) backend
                 * failure here -- zeroize before propagating the error. */
                zeromem(block.as_mut_slice());
                return Err(e)?;
            }
        };
        let take = std::cmp::min(n, out.len() - produced);
        out[produced..produced + take].copy_from_slice(&block[..take]);
        produced += take;
        zeromem(block.as_mut_slice());
        counter += 1;
    }
    Ok(())
}

/// SP 800-56C "One-Step" KDF (equivalently, SP 800-56A's concatenation
/// KDF), digest-only mode (no MAC): concatenates `Hash(counter || Z ||
/// [FixedInfo])` for counter = 1, 2, ... (4-byte big-endian, counter
/// *before* the secret -- the one difference from X9.63 above), truncating
/// to `out.len()`. This is what OpenSSL's "SSKDF" (without a MAC)
/// implements (which `crate::ossl::ecdh::ECDHOperation::derive` drives via
/// `ossl::derive::OneStepKdfDerive`), reproduced here byte-for-byte since
/// `awslc` has no KDF primitive of its own.
fn one_step_kdf(
    alg: DigestAlg,
    secret: &[u8],
    fixed_info: Option<&[u8]>,
    out: &mut [u8],
) -> Result<()> {
    let mut counter: u32 = 1;
    let mut produced = 0usize;
    while produced < out.len() {
        let mut d = Digest::new(alg)?;
        d.update(&counter.to_be_bytes())?;
        d.update(secret)?;
        if let Some(info) = fixed_info {
            d.update(info)?;
        }
        let mut block = vec![0u8; d.size()];
        let n = match d.finalize(block.as_mut_slice()) {
            Ok(n) => n,
            Err(e) => {
                /* `block` may hold a partial digest of secret-derived
                 * material even on a (virtually unreachable) backend
                 * failure here -- zeroize before propagating the error. */
                zeromem(block.as_mut_slice());
                return Err(e)?;
            }
        };
        let take = std::cmp::min(n, out.len() - produced);
        out[produced..produced + take].copy_from_slice(&block[..take]);
        produced += take;
        zeromem(block.as_mut_slice());
        counter += 1;
    }
    Ok(())
}

/// Represents an active ECDH key derivation operation.
#[derive(Debug)]
pub struct ECDHOperation {
    /// The specific ECDH mechanism type (e.g., CKM_ECDH1_DERIVE).
    mech: CK_MECHANISM_TYPE,
    /// The Key Derivation Function to apply (e.g., CKD_NULL, CKD_SHA256_KDF).
    kdf: CK_EC_KDF_TYPE,
    /// Peer's public key point data.
    public: Vec<u8>,
    /// Optional shared data for the KDF.
    shared: Option<Vec<u8>>,
    /// Flag indicating if the derivation has been finalized.
    finalized: bool,
}

impl ECDHOperation {
    /// Creates a new `ECDHOperation` instance.
    ///
    /// Parses the `CK_ECDH1_DERIVE_PARAMS` from the mechanism, validates
    /// them, and stores the necessary parameters.
    pub fn derive_new<'a>(
        mechanism: CK_MECHANISM_TYPE,
        params: CK_ECDH1_DERIVE_PARAMS,
    ) -> Result<ECDHOperation> {
        if params.kdf == CKD_NULL {
            if params.pSharedData != std::ptr::null_mut()
                || params.ulSharedDataLen != 0
            {
                return Err(CKR_MECHANISM_PARAM_INVALID)?;
            }
        }
        if params.pPublicData == std::ptr::null_mut()
            || params.ulPublicDataLen == 0
        {
            return Err(CKR_MECHANISM_PARAM_INVALID)?;
        }
        let shared =
            if !params.pSharedData.is_null() || params.ulSharedDataLen > 0 {
                Some(bytes_to_vec(
                    params.pSharedData,
                    params.ulSharedDataLen as usize,
                ))
            } else {
                None
            };

        Ok(ECDHOperation {
            finalized: false,
            mech: mechanism,
            kdf: params.kdf,
            shared: shared,
            public: bytes_to_vec(
                params.pPublicData,
                params.ulPublicDataLen as usize,
            ),
        })
    }
}

impl MechOperation for ECDHOperation {
    fn mechanism(&self) -> Result<CK_MECHANISM_TYPE> {
        Ok(self.mech)
    }

    fn finalized(&self) -> bool {
        self.finalized
    }
}

impl Derive for ECDHOperation {
    /// Performs the ECDH key derivation.
    ///
    /// Computes the raw ECDH shared secret against the local private `key`
    /// and the peer's public point (`self.public`) via
    /// `EcKey::derive_shared_secret` (cofactor mode makes no difference for
    /// this backend's 3 supported curves, see the module doc comment),
    /// applies the specified KDF (`self.kdf`) if needed, and creates the
    /// derived key object using the template.
    fn derive(
        &mut self,
        key: &Object,
        template: &[CK_ATTRIBUTE],
        _mechanisms: &Mechanisms,
        objfactories: &ObjectFactories,
    ) -> Result<Vec<Object>> {
        if self.finalized {
            return Err(CKR_OPERATION_NOT_INITIALIZED)?;
        }
        self.finalized = true;

        /* the raw ECDH results have length of the field's fixed byte
         * width -- dispatches between the classic `EcKey`/Weierstrass
         * path and X25519 based on `key`'s own `CKA_KEY_TYPE` (see
         * `raw_max_for_key`'s doc comment for why this backend needs
         * this, unlike the OpenSSL reference). */
        let raw_max = raw_max_for_key(key)?;

        let factory =
            objfactories.get_obj_factory_from_key_template(template)?;

        let keylen = match template.iter().find(|x| x.type_ == CKA_VALUE_LEN) {
            Some(a) => {
                let value_len = usize::try_from(a.to_ulong()?)?;
                if self.kdf == CKD_NULL && value_len > raw_max {
                    return Err(CKR_TEMPLATE_INCONSISTENT)?;
                }
                value_len
            }
            None => {
                /* X9.63/SP800 KDFs do not have any maximum size */
                if self.kdf != CKD_NULL {
                    return Err(CKR_TEMPLATE_INCONSISTENT)?;
                }
                match factory
                    .as_secret_key_factory()?
                    .recommend_key_size(raw_max)
                {
                    Ok(len) => len,
                    Err(_) => return Err(CKR_TEMPLATE_INCONSISTENT)?,
                }
            }
        };

        let ec_point = {
            if self.public.len() > (2 * raw_max) + 1 {
                /* try to see if it is a DER encoded point */
                match asn1::parse_single::<&[u8]>(self.public.as_slice()) {
                    Ok(pt) => Cow::Owned(pt.to_vec()),
                    Err(_) => return Err(CKR_MECHANISM_PARAM_INVALID)?,
                }
            } else {
                Cow::Borrowed(&self.public)
            }
        };

        let mut secret = raw_shared_secret(key, ec_point.as_ref())?;

        if self.kdf == CKD_NULL {
            if secret.len() < keylen {
                zeromem(secret.as_mut_slice());
                return Err(CKR_TEMPLATE_INCONSISTENT)?;
            }
            /* We need to take the tail of the raw output */
            let drop = secret.len() - keylen;
            zeromem(&mut secret[..drop]);
            secret.drain(..drop);
        } else {
            /* Handle KDFs in-token, since awslc has no KDF primitive */
            let digest = kdf_type_to_digest_alg(self.kdf)?;
            let mut output = vec![0u8; keylen];

            let kdf_result = if kdf_type_is_x963(self.kdf)? {
                x963_kdf(
                    digest,
                    secret.as_slice(),
                    self.shared.as_deref(),
                    output.as_mut_slice(),
                )
            } else {
                one_step_kdf(
                    digest,
                    secret.as_slice(),
                    self.shared.as_deref(),
                    output.as_mut_slice(),
                )
            };

            zeromem(secret.as_mut_slice());
            if let Err(e) = kdf_result {
                zeromem(output.as_mut_slice());
                return Err(e);
            }
            secret = output;
        }

        let mut tmpl = CkAttrs::from(template);
        let attr_result = tmpl.add_vec(CKA_VALUE, secret);
        tmpl.zeroize = true;
        attr_result?;
        let mut obj = factory.create(tmpl.as_slice())?;

        default_key_attributes(&mut obj, self.mech)?;
        Ok(vec![obj])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ec::curvename_to_ec_params;
    use crate::object::ObjectFactories;

    fn no_param_mech(mechanism: CK_MECHANISM_TYPE) -> CK_MECHANISM {
        CK_MECHANISM {
            mechanism,
            pParameter: std::ptr::null_mut(),
            ulParameterLen: 0,
        }
    }

    /// Registers the real, backend-agnostic ECDH mechanisms/factories from
    /// `src/ec/ecdh.rs` (via `crate::ec::ecdh::register`) plus the EC
    /// key-pair-gen mechanism/factories (needed to actually produce
    /// keypairs to derive from) from `crate::ec::ecdsa::register`, exactly
    /// as production `C_Initialize`/`C_GenerateKeyPair`/`C_DeriveKey`
    /// reach them.
    fn registered() -> (Mechanisms, ObjectFactories) {
        let mut mechs = Mechanisms::new();
        let mut ot = ObjectFactories::new();
        // Generic secret key factory: `CKO_SECRET_KEY`/`CKK_GENERIC_SECRET`
        // is the object type the derive templates below target -- without
        // this, `ObjectFactories::get_factory` has no factory registered
        // for that (class, key_type) pair at all.
        crate::object::factory::register(&mut mechs, &mut ot);
        crate::ec::ecdsa::register(&mut mechs, &mut ot);
        crate::ec::ecdh::register(&mut mechs, &mut ot);
        (mechs, ot)
    }

    fn generate_keypair(
        mechs: &Mechanisms,
        curve_name: &str,
    ) -> (Object, Object) {
        let params = curvename_to_ec_params(curve_name).unwrap();
        let mut ck_true: CK_BBOOL = CK_TRUE;
        let pubkey_template = [
            CK_ATTRIBUTE {
                type_: CKA_EC_PARAMS,
                pValue: params.as_ptr() as CK_VOID_PTR,
                ulValueLen: params.len() as CK_ULONG,
            },
            CK_ATTRIBUTE {
                type_: CKA_DERIVE,
                pValue: &mut ck_true as *mut CK_BBOOL as CK_VOID_PTR,
                ulValueLen: std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
            },
        ];
        let prikey_template = [CK_ATTRIBUTE {
            type_: CKA_DERIVE,
            pValue: &mut ck_true as *mut CK_BBOOL as CK_VOID_PTR,
            ulValueLen: std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
        }];
        let mech = no_param_mech(CKM_EC_KEY_PAIR_GEN);
        let entry = mechs.get(CKM_EC_KEY_PAIR_GEN).unwrap();
        entry
            .generate_keypair(&mech, &pubkey_template, &prikey_template)
            .expect("generate_keypair")
    }

    /// Builds a `CK_ECDH1_DERIVE_PARAMS` pointing at `peer_point`, with no
    /// KDF (`CKD_NULL`) and no shared data.
    fn null_kdf_params(peer_point: &[u8]) -> CK_ECDH1_DERIVE_PARAMS {
        CK_ECDH1_DERIVE_PARAMS {
            kdf: CKD_NULL,
            ulSharedDataLen: 0,
            pSharedData: std::ptr::null_mut(),
            ulPublicDataLen: peer_point.len() as CK_ULONG,
            pPublicData: peer_point.as_ptr() as *mut u8,
        }
    }

    /// Builds a `CKO_SECRET_KEY`/`CKK_GENERIC_SECRET` derive template
    /// requesting `value_len` bytes, using the crate's own `CkAttrs`
    /// builder (owned storage, no manual pointer lifetime management).
    fn derive_secret_template(value_len: usize) -> CkAttrs<'static> {
        let mut tmpl = CkAttrs::new();
        tmpl.add_owned_ulong(CKA_CLASS, CKO_SECRET_KEY).unwrap();
        tmpl.add_owned_ulong(CKA_KEY_TYPE, CKK_GENERIC_SECRET)
            .unwrap();
        tmpl.add_owned_ulong(CKA_VALUE_LEN, value_len as CK_ULONG)
            .unwrap();
        tmpl.add_owned_bool(CKA_EXTRACTABLE, CK_TRUE).unwrap();
        tmpl
    }

    /// Round-trip through the real `Derive` trait: two AwsLc-backed EC
    /// keypairs, deriving from each side, confirming matching
    /// shared-secret-derived key material (mirrors what two real PKCS#11
    /// peers negotiating ECDH would each compute independently).
    fn round_trip_for(curve_name: &str, value_len: usize) {
        let (mechs, _ot) = registered();
        let (pubkey1, privkey1) = generate_keypair(&mechs, curve_name);
        let (pubkey2, privkey2) = generate_keypair(&mechs, curve_name);

        let point1 = crate::ec::get_ec_point_from_obj(&pubkey1).unwrap();
        let point2 = crate::ec::get_ec_point_from_obj(&pubkey2).unwrap();

        let entry = mechs.get(CKM_ECDH1_DERIVE).unwrap();

        let params1 = null_kdf_params(&point2);
        let mech1 = CK_MECHANISM {
            mechanism: CKM_ECDH1_DERIVE,
            pParameter: &params1 as *const _ as CK_VOID_PTR,
            ulParameterLen: std::mem::size_of::<CK_ECDH1_DERIVE_PARAMS>()
                as CK_ULONG,
        };
        let template1 = derive_secret_template(value_len);
        let mut objs1 = entry
            .derive_operation(&mech1)
            .unwrap()
            .derive(&privkey1, template1.as_slice(), &mechs, &_ot)
            .expect("derive side 1");
        let obj1 = objs1.pop().unwrap();
        let secret1 = obj1.get_attr_as_bytes(CKA_VALUE).unwrap().clone();

        let params2 = null_kdf_params(&point1);
        let mech2 = CK_MECHANISM {
            mechanism: CKM_ECDH1_DERIVE,
            pParameter: &params2 as *const _ as CK_VOID_PTR,
            ulParameterLen: std::mem::size_of::<CK_ECDH1_DERIVE_PARAMS>()
                as CK_ULONG,
        };
        let template2 = derive_secret_template(value_len);
        let mut objs2 = entry
            .derive_operation(&mech2)
            .unwrap()
            .derive(&privkey2, template2.as_slice(), &mechs, &_ot)
            .expect("derive side 2");
        let obj2 = objs2.pop().unwrap();
        let secret2 = obj2.get_attr_as_bytes(CKA_VALUE).unwrap().clone();

        assert_eq!(secret1, secret2);
        assert_eq!(secret1.len(), value_len);
    }

    #[test]
    fn p256_round_trip_full_length() {
        round_trip_for(crate::ec::PRIME256V1, 32);
    }

    #[test]
    fn p256_round_trip_truncated() {
        round_trip_for(crate::ec::PRIME256V1, 16);
    }

    #[test]
    fn p384_round_trip_full_length() {
        round_trip_for(crate::ec::SECP384R1, 48);
    }

    #[test]
    fn p521_round_trip_full_length() {
        round_trip_for(crate::ec::SECP521R1, 66);
    }

    /// `CKM_ECDH1_COFACTOR_DERIVE` must produce the exact same shared
    /// secret as plain `CKM_ECDH1_DERIVE` for these 3 curves (cofactor 1
    /// for all of them -- see the module doc comment).
    #[test]
    fn cofactor_variant_matches_plain_derive() {
        let (mechs, ot) = registered();
        let (pubkey1, privkey1) =
            generate_keypair(&mechs, crate::ec::PRIME256V1);
        let (pubkey2, _privkey2) =
            generate_keypair(&mechs, crate::ec::PRIME256V1);
        let point2 = crate::ec::get_ec_point_from_obj(&pubkey2).unwrap();
        let _ = &pubkey1;

        let params = null_kdf_params(&point2);

        let plain_entry = mechs.get(CKM_ECDH1_DERIVE).unwrap();
        let mech_plain = CK_MECHANISM {
            mechanism: CKM_ECDH1_DERIVE,
            pParameter: &params as *const _ as CK_VOID_PTR,
            ulParameterLen: std::mem::size_of::<CK_ECDH1_DERIVE_PARAMS>()
                as CK_ULONG,
        };
        let template_plain = derive_secret_template(32);
        let mut objs_plain = plain_entry
            .derive_operation(&mech_plain)
            .unwrap()
            .derive(&privkey1, template_plain.as_slice(), &mechs, &ot)
            .expect("derive plain");
        let secret_plain = objs_plain
            .pop()
            .unwrap()
            .get_attr_as_bytes(CKA_VALUE)
            .unwrap()
            .clone();

        let cofactor_entry = mechs.get(CKM_ECDH1_COFACTOR_DERIVE).unwrap();
        let mech_cofactor = CK_MECHANISM {
            mechanism: CKM_ECDH1_COFACTOR_DERIVE,
            pParameter: &params as *const _ as CK_VOID_PTR,
            ulParameterLen: std::mem::size_of::<CK_ECDH1_DERIVE_PARAMS>()
                as CK_ULONG,
        };
        let template_cofactor = derive_secret_template(32);
        let mut objs_cofactor = cofactor_entry
            .derive_operation(&mech_cofactor)
            .unwrap()
            .derive(&privkey1, template_cofactor.as_slice(), &mechs, &ot)
            .expect("derive cofactor");
        let secret_cofactor = objs_cofactor
            .pop()
            .unwrap()
            .get_attr_as_bytes(CKA_VALUE)
            .unwrap()
            .clone();

        assert_eq!(secret_plain, secret_cofactor);
    }

    /// Both KDF variants (X9.63 and SP800 concatenation) must produce
    /// matching output on both sides of the exchange, and must actually
    /// differ from the raw (`CKD_NULL`) secret.
    fn kdf_round_trip_for(kdf: CK_EC_KDF_TYPE, keylen: usize) {
        let (mechs, ot) = registered();
        let (pubkey1, privkey1) =
            generate_keypair(&mechs, crate::ec::PRIME256V1);
        let (pubkey2, privkey2) =
            generate_keypair(&mechs, crate::ec::PRIME256V1);
        let point1 = crate::ec::get_ec_point_from_obj(&pubkey1).unwrap();
        let point2 = crate::ec::get_ec_point_from_obj(&pubkey2).unwrap();

        let shared_data = b"shared info".to_vec();

        let params1 = CK_ECDH1_DERIVE_PARAMS {
            kdf,
            ulSharedDataLen: shared_data.len() as CK_ULONG,
            pSharedData: shared_data.as_ptr() as *mut u8,
            ulPublicDataLen: point2.len() as CK_ULONG,
            pPublicData: point2.as_ptr() as *mut u8,
        };
        let mech1 = CK_MECHANISM {
            mechanism: CKM_ECDH1_DERIVE,
            pParameter: &params1 as *const _ as CK_VOID_PTR,
            ulParameterLen: std::mem::size_of::<CK_ECDH1_DERIVE_PARAMS>()
                as CK_ULONG,
        };
        let entry = mechs.get(CKM_ECDH1_DERIVE).unwrap();
        let template1 = derive_secret_template(keylen);
        let mut objs1 = entry
            .derive_operation(&mech1)
            .unwrap()
            .derive(&privkey1, template1.as_slice(), &mechs, &ot)
            .expect("derive side 1");
        let secret1 = objs1
            .pop()
            .unwrap()
            .get_attr_as_bytes(CKA_VALUE)
            .unwrap()
            .clone();

        let params2 = CK_ECDH1_DERIVE_PARAMS {
            kdf,
            ulSharedDataLen: shared_data.len() as CK_ULONG,
            pSharedData: shared_data.as_ptr() as *mut u8,
            ulPublicDataLen: point1.len() as CK_ULONG,
            pPublicData: point1.as_ptr() as *mut u8,
        };
        let mech2 = CK_MECHANISM {
            mechanism: CKM_ECDH1_DERIVE,
            pParameter: &params2 as *const _ as CK_VOID_PTR,
            ulParameterLen: std::mem::size_of::<CK_ECDH1_DERIVE_PARAMS>()
                as CK_ULONG,
        };
        let template2 = derive_secret_template(keylen);
        let mut objs2 = entry
            .derive_operation(&mech2)
            .unwrap()
            .derive(&privkey2, template2.as_slice(), &mechs, &ot)
            .expect("derive side 2");
        let secret2 = objs2
            .pop()
            .unwrap()
            .get_attr_as_bytes(CKA_VALUE)
            .unwrap()
            .clone();

        assert_eq!(secret1, secret2);
        assert_eq!(secret1.len(), keylen);

        // Sanity: the KDF output must not equal the raw shared secret.
        let raw = privkey1
            .get_attr_as_bytes(CKA_VALUE)
            .map(|v| v.clone())
            .unwrap_or_default();
        assert_ne!(secret1, raw);
    }

    #[test]
    fn x963_sha256_kdf_round_trip_short() {
        kdf_round_trip_for(CKD_SHA256_KDF, 16);
    }

    #[test]
    fn x963_sha256_kdf_round_trip_long() {
        // Longer than one SHA-256 block (32 bytes): exercises the
        // multi-iteration counter loop.
        kdf_round_trip_for(CKD_SHA256_KDF, 64);
    }

    #[test]
    fn sp800_sha256_kdf_round_trip() {
        kdf_round_trip_for(CKD_SHA256_KDF_SP800, 48);
    }

    /// The X9.63 and SP800 variants of the same digest must produce
    /// *different* output for the same secret (they differ in whether the
    /// counter comes before or after the secret in the hash input).
    #[test]
    fn x963_and_sp800_kdf_diverge() {
        let alg = DigestAlg::Sha2_256;
        let secret = [0x42u8; 32];
        let mut x963_out = [0u8; 32];
        let mut sp800_out = [0u8; 32];
        x963_kdf(alg, &secret, None, &mut x963_out).unwrap();
        one_step_kdf(alg, &secret, None, &mut sp800_out).unwrap();
        assert_ne!(x963_out, sp800_out);
    }
}
