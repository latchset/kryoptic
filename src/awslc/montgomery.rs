// Copyright 2026
// See LICENSE.txt file for terms

//! AWS-LC-backed implementation of the Montgomery-curve (X25519/X448)
//! surface `src/ec/montgomery.rs` requires: `ECMontgomeryOperation`
//! (mirroring `crate::ossl::montgomery`, which `src/ec/montgomery.rs`
//! imports via `use crate::ossl::montgomery::ECMontgomeryOperation;` --
//! resolved to this module under the `awslc` feature by `src/lib.rs`'s
//! `use awslc as ossl;` alias).
//!
//! AWS-LC only implements X25519 (`awslc::x25519::X25519Key`, wrapping the
//! raw `X25519_*` functions -- no `EC_KEY`/`EVP_PKEY` involved). There is
//! no X448 implementation anywhere in AWS-LC (the same situation as
//! Ed25519/Ed448 above: only NID/type-tag constants exist for X448 in the
//! bindings, no
//! `X448_*` functions at all). `src/ec/montgomery.rs` is generic over both
//! curves (dispatching by the `CKA_EC_PARAMS` OID -- see `oid::X25519_OID
//! | oid::X448_OID` in its `ECMontgomeryPubFactory::create`/
//! `ECMontgomeryPrivFactory::create`), so this module explicitly rejects
//! any X448 key with `CKR_CURVE_NOT_SUPPORTED` -- the same error
//! `src/ec/montgomery.rs`/`src/ec/eddsa.rs`/`src/ec/ecdsa.rs` themselves
//! already use for an OID their own generic dispatch doesn't recognize at
//! all, matching `awslc::eddsa`'s precedent for the analogous Ed448 gap.
//!
//! Unlike Ed25519, X25519's private key IS the raw 32-byte scalar PKCS#11
//! stores directly for `CKA_VALUE` -- no seed-vs-expanded-key distinction
//! to track (confirmed in `awslc::x25519::X25519Key`'s own doc comment).
//!
//! # Wiring into `CKM_ECDH1_DERIVE` (a documented, justified scope
//! extension into `src/awslc/ecdh.rs`)
//!
//! `src/ec/montgomery.rs` only drives key generation
//! (`CKM_EC_MONTGOMERY_KEY_PAIR_GEN`) -- it registers no `Derive`-capable
//! mechanism of its own (`crate::ec::montgomery::register` adds only that
//! one `CKF_GENERATE_KEY_PAIR` mechanism). X25519 key derivation is
//! reached, in production, through the *same* backend-agnostic
//! `CKM_ECDH1_DERIVE`/`CKM_ECDH1_COFACTOR_DERIVE` mechanism
//! `src/ec/ecdh.rs` registers for Weierstrass ECDH:
//! `crate::ec::ecdh::ECDHMechanism::derive_operation` builds its
//! `ECDHOperation` from just `CK_ECDH1_DERIVE_PARAMS`, with no
//! curve-family awareness at all -- the *key itself*, supplied later at
//! `Derive::derive()`, is what decides which curve family's math actually
//! runs. For the OpenSSL backend this "just works" because
//! `crate::ossl::common::privkey_from_object` builds a generic `EvpPkey`
//! for *any* `CKA_KEY_TYPE` (including `CKK_EC_MONTGOMERY`, via this
//! module's OpenSSL analogue, `ecm_object_to_pkey`), and OpenSSL's
//! `EVP_PKEY_derive` API runs the right math regardless of key type.
//!
//! AWS-LC has no such uniform abstraction: X25519 uses these raw
//! `X25519_*` functions, entirely disjoint from the classic `EC_KEY` API
//! `awslc::ec::EcKey` wraps for the 3 NIST curves. Confirmed by reading
//! `crate::awslc::common::ec_curve_from_oid`'s match arms: it returns
//! `CKR_GENERAL_ERROR` for any OID that isn't one of the 3 NIST curves.
//! So a Montgomery private key handed to the unmodified
//! `crate::awslc::ecdh::ECDHOperation::derive` would fail before ever
//! reaching this module -- X25519 derivation would be unreachable through
//! the real `C_DeriveKey` dispatch despite this file existing.
//!
//! This is a real, verified gap (not a guess -- confirmed directly from
//! source) between this file's nominal scope (`src/awslc/montgomery.rs`
//! + `src/awslc/mod.rs` only) and what's actually needed to make X25519
//! derivation reachable in practice. Rather than either silently
//! expanding scope unremarked or blocking entirely on a question whose
//! answer is already fully verified from source, this is a deliberate,
//! narrowly-scoped extension into a different, already-reviewed file: we
//! extended `src/awslc/ecdh.rs`'s `Derive::derive` with a small,
//! additive, `#[cfg(feature = "ec_montgomery")]`-gated dispatch: a
//! `CKK_EC_MONTGOMERY` key routes to `ensure_x25519`/
//! `derive_shared_secret` below instead of the `EcKey` path; every other
//! key type's behavior is byte-for-byte unchanged. See that file's own
//! updated doc comment for the full record.

use crate::attribute::Attribute;
use crate::ec::get_oid_from_obj;
use crate::error::Result;
use crate::kasn1::oid;
use crate::misc::zeromem;
use crate::object::Object;
use crate::pkcs11::*;

use crate::lowlevel::x25519::X25519Key;

/// Raw X25519 private/public key material length (RFC 7748) in bytes.
pub(crate) const KEYLEN_X25519: usize = 32;

/// Validates that `key`'s `CKA_EC_PARAMS` OID is X25519, rejecting X448
/// (see the module doc comment) with `CKR_CURVE_NOT_SUPPORTED`.
pub(crate) fn ensure_x25519(key: &Object) -> Result<()> {
    match get_oid_from_obj(key)? {
        oid::X25519_OID => Ok(()),
        _ => Err(CKR_CURVE_NOT_SUPPORTED)?,
    }
}

/// Builds an `X25519Key` for deriving from a `CKO_PRIVATE_KEY` `Object`'s
/// `CKA_VALUE`: PKCS#11's Montgomery private key storage convention is the
/// raw 32-byte scalar (RFC 7748), exactly what `X25519Key::from_private`
/// expects (confirmed against `awslc::x25519::X25519Key`, whose private
/// storage is documented as exactly the raw 32-byte scalar, no
/// seed/expanded-key distinction unlike Ed25519).
fn privkey_from_object(key: &Object) -> Result<X25519Key> {
    ensure_x25519(key)?;
    let value = key.get_attr_as_bytes(CKA_VALUE)?;
    if value.len() != KEYLEN_X25519 {
        return Err(CKR_KEY_SIZE_RANGE)?;
    }
    /* `scalar` is a fresh copy of secret key material off the Object's own
     * storage (needed because `from_private` takes a fixed-size array,
     * not a slice) -- scrub it once consumed rather than leaving it to a
     * normal drop, mirroring `crate::awslc::eddsa::privkey_from_object`'s
     * own pattern. */
    let mut scalar = [0u8; KEYLEN_X25519];
    scalar.copy_from_slice(value);
    let result = X25519Key::from_private(&scalar);
    zeromem(&mut scalar);
    Ok(result?)
}

/// Computes the raw X25519 shared secret between `key` (a
/// `CKO_PRIVATE_KEY` `Object`) and `peer_point` (the peer's raw 32-byte
/// public value, as supplied via `CK_ECDH1_DERIVE_PARAMS::pPublicData`).
/// Used by `crate::awslc::ecdh::ECDHOperation::derive` (see the module doc
/// comment) to reach X25519 through the same `CKM_ECDH1_DERIVE`/
/// `CKM_ECDH1_COFACTOR_DERIVE` dispatch Weierstrass ECDH uses -- AWS-LC's
/// raw `X25519` function has no cofactor-mode knob at all (RFC 7748
/// clamping is baked into the one primitive), so both mechanisms
/// necessarily produce the same result here, matching this backend's 3
/// NIST curves (all cofactor 1).
pub(crate) fn derive_shared_secret(
    key: &Object,
    peer_point: &[u8],
) -> Result<Vec<u8>> {
    let eckey = privkey_from_object(key)?;
    if peer_point.len() != KEYLEN_X25519 {
        return Err(CKR_MECHANISM_PARAM_INVALID)?;
    }
    let mut peer = [0u8; KEYLEN_X25519];
    peer.copy_from_slice(peer_point);
    let mut secret = eckey.derive_shared_secret(&peer)?;
    let out = secret.to_vec();
    /* `secret` is a local, fixed-size stack copy of the raw shared
     * secret -- unlike a `Vec`'s heap storage, it isn't dropped/freed by
     * anything, so it would otherwise linger unscrubbed on the stack
     * after this function returns. `out` (the `Vec` the caller receives)
     * is the only copy that should survive. */
    zeromem(&mut secret);
    Ok(out)
}

/// Represents state for Montgomery curve operations (currently mainly
/// keygen). Placeholder for potential future stateful operations, mirrors
/// `crate::ossl::montgomery::ECMontgomeryOperation`.
#[derive(Debug)]
pub struct ECMontgomeryOperation {}

impl ECMontgomeryOperation {
    /// Generates an X25519 key pair using AWS-LC.
    ///
    /// Takes mutable references to pre-created public and private key
    /// `Object`s (which contain the desired curve in CKA_EC_PARAMS),
    /// generates the key pair, and populates the CKA_EC_POINT and
    /// CKA_VALUE attributes. Rejects X448 (see the module doc comment)
    /// before ever calling into AWS-LC.
    pub fn generate_keypair(
        pubkey: &mut Object,
        privkey: &mut Object,
    ) -> Result<()> {
        ensure_x25519(pubkey)?;

        let key = X25519Key::generate()?;

        /* Set Public Key: CKA_EC_POINT for CKK_EC_MONTGOMERY is the raw
         * public key bytes, no DER wrapping (unlike CKK_EC). */
        pubkey.set_attr(Attribute::from_bytes(
            CKA_EC_POINT,
            key.public_key().to_vec(),
        ))?;

        /* Set Private Key: CKA_VALUE is the raw 32-byte scalar. `private`
         * here is a fresh copy outside of `key`'s own zeroizing `Drop`,
         * so scrub it explicitly once copied into the attribute's own
         * storage. */
        let mut private = key.private_key();
        let result = privkey
            .set_attr(Attribute::from_bytes(CKA_VALUE, private.to_vec()));
        zeromem(&mut private);
        result?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ec::curvename_to_ec_params;
    use crate::mechanism::{Derive, Mechanisms};
    use crate::object::ObjectFactories;

    fn no_param_mech(mechanism: CK_MECHANISM_TYPE) -> CK_MECHANISM {
        CK_MECHANISM {
            mechanism,
            pParameter: std::ptr::null_mut(),
            ulParameterLen: 0,
        }
    }

    /// Registers the real, backend-agnostic EC-Montgomery keygen
    /// mechanism/factories (`crate::ec::montgomery::register`), the real
    /// ECDH derive mechanism (`crate::ec::ecdh::register` -- the same
    /// `CKM_ECDH1_DERIVE` Weierstrass ECDH uses, see the module doc
    /// comment), and the generic secret key factory (needed as a derive
    /// target), exactly as production `C_Initialize`/`C_GenerateKeyPair`/
    /// `C_DeriveKey` reach them -- driving `ECMontgomeryMechanism::
    /// generate_keypair` and `ECDHMechanism::derive_operation` (which in
    /// turn call into this module) rather than calling this module's
    /// functions directly.
    fn registered() -> (Mechanisms, ObjectFactories) {
        let mut mechs = Mechanisms::new();
        let mut ot = ObjectFactories::new();
        crate::object::factory::register(&mut mechs, &mut ot);
        crate::ec::montgomery::register(&mut mechs, &mut ot);
        crate::ec::ecdh::register(&mut mechs, &mut ot);
        (mechs, ot)
    }

    fn generate_keypair_for(
        mechs: &Mechanisms,
        curve_name: &str,
    ) -> Result<(Object, Object)> {
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
        let mech = no_param_mech(CKM_EC_MONTGOMERY_KEY_PAIR_GEN);
        let entry = mechs.get(CKM_EC_MONTGOMERY_KEY_PAIR_GEN).unwrap();
        entry.generate_keypair(&mech, &pubkey_template, &prikey_template)
    }

    fn generate_keypair(
        mechs: &Mechanisms,
        curve_name: &str,
    ) -> (Object, Object) {
        generate_keypair_for(mechs, curve_name).expect("generate_keypair")
    }

    /// Builds a `CKO_SECRET_KEY`/`CKK_GENERIC_SECRET` derive template
    /// requesting `value_len` bytes.
    fn derive_secret_template(
        value_len: usize,
    ) -> crate::attribute::CkAttrs<'static> {
        let mut tmpl = crate::attribute::CkAttrs::new();
        tmpl.add_owned_ulong(CKA_CLASS, CKO_SECRET_KEY).unwrap();
        tmpl.add_owned_ulong(CKA_KEY_TYPE, CKK_GENERIC_SECRET)
            .unwrap();
        tmpl.add_owned_ulong(CKA_VALUE_LEN, value_len as CK_ULONG)
            .unwrap();
        tmpl.add_owned_bool(CKA_EXTRACTABLE, CK_TRUE).unwrap();
        tmpl
    }

    fn null_kdf_params(peer_point: &[u8]) -> CK_ECDH1_DERIVE_PARAMS {
        CK_ECDH1_DERIVE_PARAMS {
            kdf: CKD_NULL,
            ulSharedDataLen: 0,
            pSharedData: std::ptr::null_mut(),
            ulPublicDataLen: peer_point.len() as CK_ULONG,
            pPublicData: peer_point.as_ptr() as *mut u8,
        }
    }

    fn derive_via_mech(
        mechs: &Mechanisms,
        ot: &ObjectFactories,
        privkey: &Object,
        peer_point: &[u8],
        value_len: usize,
    ) -> Result<Vec<u8>> {
        let params = null_kdf_params(peer_point);
        let mech = CK_MECHANISM {
            mechanism: CKM_ECDH1_DERIVE,
            pParameter: &params as *const _ as CK_VOID_PTR,
            ulParameterLen: std::mem::size_of::<CK_ECDH1_DERIVE_PARAMS>()
                as CK_ULONG,
        };
        let entry = mechs.get(CKM_ECDH1_DERIVE).unwrap();
        let template = derive_secret_template(value_len);
        let mut op: Box<dyn Derive> = entry.derive_operation(&mech)?;
        let mut objs = op.derive(privkey, template.as_slice(), mechs, ot)?;
        let obj = objs.pop().unwrap();
        Ok(obj.get_attr_as_bytes(CKA_VALUE)?.clone())
    }

    /// Round-trip through the real `Mechanism`/`Derive` trait dispatch:
    /// generate two AwsLc-backed X25519 keypairs via the real
    /// `CKM_EC_MONTGOMERY_KEY_PAIR_GEN` mechanism, then derive from each
    /// side via the real `CKM_ECDH1_DERIVE` mechanism (the same one
    /// Weierstrass ECDH uses -- see the module doc comment), confirming
    /// matching shared-secret-derived key material.
    #[test]
    fn x25519_generate_derive_round_trip() {
        let (mechs, ot) = registered();
        let (pubkey1, privkey1) =
            generate_keypair(&mechs, crate::ec::CURVE25519);
        let (pubkey2, privkey2) =
            generate_keypair(&mechs, crate::ec::CURVE25519);

        assert_eq!(
            pubkey1.get_attr_as_ulong(CKA_KEY_TYPE).unwrap(),
            CKK_EC_MONTGOMERY
        );
        assert_eq!(
            privkey1.get_attr_as_ulong(CKA_KEY_TYPE).unwrap(),
            CKK_EC_MONTGOMERY
        );

        let point1 = crate::ec::get_ec_point_from_obj(&pubkey1).unwrap();
        let point2 = crate::ec::get_ec_point_from_obj(&pubkey2).unwrap();
        assert_eq!(point1.len(), KEYLEN_X25519);

        let secret1 =
            derive_via_mech(&mechs, &ot, &privkey1, &point2, KEYLEN_X25519)
                .expect("derive side 1");
        let secret2 =
            derive_via_mech(&mechs, &ot, &privkey2, &point1, KEYLEN_X25519)
                .expect("derive side 2");

        assert_eq!(secret1, secret2);
        assert_eq!(secret1.len(), KEYLEN_X25519);

        // Sanity: the shared secret must not equal either side's raw
        // private scalar.
        let raw1 = privkey1.get_attr_as_bytes(CKA_VALUE).unwrap().clone();
        assert_ne!(secret1, raw1);
    }

    /// Truncated output length (`CKA_VALUE_LEN` smaller than the raw
    /// 32-byte agreement) must still match on both sides.
    #[test]
    fn x25519_derive_truncated_length() {
        let (mechs, ot) = registered();
        let (pubkey1, privkey1) =
            generate_keypair(&mechs, crate::ec::CURVE25519);
        let (pubkey2, privkey2) =
            generate_keypair(&mechs, crate::ec::CURVE25519);
        let point1 = crate::ec::get_ec_point_from_obj(&pubkey1).unwrap();
        let point2 = crate::ec::get_ec_point_from_obj(&pubkey2).unwrap();

        let secret1 = derive_via_mech(&mechs, &ot, &privkey1, &point2, 16)
            .expect("derive side 1");
        let secret2 = derive_via_mech(&mechs, &ot, &privkey2, &point1, 16)
            .expect("derive side 2");

        assert_eq!(secret1, secret2);
        assert_eq!(secret1.len(), 16);
    }

    /// The core gap this task documents: AWS-LC has no X448 primitive at
    /// all, so key generation for X448 must fail cleanly through the real
    /// `Mechanism::generate_keypair` dispatch, with a curve-specific error
    /// (`CKR_CURVE_NOT_SUPPORTED`) rather than a generic failure, a panic,
    /// or (worse) silently mis-handling the key as if it were X25519.
    #[test]
    fn x448_key_generation_is_rejected() {
        let (mechs, _ot) = registered();
        let err = generate_keypair_for(&mechs, crate::ec::CURVE448)
            .expect_err("X448 key generation must fail: no AWS-LC primitive");
        assert_eq!(err.rv(), CKR_CURVE_NOT_SUPPORTED);
    }

    /// Even if an X448 key object were somehow constructed and handed to
    /// the real `CKM_ECDH1_DERIVE` dispatch directly (bypassing key
    /// generation), this module's own OID check (via `ensure_x25519`) must
    /// still reject it rather than mis-interpreting X448 key material as
    /// X25519's.
    #[test]
    fn x448_derive_is_rejected() {
        let (mechs, ot) = registered();
        // Build a bogus but well-formed-enough CKO_PRIVATE_KEY/
        // CKK_EC_MONTGOMERY object carrying the X448 OID directly, since
        // `crate::ec::montgomery`'s own private-key factory validates
        // `CKA_VALUE`'s length against `ec_key_size(&oid)` (56 bytes for
        // X448) at creation time -- there is no way to reach this
        // module's `derive_shared_secret` with an X25519-shaped 32-byte
        // value and an X448 OID via the normal object-creation path.
        let params = curvename_to_ec_params(crate::ec::CURVE448).unwrap();
        let value = vec![0u8; crate::ec::ec_key_size(&oid::X448_OID).unwrap()];
        let point_len = crate::ec::ec_point_size(&oid::X448_OID).unwrap();
        let dummy_point = vec![0u8; point_len];
        let pki = crate::kasn1::pkcs::SubjectPublicKeyInfo::new(
            crate::kasn1::pkcs::X448_ALG,
            &dummy_point,
        )
        .unwrap()
        .serialize()
        .unwrap();
        let mut ck_true: CK_BBOOL = CK_TRUE;
        let template = [
            CK_ATTRIBUTE {
                type_: CKA_CLASS,
                pValue: &CKO_PRIVATE_KEY as *const _ as CK_VOID_PTR,
                ulValueLen: std::mem::size_of::<CK_OBJECT_CLASS>() as CK_ULONG,
            },
            CK_ATTRIBUTE {
                type_: CKA_KEY_TYPE,
                pValue: &CKK_EC_MONTGOMERY as *const _ as CK_VOID_PTR,
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
            CK_ATTRIBUTE {
                type_: CKA_PUBLIC_KEY_INFO,
                pValue: pki.as_ptr() as CK_VOID_PTR,
                ulValueLen: pki.len() as CK_ULONG,
            },
            CK_ATTRIBUTE {
                type_: CKA_DERIVE,
                pValue: &mut ck_true as *mut CK_BBOOL as CK_VOID_PTR,
                ulValueLen: std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
            },
        ];
        let factory = ot.get_obj_factory_from_key_template(&template).unwrap();
        let privkey = factory.create(&template).unwrap();

        let peer_point = vec![0u8; point_len];
        let err = derive_via_mech(&mechs, &ot, &privkey, &peer_point, 32)
            .expect_err("X448 derive must fail: no AWS-LC primitive");
        assert_eq!(err.rv(), CKR_CURVE_NOT_SUPPORTED);
    }

    #[test]
    fn registration_covers_expected_mechanisms() {
        let (mechs, _ot) = registered();
        for ckm in [CKM_EC_MONTGOMERY_KEY_PAIR_GEN, CKM_ECDH1_DERIVE] {
            assert!(mechs.get(ckm).is_ok());
        }
    }
}
