// Copyright 2026
// See LICENSE.txt file for terms

//! AWS-LC-backed implementation of the FFDH (Finite Field Diffie-Hellman)
//! surface `src/ffdh.rs` requires: `FFDHOperation`, providing
//! `CKM_DH_PKCS_KEY_PAIR_GEN` key generation and `CKM_DH_PKCS_DERIVE` key
//! derivation (mirroring `crate::ossl::ffdh`, which `src/ffdh.rs` imports
//! via `use crate::ossl::ffdh::FFDHOperation;` -- resolved to this module
//! under the `awslc` feature by `src/lib.rs`'s `use awslc as ossl;` alias).
//!
//! # Mechanism reachability (verified, not assumed)
//!
//! Unlike X25519 (which is only reachable through ECDH's generic
//! `CKM_ECDH1_DERIVE` mechanism, because `src/ec/montgomery.rs` registers
//! no `Derive`-capable mechanism of its own), `src/ffdh.rs::register`
//! directly registers two dedicated `FFDHMechanism` entries of its own:
//! `CKM_DH_PKCS_DERIVE` (`CKF_DERIVE`) and `CKM_DH_PKCS_KEY_PAIR_GEN`
//! (`CKF_GENERATE_KEY_PAIR`) -- see `src/ffdh.rs`'s `register` function and
//! `FFDHMechanism::derive_operation`/`generate_keypair`, which dispatch
//! straight to `FFDHOperation::derive_new`/`FFDHOperation::generate_keypair`
//! below (through this module under the `awslc` feature). FFDH is
//! therefore fully self-contained: this file's `FFDHOperation` is reached
//! directly through its own mechanism registration, with no cross-file
//! dependency of the kind X25519 needs.
//!
//! # Fixed-width shared secret (a forced, narrow, additive change to
//! `awslc/src/dh.rs`, flagged for review)
//!
//! PKCS#11's `CKM_DH_PKCS_DERIVE` mechanism (implemented by `Derive::derive`
//! below, mirroring `crate::ossl::ffdh::FFDHOperation::derive`) needs a
//! fixed-width, deterministic shared secret: `CKA_VALUE_LEN` bytes are
//! taken from the low-order (rightmost) end of the full-width, big-endian
//! shared value -- the same "pad to the group's prime size, then take the
//! tail" convention `crate::awslc::ecdh::ECDHOperation::derive`'s `CKD_NULL`
//! branch already implements for EC. `awslc::dh::DhKey::derive_shared_secret`,
//! however, wraps AWS-LC's plain `DH_compute_key`, which strips
//! leading zero bytes and so returns a *variable*-length result --
//! confirmed directly from AWS-LC's own vendored header comment for the
//! sibling function it doesn't use (`aws-lc-sys`'s
//! `include/openssl/dh.h`, `DH_compute_key_padded`): "this function
//! differs from |DH_compute_key| in that it preserves leading zeros in the
//! secret... Callers that expect a fixed-width secret should use this
//! function over |DH_compute_key|." So the existing method cannot
//! correctly support this mechanism (an occasional leading-zero shared
//! value would silently shift which bytes get truncated, breaking
//! agreement with any peer that pads). This module therefore adds one new,
//! purely additive method to `awslc/src/dh.rs`,
//! `DhKey::derive_shared_secret_padded`, built on `DH_compute_key_padded`
//! instead, which always returns exactly `DH_size` (the prime's byte
//! width) bytes on success -- deterministically, unlike the reference
//! OpenSSL backend's own analogous code in `crate::ossl::ffdh::
//! FFDHOperation::derive`, whose comment notes its underlying
//! `ossl::derive::FfdhDerive` output length "is not fully deterministic and
//! can vary slightly"; AWS-LC's padded primitive has no such quirk, so this
//! module's `derive` below is simpler than that reference (no
//! recommend-key-size recheck/shrink fallback is needed). `derive_shared_secret`
//! itself, and its own existing tests, are untouched by this addition. See
//! `awslc/src/dh.rs`'s updated doc comment for the full record.

use crate::attribute::{Attribute, CkAttrs};
use crate::error::{Error, Result};
use crate::ffdh_groups::{self, DHGroupName};
use crate::mechanism::{Derive, MechOperation, Mechanisms};
use crate::misc::zeromem;
use crate::object::{default_key_attributes, Object, ObjectFactories};
use crate::pkcs11::*;

use crate::lowlevel::dh::DhKey;

/// Builds a `DhKey` for deriving from a `CKO_PRIVATE_KEY` `Object`.
///
/// Resolves the well-known group from `CKA_PRIME`/`CKA_BASE`
/// (`ffdh_groups::get_group_name` -- already validated once, at object
/// creation time, by `crate::ffdh::FFDHPrivFactory::create`; re-checked
/// here defensively, mirroring `crate::ossl::ffdh::ffdh_object_to_pkey`'s
/// own `CKR_KEY_INDIGESTIBLE` mapping for an unrecognized group), then
/// reconstructs the key from `CKA_VALUE` (the raw private scalar) via
/// `DhKey::from_private`. `key.get_attr_as_bytes(CKA_VALUE)` returns a
/// borrow of the `Object`'s own attribute storage (no extra copy is made
/// here); `DhKey::from_private` copies it into an AWS-LC-owned `BIGNUM`
/// inside the returned `DhKey`, which zeroizes nothing on drop (small
/// integers aren't scrubbed by AWS-LC's `BN_free`) but is otherwise the
/// same private-key-material lifetime `awslc::dh::DhKey` was already
/// reviewed against.
///
/// Returns the reconstructed key together with the group's prime byte
/// width (`DH_size`), used as the maximum derivable secret length.
fn privkey_from_object(key: &Object) -> Result<(DhKey, usize)> {
    let group = match ffdh_groups::get_group_name(key) {
        Ok(g) => g,
        Err(e) => return Err(Error::ck_rv_from_error(CKR_KEY_INDIGESTIBLE, e)),
    };
    let (p, g, _q) = ffdh_groups::group_values(group)?;
    let private = key.get_attr_as_bytes(CKA_VALUE)?;
    let dhkey = DhKey::from_private(p, g, private.as_slice())?;
    Ok((dhkey, p.len()))
}

/// Represents an active FFDH key derivation operation.
#[derive(Debug)]
pub struct FFDHOperation {
    /// The specific FFDH mechanism type (e.g., CKM_DH_PKCS_DERIVE).
    mech: CK_MECHANISM_TYPE,
    /// Peer's public key value.
    public: Vec<u8>,
    /// Flag indicating if the derivation has been finalized.
    finalized: bool,
}

impl FFDHOperation {
    /// Creates a new `FFDHOperation` instance.
    pub fn derive_new<'a>(
        mechanism: CK_MECHANISM_TYPE,
        peerpub: Vec<u8>,
    ) -> Result<FFDHOperation> {
        if peerpub.is_empty() {
            return Err(CKR_MECHANISM_PARAM_INVALID)?;
        }

        Ok(FFDHOperation {
            finalized: false,
            mech: mechanism,
            public: peerpub,
        })
    }

    /// Generates an FFDH key pair using AWS-LC.
    ///
    /// Takes mutable references to pre-created public and private key
    /// `Object`s, generates the key pair, and populates the CKA_VALUE
    /// attributes for both the private and public key objects.
    pub fn generate_keypair(
        group: DHGroupName,
        pubkey: &mut Object,
        privkey: &mut Object,
    ) -> Result<()> {
        let (p, g, _q) = ffdh_groups::group_values(group)?;
        let key = DhKey::generate(p, g)?;

        /* Set Public Key. `public_value()` builds a fresh `Vec` from the
         * key's public `BIGNUM` -- not secret, no zeroization needed. */
        pubkey
            .set_attr(Attribute::from_bytes(CKA_VALUE, key.public_value()?))?;

        /* Set Private Key. `private_value()` similarly builds a fresh
         * `Vec` copy of the secret scalar (the `DhKey` itself, and its own
         * internal `BIGNUM`s, are separately freed/dropped independently
         * of this copy per `Drop for DhKey`) -- scrub this local
         * copy once it has been copied again into the private key
         * object's own attribute storage, mirroring
         * `crate::awslc::montgomery::ECMontgomeryOperation::
         * generate_keypair`'s identical pattern for its own private
         * scalar. */
        let mut private = key.private_value()?;
        privkey.set_attr(Attribute::from_ulong(
            CKA_VALUE_BITS,
            CK_ULONG::try_from(private.len() * 8)?,
        ))?;
        let result = privkey
            .set_attr(Attribute::from_bytes(CKA_VALUE, private.to_vec()));
        zeromem(&mut private);
        result?;

        Ok(())
    }
}

impl MechOperation for FFDHOperation {
    fn mechanism(&self) -> Result<CK_MECHANISM_TYPE> {
        Ok(self.mech)
    }

    fn finalized(&self) -> bool {
        self.finalized
    }
}

impl Derive for FFDHOperation {
    /// Performs the FFDH key derivation.
    ///
    /// Computes the shared secret between the local private `key` and the
    /// peer's public value (`self.public`) via
    /// `DhKey::derive_shared_secret_padded` (always exactly the group's
    /// prime byte width, see the module doc comment), takes the low-order
    /// `req_len` bytes as PKCS#11's `CKM_DH_PKCS_DERIVE` requires, and
    /// creates the derived key object using the template.
    fn derive(
        &mut self,
        key: &Object,
        template: &[CK_ATTRIBUTE],
        _mechanism: &Mechanisms,
        objectfactories: &ObjectFactories,
    ) -> Result<Vec<Object>> {
        if self.finalized {
            return Err(CKR_OPERATION_NOT_INITIALIZED)?;
        }
        self.finalized = true;

        let factory =
            objectfactories.get_obj_factory_from_key_template(template)?;

        let (dhkey, pkey_size) = privkey_from_object(key)?;

        let req_len = match template.iter().find(|x| x.type_ == CKA_VALUE_LEN) {
            Some(attr) => {
                let len = usize::try_from(attr.to_ulong()?)?;
                if len > pkey_size {
                    return Err(CKR_TEMPLATE_INCONSISTENT)?;
                }
                len
            }
            None => match factory
                .as_secret_key_factory()?
                .recommend_key_size(pkey_size)
            {
                Ok(len) => len,
                Err(_) => return Err(CKR_TEMPLATE_INCONSISTENT)?,
            },
        };

        /* Always exactly `pkey_size` bytes on success (see the module doc
         * comment): unlike the OpenSSL reference, no variable-outlen
         * recheck/shrink fallback is needed here. */
        let mut secret =
            dhkey.derive_shared_secret_padded(self.public.as_slice())?;

        /* Take the low-order (rightmost) `req_len` bytes, scrubbing the
         * discarded leading bytes before they're dropped -- mirrors
         * `crate::awslc::ecdh::ECDHOperation::derive`'s identical
         * `CKD_NULL` tail-take/zeroize pattern, including this guard
         * against `req_len` exceeding the actual secret length: not
         * reachable today (the
         * `CKA_VALUE_LEN` branch above already bounds `req_len` by
         * `pkey_size`, and `derive_shared_secret_padded` always returns
         * exactly `pkey_size` bytes), but an unguarded subtraction here
         * would panic across an FFI-adjacent boundary instead of
         * surfacing a clean `CKR_*` error. */
        if secret.len() < req_len {
            zeromem(secret.as_mut_slice());
            return Err(CKR_TEMPLATE_INCONSISTENT)?;
        }
        let drop = secret.len() - req_len;
        zeromem(&mut secret[..drop]);
        secret.drain(..drop);

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
    use crate::object::ObjectFactories;

    fn no_param_mech(mechanism: CK_MECHANISM_TYPE) -> CK_MECHANISM {
        CK_MECHANISM {
            mechanism,
            pParameter: std::ptr::null_mut(),
            ulParameterLen: 0,
        }
    }

    /// Registers the real, backend-agnostic FFDH mechanisms/factories
    /// (`crate::ffdh::register`) and the generic secret key factory
    /// (needed as a derive target), exactly as production
    /// `C_Initialize`/`C_GenerateKeyPair`/`C_DeriveKey` reach them --
    /// driving `FFDHMechanism::generate_keypair` and
    /// `FFDHMechanism::derive_operation` (which in turn call into this
    /// module), rather than calling this module's functions directly.
    fn registered() -> (Mechanisms, ObjectFactories) {
        let mut mechs = Mechanisms::new();
        let mut ot = ObjectFactories::new();
        crate::object::factory::register(&mut mechs, &mut ot);
        crate::ffdh::register(&mut mechs, &mut ot);
        (mechs, ot)
    }

    /// Builds a `CKA_PRIME`/`CKA_BASE` pubkey/prikey template pair for one
    /// of kryoptic's actual registered well-known groups (`ffdh_groups.rs`)
    /// -- not an arbitrary/isolated test prime -- confirming the real
    /// group-recognition path (`FFDHPubFactory`/`FFDHPrivFactory::create`
    /// calling `ffdh_groups::get_group_name`) accepts it.
    fn generate_keypair_for_group(
        mechs: &Mechanisms,
        group: DHGroupName,
    ) -> (Object, Object) {
        let (p, g, _q) = ffdh_groups::group_values(group).unwrap();
        let mut ck_true: CK_BBOOL = CK_TRUE;
        let pubkey_template = [
            CK_ATTRIBUTE {
                type_: CKA_PRIME,
                pValue: p.as_ptr() as CK_VOID_PTR,
                ulValueLen: p.len() as CK_ULONG,
            },
            CK_ATTRIBUTE {
                type_: CKA_BASE,
                pValue: g.as_ptr() as CK_VOID_PTR,
                ulValueLen: g.len() as CK_ULONG,
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
        let mech = no_param_mech(CKM_DH_PKCS_KEY_PAIR_GEN);
        let entry = mechs.get(CKM_DH_PKCS_KEY_PAIR_GEN).unwrap();
        entry
            .generate_keypair(&mech, &pubkey_template, &prikey_template)
            .expect("generate_keypair")
    }

    /// Builds a `CKO_SECRET_KEY`/`CKK_GENERIC_SECRET` derive template
    /// requesting `value_len` bytes.
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

    fn derive_via_mech(
        mechs: &Mechanisms,
        ot: &ObjectFactories,
        privkey: &Object,
        peer_pub: &[u8],
        value_len: usize,
    ) -> Result<Vec<u8>> {
        let mech = CK_MECHANISM {
            mechanism: CKM_DH_PKCS_DERIVE,
            pParameter: peer_pub.as_ptr() as CK_VOID_PTR,
            ulParameterLen: peer_pub.len() as CK_ULONG,
        };
        let entry = mechs.get(CKM_DH_PKCS_DERIVE).unwrap();
        let template = derive_secret_template(value_len);
        let mut op: Box<dyn Derive> = entry.derive_operation(&mech)?;
        let mut objs = op.derive(privkey, template.as_slice(), mechs, ot)?;
        let obj = objs.pop().unwrap();
        Ok(obj.get_attr_as_bytes(CKA_VALUE)?.clone())
    }

    /// Round-trip through the real `Mechanism`/`Derive` trait dispatch,
    /// using kryoptic's actual `FFDHE2048` well-known group (not an
    /// isolated test-only prime): generate two AwsLc-backed DH keypairs
    /// via the real `CKM_DH_PKCS_KEY_PAIR_GEN` mechanism, then derive from
    /// each side via the real `CKM_DH_PKCS_DERIVE` mechanism, confirming
    /// matching shared-secret-derived key material.
    #[test]
    fn ffdhe2048_generate_derive_round_trip() {
        let (mechs, ot) = registered();
        let (pubkey1, privkey1) =
            generate_keypair_for_group(&mechs, DHGroupName::FFDHE2048);
        let (pubkey2, privkey2) =
            generate_keypair_for_group(&mechs, DHGroupName::FFDHE2048);

        assert_eq!(pubkey1.get_attr_as_ulong(CKA_KEY_TYPE).unwrap(), CKK_DH);
        assert_eq!(privkey1.get_attr_as_ulong(CKA_KEY_TYPE).unwrap(), CKK_DH);

        let pub1 = pubkey1.get_attr_as_bytes(CKA_VALUE).unwrap().clone();
        let pub2 = pubkey2.get_attr_as_bytes(CKA_VALUE).unwrap().clone();

        let secret1 = derive_via_mech(&mechs, &ot, &privkey1, &pub2, 32)
            .expect("derive side 1");
        let secret2 = derive_via_mech(&mechs, &ot, &privkey2, &pub1, 32)
            .expect("derive side 2");

        assert_eq!(secret1, secret2);
        assert_eq!(secret1.len(), 32);

        // Sanity: the shared secret must not equal either side's raw
        // private value.
        let raw1 = privkey1.get_attr_as_bytes(CKA_VALUE).unwrap().clone();
        assert_ne!(secret1, raw1);
    }

    /// Requesting the full group prime width (no truncation) must still
    /// agree on both sides.
    #[test]
    fn ffdhe2048_derive_full_width() {
        let (mechs, ot) = registered();
        let (pubkey1, privkey1) =
            generate_keypair_for_group(&mechs, DHGroupName::FFDHE2048);
        let (pubkey2, privkey2) =
            generate_keypair_for_group(&mechs, DHGroupName::FFDHE2048);
        let pub1 = pubkey1.get_attr_as_bytes(CKA_VALUE).unwrap().clone();
        let pub2 = pubkey2.get_attr_as_bytes(CKA_VALUE).unwrap().clone();

        let (p, _g, _q) =
            ffdh_groups::group_values(DHGroupName::FFDHE2048).unwrap();

        let secret1 = derive_via_mech(&mechs, &ot, &privkey1, &pub2, p.len())
            .expect("derive side 1");
        let secret2 = derive_via_mech(&mechs, &ot, &privkey2, &pub1, p.len())
            .expect("derive side 2");

        assert_eq!(secret1, secret2);
        assert_eq!(secret1.len(), p.len());
    }

    /// A second well-known group (`MODP2048`, a distinct P/G pair from
    /// `FFDHE2048`) must also round-trip correctly.
    #[test]
    fn modp2048_generate_derive_round_trip() {
        let (mechs, ot) = registered();
        let (pubkey1, privkey1) =
            generate_keypair_for_group(&mechs, DHGroupName::MODP2048);
        let (pubkey2, privkey2) =
            generate_keypair_for_group(&mechs, DHGroupName::MODP2048);
        let pub1 = pubkey1.get_attr_as_bytes(CKA_VALUE).unwrap().clone();
        let pub2 = pubkey2.get_attr_as_bytes(CKA_VALUE).unwrap().clone();

        let secret1 = derive_via_mech(&mechs, &ot, &privkey1, &pub2, 24)
            .expect("derive side 1");
        let secret2 = derive_via_mech(&mechs, &ot, &privkey2, &pub1, 24)
            .expect("derive side 2");

        assert_eq!(secret1, secret2);
        assert_eq!(secret1.len(), 24);
    }

    /// `CKA_VALUE_LEN` larger than the group's prime byte width must be
    /// rejected before ever calling into AWS-LC.
    #[test]
    fn derive_rejects_oversized_value_len() {
        let (mechs, ot) = registered();
        let (pubkey1, privkey1) =
            generate_keypair_for_group(&mechs, DHGroupName::FFDHE2048);
        let (p, _g, _q) =
            ffdh_groups::group_values(DHGroupName::FFDHE2048).unwrap();
        let pub1 = pubkey1.get_attr_as_bytes(CKA_VALUE).unwrap().clone();

        let err = derive_via_mech(&mechs, &ot, &privkey1, &pub1, p.len() + 1)
            .expect_err("oversized CKA_VALUE_LEN must be rejected");
        assert_eq!(err.rv(), CKR_TEMPLATE_INCONSISTENT);
    }

    /// An empty peer public value must be rejected at mechanism-init time.
    #[test]
    fn derive_new_rejects_empty_peer_public() {
        let err = FFDHOperation::derive_new(CKM_DH_PKCS_DERIVE, Vec::new())
            .expect_err("empty peer public value must be rejected");
        assert_eq!(err.rv(), CKR_MECHANISM_PARAM_INVALID);
    }

    #[test]
    fn registration_covers_expected_mechanisms() {
        let (mechs, _ot) = registered();
        for ckm in [CKM_DH_PKCS_DERIVE, CKM_DH_PKCS_KEY_PAIR_GEN] {
            assert!(mechs.get(ckm).is_ok());
        }
    }
}
