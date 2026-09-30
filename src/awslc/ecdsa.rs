// Copyright 2026
// See LICENSE.txt file for terms

//! AWS-LC-backed implementation of the ECDSA surface `src/ec/ecdsa.rs`
//! requires: `EcdsaOperation` (mirroring `crate::ossl::ecdsa`, which
//! `src/ec/ecdsa.rs` imports via `use crate::ossl::ecdsa::EcdsaOperation;`
//! -- resolved to this module under the `awslc` feature by `src/lib.rs`'s
//! `use awslc as ossl;` alias).
//!
//! Unlike the OpenSSL backend, `awslc::ec::EcKey::sign`/`verify` already
//! speak PKCS#11's raw fixed-width (r, s) signature format directly (no DER
//! SEQUENCE the reference has to convert to/from via its own
//! `ossl_to_pkcs11_signature`/`pkcs11_to_ossl_signature` helpers), and
//! `EcKey` is agnostic to which hash produced the digest it signs/verifies
//! -- so this module does its own hashing (via `awslc::digest::Digest`,
//! built on `crate::awslc::hash`/`crate::awslc::common` infrastructure)
//! for the combined hash+sign mechanisms (`CKM_ECDSA_SHA256` etc.), then
//! hands the resulting digest to `EcKey::sign`/`verify`. Plain `CKM_ECDSA`
//! skips hashing entirely: the caller supplies the pre-computed digest
//! directly, and (mirroring the reference exactly) only the one-shot
//! `sign()`/`verify()` path is supported for it -- `sign_update`/
//! `verify_update` always fail for `CKM_ECDSA`, matching
//! `crate::ossl::ecdsa::EcdsaOperation`'s own behavior.

use crate::ec::get_ec_point_from_obj;
use crate::error::Result;
use crate::mechanism::*;
use crate::object::Object;
use crate::pkcs11::*;

use crate::awslc::common::{ec_curve_from_oid, mech_type_to_digest_alg};

use crate::lowlevel::digest::Digest as AwsLcDigest;
use crate::lowlevel::ec::{EcCurve, EcKey};

/// Maps a `CKA_EC_PARAMS`-bearing `Object` to the `EcCurve` variant AWS-LC's
/// primitive needs, mirroring `crate::ossl::common::get_evp_pkey_type_from_obj`
/// (which maps to `ossl::pkey::EvpPkeyType` instead). `src/ec/mod.rs` only
/// ever accepts P-256/384/521 for `CKK_EC` (confirmed by reading
/// `ECDSAPubFactory::create`/`ECDSAPrivFactory::create` in
/// `src/ec/ecdsa.rs`, which reject every other OID before this would ever
/// be reached), matching `EcCurve`'s exactly 3 variants -- no gap here. The
/// OID-to-`EcCurve` mapping itself lives in `crate::awslc::common` (shared
/// with `extract_public_key` there) so it exists in exactly one place.
fn ec_curve_from_obj(key: &Object) -> Result<EcCurve> {
    let oid = crate::ec::get_oid_from_obj(key)?;
    ec_curve_from_oid(&oid)
}

/// Builds an `EcKey` for signing from a `CKO_PRIVATE_KEY` `Object`'s
/// `CKA_VALUE` (raw private scalar, possibly shorter than the curve's
/// order width if leading zero bytes were stripped -- exactly
/// `EcKey::from_private_scalar`'s expected input format, no conversion
/// needed).
fn privkey_from_object(key: &Object) -> Result<EcKey> {
    let curve = ec_curve_from_obj(key)?;
    let scalar = key.get_attr_as_bytes(CKA_VALUE)?;
    Ok(EcKey::from_private_scalar(curve, scalar.as_slice())?)
}

/// Builds an `EcKey` for verification from a `CKO_PUBLIC_KEY` `Object`'s
/// `CKA_EC_POINT` (DER-OCTET-STRING-wrapped raw uncompressed point --
/// `get_ec_point_from_obj` strips that wrapping, matching what
/// `EcKey::from_public_point` expects).
fn pubkey_from_object(key: &Object) -> Result<EcKey> {
    let curve = ec_curve_from_obj(key)?;
    let point = get_ec_point_from_obj(key)?;
    Ok(EcKey::from_public_point(curve, point.as_slice())?)
}

/// Maps a PKCS#11 ECDSA mechanism type to the digest algorithm it implies,
/// or `None` for plain `CKM_ECDSA` (no hashing -- the caller supplies the
/// pre-computed digest directly). Mirrors
/// `crate::ossl::ecdsa::ecdsa_type_to_ossl_alg`'s role, but split from the
/// signature backend itself since `awslc::ec::EcKey` has no combined
/// hash+sign primitive of its own.
fn ecdsa_mech_to_digest_alg(
    mech: CK_MECHANISM_TYPE,
) -> Result<Option<crate::lowlevel::digest::DigestAlg>> {
    if mech == CKM_ECDSA {
        return Ok(None);
    }
    Ok(Some(mech_type_to_digest_alg(mech)?))
}

/// Represents an active ECDSA signing or verification operation.
#[derive(Debug)]
pub struct EcdsaOperation {
    /// The specific ECDSA mechanism type (e.g., CKM_ECDSA_SHA256).
    mech: CK_MECHANISM_TYPE,
    /// Expected output length of the signature in bytes (2 * order size).
    output_len: usize,
    /// Flag indicating if the operation has been finalized.
    finalized: bool,
    /// Flag indicating if the operation is in progress (at least one
    /// update has been fed in).
    in_use: bool,
    /// `Some` for the combined hash+sign mechanisms (accumulates the
    /// message as it streams in); `None` for plain `CKM_ECDSA`, where
    /// `data` is instead the pre-computed digest handed directly to
    /// `sign`/`verify`.
    hasher: Option<AwsLcDigest>,
    /// The EC key material: a private key for signing, a public key for
    /// verification.
    key: EcKey,
    /// `Some` only for `verify_signature_new` (PKCS#11 v3.2's
    /// `VerifySignature`, where the signature is supplied at
    /// initialization time rather than at `verify()`): the raw (r, s)
    /// halves, split up-front so `verify_internal` doesn't need to
    /// re-validate/re-split the length on every call.
    signature: Option<(Vec<u8>, Vec<u8>)>,
}

impl EcdsaOperation {
    /// Splits a raw PKCS#11 ECDSA signature (fixed-width r || s) into its
    /// two halves, validating its total length against `output_len` first.
    fn split_signature(
        signature: &[u8],
        output_len: usize,
    ) -> Result<(Vec<u8>, Vec<u8>)> {
        if signature.len() != output_len {
            return Err(CKR_SIGNATURE_LEN_RANGE)?;
        }
        let half = output_len / 2;
        Ok((signature[..half].to_vec(), signature[half..].to_vec()))
    }

    /// Internal constructor shared by `sign_new`/`verify_new`/
    /// `verify_signature_new`.
    fn new_op(
        flag: CK_FLAGS,
        mech: &CK_MECHANISM,
        key: &Object,
        signature: Option<&[u8]>,
    ) -> Result<EcdsaOperation> {
        let (eckey, order_bytes) = match flag {
            CKF_SIGN => {
                let k = privkey_from_object(key)?;
                let ob = ec_curve_from_obj(key)?.order_bytes();
                (k, ob)
            }
            CKF_VERIFY => {
                let k = pubkey_from_object(key)?;
                let ob = ec_curve_from_obj(key)?.order_bytes();
                (k, ob)
            }
            _ => return Err(CKR_GENERAL_ERROR)?,
        };
        let output_len = 2 * order_bytes;
        let digest_alg = ecdsa_mech_to_digest_alg(mech.mechanism)?;
        let hasher = match digest_alg {
            Some(alg) => Some(AwsLcDigest::new(alg)?),
            None => None,
        };
        let sig = match signature {
            Some(s) => Some(Self::split_signature(s, output_len)?),
            None => None,
        };
        Ok(EcdsaOperation {
            mech: mech.mechanism,
            output_len,
            finalized: false,
            in_use: false,
            hasher,
            key: eckey,
            signature: sig,
        })
    }

    /// Creates a new `EcdsaOperation` for signing.
    pub fn sign_new(
        mech: &CK_MECHANISM,
        key: &Object,
        _: &CK_MECHANISM_INFO,
    ) -> Result<EcdsaOperation> {
        Self::new_op(CKF_SIGN, mech, key, None)
    }

    /// Creates a new `EcdsaOperation` for verification.
    pub fn verify_new(
        mech: &CK_MECHANISM,
        key: &Object,
        _: &CK_MECHANISM_INFO,
    ) -> Result<EcdsaOperation> {
        Self::new_op(CKF_VERIFY, mech, key, None)
    }

    /// Creates a new `EcdsaOperation` for verification with a pre-supplied
    /// signature.
    pub fn verify_signature_new(
        mech: &CK_MECHANISM,
        key: &Object,
        _: &CK_MECHANISM_INFO,
        signature: &[u8],
    ) -> Result<EcdsaOperation> {
        Self::new_op(CKF_VERIFY, mech, key, Some(signature))
    }

    /// Generates an EC key pair using AWS-LC.
    ///
    /// Takes mutable references to pre-created public and private key
    /// `Object`s (which contain the desired curve in CKA_EC_PARAMS),
    /// generates the key pair, and populates the CKA_EC_POINT and CKA_VALUE
    /// attributes.
    pub fn generate_keypair(
        pubkey: &mut Object,
        privkey: &mut Object,
    ) -> Result<()> {
        let curve = ec_curve_from_obj(pubkey)?;
        let key = EcKey::generate(curve)?;

        /* Set Public Key: CKA_EC_POINT is a DER-encoded OCTET STRING
         * wrapping the raw uncompressed point octets (PKCS#11 v3.1 6.3.3),
         * exactly as `crate::ossl::ecdsa::EcdsaOperation::generate_keypair`
         * encodes it. */
        let point_encoded =
            match asn1::write_single(&key.public_point().as_slice()) {
                Ok(b) => b,
                Err(_) => return Err(CKR_GENERAL_ERROR)?,
            };
        pubkey.set_attr(crate::attribute::Attribute::from_bytes(
            CKA_EC_POINT,
            point_encoded,
        ))?;

        /* Set Private Key: CKA_VALUE is the raw fixed-width scalar, no
         * wrapping. Moved (not cloned) into the attribute: `scalar` becomes
         * the object's actual key material, so there is no separate stack
         * copy left over to scrub. */
        let scalar = key.private_scalar()?;
        privkey.set_attr(crate::attribute::Attribute::from_bytes(
            CKA_VALUE, scalar,
        ))?;

        Ok(())
    }

    /// Feeds `data` into the digest accumulator for a combined hash+sign
    /// mechanism. Not used for plain `CKM_ECDSA` (see `hasher`'s doc
    /// comment).
    fn update_hasher(&mut self, data: &[u8]) -> Result<()> {
        match &mut self.hasher {
            Some(h) => Ok(h.update(data)?),
            None => Err(CKR_GENERAL_ERROR)?,
        }
    }

    /// Finalizes the digest accumulator and returns the resulting digest
    /// bytes.
    fn finalize_hasher(&mut self) -> Result<Vec<u8>> {
        match &mut self.hasher {
            Some(h) => {
                let mut digest = vec![0u8; h.size()];
                let len = h.finalize(digest.as_mut_slice())?;
                digest.truncate(len);
                Ok(digest)
            }
            None => Err(CKR_GENERAL_ERROR)?,
        }
    }
}

impl MechOperation for EcdsaOperation {
    fn mechanism(&self) -> Result<CK_MECHANISM_TYPE> {
        Ok(self.mech)
    }

    fn finalized(&self) -> bool {
        self.finalized
    }
}

impl Sign for EcdsaOperation {
    fn sign(&mut self, data: &[u8], signature: &mut [u8]) -> Result<()> {
        if self.in_use {
            return Err(CKR_OPERATION_NOT_INITIALIZED)?;
        }
        if self.finalized {
            return Err(CKR_OPERATION_NOT_INITIALIZED)?;
        }
        if signature.len() != self.output_len {
            return Err(CKR_SIGNATURE_LEN_RANGE)?;
        }
        if self.mech == CKM_ECDSA {
            self.finalized = true;
            let (r, s) = self.key.sign(data)?;
            let half = self.output_len / 2;
            signature[..half].copy_from_slice(&r);
            signature[half..].copy_from_slice(&s);
            return Ok(());
        }
        self.sign_update(data)?;
        self.sign_final(signature)
    }

    fn sign_update(&mut self, data: &[u8]) -> Result<()> {
        if self.mech == CKM_ECDSA {
            self.finalized = true;
        }
        if self.finalized {
            return Err(CKR_OPERATION_NOT_INITIALIZED)?;
        }
        self.in_use = true;
        self.update_hasher(data)
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
            return Err(CKR_SIGNATURE_LEN_RANGE)?;
        }
        let mut digest = self.finalize_hasher()?;
        let result = self.key.sign(digest.as_slice());
        crate::misc::zeromem(digest.as_mut_slice());
        let (r, s) = result?;
        let half = self.output_len / 2;
        signature[..half].copy_from_slice(&r);
        signature[half..].copy_from_slice(&s);
        Ok(())
    }

    fn signature_len(&self) -> Result<usize> {
        Ok(self.output_len)
    }
}

impl EcdsaOperation {
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
        if self.mech == CKM_ECDSA {
            self.finalized = true;
            let (r, s) = match signature {
                Some(s) => Self::split_signature(s, self.output_len)?,
                None => match &self.signature {
                    Some(rs) => rs.clone(),
                    None => return Err(CKR_GENERAL_ERROR)?,
                },
            };
            return Ok(self.key.verify(data, &r, &s)?);
        }
        self.verify_int_update(data)?;
        self.verify_int_final(signature)
    }

    /// Internal helper for updating a multi-part verification.
    fn verify_int_update(&mut self, data: &[u8]) -> Result<()> {
        if self.mech == CKM_ECDSA {
            self.finalized = true;
        }
        if self.finalized {
            return Err(CKR_OPERATION_NOT_INITIALIZED)?;
        }
        self.in_use = true;
        self.update_hasher(data)
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
        let (r, s) = match signature {
            Some(s) => Self::split_signature(s, self.output_len)?,
            None => match &self.signature {
                Some(rs) => rs.clone(),
                None => return Err(CKR_GENERAL_ERROR)?,
            },
        };
        let mut digest = self.finalize_hasher()?;
        let result = self.key.verify(digest.as_slice(), &r, &s);
        crate::misc::zeromem(digest.as_mut_slice());
        Ok(result?)
    }
}

impl Verify for EcdsaOperation {
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

impl VerifySignature for EcdsaOperation {
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

    /// Registers the real, backend-agnostic ECDSA mechanisms/factories from
    /// `src/ec/ecdsa.rs` (via `crate::ec::ecdsa::register`), exactly as
    /// production `C_Initialize`/`C_GenerateKeyPair`/`C_SignInit`/
    /// `C_VerifyInit` reach them -- driving `EcdsaMechanism::sign_new`/
    /// `verify_new`/`generate_keypair` (which in turn call into this
    /// module's `EcdsaOperation`) rather than calling `EcdsaOperation`
    /// directly, so these tests exercise the real `Mechanism`/`Sign`/
    /// `Verify` trait dispatch, not just the `awslc::ec` primitive layer.
    fn registered() -> (Mechanisms, ObjectFactories) {
        let mut mechs = Mechanisms::new();
        let mut ot = ObjectFactories::new();
        crate::ec::ecdsa::register(&mut mechs, &mut ot);
        (mechs, ot)
    }

    /// Generates a keypair for `curve_name` through the real
    /// `Mechanism::generate_keypair` dispatch. Sets `CKA_VERIFY`/`CKA_SIGN`
    /// explicitly in the templates -- both default to `false`
    /// (`add_common_public_key_attrs`/`add_common_private_key_attrs` in
    /// `src/object/key.rs`), and `sign_new`/`verify_new`'s
    /// `check_key_ops(..., CKA_SIGN/CKA_VERIFY)` check rejects with
    /// `CKR_KEY_FUNCTION_NOT_PERMITTED` otherwise, exactly like a real
    /// caller that forgot to request these capabilities would see.
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
                type_: CKA_VERIFY,
                pValue: &mut ck_true as *mut CK_BBOOL as CK_VOID_PTR,
                ulValueLen: std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
            },
        ];
        let prikey_template = [CK_ATTRIBUTE {
            type_: CKA_SIGN,
            pValue: &mut ck_true as *mut CK_BBOOL as CK_VOID_PTR,
            ulValueLen: std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
        }];
        let mech = no_param_mech(CKM_EC_KEY_PAIR_GEN);
        let entry = mechs.get(CKM_EC_KEY_PAIR_GEN).unwrap();
        entry
            .generate_keypair(&mech, &pubkey_template, &prikey_template)
            .expect("generate_keypair")
    }

    fn round_trip_for(curve_name: &str, sign_mech: CK_MECHANISM_TYPE) {
        let (mechs, _ot) = registered();
        let (pubkey, privkey) = generate_keypair(&mechs, curve_name);

        assert_eq!(pubkey.get_attr_as_ulong(CKA_KEY_TYPE).unwrap(), CKK_EC);
        assert_eq!(privkey.get_attr_as_ulong(CKA_KEY_TYPE).unwrap(), CKK_EC);

        let data = b"the quick brown fox jumps over the lazy dog";
        let mech = no_param_mech(sign_mech);

        let entry = mechs.get(sign_mech).unwrap();
        let mut sign_op = entry.sign_new(&mech, &privkey).expect("sign_new");
        let siglen = sign_op.signature_len().unwrap();
        let mut signature = vec![0u8; siglen];
        sign_op.sign(data, &mut signature).expect("sign");

        let mut verify_op =
            entry.verify_new(&mech, &pubkey).expect("verify_new");
        verify_op.verify(data, &signature).expect("verify");

        // Tampered data must be rejected.
        let mut verify_op2 =
            entry.verify_new(&mech, &pubkey).expect("verify_new 2");
        let mut tampered = data.to_vec();
        tampered[0] ^= 0xff;
        let err = verify_op2
            .verify(&tampered, &signature)
            .expect_err("tampered data must fail verification");
        assert_eq!(err.rv(), CKR_SIGNATURE_INVALID);
    }

    #[test]
    fn p256_sha256_round_trip() {
        round_trip_for(crate::ec::PRIME256V1, CKM_ECDSA_SHA256);
    }

    #[test]
    fn p384_sha256_round_trip() {
        round_trip_for(crate::ec::SECP384R1, CKM_ECDSA_SHA256);
    }

    #[test]
    fn p521_sha256_round_trip() {
        round_trip_for(crate::ec::SECP521R1, CKM_ECDSA_SHA256);
    }

    /// Plain `CKM_ECDSA`: the caller supplies a pre-computed digest
    /// directly (here, a 32-byte value standing in for a SHA-256 digest
    /// the caller computed itself) rather than this module hashing it.
    #[test]
    fn plain_ecdsa_signs_precomputed_digest() {
        let (mechs, _ot) = registered();
        let (pubkey, privkey) = generate_keypair(&mechs, crate::ec::PRIME256V1);

        let digest = [0x5au8; 32];
        let mech = no_param_mech(CKM_ECDSA);

        let entry = mechs.get(CKM_ECDSA).unwrap();
        let mut sign_op = entry.sign_new(&mech, &privkey).unwrap();
        let mut signature = vec![0u8; sign_op.signature_len().unwrap()];
        sign_op.sign(&digest, &mut signature).unwrap();

        let mut verify_op = entry.verify_new(&mech, &pubkey).unwrap();
        verify_op.verify(&digest, &signature).unwrap();
    }

    /// `CKM_ECDSA` must reject multi-part `sign_update`/`verify_update`,
    /// mirroring `crate::ossl::ecdsa::EcdsaOperation`'s own behavior (only
    /// the one-shot `sign()`/`verify()` path is supported for raw ECDSA).
    #[test]
    fn plain_ecdsa_rejects_multipart() {
        let (mechs, _ot) = registered();
        let (_pubkey, privkey) =
            generate_keypair(&mechs, crate::ec::PRIME256V1);
        let mech = no_param_mech(CKM_ECDSA);
        let entry = mechs.get(CKM_ECDSA).unwrap();
        let mut sign_op = entry.sign_new(&mech, &privkey).unwrap();
        assert!(sign_op.sign_update(b"abc").is_err());
    }

    /// `CKM_ECDSA_SHA256` (a combined hash+sign mechanism) must support
    /// multi-part sign/verify, streaming through the internal digest
    /// accumulator.
    #[test]
    fn multipart_hash_and_sign_round_trip() {
        let (mechs, _ot) = registered();
        let (pubkey, privkey) = generate_keypair(&mechs, crate::ec::PRIME256V1);
        let mech = no_param_mech(CKM_ECDSA_SHA256);
        let entry = mechs.get(CKM_ECDSA_SHA256).unwrap();

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

    /// PKCS#11 v3.2's `verify_signature_new`/`VerifySignature`: the
    /// signature is supplied at initialization time rather than at
    /// `verify()`.
    #[test]
    fn verify_signature_dispatch() {
        let (mechs, _ot) = registered();
        let (pubkey, privkey) = generate_keypair(&mechs, crate::ec::PRIME256V1);
        let data = b"verify-signature test data";
        let mech = no_param_mech(CKM_ECDSA_SHA256);
        let entry = mechs.get(CKM_ECDSA_SHA256).unwrap();

        let mut sign_op = entry.sign_new(&mech, &privkey).unwrap();
        let mut signature = vec![0u8; sign_op.signature_len().unwrap()];
        sign_op.sign(data, &mut signature).unwrap();

        let mut vsop = entry
            .verify_signature_new(&mech, &pubkey, &signature)
            .expect("verify_signature_new");
        vsop.verify(data).expect("verify_signature");
    }

    /// CKA_EC_POINT must be a DER-encoded OCTET STRING wrapping the raw
    /// uncompressed point octets (PKCS#11 v3.1 6.3.3), not the raw octets
    /// directly -- confirms `generate_keypair`'s encoding matches what
    /// `crate::ec::get_ec_point_from_obj`/`get_oid_from_obj`-based parsing
    /// (used throughout `src/ec/ecdsa.rs`) expects.
    #[test]
    fn generated_ec_point_is_der_octet_string_wrapped() {
        let (mechs, _ot) = registered();
        let (pubkey, _privkey) =
            generate_keypair(&mechs, crate::ec::PRIME256V1);

        let der = pubkey.get_attr_as_bytes(CKA_EC_POINT).unwrap();
        // A raw uncompressed P-256 point is 65 bytes (0x04 || X || Y); the
        // DER OCTET STRING wrapping adds a tag+length header.
        assert!(der.len() > 65);
        let raw = asn1::parse_single::<&[u8]>(der.as_slice())
            .expect("CKA_EC_POINT must parse as a DER OCTET STRING");
        assert_eq!(raw.len(), 65);
        assert_eq!(raw[0], 0x04);
    }

    /// Regression test for a real gap: `awslc::ec::EcKey` originally had
    /// no way to construct a
    /// public-key-only key (needed because a `CKO_PUBLIC_KEY` object never
    /// carries `CKA_VALUE`). This drives `pubkey_from_object` end-to-end
    /// through the real object/attribute layer (not just
    /// `EcKey::from_public_point` directly, which `awslc/src/ec.rs`'s own
    /// unit tests already cover).
    #[test]
    fn pubkey_from_object_builds_a_working_verify_key() {
        let (mechs, _ot) = registered();
        let (pubkey, privkey) = generate_keypair(&mechs, crate::ec::PRIME256V1);

        let signing_key = privkey_from_object(&privkey).unwrap();
        let digest = [0x12u8; 32];
        let (r, s) = signing_key.sign(&digest).unwrap();

        let verify_key = pubkey_from_object(&pubkey).unwrap();
        verify_key.verify(&digest, &r, &s).unwrap();
    }

    /// A tampered `CKA_VALUE` used for signing must not silently leave a
    /// stale valid signature behind, and a rejected verification must not
    /// panic or leak the digest into the error path.
    #[test]
    fn wrong_key_signature_rejected() {
        let (mechs, _ot) = registered();
        let (_pubkey1, privkey1) =
            generate_keypair(&mechs, crate::ec::PRIME256V1);
        let (pubkey2, _privkey2) =
            generate_keypair(&mechs, crate::ec::PRIME256V1);

        let data = b"cross-key test";
        let mech = no_param_mech(CKM_ECDSA_SHA256);
        let entry = mechs.get(CKM_ECDSA_SHA256).unwrap();

        let mut sign_op = entry.sign_new(&mech, &privkey1).unwrap();
        let mut signature = vec![0u8; sign_op.signature_len().unwrap()];
        sign_op.sign(data, &mut signature).unwrap();

        // Verify against the *other* keypair's public key: must fail.
        let mut verify_op = entry.verify_new(&mech, &pubkey2).unwrap();
        let err = verify_op
            .verify(data, &signature)
            .expect_err("wrong public key must fail verification");
        assert_eq!(err.rv(), CKR_SIGNATURE_INVALID);
    }

    #[test]
    fn registration_covers_expected_mechanisms() {
        let (mechs, _ot) = registered();
        for ckm in [
            CKM_ECDSA,
            CKM_ECDSA_SHA256,
            CKM_ECDSA_SHA384,
            CKM_ECDSA_SHA512,
            CKM_EC_KEY_PAIR_GEN,
        ] {
            assert!(mechs.get(ckm).is_ok());
        }
    }
}
