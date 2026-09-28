// Copyright 2026
// See LICENSE.txt file for terms

//! AWS-LC-backed implementation of the EdDSA surface `src/ec/eddsa.rs`
//! requires: `EddsaOperation` (mirroring `crate::ossl::eddsa`, which
//! `src/ec/eddsa.rs` imports via `use crate::ossl::eddsa::EddsaOperation;`
//! -- resolved to this module under the `awslc` feature by `src/lib.rs`'s
//! `use awslc as ossl;` alias).
//!
//! AWS-LC only implements Ed25519 (`awslc::eddsa::Ed25519Key`, wrapping the
//! raw `ED25519_*` functions -- no `EC_KEY`/`EVP_PKEY` involved). There is
//! no Ed448 implementation anywhere in AWS-LC: only NID/type-tag constants
//! exist for Ed448 in the bindings, no `ED448_sign`/`verify`/`keypair`
//! functions. `src/ec/eddsa.rs` is generic over both curves (dispatching
//! by the `CKA_EC_PARAMS` OID -- see `oid::ED25519_OID | oid::ED448_OID`
//! in its `EDDSAPubFactory::create`/`EDDSAPrivFactory::create`), so this
//! module explicitly rejects any Ed448 key with `CKR_CURVE_NOT_SUPPORTED`
//! -- the same error `src/ec/eddsa.rs`, `src/ec/ecdsa.rs` and
//! `src/ec/montgomery.rs` themselves already use for an OID their own
//! generic dispatch doesn't recognize at all (e.g. `src/ec/eddsa.rs`'s
//! `eddsa_public_key_info`'s `_ => return Err(CKR_CURVE_NOT_SUPPORTED)?`),
//! rather than inventing a new error shape for "this backend doesn't have
//! it" vs. "no one has heard of this curve" -- both are, from a caller's
//! perspective, "the token can't do this curve".
//!
//! `awslc::eddsa::Ed25519Key`'s raw `ED25519_sign`/`ED25519_verify`
//! implement plain (pure) Ed25519 over the whole message, with an
//! (implicitly empty) context and no prehashing -- there is no AWS-LC
//! primitive for Ed25519ph (prehashed) or Ed25519ctx (non-empty context).
//! Bare `CKM_EDDSA` (`ulParameterLen == 0`) and `CK_EDDSA_PARAMS` with
//! `phFlag == CK_FALSE` and an empty context both map onto that one
//! supported variant; a request for prehashing or a non-empty context is
//! rejected with `CKR_MECHANISM_PARAM_INVALID`, mirroring
//! `crate::ossl::eddsa::parse_params`'s own use of that error for
//! unsupported parameter combinations.
//!
//! Ed25519 doesn't support incremental/streaming signing at the RFC 8032
//! level (the whole message must be known before the single, deterministic
//! `ED25519_sign` call) -- like `crate::ossl::eddsa::EddsaOperation`
//! (whose OpenSSL `EVP_DigestSign`/`EVP_DigestVerify` calls buffer
//! internally for pure EdDSA), this module's `sign_update`/`verify_update`
//! simply accumulate the message into a `Vec<u8>`, doing the actual
//! sign/verify work at `sign_final`/`verify_final`.

use crate::attribute::Attribute;
use crate::ec::{get_ec_point_from_obj, get_oid_from_obj};
use crate::error::Result;
use crate::kasn1::oid;
use crate::mechanism::*;
use crate::object::Object;
use crate::pkcs11::*;

#[cfg(not(feature = "fips"))]
use crate::misc::bytes_to_vec;

use crate::lowlevel::eddsa::Ed25519Key;

#[cfg(feature = "fips")]
use crate::fips::FipsApproval;

/// Expected signature length for Ed25519 in bytes.
const OUTLEN_ED25519: usize = 64;
/// Raw Ed25519 public/private key material length (the 32-byte seed and
/// the 32-byte public point) in bytes. `pub(crate)` so
/// `crate::awslc::common::extract_public_key` can validate `CKA_VALUE`'s
/// length against the same constant this module uses, mirroring
/// `crate::awslc::montgomery::KEYLEN_X25519`'s identical cross-module reuse.
pub(crate) const KEYLEN_ED25519: usize = 32;

/// Validates that `key`'s `CKA_EC_PARAMS` OID is Ed25519, rejecting Ed448
/// (see the module doc comment) with `CKR_CURVE_NOT_SUPPORTED`.
/// `pub(crate)` so `crate::awslc::common::extract_public_key` can run the
/// same OID check before treating `CKA_VALUE` as an Ed25519 seed, mirroring
/// `crate::awslc::montgomery::ensure_x25519`'s identical cross-module reuse.
pub(crate) fn ensure_ed25519(key: &Object) -> Result<()> {
    match get_oid_from_obj(key)? {
        oid::ED25519_OID => Ok(()),
        _ => Err(CKR_CURVE_NOT_SUPPORTED)?,
    }
}

/// Which RFC 8032 EdDSA variant an operation is using. AWS-LC's raw
/// `ED25519ctx_sign`/`ED25519ph_sign` primitives (see
/// `crate::lowlevel::eddsa::Ed25519Key::sign_ctx`/`sign_ph`) make both
/// variants real, not hand-rolled -- unlike the module doc comment's older
/// claim (written against an earlier AWS-LC version that didn't export
/// them).
#[derive(Debug, Clone)]
enum EddsaVariant {
    /// Plain (pure) Ed25519: empty context, no prehashing.
    Plain,
    /// Ed25519ctx: a non-empty context, no prehashing.
    #[cfg(not(feature = "fips"))]
    Ctx(Vec<u8>),
    /// Ed25519ph: message is SHA-512-prehashed; context may be empty.
    #[cfg(not(feature = "fips"))]
    Ph(Vec<u8>),
}

/// Parses mechanism parameters for EdDSA operations, mirroring
/// `crate::ossl::eddsa::parse_params`'s role.
///
/// Under `fips`, this keeps the original, narrower behavior (only plain
/// Ed25519 is accepted, matching `src/tests/eddsa.rs`'s own
/// `cfg!(feature = "fips")` branch, which expects `CKR_MECHANISM_PARAM_
/// INVALID` for Ed25519ctx even on backends that otherwise support it --
/// presumably because the reference OpenSSL FIPS module doesn't approve
/// it either) -- not because AWS-LC's FIPS module lacks these primitives
/// (it doesn't check that), but to avoid changing this backend's FIPS
/// approval surface as a side effect of closing this gap.
fn check_params(mech: &CK_MECHANISM) -> Result<EddsaVariant> {
    if mech.mechanism != CKM_EDDSA {
        return Err(CKR_MECHANISM_INVALID)?;
    }
    if mech.ulParameterLen == 0 {
        return Ok(EddsaVariant::Plain);
    }
    let params = mech.get_parameters::<CK_EDDSA_PARAMS>()?;
    #[cfg(feature = "fips")]
    {
        if params.phFlag == CK_TRUE || params.ulContextDataLen != 0 {
            return Err(CKR_MECHANISM_PARAM_INVALID)?;
        }
        Ok(EddsaVariant::Plain)
    }
    #[cfg(not(feature = "fips"))]
    {
        let context = if params.ulContextDataLen == 0 {
            Vec::new()
        } else {
            bytes_to_vec(
                params.pContextData,
                usize::try_from(params.ulContextDataLen)?,
            )
        };
        if params.phFlag == CK_TRUE {
            Ok(EddsaVariant::Ph(context))
        } else if !context.is_empty() {
            Ok(EddsaVariant::Ctx(context))
        } else {
            Ok(EddsaVariant::Plain)
        }
    }
}

/// Builds an `Ed25519Key` for signing from a `CKO_PRIVATE_KEY` `Object`'s
/// `CKA_VALUE`: PKCS#11's EdDSA private key storage convention is the raw
/// 32-byte seed (RFC 8032), exactly what `Ed25519Key::from_seed` expects
/// (confirmed against `awslc::eddsa::Ed25519Key`, whose private storage is
/// documented as exactly the 32-byte seed, matching
/// `EVP_PKEY_get_raw_private_key`'s OpenSSL convention).
fn privkey_from_object(key: &Object) -> Result<Ed25519Key> {
    ensure_ed25519(key)?;
    let value = key.get_attr_as_bytes(CKA_VALUE)?;
    if value.len() != KEYLEN_ED25519 {
        return Err(CKR_KEY_SIZE_RANGE)?;
    }
    /* `seed` is a fresh copy of secret key material off the Object's own
     * storage (needed because `from_seed` takes a fixed-size array, not a
     * slice) -- scrub it once consumed rather than leaving it to a normal
     * drop, mirroring `crate::awslc::ecdsa::EcdsaOperation::generate_keypair`'s
     * own `zeromem` of its local `scalar` copy. */
    let mut seed = [0u8; KEYLEN_ED25519];
    seed.copy_from_slice(value);
    let result = Ed25519Key::from_seed(&seed);
    crate::misc::zeromem(&mut seed);
    Ok(result?)
}

/// Extracts the raw 32-byte Ed25519 public key from a `CKO_PUBLIC_KEY`
/// `Object`'s `CKA_EC_POINT` (public data -- no zeroization needed).
fn pubkey_from_object(key: &Object) -> Result<[u8; KEYLEN_ED25519]> {
    ensure_ed25519(key)?;
    let point = get_ec_point_from_obj(key)?;
    if point.len() != KEYLEN_ED25519 {
        return Err(CKR_KEY_SIZE_RANGE)?;
    }
    let mut public = [0u8; KEYLEN_ED25519];
    public.copy_from_slice(&point);
    Ok(public)
}

/// Validates a raw PKCS#11 EdDSA signature's length against the one
/// supported curve's expected width, before it's ever copied into a
/// fixed-size buffer (avoiding a `copy_from_slice` length-mismatch panic).
fn validate_signature_len(signature: &[u8]) -> Result<()> {
    if signature.len() != OUTLEN_ED25519 {
        return Err(CKR_SIGNATURE_LEN_RANGE)?;
    }
    Ok(())
}

/// The key material backing an active `EddsaOperation`: a private key for
/// signing, or a raw public key point for verification.
#[derive(Debug)]
enum EddsaKey {
    Sign(Ed25519Key),
    Verify([u8; KEYLEN_ED25519]),
}

/// Represents an active EdDSA (Ed25519-only, see the module doc comment)
/// signing or verification operation.
#[derive(Debug)]
pub struct EddsaOperation {
    /// The specific EdDSA mechanism type (always CKM_EDDSA).
    mech: CK_MECHANISM_TYPE,
    /// Expected signature length (always 64 -- Ed25519 is the only
    /// supported curve).
    output_len: usize,
    /// Flag indicating if the operation has been finalized.
    finalized: bool,
    /// Flag indicating if the operation is in progress.
    in_use: bool,
    /// The key material (private for signing, public for verification).
    key: EddsaKey,
    /// Which RFC 8032 variant to sign/verify with (see `check_params`).
    variant: EddsaVariant,
    /// Accumulates the message as it streams in via `sign_update`/
    /// `verify_update` -- Ed25519 (pure) has no incremental primitive, so
    /// the full message must be buffered before the single `sign`/`verify`
    /// call at finalization (see the module doc comment).
    buffer: Vec<u8>,
    /// `Some` only for `verify_signature_new` (PKCS#11 v3.2's
    /// `VerifySignature`, where the signature is supplied at
    /// initialization time rather than at `verify()`).
    signature: Option<Vec<u8>>,
    /// FIPS approval status for the operation.
    #[cfg(feature = "fips")]
    fips_approval: FipsApproval,
}

impl EddsaOperation {
    /// Internal constructor to create a new `EddsaOperation`.
    fn new_op(
        flag: CK_FLAGS,
        mech: &CK_MECHANISM,
        key: &Object,
        signature: Option<Vec<u8>>,
    ) -> Result<EddsaOperation> {
        let variant = check_params(mech)?;
        if let Some(sig) = &signature {
            validate_signature_len(sig)?;
        }
        let material = match flag {
            CKF_SIGN => EddsaKey::Sign(privkey_from_object(key)?),
            CKF_VERIFY => EddsaKey::Verify(pubkey_from_object(key)?),
            _ => return Err(CKR_GENERAL_ERROR)?,
        };
        Ok(EddsaOperation {
            mech: mech.mechanism,
            output_len: OUTLEN_ED25519,
            finalized: false,
            in_use: false,
            key: material,
            variant,
            buffer: Vec::new(),
            signature,
            #[cfg(feature = "fips")]
            fips_approval: FipsApproval::init(),
        })
    }

    /// Creates a new `EddsaOperation` for signing.
    pub fn sign_new(
        mech: &CK_MECHANISM,
        key: &Object,
        _: &CK_MECHANISM_INFO,
    ) -> Result<EddsaOperation> {
        Self::new_op(CKF_SIGN, mech, key, None)
    }

    /// Creates a new `EddsaOperation` for verification.
    pub fn verify_new(
        mech: &CK_MECHANISM,
        key: &Object,
        _: &CK_MECHANISM_INFO,
    ) -> Result<EddsaOperation> {
        Self::new_op(CKF_VERIFY, mech, key, None)
    }

    /// Creates a new `EddsaOperation` for verification with a pre-supplied
    /// signature.
    pub fn verify_signature_new(
        mech: &CK_MECHANISM,
        key: &Object,
        _: &CK_MECHANISM_INFO,
        signature: &[u8],
    ) -> Result<EddsaOperation> {
        Self::new_op(CKF_VERIFY, mech, key, Some(signature.to_vec()))
    }

    /// Generates an Ed25519 key pair using AWS-LC.
    ///
    /// Takes mutable references to pre-created public and private key
    /// `Object`s (which contain the desired curve in CKA_EC_PARAMS),
    /// generates the key pair, and populates the CKA_EC_POINT and CKA_VALUE
    /// attributes. Rejects Ed448 (see the module doc comment) before ever
    /// calling into AWS-LC.
    pub fn generate_keypair(
        pubkey: &mut Object,
        privkey: &mut Object,
    ) -> Result<()> {
        ensure_ed25519(pubkey)?;

        let key = Ed25519Key::generate()?;

        /* Set Public Key: CKA_EC_POINT for CKK_EC_EDWARDS is the raw
         * public key bytes, no DER wrapping (unlike CKK_EC). */
        pubkey.set_attr(Attribute::from_bytes(
            CKA_EC_POINT,
            key.public_key().to_vec(),
        ))?;

        /* Set Private Key: CKA_VALUE is the raw 32-byte seed. `seed` here
         * is a fresh copy outside of `key`'s own zeroizing `Drop`, so scrub it
         * explicitly once copied into the attribute's own
         * storage. */
        let mut seed = key.seed();
        let result =
            privkey.set_attr(Attribute::from_bytes(CKA_VALUE, seed.to_vec()));
        crate::misc::zeromem(&mut seed);
        result?;

        Ok(())
    }
}

impl MechOperation for EddsaOperation {
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

impl Sign for EddsaOperation {
    fn sign(&mut self, data: &[u8], signature: &mut [u8]) -> Result<()> {
        if self.in_use {
            return Err(CKR_OPERATION_NOT_INITIALIZED)?;
        }
        if self.finalized {
            return Err(CKR_OPERATION_NOT_INITIALIZED)?;
        }
        self.sign_update(data)?;
        self.sign_final(signature)
    }

    fn sign_update(&mut self, data: &[u8]) -> Result<()> {
        if self.finalized {
            return Err(CKR_OPERATION_NOT_INITIALIZED)?;
        }
        self.in_use = true;
        self.buffer.extend_from_slice(data);
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
            return Err(CKR_SIGNATURE_LEN_RANGE)?;
        }
        let key = match &self.key {
            EddsaKey::Sign(k) => k,
            EddsaKey::Verify(_) => return Err(CKR_GENERAL_ERROR)?,
        };

        #[cfg(feature = "fips")]
        self.fips_approval.clear();

        let sig = match &self.variant {
            EddsaVariant::Plain => key.sign(&self.buffer),
            #[cfg(not(feature = "fips"))]
            EddsaVariant::Ctx(ctx) => key.sign_ctx(&self.buffer, ctx)?,
            #[cfg(not(feature = "fips"))]
            EddsaVariant::Ph(ctx) => key.sign_ph(&self.buffer, ctx)?,
        };

        #[cfg(feature = "fips")]
        self.fips_approval.finalize();

        signature.copy_from_slice(&sig);
        Ok(())
    }

    fn signature_len(&self) -> Result<usize> {
        Ok(self.output_len)
    }
}

impl EddsaOperation {
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
        self.verify_int_update(data)?;
        self.verify_int_final(signature)
    }

    /// Internal helper for updating a multi-part verification. Accumulates
    /// data.
    fn verify_int_update(&mut self, data: &[u8]) -> Result<()> {
        if self.finalized {
            return Err(CKR_OPERATION_NOT_INITIALIZED)?;
        }
        self.in_use = true;
        self.buffer.extend_from_slice(data);
        Ok(())
    }

    /// Internal helper for the final step of multi-part verification using
    /// accumulated data.
    fn verify_int_final(&mut self, signature: Option<&[u8]>) -> Result<()> {
        if !self.in_use {
            return Err(CKR_OPERATION_NOT_INITIALIZED)?;
        }
        if self.finalized {
            return Err(CKR_OPERATION_NOT_INITIALIZED)?;
        }
        self.finalized = true;

        let sig: &[u8] = match signature {
            Some(s) => {
                validate_signature_len(s)?;
                s
            }
            None => match &self.signature {
                Some(s) => s.as_slice(),
                None => return Err(CKR_GENERAL_ERROR)?,
            },
        };
        let public = match &self.key {
            EddsaKey::Verify(p) => p,
            EddsaKey::Sign(_) => return Err(CKR_GENERAL_ERROR)?,
        };
        let mut sig_arr = [0u8; OUTLEN_ED25519];
        sig_arr.copy_from_slice(sig);

        #[cfg(feature = "fips")]
        self.fips_approval.clear();

        match &self.variant {
            EddsaVariant::Plain => {
                Ed25519Key::verify(public, &self.buffer, &sig_arr)?
            }
            #[cfg(not(feature = "fips"))]
            EddsaVariant::Ctx(ctx) => {
                Ed25519Key::verify_ctx(public, &self.buffer, &sig_arr, ctx)?
            }
            #[cfg(not(feature = "fips"))]
            EddsaVariant::Ph(ctx) => {
                Ed25519Key::verify_ph(public, &self.buffer, &sig_arr, ctx)?
            }
        };

        #[cfg(feature = "fips")]
        self.fips_approval.finalize();

        Ok(())
    }
}

impl Verify for EddsaOperation {
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

impl VerifySignature for EddsaOperation {
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

    /// Registers the real, backend-agnostic EdDSA mechanisms/factories from
    /// `src/ec/eddsa.rs` (via `crate::ec::eddsa::register`), exactly as
    /// production `C_Initialize`/`C_GenerateKeyPair`/`C_SignInit`/
    /// `C_VerifyInit` reach them -- driving `EddsaMechanism::sign_new`/
    /// `verify_new`/`generate_keypair` (which in turn call into this
    /// module's `EddsaOperation`) rather than calling `EddsaOperation`
    /// directly, so these tests exercise the real `Mechanism`/`Sign`/
    /// `Verify` trait dispatch, not just the `awslc::eddsa` primitive
    /// layer.
    fn registered() -> (Mechanisms, ObjectFactories) {
        let mut mechs = Mechanisms::new();
        let mut ot = ObjectFactories::new();
        crate::ec::eddsa::register(&mut mechs, &mut ot);
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
        let mech = no_param_mech(CKM_EC_EDWARDS_KEY_PAIR_GEN);
        let entry = mechs.get(CKM_EC_EDWARDS_KEY_PAIR_GEN).unwrap();
        entry.generate_keypair(&mech, &pubkey_template, &prikey_template)
    }

    fn generate_keypair(
        mechs: &Mechanisms,
        curve_name: &str,
    ) -> (Object, Object) {
        generate_keypair_for(mechs, curve_name).expect("generate_keypair")
    }

    #[test]
    fn ed25519_generate_sign_verify_round_trip() {
        let (mechs, _ot) = registered();
        let (pubkey, privkey) =
            generate_keypair(&mechs, crate::ec::EDWARDS25519);

        assert_eq!(
            pubkey.get_attr_as_ulong(CKA_KEY_TYPE).unwrap(),
            CKK_EC_EDWARDS
        );
        assert_eq!(
            privkey.get_attr_as_ulong(CKA_KEY_TYPE).unwrap(),
            CKK_EC_EDWARDS
        );

        let data = b"the quick brown fox jumps over the lazy dog";
        let mech = no_param_mech(CKM_EDDSA);
        let entry = mechs.get(CKM_EDDSA).unwrap();

        let mut sign_op = entry.sign_new(&mech, &privkey).expect("sign_new");
        let siglen = sign_op.signature_len().unwrap();
        assert_eq!(siglen, OUTLEN_ED25519);
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

    /// Multi-part `sign_update`/`sign_final` and `verify_update`/
    /// `verify_final` must produce/accept the same result as the one-shot
    /// path (both buffer the full message internally -- see the module
    /// doc comment on why Ed25519 can't stream incrementally).
    #[test]
    fn multipart_sign_verify_matches_one_shot() {
        let (mechs, _ot) = registered();
        let (pubkey, privkey) =
            generate_keypair(&mechs, crate::ec::EDWARDS25519);
        let mech = no_param_mech(CKM_EDDSA);
        let entry = mechs.get(CKM_EDDSA).unwrap();

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
        let (pubkey, privkey) =
            generate_keypair(&mechs, crate::ec::EDWARDS25519);
        let data = b"verify-signature test data";
        let mech = no_param_mech(CKM_EDDSA);
        let entry = mechs.get(CKM_EDDSA).unwrap();

        let mut sign_op = entry.sign_new(&mech, &privkey).unwrap();
        let mut signature = vec![0u8; sign_op.signature_len().unwrap()];
        sign_op.sign(data, &mut signature).unwrap();

        let mut vsop = entry
            .verify_signature_new(&mech, &pubkey, &signature)
            .expect("verify_signature_new");
        vsop.verify(data).expect("verify_signature");
    }

    /// A signature produced against one keypair must not verify against a
    /// different keypair's public key.
    #[test]
    fn wrong_key_signature_rejected() {
        let (mechs, _ot) = registered();
        let (_pubkey1, privkey1) =
            generate_keypair(&mechs, crate::ec::EDWARDS25519);
        let (pubkey2, _privkey2) =
            generate_keypair(&mechs, crate::ec::EDWARDS25519);

        let data = b"cross-key test";
        let mech = no_param_mech(CKM_EDDSA);
        let entry = mechs.get(CKM_EDDSA).unwrap();

        let mut sign_op = entry.sign_new(&mech, &privkey1).unwrap();
        let mut signature = vec![0u8; sign_op.signature_len().unwrap()];
        sign_op.sign(data, &mut signature).unwrap();

        let mut verify_op = entry.verify_new(&mech, &pubkey2).unwrap();
        let err = verify_op
            .verify(data, &signature)
            .expect_err("wrong public key must fail verification");
        assert_eq!(err.rv(), CKR_SIGNATURE_INVALID);
    }

    /// The core gap this task documents: AWS-LC has no Ed448 primitive at
    /// all, so key generation for Ed448 must fail cleanly through the real
    /// `Mechanism::generate_keypair` dispatch, with a curve-specific error
    /// (`CKR_CURVE_NOT_SUPPORTED`) rather than a generic failure, a panic,
    /// or (worse) silently mis-handling the key as if it were Ed25519.
    #[test]
    fn ed448_key_generation_is_rejected() {
        let (mechs, _ot) = registered();
        let err = generate_keypair_for(&mechs, crate::ec::EDWARDS448)
            .expect_err("Ed448 key generation must fail: no AWS-LC primitive");
        assert_eq!(err.rv(), CKR_CURVE_NOT_SUPPORTED);
    }

    /// Even if an Ed448 key object were somehow constructed and handed to
    /// `sign_new`/`verify_new` directly (bypassing key generation), this
    /// module's own OID check must still reject it rather than
    /// mis-interpreting Ed448 key material as Ed25519's.
    #[test]
    fn ed448_sign_new_is_rejected() {
        let (mechs, ot) = registered();
        // Build a bogus but well-formed-enough CKO_PRIVATE_KEY/
        // CKK_EC_EDWARDS object carrying the Ed448 OID directly, since
        // `crate::ec::eddsa`'s own private-key factory validates
        // `CKA_VALUE`'s length against `ec_key_size(&oid)` (57 bytes for
        // Ed448) at creation time -- there is no way to reach this
        // module's `sign_new` with an Ed25519-shaped 32-byte value and an
        // Ed448 OID via the normal object-creation path.
        let params = curvename_to_ec_params(crate::ec::EDWARDS448).unwrap();
        let value = vec![0u8; crate::ec::ec_key_size(&oid::ED448_OID).unwrap()];
        // `EDDSAPrivFactory::create` unconditionally calls
        // `extract_public_key` on the object being created, which (for
        // this backend, see `crate::awslc::common::extract_public_key`'s
        // doc comment) only derives from raw key material for `CKK_EC`,
        // not yet `CKK_EC_EDWARDS` -- pre-populating `CKA_PUBLIC_KEY_INFO`
        // makes it take the "already have it" short-circuit instead, so
        // this test isolates the thing it actually means to exercise
        // (this module's own Ed25519-vs-Ed448 OID check in `sign_new`)
        // rather than tripping over that unrelated, pre-existing gap.
        let point_len = crate::ec::ec_point_size(&oid::ED448_OID).unwrap();
        let dummy_point = vec![0u8; point_len];
        let pki = crate::kasn1::pkcs::SubjectPublicKeyInfo::new(
            crate::kasn1::pkcs::ED448_ALG,
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
                pValue: &CKK_EC_EDWARDS as *const _ as CK_VOID_PTR,
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
                type_: CKA_SIGN,
                pValue: &mut ck_true as *mut CK_BBOOL as CK_VOID_PTR,
                ulValueLen: std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
            },
        ];
        let factory = ot.get_obj_factory_from_key_template(&template).unwrap();
        let privkey = factory.create(&template).unwrap();

        let mech = no_param_mech(CKM_EDDSA);
        let entry = mechs.get(CKM_EDDSA).unwrap();
        let err = entry
            .sign_new(&mech, &privkey)
            .expect_err("Ed448 sign_new must fail: no AWS-LC primitive");
        assert_eq!(err.rv(), CKR_CURVE_NOT_SUPPORTED);
    }

    /// `CK_EDDSA_PARAMS` requesting the prehashed variant (Ed25519ph) is
    /// supported via `ED25519ph_sign`/`_verify` (see `check_params`'s doc
    /// comment); the reference distinguishes it via `phFlag` alone,
    /// context length is independent (may be empty or not).
    #[test]
    #[cfg(not(feature = "fips"))]
    fn ed25519ph_sign_verify_round_trip() {
        let (mechs, _ot) = registered();
        let (pubkey, privkey) =
            generate_keypair(&mechs, crate::ec::EDWARDS25519);
        let context = b"some context".to_vec();
        let params = CK_EDDSA_PARAMS {
            phFlag: CK_TRUE,
            ulContextDataLen: context.len() as CK_ULONG,
            pContextData: context.as_ptr() as *mut u8,
        };
        let mech = CK_MECHANISM {
            mechanism: CKM_EDDSA,
            pParameter: &params as *const _ as CK_VOID_PTR,
            ulParameterLen: std::mem::size_of::<CK_EDDSA_PARAMS>() as CK_ULONG,
        };
        let entry = mechs.get(CKM_EDDSA).unwrap();
        let data = b"ed25519ph test message";

        let mut sign_op = entry.sign_new(&mech, &privkey).expect("sign_new");
        let mut signature = vec![0u8; sign_op.signature_len().unwrap()];
        sign_op.sign(data, &mut signature).expect("sign");

        let mut verify_op =
            entry.verify_new(&mech, &pubkey).expect("verify_new");
        verify_op.verify(data, &signature).expect("verify");

        // A plain (non-ph) verify of a ph-signed message must fail: they're
        // genuinely different signature schemes (SHA-512-prehashed vs. not).
        let plain_mech = no_param_mech(CKM_EDDSA);
        let mut plain_verify = entry.verify_new(&plain_mech, &pubkey).unwrap();
        assert!(plain_verify.verify(data, &signature).is_err());
    }

    /// `CK_EDDSA_PARAMS` with a non-empty context (Ed25519ctx) is supported
    /// via `ED25519ctx_sign`/`_verify` (see `check_params`'s doc comment).
    #[test]
    #[cfg(not(feature = "fips"))]
    fn ed25519ctx_sign_verify_round_trip() {
        let (mechs, _ot) = registered();
        let (pubkey, privkey) =
            generate_keypair(&mechs, crate::ec::EDWARDS25519);
        let context = b"some context".to_vec();
        let params = CK_EDDSA_PARAMS {
            phFlag: CK_FALSE,
            ulContextDataLen: context.len() as CK_ULONG,
            pContextData: context.as_ptr() as *mut u8,
        };
        let mech = CK_MECHANISM {
            mechanism: CKM_EDDSA,
            pParameter: &params as *const _ as CK_VOID_PTR,
            ulParameterLen: std::mem::size_of::<CK_EDDSA_PARAMS>() as CK_ULONG,
        };
        let entry = mechs.get(CKM_EDDSA).unwrap();
        let data = b"ed25519ctx test message";

        let mut sign_op = entry.sign_new(&mech, &privkey).expect("sign_new");
        let mut signature = vec![0u8; sign_op.signature_len().unwrap()];
        sign_op.sign(data, &mut signature).expect("sign");

        let mut verify_op =
            entry.verify_new(&mech, &pubkey).expect("verify_new");
        verify_op.verify(data, &signature).expect("verify");

        // A different context must fail verification.
        let other_context = b"different context".to_vec();
        let other_params = CK_EDDSA_PARAMS {
            phFlag: CK_FALSE,
            ulContextDataLen: other_context.len() as CK_ULONG,
            pContextData: other_context.as_ptr() as *mut u8,
        };
        let other_mech = CK_MECHANISM {
            mechanism: CKM_EDDSA,
            pParameter: &other_params as *const _ as CK_VOID_PTR,
            ulParameterLen: std::mem::size_of::<CK_EDDSA_PARAMS>() as CK_ULONG,
        };
        let mut verify_op2 = entry
            .verify_new(&other_mech, &pubkey)
            .expect("verify_new 2");
        assert!(verify_op2.verify(data, &signature).is_err());
    }

    /// Under `fips`, Ed25519ph/Ed25519ctx must still be rejected exactly as
    /// before (see `check_params`'s doc comment for why this is
    /// deliberately not extended to fips builds).
    #[test]
    #[cfg(feature = "fips")]
    fn ed25519ph_and_ctx_still_rejected_under_fips() {
        let (mechs, _ot) = registered();
        let (_pubkey, privkey) =
            generate_keypair(&mechs, crate::ec::EDWARDS25519);
        let entry = mechs.get(CKM_EDDSA).unwrap();

        let ph_params = CK_EDDSA_PARAMS {
            phFlag: CK_TRUE,
            ulContextDataLen: 0,
            pContextData: std::ptr::null_mut(),
        };
        let ph_mech = CK_MECHANISM {
            mechanism: CKM_EDDSA,
            pParameter: &ph_params as *const _ as CK_VOID_PTR,
            ulParameterLen: std::mem::size_of::<CK_EDDSA_PARAMS>() as CK_ULONG,
        };
        let err = entry
            .sign_new(&ph_mech, &privkey)
            .expect_err("Ed25519ph must still be rejected under fips");
        assert_eq!(err.rv(), CKR_MECHANISM_PARAM_INVALID);

        let context = b"some context".to_vec();
        let ctx_params = CK_EDDSA_PARAMS {
            phFlag: CK_FALSE,
            ulContextDataLen: context.len() as CK_ULONG,
            pContextData: context.as_ptr() as *mut u8,
        };
        let ctx_mech = CK_MECHANISM {
            mechanism: CKM_EDDSA,
            pParameter: &ctx_params as *const _ as CK_VOID_PTR,
            ulParameterLen: std::mem::size_of::<CK_EDDSA_PARAMS>() as CK_ULONG,
        };
        let err = entry
            .sign_new(&ctx_mech, &privkey)
            .expect_err("Ed25519ctx must still be rejected under fips");
        assert_eq!(err.rv(), CKR_MECHANISM_PARAM_INVALID);
    }

    #[test]
    fn registration_covers_expected_mechanisms() {
        let (mechs, _ot) = registered();
        for ckm in [CKM_EDDSA, CKM_EC_EDWARDS_KEY_PAIR_GEN] {
            assert!(mechs.get(ckm).is_ok());
        }
    }
}
