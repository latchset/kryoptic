// Copyright 2025 Simo Sorce
// See LICENSE.txt file for terms

//! This module implements the ML-DSA signature mechanisms as defined in FIPS
//! 204 using OpenSSL (3.5+) EVP_PKEY functions. It handles key generation,
//! signing, verification, and parameter/context handling for different ML-DSA
//! variants.

use std::ffi::c_char;

use crate::attribute::Attribute;
use crate::error::Result;
use crate::hash;
use crate::interface::*;
use crate::kasn1::oid::*;
use crate::mechanism::{Digest, MechOperation, Sign, Verify, VerifySignature};
use crate::object::Object;
use crate::ossl::bindings::*;
use crate::ossl::common::*;
use crate::{bytes_to_vec, cast_params};

use asn1;
use bitflags::bitflags;

#[cfg(feature = "fips")]
use crate::ossl::fips::*;

/// Maximum buffer size for accumulating data when emulating multi-part
/// operations for OpenSSL versions that only support one-shot ML-DSA.
const MAX_BUFFER_LEN: usize = 1024 * 1024;

/* Openssl Key types */
static ML_DSA_44_TYPE: &[u8; 10] = b"ML-DSA-44\0";
static ML_DSA_65_TYPE: &[u8; 10] = b"ML-DSA-65\0";
static ML_DSA_87_TYPE: &[u8; 10] = b"ML-DSA-87\0";

const ML_DSA_44_SIG_SIZE: usize = 2420;
const ML_DSA_65_SIG_SIZE: usize = 3309;
const ML_DSA_87_SIG_SIZE: usize = 4627;

/// Maximum allowed context length.
const MAX_CONTEXT_LEN: usize = 255;
/// Maximum expected DER length for a hash OID used in Hash-ML-DSA M'
/// construction. (17 bytes is probably sufficient, but we put some
/// headroom here) */
const MAX_OID_DER_LEN: usize = 20;
/// Maximum expected hash output length used in Hash-ML-DSA M' construction.
const MAX_HASH_LEN: usize = 64;

/// Maps a PKCS#11 ML-DSA parameter set type (`CK_ML_DSA_PARAMETER_SET_TYPE`)
/// to the corresponding OpenSSL algorithm name string.
pub fn mldsa_param_set_to_name(
    pset: CK_ML_DSA_PARAMETER_SET_TYPE,
) -> Result<*const c_char> {
    match pset {
        CKP_ML_DSA_44 => Ok(name_as_char(ML_DSA_44_TYPE)),
        CKP_ML_DSA_65 => Ok(name_as_char(ML_DSA_65_TYPE)),
        CKP_ML_DSA_87 => Ok(name_as_char(ML_DSA_87_TYPE)),
        _ => Err(CKR_ATTRIBUTE_VALUE_INVALID)?,
    }
}

/// Converts a PKCS#11 ML-DSA key `Object` into OpenSSL parameters
/// (`OsslParam`).
///
/// Extracts the parameter set (`CKA_PARAMETER_SET`) to determine the algorithm
/// name. Extracts key components (`CKA_VALUE` for public/private key,
/// `CKA_SEED`) based on the object `class` and populates an `OsslParam`
/// structure.
pub fn mldsa_object_to_params(
    key: &Object,
    class: CK_OBJECT_CLASS,
) -> Result<(*const c_char, OsslParam)> {
    let kclass = key.get_attr_as_ulong(CKA_CLASS)?;
    if kclass != class {
        return Err(CKR_KEY_TYPE_INCONSISTENT)?;
    }
    let mut params = OsslParam::with_capacity(3);
    params.zeroize = true;

    match kclass {
        CKO_PUBLIC_KEY => {
            params.add_owned_octet_string(
                name_as_char(OSSL_PKEY_PARAM_PUB_KEY),
                key.get_attr_as_bytes(CKA_VALUE)?.to_vec(),
            )?;
        }
        CKO_PRIVATE_KEY => {
            params.add_owned_octet_string(
                name_as_char(OSSL_PKEY_PARAM_PRIV_KEY),
                key.get_attr_as_bytes(CKA_VALUE)?.to_vec(),
            )?;
            match key.get_attr_as_bytes(CKA_SEED) {
                Ok(s) => params.add_owned_octet_string(
                    name_as_char(OSSL_PKEY_PARAM_ML_DSA_SEED),
                    s.to_vec(),
                )?,
                Err(_) => (),
            }
        }
        _ => return Err(CKR_KEY_TYPE_INCONSISTENT)?,
    }

    params.finalize();

    let param_set = key.get_attr_as_ulong(CKA_PARAMETER_SET)?;
    Ok((mldsa_param_set_to_name(param_set)?, params))
}

bitflags! {
    #[derive(Debug, Clone, Copy)]
    struct ParmFlags: u8 {
        const Empty       = 0x00;
        const Sign        = 0x01;
        const Verify      = 0x02;
        const RawEncoding = 0x04;
    }
}

/// Holds parsed parameters specific to an ML-DSA operation instance.
#[derive(Debug)]
struct MlDsaParams {
    /// The ML-DSA parameter set (e.g., CKP_ML_DSA_65).
    param_set: CK_ML_DSA_PARAMETER_SET_TYPE,
    /// The hedging variant requested (e.g., CKH_HEDGE_PREFERRED).
    hedge: CK_HEDGE_TYPE,
    /// Optional context string.
    context: Option<Vec<u8>>,
    /// Hash mechanism for CKM_HASH_ML_DSA.
    hash: CK_MECHANISM_TYPE,
    /// Expected signature size based on the parameter set.
    sigsize: usize,
}

impl MlDsaParams {
    /// Creates a new `MlDsaParams` instance by parsing mechanism parameters.
    pub fn new(
        mech: &CK_MECHANISM,
        param_set: CK_ML_DSA_PARAMETER_SET_TYPE,
    ) -> Result<MlDsaParams> {
        let mut mldsa_params = MlDsaParams {
            param_set: param_set,
            hedge: CKH_HEDGE_PREFERRED,
            context: None,
            hash: CK_UNAVAILABLE_INFORMATION,
            sigsize: match param_set {
                CKP_ML_DSA_44 => ML_DSA_44_SIG_SIZE,
                CKP_ML_DSA_65 => ML_DSA_65_SIG_SIZE,
                CKP_ML_DSA_87 => ML_DSA_87_SIG_SIZE,
                _ => return Err(CKR_KEY_INDIGESTIBLE)?,
            },
        };

        if !mech.pParameter.is_null() {
            match mech.mechanism {
                CKM_ML_DSA
                | CKM_HASH_ML_DSA_SHA224
                | CKM_HASH_ML_DSA_SHA256
                | CKM_HASH_ML_DSA_SHA384
                | CKM_HASH_ML_DSA_SHA512
                | CKM_HASH_ML_DSA_SHA3_224
                | CKM_HASH_ML_DSA_SHA3_256
                | CKM_HASH_ML_DSA_SHA3_384
                | CKM_HASH_ML_DSA_SHA3_512
                | CKM_HASH_ML_DSA_SHAKE128
                | CKM_HASH_ML_DSA_SHAKE256 => {
                    let params = cast_params!(mech, CK_SIGN_ADDITIONAL_CONTEXT);
                    match params.hedgeVariant {
                        CKH_HEDGE_PREFERRED
                        | CKH_HEDGE_REQUIRED
                        | CKH_DETERMINISTIC_REQUIRED => (),
                        _ => return Err(CKR_MECHANISM_PARAM_INVALID)?,
                    }
                    mldsa_params.hedge = params.hedgeVariant;
                    if params.ulContextLen > 0 {
                        if params.ulContextLen > MAX_CONTEXT_LEN as CK_ULONG {
                            return Err(CKR_MECHANISM_PARAM_INVALID)?;
                        }
                        mldsa_params.context = Some(bytes_to_vec!(
                            params.pContext,
                            params.ulContextLen
                        ));
                    }
                }
                CKM_HASH_ML_DSA => {
                    let params =
                        cast_params!(mech, CK_HASH_SIGN_ADDITIONAL_CONTEXT);
                    match params.hedgeVariant {
                        CKH_HEDGE_PREFERRED
                        | CKH_HEDGE_REQUIRED
                        | CKH_DETERMINISTIC_REQUIRED => (),
                        _ => return Err(CKR_MECHANISM_PARAM_INVALID)?,
                    }
                    mldsa_params.hedge = params.hedgeVariant;
                    if params.ulContextLen > 0 {
                        if params.ulContextLen > MAX_CONTEXT_LEN as CK_ULONG {
                            return Err(CKR_MECHANISM_PARAM_INVALID)?;
                        }
                        mldsa_params.context = Some(bytes_to_vec!(
                            params.pContext,
                            params.ulContextLen
                        ));
                    }
                    mldsa_params.hash = params.hash;
                }
                _ => return Err(CKR_MECHANISM_INVALID)?,
            }
        }
        Ok(mldsa_params)
    }

    /// Creates an `OsslParam` array suitable for passing to OpenSSL's
    /// `EVP_PKEY_sign/verify_message_init` based on the stored parameters
    /// and operation flags (sign/verify, raw encoding). Handles context string
    /// and deterministic/hedging parameters.
    fn ossl_params(&self, flags: ParmFlags) -> Result<OsslParam> {
        let mut params = OsslParam::with_capacity(3);
        if flags.contains(ParmFlags::RawEncoding) {
            params.add_owned_int(
                name_as_char(OSSL_SIGNATURE_PARAM_MESSAGE_ENCODING),
                0,
            )?;
        } else {
            if let Some(ctx) = &self.context {
                params.add_octet_string(
                    name_as_char(OSSL_SIGNATURE_PARAM_CONTEXT_STRING),
                    ctx,
                )?;
            }
        }
        /* from the spec:
         * On verification the hedgeVariant parameter is ignored. */
        if flags.contains(ParmFlags::Sign) {
            if self.hedge == CKH_DETERMINISTIC_REQUIRED {
                params.add_owned_int(
                    name_as_char(OSSL_SIGNATURE_PARAM_DETERMINISTIC),
                    1,
                )?;
            }
        }
        params.finalize();

        Ok(params)
    }
}

/// Represents an active ML-DSA signing or verification operation.
#[derive(Debug)]
pub struct MlDsaOperation {
    /// The specific ML-DSA mechanism being used.
    mech: CK_MECHANISM_TYPE,
    /// Flag indicating if the operation has been finalized.
    finalized: bool,
    /// Flag indicating if the operation is in progress (update called).
    in_use: bool,
    /// Parsed ML-DSA parameters for this operation instance.
    params: MlDsaParams,
    /// The underlying OpenSSL EVP PKEY context.
    sigctx: EvpPkeyCtx,
    /// Buffer to accumulate data for multi-part emulation if needed.
    data: Option<Vec<u8>>,
    /// Size of the hash for Hash-ML-DSA variants.
    hashsize: usize,
    /// Optional hasher instance for Hash-ML-DSA variants.
    hasher: Option<Box<dyn Digest>>,
    /// Stored signature for VerifySignature operations if updates aren't
    /// supported by the OpenSSL ML-DSA provider.
    signature: Option<Vec<u8>>,
    /// Flag indicating if the current OpenSSL version supports multi-part
    /// updates.
    supports_updates: bool,
    /// FIPS approval status for the operation.
    #[cfg(feature = "fips")]
    fips_approved: Option<bool>,
}

impl MechOperation for MlDsaOperation {
    fn mechanism(&self) -> Result<CK_MECHANISM_TYPE> {
        Ok(self.mech)
    }

    fn finalized(&self) -> bool {
        self.finalized
    }

    #[cfg(feature = "fips")]
    fn fips_approved(&self) -> Option<bool> {
        self.fips_approved
    }
}

impl MlDsaOperation {
    /// Creates a new ML-DSA sign or verify operation context.
    ///
    /// Initializes the internal state, parses mechanism parameters, imports
    /// the key into an OpenSSL `EVP_PKEY_CTX`, and initializes the context
    /// for signing or verification using `EVP_PKEY_sign/verify_message_init`.
    /// It also probes whether the OpenSSL version supports multi-part updates
    /// for ML-DSA and sets up internal hashing if a Hash-ML-DSA variant is
    /// used.
    pub fn sigver_new(
        mech: &CK_MECHANISM,
        key: &Object,
        flag: CK_FLAGS,
        signature: Option<&[u8]>,
    ) -> Result<MlDsaOperation> {
        #[cfg(feature = "fips")]
        let fips_approved: Option<bool> = {
            let mut fa: Option<bool> = None;
            fips_approval_init_checks(&mut fa);
            fa
        };
        let mut op = MlDsaOperation {
            mech: mech.mechanism,
            finalized: false,
            in_use: false,
            params: MlDsaParams::new(
                mech,
                key.get_attr_as_ulong(CKA_PARAMETER_SET)?,
            )?,
            sigctx: match flag {
                CKF_SIGN => {
                    let mut privkey = EvpPkey::privkey_from_object(key)?;
                    privkey.new_ctx()?
                }
                CKF_VERIFY => {
                    let mut pubkey = EvpPkey::pubkey_from_object(key)?;
                    pubkey.new_ctx()?
                }
                _ => return Err(CKR_GENERAL_ERROR)?,
            },
            data: None,
            hashsize: 0,
            hasher: None,
            signature: None,
            supports_updates: false,
            #[cfg(feature = "fips")]
            fips_approved: fips_approved,
        };

        /* OpenSSL 3.5.0 does not offer HashML-DSA, so we'll
         * have to compute the context on our own via raw
         * encoding. */
        let mut pflags = if mech.mechanism != CKM_ML_DSA {
            ParmFlags::RawEncoding
        } else {
            ParmFlags::Empty
        };

        match flag {
            CKF_SIGN => {
                pflags = pflags | ParmFlags::Sign;
                let res = unsafe {
                    EVP_PKEY_sign_message_init(
                        op.sigctx.as_mut_ptr(),
                        EvpSignature::new(mldsa_param_set_to_name(
                            op.params.param_set,
                        )?)?
                        .as_mut_ptr(),
                        op.params.ossl_params(pflags)?.as_ptr(),
                    )
                };
                if res != 1 {
                    return Err(CKR_DEVICE_ERROR)?;
                }
            }
            CKF_VERIFY => {
                pflags = pflags | ParmFlags::Verify;

                let res = unsafe {
                    EVP_PKEY_verify_message_init(
                        op.sigctx.as_mut_ptr(),
                        EvpSignature::new(mldsa_param_set_to_name(
                            op.params.param_set,
                        )?)?
                        .as_mut_ptr(),
                        op.params.ossl_params(pflags)?.as_ptr(),
                    )
                };
                if res != 1 {
                    return Err(CKR_DEVICE_ERROR)?;
                }
            }
            _ => return Err(CKR_GENERAL_ERROR)?,
        }

        match mech.mechanism {
            CKM_ML_DSA => match flag {
                /* OpenSSL 3.5 implements only one shot ML-DSA,
                 * while later implementations can deal with
                 * update()/final() operations. Probe here, and
                 * set up a backup buffer if update()s are not
                 * supported.
                 */
                CKF_SIGN => {
                    if unsafe {
                        EVP_PKEY_sign_message_update(
                            op.sigctx.as_mut_ptr(),
                            std::ptr::null(),
                            0,
                        )
                    } == 1
                    {
                        op.supports_updates = true;
                    }
                }
                CKF_VERIFY => {
                    if unsafe {
                        EVP_PKEY_verify_message_update(
                            op.sigctx.as_mut_ptr(),
                            std::ptr::null(),
                            0,
                        )
                    } == 1
                    {
                        op.supports_updates = true;
                    }
                }
                _ => return Err(CKR_GENERAL_ERROR)?,
            },
            CKM_HASH_ML_DSA => {
                /* check that the hash is of the right size */
                op.hashsize = match hash::hash_size(op.params.hash) {
                    hash::INVALID_HASH_SIZE => {
                        return Err(CKR_MECHANISM_INVALID)?;
                    }
                    x => x,
                }
            }
            CKM_HASH_ML_DSA_SHA224 => op.setup_digest(CKM_SHA224)?,
            CKM_HASH_ML_DSA_SHA256 => op.setup_digest(CKM_SHA256)?,
            CKM_HASH_ML_DSA_SHA384 => op.setup_digest(CKM_SHA384)?,
            CKM_HASH_ML_DSA_SHA512 => op.setup_digest(CKM_SHA512)?,
            CKM_HASH_ML_DSA_SHA3_224 => op.setup_digest(CKM_SHA3_224)?,
            CKM_HASH_ML_DSA_SHA3_256 => op.setup_digest(CKM_SHA3_256)?,
            CKM_HASH_ML_DSA_SHA3_384 => op.setup_digest(CKM_SHA3_384)?,
            CKM_HASH_ML_DSA_SHA3_512 => op.setup_digest(CKM_SHA3_512)?,
            _ => return Err(CKR_MECHANISM_INVALID)?,
        };

        if flag == CKF_VERIFY {
            /* Can try to set the signature only after we probed updates.
             * Unfortunately EVP_PKEY_CTX_settable_params() is not available
             * directly in the FIPS provider so we avoid using that function
             * to probe and infer support from the fact this change went in
             * at the same time the update() functions were added */
            match signature {
                Some(sig) => op.set_signature(sig)?,
                None => (),
            }
        }

        #[cfg(feature = "fips")]
        fips_approval_check(&mut op.fips_approved);

        Ok(op)
    }

    /// Sets the signature for a VerifySignature operation.
    /// If the OpenSSL backend supports setting it early (via
    /// `EVP_PKEY_CTX_set_signature`), it does so; otherwise, it stores the
    /// signature internally for later use.
    fn set_signature(&mut self, signature: &[u8]) -> Result<()> {
        let size = match self.params.param_set {
            CKP_ML_DSA_44 => ML_DSA_44_SIG_SIZE,
            CKP_ML_DSA_65 => ML_DSA_65_SIG_SIZE,
            CKP_ML_DSA_87 => ML_DSA_87_SIG_SIZE,
            _ => return Err(CKR_GENERAL_ERROR)?,
        };
        if signature.len() != size {
            return Err(CKR_SIGNATURE_LEN_RANGE)?;
        }

        /* For ML-DSA:
         *   OpenSSL 3.5 implements only one shot ML-DSA and
         *   can't ingest a signature early, if that's the case,
         *   then we store it for later use.
         * For HashML-DSA:
         *   We currently implement the pre-hasing ourselves in
         *   all cases because OpenSSL 3.5 does not support
         *   HashML-DSA at all, so we always store the signature
         *   to provide it later to EVP_PKEY_verify()
         */
        if self.mech == CKM_ML_DSA && self.supports_updates {
            let ret = unsafe {
                EVP_PKEY_CTX_set_signature(
                    self.sigctx.as_mut_ptr(),
                    signature.as_ptr(),
                    signature.len(),
                )
            };
            if ret != 1 {
                return Err(CKR_DEVICE_ERROR)?;
            }
        } else {
            self.signature = Some(signature.to_vec())
        }

        Ok(())
    }

    /// Sets up the internal hasher for Hash-ML-DSA variants based on the
    /// mechanism type.
    fn setup_digest(&mut self, hash: CK_MECHANISM_TYPE) -> Result<()> {
        self.hashsize = match hash::hash_size(hash) {
            hash::INVALID_HASH_SIZE => {
                return Err(CKR_MECHANISM_INVALID)?;
            }
            x => x,
        };
        self.hasher = Some(hash::internal_hash_op(hash)?);
        /* record the hash in params to use it later to
         * know which OID to use in M' calculation */
        self.params.hash = hash;
        Ok(())
    }

    /// Compute M' for Hash-ML-DSA
    ///
    /// For Hash-ML-DSA the encoding is:
    /// M' = 01 || ctx_len || ctx || OID || Hash(msg)
    /// See FIPS-204 Algorithm 4 Step 23 (and Algorithm 5 Step 18)
    fn hash_mldsa_m_prime(&self, hmsg: &[u8]) -> Result<Vec<u8>> {
        let mut mp = Vec::<u8>::with_capacity(
            1 + 1 + MAX_CONTEXT_LEN + MAX_OID_DER_LEN + MAX_HASH_LEN,
        );

        /* 01 */
        mp.push(1);

        /* || ctx_len || ctx */
        if let Some(ctx) = &self.params.context {
            mp.push(u8::try_from(ctx.len())?);
            mp.extend_from_slice(ctx.as_slice());
        } else {
            mp.push(0);
        }

        let oid = match self.params.hash {
            CKM_SHA224 => SHA224_OID,
            CKM_SHA256 => SHA256_OID,
            CKM_SHA384 => SHA384_OID,
            CKM_SHA512 => SHA512_OID,
            CKM_SHA3_224 => SHA3_224_OID,
            CKM_SHA3_256 => SHA3_256_OID,
            CKM_SHA3_384 => SHA3_384_OID,
            CKM_SHA3_512 => SHA3_512_OID,
            _ => return Err(CKR_MECHANISM_PARAM_INVALID)?,
        };

        /* || OID */
        let oid_encoded = match asn1::write_single(&oid) {
            Ok(b) => b,
            Err(_) => return Err(CKR_GENERAL_ERROR)?,
        };
        mp.extend_from_slice(oid_encoded.as_slice());

        /* || Hash(msg) */
        if hmsg.len() != hash::hash_size(self.params.hash) {
            return Err(CKR_DATA_LEN_RANGE)?;
        }
        mp.extend_from_slice(hmsg);

        Ok(mp)
    }

    /// Internal helper to update the internal hasher for Hash-ML-DSA variants.
    fn digest_int_update(&mut self, data: &[u8]) -> Result<()> {
        match &mut self.hasher {
            Some(op) => op.digest_update(data),
            None => Err(CKR_GENERAL_ERROR)?,
        }
    }

    /// Internal helper to finalize the internal hasher for Hash-ML-DSA
    /// variants.
    fn digest_int_final(&mut self, digest: &mut [u8]) -> Result<()> {
        match &mut self.hasher {
            Some(op) => op.digest_final(digest),
            None => Err(CKR_GENERAL_ERROR)?,
        }
    }

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
        match self.mech {
            CKM_HASH_ML_DSA => {
                self.in_use = true;

                /* For CKM_HASH_ML_DSA the data is the hash! */
                if data.len() != self.hashsize {
                    self.finalized = true;
                    return Err(CKR_DATA_LEN_RANGE)?;
                }
                self.data = Some(data.to_vec());
            }
            _ => self.verify_int_update(data)?,
        }
        self.verify_int_final(signature)
    }

    /// Internal helper for updating a multi-part verification.
    /// Handles data buffering.
    fn verify_int_update(&mut self, data: &[u8]) -> Result<()> {
        if self.finalized {
            return Err(CKR_OPERATION_NOT_INITIALIZED)?;
        }
        if !self.in_use {
            self.in_use = true;
        }

        #[cfg(feature = "fips")]
        fips_approval_prep_check();

        match self.mech {
            CKM_ML_DSA => {
                if self.supports_updates {
                    if unsafe {
                        EVP_PKEY_verify_message_update(
                            self.sigctx.as_mut_ptr(),
                            data.as_ptr(),
                            data.len(),
                        )
                    } != 1
                    {
                        self.finalized = true;
                        return Err(CKR_DEVICE_ERROR)?;
                    }
                } else {
                    match &mut self.data {
                        Some(buffer) => {
                            if buffer.len() + data.len() > MAX_BUFFER_LEN {
                                self.finalized = true;
                                return Err(CKR_GENERAL_ERROR)?;
                            }
                            buffer.extend_from_slice(data);
                        }
                        None => {
                            if data.len() > MAX_BUFFER_LEN {
                                self.finalized = true;
                                return Err(CKR_GENERAL_ERROR)?;
                            }
                            self.data = Some(data.to_vec());
                        }
                    }
                }
            }
            CKM_HASH_ML_DSA => {
                /* CKM_HASH_ML_DSA is single-part only */
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
            | CKM_HASH_ML_DSA_SHA3_512 => self.digest_int_update(data)?,
            _ => return Err(CKR_GENERAL_ERROR)?,
        }

        #[cfg(feature = "fips")]
        fips_approval_finalize(&mut self.fips_approved);

        Ok(())
    }

    /// Internal helper for the final step of multi-part verification.
    /// Computes M' if necessary and performs the final OpenSSL verification
    /// call.
    fn verify_int_final(&mut self, signature: Option<&[u8]>) -> Result<()> {
        if !self.in_use {
            return Err(CKR_OPERATION_NOT_INITIALIZED)?;
        }
        if self.finalized {
            return Err(CKR_OPERATION_NOT_INITIALIZED)?;
        }

        self.finalized = true;

        #[cfg(feature = "fips")]
        fips_approval_prep_check();

        match self.mech {
            CKM_ML_DSA | CKM_HASH_ML_DSA => (),
            CKM_HASH_ML_DSA_SHA224
            | CKM_HASH_ML_DSA_SHA256
            | CKM_HASH_ML_DSA_SHA384
            | CKM_HASH_ML_DSA_SHA512
            | CKM_HASH_ML_DSA_SHA3_224
            | CKM_HASH_ML_DSA_SHA3_256
            | CKM_HASH_ML_DSA_SHA3_384
            | CKM_HASH_ML_DSA_SHA3_512 => {
                let mut hash = vec![0u8; self.hashsize];
                self.digest_int_final(hash.as_mut_slice())?;
                self.data = Some(hash);
            }
            _ => return Err(CKR_GENERAL_ERROR)?,
        }

        if let Some(mut buffer) = self.data.take() {
            if self.mech != CKM_ML_DSA {
                buffer = self.hash_mldsa_m_prime(buffer.as_slice())?;
            }
            self.data = None;

            let sig = match signature {
                Some(s) => s,
                None => match &self.signature {
                    Some(s) => s.as_slice(),
                    None => return Err(CKR_SIGNATURE_LEN_RANGE)?,
                },
            };
            let ret = unsafe {
                EVP_PKEY_verify(
                    self.sigctx.as_mut_ptr(),
                    sig.as_ptr(),
                    sig.len(),
                    buffer.as_ptr(),
                    buffer.len(),
                )
            };
            if ret != 1 {
                return Err(CKR_DEVICE_ERROR)?;
            }
        } else {
            if !self.supports_updates {
                return Err(CKR_GENERAL_ERROR)?;
            }
            match signature {
                Some(sig) => {
                    let ret = unsafe {
                        EVP_PKEY_CTX_set_signature(
                            self.sigctx.as_mut_ptr(),
                            sig.as_ptr(),
                            sig.len(),
                        )
                    };
                    if ret != 1 {
                        return Err(CKR_DEVICE_ERROR)?;
                    }
                }
                None => (),
            }
            if unsafe {
                EVP_PKEY_verify_message_final(self.sigctx.as_mut_ptr())
            } != 1
            {
                return Err(CKR_DEVICE_ERROR)?;
            }
        }

        #[cfg(feature = "fips")]
        fips_approval_check(&mut self.fips_approved);

        Ok(())
    }
}

impl Sign for MlDsaOperation {
    fn sign(&mut self, data: &[u8], signature: &mut [u8]) -> Result<()> {
        if self.in_use {
            return Err(CKR_OPERATION_NOT_INITIALIZED)?;
        }
        if self.finalized {
            return Err(CKR_OPERATION_NOT_INITIALIZED)?;
        }
        match self.mech {
            CKM_HASH_ML_DSA => {
                self.in_use = true;

                /* For CKM_HASH_ML_DSA the data is the hash! */
                if data.len() != self.hashsize {
                    self.finalized = true;
                    return Err(CKR_DATA_LEN_RANGE)?;
                }
                self.data = Some(data.to_vec());
            }
            _ => self.sign_update(data)?,
        }
        self.sign_final(signature)
    }

    fn sign_update(&mut self, data: &[u8]) -> Result<()> {
        if self.finalized {
            return Err(CKR_OPERATION_NOT_INITIALIZED)?;
        }
        if !self.in_use {
            self.in_use = true;
        }

        #[cfg(feature = "fips")]
        fips_approval_prep_check();

        match self.mech {
            CKM_ML_DSA => {
                if self.supports_updates {
                    let ret = unsafe {
                        EVP_PKEY_sign_message_update(
                            self.sigctx.as_mut_ptr(),
                            data.as_ptr(),
                            data.len(),
                        )
                    };
                    if ret != 1 {
                        self.finalized = true;
                        return Err(CKR_DEVICE_ERROR)?;
                    }
                } else {
                    match &mut self.data {
                        Some(buffer) => {
                            if buffer.len() + data.len() > MAX_BUFFER_LEN {
                                self.finalized = true;
                                return Err(CKR_GENERAL_ERROR)?;
                            }
                            buffer.extend_from_slice(data);
                        }
                        None => {
                            if data.len() > MAX_BUFFER_LEN {
                                self.finalized = true;
                                return Err(CKR_GENERAL_ERROR)?;
                            }
                            self.data = Some(data.to_vec());
                        }
                    }
                }
            }
            CKM_HASH_ML_DSA => {
                /* CKM_HASH_ML_DSA is single-part only */
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
            | CKM_HASH_ML_DSA_SHA3_512 => self.digest_int_update(data)?,
            _ => return Err(CKR_GENERAL_ERROR)?,
        }

        #[cfg(feature = "fips")]
        fips_approval_check(&mut self.fips_approved);

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

        #[cfg(feature = "fips")]
        fips_approval_prep_check();

        match self.mech {
            CKM_ML_DSA | CKM_HASH_ML_DSA => (),
            CKM_HASH_ML_DSA_SHA224
            | CKM_HASH_ML_DSA_SHA256
            | CKM_HASH_ML_DSA_SHA384
            | CKM_HASH_ML_DSA_SHA512
            | CKM_HASH_ML_DSA_SHA3_224
            | CKM_HASH_ML_DSA_SHA3_256
            | CKM_HASH_ML_DSA_SHA3_384
            | CKM_HASH_ML_DSA_SHA3_512 => {
                let mut hash = vec![0u8; self.hashsize];
                self.digest_int_final(hash.as_mut_slice())?;
                self.data = Some(hash);
            }
            _ => return Err(CKR_GENERAL_ERROR)?,
        }

        let mut siglen = signature.len();
        let siglen_ptr: *mut usize = &mut siglen;

        if let Some(mut buffer) = self.data.take() {
            if self.mech != CKM_ML_DSA {
                buffer = self.hash_mldsa_m_prime(buffer.as_slice())?;
            }
            if unsafe {
                EVP_PKEY_sign(
                    self.sigctx.as_mut_ptr(),
                    signature.as_mut_ptr(),
                    siglen_ptr,
                    buffer.as_ptr(),
                    buffer.len(),
                )
            } != 1
            {
                return Err(CKR_DEVICE_ERROR)?;
            }
        } else {
            if !self.supports_updates {
                return Err(CKR_GENERAL_ERROR)?;
            }
            if unsafe {
                EVP_PKEY_sign_message_final(
                    self.sigctx.as_mut_ptr(),
                    signature.as_mut_ptr(),
                    siglen_ptr,
                )
            } != 1
            {
                return Err(CKR_DEVICE_ERROR)?;
            }
        }

        if siglen != signature.len() {
            return Err(CKR_DEVICE_ERROR)?;
        }

        #[cfg(feature = "fips")]
        fips_approval_check(&mut self.fips_approved);

        Ok(())
    }

    fn signature_len(&self) -> Result<usize> {
        Ok(self.params.sigsize)
    }
}

impl Verify for MlDsaOperation {
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
        Ok(self.params.sigsize)
    }
}

impl VerifySignature for MlDsaOperation {
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
/// Populates the public (`CKA_VALUE`) and private (`CKA_VALUE`, `CKA_SEED`)
/// key attributes in the provided `Object`s.
pub fn generate_keypair(
    param_set: CK_ML_DSA_PARAMETER_SET_TYPE,
    pubkey: &mut Object,
    privkey: &mut Object,
) -> Result<()> {
    let evp_pkey = EvpPkey::generate(
        mldsa_param_set_to_name(param_set)?,
        &OsslParam::empty(),
    )?;

    let mut params = evp_pkey.todata(EVP_PKEY_KEYPAIR)?;
    let val =
        params.get_octet_string(name_as_char(OSSL_PKEY_PARAM_PRIV_KEY))?;
    privkey.set_attr(Attribute::from_bytes(CKA_VALUE, val.to_vec()))?;

    match params.get_octet_string(name_as_char(OSSL_PKEY_PARAM_ML_DSA_SEED)) {
        Ok(val) => {
            privkey.set_attr(Attribute::from_bytes(CKA_SEED, val.to_vec()))?
        }
        Err(e) => {
            if !e.attr_not_found() {
                return Err(e);
            }
        }
    }

    // OpenSSL helpfully does not provide public key when we ask for key pair
    // here so if it is not available, retry exporting just public key part
    // https://github.com/openssl/openssl/issues/27542
    let val = match params
        .get_octet_string(name_as_char(OSSL_PKEY_PARAM_PUB_KEY))
    {
        Ok(v) => v,
        Err(_) => {
            params = evp_pkey.todata(EVP_PKEY_PUBLIC_KEY)?;
            params.get_octet_string(name_as_char(OSSL_PKEY_PARAM_PUB_KEY))?
        }
    };
    pubkey.set_attr(Attribute::from_bytes(CKA_VALUE, val.to_vec()))?;

    Ok(())
}
