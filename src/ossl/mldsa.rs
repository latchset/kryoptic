// Copyright 2025 Simo Sorce
// See LICENSE.txt file for terms

//! This module implements the ML-DSA signature mechanisms as defined in FIPS
//! 204 using OpenSSL (3.5+) EVP_PKEY functions. It handles key generation,
//! signing, verification, and parameter/context handling for different ML-DSA
//! variants.

use crate::attribute::Attribute;
use crate::error::Result;
use crate::hash;
use crate::kasn1::oid::*;
use crate::mechanism::{Digest, MechOperation, Sign, Verify, VerifySignature};
use crate::object::Object;
use crate::ossl::common::{osslctx, privkey_from_object, pubkey_from_object};
use crate::pkcs11::*;
use crate::{bytes_to_vec, cast_params};

use asn1;
use bitflags::bitflags;
use ossl::pkey::{EvpPkey, EvpPkeyType, MlkeyData, PkeyData};
use ossl::signature::{mldsa_params, OsslSignature, SigAlg, SigOp};
use ossl::{OsslParam, OsslSecret};

#[cfg(feature = "fips")]
use ossl::fips::FipsApproval;

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
/// to the corresponding EvpPkeyType
fn mldsa_param_set_to_pkey_type(
    pset: CK_ML_DSA_PARAMETER_SET_TYPE,
) -> Result<EvpPkeyType> {
    match pset {
        CKP_ML_DSA_44 => Ok(EvpPkeyType::Mldsa44),
        CKP_ML_DSA_65 => Ok(EvpPkeyType::Mldsa65),
        CKP_ML_DSA_87 => Ok(EvpPkeyType::Mldsa87),
        _ => Err(CKR_ATTRIBUTE_VALUE_INVALID)?,
    }
}

/// Maps a PKCS#11 ML-DSA parameter set type (`CK_ML_DSA_PARAMETER_SET_TYPE`)
/// to the corresponding SigAlg
fn mldsa_param_set_to_sigalg(
    pset: CK_ML_DSA_PARAMETER_SET_TYPE,
) -> Result<SigAlg> {
    match pset {
        CKP_ML_DSA_44 => Ok(SigAlg::Mldsa44),
        CKP_ML_DSA_65 => Ok(SigAlg::Mldsa65),
        CKP_ML_DSA_87 => Ok(SigAlg::Mldsa87),
        _ => Err(CKR_ATTRIBUTE_VALUE_INVALID)?,
    }
}

/// Maps a PKCS#11 ML-DSA parameter set type (`CK_ML_DSA_PARAMETER_SET_TYPE`)
/// to the corresponding signature size
fn mldsa_param_to_sig_size(
    pset: CK_ML_DSA_PARAMETER_SET_TYPE,
) -> Result<usize> {
    let size = match pset {
        CKP_ML_DSA_44 => ML_DSA_44_SIG_SIZE,
        CKP_ML_DSA_65 => ML_DSA_65_SIG_SIZE,
        CKP_ML_DSA_87 => ML_DSA_87_SIG_SIZE,
        _ => return Err(CKR_GENERAL_ERROR)?,
    };
    Ok(size)
}

/// Converts a PKCS#11 ML-DSA key `Object` into an `EvpPkey`.
///
/// Extracts the parameter set (`CKA_PARAMETER_SET`) to determine the algorithm
/// name. Extracts key components (`CKA_VALUE` for public/private key,
/// `CKA_SEED`) based on the object `class` and populates an `MlkeyData`
/// structure.
pub fn mldsa_object_to_pkey(
    key: &Object,
    class: CK_OBJECT_CLASS,
) -> Result<EvpPkey> {
    let kclass = key.get_attr_as_ulong(CKA_CLASS)?;
    if kclass != class {
        return Err(CKR_KEY_TYPE_INCONSISTENT)?;
    }

    let param_set = key.get_attr_as_ulong(CKA_PARAMETER_SET)?;

    match kclass {
        CKO_PUBLIC_KEY => Ok(EvpPkey::import(
            osslctx(),
            mldsa_param_set_to_pkey_type(param_set)?,
            PkeyData::Mlkey(MlkeyData {
                pubkey: Some(key.get_attr_as_bytes(CKA_VALUE)?.clone()),
                prikey: None,
                seed: None,
            }),
        )?),
        CKO_PRIVATE_KEY => Ok(EvpPkey::import(
            osslctx(),
            mldsa_param_set_to_pkey_type(param_set)?,
            PkeyData::Mlkey(MlkeyData {
                pubkey: None,
                prikey: Some(OsslSecret::from_vec(
                    key.get_attr_as_bytes(CKA_VALUE)?.clone(),
                )),
                seed: match key.get_attr_as_bytes(CKA_SEED) {
                    Ok(s) => Some(OsslSecret::from_vec(s.clone())),
                    Err(_) => None,
                },
            }),
        )?),
        _ => Err(CKR_KEY_TYPE_INCONSISTENT)?,
    }
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
            sigsize: mldsa_param_to_sig_size(param_set)?,
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
    fn ossl_params<'a>(
        &'a self,
        flags: ParmFlags,
    ) -> Result<Option<OsslParam<'a>>> {
        Ok(mldsa_params(
            flags.contains(ParmFlags::RawEncoding),
            self.context.as_ref(),
            /* from the spec:
             * On verification the hedgeVariant parameter is ignored. */
            flags.contains(ParmFlags::Sign)
                && self.hedge == CKH_DETERMINISTIC_REQUIRED,
        )?)
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
    /// The ossl signature context.
    sigctx: OsslSignature,
    /// Size of the hash for Hash-ML-DSA variants.
    hashsize: usize,
    /// Optional hasher instance for Hash-ML-DSA variants.
    hasher: Option<Box<dyn Digest>>,
    /// Stored signature for VerifySignature operations for HashML-DSA.
    signature: Option<Vec<u8>>,
    /// FIPS approval status for the operation.
    #[cfg(feature = "fips")]
    fips_approval: FipsApproval,
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
        self.fips_approval.approval()
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
        let fips_approval = FipsApproval::init();

        /* OpenSSL 3.5.0 does not offer HashML-DSA, so we'll
         * have to compute the context on our own via raw
         * encoding. */
        let mut pflags = if mech.mechanism != CKM_ML_DSA {
            ParmFlags::RawEncoding
        } else {
            ParmFlags::Empty
        };

        let params =
            MlDsaParams::new(mech, key.get_attr_as_ulong(CKA_PARAMETER_SET)?)?;

        let (op, mut pkey) = match flag {
            CKF_SIGN => {
                pflags = pflags | ParmFlags::Sign;
                (SigOp::Sign, privkey_from_object(key)?)
            }
            CKF_VERIFY => {
                pflags = pflags | ParmFlags::Sign;
                (SigOp::Verify, pubkey_from_object(key)?)
            }
            _ => return Err(CKR_GENERAL_ERROR)?,
        };
        let sigctx = OsslSignature::new(
            osslctx(),
            op,
            mldsa_param_set_to_sigalg(params.param_set)?,
            &mut pkey,
            params.ossl_params(pflags)?.as_ref(),
        )?;

        let mut op = MlDsaOperation {
            mech: mech.mechanism,
            finalized: false,
            in_use: false,
            params: params,
            sigctx: sigctx,
            hashsize: 0,
            hasher: None,
            signature: None,
            #[cfg(feature = "fips")]
            fips_approval: fips_approval,
        };

        match mech.mechanism {
            CKM_ML_DSA => (),
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
            /* TODO SHAKE hashes? */
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
        op.fips_approval.update();

        Ok(op)
    }

    /// Sets the signature for a VerifySignature operation.
    fn set_signature(&mut self, signature: &[u8]) -> Result<()> {
        let size = mldsa_param_to_sig_size(self.params.param_set)?;
        if signature.len() != size {
            return Err(CKR_SIGNATURE_LEN_RANGE)?;
        }

        /*  HashML-DSA:
         *   We currently implement the pre-hasing ourselves in
         *   all cases because OpenSSL 3.5 does not support
         *   HashML-DSA at all, so we always store the signature
         *   to provide it later to message_verify()
         */
        if self.mech == CKM_ML_DSA {
            self.sigctx.set_signature(signature)?;
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
            /* TODO SHAKE hashes? */
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

    fn verify_hash(
        &mut self,
        hash: &[u8],
        signature: Option<&[u8]>,
    ) -> Result<()> {
        let mprime = self.hash_mldsa_m_prime(hash)?;
        let sig = match signature {
            Some(s) => s,
            None => match &self.signature {
                Some(s) => s.as_slice(),
                None => return Err(CKR_SIGNATURE_LEN_RANGE)?,
            },
        };
        Ok(self.sigctx.verify(mprime.as_slice(), Some(sig))?)
    }

    fn sign_hash(
        &mut self,
        hash: &[u8],
        signature: &mut [u8],
    ) -> Result<usize> {
        let mprime = self.hash_mldsa_m_prime(hash)?;
        Ok(self.sigctx.sign(mprime.as_slice(), Some(signature))?)
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
                self.finalized = true;

                /* For CKM_HASH_ML_DSA the data is the hash! */
                if data.len() != self.hashsize {
                    return Err(CKR_DATA_LEN_RANGE)?;
                }

                return self.verify_hash(data, signature);
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
        self.fips_approval.clear();

        match self.mech {
            CKM_ML_DSA => match self.sigctx.update(data) {
                Ok(()) => (),
                Err(e) => {
                    self.finalized = true;
                    return Err(e)?;
                }
            },
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
        self.fips_approval.finalize();

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
        self.fips_approval.clear();

        match self.mech {
            CKM_ML_DSA => self.sigctx.verify_final(signature)?,
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
                self.verify_hash(hash.as_slice(), signature)?
            }
            _ => return Err(CKR_GENERAL_ERROR)?,
        }

        #[cfg(feature = "fips")]
        self.fips_approval.update();

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
                self.finalized = true;

                /* For CKM_HASH_ML_DSA the data is the hash! */
                if data.len() != self.hashsize {
                    return Err(CKR_DATA_LEN_RANGE)?;
                }

                let siglen = self.sign_hash(data, signature)?;
                if siglen != signature.len() {
                    return Err(CKR_DEVICE_ERROR)?;
                }

                return Ok(());
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
        self.fips_approval.clear();

        match self.mech {
            CKM_ML_DSA => match self.sigctx.update(data) {
                Ok(()) => (),
                Err(e) => {
                    self.finalized = true;
                    return Err(e)?;
                }
            },
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

        #[cfg(feature = "fips")]
        self.fips_approval.clear();

        let siglen = match self.mech {
            CKM_ML_DSA => self.sigctx.sign_final(signature)?,
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
                self.sign_hash(hash.as_slice(), signature)?
            }
            _ => return Err(CKR_GENERAL_ERROR)?,
        };

        if siglen != signature.len() {
            return Err(CKR_DEVICE_ERROR)?;
        }

        #[cfg(feature = "fips")]
        self.fips_approval.update();

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
    let pkey =
        EvpPkey::generate(osslctx(), mldsa_param_set_to_pkey_type(param_set)?)?;
    let mut mlk = match pkey.export()? {
        PkeyData::Mlkey(m) => m,
        _ => return Err(CKR_GENERAL_ERROR)?,
    };

    /* Set Public Key */
    if let Some(key) = mlk.pubkey.take() {
        pubkey.set_attr(Attribute::from_bytes(CKA_VALUE, key))?;
    } else {
        return Err(CKR_DEVICE_ERROR)?;
    }

    /* Set private key and/or seed */
    if mlk.prikey.is_none() && mlk.seed.is_none() {
        return Err(CKR_DEVICE_ERROR)?;
    }
    if let Some(key) = mlk.prikey.take() {
        privkey.set_attr(Attribute::from_bytes(CKA_VALUE, key.to_vec()))?;
    }
    if let Some(seed) = mlk.seed.take() {
        privkey.set_attr(Attribute::from_bytes(CKA_SEED, seed.to_vec()))?;
    }

    Ok(())
}
