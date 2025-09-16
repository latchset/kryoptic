// Copyright 2025 Simo Sorce
// See LICENSE.txt file for terms

//! This module provides a coherent abstraction over the several OpenSSL
//! signature apis

use std::ffi::{c_char, c_int, CStr};

use crate::bindings::*;
use crate::digest::{digest_to_string, DigestAlg};
use crate::pkey::{EvpPkey, EvpPkeyCtx};
use crate::{
    cstr, trace_ossl, Error, ErrorKind, OsslContext, OsslParam,
    OsslParamBuilder,
};

#[cfg(not(feature = "fips"))]
use crate::digest::EvpMdCtx;

#[cfg(feature = "fips")]
use crate::fips::ProviderSignatureCtx;

/// Wrapper around OpenSSL's `EVP_SIGNATURE`, used for ML-DSA and SLH-DSA operations.
#[cfg(ossl_v350)]
struct EvpSignature {
    ptr: *mut EVP_SIGNATURE,
}

#[cfg(ossl_v350)]
impl EvpSignature {
    /// Creates a new `EvpSignature` instance by fetching it by name.
    pub fn new(ctx: &OsslContext, name: &CStr) -> Result<EvpSignature, Error> {
        let ptr: *mut EVP_SIGNATURE = unsafe {
            EVP_SIGNATURE_fetch(ctx.ptr(), name.as_ptr(), std::ptr::null_mut())
        };
        if ptr.is_null() {
            trace_ossl!("EVP_SIGNATURE_fetch()");
            return Err(Error::new(ErrorKind::NullPtr));
        }
        Ok(EvpSignature { ptr })
    }

    /// Returns a const pointer to the underlying `EVP_SIGNATURE`.
    #[allow(dead_code)]
    pub fn as_ptr(&self) -> *const EVP_SIGNATURE {
        self.ptr
    }

    /// Returns a mutable pointer to the underlying `EVP_SIGNATURE`.
    pub fn as_mut_ptr(&mut self) -> *mut EVP_SIGNATURE {
        self.ptr
    }
}

#[cfg(ossl_v350)]
impl Drop for EvpSignature {
    fn drop(&mut self) {
        unsafe {
            EVP_SIGNATURE_free(self.ptr);
        }
    }
}

/// Known algorithms selectable for OsslSignature
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum SigAlg {
    Ecdsa,
    EcdsaSha1,
    EcdsaSha2_224,
    EcdsaSha2_256,
    EcdsaSha2_384,
    EcdsaSha2_512,
    EcdsaSha3_224,
    EcdsaSha3_256,
    EcdsaSha3_384,
    EcdsaSha3_512,
    Ed25519,
    Ed25519ctx,
    Ed25519ph,
    Ed448,
    Ed448ph,
    Mldsa44,
    Mldsa65,
    Mldsa87,
    Rsa,
    RsaNoPad,
    RsaSha1,
    RsaSha2_224,
    RsaSha2_256,
    RsaSha2_384,
    RsaSha2_512,
    RsaSha3_224,
    RsaSha3_256,
    RsaSha3_384,
    RsaSha3_512,
    RsaPss,
    RsaPssSha1,
    RsaPssSha2_224,
    RsaPssSha2_256,
    RsaPssSha2_384,
    RsaPssSha2_512,
    RsaPssSha3_224,
    RsaPssSha3_256,
    RsaPssSha3_384,
    RsaPssSha3_512,
    /* SLH-DSA */
    SlhdsaSha2_128s,
    SlhdsaShake128s,
    SlhdsaSha2_128f,
    SlhdsaShake128f,
    SlhdsaSha2_192s,
    SlhdsaShake192s,
    SlhdsaSha2_192f,
    SlhdsaShake192f,
    SlhdsaSha2_256s,
    SlhdsaShake256s,
    SlhdsaSha2_256f,
    SlhdsaShake256f,
    #[cfg(feature = "rfc9580")]
    Dsa,
}

/// Helper that indicates if a signature algorithm should use oneshot apis
fn sigalg_is_oneshot(alg: SigAlg) -> bool {
    match alg {
        SigAlg::Ecdsa | SigAlg::Rsa | SigAlg::RsaPss | SigAlg::RsaNoPad => true,
        #[cfg(feature = "rfc9580")]
        SigAlg::Dsa => true,
        _ => false,
    }
}

/// Helper that indicates if a signature algorithm should use legacy apis
fn sigalg_uses_legacy_api(alg: SigAlg) -> bool {
    #[cfg(not(ossl_v350))]
    match alg {
        SigAlg::Ecdsa | SigAlg::Rsa | SigAlg::RsaPss | SigAlg::RsaNoPad => {
            false
        }
        SigAlg::Mldsa44 | SigAlg::Mldsa65 | SigAlg::Mldsa87 => false,
        SigAlg::SlhdsaSha2_128s
        | SigAlg::SlhdsaShake128s
        | SigAlg::SlhdsaSha2_128f
        | SigAlg::SlhdsaShake128f
        | SigAlg::SlhdsaSha2_192s
        | SigAlg::SlhdsaShake192s
        | SigAlg::SlhdsaSha2_192f
        | SigAlg::SlhdsaShake192f
        | SigAlg::SlhdsaSha2_256s
        | SigAlg::SlhdsaShake256s
        | SigAlg::SlhdsaSha2_256f
        | SigAlg::SlhdsaShake256f => false,
        _ => true,
    }
    #[cfg(ossl_v350)]
    match alg {
        SigAlg::RsaPssSha1
        | SigAlg::RsaPssSha2_224
        | SigAlg::RsaPssSha2_256
        | SigAlg::RsaPssSha2_384
        | SigAlg::RsaPssSha2_512
        | SigAlg::RsaPssSha3_224
        | SigAlg::RsaPssSha3_256
        | SigAlg::RsaPssSha3_384
        | SigAlg::RsaPssSha3_512 => true,
        _ => false,
    }
}

/// Helper that indicates if a signature algorithm supports updates
/// a value of None indicates autodetection should be performed
fn sigalg_supports_updates(alg: SigAlg) -> Option<bool> {
    match alg {
        SigAlg::Ecdsa
        | SigAlg::Ed25519
        | SigAlg::Ed25519ctx
        | SigAlg::Ed25519ph
        | SigAlg::Ed448
        | SigAlg::Ed448ph
        | SigAlg::Rsa
        | SigAlg::RsaPss
        | SigAlg::RsaNoPad => Some(false),
        #[cfg(feature = "rfc9580")]
        SigAlg::Dsa => Some(false),
        SigAlg::Mldsa44 | SigAlg::Mldsa65 | SigAlg::Mldsa87 => None,
        SigAlg::SlhdsaSha2_128s
        | SigAlg::SlhdsaShake128s
        | SigAlg::SlhdsaSha2_128f
        | SigAlg::SlhdsaShake128f
        | SigAlg::SlhdsaSha2_192s
        | SigAlg::SlhdsaShake192s
        | SigAlg::SlhdsaSha2_192f
        | SigAlg::SlhdsaShake192f
        | SigAlg::SlhdsaSha2_256s
        | SigAlg::SlhdsaShake256s
        | SigAlg::SlhdsaSha2_256f
        | SigAlg::SlhdsaShake256f => Some(false),
        _ => Some(true),
    }
}

static ECDSA_NAME: &CStr = c"ECDSA";
static ECDSASHA1_NAME: &CStr = c"ECDSA-SHA1";
static ECDSASHA2_224_NAME: &CStr = c"ECDSA-SHA2-224";
static ECDSASHA2_256_NAME: &CStr = c"ECDSA-SHA2-256";
static ECDSASHA2_384_NAME: &CStr = c"ECDSA-SHA2-384";
static ECDSASHA2_512_NAME: &CStr = c"ECDSA-SHA2-512";
static ECDSASHA3_224_NAME: &CStr = c"ECDSA-SHA3-224";
static ECDSASHA3_256_NAME: &CStr = c"ECDSA-SHA3-256";
static ECDSASHA3_384_NAME: &CStr = c"ECDSA-SHA3-384";
static ECDSASHA3_512_NAME: &CStr = c"ECDSA-SHA3-512";
static ED25519_NAME: &CStr = c"ED25519";
static ED25519CTX_NAME: &CStr = c"ED25519CTX";
static ED25519PH_NAME: &CStr = c"ED25519PH";
static ED448_NAME: &CStr = c"ED448";
static ED448PH_NAME: &CStr = c"ED448PH";
static MLDSA44_NAME: &CStr = c"ML-DSA-44";
static MLDSA65_NAME: &CStr = c"ML-DSA-65";
static MLDSA87_NAME: &CStr = c"ML-DSA-87";
static RSA_NAME: &CStr = c"RSA";
static RSASHA1_NAME: &CStr = c"RSA-SHA1";
static RSASHA2_224_NAME: &CStr = c"RSA-SHA2-224";
static RSASHA2_256_NAME: &CStr = c"RSA-SHA2-256";
static RSASHA2_384_NAME: &CStr = c"RSA-SHA2-384";
static RSASHA2_512_NAME: &CStr = c"RSA-SHA2-512";
static RSASHA3_224_NAME: &CStr = c"RSA-SHA3-224";
static RSASHA3_256_NAME: &CStr = c"RSA-SHA3-256";
static RSASHA3_384_NAME: &CStr = c"RSA-SHA3-384";
static RSASHA3_512_NAME: &CStr = c"RSA-SHA3-512";
static SLHDSASHA2_128F_NAME: &CStr = c"SLH-DSA-SHA2-128f";
static SLHDSASHA2_128S_NAME: &CStr = c"SLH-DSA-SHA2-128s";
static SLHDSASHA2_192F_NAME: &CStr = c"SLH-DSA-SHA2-192f";
static SLHDSASHA2_192S_NAME: &CStr = c"SLH-DSA-SHA2-192s";
static SLHDSASHA2_256F_NAME: &CStr = c"SLH-DSA-SHA2-256f";
static SLHDSASHA2_256S_NAME: &CStr = c"SLH-DSA-SHA2-256s";
static SLHDSASHAKE128F_NAME: &CStr = c"SLH-DSA-SHAKE-128f";
static SLHDSASHAKE128S_NAME: &CStr = c"SLH-DSA-SHAKE-128s";
static SLHDSASHAKE192F_NAME: &CStr = c"SLH-DSA-SHAKE-192f";
static SLHDSASHAKE192S_NAME: &CStr = c"SLH-DSA-SHAKE-192s";
static SLHDSASHAKE256F_NAME: &CStr = c"SLH-DSA-SHAKE-256f";
static SLHDSASHAKE256S_NAME: &CStr = c"SLH-DSA-SHAKE-256s";
#[cfg(feature = "rfc9580")]
static DSA_NAME: &CStr = c"DSA";
/* The following names are not actually recognized by
 * OpenSSL and will cause a fetch error if used, they
 * have been made up for completeness, and debugging */
static RSAPSS_NAME: &CStr = c"RSA-PSS";
static RSAPSSSHA1_NAME: &CStr = c"RSA-PSS-SHA1";
static RSAPSSSHA2_224_NAME: &CStr = c"RSA-PSS-SHA2-224";
static RSAPSSSHA2_256_NAME: &CStr = c"RSA-PSS-SHA2-256";
static RSAPSSSHA2_384_NAME: &CStr = c"RSA-PSS-SHA2-384";
static RSAPSSSHA2_512_NAME: &CStr = c"RSA-PSS-SHA2-512";
static RSAPSSSHA3_224_NAME: &CStr = c"RSA-PSS-SHA3-224";
static RSAPSSSHA3_256_NAME: &CStr = c"RSA-PSS-SHA3-256";
static RSAPSSSHA3_384_NAME: &CStr = c"RSA-PSS-SHA3-384";
static RSAPSSSHA3_512_NAME: &CStr = c"RSA-PSS-SHA3-512";
static RSANOPAD_NAME: &CStr = c"RSA-NO-PAD";

/// Helper to return OpenSSL sigalg name
fn sigalg_to_ossl_name(alg: SigAlg) -> &'static CStr {
    match alg {
        SigAlg::Ecdsa => ECDSA_NAME,
        SigAlg::EcdsaSha1 => ECDSASHA1_NAME,
        SigAlg::EcdsaSha2_224 => ECDSASHA2_224_NAME,
        SigAlg::EcdsaSha2_256 => ECDSASHA2_256_NAME,
        SigAlg::EcdsaSha2_384 => ECDSASHA2_384_NAME,
        SigAlg::EcdsaSha2_512 => ECDSASHA2_512_NAME,
        SigAlg::EcdsaSha3_224 => ECDSASHA3_224_NAME,
        SigAlg::EcdsaSha3_256 => ECDSASHA3_256_NAME,
        SigAlg::EcdsaSha3_384 => ECDSASHA3_384_NAME,
        SigAlg::EcdsaSha3_512 => ECDSASHA3_512_NAME,
        SigAlg::Ed25519 => ED25519_NAME,
        SigAlg::Ed25519ctx => ED25519CTX_NAME,
        SigAlg::Ed25519ph => ED25519PH_NAME,
        SigAlg::Ed448 => ED448_NAME,
        SigAlg::Ed448ph => ED448PH_NAME,
        SigAlg::Mldsa44 => MLDSA44_NAME,
        SigAlg::Mldsa65 => MLDSA65_NAME,
        SigAlg::Mldsa87 => MLDSA87_NAME,
        SigAlg::Rsa => RSA_NAME,
        SigAlg::RsaSha1 => RSASHA1_NAME,
        SigAlg::RsaSha2_224 => RSASHA2_224_NAME,
        SigAlg::RsaSha2_256 => RSASHA2_256_NAME,
        SigAlg::RsaSha2_384 => RSASHA2_384_NAME,
        SigAlg::RsaSha2_512 => RSASHA2_512_NAME,
        SigAlg::RsaSha3_224 => RSASHA3_224_NAME,
        SigAlg::RsaSha3_256 => RSASHA3_256_NAME,
        SigAlg::RsaSha3_384 => RSASHA3_384_NAME,
        SigAlg::RsaSha3_512 => RSASHA3_512_NAME,
        SigAlg::RsaPss => RSAPSS_NAME,
        SigAlg::RsaPssSha1 => RSAPSSSHA1_NAME,
        SigAlg::RsaPssSha2_224 => RSAPSSSHA2_224_NAME,
        SigAlg::RsaPssSha2_256 => RSAPSSSHA2_256_NAME,
        SigAlg::RsaPssSha2_384 => RSAPSSSHA2_384_NAME,
        SigAlg::RsaPssSha2_512 => RSAPSSSHA2_512_NAME,
        SigAlg::RsaPssSha3_224 => RSAPSSSHA3_224_NAME,
        SigAlg::RsaPssSha3_256 => RSAPSSSHA3_256_NAME,
        SigAlg::RsaPssSha3_384 => RSAPSSSHA3_384_NAME,
        SigAlg::RsaPssSha3_512 => RSAPSSSHA3_512_NAME,
        SigAlg::RsaNoPad => RSANOPAD_NAME,
        SigAlg::SlhdsaSha2_128f => SLHDSASHA2_128F_NAME,
        SigAlg::SlhdsaSha2_128s => SLHDSASHA2_128S_NAME,
        SigAlg::SlhdsaSha2_192f => SLHDSASHA2_192F_NAME,
        SigAlg::SlhdsaSha2_192s => SLHDSASHA2_192S_NAME,
        SigAlg::SlhdsaSha2_256f => SLHDSASHA2_256F_NAME,
        SigAlg::SlhdsaSha2_256s => SLHDSASHA2_256S_NAME,
        SigAlg::SlhdsaShake128f => SLHDSASHAKE128F_NAME,
        SigAlg::SlhdsaShake128s => SLHDSASHAKE128S_NAME,
        SigAlg::SlhdsaShake192f => SLHDSASHAKE192F_NAME,
        SigAlg::SlhdsaShake192s => SLHDSASHAKE192S_NAME,
        SigAlg::SlhdsaShake256f => SLHDSASHAKE256F_NAME,
        SigAlg::SlhdsaShake256s => SLHDSASHAKE256S_NAME,
        #[cfg(feature = "rfc9580")]
        SigAlg::Dsa => DSA_NAME,
    }
}

/// Helper that returns the OpenSSL digest name associated to a sigalg
///
/// note, that this is relevant only for the mechanism using legacy API
fn sigalg_to_digest_ptr(alg: SigAlg) -> *const c_char {
    match alg {
        SigAlg::EcdsaSha1 | SigAlg::RsaSha1 | SigAlg::RsaPssSha1 => {
            cstr!(OSSL_DIGEST_NAME_SHA1).as_ptr()
        }
        SigAlg::EcdsaSha2_224
        | SigAlg::RsaSha2_224
        | SigAlg::RsaPssSha2_224 => cstr!(OSSL_DIGEST_NAME_SHA2_224).as_ptr(),
        SigAlg::EcdsaSha2_256
        | SigAlg::RsaSha2_256
        | SigAlg::RsaPssSha2_256 => cstr!(OSSL_DIGEST_NAME_SHA2_256).as_ptr(),
        SigAlg::EcdsaSha2_384
        | SigAlg::RsaSha2_384
        | SigAlg::RsaPssSha2_384 => cstr!(OSSL_DIGEST_NAME_SHA2_384).as_ptr(),
        SigAlg::EcdsaSha2_512
        | SigAlg::RsaSha2_512
        | SigAlg::RsaPssSha2_512 => cstr!(OSSL_DIGEST_NAME_SHA2_512).as_ptr(),
        SigAlg::EcdsaSha3_224
        | SigAlg::RsaSha3_224
        | SigAlg::RsaPssSha3_224 => cstr!(OSSL_DIGEST_NAME_SHA3_224).as_ptr(),
        SigAlg::EcdsaSha3_256
        | SigAlg::RsaSha3_256
        | SigAlg::RsaPssSha3_256 => cstr!(OSSL_DIGEST_NAME_SHA3_256).as_ptr(),
        SigAlg::EcdsaSha3_384
        | SigAlg::RsaSha3_384
        | SigAlg::RsaPssSha3_384 => cstr!(OSSL_DIGEST_NAME_SHA3_384).as_ptr(),
        SigAlg::EcdsaSha3_512
        | SigAlg::RsaSha3_512
        | SigAlg::RsaPssSha3_512 => cstr!(OSSL_DIGEST_NAME_SHA3_512).as_ptr(),
        SigAlg::Mldsa44
        | SigAlg::Mldsa65
        | SigAlg::Mldsa87
        | SigAlg::Ecdsa
        | SigAlg::Ed25519
        | SigAlg::Ed25519ctx
        | SigAlg::Ed25519ph
        | SigAlg::Ed448
        | SigAlg::Ed448ph
        | SigAlg::Rsa
        | SigAlg::RsaPss
        | SigAlg::RsaNoPad
        | SigAlg::SlhdsaSha2_128f
        | SigAlg::SlhdsaSha2_128s
        | SigAlg::SlhdsaSha2_192f
        | SigAlg::SlhdsaSha2_192s
        | SigAlg::SlhdsaSha2_256f
        | SigAlg::SlhdsaSha2_256s
        | SigAlg::SlhdsaShake128f
        | SigAlg::SlhdsaShake128s
        | SigAlg::SlhdsaShake192f
        | SigAlg::SlhdsaShake192s
        | SigAlg::SlhdsaShake256f
        | SigAlg::SlhdsaShake256s => std::ptr::null(),
        #[cfg(feature = "rfc9580")]
        SigAlg::Dsa => std::ptr::null(),
    }
}

/// Pss Parameters container
pub struct RsaPssParams {
    pub digest: DigestAlg,
    pub mgf1: DigestAlg,
    pub saltlen: usize,
}

/// Helper to generate OsslParam arrays for initialization
pub fn rsa_sig_params(
    alg: SigAlg,
    pss_params: &Option<RsaPssParams>,
) -> Result<Option<OsslParam<'_>>, Error> {
    match alg {
        SigAlg::RsaNoPad => {
            let mut params_builder = OsslParamBuilder::new();
            params_builder.add_const_c_string(
                cstr!(OSSL_SIGNATURE_PARAM_PAD_MODE),
                cstr!(OSSL_PKEY_RSA_PAD_MODE_NONE),
            )?;
            let params = params_builder.finalize();
            return Ok(Some(params));
        }
        SigAlg::Rsa
        | SigAlg::RsaSha1
        | SigAlg::RsaSha2_224
        | SigAlg::RsaSha2_256
        | SigAlg::RsaSha2_384
        | SigAlg::RsaSha2_512
        | SigAlg::RsaSha3_224
        | SigAlg::RsaSha3_256
        | SigAlg::RsaSha3_384
        | SigAlg::RsaSha3_512 => {
            /* In 3.5.0 there is direct sigalg support for
             * PCKCS1 padding for digest algorithms so no
             * paramters are needed or processed */
            #[cfg(ossl_v350)]
            if alg != SigAlg::Rsa {
                return Ok(None);
            }

            let mut params_builder = OsslParamBuilder::new();
            params_builder.add_const_c_string(
                cstr!(OSSL_SIGNATURE_PARAM_PAD_MODE),
                cstr!(OSSL_PKEY_RSA_PAD_MODE_PKCSV15),
            )?;
            let params = params_builder.finalize();
            return Ok(Some(params));
        }
        SigAlg::RsaPss
        | SigAlg::RsaPssSha1
        | SigAlg::RsaPssSha2_224
        | SigAlg::RsaPssSha2_256
        | SigAlg::RsaPssSha2_384
        | SigAlg::RsaPssSha2_512
        | SigAlg::RsaPssSha3_224
        | SigAlg::RsaPssSha3_256
        | SigAlg::RsaPssSha3_384
        | SigAlg::RsaPssSha3_512 => {
            /* Pss always uses legacy interfaces, so we need
             * all params set up */
            if let Some(pss) = pss_params {
                let mut params_builder = OsslParamBuilder::new();

                params_builder.add_const_c_string(
                    cstr!(OSSL_SIGNATURE_PARAM_PAD_MODE),
                    cstr!(OSSL_PKEY_RSA_PAD_MODE_PSS),
                )?;
                params_builder.add_const_c_string(
                    cstr!(OSSL_SIGNATURE_PARAM_DIGEST),
                    digest_to_string(pss.digest),
                )?;
                params_builder.add_const_c_string(
                    cstr!(OSSL_SIGNATURE_PARAM_MGF1_DIGEST),
                    digest_to_string(pss.mgf1),
                )?;
                params_builder.add_owned_int(
                    cstr!(OSSL_SIGNATURE_PARAM_PSS_SALTLEN),
                    c_int::try_from(pss.saltlen)?,
                )?;
                let params = params_builder.finalize();
                return Ok(Some(params));
            } else {
                return Err(Error::new(ErrorKind::NullPtr));
            }
        }
        _ => Err(Error::new(ErrorKind::WrapperError)),
    }
}

/// Helper to generate OsslParam arrays for Eddsa initialization
#[cfg(ossl_v320)]
pub fn eddsa_params(
    alg: SigAlg,
    context: Option<Vec<u8>>,
) -> Result<Option<OsslParam<'static>>, Error> {
    match alg {
        SigAlg::Ed25519
        | SigAlg::Ed25519ph
        | SigAlg::Ed448
        | SigAlg::Ed448ph
        | SigAlg::Ed25519ctx => (),
        _ => return Err(Error::new(ErrorKind::WrapperError)),
    }

    /* With 3.5.0 we use the sigalg interface so no need
     * for params */
    #[cfg(ossl_v350)]
    if context.is_none() {
        return Ok(None);
    }

    let mut params_builder = OsslParamBuilder::new();

    #[cfg(not(ossl_v350))]
    params_builder.add_const_c_string(
        cstr!(OSSL_SIGNATURE_PARAM_INSTANCE),
        sigalg_to_ossl_name(alg),
    )?;

    if let Some(v) = context {
        params_builder.add_owned_octet_string(
            cstr!(OSSL_SIGNATURE_PARAM_CONTEXT_STRING),
            v,
        )?;
    }

    let params = params_builder.finalize();
    return Ok(Some(params));
}

/// Helper to generate OsslParam arrays for Mldsa initialization
#[cfg(ossl_v350)]
pub fn mldsa_params<'a>(
    raw: bool,
    context: Option<&'a Vec<u8>>,
    deterministic: bool,
) -> Result<Option<OsslParam<'a>>, Error> {
    let mut params_builder = OsslParamBuilder::with_capacity(3);
    if raw {
        params_builder
            .add_owned_int(cstr!(OSSL_SIGNATURE_PARAM_MESSAGE_ENCODING), 0)?;
    }
    if let Some(ctx) = context {
        params_builder.add_octet_string(
            cstr!(OSSL_SIGNATURE_PARAM_CONTEXT_STRING),
            ctx,
        )?;
    }
    if deterministic {
        params_builder
            .add_owned_int(cstr!(OSSL_SIGNATURE_PARAM_DETERMINISTIC), 1)?;
    }
    let params = params_builder.finalize();
    return Ok(Some(params));
}

/// Helper to generate OsslParam arrays for SLH-DSA initialization
/// FIXME: The same as mldsa_params?
#[cfg(ossl_v350)]
pub fn slhdsa_params<'a>(
    raw: bool,
    context: Option<&'a Vec<u8>>,
    deterministic: bool,
) -> Result<Option<OsslParam<'a>>, Error> {
    let mut params_builder = OsslParamBuilder::with_capacity(3);
    if raw {
        params_builder
            .add_owned_int(cstr!(OSSL_SIGNATURE_PARAM_MESSAGE_ENCODING), 0)?;
    }
    if let Some(ctx) = context {
        params_builder.add_octet_string(
            cstr!(OSSL_SIGNATURE_PARAM_CONTEXT_STRING),
            ctx,
        )?;
    }
    if deterministic {
        params_builder
            .add_owned_int(cstr!(OSSL_SIGNATURE_PARAM_DETERMINISTIC), 1)?;
    }
    let params = params_builder.finalize();
    return Ok(Some(params));
}

/// Maximum buffer size for accumulating data when emulating multi-part
/// operations for OpenSSL versions that only support one-shot operations.
const MAX_BUFFER_LEN: usize = 1024 * 1024;

/// Operation type for OsslSignature
#[derive(Debug, PartialEq)]
pub enum SigOp {
    Sign,
    Verify,
}

/// Higher level wrapper for signature operations with OpenSSL
#[derive(Debug)]
pub struct OsslSignature {
    /// The underlying OpenSSL EVP PKEY context.
    pkey_ctx: EvpPkeyCtx,
    /// The requested operation type
    op: SigOp,
    /// The MD Ctx for cases when the old EVP_Digest interfaces need to be used
    #[cfg(not(feature = "fips"))]
    legacy_ctx: Option<EvpMdCtx>,
    #[cfg(feature = "fips")]
    legacy_ctx: Option<ProviderSignatureCtx>,
    /// Flag indicating if the current OpenSSL version supports multi-part
    /// updates.
    supports_updates: bool,
    /// Buffer to accumulate data for multi-part emulation if needed.
    data: Option<Vec<u8>>,
    /// Stored signature for VerifySignature operations if updates aren't
    /// supported by the OpenSSL provider.
    signature: Option<Vec<u8>>,
}

impl OsslSignature {
    /// Creates a new message sign/verify context.
    pub fn new(
        libctx: &OsslContext,
        op: SigOp,
        alg: SigAlg,
        key: &mut EvpPkey,
        params: Option<&OsslParam>,
    ) -> Result<OsslSignature, Error> {
        let mut ctx = OsslSignature {
            pkey_ctx: key.new_ctx(libctx)?,
            op: op,
            legacy_ctx: None,
            supports_updates: false,
            data: None,
            signature: None,
        };

        if sigalg_is_oneshot(alg) {
            /* Single shot algorithms must always use EVP_PKEY_..._init */
            let ret = unsafe {
                match ctx.op {
                    SigOp::Sign => {
                        EVP_PKEY_sign_init(ctx.pkey_ctx.as_mut_ptr())
                    }
                    SigOp::Verify => {
                        EVP_PKEY_verify_init(ctx.pkey_ctx.as_mut_ptr())
                    }
                }
            };
            if ret != 1 {
                match ctx.op {
                    SigOp::Sign => {
                        trace_ossl!("EVP_PKEY_sign_init()");
                    }
                    SigOp::Verify => {
                        trace_ossl!("EVP_PKEY_verify_init()");
                    }
                }
                return Err(Error::new(ErrorKind::OsslError));
            }
            if let Some(p) = params {
                let ret = unsafe {
                    EVP_PKEY_CTX_set_params(
                        ctx.pkey_ctx.as_mut_ptr(),
                        p.as_ptr(),
                    )
                };
                if ret != 1 {
                    trace_ossl!("EVP_PKEY_CTX_set_params()");
                    return Err(Error::new(ErrorKind::OsslError));
                }
            }
            return Ok(ctx);
        }

        if sigalg_uses_legacy_api(alg) {
            let params_ptr = match params {
                Some(p) => p.as_ptr(),
                None => std::ptr::null(),
            };
            let digest_ptr = sigalg_to_digest_ptr(alg);
            #[cfg(not(feature = "fips"))]
            {
                let mut lctx = EvpMdCtx::new()?;
                let ret = unsafe {
                    match ctx.op {
                        SigOp::Sign => EVP_DigestSignInit_ex(
                            lctx.as_mut_ptr(),
                            std::ptr::null_mut(),
                            digest_ptr,
                            libctx.ptr(),
                            std::ptr::null(),
                            key.as_mut_ptr(),
                            params_ptr,
                        ),
                        SigOp::Verify => EVP_DigestVerifyInit_ex(
                            lctx.as_mut_ptr(),
                            std::ptr::null_mut(),
                            digest_ptr,
                            libctx.ptr(),
                            std::ptr::null(),
                            key.as_mut_ptr(),
                            params_ptr,
                        ),
                    }
                };
                if ret != 1 {
                    match ctx.op {
                        SigOp::Sign => {
                            trace_ossl!("EVP_DigestSignInit_ex()");
                        }
                        SigOp::Verify => {
                            trace_ossl!("EVP_DigestVerifyInit_ex()");
                        }
                    }
                    return Err(Error::new(ErrorKind::OsslError));
                }
                ctx.legacy_ctx = Some(lctx);
            }
            #[cfg(feature = "fips")]
            {
                let mut lctx = ProviderSignatureCtx::new(alg)?;
                match ctx.op {
                    SigOp::Sign => {
                        lctx.digest_sign_init(digest_ptr, key, params_ptr)?
                    }
                    SigOp::Verify => {
                        lctx.digest_verify_init(digest_ptr, key, params_ptr)?
                    }
                }
                ctx.legacy_ctx = Some(lctx);
            }
            ctx.supports_updates = match sigalg_supports_updates(alg) {
                Some(b) => b,
                None => false,
            };
            return Ok(ctx);
        }

        #[cfg(ossl_v350)]
        {
            let mut sig = EvpSignature::new(libctx, sigalg_to_ossl_name(alg))?;
            let params_ptr = match params {
                Some(p) => p.as_ptr(),
                None => std::ptr::null(),
            };
            let ret = unsafe {
                match ctx.op {
                    SigOp::Sign => EVP_PKEY_sign_message_init(
                        ctx.pkey_ctx.as_mut_ptr(),
                        sig.as_mut_ptr(),
                        params_ptr,
                    ),
                    SigOp::Verify => EVP_PKEY_verify_message_init(
                        ctx.pkey_ctx.as_mut_ptr(),
                        sig.as_mut_ptr(),
                        params_ptr,
                    ),
                }
            };
            if ret != 1 {
                match ctx.op {
                    SigOp::Sign => {
                        trace_ossl!("EVP_PKEY_sign_message_init()");
                    }
                    SigOp::Verify => {
                        trace_ossl!("EVP_PKEY_verify_message_init()");
                    }
                }
                return Err(Error::new(ErrorKind::OsslError));
            }
            ctx.supports_updates = match sigalg_supports_updates(alg) {
                Some(true) => true,
                Some(false) => false,
                None => {
                    /* OpenSSL 3.5 implements only one shot ML-DSA,
                     * while later implementations can deal with
                     * update()/final() operations. Probe here, and
                     * set up a backup buffer if update()s are not
                     * supported.
                     */
                    let ret = unsafe {
                        match ctx.op {
                            SigOp::Sign => EVP_PKEY_sign_message_update(
                                ctx.pkey_ctx.as_mut_ptr(),
                                std::ptr::null(),
                                0,
                            ),
                            SigOp::Verify => EVP_PKEY_verify_message_update(
                                ctx.pkey_ctx.as_mut_ptr(),
                                std::ptr::null(),
                                0,
                            ),
                        }
                    };
                    if ret == 1 {
                        true
                    } else {
                        trace_ossl!("update() not supported, fallback enabled");
                        false
                    }
                }
            };
            return Ok(ctx);
        }

        #[cfg(not(ossl_v350))]
        Err(Error::new(ErrorKind::WrapperError))
    }

    /// Accumulates data when native update is not available
    fn store_data(&mut self, data: &[u8]) -> Result<(), Error> {
        match &mut self.data {
            Some(buffer) => {
                if buffer.len() + data.len() > MAX_BUFFER_LEN {
                    return Err(Error::new(ErrorKind::BufferSize));
                }
                buffer.extend_from_slice(data);
            }
            None => {
                if data.len() > MAX_BUFFER_LEN {
                    return Err(Error::new(ErrorKind::BufferSize));
                }
                self.data = Some(data.to_vec());
            }
        }

        Ok(())
    }

    /// One shot signature, takes data and a buffer where to store
    /// the signature. The signature buffer must have enough space
    /// to receive the signature. On success the siganture length is
    /// returned.
    pub fn sign(
        &mut self,
        data: &[u8],
        signature: Option<&mut [u8]>,
    ) -> Result<usize, Error> {
        if self.op != SigOp::Sign {
            return Err(Error::new(ErrorKind::WrapperError));
        }
        let mut siglen = match &signature {
            Some(sig) => sig.len(),
            None => 0,
        };
        let siglen_ptr: *mut usize = &mut siglen;

        /* check siglen buffer is large enough */
        if let Some(ctx) = &mut self.legacy_ctx {
            #[cfg(not(feature = "fips"))]
            {
                let ret = unsafe {
                    EVP_DigestSign(
                        ctx.as_mut_ptr(),
                        std::ptr::null_mut(),
                        siglen_ptr,
                        data.as_ptr(),
                        data.len(),
                    )
                };
                if ret != 1 {
                    trace_ossl!("EVP_DigestSign()");
                    return Err(Error::new(ErrorKind::OsslError));
                }
            }
            #[cfg(feature = "fips")]
            {
                siglen = ctx.digest_sign(None, data)?;
            }
        } else {
            let ret = unsafe {
                EVP_PKEY_sign(
                    self.pkey_ctx.as_mut_ptr(),
                    std::ptr::null_mut(),
                    siglen_ptr,
                    data.as_ptr(),
                    data.len(),
                )
            };
            if ret != 1 {
                trace_ossl!("EVP_PKEY_sign()");
                return Err(Error::new(ErrorKind::OsslError));
            }
        }

        if let Some(sig) = signature {
            if siglen > sig.len() {
                return Err(Error::new(ErrorKind::BufferSize));
            }

            if let Some(ctx) = &mut self.legacy_ctx {
                #[cfg(not(feature = "fips"))]
                {
                    let ret = unsafe {
                        EVP_DigestSign(
                            ctx.as_mut_ptr(),
                            sig.as_mut_ptr(),
                            siglen_ptr,
                            data.as_ptr(),
                            data.len(),
                        )
                    };
                    if ret != 1 {
                        trace_ossl!("EVP_DigestSign()");
                        return Err(Error::new(ErrorKind::OsslError));
                    }
                }
                #[cfg(feature = "fips")]
                {
                    siglen = ctx.digest_sign(Some(sig), data)?;
                }
            } else {
                let ret = unsafe {
                    EVP_PKEY_sign(
                        self.pkey_ctx.as_mut_ptr(),
                        sig.as_mut_ptr(),
                        siglen_ptr,
                        data.as_ptr(),
                        data.len(),
                    )
                };
                if ret != 1 {
                    trace_ossl!("EVP_PKEY_sign()");
                    return Err(Error::new(ErrorKind::OsslError));
                }
            }
        }

        Ok(siglen)
    }

    /// One shot verification function
    pub fn verify(
        &mut self,
        data: &[u8],
        signature: Option<&[u8]>,
    ) -> Result<(), Error> {
        if self.op != SigOp::Verify {
            return Err(Error::new(ErrorKind::WrapperError));
        }
        let sig = match &signature {
            Some(s) => s,
            None => match &self.signature {
                Some(v) => v.as_slice(),
                None => return Err(Error::new(ErrorKind::WrapperError)),
            },
        };
        if let Some(ctx) = &mut self.legacy_ctx {
            #[cfg(not(feature = "fips"))]
            {
                let ret = unsafe {
                    EVP_DigestVerify(
                        ctx.as_mut_ptr(),
                        sig.as_ptr(),
                        sig.len(),
                        data.as_ptr(),
                        data.len(),
                    )
                };
                if ret != 1 {
                    trace_ossl!("EVP_DigestVerify()");
                    return Err(Error::new(ErrorKind::OsslError));
                }
            }
            #[cfg(feature = "fips")]
            {
                ctx.digest_verify(sig, data)?;
            }
        } else {
            let ret = unsafe {
                EVP_PKEY_verify(
                    self.pkey_ctx.as_mut_ptr(),
                    sig.as_ptr(),
                    sig.len(),
                    data.as_ptr(),
                    data.len(),
                )
            };
            if ret != 1 {
                trace_ossl!("EVP_PKEY_verify()");
                return Err(Error::new(ErrorKind::OsslError));
            }
        }
        Ok(())
    }

    /// Feeds data to the message sign provider
    pub fn update(&mut self, data: &[u8]) -> Result<(), Error> {
        if !self.supports_updates {
            return self.store_data(data);
        }

        if let Some(ctx) = &mut self.legacy_ctx {
            #[cfg(not(feature = "fips"))]
            {
                let ret = match self.op {
                    SigOp::Sign => unsafe {
                        EVP_DigestSignUpdate(
                            ctx.as_mut_ptr(),
                            data.as_ptr() as *const std::ffi::c_void,
                            data.len(),
                        )
                    },
                    SigOp::Verify => unsafe {
                        EVP_DigestVerifyUpdate(
                            ctx.as_mut_ptr(),
                            data.as_ptr() as *const std::ffi::c_void,
                            data.len(),
                        )
                    },
                };
                if ret != 1 {
                    match self.op {
                        SigOp::Sign => {
                            trace_ossl!("EVP_DigestSignUpdate()");
                        }
                        SigOp::Verify => {
                            trace_ossl!("EVP_DigestVerifyUpdate()");
                        }
                    }
                    return Err(Error::new(ErrorKind::OsslError));
                }
            }
            #[cfg(feature = "fips")]
            match self.op {
                SigOp::Sign => ctx.digest_sign_update(data)?,
                SigOp::Verify => ctx.digest_verify_update(data)?,
            }

            return Ok(());
        }

        #[cfg(ossl_v350)]
        {
            let ret = match self.op {
                SigOp::Sign => unsafe {
                    EVP_PKEY_sign_message_update(
                        self.pkey_ctx.as_mut_ptr(),
                        data.as_ptr(),
                        data.len(),
                    )
                },
                SigOp::Verify => unsafe {
                    EVP_PKEY_verify_message_update(
                        self.pkey_ctx.as_mut_ptr(),
                        data.as_ptr(),
                        data.len(),
                    )
                },
            };
            if ret != 1 {
                match self.op {
                    SigOp::Sign => {
                        trace_ossl!("EVP_PKEY_sign_mesage_update()");
                    }
                    SigOp::Verify => {
                        trace_ossl!("EVP_PKEY_verify_message_update()");
                    }
                }
                return Err(Error::new(ErrorKind::OsslError));
            }

            return Ok(());
        }

        #[cfg(not(ossl_v350))]
        Err(Error::new(ErrorKind::WrapperError))
    }

    /// Finalizes data and generates signature
    pub fn sign_final(&mut self, signature: &mut [u8]) -> Result<usize, Error> {
        if self.op != SigOp::Sign {
            return Err(Error::new(ErrorKind::WrapperError));
        }
        if !self.supports_updates {
            if let Some(buffer) = self.data.take() {
                return self.sign(buffer.as_slice(), Some(signature));
            }

            return Err(Error::new(ErrorKind::WrapperError));
        }

        if let Some(ctx) = &mut self.legacy_ctx {
            #[cfg(not(feature = "fips"))]
            {
                let mut siglen = signature.len();
                let siglen_ptr: *mut usize = &mut siglen;

                let ret = unsafe {
                    EVP_DigestSignFinal(
                        ctx.as_mut_ptr(),
                        signature.as_mut_ptr(),
                        siglen_ptr,
                    )
                };
                if ret != 1 {
                    trace_ossl!("EVP_DigestSignFinal()");
                    return Err(Error::new(ErrorKind::OsslError));
                }
                return Ok(siglen);
            }
            #[cfg(feature = "fips")]
            return ctx.digest_sign_final(signature);
        }

        #[cfg(ossl_v350)]
        {
            let mut siglen = signature.len();
            let siglen_ptr: *mut usize = &mut siglen;

            let ret = unsafe {
                EVP_PKEY_sign_message_final(
                    self.pkey_ctx.as_mut_ptr(),
                    signature.as_mut_ptr(),
                    siglen_ptr,
                )
            };
            if ret != 1 {
                trace_ossl!("EVP_PKEY_sign_mesage_final()");
                return Err(Error::new(ErrorKind::OsslError));
            }

            return Ok(siglen);
        }

        #[cfg(not(ossl_v350))]
        Err(Error::new(ErrorKind::WrapperError))
    }

    /// Sets the signature for a VerifySignature operation.
    /// If the OpenSSL backend supports setting it early (via
    /// `EVP_PKEY_CTX_set_signature`), it does so; otherwise, it stores the
    /// signature internally for later use.
    pub fn set_signature(&mut self, signature: &[u8]) -> Result<(), Error> {
        if self.op != SigOp::Verify {
            return Err(Error::new(ErrorKind::WrapperError));
        }
        if self.legacy_ctx.is_some() || !self.supports_updates {
            self.signature = Some(signature.to_vec());
            return Ok(());
        }

        #[cfg(ossl_v350)]
        {
            let ret = unsafe {
                EVP_PKEY_CTX_set_signature(
                    self.pkey_ctx.as_mut_ptr(),
                    signature.as_ptr(),
                    signature.len(),
                )
            };
            if ret != 1 {
                trace_ossl!("EVP_PKEY_CTX_set_signature()");
                return Err(Error::new(ErrorKind::OsslError));
            }

            Ok(())
        }
        #[cfg(not(ossl_v350))]
        {
            trace_ossl!("unsupported");
            return Err(Error::new(ErrorKind::WrapperError));
        }
    }

    /// Finalizes data and verifies signature
    pub fn verify_final(
        &mut self,
        signature: Option<&[u8]>,
    ) -> Result<(), Error> {
        if self.op != SigOp::Verify {
            return Err(Error::new(ErrorKind::WrapperError));
        }
        if !self.supports_updates {
            if let Some(buffer) = self.data.take() {
                return self.verify(buffer.as_slice(), signature);
            }

            return Err(Error::new(ErrorKind::WrapperError));
        }

        if let Some(ctx) = &mut self.legacy_ctx {
            let sig = match &signature {
                Some(s) => s,
                None => match &self.signature {
                    Some(v) => v.as_slice(),
                    None => return Err(Error::new(ErrorKind::NullPtr)),
                },
            };
            #[cfg(not(feature = "fips"))]
            {
                let ret = unsafe {
                    EVP_DigestVerifyFinal(
                        ctx.as_mut_ptr(),
                        sig.as_ptr(),
                        sig.len(),
                    )
                };
                if ret != 1 {
                    trace_ossl!("EVP_DigestVerifyFinal()");
                    return Err(Error::new(ErrorKind::OsslError));
                } else {
                    return Ok(());
                }
            }
            #[cfg(feature = "fips")]
            return ctx.digest_verify_final(sig);
        }

        #[cfg(ossl_v350)]
        {
            match signature {
                Some(sig) => {
                    self.set_signature(sig)?;
                }
                None => (),
            }

            let ret = unsafe {
                EVP_PKEY_verify_message_final(self.pkey_ctx.as_mut_ptr())
            };
            if ret != 1 {
                trace_ossl!("EVP_PKEY_verify_message_final()");
                return Err(Error::new(ErrorKind::OsslError));
            }

            return Ok(());
        }

        #[cfg(not(ossl_v350))]
        Err(Error::new(ErrorKind::WrapperError))
    }
}
