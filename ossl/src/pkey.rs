// Copyright 2025 Simo Sorce
// See LICENSE.txt file for terms

//! This module provides a coherent abstraction for OpenSSL asymmetric Key
//! management. It handles import/export and key generation

use std::ffi::{c_int, c_uint, c_void, CStr};

use crate::bindings::*;
use crate::{
    cstr, trace_ossl, Error, ErrorKind, OsslContext, OsslParam,
    OsslParamBuilder, OsslSecret,
};

/// Wrapper around OpenSSL's `EVP_PKEY_CTX`, managing its lifecycle.
/// Used for various public key algorithm operations (key generation, signing,
/// encryption context setup, etc.).
#[derive(Debug)]
pub struct EvpPkeyCtx {
    ptr: *mut EVP_PKEY_CTX,
}

/// Methods for creating and accessing `EvpPkeyCtx`.
impl EvpPkeyCtx {
    /// Fetches an algorithm by name and returns a wrapper `EvpPkeyCtx`
    pub fn new(ctx: &OsslContext, name: &CStr) -> Result<EvpPkeyCtx, Error> {
        let ptr = unsafe {
            EVP_PKEY_CTX_new_from_name(
                ctx.ptr(),
                name.as_ptr(),
                std::ptr::null(),
            )
        };
        if ptr.is_null() {
            trace_ossl!("EVP_PKEY_CTX_new_from_name()");
            return Err(Error::new(ErrorKind::NullPtr));
        }
        Ok(EvpPkeyCtx { ptr: ptr })
    }

    /// Creates an `EvpPkeyCtx` from an existing raw pointer (takes ownership).
    pub unsafe fn from_ptr(
        ptr: *mut EVP_PKEY_CTX,
    ) -> Result<EvpPkeyCtx, Error> {
        if ptr.is_null() {
            return Err(Error::new(ErrorKind::NullPtr));
        }
        Ok(EvpPkeyCtx { ptr: ptr })
    }

    /// Returns a const pointer to the underlying `EVP_PKEY_CTX`.
    #[allow(dead_code)]
    pub fn as_ptr(&self) -> *const EVP_PKEY_CTX {
        self.ptr
    }

    /// Returns a mutable pointer to the underlying `EVP_PKEY_CTX`.
    pub fn as_mut_ptr(&mut self) -> *mut EVP_PKEY_CTX {
        self.ptr
    }
}

impl Drop for EvpPkeyCtx {
    fn drop(&mut self) {
        unsafe {
            EVP_PKEY_CTX_free(self.ptr);
        }
    }
}

unsafe impl Send for EvpPkeyCtx {}
unsafe impl Sync for EvpPkeyCtx {}

#[derive(Clone, Debug)]
pub enum EvpPkeyType {
    /* DH */
    Ffdhe2048,
    Ffdhe3072,
    Ffdhe4096,
    Ffdhe6144,
    Ffdhe8192,
    Modp2048,
    Modp3072,
    Modp4096,
    Modp6144,
    Modp8192,
    /* Ecc */
    P256,
    P384,
    P521,
    Ed25519,
    Ed448,
    X25519,
    X448,
    BrainpoolP256r1,
    BrainpoolP384r1,
    BrainpoolP512r1,
    /* ML */
    Mldsa44,
    Mldsa65,
    Mldsa87,
    MlKem512,
    MlKem768,
    MlKem1024,
    /* RSA */
    Rsa(usize, Vec<u8>),
}

/// Adds group name to params if needed, and returns the ossl key type name
fn pkey_type_to_params(
    pt: &EvpPkeyType,
    params: &mut OsslParamBuilder,
) -> Result<&'static CStr, Error> {
    let name = match pt {
        EvpPkeyType::Ffdhe2048 => {
            params.add_const_c_string(
                cstr!(OSSL_PKEY_PARAM_GROUP_NAME),
                c"ffdhe2048",
            )?;
            c"DH"
        }
        EvpPkeyType::Ffdhe3072 => {
            params.add_const_c_string(
                cstr!(OSSL_PKEY_PARAM_GROUP_NAME),
                c"ffdhe3072",
            )?;
            c"DH"
        }
        EvpPkeyType::Ffdhe4096 => {
            params.add_const_c_string(
                cstr!(OSSL_PKEY_PARAM_GROUP_NAME),
                c"ffdhe4096",
            )?;
            c"DH"
        }
        EvpPkeyType::Ffdhe6144 => {
            params.add_const_c_string(
                cstr!(OSSL_PKEY_PARAM_GROUP_NAME),
                c"ffdhe6144",
            )?;
            c"DH"
        }
        EvpPkeyType::Ffdhe8192 => {
            params.add_const_c_string(
                cstr!(OSSL_PKEY_PARAM_GROUP_NAME),
                c"ffdhe8192",
            )?;
            c"DH"
        }
        EvpPkeyType::Modp2048 => {
            params.add_const_c_string(
                cstr!(OSSL_PKEY_PARAM_GROUP_NAME),
                c"modp_2048",
            )?;
            c"DH"
        }
        EvpPkeyType::Modp3072 => {
            params.add_const_c_string(
                cstr!(OSSL_PKEY_PARAM_GROUP_NAME),
                c"modp_3072",
            )?;
            c"DH"
        }
        EvpPkeyType::Modp4096 => {
            params.add_const_c_string(
                cstr!(OSSL_PKEY_PARAM_GROUP_NAME),
                c"modp_4096",
            )?;
            c"DH"
        }
        EvpPkeyType::Modp6144 => {
            params.add_const_c_string(
                cstr!(OSSL_PKEY_PARAM_GROUP_NAME),
                c"modp_6144",
            )?;
            c"DH"
        }
        EvpPkeyType::Modp8192 => {
            params.add_const_c_string(
                cstr!(OSSL_PKEY_PARAM_GROUP_NAME),
                c"modp_8192",
            )?;
            c"DH"
        }
        EvpPkeyType::P256 => {
            params.add_const_c_string(
                cstr!(OSSL_PKEY_PARAM_GROUP_NAME),
                c"prime256v1",
            )?;
            c"EC"
        }
        EvpPkeyType::P384 => {
            params.add_const_c_string(
                cstr!(OSSL_PKEY_PARAM_GROUP_NAME),
                c"secp384r1",
            )?;
            c"EC"
        }
        EvpPkeyType::P521 => {
            params.add_const_c_string(
                cstr!(OSSL_PKEY_PARAM_GROUP_NAME),
                c"secp521r1",
            )?;
            c"EC"
        }
        EvpPkeyType::BrainpoolP256r1 => {
            params.add_const_c_string(
                cstr!(OSSL_PKEY_PARAM_GROUP_NAME),
                c"brainpoolP256r1",
            )?;
            c"EC"
        }
        EvpPkeyType::BrainpoolP384r1 => {
            params.add_const_c_string(
                cstr!(OSSL_PKEY_PARAM_GROUP_NAME),
                c"brainpoolP384r1",
            )?;
            c"EC"
        }
        EvpPkeyType::BrainpoolP512r1 => {
            params.add_const_c_string(
                cstr!(OSSL_PKEY_PARAM_GROUP_NAME),
                c"brainpoolP512r1",
            )?;
            c"EC"
        }
        EvpPkeyType::Ed25519 => c"ED25519",
        EvpPkeyType::Ed448 => c"ED448",
        EvpPkeyType::X25519 => c"X25519",
        EvpPkeyType::X448 => c"X448",
        EvpPkeyType::Mldsa44 => c"ML-DSA-44",
        EvpPkeyType::Mldsa65 => c"ML-DSA-65",
        EvpPkeyType::Mldsa87 => c"ML-DSA-87",
        EvpPkeyType::MlKem512 => c"ML-KEM-512",
        EvpPkeyType::MlKem768 => c"ML-KEM-768",
        EvpPkeyType::MlKem1024 => c"ML-KEM-1024",
        EvpPkeyType::Rsa(size, exp) => {
            params.add_bn(cstr!(OSSL_PKEY_PARAM_RSA_E), &exp)?;
            params.add_owned_uint(
                cstr!(OSSL_PKEY_PARAM_RSA_BITS),
                c_uint::try_from(*size)?,
            )?;
            c"RSA"
        }
    };
    Ok(name)
}

/* Allocate enough space for a large name */
const MAX_GROUP_NAME_LEN: usize = 128;

/// Helper function to get pkey_type
fn pkey_to_type(
    pkey: &EvpPkey,
    params: &OsslParam,
) -> Result<EvpPkeyType, Error> {
    #[cfg(not(feature = "fips"))]
    let name = unsafe { EVP_PKEY_get0_type_name(pkey.as_ptr()) };
    #[cfg(feature = "fips")]
    let name = crate::fips::pkey_type_name(pkey.as_ptr());
    if name.is_null() {
        return Err(Error::new(ErrorKind::OsslError));
    }
    let type_name = unsafe { CStr::from_ptr(name) };
    match type_name.to_bytes() {
        b"EC" => {
            let group_name =
                params.get_utf8_string(cstr!(OSSL_PKEY_PARAM_GROUP_NAME))?;
            match group_name.to_bytes() {
                b"prime256v1" => Ok(EvpPkeyType::P256),
                b"secp384r1" => Ok(EvpPkeyType::P384),
                b"secp521r1" => Ok(EvpPkeyType::P521),
                b"brainpoolP256r1" => Ok(EvpPkeyType::BrainpoolP256r1),
                b"brainpoolP384r1" => Ok(EvpPkeyType::BrainpoolP384r1),
                b"brainpoolP512r1" => Ok(EvpPkeyType::BrainpoolP512r1),
                _ => Err(Error::new(ErrorKind::WrapperError)),
            }
        }
        b"ED25519" => Ok(EvpPkeyType::Ed25519),
        b"ED448" => Ok(EvpPkeyType::Ed448),
        b"X25519" => Ok(EvpPkeyType::X25519),
        b"X448" => Ok(EvpPkeyType::X448),
        b"DH" => {
            let group_name =
                params.get_utf8_string(cstr!(OSSL_PKEY_PARAM_GROUP_NAME))?;
            match group_name.to_bytes() {
                b"ffdhe2048" => Ok(EvpPkeyType::Ffdhe2048),
                b"ffdhe3072" => Ok(EvpPkeyType::Ffdhe3072),
                b"ffdhe4096" => Ok(EvpPkeyType::Ffdhe4096),
                b"ffdhe6144" => Ok(EvpPkeyType::Ffdhe6144),
                b"ffdhe8192" => Ok(EvpPkeyType::Ffdhe8192),
                b"modp_2048" => Ok(EvpPkeyType::Modp2048),
                b"modp_3072" => Ok(EvpPkeyType::Modp3072),
                b"modp_4096" => Ok(EvpPkeyType::Modp4096),
                b"modp_6144" => Ok(EvpPkeyType::Modp6144),
                b"modp_8192" => Ok(EvpPkeyType::Modp8192),
                _ => Err(Error::new(ErrorKind::WrapperError)),
            }
        }
        b"ML-DSA-44" => Ok(EvpPkeyType::Mldsa44),
        b"ML-DSA-65" => Ok(EvpPkeyType::Mldsa65),
        b"ML-DSA-87" => Ok(EvpPkeyType::Mldsa87),
        b"ML-KEM-512" => Ok(EvpPkeyType::MlKem512),
        b"ML-KEM-768" => Ok(EvpPkeyType::MlKem768),
        b"ML-KEM-1024" => Ok(EvpPkeyType::MlKem1024),
        b"RSA" => {
            let e = params.get_bn(cstr!(OSSL_PKEY_PARAM_RSA_E))?;
            let n = params.get_bn(cstr!(OSSL_PKEY_PARAM_RSA_N))?;
            let size = n.len() * 8;
            Ok(EvpPkeyType::Rsa(size, e))
        }
        _ => Err(Error::new(ErrorKind::WrapperError)),
    }
}

/// Structure that holds Ecc key data
#[derive(Debug)]
pub struct EccData {
    pub pubkey: Option<Vec<u8>>,
    pub prikey: Option<OsslSecret>,
}

impl Drop for EccData {
    fn drop(&mut self) {
        if let Some(mut v) = self.pubkey.take() {
            unsafe {
                OPENSSL_cleanse(v.as_mut_ptr() as *mut _, v.len());
            }
        }
    }
}

/// Structure that holds Ffdh key data
#[derive(Debug)]
pub struct FfdhData {
    pub pubkey: Option<Vec<u8>>,
    pub prikey: Option<OsslSecret>,
}

impl Drop for FfdhData {
    fn drop(&mut self) {
        if let Some(mut v) = self.pubkey.take() {
            unsafe {
                OPENSSL_cleanse(v.as_mut_ptr() as *mut _, v.len());
            }
        }
    }
}

/// Structure that holds ML Keys data (MlDsa and MlKem)
#[derive(Debug)]
pub struct MlkeyData {
    pub pubkey: Option<Vec<u8>>,
    pub prikey: Option<OsslSecret>,
    pub seed: Option<OsslSecret>,
}

impl Drop for MlkeyData {
    fn drop(&mut self) {
        if let Some(mut v) = self.pubkey.take() {
            unsafe {
                OPENSSL_cleanse(v.as_mut_ptr() as *mut _, v.len());
            }
        }
    }
}

/// Structure that holds RSA key data
#[derive(Debug)]
pub struct RsaData {
    pub n: Vec<u8>,
    pub d: Option<OsslSecret>,
    pub p: Option<OsslSecret>,
    pub q: Option<OsslSecret>,
    pub a: Option<OsslSecret>,
    pub b: Option<OsslSecret>,
    pub c: Option<OsslSecret>,
}

impl Drop for RsaData {
    fn drop(&mut self) {
        unsafe {
            OPENSSL_cleanse(self.n.as_mut_ptr() as *mut _, self.n.len());
        }
    }
}

#[cfg(feature = "rfc9580")]
impl RsaData {
    /// Creates a parameter set from `d`, `p`, and `q`.
    pub fn from_dpq(
        d: &[u8],
        p: &[u8],
        q: &[u8],
    ) -> Result<(Vec<u8>, RsaData), Error> {
        use crate::BigNum;

        /// Subtracts `b` from `a` storing the result in `res`.
        fn checked_sub(
            res: &mut BigNum,
            a: &BigNum,
            b: &BigNum,
        ) -> Result<(), Error> {
            let ret =
                unsafe { BN_sub(res.as_mut_ptr(), a.as_ptr(), b.as_ptr()) };

            if ret == 1 {
                Ok(())
            } else {
                trace_ossl!("BN_sub()");
                Err(Error::new(ErrorKind::OsslError))
            }
        }

        /// Computes the product of the given numbers storing the result
        /// in `res`.
        fn checked_mul(
            res: &mut BigNum,
            a: &BigNum,
            b: &BigNum,
        ) -> Result<(), Error> {
            unsafe {
                let ctx = BN_CTX_secure_new();
                if ctx.is_null() {
                    return Err(Error::new(ErrorKind::NullPtr));
                }

                let ret = BN_mul(res.as_mut_ptr(), a.as_ptr(), b.as_ptr(), ctx);

                BN_CTX_free(ctx);

                if ret == 1 {
                    Ok(())
                } else {
                    trace_ossl!("BN_mul()");
                    Err(Error::new(ErrorKind::OsslError))
                }
            }
        }

        /// Computes the inverse of `a` modulo `n` storing the result in
        /// `res`.
        fn checked_mod_inverse(
            res: &mut BigNum,
            a: &BigNum,
            n: &BigNum,
        ) -> Result<(), Error> {
            unsafe {
                let ctx = BN_CTX_secure_new();
                if ctx.is_null() {
                    return Err(Error::new(ErrorKind::NullPtr));
                }

                let ret = BN_mod_inverse(
                    res.as_mut_ptr(),
                    a.as_ptr(),
                    n.as_ptr(),
                    ctx,
                );

                BN_CTX_free(ctx);

                if !ret.is_null() {
                    Ok(())
                } else {
                    trace_ossl!("BN_mod_inverse()");
                    Err(Error::new(ErrorKind::OsslError))
                }
            }
        }

        /// Configures the given `BigNum` to use constant-time
        /// operations.
        fn use_constant_time_ops(bn: &mut BigNum) {
            unsafe {
                BN_set_flags(bn.as_mut_ptr(), BN_FLG_CONSTTIME as i32);
            }
        }

        let (e, n) = {
            use crate::BigNum;

            // Compute n = p * q.
            let p = BigNum::from_bigendian_slice(p)?;
            let q = BigNum::from_bigendian_slice(q)?;

            let mut n = BigNum::new()?;
            use_constant_time_ops(&mut n);
            checked_mul(&mut n, &p, &q)?;

            // Compute 𝜙 = (p - 1) * (q - 1).
            let one = BigNum::from_bigendian_slice(&[1])?;
            let mut p_dec = BigNum::new()?;
            use_constant_time_ops(&mut p_dec);
            checked_sub(&mut p_dec, &p, &one)?;
            let mut q_dec = BigNum::new()?;
            use_constant_time_ops(&mut q_dec);
            checked_sub(&mut q_dec, &q, &one)?;

            let mut phi = BigNum::new()?;
            use_constant_time_ops(&mut phi);
            checked_mul(&mut phi, &p_dec, &q_dec)?;

            // Compute e ≡ d⁻¹ (mod 𝜙).
            let d = BigNum::from_bigendian_slice(d)?;
            let mut e = BigNum::new()?;
            checked_mod_inverse(&mut e, &d, &phi)?;

            (e, n)
        };

        Ok((
            e.to_bigendian_vec()?,
            RsaData {
                n: n.to_bigendian_vec()?,
                d: Some(OsslSecret::from_vec(d.to_vec())),
                p: Some(OsslSecret::from_vec(p.to_vec())),
                q: Some(OsslSecret::from_vec(q.to_vec())),
                a: None,
                b: None,
                c: None,
            },
        ))
    }

    /// Computes the inverse of p modulo q, i.e. u ≡ p⁻¹ (mod q).
    pub fn inverse_p_mod_q(&self) -> Result<Vec<u8>, Error> {
        use crate::BigNum;

        /// Computes the inverse of `a` modulo `n` storing the result in
        /// `res`.
        fn checked_mod_inverse(
            res: &mut BigNum,
            a: &BigNum,
            n: &BigNum,
        ) -> Result<(), Error> {
            unsafe {
                let ctx = BN_CTX_secure_new();
                if ctx.is_null() {
                    return Err(Error::new(ErrorKind::NullPtr));
                }

                let ret = BN_mod_inverse(
                    res.as_mut_ptr(),
                    a.as_ptr(),
                    n.as_ptr(),
                    ctx,
                );

                BN_CTX_free(ctx);

                if !ret.is_null() {
                    Ok(())
                } else {
                    trace_ossl!("BN_mod_inverse()");
                    Err(Error::new(ErrorKind::OsslError))
                }
            }
        }

        /// Configures the given `BigNum` to use constant-time
        /// operations.
        fn use_constant_time_ops(bn: &mut BigNum) {
            unsafe {
                BN_set_flags(bn.as_mut_ptr(), BN_FLG_CONSTTIME as i32);
            }
        }

        let p = BigNum::from_bigendian_slice(
            self.p.as_ref().ok_or(Error::new(ErrorKind::NullPtr))?,
        )?;
        let q = BigNum::from_bigendian_slice(
            self.q.as_ref().ok_or(Error::new(ErrorKind::NullPtr))?,
        )?;
        let mut u = BigNum::new()?;
        use_constant_time_ops(&mut u);
        checked_mod_inverse(&mut u, &p, &q)?;

        Ok(u.to_bigendian_vec()?)
    }
}

/// Wrapper to handle import/export data based on the type
#[derive(Debug)]
pub enum PkeyData {
    Ecc(EccData),
    Ffdh(FfdhData),
    Mlkey(MlkeyData),
    Rsa(RsaData),
}

#[cfg(ossl_mldsa)]
fn params_to_mldsa_data(
    pkey: &EvpPkey,
    params: &OsslParam,
) -> Result<PkeyData, Error> {
    Ok(PkeyData::Mlkey(MlkeyData {
        pubkey: match params.get_octet_string(cstr!(OSSL_PKEY_PARAM_PUB_KEY)) {
            Ok(p) => Some(p.to_vec()),
            Err(e) => match e.kind() {
                ErrorKind::NullPtr => {
                    // OpenSSL does not always provide public key when
                    // asked for key pair here so if it not available,
                    // retry exporting just public key part
                    // https://github.com/openssl/openssl/issues/27542
                    let p2 = pkey.export_params(EVP_PKEY_PUBLIC_KEY)?;
                    match p2.get_octet_string(cstr!(OSSL_PKEY_PARAM_PUB_KEY)) {
                        Ok(p) => Some(p.to_vec()),
                        Err(e) => match e.kind() {
                            ErrorKind::NullPtr => None,
                            _ => return Err(e),
                        },
                    }
                }
                _ => return Err(e),
            },
        },
        prikey: match params.get_octet_string(cstr!(OSSL_PKEY_PARAM_PRIV_KEY)) {
            Ok(p) => Some(OsslSecret::from_slice(p)),
            Err(e) => match e.kind() {
                ErrorKind::NullPtr => None,
                _ => return Err(e),
            },
        },
        seed: match params.get_octet_string(cstr!(OSSL_PKEY_PARAM_ML_DSA_SEED))
        {
            Ok(p) => Some(OsslSecret::from_slice(p)),
            Err(e) => match e.kind() {
                ErrorKind::NullPtr => None,
                _ => return Err(e),
            },
        },
    }))
}

#[cfg(ossl_mldsa)]
fn params_to_mlkem_data(params: &OsslParam) -> Result<PkeyData, Error> {
    Ok(PkeyData::Mlkey(MlkeyData {
        pubkey: match params.get_octet_string(cstr!(OSSL_PKEY_PARAM_PUB_KEY)) {
            Ok(p) => Some(p.to_vec()),
            Err(e) => match e.kind() {
                ErrorKind::NullPtr => None,
                _ => return Err(e),
            },
        },
        prikey: match params.get_octet_string(cstr!(OSSL_PKEY_PARAM_PRIV_KEY)) {
            Ok(p) => Some(OsslSecret::from_slice(p)),
            Err(e) => match e.kind() {
                ErrorKind::NullPtr => None,
                _ => return Err(e),
            },
        },
        seed: match params.get_octet_string(cstr!(OSSL_PKEY_PARAM_ML_KEM_SEED))
        {
            Ok(p) => Some(OsslSecret::from_slice(p)),
            Err(e) => match e.kind() {
                ErrorKind::NullPtr => None,
                _ => return Err(e),
            },
        },
    }))
}

fn params_to_rsa_data(params: &OsslParam) -> Result<PkeyData, Error> {
    Ok(PkeyData::Rsa(RsaData {
        n: params.get_bn(cstr!(OSSL_PKEY_PARAM_RSA_N))?,
        d: match params.get_bn(cstr!(OSSL_PKEY_PARAM_RSA_D)) {
            Ok(p) => Some(OsslSecret::from_vec(p)),
            Err(e) => match e.kind() {
                ErrorKind::NullPtr => None,
                _ => return Err(e),
            },
        },
        p: match params.get_bn(cstr!(OSSL_PKEY_PARAM_RSA_FACTOR1)) {
            Ok(p) => Some(OsslSecret::from_vec(p)),
            Err(e) => match e.kind() {
                ErrorKind::NullPtr => None,
                _ => return Err(e),
            },
        },
        q: match params.get_bn(cstr!(OSSL_PKEY_PARAM_RSA_FACTOR2)) {
            Ok(p) => Some(OsslSecret::from_vec(p)),
            Err(e) => match e.kind() {
                ErrorKind::NullPtr => None,
                _ => return Err(e),
            },
        },
        a: match params.get_bn(cstr!(OSSL_PKEY_PARAM_RSA_EXPONENT1)) {
            Ok(p) => Some(OsslSecret::from_vec(p)),
            Err(e) => match e.kind() {
                ErrorKind::NullPtr => None,
                _ => return Err(e),
            },
        },
        b: match params.get_bn(cstr!(OSSL_PKEY_PARAM_RSA_EXPONENT2)) {
            Ok(p) => Some(OsslSecret::from_vec(p)),
            Err(e) => match e.kind() {
                ErrorKind::NullPtr => None,
                _ => return Err(e),
            },
        },
        c: match params.get_bn(cstr!(OSSL_PKEY_PARAM_RSA_COEFFICIENT1)) {
            Ok(p) => Some(OsslSecret::from_vec(p)),
            Err(e) => match e.kind() {
                ErrorKind::NullPtr => None,
                _ => return Err(e),
            },
        },
    }))
}

fn rsa_data_to_params(
    rsa: &RsaData,
    params: &mut OsslParamBuilder,
) -> Result<bool, Error> {
    let mut is_priv = false;
    params.add_bn(cstr!(OSSL_PKEY_PARAM_RSA_N), rsa.n.as_slice())?;
    if let Some(p) = &rsa.d {
        is_priv = true;
        params.add_bn(cstr!(OSSL_PKEY_PARAM_RSA_D), p)?;
    }
    if let Some(p) = &rsa.p {
        is_priv = true;
        params.add_bn(cstr!(OSSL_PKEY_PARAM_RSA_FACTOR1), p)?;
    }
    if let Some(p) = &rsa.q {
        is_priv = true;
        params.add_bn(cstr!(OSSL_PKEY_PARAM_RSA_FACTOR2), p)?;
    }
    if let Some(p) = &rsa.a {
        is_priv = true;
        params.add_bn(cstr!(OSSL_PKEY_PARAM_RSA_EXPONENT1), p)?;
    }
    if let Some(p) = &rsa.b {
        is_priv = true;
        params.add_bn(cstr!(OSSL_PKEY_PARAM_RSA_EXPONENT2), p)?;
    }
    if let Some(p) = &rsa.c {
        is_priv = true;
        params.add_bn(cstr!(OSSL_PKEY_PARAM_RSA_COEFFICIENT1), p)?;
    }
    Ok(is_priv)
}

/// An `extern "C"` callback function for `EVP_PKEY_export`.
///
/// This function is passed to the OpenSSL `EVP_PKEY_export` function to handle
/// the exported key material. It receives an array of `OSSL_PARAM` structures
/// from OpenSSL and an argument pointer, which is a mutable pointer to an
/// `OsslParamBuilder`.
///
/// Critically this function will zeroize allocated parameters after makig a
/// full copy of them, before returning control to OpenSSL.
unsafe extern "C" fn export_params_callback(
    params: *const OSSL_PARAM,
    arg: *mut c_void,
) -> c_int {
    if params.is_null() || arg.is_null() {
        return 0;
    }

    /* get num of elements */
    let mut nelem = 0;
    let mut total_size = 0;
    let mut counter = params;
    unsafe {
        while !(*counter).key.is_null() {
            nelem += 1;
            total_size += std::mem::size_of::<OSSL_PARAM>();
            total_size += (*counter).data_size;
            counter = counter.offset(1);
        }
    }
    let pslice = unsafe { std::slice::from_raw_parts(params, nelem) };

    let params_builder = &mut *(arg as *mut OsslParamBuilder);
    let ret = params_builder.copy_params(&pslice);

    /* Zeroize any allocated data wich may hold copies of secrets.
     * This is not the most clean way to do it, because this depends
     * on knowing how OpenSSL internally builds parameter slices, and if
     * that ever changes we may be overwrting memory that was not a
     * temporary copy */
    let max_ptr = pslice.as_ptr().wrapping_add(total_size) as *const c_void;
    let base_ptr = pslice.as_ptr() as *const c_void;
    for p in pslice {
        if p.data.is_null() {
            continue;
        }
        let pdata = p.data as *const c_void;
        if pdata > base_ptr && pdata < max_ptr {
            unsafe {
                OPENSSL_cleanse(p.data, p.data_size);
            }
        }
    }
    if ret.is_ok() {
        return 1;
    }
    return 0;
}

/// Wrapper around OpenSSL's `EVP_PKEY`, representing a generic public or
/// private key. Manages the key's lifecycle.
#[derive(Debug)]
pub struct EvpPkey {
    ptr: *mut EVP_PKEY,
}

impl EvpPkey {
    /// Creates an `EvpPkey` from key material provided via `OSSL_PARAM`s.
    ///
    /// Used for importing public or private keys based on their components
    /// (e.g., modulus/exponent for RSA, curve/point for EC).
    pub fn fromdata(
        ctx: &OsslContext,
        pkey_name: &CStr,
        pkey_type: u32,
        params: &OsslParam,
    ) -> Result<EvpPkey, Error> {
        let mut pctx = EvpPkeyCtx::new(ctx, pkey_name)?;
        let res = unsafe { EVP_PKEY_fromdata_init(pctx.as_mut_ptr()) };
        if res != 1 {
            trace_ossl!("EVP_PKEY_fromdata_init()");
            return Err(Error::new(ErrorKind::OsslError));
        }
        let mut pkey: *mut EVP_PKEY = std::ptr::null_mut();
        let res = unsafe {
            EVP_PKEY_fromdata(
                pctx.as_mut_ptr(),
                &mut pkey,
                pkey_type as i32,
                params.as_ptr() as *mut OSSL_PARAM,
            )
        };
        if res != 1 {
            trace_ossl!("EVP_PKEY_fromdata()");
            return Err(Error::new(ErrorKind::OsslError));
        }
        Ok(EvpPkey { ptr: pkey })
    }

    /// Exports key material components into an `OsslParam` structure.
    ///
    /// The `selection` argument specifies which components to export
    /// (e.g., public, private, parameters).
    fn export_params(&self, selection: u32) -> Result<OsslParam<'_>, Error> {
        let mut params_builder = OsslParamBuilder::new();
        params_builder.zeroize = true;
        let ret = unsafe {
            EVP_PKEY_export(
                self.ptr,
                c_int::try_from(selection)?,
                Some(export_params_callback),
                &mut params_builder as *mut OsslParamBuilder as *mut c_void,
            )
        };
        if ret != 1 {
            trace_ossl!("EVP_PKEY_export()");
            return Err(Error::new(ErrorKind::OsslError));
        }
        Ok(params_builder.finalize())
    }

    /// Allow to get parameters from a key.
    /// The caller must preallocate the payloads with enough space to
    /// receive the data, which is copied into the parameters.
    pub fn get_params(&self, params: &mut OsslParam) -> Result<(), Error> {
        if unsafe { EVP_PKEY_get_params(self.ptr, params.as_mut_ptr()) } != 1 {
            return Err(Error::new(ErrorKind::OsslError));
        }
        Ok(())
    }

    /// Generates a new key pair based on provided algorithm name and
    /// parameters.
    pub fn generate(
        ctx: &OsslContext,
        pkey_type: EvpPkeyType,
    ) -> Result<EvpPkey, Error> {
        let mut params_builder = OsslParamBuilder::new();
        let name = pkey_type_to_params(&pkey_type, &mut params_builder)?;
        let params = params_builder.finalize();
        let mut pctx = EvpPkeyCtx::new(ctx, name)?;
        let res = unsafe { EVP_PKEY_keygen_init(pctx.as_mut_ptr()) };
        if res != 1 {
            trace_ossl!("EVP_PKEY_keygen_init()");
            return Err(Error::new(ErrorKind::OsslError));
        }
        let res = unsafe {
            EVP_PKEY_CTX_set_params(pctx.as_mut_ptr(), params.as_ptr())
        };
        if res != 1 {
            trace_ossl!("EVP_PKEY_CTX_set_params()");
            return Err(Error::new(ErrorKind::OsslError));
        }
        let mut pkey: *mut EVP_PKEY = std::ptr::null_mut();
        let res = unsafe { EVP_PKEY_generate(pctx.as_mut_ptr(), &mut pkey) };
        if res != 1 {
            trace_ossl!("EVP_PKEY_generate()");
            return Err(Error::new(ErrorKind::OsslError));
        }
        Ok(EvpPkey { ptr: pkey })
    }

    /// Creates a new `EvpPkeyCtx` associated with this `EvpPkey`.
    ///
    /// Used to prepare for operations using this specific key.
    pub fn new_ctx(&mut self, ctx: &OsslContext) -> Result<EvpPkeyCtx, Error> {
        /* this function takes care of checking for NULL */
        unsafe {
            EvpPkeyCtx::from_ptr(
                /* this function will use refcounting to keep EVP_PKEY
                 * alive for the lifetime of the context, so it is ok
                 * to not use rust lifetimes here */
                EVP_PKEY_CTX_new_from_pkey(
                    ctx.ptr(),
                    self.as_mut_ptr(),
                    std::ptr::null_mut(),
                ),
            )
        }
    }

    /// Helper to import a public/private pkey */
    pub fn import(
        ctx: &OsslContext,
        pkey_type: EvpPkeyType,
        data: PkeyData,
    ) -> Result<EvpPkey, Error> {
        let mut pkey_class: u32 = 0;
        let mut params_builder = OsslParamBuilder::with_capacity(2);
        params_builder.zeroize = true;

        let name = pkey_type_to_params(&pkey_type, &mut params_builder)?;

        match pkey_type {
            EvpPkeyType::P256
            | EvpPkeyType::P384
            | EvpPkeyType::P521
            | EvpPkeyType::BrainpoolP256r1
            | EvpPkeyType::BrainpoolP384r1
            | EvpPkeyType::BrainpoolP512r1 => match &data {
                PkeyData::Ecc(ecc) => {
                    if let Some(p) = &ecc.pubkey {
                        pkey_class |= EVP_PKEY_PUBLIC_KEY;
                        params_builder.add_octet_slice(
                            cstr!(OSSL_PKEY_PARAM_PUB_KEY),
                            p.as_slice(),
                        )?
                    }
                    if let Some(p) = &ecc.prikey {
                        pkey_class |= EVP_PKEY_PRIVATE_KEY;
                        params_builder
                            .add_bn(cstr!(OSSL_PKEY_PARAM_PRIV_KEY), p)?
                    }
                }
                _ => return Err(Error::new(ErrorKind::WrapperError)),
            },
            EvpPkeyType::Ed25519
            | EvpPkeyType::Ed448
            | EvpPkeyType::X25519
            | EvpPkeyType::X448 => match &data {
                PkeyData::Ecc(ecc) => {
                    if let Some(p) = &ecc.pubkey {
                        pkey_class |= EVP_PKEY_PUBLIC_KEY;
                        params_builder.add_octet_slice(
                            cstr!(OSSL_PKEY_PARAM_PUB_KEY),
                            p.as_slice(),
                        )?
                    }
                    if let Some(p) = &ecc.prikey {
                        pkey_class |= EVP_PKEY_PRIVATE_KEY;
                        params_builder.add_octet_slice(
                            cstr!(OSSL_PKEY_PARAM_PRIV_KEY),
                            p,
                        )?
                    }
                }
                _ => return Err(Error::new(ErrorKind::WrapperError)),
            },
            EvpPkeyType::Ffdhe2048
            | EvpPkeyType::Ffdhe3072
            | EvpPkeyType::Ffdhe4096
            | EvpPkeyType::Ffdhe6144
            | EvpPkeyType::Ffdhe8192
            | EvpPkeyType::Modp2048
            | EvpPkeyType::Modp3072
            | EvpPkeyType::Modp4096
            | EvpPkeyType::Modp6144
            | EvpPkeyType::Modp8192 => match &data {
                PkeyData::Ffdh(ffdh) => {
                    if let Some(p) = &ffdh.pubkey {
                        pkey_class |= EVP_PKEY_PUBLIC_KEY;
                        params_builder.add_bn(
                            cstr!(OSSL_PKEY_PARAM_PUB_KEY),
                            p.as_slice(),
                        )?
                    }
                    if let Some(p) = &ffdh.prikey {
                        pkey_class |= EVP_PKEY_PRIVATE_KEY;
                        params_builder
                            .add_bn(cstr!(OSSL_PKEY_PARAM_PRIV_KEY), p)?
                    }
                }
                _ => return Err(Error::new(ErrorKind::WrapperError)),
            },
            EvpPkeyType::Mldsa44
            | EvpPkeyType::Mldsa65
            | EvpPkeyType::Mldsa87 => match &data {
                #[cfg(ossl_mldsa)]
                PkeyData::Mlkey(mlk) => {
                    if let Some(p) = &mlk.pubkey {
                        pkey_class |= EVP_PKEY_PUBLIC_KEY;
                        params_builder.add_octet_slice(
                            cstr!(OSSL_PKEY_PARAM_PUB_KEY),
                            p.as_slice(),
                        )?
                    }
                    if let Some(p) = &mlk.prikey {
                        pkey_class |= EVP_PKEY_PRIVATE_KEY;
                        params_builder.add_octet_slice(
                            cstr!(OSSL_PKEY_PARAM_PRIV_KEY),
                            p,
                        )?
                    }
                    if let Some(p) = &mlk.seed {
                        pkey_class |= EVP_PKEY_PRIVATE_KEY;
                        params_builder.add_octet_slice(
                            cstr!(OSSL_PKEY_PARAM_ML_DSA_SEED),
                            p,
                        )?
                    }
                }
                _ => return Err(Error::new(ErrorKind::WrapperError)),
            },
            EvpPkeyType::MlKem512
            | EvpPkeyType::MlKem768
            | EvpPkeyType::MlKem1024 => match &data {
                #[cfg(ossl_mlkem)]
                PkeyData::Mlkey(mlk) => {
                    if let Some(p) = &mlk.pubkey {
                        pkey_class |= EVP_PKEY_PUBLIC_KEY;
                        params_builder.add_octet_slice(
                            cstr!(OSSL_PKEY_PARAM_PUB_KEY),
                            p.as_slice(),
                        )?
                    }
                    if let Some(p) = &mlk.prikey {
                        pkey_class |= EVP_PKEY_PRIVATE_KEY;
                        params_builder.add_octet_slice(
                            cstr!(OSSL_PKEY_PARAM_PRIV_KEY),
                            p,
                        )?
                    }
                    if let Some(p) = &mlk.seed {
                        pkey_class |= EVP_PKEY_PRIVATE_KEY;
                        params_builder.add_octet_slice(
                            cstr!(OSSL_PKEY_PARAM_ML_KEM_SEED),
                            p,
                        )?
                    }
                }
                _ => return Err(Error::new(ErrorKind::WrapperError)),
            },
            EvpPkeyType::Rsa(_, _) => match &data {
                PkeyData::Rsa(rsa) => {
                    if rsa_data_to_params(&rsa, &mut params_builder)? {
                        pkey_class |= EVP_PKEY_PRIVATE_KEY;
                    } else {
                        pkey_class |= EVP_PKEY_PUBLIC_KEY;
                    }
                }
                _ => return Err(Error::new(ErrorKind::WrapperError)),
            },
        }
        let params = params_builder.finalize();

        EvpPkey::fromdata(ctx, name, pkey_class, &params)
    }

    /// Export public point in encoded form and/or private key
    pub fn export(&self) -> Result<PkeyData, Error> {
        let params = self.export_params(EVP_PKEY_KEYPAIR)?;
        let pkey_type = pkey_to_type(&self, &params)?;
        Ok(match pkey_type {
            EvpPkeyType::P256
            | EvpPkeyType::P384
            | EvpPkeyType::P521
            | EvpPkeyType::BrainpoolP256r1
            | EvpPkeyType::BrainpoolP384r1
            | EvpPkeyType::BrainpoolP512r1 => PkeyData::Ecc(EccData {
                pubkey: match params
                    .get_octet_string(cstr!(OSSL_PKEY_PARAM_PUB_KEY))
                {
                    Ok(p) => Some(p.to_vec()),
                    Err(e) => match e.kind() {
                        ErrorKind::NullPtr => None,
                        _ => return Err(e),
                    },
                },
                prikey: match params.get_bn(cstr!(OSSL_PKEY_PARAM_PRIV_KEY)) {
                    Ok(p) => Some(OsslSecret::from_vec(p)),
                    Err(e) => match e.kind() {
                        ErrorKind::NullPtr => None,
                        _ => return Err(e),
                    },
                },
            }),
            EvpPkeyType::Ed25519
            | EvpPkeyType::Ed448
            | EvpPkeyType::X25519
            | EvpPkeyType::X448 => PkeyData::Ecc(EccData {
                pubkey: match params
                    .get_octet_string(cstr!(OSSL_PKEY_PARAM_PUB_KEY))
                {
                    Ok(p) => Some(p.to_vec()),
                    Err(e) => match e.kind() {
                        ErrorKind::NullPtr => None,
                        _ => return Err(e),
                    },
                },
                prikey: match params
                    .get_octet_string(cstr!(OSSL_PKEY_PARAM_PRIV_KEY))
                {
                    Ok(p) => Some(OsslSecret::from_slice(p)),
                    Err(e) => match e.kind() {
                        ErrorKind::NullPtr => None,
                        _ => return Err(e),
                    },
                },
            }),
            EvpPkeyType::Ffdhe2048
            | EvpPkeyType::Ffdhe3072
            | EvpPkeyType::Ffdhe4096
            | EvpPkeyType::Ffdhe6144
            | EvpPkeyType::Ffdhe8192
            | EvpPkeyType::Modp2048
            | EvpPkeyType::Modp3072
            | EvpPkeyType::Modp4096
            | EvpPkeyType::Modp6144
            | EvpPkeyType::Modp8192 => PkeyData::Ffdh(FfdhData {
                pubkey: match params.get_bn(cstr!(OSSL_PKEY_PARAM_PUB_KEY)) {
                    Ok(p) => Some(p),
                    Err(e) => match e.kind() {
                        ErrorKind::NullPtr => None,
                        _ => return Err(e),
                    },
                },
                prikey: match params.get_bn(cstr!(OSSL_PKEY_PARAM_PRIV_KEY)) {
                    Ok(p) => Some(OsslSecret::from_vec(p)),
                    Err(e) => match e.kind() {
                        ErrorKind::NullPtr => None,
                        _ => return Err(e),
                    },
                },
            }),
            EvpPkeyType::Mldsa44
            | EvpPkeyType::Mldsa65
            | EvpPkeyType::Mldsa87 => {
                #[cfg(ossl_mldsa)]
                return params_to_mldsa_data(&self, &params);
                #[cfg(not(ossl_mldsa))]
                return Err(Error::new(ErrorKind::WrapperError));
            }
            EvpPkeyType::MlKem512
            | EvpPkeyType::MlKem768
            | EvpPkeyType::MlKem1024 => {
                #[cfg(ossl_mlkem)]
                return params_to_mlkem_data(&params);
                #[cfg(not(ossl_mlkem))]
                return Err(Error::new(ErrorKind::WrapperError));
            }
            EvpPkeyType::Rsa(_, _) => return params_to_rsa_data(&params),
        })
    }

    /// Creates a new public EvpPkey with this key as template and the provided
    /// slice as as public key value
    pub fn make_peer(
        &self,
        ctx: &OsslContext,
        public: &[u8],
    ) -> Result<EvpPkey, Error> {
        let mut params_builder = OsslParamBuilder::with_capacity(1);
        params_builder.add_empty_utf8_string(
            cstr!(OSSL_PKEY_PARAM_GROUP_NAME),
            MAX_GROUP_NAME_LEN + 1,
        )?;
        let mut params = params_builder.finalize();
        self.get_params(&mut params)?;
        let pkey_type = pkey_to_type(&self, &params)?;
        let data = match pkey_type {
            EvpPkeyType::P256
            | EvpPkeyType::P384
            | EvpPkeyType::P521
            | EvpPkeyType::BrainpoolP256r1
            | EvpPkeyType::BrainpoolP384r1
            | EvpPkeyType::BrainpoolP512r1
            | EvpPkeyType::Ed25519
            | EvpPkeyType::Ed448
            | EvpPkeyType::X25519
            | EvpPkeyType::X448 => PkeyData::Ecc(EccData {
                pubkey: Some(public.to_vec()),
                prikey: None,
            }),
            EvpPkeyType::Ffdhe2048
            | EvpPkeyType::Ffdhe3072
            | EvpPkeyType::Ffdhe4096
            | EvpPkeyType::Ffdhe6144
            | EvpPkeyType::Ffdhe8192
            | EvpPkeyType::Modp2048
            | EvpPkeyType::Modp3072
            | EvpPkeyType::Modp4096
            | EvpPkeyType::Modp6144
            | EvpPkeyType::Modp8192 => PkeyData::Ffdh(FfdhData {
                pubkey: Some(public.to_vec()),
                prikey: None,
            }),
            _ => return Err(Error::new(ErrorKind::WrapperError)),
        };
        Self::import(ctx, pkey_type, data)
    }

    /// Returns a const pointer to the underlying `EVP_PKEY`.
    pub fn as_ptr(&self) -> *const EVP_PKEY {
        self.ptr
    }

    /// Returns a mutable pointer to the underlying `EVP_PKEY`.
    pub fn as_mut_ptr(&mut self) -> *mut EVP_PKEY {
        self.ptr
    }

    /// Gets the key size in bits. Handles FIPS provider differences.
    #[cfg(not(feature = "fips"))]
    pub fn get_bits(&self) -> Result<usize, Error> {
        let ret = unsafe { EVP_PKEY_get_bits(self.ptr) };
        if ret == 0 {
            /* TODO: may want to return a special error
             * for unsupported keys */
            return Err(Error::new(ErrorKind::OsslError));
        }
        Ok(usize::try_from(ret)?)
    }
    #[cfg(feature = "fips")]
    pub fn get_bits(&self) -> Result<usize, Error> {
        /* EVP_PKEY_get_bits() not available in libfips.a */
        let mut bits: c_int = 0;
        let name = cstr!(OSSL_PKEY_PARAM_BITS).as_ptr();
        let ret = unsafe { EVP_PKEY_get_int_param(self.ptr, name, &mut bits) };
        if ret == 0 {
            /* TODO: may want to return a special error
             * for unsupported keys */
            return Err(Error::new(ErrorKind::OsslError));
        }
        Ok(usize::try_from(bits)?)
    }

    /// Gets the actual key size by querying the underlying `EVP_PKEY`
    pub fn get_size(&self) -> Result<usize, Error> {
        Ok(usize::try_from(unsafe {
            EVP_PKEY_get_size(self.as_ptr())
        })?)
    }
}

impl Drop for EvpPkey {
    fn drop(&mut self) {
        unsafe {
            EVP_PKEY_free(self.ptr);
        }
    }
}

unsafe impl Send for EvpPkey {}
unsafe impl Sync for EvpPkey {}

#[cfg(test)]
mod tests {
    use super::*;

    /// Tests importing a key from d, p, and q, and the computation of
    /// the inverse of p mod q.
    ///
    /// This test vector has been extracted from Sequoia's test suite.
    #[cfg(feature = "rfc9580")]
    #[test]
    fn import_rsa_dpq() -> Result<(), Error> {
        // The inputs.
        let d = b"\x14\xC4\x3A\x0C\x3A\x79\xA4\xF7\x63\x0D\x89\x93\x63\x8B\x56\x9C\x29\x2E\xCD\xCF\xBF\xB0\xEC\x66\x52\xC3\x70\x1B\x19\x21\x73\xDE\x8B\xAC\x0E\xF2\xE1\x28\x42\x66\x56\x55\x00\x3B\xFD\x50\xC4\x7C\xBC\x9D\xEB\x7D\xF4\x81\xFC\xC3\xBF\xF7\xFF\xD0\x41\x3E\x50\x3B\x5F\x5D\x5F\x56\x67\x5E\x00\xCE\xA4\x53\xB8\x59\xA0\x40\xC8\x96\x6D\x12\x09\x27\xBE\x1D\xF1\xC2\x68\xFC\xF0\x14\xD6\x52\x77\x07\xC8\x12\x36\x9C\x9A\x5C\xAF\x43\xCC\x95\x20\xBB\x0A\x44\x94\xDD\xB4\x4F\x45\x4E\x3A\x1A\x30\x0D\x66\x40\xAC\x68\xE8\xB0\xFD\xCD\x6C\x6B\x6C\xB5\xF7\xE4\x36\x95\xC2\x96\x98\xFD\xCA\x39\x6C\x1A\x2E\x55\xAD\xB6\xE0\xF8\x2C\xFF\xBC\xD3\x32\x15\x52\x39\xB3\x92\x35\xDB\x8B\x68\xAF\x2D\x4A\x6E\x64\xB8\x28\x63\xC4\x24\x94\x2D\xA9\xDB\x93\x56\xE3\xBC\xD0\xB6\x38\x84\x04\xA4\xC6\x18\x48\xFE\xB2\xF8\xE1\x60\x37\x52\x96\x41\xA5\x79\xF6\x3D\xB7\x2A\x71\x5B\x7A\x75\xBF\x7F\xA2\x5A\xC8\xA1\x38\xF2\x5A\xBD\x14\xFC\xAF\xB4\x54\x83\xA4\xBD\x49\xA2\x8B\x91\xB0\xE0\x4A\x1B\x21\x54\x07\x19\x70\x64\x7C\x3E\x9F\x8D\x8B\xE4\x70\xD1\xE7\xBE\x4E\x5C\xCE\xF1";
        let p = b"\xC8\x32\xD1\x17\x41\x4D\x8F\x37\x09\x18\x32\x4C\x4C\xF4\xA2\x15\x27\x43\x3D\xBB\xB5\xF6\x1F\xCF\xD2\xE4\x43\x61\x07\x0E\x9E\x35\x1F\x0A\x5D\xFB\x3A\x45\x74\x61\x73\x73\x7B\x5F\x1F\x87\xFB\x54\x8D\xA8\x85\x3E\xB0\xB7\xC7\xF5\xC9\x13\x99\x8D\x40\xE6\xA6\xD0\x71\x3A\xE3\x2D\x4A\xC3\xA3\xFF\xF7\x72\x82\x14\x52\xA4\xBA\x63\x0E\x17\xCA\xCA\x18\xC4\x3A\x40\x79\xF1\x86\xB3\x10\x4B\x9F\xB2\xAE\x2E\x13\x38\x8D\x2C\xF9\x88\x4C\x25\x53\xEF\xF9\xD1\x8B\x1A\x7C\xE7\xF6\x4B\x73\x51\x31\xFA\x44\x1D\x36\x65\x71\xDA\xFC\x6F";
        let q = b"\xCC\x30\xE9\xCC\xCB\x31\x28\xB5\x90\xFF\x06\x62\x42\x5B\x24\x0E\x00\xFE\xE2\x37\xC4\xAC\xBB\x3B\x8F\xF2\x0E\x3F\x78\xCF\x6B\x7C\xE8\x75\x57\x7C\x15\x9D\x1A\x66\xF2\x0A\xE5\xD3\x0B\xE7\x40\xF7\xE7\x00\xB6\x86\xB5\xD9\x20\x67\xE0\x4A\xC0\x90\xA4\x13\x4D\xC9\xB0\x12\xC5\xCD\x4C\xEB\xA1\x91\x2D\x43\x58\x6E\xB6\x75\xA0\x93\xF0\x5B\xC5\x31\xCA\xB7\xC6\x22\x0C\xD3\xEC\x84\xC5\x91\xA1\x5F\x2C\x8E\x07\x5D\xA1\x98\x67\xC5\x7A\x58\x16\x71\x3D\xED\x91\x03\x0D\xD4\x25\x07\x89\x9B\x33\x98\xA3\x70\xD9\xE7\xC8\x17\xA3\xD9";

        // The expected outputs.
        let expect_e = b"\x01\x00\x01";
        let expect_n = b"\x9f\xae\xbe\xfc\x24\x19\x92\xff\xba\xf1\xb1\x08\x3b\xcb\x52\x22\x6a\x5b\x94\xaa\xa6\xd7\x9a\x93\x17\xcf\xc9\xa6\x77\xfb\x58\x28\x1d\x64\xca\x69\xca\x91\xc8\x82\xbd\x82\x77\x08\xaa\xbf\xdd\xcd\xc0\x95\x39\x55\xef\x1e\x2a\x29\xc5\xc8\x2f\x95\xd2\xb8\xe3\x5d\xab\xdc\x47\x1e\x91\x72\xc6\x33\x09\x2c\x06\x0c\x36\x7f\x8f\x47\xa0\x60\xc8\xb2\x46\x27\xd3\x13\x84\x1c\x44\x2d\x01\xb0\xec\xc1\x0b\xfb\xfe\xe2\x15\x3e\x8d\xf7\x67\xae\xf0\xf4\xf2\x52\x74\x30\x74\x35\xc0\xe8\x95\x79\x33\x8f\x5f\x6d\x80\xa2\x1b\xfd\xac\x09\x74\xb2\x56\xd2\x49\x0d\xc4\x16\x91\x64\x12\x65\xab\x02\xf3\x63\xe6\x15\x7e\x02\xff\x94\x2a\xba\x76\x7a\x9d\x74\x4b\x93\x1e\xfd\x12\xb1\xf0\x0b\x3a\x8e\xf4\x6a\x98\xee\xb8\x0f\x12\xb9\x95\xd0\x77\x76\x2d\x75\x2d\x01\xeb\x02\x99\x20\x45\x89\x1d\xce\x95\xed\x4c\xc0\xdc\x29\xeb\xb8\x73\x42\x61\x48\x2e\xaa\x01\x44\xa9\x89\xa0\x43\x9f\x86\x33\xa2\x4c\x23\x04\x4f\x84\x8f\xec\x81\x36\xa5\xca\x46\x28\x9c\x8f\xc8\x91\xf0\x95\xfb\x06\xf1\x22\x93\x5c\x13\xac\xbb\xd3\x54\x8b\x35\xf8\x1e\xf4\x99\xe2\x88\x57\x53\xa7\x17";
        let expect_u = b"\x32\xd4\xd9\x5a\x71\xa5\x4f\xf7\x04\xaa\xd1\x3b\x90\x32\xbd\xf3\x14\x29\x69\x4a\x5e\x57\x93\xa6\x88\x1d\xc1\xcb\xb4\x84\x76\x27\xb4\xaa\xf8\x99\xc7\xbb\xb4\x19\x51\x41\x18\x6d\x52\xfe\x1d\xcd\x14\x3c\x38\x9e\xf9\xa3\x2b\xed\x97\xd9\x8d\x7d\x66\x88\x38\x1f\xc9\xbf\x95\x0e\xc5\xe5\xe1\x8e\x1d\xb4\x3f\x6d\xcd\x0a\x5a\xed\xa0\xcf\xb9\x95\x88\x9a\x2c\x4c\x74\x65\xf0\xfc\xc6\xaf\x39\x00\xaa\xab\x84\xcc\x1c\xc3\x88\xc7\xd2\x58\x49\x79\xb4\xd8\x38\x47\x8a\xad\xf0\xfa\x48\xf6\xcb\x6f\x30\x6f\xf3\x95\xf9\x58\x2c\x3b";

        let (e, data) = RsaData::from_dpq(d, p, q)?;
        assert_eq!(e, expect_e);
        assert_eq!(&data.n, expect_n);
        assert_eq!(&data.inverse_p_mod_q()?, expect_u);
        Ok(())
    }
}
