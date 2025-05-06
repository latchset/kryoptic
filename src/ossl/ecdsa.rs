// Copyright 2023 - 2024 Simo Sorce, Jakub Jelen
// See LICENSE.txt file for terms

//! This module implements ECDSA (Elliptic Curve Digital Signature Algorithm)
//! functionalities using the OpenSSL EVP interface, including key generation,
//! signing, verification, and signature format conversions.

use core::ffi::c_char;

use crate::attribute::Attribute;
use crate::ec::ecdsa::*;
use crate::ec::get_ec_point_from_obj;
use crate::error::{some_or_err, Result};
use crate::interface::*;
use crate::kasn1::DerEncBigUint;
use crate::mechanism::*;
use crate::misc::zeromem;
use crate::object::Object;
use crate::ossl::bindings::*;
use crate::ossl::common::*;

#[cfg(feature = "fips")]
use crate::ossl::fips::*;

#[cfg(not(feature = "fips"))]
use crate::ossl::get_libctx;

/// Converts a PKCS#11 EC key `Object` into OpenSSL parameters (`OsslParam`).
///
/// Extracts the curve name and relevant key components (public point or private
/// value) based on the object `class` and populates an `OsslParam` structure
/// suitable for creating an OpenSSL `EvpPkey`.
pub fn ecc_object_to_params(
    key: &Object,
    class: CK_OBJECT_CLASS,
) -> Result<(*const c_char, OsslParam)> {
    let kclass = key.get_attr_as_ulong(CKA_CLASS)?;
    if kclass != class {
        return Err(CKR_KEY_TYPE_INCONSISTENT)?;
    }
    let mut params = OsslParam::with_capacity(2);
    params.zeroize = true;

    params.add_const_c_string(
        name_as_char(OSSL_PKEY_PARAM_GROUP_NAME),
        name_as_char(get_ossl_name_from_obj(key)?),
    )?;

    match kclass {
        CKO_PUBLIC_KEY => {
            params.add_owned_octet_string(
                name_as_char(OSSL_PKEY_PARAM_PUB_KEY),
                get_ec_point_from_obj(key)?,
            )?;
        }
        CKO_PRIVATE_KEY => {
            params.add_bn(
                name_as_char(OSSL_PKEY_PARAM_PRIV_KEY),
                key.get_attr_as_bytes(CKA_VALUE)?,
            )?;
        }
        _ => return Err(CKR_KEY_TYPE_INCONSISTENT)?,
    }

    params.finalize();

    Ok((name_as_char(EC_NAME), params))
}

/// ASN.1 structure for an ECDSA signature value (SEQUENCE of two INTEGERs).
#[derive(asn1::Asn1Read, asn1::Asn1Write)]
struct EcdsaSignature<'a> {
    r: DerEncBigUint<'a>,
    s: DerEncBigUint<'a>,
}

/// Copies one half (r or s) of an ECDSA signature from an input slice `hin`
/// to an output slice `hout` of potentially different (but sufficient) length,
/// handling necessary padding or truncation of leading zeros.
fn slice_to_sig_half(hin: &[u8], hout: &mut [u8]) -> Result<()> {
    let mut len = hin.len();
    if len > hout.len() {
        /* check for leading zeros */
        for i in 0..hin.len() {
            if hin[i] != 0 {
                break;
            }
            len -= 1;
        }
        if len == 0 || len > hout.len() {
            return Err(CKR_GENERAL_ERROR)?;
        }
    }
    let ipad = hin.len() - len;
    let opad = hout.len() - len;
    if opad > 0 {
        hout[0..opad].fill(0);
    }
    hout[opad..].copy_from_slice(&hin[ipad..]);
    Ok(())
}

/// Convert OpenSSL ECDSA signature to PKCS #11 format
///
/// The OpenSSL ECDSA signature is DER encoded SEQUENCE of r and s values.
/// The PKCS #11 is representing the signature only using the two concatenated bignums
/// padded with zeroes to the fixed length.
/// This means we here parse the numbers from the DER encoding and construct fixed length
/// buffer with padding if needed.
/// Do not care if the first bit is 1 as in PKCS #11 we interpret the number always positive
fn ossl_to_pkcs11_signature(
    ossl_sign: &Vec<u8>,
    signature: &mut [u8],
) -> Result<()> {
    let sig = match asn1::parse_single::<EcdsaSignature>(ossl_sign.as_slice()) {
        Ok(a) => a,
        Err(_) => return Err(CKR_GENERAL_ERROR)?,
    };
    let bn_len = signature.len() / 2;
    slice_to_sig_half(sig.r.as_bytes(), &mut signature[..bn_len])?;
    slice_to_sig_half(sig.s.as_bytes(), &mut signature[bn_len..])
}

/// Convert PKCS #11 ECDSA signature to OpenSSL format
///
/// The PKCS #11 represents the ECDSA signature only as a two padded values of fixed length.
/// The OpenSSL expects the signature to be DER encoded SEQUENCE of two bignums so
/// we split here the provided buffer and wrap it with the DER encoding.
fn pkcs11_to_ossl_signature(signature: &[u8]) -> Result<Vec<u8>> {
    let bn_len = signature.len() / 2;
    let sig = EcdsaSignature {
        r: DerEncBigUint::new(&signature[..bn_len])?,
        s: DerEncBigUint::new(&signature[bn_len..])?,
    };
    let ossl_sign = match asn1::write_single(&sig) {
        Ok(b) => b,
        Err(_) => return Err(CKR_GENERAL_ERROR)?,
    };
    Ok(ossl_sign)
}

/// Represents an active ECDSA signing or verification operation.
#[derive(Debug)]
pub struct EcdsaOperation {
    /// The specific ECDSA mechanism type (e.g., CKM_ECDSA_SHA256).
    mech: CK_MECHANISM_TYPE,
    /// Expected output length of the signature in bytes (2 * field size).
    output_len: usize,
    /// The public key used for verification (wrapped `EvpPkey`).
    public_key: Option<EvpPkey>,
    /// The private key used for signing (wrapped `EvpPkey`).
    private_key: Option<EvpPkey>,
    /// Flag indicating if the operation has been finalized.
    finalized: bool,
    /// Flag indicating if the operation is in progress.
    in_use: bool,
    /// The underlying EVP MD CTX (non fips builds)
    #[cfg(not(feature = "fips"))]
    sigctx: Option<EvpMdCtx>,
    /// The underlying wrapped `EVP_SIGNATURE` context (fips builds)
    #[cfg(feature = "fips")]
    sigctx: Option<ProviderSignatureCtx>,
    /// Optional storage for signatures, used when the signature to verify
    /// is provided at initialization
    signature: Option<Vec<u8>>,
}

impl EcdsaOperation {
    /// Helper function to create a new boxed `EcdsaMechanism`.
    fn new_mechanism() -> Box<dyn Mechanism> {
        Box::new(EcdsaMechanism::new(
            CK_ULONG::try_from(MIN_EC_SIZE_BITS).unwrap(),
            CK_ULONG::try_from(MAX_EC_SIZE_BITS).unwrap(),
            CKF_SIGN | CKF_VERIFY,
        ))
    }

    /// Registers all supported ECDSA mechanisms with the `Mechanisms` registry.
    pub fn register_mechanisms(mechs: &mut Mechanisms) {
        for ckm in &[
            CKM_ECDSA,
            CKM_ECDSA_SHA1,
            CKM_ECDSA_SHA224,
            CKM_ECDSA_SHA256,
            CKM_ECDSA_SHA384,
            CKM_ECDSA_SHA512,
            CKM_ECDSA_SHA3_224,
            CKM_ECDSA_SHA3_256,
            CKM_ECDSA_SHA3_384,
            CKM_ECDSA_SHA3_512,
        ] {
            mechs.add_mechanism(*ckm, Self::new_mechanism());
        }

        mechs.add_mechanism(
            CKM_EC_KEY_PAIR_GEN,
            Box::new(EcdsaMechanism::new(
                CK_ULONG::try_from(MIN_EC_SIZE_BITS).unwrap(),
                CK_ULONG::try_from(MAX_EC_SIZE_BITS).unwrap(),
                CKF_GENERATE_KEY_PAIR,
            )),
        );
    }

    /// Internal constructor to create a new `EcdsaOperation`.
    ///
    /// Sets up the internal state based on whether it's a signature or
    /// verification operation, imports the provided key, and calculates
    /// the expected signature length.
    fn new_op(
        flag: CK_FLAGS,
        mech: &CK_MECHANISM,
        key: &Object,
        signature: Option<Vec<u8>>,
    ) -> Result<EcdsaOperation> {
        let public_key: Option<EvpPkey>;
        let private_key: Option<EvpPkey>;
        let output_len: usize;
        match flag {
            CKF_SIGN => {
                public_key = None;
                let privkey = EvpPkey::privkey_from_object(key)?;
                output_len = 2 * ((privkey.get_bits()? + 7) / 8);
                private_key = Some(privkey);
            }
            CKF_VERIFY => {
                private_key = None;
                let pubkey = EvpPkey::pubkey_from_object(key)?;
                output_len = 2 * ((pubkey.get_bits()? + 7) / 8);
                if let Some(s) = &signature {
                    if s.len() != output_len {
                        return Err(CKR_SIGNATURE_LEN_RANGE)?;
                    }
                }
                public_key = Some(pubkey);
            }
            _ => return Err(CKR_GENERAL_ERROR)?,
        }
        Ok(EcdsaOperation {
            mech: mech.mechanism,
            output_len: output_len,
            public_key: public_key,
            private_key: private_key,
            finalized: false,
            in_use: false,
            sigctx: match mech.mechanism {
                CKM_ECDSA => None,
                #[cfg(feature = "fips")]
                _ => Some(ProviderSignatureCtx::new(name_as_char(ECDSA_NAME))?),
                #[cfg(not(feature = "fips"))]
                _ => Some(EvpMdCtx::new()?),
            },
            signature: signature,
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
    #[cfg(feature = "pkcs11_3_2")]
    pub fn verify_signature_new(
        mech: &CK_MECHANISM,
        key: &Object,
        _: &CK_MECHANISM_INFO,
        signature: &[u8],
    ) -> Result<EcdsaOperation> {
        Self::new_op(CKF_VERIFY, mech, key, Some(signature.to_vec()))
    }

    /// Generates an EC key pair using OpenSSL.
    ///
    /// Takes mutable references to pre-created public and private key
    /// `Object`s (which contain the desired curve in CKA_EC_PARAMS),
    /// generates the key pair, and populates the CKA_EC_POINT and CKA_VALUE
    /// attributes.
    pub fn generate_keypair(
        pubkey: &mut Object,
        privkey: &mut Object,
    ) -> Result<()> {
        let mut params = OsslParam::with_capacity(1);
        params.add_const_c_string(
            name_as_char(OSSL_PKEY_PARAM_GROUP_NAME),
            name_as_char(get_ossl_name_from_obj(pubkey)?),
        )?;
        params.finalize();

        let evp_pkey = EvpPkey::generate(name_as_char(EC_NAME), &params)?;
        let params = evp_pkey.todata(EVP_PKEY_KEYPAIR)?;

        /* Public Key */
        let point_encoded = match asn1::write_single(
            &params.get_octet_string(name_as_char(OSSL_PKEY_PARAM_PUB_KEY))?,
        ) {
            Ok(b) => b,
            Err(_) => return Err(CKR_GENERAL_ERROR)?,
        };
        pubkey.set_attr(Attribute::from_bytes(CKA_EC_POINT, point_encoded))?;

        /* Private Key */
        privkey.set_attr(Attribute::from_bytes(
            CKA_VALUE,
            params.get_bn(name_as_char(OSSL_PKEY_PARAM_PRIV_KEY))?,
        ))?;
        Ok(())
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
        if self.mech == CKM_ECDSA {
            self.finalized = true;
            if signature.len() != self.output_len {
                return Err(CKR_SIGNATURE_LEN_RANGE)?;
            }
            let mut ctx = some_or_err!(mut self.private_key).new_ctx()?;
            let res = unsafe { EVP_PKEY_sign_init(ctx.as_mut_ptr()) };
            if res != 1 {
                return Err(CKR_DEVICE_ERROR)?;
            }

            let mut siglen = 0usize;
            let siglen_ptr: *mut usize = &mut siglen;
            let res = unsafe {
                EVP_PKEY_sign(
                    ctx.as_mut_ptr(),
                    std::ptr::null_mut(),
                    siglen_ptr,
                    data.as_ptr(),
                    data.len(),
                )
            };
            if res != 1 {
                return Err(CKR_DEVICE_ERROR)?;
            }

            let mut ossl_sign: Vec<u8> = Vec::with_capacity(siglen);
            ossl_sign.resize(siglen, 0);
            let res = unsafe {
                EVP_PKEY_sign(
                    ctx.as_mut_ptr(),
                    ossl_sign.as_mut_ptr(),
                    siglen_ptr,
                    data.as_ptr(),
                    data.len(),
                )
            };
            if res != 1 {
                return Err(CKR_DEVICE_ERROR)?;
            }
            ossl_sign.resize(siglen, 0);
            let ret = ossl_to_pkcs11_signature(&ossl_sign, signature);
            zeromem(ossl_sign.as_mut_slice());
            return ret;
        }
        self.sign_update(data)?;
        self.sign_final(signature)
    }

    fn sign_update(&mut self, data: &[u8]) -> Result<()> {
        if self.finalized {
            return Err(CKR_OPERATION_NOT_INITIALIZED)?;
        }
        if !self.in_use {
            if self.mech == CKM_ECDSA {
                return Err(CKR_OPERATION_NOT_INITIALIZED)?;
            }
            self.in_use = true;

            #[cfg(not(feature = "fips"))]
            if unsafe {
                EVP_DigestSignInit_ex(
                    self.sigctx.as_mut().unwrap().as_mut_ptr(),
                    std::ptr::null_mut(),
                    mech_type_to_digest_name(self.mech),
                    get_libctx(),
                    std::ptr::null(),
                    some_or_err!(mut self.private_key).as_mut_ptr(),
                    std::ptr::null(),
                )
            } != 1
            {
                return Err(CKR_DEVICE_ERROR)?;
            }
            #[cfg(feature = "fips")]
            self.sigctx.as_mut().unwrap().digest_sign_init(
                mech_type_to_digest_name(self.mech),
                some_or_err!(self.private_key),
                std::ptr::null(),
            )?;
        }

        #[cfg(not(feature = "fips"))]
        {
            let res = unsafe {
                EVP_DigestSignUpdate(
                    self.sigctx.as_mut().unwrap().as_mut_ptr(),
                    data.as_ptr() as *const std::os::raw::c_void,
                    data.len(),
                )
            };
            if res != 1 {
                return Err(CKR_DEVICE_ERROR)?;
            }
            Ok(())
        }
        #[cfg(feature = "fips")]
        self.sigctx.as_mut().unwrap().digest_sign_update(data)
    }

    fn sign_final(&mut self, signature: &mut [u8]) -> Result<()> {
        if !self.in_use {
            return Err(CKR_OPERATION_NOT_INITIALIZED)?;
        }
        if self.finalized {
            return Err(CKR_OPERATION_NOT_INITIALIZED)?;
        }
        self.finalized = true;

        let mut siglen = signature.len() + 10;
        let mut ossl_sign = vec![0u8; siglen];

        #[cfg(not(feature = "fips"))]
        {
            let siglen_ptr = &mut siglen;
            if unsafe {
                EVP_DigestSignFinal(
                    self.sigctx.as_mut().unwrap().as_mut_ptr(),
                    ossl_sign.as_mut_ptr(),
                    siglen_ptr,
                )
            } != 1
            {
                return Err(CKR_DEVICE_ERROR)?;
            }
        }

        #[cfg(feature = "fips")]
        {
            siglen = self
                .sigctx
                .as_mut()
                .unwrap()
                .digest_sign_final(&mut ossl_sign)?;
        }
        if siglen > ossl_sign.len() {
            return Err(CKR_DEVICE_ERROR)?;
        }

        /* can only shrink */
        unsafe {
            ossl_sign.set_len(siglen);
        }

        let ret = ossl_to_pkcs11_signature(&ossl_sign, signature);
        zeromem(ossl_sign.as_mut_slice());
        ret
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
            let mut ctx = some_or_err!(mut self.public_key).new_ctx()?;
            let res = unsafe { EVP_PKEY_verify_init(ctx.as_mut_ptr()) };
            if res != 1 {
                return Err(CKR_DEVICE_ERROR)?;
            }

            // convert PKCS #11 signature to OpenSSL format
            let mut ossl_sign = match signature {
                Some(s) => {
                    if s.len() != self.output_len {
                        return Err(CKR_SIGNATURE_LEN_RANGE)?;
                    }
                    pkcs11_to_ossl_signature(s)?
                }
                None => match &self.signature {
                    Some(s) => pkcs11_to_ossl_signature(s.as_slice())?,
                    None => return Err(CKR_GENERAL_ERROR)?,
                },
            };

            self.finalized = true;

            let res = unsafe {
                EVP_PKEY_verify(
                    ctx.as_mut_ptr(),
                    ossl_sign.as_ptr(),
                    ossl_sign.len(),
                    data.as_ptr(),
                    data.len(),
                )
            };
            if res != 1 {
                return Err(CKR_SIGNATURE_INVALID)?;
            }
            zeromem(ossl_sign.as_mut_slice());
            return Ok(());
        }
        self.verify_int_update(data)?;
        self.verify_int_final(signature)
    }

    /// Internal helper for updating a multi-part verification.
    fn verify_int_update(&mut self, data: &[u8]) -> Result<()> {
        if self.finalized {
            return Err(CKR_OPERATION_NOT_INITIALIZED)?;
        }
        if !self.in_use {
            if self.mech == CKM_ECDSA {
                return Err(CKR_OPERATION_NOT_INITIALIZED)?;
            }
            self.in_use = true;

            #[cfg(not(feature = "fips"))]
            if unsafe {
                EVP_DigestVerifyInit_ex(
                    self.sigctx.as_mut().unwrap().as_mut_ptr(),
                    std::ptr::null_mut(),
                    mech_type_to_digest_name(self.mech),
                    get_libctx(),
                    std::ptr::null(),
                    some_or_err!(mut self.public_key).as_mut_ptr(),
                    std::ptr::null(),
                )
            } != 1
            {
                return Err(CKR_DEVICE_ERROR)?;
            }
            #[cfg(feature = "fips")]
            self.sigctx.as_mut().unwrap().digest_verify_init(
                mech_type_to_digest_name(self.mech),
                some_or_err!(self.public_key),
                std::ptr::null(),
            )?;
        }

        #[cfg(not(feature = "fips"))]
        {
            let res = unsafe {
                EVP_DigestVerifyUpdate(
                    self.sigctx.as_mut().unwrap().as_mut_ptr(),
                    data.as_ptr() as *const std::os::raw::c_void,
                    data.len(),
                )
            };
            if res != 1 {
                return Err(CKR_DEVICE_ERROR)?;
            }
            Ok(())
        }

        #[cfg(feature = "fips")]
        self.sigctx.as_mut().unwrap().digest_verify_update(data)
    }

    /// Internal helper for the final step of multi-part verification.
    fn verify_int_final(&mut self, signature: Option<&[u8]>) -> Result<()> {
        if !self.in_use {
            return Err(CKR_OPERATION_NOT_INITIALIZED)?;
        }
        if self.finalized {
            return Err(CKR_OPERATION_NOT_INITIALIZED)?;
        }

        // convert PKCS #11 signature to OpenSSL format
        let mut ossl_sign = match signature {
            Some(s) => {
                if s.len() != self.output_len {
                    return Err(CKR_SIGNATURE_LEN_RANGE)?;
                }
                pkcs11_to_ossl_signature(s)?
            }
            None => match &self.signature {
                Some(s) => pkcs11_to_ossl_signature(s.as_slice())?,
                None => return Err(CKR_GENERAL_ERROR)?,
            },
        };

        self.finalized = true;

        #[cfg(not(feature = "fips"))]
        if unsafe {
            EVP_DigestVerifyFinal(
                self.sigctx.as_mut().unwrap().as_mut_ptr(),
                ossl_sign.as_ptr(),
                ossl_sign.len(),
            )
        } != 1
        {
            return Err(CKR_SIGNATURE_INVALID)?;
        }

        #[cfg(feature = "fips")]
        self.sigctx
            .as_mut()
            .unwrap()
            .digest_verify_final(&ossl_sign)?;

        zeromem(ossl_sign.as_mut_slice());
        Ok(())
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

#[cfg(feature = "pkcs11_3_2")]
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
