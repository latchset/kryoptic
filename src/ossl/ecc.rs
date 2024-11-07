// Copyright 2023 - 2024 Simo Sorce, Jakub Jelen
// See LICENSE.txt file for terms

use core::ffi::c_int;

use crate::attribute::Attribute;
use crate::ecc::*;
use crate::ecc_misc::*;
use crate::error::Result;
use crate::interface::*;
use crate::kasn1::DerEncBigUint;
use crate::mechanism::*;
use crate::object::Object;
use crate::ossl::bindings::*;
use crate::ossl::common::*;
use crate::some_or_err;

#[cfg(feature = "fips")]
use crate::ossl::fips::*;

#[cfg(not(feature = "fips"))]
use crate::ossl::get_libctx;

use zeroize::Zeroize;

/* confusingly enough, this is not EC for FIPS-level operations  */
#[cfg(feature = "fips")]
static ECDSA_NAME: &[u8; 6] = b"ECDSA\0";
static EC_NAME: &[u8; 3] = b"EC\0";

fn make_bits_from_ec_params(key: &Object) -> Result<usize> {
    let x = match key.get_attr_as_bytes(CKA_EC_PARAMS) {
        Ok(b) => b,
        Err(_) => return Err(CKR_GENERAL_ERROR)?,
    };
    let bits = match asn1::parse_single::<ECParameters>(x) {
        Ok(a) => match a {
            ECParameters::OId(o) => oid_to_bits(o)?,
            ECParameters::CurveName(c) => curve_name_to_bits(c)?,
            _ => return Err(CKR_GENERAL_ERROR)?,
        },
        Err(_) => return Err(CKR_GENERAL_ERROR)?,
    };
    Ok(bits)
}

pub fn make_output_length_from_ecdsa_obj(key: &Object) -> Result<usize> {
    let bits = match make_bits_from_ec_params(key) {
        Ok(b) => b,
        Err(_) => return Err(CKR_GENERAL_ERROR)?,
    };
    Ok(2 * ((bits + 7) / 8))
}

pub fn get_curve_name_from_obj(key: &Object) -> Result<Vec<u8>> {
    let x = match key.get_attr_as_bytes(CKA_EC_PARAMS) {
        Ok(b) => b,
        Err(_) => return Err(CKR_GENERAL_ERROR)?,
    };
    let name = match asn1::parse_single::<ECParameters>(x) {
        Ok(a) => match a {
            ECParameters::OId(o) => oid_to_curve_name(o)?,
            ECParameters::CurveName(c) => c.as_str(),
            _ => return Err(CKR_GENERAL_ERROR)?,
        },
        Err(_) => return Err(CKR_GENERAL_ERROR)?,
    };
    let mut curve_name = Vec::with_capacity(name.len() + 1);
    curve_name.extend_from_slice(name.as_bytes());
    /* null byte terminator in c string */
    curve_name.push(0);
    Ok(curve_name)
}

fn get_ec_point_from_obj(key: &Object) -> Result<Vec<u8>> {
    let x = match key.get_attr_as_bytes(CKA_EC_POINT) {
        Ok(b) => b,
        Err(_) => return Err(CKR_GENERAL_ERROR)?,
    };

    /* [u8] is an octet string for the asn1 library */
    let octet = match asn1::parse_single::<&[u8]>(x) {
        Ok(a) => a,
        Err(_) => return Err(CKR_DEVICE_ERROR)?,
    };
    Ok(octet.to_vec())
}

pub fn make_ecdsa_public_key(
    curve_name: &Vec<u8>,
    ec_point: &Vec<u8>,
) -> Result<EvpPkey> {
    let mut params = OsslParam::with_capacity(2);
    params.zeroize = true;
    params.add_utf8_string(
        name_as_char(OSSL_PKEY_PARAM_GROUP_NAME),
        curve_name,
    )?;
    params.add_octet_string(name_as_char(OSSL_PKEY_PARAM_PUB_KEY), ec_point)?;
    params.finalize();

    EvpPkey::fromdata(name_as_char(EC_NAME), EVP_PKEY_PUBLIC_KEY, &params)
}

/// Convert the PKCS #11 public key object to OpenSSL EVP_PKEY
fn object_to_ecc_public_key(key: &Object) -> Result<EvpPkey> {
    make_ecdsa_public_key(
        &get_curve_name_from_obj(key)?,
        &get_ec_point_from_obj(key)?,
    )
}

/// Convert the PKCS #11 private key object to OpenSSL EVP_PKEY
pub fn ecdsa_object_to_ecc_private_key(key: &Object) -> Result<EvpPkey> {
    let curve_name = get_curve_name_from_obj(key)?;
    let mut params = OsslParam::with_capacity(2);
    params.zeroize = true;
    params.add_utf8_string(
        name_as_char(OSSL_PKEY_PARAM_GROUP_NAME),
        &curve_name,
    )?;
    params.add_bn(
        name_as_char(OSSL_PKEY_PARAM_PRIV_KEY),
        key.get_attr_as_bytes(CKA_VALUE)?,
    )?;
    params.finalize();

    EvpPkey::fromdata(name_as_char(EC_NAME), EVP_PKEY_PRIVATE_KEY, &params)
}

#[derive(asn1::Asn1Read, asn1::Asn1Write)]
struct EcdsaSignature<'a> {
    r: DerEncBigUint<'a>,
    s: DerEncBigUint<'a>,
}

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

#[derive(Debug)]
pub struct EccOperation {
    mech: CK_MECHANISM_TYPE,
    output_len: usize,
    public_key: Option<EvpPkey>,
    private_key: Option<EvpPkey>,
    finalized: bool,
    in_use: bool,
    #[cfg(not(feature = "fips"))]
    sigctx: Option<EvpMdCtx>,
    #[cfg(feature = "fips")]
    sigctx: Option<ProviderSignatureCtx>,
}

impl EccOperation {
    fn new_mechanism() -> Box<dyn Mechanism> {
        Box::new(EccMechanism::new(
            CK_ULONG::try_from(MIN_EC_SIZE_BITS).unwrap(),
            CK_ULONG::try_from(MAX_EC_SIZE_BITS).unwrap(),
            CKF_SIGN | CKF_VERIFY,
        ))
    }

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
            Box::new(EccMechanism::new(
                CK_ULONG::try_from(MIN_EC_SIZE_BITS).unwrap(),
                CK_ULONG::try_from(MAX_EC_SIZE_BITS).unwrap(),
                CKF_GENERATE_KEY_PAIR,
            )),
        );
    }

    pub fn sign_new(
        mech: &CK_MECHANISM,
        key: &Object,
        _: &CK_MECHANISM_INFO,
    ) -> Result<EccOperation> {
        Ok(EccOperation {
            mech: mech.mechanism,
            output_len: make_output_length_from_ecdsa_obj(key)?,
            public_key: None,
            private_key: Some(ecdsa_object_to_ecc_private_key(key)?),
            finalized: false,
            in_use: false,
            sigctx: match mech.mechanism {
                CKM_ECDSA => None,
                #[cfg(feature = "fips")]
                _ => Some(ProviderSignatureCtx::new(name_as_char(ECDSA_NAME))?),
                #[cfg(not(feature = "fips"))]
                _ => Some(EvpMdCtx::new()?),
            },
        })
    }

    pub fn verify_new(
        mech: &CK_MECHANISM,
        key: &Object,
        _: &CK_MECHANISM_INFO,
    ) -> Result<EccOperation> {
        Ok(EccOperation {
            mech: mech.mechanism,
            output_len: make_output_length_from_ecdsa_obj(key)?,
            public_key: Some(object_to_ecc_public_key(key)?),
            private_key: None,
            finalized: false,
            in_use: false,
            sigctx: match mech.mechanism {
                CKM_ECDSA => None,
                #[cfg(feature = "fips")]
                _ => Some(ProviderSignatureCtx::new(name_as_char(ECDSA_NAME))?),
                #[cfg(not(feature = "fips"))]
                _ => Some(EvpMdCtx::new()?),
            },
        })
    }

    pub fn generate_keypair(
        pubkey: &mut Object,
        privkey: &mut Object,
    ) -> Result<()> {
        let curve_name = get_curve_name_from_obj(pubkey)?;
        let mut params = OsslParam::with_capacity(1);
        params.add_utf8_string(
            name_as_char(OSSL_PKEY_PARAM_GROUP_NAME),
            &curve_name,
        )?;
        params.finalize();

        let evp_pkey = EvpPkey::generate(name_as_char(EC_NAME), &params)?;

        let mut params: *mut OSSL_PARAM = std::ptr::null_mut();
        let res = unsafe {
            EVP_PKEY_todata(
                evp_pkey.as_ptr(),
                c_int::try_from(EVP_PKEY_KEYPAIR)?,
                &mut params,
            )
        };
        if res != 1 {
            return Err(CKR_DEVICE_ERROR)?;
        }
        let params = OsslParam::from_ptr(params)?;
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

impl MechOperation for EccOperation {
    fn mechanism(&self) -> Result<CK_MECHANISM_TYPE> {
        Ok(self.mech)
    }

    fn finalized(&self) -> bool {
        self.finalized
    }
}

impl Sign for EccOperation {
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
                return Err(CKR_GENERAL_ERROR)?;
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
            ossl_sign.zeroize();
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
        ossl_sign.zeroize();
        ret
    }

    fn signature_len(&self) -> Result<usize> {
        Ok(self.output_len)
    }
}

impl Verify for EccOperation {
    fn verify(&mut self, data: &[u8], signature: &[u8]) -> Result<()> {
        if self.in_use {
            return Err(CKR_OPERATION_NOT_INITIALIZED)?;
        }
        if self.finalized {
            return Err(CKR_OPERATION_NOT_INITIALIZED)?;
        }
        if self.mech == CKM_ECDSA {
            if signature.len() != self.output_len {
                return Err(CKR_GENERAL_ERROR)?; // already checked in fn_verify
            }
            let mut ctx = some_or_err!(mut self.public_key).new_ctx()?;
            let res = unsafe { EVP_PKEY_verify_init(ctx.as_mut_ptr()) };
            if res != 1 {
                return Err(CKR_DEVICE_ERROR)?;
            }

            // convert PKCS #11 signature to OpenSSL format
            let mut ossl_sign = pkcs11_to_ossl_signature(signature)?;

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
            ossl_sign.zeroize();
            return Ok(());
        }
        self.verify_update(data)?;
        self.verify_final(signature)
    }

    fn verify_update(&mut self, data: &[u8]) -> Result<()> {
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

    fn verify_final(&mut self, signature: &[u8]) -> Result<()> {
        if !self.in_use {
            return Err(CKR_OPERATION_NOT_INITIALIZED)?;
        }
        if self.finalized {
            return Err(CKR_OPERATION_NOT_INITIALIZED)?;
        }

        // convert PKCS #11 signature to OpenSSL format
        let mut ossl_sign = pkcs11_to_ossl_signature(signature)?;

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

        ossl_sign.zeroize();
        Ok(())
    }

    fn signature_len(&self) -> Result<usize> {
        Ok(self.output_len)
    }
}
