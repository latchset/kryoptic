// Copyright 2023 - 2024 Simo Sorce, Jakub Jelen
// See LICENSE.txt file for terms

#[cfg(feature = "fips")]
use {super::fips, fips::*};

#[cfg(not(feature = "fips"))]
use {super::ossl, ossl::*};

use super::mechanism;

use kasn1::DerEncBigUint;
use mechanism::*;

use zeroize::Zeroize;

pub fn ecc_import(obj: &mut Object) -> KResult<()> {
    bytes_attr_not_empty!(obj; CKA_EC_PARAMS);
    bytes_attr_not_empty!(obj; CKA_VALUE);
    Ok(())
}

/* confusingly enough, this is not EC for FIPS-level operations  */
#[cfg(feature = "fips")]
static ECDSA_NAME: &[u8; 6] = b"ECDSA\0";
static EC_NAME: &[u8; 3] = b"EC\0";

#[cfg(not(feature = "fips"))]
#[derive(Debug)]
struct EccOperation {
    mech: CK_MECHANISM_TYPE,
    output_len: usize,
    public_key: EvpPkey,
    private_key: EvpPkey,
    finalized: bool,
    in_use: bool,
    sigctx: Option<EvpMdCtx>,
}

#[cfg(feature = "fips")]
#[derive(Debug)]
struct EccOperation {
    mech: CK_MECHANISM_TYPE,
    output_len: usize,
    public_key: EvpPkey,
    private_key: EvpPkey,
    finalized: bool,
    in_use: bool,
    sigctx: Option<ProviderSignatureCtx>,
}

fn make_bits_from_ec_params(key: &Object) -> KResult<usize> {
    let x = match key.get_attr_as_bytes(CKA_EC_PARAMS) {
        Ok(b) => b,
        Err(_) => return err_rv!(CKR_GENERAL_ERROR),
    };
    let bits = match asn1::parse_single::<ECParameters>(x) {
        Ok(a) => match a {
            ECParameters::OId(o) => oid_to_bits(o)?,
            ECParameters::CurveName(c) => curve_name_to_bits(c)?,
            _ => return err_rv!(CKR_GENERAL_ERROR),
        },
        Err(_) => return err_rv!(CKR_GENERAL_ERROR),
    };
    Ok(bits)
}

fn make_output_length_from_obj(key: &Object) -> KResult<usize> {
    let bits = match make_bits_from_ec_params(key) {
        Ok(b) => b,
        Err(_) => return err_rv!(CKR_GENERAL_ERROR),
    };
    Ok(2 * ((bits + 7) / 8))
}

fn new_pkey_ctx() -> KResult<EvpPkeyCtx> {
    Ok(EvpPkeyCtx::from_ptr(unsafe {
        EVP_PKEY_CTX_new_from_name(
            get_libctx(),
            name_as_char(EC_NAME),
            std::ptr::null(),
        )
    })?)
}

fn get_curve_name_from_obj(key: &Object) -> KResult<Vec<u8>> {
    let x = match key.get_attr_as_bytes(CKA_EC_PARAMS) {
        Ok(b) => b,
        Err(_) => return err_rv!(CKR_GENERAL_ERROR),
    };
    let name = match asn1::parse_single::<ECParameters>(x) {
        Ok(a) => match a {
            ECParameters::OId(o) => oid_to_curve_name(o)?,
            ECParameters::CurveName(c) => c.as_str(),
            _ => return err_rv!(CKR_GENERAL_ERROR),
        },
        Err(_) => return err_rv!(CKR_GENERAL_ERROR),
    };
    let mut curve_name = Vec::with_capacity(name.len() + 1);
    curve_name.extend_from_slice(name.as_bytes());
    /* null byte terminator in c string */
    curve_name.push(0);
    Ok(curve_name)
}

fn get_ec_point_from_obj(key: &Object) -> KResult<Vec<u8>> {
    let x = match key.get_attr_as_bytes(CKA_EC_POINT) {
        Ok(b) => b,
        Err(_) => return err_rv!(CKR_GENERAL_ERROR),
    };

    /* [u8] is an octet string for the asn1 library */
    let octet = match asn1::parse_single::<&[u8]>(x) {
        Ok(a) => a,
        Err(_) => return err_rv!(CKR_DEVICE_ERROR),
    };
    let mut v = Vec::with_capacity(octet.len());
    v.extend_from_slice(octet);
    Ok(v)
}

/// Convert the PKCS #11 public key object to OpenSSL EVP_PKEY
fn object_to_ecc_public_key(key: &Object) -> KResult<EvpPkey> {
    let curve_name = get_curve_name_from_obj(key)?;
    let ec_point = get_ec_point_from_obj(key)?;
    let mut params = OsslParam::with_capacity(3)
        .set_zeroize()
        .add_utf8_string(name_as_char(OSSL_PKEY_PARAM_GROUP_NAME), &curve_name)?
        .add_octet_string(name_as_char(OSSL_PKEY_PARAM_PUB_KEY), &ec_point)?
        .finalize();

    let mut ctx = new_pkey_ctx()?;
    let res = unsafe { EVP_PKEY_fromdata_init(ctx.as_mut_ptr()) };
    if res != 1 {
        return err_rv!(CKR_DEVICE_ERROR);
    }
    let mut pkey: *mut EVP_PKEY = std::ptr::null_mut();
    let res = unsafe {
        EVP_PKEY_fromdata(
            ctx.as_mut_ptr(),
            &mut pkey,
            EVP_PKEY_PUBLIC_KEY as i32,
            params.as_mut_ptr(),
        )
    };
    if res != 1 {
        return err_rv!(CKR_DEVICE_ERROR);
    }
    EvpPkey::from_ptr(pkey)
}

/// Convert the PKCS #11 private key object to OpenSSL EVP_PKEY
fn object_to_ecc_private_key(key: &Object) -> KResult<EvpPkey> {
    let curve_name = get_curve_name_from_obj(key)?;
    let mut params = OsslParam::with_capacity(3)
        .set_zeroize()
        .add_utf8_string(name_as_char(OSSL_PKEY_PARAM_GROUP_NAME), &curve_name)?
        .add_bn_from_obj(
            key,
            CKA_VALUE,
            name_as_char(OSSL_PKEY_PARAM_PRIV_KEY),
        )?
        .finalize();

    let mut ctx = new_pkey_ctx()?;
    let res = unsafe { EVP_PKEY_fromdata_init(ctx.as_mut_ptr()) };
    if res != 1 {
        return err_rv!(CKR_DEVICE_ERROR);
    }
    let mut pkey: *mut EVP_PKEY = std::ptr::null_mut();
    let res = unsafe {
        EVP_PKEY_fromdata(
            ctx.as_mut_ptr(),
            &mut pkey,
            EVP_PKEY_PRIVATE_KEY as i32,
            params.as_mut_ptr(),
        )
    };
    if res != 1 {
        return err_rv!(CKR_DEVICE_ERROR);
    }
    EvpPkey::from_ptr(pkey)
}

#[derive(asn1::Asn1Read, asn1::Asn1Write)]
struct EcdsaSignature<'a> {
    r: DerEncBigUint<'a>,
    s: DerEncBigUint<'a>,
}

fn slice_to_sig_half(hin: &[u8], hout: &mut [u8]) -> KResult<()> {
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
            return err_rv!(CKR_GENERAL_ERROR);
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
) -> KResult<()> {
    let sig = match asn1::parse_single::<EcdsaSignature>(ossl_sign.as_slice()) {
        Ok(a) => a,
        Err(_) => return err_rv!(CKR_GENERAL_ERROR),
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
fn pkcs11_to_ossl_signature(signature: &[u8]) -> KResult<Vec<u8>> {
    let bn_len = signature.len() / 2;
    let sig = EcdsaSignature {
        r: DerEncBigUint::new(&signature[..bn_len])?,
        s: DerEncBigUint::new(&signature[bn_len..])?,
    };
    let ossl_sign = match asn1::write_single(&sig) {
        Ok(b) => b,
        Err(_) => return err_rv!(CKR_GENERAL_ERROR),
    };
    Ok(ossl_sign)
}

impl EccOperation {
    fn new_mechanism() -> Box<dyn Mechanism> {
        Box::new(EccMechanism {
            info: CK_MECHANISM_INFO {
                ulMinKeySize: MIN_EC_SIZE_BITS as CK_ULONG,
                ulMaxKeySize: MAX_EC_SIZE_BITS as CK_ULONG,
                flags: CKF_SIGN | CKF_VERIFY,
            },
        })
    }

    fn register_mechanisms(mechs: &mut Mechanisms) {
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
            Box::new(EccMechanism {
                info: CK_MECHANISM_INFO {
                    ulMinKeySize: MIN_EC_SIZE_BITS as CK_ULONG,
                    ulMaxKeySize: MAX_EC_SIZE_BITS as CK_ULONG,
                    flags: CKF_GENERATE_KEY_PAIR,
                },
            }),
        );
    }

    // todo derive?

    fn sign_new(
        mech: &CK_MECHANISM,
        key: &Object,
        _: &CK_MECHANISM_INFO,
    ) -> KResult<EccOperation> {
        Ok(EccOperation {
            mech: mech.mechanism,
            output_len: make_output_length_from_obj(key)?,
            public_key: empty_public_key(),
            private_key: object_to_ecc_private_key(key)?,
            finalized: false,
            in_use: false,
            sigctx: match mech.mechanism {
                CKM_ECDSA => None,
                #[cfg(feature = "fips")]
                _ => Some(ProviderSignatureCtx::new(name_as_char(ECDSA_NAME))?),
                #[cfg(not(feature = "fips"))]
                _ => Some(EvpMdCtx::from_ptr(unsafe { EVP_MD_CTX_new() })?),
            },
        })
    }

    fn verify_new(
        mech: &CK_MECHANISM,
        key: &Object,
        _: &CK_MECHANISM_INFO,
    ) -> KResult<EccOperation> {
        Ok(EccOperation {
            mech: mech.mechanism,
            output_len: make_output_length_from_obj(key)?,
            public_key: object_to_ecc_public_key(key)?,
            private_key: empty_private_key(),
            finalized: false,
            in_use: false,
            sigctx: match mech.mechanism {
                CKM_ECDSA => None,
                #[cfg(feature = "fips")]
                _ => Some(ProviderSignatureCtx::new(name_as_char(ECDSA_NAME))?),
                #[cfg(not(feature = "fips"))]
                _ => Some(EvpMdCtx::from_ptr(unsafe { EVP_MD_CTX_new() })?),
            },
        })
    }

    fn generate_keypair(
        pubkey: &mut Object,
        privkey: &mut Object,
    ) -> KResult<()> {
        let mut ctx = new_pkey_ctx()?;
        let res = unsafe { EVP_PKEY_keygen_init(ctx.as_mut_ptr()) };
        if res != 1 {
            return err_rv!(CKR_DEVICE_ERROR);
        }
        let curve_name = get_curve_name_from_obj(pubkey)?;
        let params = OsslParam::with_capacity(2)
            .add_utf8_string(
                name_as_char(OSSL_PKEY_PARAM_GROUP_NAME),
                &curve_name,
            )?
            .finalize();
        let res = unsafe {
            EVP_PKEY_CTX_set_params(ctx.as_mut_ptr(), params.as_ptr())
        };
        if res != 1 {
            return err_rv!(CKR_DEVICE_ERROR);
        }
        let mut pkey: *mut EVP_PKEY = std::ptr::null_mut();
        let res = unsafe { EVP_PKEY_generate(ctx.as_mut_ptr(), &mut pkey) };
        if res != 1 {
            return err_rv!(CKR_DEVICE_ERROR);
        }
        let evp_pkey = EvpPkey::from_ptr(pkey)?;
        let mut params: *mut OSSL_PARAM = std::ptr::null_mut();

        let res = unsafe {
            EVP_PKEY_todata(
                evp_pkey.as_ptr(),
                EVP_PKEY_KEYPAIR as std::os::raw::c_int,
                &mut params,
            )
        };
        if res != 1 {
            return err_rv!(CKR_DEVICE_ERROR);
        }
        let params = OsslParam::from_ptr(params)?;
        /* Public Key */
        let point =
            params.get_octet_string(name_as_char(OSSL_PKEY_PARAM_PUB_KEY))?;
        let point_encoded = match asn1::write_single(&point.as_slice()) {
            Ok(b) => b,
            Err(_) => return err_rv!(CKR_GENERAL_ERROR),
        };
        pubkey.set_attr(attribute::from_bytes(CKA_EC_POINT, point_encoded))?;

        /* Private Key */
        privkey.set_attr(attribute::from_bytes(
            CKA_VALUE,
            params.get_bn(name_as_char(OSSL_PKEY_PARAM_PRIV_KEY))?,
        ))?;
        Ok(())
    }
}

impl MechOperation for EccOperation {
    fn finalized(&self) -> bool {
        self.finalized
    }
}

impl Sign for EccOperation {
    fn sign(&mut self, data: &[u8], signature: &mut [u8]) -> KResult<()> {
        if self.in_use {
            return err_rv!(CKR_OPERATION_NOT_INITIALIZED);
        }
        if self.finalized {
            return err_rv!(CKR_OPERATION_NOT_INITIALIZED);
        }
        if self.mech == CKM_ECDSA {
            self.finalized = true;
            if signature.len() != self.output_len {
                return err_rv!(CKR_GENERAL_ERROR);
            }
            let mut ctx = EvpPkeyCtx::from_ptr(unsafe {
                EVP_PKEY_CTX_new_from_pkey(
                    get_libctx(),
                    self.private_key.as_mut_ptr(),
                    std::ptr::null_mut(),
                )
            })?;
            let res = unsafe { EVP_PKEY_sign_init(ctx.as_mut_ptr()) };
            if res != 1 {
                return err_rv!(CKR_DEVICE_ERROR);
            }

            self.finalized = true;

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
                return err_rv!(CKR_DEVICE_ERROR);
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
                return err_rv!(CKR_DEVICE_ERROR);
            }
            ossl_sign.resize(siglen, 0);
            let ret = ossl_to_pkcs11_signature(&ossl_sign, signature);
            ossl_sign.zeroize();
            return ret;
        }
        self.sign_update(data)?;
        self.sign_final(signature)
    }

    fn sign_update(&mut self, data: &[u8]) -> KResult<()> {
        if self.finalized {
            return err_rv!(CKR_OPERATION_NOT_INITIALIZED);
        }
        if !self.in_use {
            if self.mech == CKM_ECDSA {
                return err_rv!(CKR_OPERATION_NOT_INITIALIZED);
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
                    self.private_key.as_mut_ptr(),
                    std::ptr::null(),
                )
            } != 1
            {
                return err_rv!(CKR_DEVICE_ERROR);
            }
            #[cfg(feature = "fips")]
            self.sigctx.as_mut().unwrap().digest_sign_init(
                mech_type_to_digest_name(self.mech),
                &self.private_key,
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
                return err_rv!(CKR_DEVICE_ERROR);
            }
            Ok(())
        }
        #[cfg(feature = "fips")]
        self.sigctx.as_mut().unwrap().digest_sign_update(data)
    }

    fn sign_final(&mut self, signature: &mut [u8]) -> KResult<()> {
        if !self.in_use {
            return err_rv!(CKR_OPERATION_NOT_INITIALIZED);
        }
        if self.finalized {
            return err_rv!(CKR_OPERATION_NOT_INITIALIZED);
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
                return err_rv!(CKR_DEVICE_ERROR);
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
            return err_rv!(CKR_DEVICE_ERROR);
        }

        /* can only shrink */
        unsafe {
            ossl_sign.set_len(siglen);
        }

        let ret = ossl_to_pkcs11_signature(&ossl_sign, signature);
        ossl_sign.zeroize();
        ret
    }

    fn signature_len(&self) -> KResult<usize> {
        Ok(self.output_len)
    }
}

impl Verify for EccOperation {
    fn verify(&mut self, data: &[u8], signature: &[u8]) -> KResult<()> {
        if self.in_use {
            return err_rv!(CKR_OPERATION_NOT_INITIALIZED);
        }
        if self.finalized {
            return err_rv!(CKR_OPERATION_NOT_INITIALIZED);
        }
        if self.mech == CKM_ECDSA {
            if signature.len() != self.output_len {
                return err_rv!(CKR_GENERAL_ERROR); // already checked in fn_verify
            }
            let mut ctx = EvpPkeyCtx::from_ptr(unsafe {
                EVP_PKEY_CTX_new_from_pkey(
                    get_libctx(),
                    self.public_key.as_mut_ptr(),
                    std::ptr::null_mut(),
                )
            })?;
            let res = unsafe { EVP_PKEY_verify_init(ctx.as_mut_ptr()) };
            if res != 1 {
                return err_rv!(CKR_DEVICE_ERROR);
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
                return err_rv!(CKR_SIGNATURE_INVALID);
            }
            ossl_sign.zeroize();
            return Ok(());
        }
        self.verify_update(data)?;
        self.verify_final(signature)
    }

    fn verify_update(&mut self, data: &[u8]) -> KResult<()> {
        if self.finalized {
            return err_rv!(CKR_OPERATION_NOT_INITIALIZED);
        }
        if !self.in_use {
            if self.mech == CKM_ECDSA {
                return err_rv!(CKR_OPERATION_NOT_INITIALIZED);
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
                    self.public_key.as_mut_ptr(),
                    std::ptr::null(),
                )
            } != 1
            {
                return err_rv!(CKR_DEVICE_ERROR);
            }
            #[cfg(feature = "fips")]
            self.sigctx.as_mut().unwrap().digest_verify_init(
                mech_type_to_digest_name(self.mech),
                &self.public_key,
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
                return err_rv!(CKR_DEVICE_ERROR);
            }
            Ok(())
        }

        #[cfg(feature = "fips")]
        self.sigctx.as_mut().unwrap().digest_verify_update(data)
    }

    fn verify_final(&mut self, signature: &[u8]) -> KResult<()> {
        if !self.in_use {
            return err_rv!(CKR_OPERATION_NOT_INITIALIZED);
        }
        if self.finalized {
            return err_rv!(CKR_OPERATION_NOT_INITIALIZED);
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
            return err_rv!(CKR_SIGNATURE_INVALID);
        }

        #[cfg(feature = "fips")]
        self.sigctx
            .as_mut()
            .unwrap()
            .digest_verify_final(&ossl_sign)?;

        ossl_sign.zeroize();
        Ok(())
    }

    fn signature_len(&self) -> KResult<usize> {
        Ok(self.output_len)
    }
}
