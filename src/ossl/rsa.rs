// Copyright 2023 Simo Sorce
// See LICENSE.txt file for terms

#[cfg(feature = "fips")]
use super::fips;

use super::hash;
use super::mechanism;
use super::{bytes_to_vec, cast_params, some_or_err};

#[cfg(not(feature = "fips"))]
use super::ossl;

#[cfg(feature = "fips")]
use fips::*;

use hash::{hash_size, INVALID_HASH_SIZE};
use mechanism::*;

#[cfg(not(feature = "fips"))]
use ossl::*;

use std::os::raw::c_char;
use std::os::raw::c_int;
use std::os::raw::c_uint;
use zeroize::Zeroize;

#[cfg(not(feature = "fips"))]
pub const MIN_RSA_SIZE_BITS: usize = 1024;
#[cfg(feature = "fips")]
pub const MIN_RSA_SIZE_BITS: usize = 2048;

pub const MAX_RSA_SIZE_BITS: usize = 16536;
pub const MIN_RSA_SIZE_BYTES: usize = MIN_RSA_SIZE_BITS / 8;

static RSA_NAME: &[u8; 4] = b"RSA\0";

pub fn rsa_import(obj: &mut Object) -> Result<()> {
    let modulus = match obj.get_attr_as_bytes(CKA_MODULUS) {
        Ok(m) => m,
        Err(_) => return Err(CKR_TEMPLATE_INCOMPLETE)?,
    };
    match obj.get_attr_as_ulong(CKA_MODULUS_BITS) {
        Ok(_) => return Err(CKR_ATTRIBUTE_VALUE_INVALID)?,
        Err(e) => {
            if !e.attr_not_found() {
                return Err(e);
            }
        }
    }
    if modulus.len() < MIN_RSA_SIZE_BYTES {
        return Err(CKR_ATTRIBUTE_VALUE_INVALID)?;
    }
    match obj.get_attr_as_ulong(CKA_CLASS) {
        Ok(c) => match c {
            CKO_PUBLIC_KEY => {
                bytes_attr_not_empty!(obj; CKA_PUBLIC_EXPONENT);
            }
            CKO_PRIVATE_KEY => {
                bytes_attr_not_empty!(obj; CKA_PUBLIC_EXPONENT);
                bytes_attr_not_empty!(obj; CKA_PRIVATE_EXPONENT);
                /* The FIPS module can handle missing p,q,a,b,c */
            }
            _ => return Err(CKR_ATTRIBUTE_VALUE_INVALID)?,
        },
        Err(_) => return Err(CKR_TEMPLATE_INCOMPLETE)?,
    }

    Ok(())
}

fn object_to_rsa_public_key(key: &Object) -> Result<EvpPkey> {
    let mut params = OsslParam::with_capacity(2);
    params.zeroize = true;
    params.add_bn(
        name_as_char(OSSL_PKEY_PARAM_RSA_N),
        key.get_attr_as_bytes(CKA_MODULUS)?,
    )?;
    params.add_bn(
        name_as_char(OSSL_PKEY_PARAM_RSA_E),
        key.get_attr_as_bytes(CKA_PUBLIC_EXPONENT)?,
    )?;
    params.finalize();

    EvpPkey::fromdata(name_as_char(RSA_NAME), EVP_PKEY_PUBLIC_KEY, &params)
}

fn object_to_rsa_private_key(key: &Object) -> Result<EvpPkey> {
    let mut params = OsslParam::with_capacity(9);
    params.zeroize = true;
    params.add_bn(
        name_as_char(OSSL_PKEY_PARAM_RSA_N),
        key.get_attr_as_bytes(CKA_MODULUS)?,
    )?;
    params.add_bn(
        name_as_char(OSSL_PKEY_PARAM_RSA_E),
        key.get_attr_as_bytes(CKA_PUBLIC_EXPONENT)?,
    )?;
    params.add_bn(
        name_as_char(OSSL_PKEY_PARAM_RSA_D),
        key.get_attr_as_bytes(CKA_PRIVATE_EXPONENT)?,
    )?;

    /* OpenSSL can compute a,b,c with just p,q */
    if key.get_attr(CKA_PRIME_1).is_some()
        && key.get_attr(CKA_PRIME_2).is_some()
    {
        params.add_bn(
            name_as_char(OSSL_PKEY_PARAM_RSA_FACTOR1),
            key.get_attr_as_bytes(CKA_PRIME_1)?,
        )?;
        params.add_bn(
            name_as_char(OSSL_PKEY_PARAM_RSA_FACTOR2),
            key.get_attr_as_bytes(CKA_PRIME_2)?,
        )?;
    }

    if key.get_attr(CKA_EXPONENT_1).is_some()
        && key.get_attr(CKA_EXPONENT_2).is_some()
        && key.get_attr(CKA_COEFFICIENT).is_some()
    {
        params.add_bn(
            name_as_char(OSSL_PKEY_PARAM_RSA_EXPONENT1),
            key.get_attr_as_bytes(CKA_EXPONENT_1)?,
        )?;
        params.add_bn(
            name_as_char(OSSL_PKEY_PARAM_RSA_EXPONENT2),
            key.get_attr_as_bytes(CKA_EXPONENT_2)?,
        )?;
        params.add_bn(
            name_as_char(OSSL_PKEY_PARAM_RSA_COEFFICIENT1),
            key.get_attr_as_bytes(CKA_COEFFICIENT)?,
        )?;
    }
    params.finalize();

    EvpPkey::fromdata(name_as_char(RSA_NAME), EVP_PKEY_PRIVATE_KEY, &params)
}

fn mgf1_to_digest_name_as_slice(mech: CK_MECHANISM_TYPE) -> &'static [u8] {
    match mech {
        CKG_MGF1_SHA1 => OSSL_DIGEST_NAME_SHA1,
        CKG_MGF1_SHA224 => OSSL_DIGEST_NAME_SHA2_224,
        CKG_MGF1_SHA256 => OSSL_DIGEST_NAME_SHA2_256,
        CKG_MGF1_SHA384 => OSSL_DIGEST_NAME_SHA2_384,
        CKG_MGF1_SHA512 => OSSL_DIGEST_NAME_SHA2_512,
        CKG_MGF1_SHA3_224 => OSSL_DIGEST_NAME_SHA3_224,
        CKG_MGF1_SHA3_256 => OSSL_DIGEST_NAME_SHA3_256,
        CKG_MGF1_SHA3_384 => OSSL_DIGEST_NAME_SHA3_384,
        CKG_MGF1_SHA3_512 => OSSL_DIGEST_NAME_SHA3_512,
        _ => &[],
    }
}

#[derive(Debug)]
struct RsaPssParams {
    hash: CK_ULONG,
    mgf: CK_ULONG,
    saltlen: c_int,
}

fn no_pss_params() -> RsaPssParams {
    RsaPssParams {
        hash: 0,
        mgf: 0,
        saltlen: 0,
    }
}

fn parse_pss_params(mech: &CK_MECHANISM) -> Result<RsaPssParams> {
    match mech.mechanism {
        CKM_RSA_PKCS_PSS
        | CKM_SHA1_RSA_PKCS_PSS
        | CKM_SHA224_RSA_PKCS_PSS
        | CKM_SHA256_RSA_PKCS_PSS
        | CKM_SHA384_RSA_PKCS_PSS
        | CKM_SHA512_RSA_PKCS_PSS
        | CKM_SHA3_224_RSA_PKCS_PSS
        | CKM_SHA3_256_RSA_PKCS_PSS
        | CKM_SHA3_384_RSA_PKCS_PSS
        | CKM_SHA3_512_RSA_PKCS_PSS => {
            let params = cast_params!(mech, CK_RSA_PKCS_PSS_PARAMS);
            if mech.mechanism != CKM_RSA_PKCS_PSS {
                let mdname = mech_type_to_digest_name(params.hashAlg);
                if mech_type_to_digest_name(mech.mechanism) != mdname {
                    return Err(CKR_ARGUMENTS_BAD)?;
                }
            }
            Ok(RsaPssParams {
                hash: params.hashAlg,
                mgf: params.mgf,
                saltlen: c_int::try_from(params.sLen)?,
            })
        }
        _ => Ok(no_pss_params()),
    }
}

#[derive(Debug)]
struct RsaOaepParams {
    hash: CK_ULONG,
    mgf: CK_ULONG,
    source: Option<Vec<u8>>,
}

fn no_oaep_params() -> RsaOaepParams {
    RsaOaepParams {
        hash: 0,
        mgf: 0,
        source: None,
    }
}

fn parse_oaep_params(mech: &CK_MECHANISM) -> Result<RsaOaepParams> {
    if mech.mechanism != CKM_RSA_PKCS_OAEP {
        return Ok(no_oaep_params());
    }
    let params = cast_params!(mech, CK_RSA_PKCS_OAEP_PARAMS);
    let source = match params.source {
        0 => {
            if params.ulSourceDataLen != 0 {
                return Err(CKR_MECHANISM_PARAM_INVALID)?;
            }
            None
        }
        CKZ_DATA_SPECIFIED => match params.ulSourceDataLen {
            0 => None,
            _ => {
                Some(bytes_to_vec!(params.pSourceData, params.ulSourceDataLen))
            }
        },
        _ => return Err(CKR_MECHANISM_PARAM_INVALID)?,
    };

    Ok(RsaOaepParams {
        hash: params.hashAlg,
        mgf: params.mgf,
        source: source,
    })
}

#[derive(Debug)]
struct RsaPKCSOperation {
    mech: CK_MECHANISM_TYPE,
    max_input: usize,
    output_len: usize,
    public_key: Option<EvpPkey>,
    private_key: Option<EvpPkey>,
    finalized: bool,
    in_use: bool,
    #[cfg(feature = "fips")]
    sigctx: Option<ProviderSignatureCtx>,
    #[cfg(not(feature = "fips"))]
    sigctx: Option<EvpMdCtx>,
    pss: RsaPssParams,
    oaep: RsaOaepParams,
    #[cfg(feature = "fips")]
    fips_approved: Option<bool>,
}

impl RsaPKCSOperation {
    fn new_mechanism(flags: CK_FLAGS) -> Box<dyn Mechanism> {
        Box::new(RsaPKCSMechanism {
            info: CK_MECHANISM_INFO {
                ulMinKeySize: CK_ULONG::try_from(MIN_RSA_SIZE_BITS).unwrap(),
                ulMaxKeySize: CK_ULONG::try_from(MAX_RSA_SIZE_BITS).unwrap(),
                flags: flags,
            },
        })
    }

    fn register_mechanisms(mechs: &mut Mechanisms) {
        mechs.add_mechanism(
            CKM_RSA_PKCS,
            Self::new_mechanism(
                CKF_ENCRYPT
                    | CKF_DECRYPT
                    | CKF_SIGN
                    | CKF_VERIFY
                    | CKF_WRAP
                    | CKF_UNWRAP,
            ),
        );

        for ckm in &[
            CKM_SHA1_RSA_PKCS,
            CKM_SHA224_RSA_PKCS,
            CKM_SHA256_RSA_PKCS,
            CKM_SHA384_RSA_PKCS,
            CKM_SHA512_RSA_PKCS,
            CKM_SHA3_224_RSA_PKCS,
            CKM_SHA3_256_RSA_PKCS,
            CKM_SHA3_384_RSA_PKCS,
            CKM_SHA3_512_RSA_PKCS,
            CKM_RSA_PKCS_PSS,
            CKM_SHA1_RSA_PKCS_PSS,
            CKM_SHA224_RSA_PKCS_PSS,
            CKM_SHA256_RSA_PKCS_PSS,
            CKM_SHA384_RSA_PKCS_PSS,
            CKM_SHA512_RSA_PKCS_PSS,
            CKM_SHA3_224_RSA_PKCS_PSS,
            CKM_SHA3_256_RSA_PKCS_PSS,
            CKM_SHA3_384_RSA_PKCS_PSS,
            CKM_SHA3_512_RSA_PKCS_PSS,
        ] {
            mechs.add_mechanism(
                *ckm,
                Self::new_mechanism(CKF_SIGN | CKF_VERIFY),
            );
        }

        mechs.add_mechanism(
            CKM_RSA_PKCS_KEY_PAIR_GEN,
            Self::new_mechanism(CKF_GENERATE_KEY_PAIR),
        );

        mechs.add_mechanism(
            CKM_RSA_PKCS_OAEP,
            Self::new_mechanism(
                CKF_ENCRYPT | CKF_DECRYPT | CKF_WRAP | CKF_UNWRAP,
            ),
        );
    }

    fn hash_len(hash: CK_MECHANISM_TYPE) -> Result<usize> {
        match hash_size(hash) {
            INVALID_HASH_SIZE => Err(CKR_MECHANISM_INVALID)?,
            x => Ok(x),
        }
    }

    fn max_message_len(
        modulus: usize,
        mech: CK_MECHANISM_TYPE,
        hash: CK_MECHANISM_TYPE,
    ) -> Result<usize> {
        match mech {
            CKM_RSA_PKCS => Ok(modulus - 11),
            CKM_RSA_PKCS_OAEP => {
                let hs = Self::hash_len(hash)?;
                Ok(modulus - 2 * hs - 2)
            }
            _ => Err(CKR_MECHANISM_INVALID)?,
        }
    }

    fn encrypt_new(
        mech: &CK_MECHANISM,
        key: &Object,
        info: &CK_MECHANISM_INFO,
    ) -> Result<RsaPKCSOperation> {
        let modulus = key.get_attr_as_bytes(CKA_MODULUS)?;
        let modulus_bits: u64 = modulus.len() as u64 * 8;
        if modulus_bits < info.ulMinKeySize
            || (info.ulMaxKeySize != 0 && modulus_bits > info.ulMaxKeySize)
        {
            return Err(CKR_KEY_SIZE_RANGE)?;
        }
        let oaep_params = parse_oaep_params(mech)?;
        Ok(RsaPKCSOperation {
            mech: mech.mechanism,
            max_input: Self::max_message_len(
                modulus.len(),
                mech.mechanism,
                oaep_params.hash,
            )?,
            output_len: modulus.len(),
            public_key: Some(object_to_rsa_public_key(key)?),
            private_key: None,
            finalized: false,
            in_use: false,
            sigctx: None,
            pss: no_pss_params(),
            oaep: oaep_params,
            #[cfg(feature = "fips")]
            fips_approved: None,
        })
    }

    fn decrypt_new(
        mech: &CK_MECHANISM,
        key: &Object,
        info: &CK_MECHANISM_INFO,
    ) -> Result<RsaPKCSOperation> {
        let modulus = key.get_attr_as_bytes(CKA_MODULUS)?;
        let modulus_bits: u64 = modulus.len() as u64 * 8;
        if modulus_bits < info.ulMinKeySize
            || (info.ulMaxKeySize != 0 && modulus_bits > info.ulMaxKeySize)
        {
            return Err(CKR_KEY_SIZE_RANGE)?;
        }
        let oaep_params = parse_oaep_params(mech)?;
        Ok(RsaPKCSOperation {
            mech: mech.mechanism,
            max_input: modulus.len(),
            output_len: Self::max_message_len(
                modulus.len(),
                mech.mechanism,
                oaep_params.hash,
            )?,
            public_key: Some(object_to_rsa_public_key(key)?),
            private_key: Some(object_to_rsa_private_key(key)?),
            finalized: false,
            in_use: false,
            sigctx: None,
            pss: no_pss_params(),
            oaep: oaep_params,
            #[cfg(feature = "fips")]
            fips_approved: None,
        })
    }

    fn sign_new(
        mech: &CK_MECHANISM,
        key: &Object,
        info: &CK_MECHANISM_INFO,
    ) -> Result<RsaPKCSOperation> {
        let modulus = key.get_attr_as_bytes(CKA_MODULUS)?;
        let modulus_bits: u64 = modulus.len() as u64 * 8;
        if modulus_bits < info.ulMinKeySize
            || (info.ulMaxKeySize != 0 && modulus_bits > info.ulMaxKeySize)
        {
            return Err(CKR_KEY_SIZE_RANGE)?;
        }

        let pss_params = parse_pss_params(mech)?;
        Ok(RsaPKCSOperation {
            mech: mech.mechanism,
            max_input: match mech.mechanism {
                CKM_RSA_PKCS => modulus.len() - 11,
                CKM_RSA_PKCS_PSS => Self::hash_len(pss_params.hash)?,
                _ => 0,
            },
            output_len: modulus.len(),
            public_key: Some(object_to_rsa_public_key(key)?),
            private_key: Some(object_to_rsa_private_key(key)?),
            finalized: false,
            in_use: false,
            sigctx: match mech.mechanism {
                CKM_RSA_PKCS => None,
                #[cfg(feature = "fips")]
                _ => Some(ProviderSignatureCtx::new(name_as_char(RSA_NAME))?),
                #[cfg(not(feature = "fips"))]
                _ => Some(EvpMdCtx::new()?),
            },
            pss: pss_params,
            oaep: no_oaep_params(),
            #[cfg(feature = "fips")]
            fips_approved: None,
        })
    }

    fn verify_new(
        mech: &CK_MECHANISM,
        key: &Object,
        info: &CK_MECHANISM_INFO,
    ) -> Result<RsaPKCSOperation> {
        let modulus = key.get_attr_as_bytes(CKA_MODULUS)?;
        let modulus_bits: u64 = modulus.len() as u64 * 8;
        if modulus_bits < info.ulMinKeySize
            || (info.ulMaxKeySize != 0 && modulus_bits > info.ulMaxKeySize)
        {
            return Err(CKR_KEY_SIZE_RANGE)?;
        }

        let pss_params = parse_pss_params(mech)?;
        Ok(RsaPKCSOperation {
            mech: mech.mechanism,
            max_input: match mech.mechanism {
                CKM_RSA_PKCS => modulus.len() - 11,
                _ => 0,
            },
            output_len: modulus.len(),
            public_key: Some(object_to_rsa_public_key(key)?),
            private_key: None,
            finalized: false,
            in_use: false,
            sigctx: match mech.mechanism {
                CKM_RSA_PKCS => None,
                #[cfg(feature = "fips")]
                _ => Some(ProviderSignatureCtx::new(name_as_char(RSA_NAME))?),
                #[cfg(not(feature = "fips"))]
                _ => Some(EvpMdCtx::new()?),
            },
            pss: pss_params,
            oaep: no_oaep_params(),
            #[cfg(feature = "fips")]
            fips_approved: None,
        })
    }

    fn generate_keypair(
        exponent: Vec<u8>,
        bits: usize,
        pubkey: &mut Object,
        privkey: &mut Object,
    ) -> Result<()> {
        if bits < MIN_RSA_SIZE_BITS || bits > MAX_RSA_SIZE_BITS {
            return Err(CKR_ATTRIBUTE_VALUE_INVALID)?;
        }
        let c_bits = bits as c_uint;
        let mut params = OsslParam::with_capacity(2);
        params.add_bn(name_as_char(OSSL_PKEY_PARAM_RSA_E), &exponent)?;
        params.add_uint(name_as_char(OSSL_PKEY_PARAM_RSA_BITS), &c_bits)?;
        params.finalize();

        let evp_pkey = EvpPkey::generate(name_as_char(RSA_NAME), &params)?;

        let mut params: *mut OSSL_PARAM = std::ptr::null_mut();
        let res = unsafe {
            EVP_PKEY_todata(
                evp_pkey.as_ptr(),
                EVP_PKEY_KEYPAIR as std::os::raw::c_int,
                &mut params,
            )
        };
        if res != 1 {
            return Err(CKR_DEVICE_ERROR)?;
        }
        let params = OsslParam::from_ptr(params)?;
        /* Public Key (has E already set) */
        pubkey.set_attr(attribute::from_bytes(
            CKA_MODULUS,
            params.get_bn(name_as_char(OSSL_PKEY_PARAM_RSA_N))?,
        ))?;

        /* Private Key */
        privkey.set_attr(attribute::from_bytes(
            CKA_MODULUS,
            params.get_bn(name_as_char(OSSL_PKEY_PARAM_RSA_N))?,
        ))?;
        privkey.set_attr(attribute::from_bytes(
            CKA_PUBLIC_EXPONENT,
            params.get_bn(name_as_char(OSSL_PKEY_PARAM_RSA_E))?,
        ))?;
        privkey.set_attr(attribute::from_bytes(
            CKA_PRIVATE_EXPONENT,
            params.get_bn(name_as_char(OSSL_PKEY_PARAM_RSA_D))?,
        ))?;
        privkey.set_attr(attribute::from_bytes(
            CKA_PRIME_1,
            params.get_bn(name_as_char(OSSL_PKEY_PARAM_RSA_FACTOR1))?,
        ))?;
        privkey.set_attr(attribute::from_bytes(
            CKA_PRIME_2,
            params.get_bn(name_as_char(OSSL_PKEY_PARAM_RSA_FACTOR2))?,
        ))?;
        privkey.set_attr(attribute::from_bytes(
            CKA_EXPONENT_1,
            params.get_bn(name_as_char(OSSL_PKEY_PARAM_RSA_EXPONENT1))?,
        ))?;
        privkey.set_attr(attribute::from_bytes(
            CKA_EXPONENT_2,
            params.get_bn(name_as_char(OSSL_PKEY_PARAM_RSA_EXPONENT2))?,
        ))?;
        privkey.set_attr(attribute::from_bytes(
            CKA_COEFFICIENT,
            params.get_bn(name_as_char(OSSL_PKEY_PARAM_RSA_COEFFICIENT1))?,
        ))?;
        Ok(())
    }

    fn wrap(
        mech: &CK_MECHANISM,
        wrapping_key: &Object,
        mut keydata: Vec<u8>,
        output: &mut [u8],
        info: &CK_MECHANISM_INFO,
    ) -> Result<usize> {
        let mut op = match Self::encrypt_new(mech, wrapping_key, info) {
            Ok(o) => o,
            Err(e) => {
                keydata.zeroize();
                return Err(e);
            }
        };
        let result = op.encrypt(&keydata, output);
        keydata.zeroize();
        result
    }

    fn unwrap(
        mech: &CK_MECHANISM,
        wrapping_key: &Object,
        data: &[u8],
        info: &CK_MECHANISM_INFO,
    ) -> Result<Vec<u8>> {
        let mut op = Self::decrypt_new(mech, wrapping_key, info)?;
        let outlen = op.decrypt(data, &mut [])?;
        let mut result = vec![0u8; outlen];
        let outlen = op.decrypt(data, result.as_mut_slice())?;
        result.resize(outlen, 0);
        Ok(result)
    }

    fn rsa_sig_params(&self) -> Vec<OSSL_PARAM> {
        let mut params = Vec::<OSSL_PARAM>::new();
        match self.mech {
            CKM_RSA_PKCS
            | CKM_SHA1_RSA_PKCS
            | CKM_SHA224_RSA_PKCS
            | CKM_SHA256_RSA_PKCS
            | CKM_SHA384_RSA_PKCS
            | CKM_SHA512_RSA_PKCS
            | CKM_SHA3_224_RSA_PKCS
            | CKM_SHA3_256_RSA_PKCS
            | CKM_SHA3_384_RSA_PKCS
            | CKM_SHA3_512_RSA_PKCS => {
                params.push(unsafe {
                    OSSL_PARAM_construct_utf8_string(
                        OSSL_SIGNATURE_PARAM_PAD_MODE.as_ptr() as *const c_char,
                        OSSL_PKEY_RSA_PAD_MODE_PKCSV15.as_ptr() as *mut c_char,
                        OSSL_PKEY_RSA_PAD_MODE_PKCSV15.len(),
                    )
                });
            }
            CKM_RSA_PKCS_PSS
            | CKM_SHA1_RSA_PKCS_PSS
            | CKM_SHA224_RSA_PKCS_PSS
            | CKM_SHA256_RSA_PKCS_PSS
            | CKM_SHA384_RSA_PKCS_PSS
            | CKM_SHA512_RSA_PKCS_PSS
            | CKM_SHA3_224_RSA_PKCS_PSS
            | CKM_SHA3_256_RSA_PKCS_PSS
            | CKM_SHA3_384_RSA_PKCS_PSS
            | CKM_SHA3_512_RSA_PKCS_PSS => {
                params.push(unsafe {
                    OSSL_PARAM_construct_utf8_string(
                        OSSL_SIGNATURE_PARAM_PAD_MODE.as_ptr() as *const c_char,
                        OSSL_PKEY_RSA_PAD_MODE_PSS.as_ptr() as *mut c_char,
                        OSSL_PKEY_RSA_PAD_MODE_PSS.len(),
                    )
                });
                let hash = mech_type_to_digest_name(self.pss.hash);
                params.push(unsafe {
                    OSSL_PARAM_construct_utf8_string(
                        OSSL_SIGNATURE_PARAM_DIGEST.as_ptr() as *const c_char,
                        hash as *mut c_char,
                        0,
                    )
                });
                let mgf1 = mgf1_to_digest_name_as_slice(self.pss.mgf);
                params.push(unsafe {
                    OSSL_PARAM_construct_utf8_string(
                        OSSL_SIGNATURE_PARAM_MGF1_DIGEST.as_ptr()
                            as *const c_char,
                        mgf1.as_ptr() as *mut c_char,
                        mgf1.len() - 1,
                    )
                });
                params.push(unsafe {
                    OSSL_PARAM_construct_int(
                        OSSL_SIGNATURE_PARAM_PSS_SALTLEN.as_ptr()
                            as *const c_char,
                        &self.pss.saltlen as *const c_int as *mut c_int,
                    )
                });
            }
            _ => (),
        }
        params.push(unsafe { OSSL_PARAM_construct_end() });
        params
    }

    fn rsa_enc_params(&self) -> Vec<OSSL_PARAM> {
        let mut params = Vec::<OSSL_PARAM>::new();
        match self.mech {
            CKM_RSA_PKCS => {
                params.push(unsafe {
                    OSSL_PARAM_construct_utf8_string(
                        OSSL_PKEY_PARAM_PAD_MODE.as_ptr() as *const c_char,
                        OSSL_PKEY_RSA_PAD_MODE_PKCSV15.as_ptr() as *mut c_char,
                        OSSL_PKEY_RSA_PAD_MODE_PKCSV15.len(),
                    )
                });
            }
            CKM_RSA_PKCS_OAEP => {
                params.push(unsafe {
                    OSSL_PARAM_construct_utf8_string(
                        OSSL_PKEY_PARAM_PAD_MODE.as_ptr() as *const c_char,
                        OSSL_PKEY_RSA_PAD_MODE_OAEP.as_ptr() as *mut c_char,
                        OSSL_PKEY_RSA_PAD_MODE_OAEP.len(),
                    )
                });
                let hash = mech_type_to_digest_name(self.oaep.hash);
                params.push(unsafe {
                    OSSL_PARAM_construct_utf8_string(
                        OSSL_ASYM_CIPHER_PARAM_OAEP_DIGEST.as_ptr()
                            as *const c_char,
                        hash as *mut c_char,
                        0,
                    )
                });
                let mgf1 = mgf1_to_digest_name_as_slice(self.oaep.mgf);
                params.push(unsafe {
                    OSSL_PARAM_construct_utf8_string(
                        OSSL_PKEY_PARAM_MGF1_DIGEST.as_ptr() as *const c_char,
                        mgf1.as_ptr() as *mut c_char,
                        mgf1.len() - 1,
                    )
                });
                match &self.oaep.source {
                    None => (),
                    Some(s) => params.push(unsafe {
                        OSSL_PARAM_construct_octet_string(
                            OSSL_ASYM_CIPHER_PARAM_OAEP_LABEL.as_ptr()
                                as *const c_char,
                            s.as_ptr() as *mut _,
                            s.len(),
                        )
                    }),
                }
            }
            _ => (),
        }
        params.push(unsafe { OSSL_PARAM_construct_end() });
        params
    }
}

impl MechOperation for RsaPKCSOperation {
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

impl Encryption for RsaPKCSOperation {
    fn encrypt(&mut self, plain: &[u8], cipher: &mut [u8]) -> Result<usize> {
        if self.in_use {
            return Err(CKR_OPERATION_NOT_INITIALIZED)?;
        }
        if self.finalized {
            return Err(CKR_OPERATION_NOT_INITIALIZED)?;
        }
        let mut ctx = some_or_err!(mut self.public_key).new_ctx()?;
        if unsafe { EVP_PKEY_encrypt_init(ctx.as_mut_ptr()) } != 1 {
            return Err(CKR_DEVICE_ERROR)?;
        }
        let params = self.rsa_enc_params();
        if unsafe { EVP_PKEY_CTX_set_params(ctx.as_mut_ptr(), params.as_ptr()) }
            != 1
        {
            return Err(CKR_DEVICE_ERROR)?;
        }

        let mut outlen = 0;
        let outlen_ptr: *mut usize = &mut outlen;
        if unsafe {
            EVP_PKEY_encrypt(
                ctx.as_mut_ptr(),
                std::ptr::null_mut(),
                outlen_ptr,
                plain.as_ptr(),
                plain.len(),
            )
        } != 1
        {
            return Err(CKR_DEVICE_ERROR)?;
        }
        if cipher.len() == 0 {
            return Ok(outlen);
        } else {
            if cipher.len() < outlen {
                return Err(error::Error::buf_too_small(outlen));
            }
        }

        self.finalized = true;

        if unsafe {
            EVP_PKEY_encrypt(
                ctx.as_mut_ptr(),
                cipher.as_mut_ptr(),
                outlen_ptr,
                plain.as_ptr(),
                plain.len(),
            )
        } != 1
        {
            return Err(CKR_DEVICE_ERROR)?;
        }
        Ok(outlen)
    }

    fn encrypt_update(
        &mut self,
        _plain: &[u8],
        _cipher: &mut [u8],
    ) -> Result<usize> {
        self.finalized = true;
        return Err(CKR_OPERATION_NOT_INITIALIZED)?;
    }

    fn encrypt_final(&mut self, _cipher: &mut [u8]) -> Result<usize> {
        self.finalized = true;
        return Err(CKR_OPERATION_NOT_INITIALIZED)?;
    }

    fn encryption_len(&mut self, _: usize, fin: bool) -> Result<usize> {
        if self.finalized {
            return Err(CKR_OPERATION_NOT_INITIALIZED)?;
        }
        if fin {
            self.finalized = true;
            return Err(CKR_OPERATION_NOT_INITIALIZED)?;
        }
        match self.mech {
            CKM_RSA_PKCS | CKM_RSA_PKCS_OAEP => Ok(self.output_len),
            _ => {
                self.finalized = true;
                Err(CKR_GENERAL_ERROR)?
            }
        }
    }
}

impl Decryption for RsaPKCSOperation {
    fn decrypt(&mut self, cipher: &[u8], plain: &mut [u8]) -> Result<usize> {
        if self.in_use {
            return Err(CKR_OPERATION_NOT_INITIALIZED)?;
        }
        if self.finalized {
            return Err(CKR_OPERATION_NOT_INITIALIZED)?;
        }
        let mut ctx = some_or_err!(mut self.private_key).new_ctx()?;
        let ret = unsafe { EVP_PKEY_decrypt_init(ctx.as_mut_ptr()) };
        if ret != 1 {
            return Err(CKR_DEVICE_ERROR)?;
        }
        let params = self.rsa_enc_params();
        let ret = unsafe {
            EVP_PKEY_CTX_set_params(ctx.as_mut_ptr(), params.as_ptr())
        };
        if ret != 1 {
            return Err(CKR_DEVICE_ERROR)?;
        }

        let mut outlen = 0usize;
        let outlen_ptr: *mut usize = &mut outlen;
        let ret = unsafe {
            EVP_PKEY_decrypt(
                ctx.as_mut_ptr(),
                std::ptr::null_mut(),
                outlen_ptr,
                cipher.as_ptr(),
                cipher.len(),
            )
        };
        if ret != 1 {
            return Err(CKR_DEVICE_ERROR)?;
        }
        if plain.len() == 0 {
            return Ok(outlen);
        }
        let mut tmp_plain: Option<Vec<u8>> = None;
        let plain_ptr = if plain.len() < outlen {
            if plain.len() < self.output_len {
                return Err(CKR_BUFFER_TOO_SMALL)?;
            }
            /* the PKCS#11 documentation allows modules to pass
             * in a buffer that is shorter than modulus by the
             * amount taken by padding, while openssl requires
             * a full modulus long buffer, so we need to use a
             * temporary buffer here to bridge this mismatch */
            tmp_plain = Some(vec![0u8; outlen]);
            if let Some(ref mut p) = tmp_plain.as_mut() {
                p.as_mut_ptr()
            } else {
                return Err(CKR_GENERAL_ERROR)?;
            }
        } else {
            plain.as_mut_ptr()
        };

        self.finalized = true;

        let ret = unsafe {
            EVP_PKEY_decrypt(
                ctx.as_mut_ptr(),
                plain_ptr,
                outlen_ptr,
                cipher.as_ptr(),
                cipher.len(),
            )
        };
        if ret != 1 {
            return Err(CKR_DEVICE_ERROR)?;
        }
        match tmp_plain {
            Some(p) => {
                plain[..outlen].copy_from_slice(&p[..outlen]);
            }
            None => (),
        }
        Ok(outlen)
    }

    fn decrypt_update(
        &mut self,
        _cipher: &[u8],
        _plain: &mut [u8],
    ) -> Result<usize> {
        self.finalized = true;
        return Err(CKR_OPERATION_NOT_INITIALIZED)?;
    }

    fn decrypt_final(&mut self, _plain: &mut [u8]) -> Result<usize> {
        self.finalized = true;
        return Err(CKR_OPERATION_NOT_INITIALIZED)?;
    }

    fn decryption_len(&mut self, _: usize, fin: bool) -> Result<usize> {
        if self.finalized {
            return Err(CKR_OPERATION_NOT_INITIALIZED)?;
        }
        if fin {
            self.finalized = true;
            return Err(CKR_OPERATION_NOT_INITIALIZED)?;
        }
        match self.mech {
            CKM_RSA_PKCS | CKM_RSA_PKCS_OAEP => Ok(self.output_len),
            _ => {
                self.finalized = true;
                Err(CKR_GENERAL_ERROR)?
            }
        }
    }
}

impl Sign for RsaPKCSOperation {
    fn sign(&mut self, data: &[u8], signature: &mut [u8]) -> Result<()> {
        if self.in_use {
            return Err(CKR_OPERATION_NOT_INITIALIZED)?;
        }
        if self.finalized {
            return Err(CKR_OPERATION_NOT_INITIALIZED)?;
        }
        match self.mech {
            CKM_RSA_PKCS | CKM_RSA_PKCS_PSS => {
                self.finalized = true;
                if match self.mech {
                    CKM_RSA_PKCS => data.len() > self.max_input,
                    CKM_RSA_PKCS_PSS => data.len() != self.max_input,
                    _ => return Err(CKR_GENERAL_ERROR)?,
                } {
                    return Err(CKR_DATA_LEN_RANGE)?;
                }
                if signature.len() != self.output_len {
                    return Err(CKR_GENERAL_ERROR)?;
                }
                let mut ctx = some_or_err!(mut self.private_key).new_ctx()?;
                let res = unsafe { EVP_PKEY_sign_init(ctx.as_mut_ptr()) };
                if res != 1 {
                    return Err(CKR_DEVICE_ERROR)?;
                }
                let params = self.rsa_sig_params();
                let res = unsafe {
                    EVP_PKEY_CTX_set_params(ctx.as_mut_ptr(), params.as_ptr())
                };
                if res != 1 {
                    return Err(CKR_DEVICE_ERROR)?;
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
                    return Err(CKR_DEVICE_ERROR)?;
                }
                if signature.len() != siglen {
                    return Err(CKR_GENERAL_ERROR)?;
                }

                let res = unsafe {
                    EVP_PKEY_sign(
                        ctx.as_mut_ptr(),
                        signature.as_mut_ptr(),
                        siglen_ptr,
                        data.as_ptr(),
                        data.len(),
                    )
                };
                if res != 1 {
                    return Err(CKR_DEVICE_ERROR)?;
                }

                Ok(())
            }
            _ => {
                self.sign_update(data)?;
                self.sign_final(signature)
            }
        }
    }

    fn sign_update(&mut self, data: &[u8]) -> Result<()> {
        if self.finalized {
            return Err(CKR_OPERATION_NOT_INITIALIZED)?;
        }
        if !self.in_use {
            if self.mech == CKM_RSA_PKCS || self.mech == CKM_RSA_PKCS_PSS {
                return Err(CKR_OPERATION_NOT_INITIALIZED)?;
            }
            self.in_use = true;

            let params = self.rsa_sig_params();

            #[cfg(feature = "fips")]
            self.sigctx.as_mut().unwrap().digest_sign_init(
                mech_type_to_digest_name(self.mech),
                some_or_err!(self.private_key),
                params.as_ptr(),
            )?;
            #[cfg(not(feature = "fips"))]
            unsafe {
                let res = EVP_DigestSignInit_ex(
                    self.sigctx.as_mut().unwrap().as_mut_ptr(),
                    std::ptr::null_mut(),
                    mech_type_to_digest_name(self.mech),
                    get_libctx(),
                    std::ptr::null(),
                    some_or_err!(mut self.private_key).as_mut_ptr(),
                    params.as_ptr(),
                );
                if res != 1 {
                    return Err(CKR_DEVICE_ERROR)?;
                }
            }
        }

        #[cfg(feature = "fips")]
        {
            self.sigctx.as_mut().unwrap().digest_sign_update(data)
        }
        #[cfg(not(feature = "fips"))]
        unsafe {
            let res = EVP_DigestSignUpdate(
                self.sigctx.as_mut().unwrap().as_mut_ptr(),
                data.as_ptr() as *const std::os::raw::c_void,
                data.len(),
            );
            if res != 1 {
                Err(CKR_DEVICE_ERROR)?
            } else {
                Ok(())
            }
        }
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
        {
            match self.sigctx.as_mut().unwrap().digest_sign_final(signature) {
                Ok(siglen) => {
                    if siglen != signature.len() {
                        Err(CKR_DEVICE_ERROR)?
                    } else {
                        Ok(())
                    }
                }
                Err(_) => return Err(CKR_DEVICE_ERROR)?,
            }
        }
        #[cfg(not(feature = "fips"))]
        unsafe {
            let mut siglen = signature.len();
            let siglen_ptr = &mut siglen;

            let res = EVP_DigestSignFinal(
                self.sigctx.as_mut().unwrap().as_mut_ptr(),
                signature.as_mut_ptr(),
                siglen_ptr,
            );
            if res != 1 {
                Err(CKR_DEVICE_ERROR)?
            } else {
                Ok(())
            }
        }
    }

    fn signature_len(&self) -> Result<usize> {
        Ok(self.output_len)
    }
}

impl Verify for RsaPKCSOperation {
    fn verify(&mut self, data: &[u8], signature: &[u8]) -> Result<()> {
        if self.in_use {
            return Err(CKR_OPERATION_NOT_INITIALIZED)?;
        }
        if self.finalized {
            return Err(CKR_OPERATION_NOT_INITIALIZED)?;
        }
        if self.mech == CKM_RSA_PKCS {
            self.finalized = true;
            if data.len() > self.max_input {
                return Err(CKR_DATA_LEN_RANGE)?;
            }
            if signature.len() != self.output_len {
                return Err(CKR_GENERAL_ERROR)?;
            }
            let mut ctx = some_or_err!(mut self.public_key).new_ctx()?;
            let res = unsafe { EVP_PKEY_verify_init(ctx.as_mut_ptr()) };
            if res != 1 {
                return Err(CKR_DEVICE_ERROR)?;
            }
            let params = self.rsa_sig_params();
            let res = unsafe {
                EVP_PKEY_CTX_set_params(ctx.as_mut_ptr(), params.as_ptr())
            };
            if res != 1 {
                return Err(CKR_DEVICE_ERROR)?;
            }

            let res = unsafe {
                EVP_PKEY_verify(
                    ctx.as_mut_ptr(),
                    signature.as_ptr(),
                    signature.len(),
                    data.as_ptr(),
                    data.len(),
                )
            };
            if res != 1 {
                return Err(CKR_SIGNATURE_INVALID)?;
            }
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
            if self.mech == CKM_RSA_PKCS {
                return Err(CKR_OPERATION_NOT_INITIALIZED)?;
            }
            self.in_use = true;

            let params = self.rsa_sig_params();

            #[cfg(feature = "fips")]
            self.sigctx.as_mut().unwrap().digest_verify_init(
                mech_type_to_digest_name(self.mech),
                some_or_err!(self.public_key),
                params.as_ptr(),
            )?;
            #[cfg(not(feature = "fips"))]
            unsafe {
                let res = EVP_DigestVerifyInit_ex(
                    self.sigctx.as_mut().unwrap().as_mut_ptr(),
                    std::ptr::null_mut(),
                    mech_type_to_digest_name(self.mech),
                    get_libctx(),
                    std::ptr::null(),
                    some_or_err!(mut self.public_key).as_mut_ptr(),
                    params.as_ptr(),
                );
                if res != 1 {
                    return Err(CKR_DEVICE_ERROR)?;
                }
            }
        }

        #[cfg(feature = "fips")]
        {
            self.sigctx.as_mut().unwrap().digest_verify_update(data)
        }
        #[cfg(not(feature = "fips"))]
        unsafe {
            let res = EVP_DigestVerifyUpdate(
                self.sigctx.as_mut().unwrap().as_mut_ptr(),
                data.as_ptr() as *const std::os::raw::c_void,
                data.len(),
            );
            if res != 1 {
                Err(CKR_DEVICE_ERROR)?
            } else {
                Ok(())
            }
        }
    }

    fn verify_final(&mut self, signature: &[u8]) -> Result<()> {
        if !self.in_use {
            return Err(CKR_OPERATION_NOT_INITIALIZED)?;
        }
        if self.finalized {
            return Err(CKR_OPERATION_NOT_INITIALIZED)?;
        }
        self.finalized = true;

        #[cfg(feature = "fips")]
        {
            self.sigctx.as_mut().unwrap().digest_verify_final(signature)
        }
        #[cfg(not(feature = "fips"))]
        unsafe {
            let res = EVP_DigestVerifyFinal(
                self.sigctx.as_mut().unwrap().as_mut_ptr(),
                signature.as_ptr(),
                signature.len(),
            );
            if res != 1 {
                Err(CKR_SIGNATURE_INVALID)?
            } else {
                Ok(())
            }
        }
    }

    fn signature_len(&self) -> Result<usize> {
        Ok(self.output_len)
    }
}
