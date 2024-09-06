// Copyright 2024 Simo Sorce
// See LICENSE.txt file for terms

#[cfg(feature = "fips")]
use {super::fips, fips::*};

#[cfg(not(feature = "fips"))]
use {super::ossl, ossl::*};

use super::{bytes_to_vec, map_err};

use constant_time_eq::constant_time_eq;
use std::ffi::{c_char, c_int, c_void};
use zeroize::Zeroize;

const MAX_CCM_BUF: usize = 1 << 20; /* 1MiB */

const AES_128_CBC_CTS: &[u8; 16] = b"AES-128-CBC-CTS\0";
const AES_192_CBC_CTS: &[u8; 16] = b"AES-192-CBC-CTS\0";
const AES_256_CBC_CTS: &[u8; 16] = b"AES-256-CBC-CTS\0";
const AES_128_WRAP_NAME: &[u8; 13] = b"AES-128-WRAP\0";
const AES_192_WRAP_NAME: &[u8; 13] = b"AES-192-WRAP\0";
const AES_256_WRAP_NAME: &[u8; 13] = b"AES-256-WRAP\0";
const AES_128_WRAP_PAD_NAME: &[u8; 17] = b"AES-128-WRAP-PAD\0";
const AES_192_WRAP_PAD_NAME: &[u8; 17] = b"AES-192-WRAP-PAD\0";
const AES_256_WRAP_PAD_NAME: &[u8; 17] = b"AES-256-WRAP-PAD\0";

/* It is safe to share const ciphers as they do not change once they have been
 * created, and reference static function pointers and other data that is
 * always valid */
struct AesCipher {
    cipher: Option<EvpCipher>,
}

impl AesCipher {
    pub fn new(name: *const u8) -> AesCipher {
        AesCipher {
            cipher: match EvpCipher::new(name as *const c_char) {
                Ok(ec) => Some(ec),
                Err(_) => None,
            },
        }
    }

    pub fn get_cipher(&self) -> Result<&EvpCipher> {
        if let Some(ref ec) = self.cipher {
            Ok(ec)
        } else {
            return err_rv!(CKR_MECHANISM_INVALID);
        }
    }
}

unsafe impl Send for AesCipher {}
unsafe impl Sync for AesCipher {}

macro_rules! aes_cipher {
    ($mode:ident; $name:expr) => {
        static $mode: Lazy<AesCipher> =
            Lazy::new(|| AesCipher::new($name.as_ptr()));
    };
}

aes_cipher!(AES_128_CCM; LN_aes_128_ccm);
aes_cipher!(AES_192_CCM; LN_aes_192_ccm);
aes_cipher!(AES_256_CCM; LN_aes_256_ccm);
aes_cipher!(AES_128_GCM; LN_aes_128_gcm);
aes_cipher!(AES_192_GCM; LN_aes_192_gcm);
aes_cipher!(AES_256_GCM; LN_aes_256_gcm);
aes_cipher!(AES_128_CTS; AES_128_CBC_CTS);
aes_cipher!(AES_192_CTS; AES_192_CBC_CTS);
aes_cipher!(AES_256_CTS; AES_256_CBC_CTS);
aes_cipher!(AES_128_CTR; LN_aes_128_ctr);
aes_cipher!(AES_192_CTR; LN_aes_192_ctr);
aes_cipher!(AES_256_CTR; LN_aes_256_ctr);
aes_cipher!(AES_128_CBC; LN_aes_128_cbc);
aes_cipher!(AES_192_CBC; LN_aes_192_cbc);
aes_cipher!(AES_256_CBC; LN_aes_256_cbc);
aes_cipher!(AES_128_ECB; LN_aes_128_ecb);
aes_cipher!(AES_192_ECB; LN_aes_192_ecb);
aes_cipher!(AES_256_ECB; LN_aes_256_ecb);
#[cfg(not(feature = "fips"))]
aes_cipher!(AES_128_CFB8; LN_aes_128_cfb8);
#[cfg(not(feature = "fips"))]
aes_cipher!(AES_192_CFB8; LN_aes_192_cfb8);
#[cfg(not(feature = "fips"))]
aes_cipher!(AES_256_CFB8; LN_aes_256_cfb8);
#[cfg(not(feature = "fips"))]
aes_cipher!(AES_128_CFB1; LN_aes_128_cfb1);
#[cfg(not(feature = "fips"))]
aes_cipher!(AES_192_CFB1; LN_aes_192_cfb1);
#[cfg(not(feature = "fips"))]
aes_cipher!(AES_256_CFB1; LN_aes_256_cfb1);
#[cfg(not(feature = "fips"))]
aes_cipher!(AES_128_CFB128; LN_aes_128_cfb128);
#[cfg(not(feature = "fips"))]
aes_cipher!(AES_192_CFB128; LN_aes_192_cfb128);
#[cfg(not(feature = "fips"))]
aes_cipher!(AES_256_CFB128; LN_aes_256_cfb128);
#[cfg(not(feature = "fips"))]
aes_cipher!(AES_128_OFB; LN_aes_128_ofb128);
#[cfg(not(feature = "fips"))]
aes_cipher!(AES_192_OFB; LN_aes_192_ofb128);
#[cfg(not(feature = "fips"))]
aes_cipher!(AES_256_OFB; LN_aes_256_ofb128);
aes_cipher!(AES_128_WRAP; AES_128_WRAP_NAME);
aes_cipher!(AES_192_WRAP; AES_192_WRAP_NAME);
aes_cipher!(AES_256_WRAP; AES_256_WRAP_NAME);
aes_cipher!(AES_128_WRAP_PAD; AES_128_WRAP_PAD_NAME);
aes_cipher!(AES_192_WRAP_PAD; AES_192_WRAP_PAD_NAME);
aes_cipher!(AES_256_WRAP_PAD; AES_256_WRAP_PAD_NAME);

#[derive(Debug)]
struct AesKey {
    raw: Vec<u8>,
}

impl Drop for AesKey {
    fn drop(&mut self) {
        self.raw.zeroize()
    }
}

fn object_to_raw_key(key: &Object) -> Result<AesKey> {
    let val = key.get_attr_as_bytes(CKA_VALUE)?;
    check_key_len(val.len())?;
    Ok(AesKey { raw: val.clone() })
}

fn new_mechanism(flags: CK_FLAGS) -> Box<dyn Mechanism> {
    Box::new(AesMechanism {
        info: CK_MECHANISM_INFO {
            ulMinKeySize: CK_ULONG::try_from(MIN_AES_SIZE_BYTES).unwrap(),
            ulMaxKeySize: CK_ULONG::try_from(MAX_AES_SIZE_BYTES).unwrap(),
            flags: flags,
        },
    })
}

#[derive(Debug)]
struct AesParams {
    iv: Vec<u8>,
    maxblocks: u128,
    ctsmode: u8,
    datalen: usize,
    aad: Vec<u8>,
    taglen: usize,
}

#[derive(Debug)]
struct AesOperation {
    mech: CK_MECHANISM_TYPE,
    key: AesKey,
    params: AesParams,
    finalized: bool,
    in_use: bool,
    ctx: EvpCipherCtx,
    finalbuf: Vec<u8>,
    blockctr: u128,
    #[cfg(feature = "fips")]
    fips_approved: Option<bool>,
}

impl Drop for AesOperation {
    fn drop(&mut self) {
        self.finalbuf.zeroize()
    }
}

impl AesOperation {
    fn register_mechanisms(mechs: &mut Mechanisms) {
        for ckm in &[
            CKM_AES_ECB,
            CKM_AES_CBC,
            CKM_AES_CBC_PAD,
            CKM_AES_CTR,
            CKM_AES_CTS,
            CKM_AES_GCM,
            CKM_AES_CCM,
            CKM_AES_KEY_WRAP,
            CKM_AES_KEY_WRAP_KWP,
        ] {
            mechs.add_mechanism(
                *ckm,
                new_mechanism(
                    CKF_ENCRYPT | CKF_DECRYPT | CKF_WRAP | CKF_UNWRAP,
                ),
            );
        }

        #[cfg(not(feature = "fips"))]
        for ckm in &[
            CKM_AES_OFB,
            CKM_AES_CFB128,
            CKM_AES_CFB1,
            CKM_AES_CFB8,
            /* OpenSSL does not implement AES CFB-64 */
        ] {
            mechs.add_mechanism(*ckm, new_mechanism(CKF_ENCRYPT | CKF_DECRYPT));
        }

        mechs.add_mechanism(CKM_AES_KEY_GEN, new_mechanism(CKF_GENERATE));
    }

    fn init_params(mech: &CK_MECHANISM) -> Result<AesParams> {
        match mech.mechanism {
            CKM_AES_CCM => {
                let params = cast_params!(mech, CK_CCM_PARAMS);
                if params.ulNonceLen < 7 || params.ulNonceLen > 13 {
                    return err_rv!(CKR_MECHANISM_PARAM_INVALID);
                }
                let l = 15 - params.ulNonceLen;
                if params.ulDataLen == 0
                    || params.ulDataLen > (1 << (8 * l))
                    || (params.ulDataLen + params.ulMACLen)
                        > CK_ULONG::try_from(u64::MAX)?
                {
                    return err_rv!(CKR_MECHANISM_PARAM_INVALID);
                }
                if params.ulAADLen > CK_ULONG::try_from(u32::MAX - 1)? {
                    return err_rv!(CKR_MECHANISM_PARAM_INVALID);
                }
                match params.ulMACLen {
                    4 | 6 | 8 | 10 | 12 | 14 | 16 => (),
                    _ => return err_rv!(CKR_MECHANISM_PARAM_INVALID),
                }
                Ok(AesParams {
                    iv: bytes_to_vec!(params.pNonce, params.ulNonceLen),
                    maxblocks: 0,
                    ctsmode: 0,
                    datalen: map_err!(
                        usize::try_from(params.ulDataLen),
                        CKR_MECHANISM_PARAM_INVALID
                    )?,
                    aad: bytes_to_vec!(params.pAAD, params.ulAADLen),
                    taglen: map_err!(
                        usize::try_from(params.ulMACLen),
                        CKR_MECHANISM_PARAM_INVALID
                    )?,
                })
            }
            CKM_AES_GCM => {
                let params = cast_params!(mech, CK_GCM_PARAMS);
                if params.ulIvLen == 0 || params.ulIvLen > (1 << 32) - 1 {
                    return err_rv!(CKR_MECHANISM_PARAM_INVALID);
                }
                if params.ulAADLen > (1 << 32) - 1 {
                    return err_rv!(CKR_MECHANISM_PARAM_INVALID);
                }
                if params.ulTagBits > 128 {
                    return err_rv!(CKR_MECHANISM_PARAM_INVALID);
                }
                if params.ulIvLen < 1 || params.pIv == std::ptr::null_mut() {
                    return err_rv!(CKR_MECHANISM_PARAM_INVALID);
                }
                let tagbits = map_err!(
                    usize::try_from(params.ulTagBits),
                    CKR_MECHANISM_PARAM_INVALID
                )?;
                Ok(AesParams {
                    iv: bytes_to_vec!(params.pIv, params.ulIvLen),
                    maxblocks: 0,
                    ctsmode: 0,
                    datalen: 0,
                    aad: bytes_to_vec!(params.pAAD, params.ulAADLen),
                    taglen: (tagbits + 7) / 8,
                })
            }
            CKM_AES_CTR => {
                let params = cast_params!(mech, CK_AES_CTR_PARAMS);
                let iv = params.cb.to_vec();
                let ctrbits = map_err!(
                    usize::try_from(params.ulCounterBits),
                    CKR_MECHANISM_PARAM_INVALID
                )?;
                let mut maxblocks = 0u128;
                if ctrbits < (AES_BLOCK_SIZE * 8) {
                    /* FIXME: support arbitrary counterbits wrapping.
                     * OpenSSL CTR mode is built to handle the whole IV
                     * as a 128bit counter unconditionally.
                     * For callers that want a smaller counterbit size all
                     * we can do is to set a maximum number of blocks so
                     * that the counter space does *not* wrap (because
                     * openssl won't wrap it but proceed to increment the
                     * octets part of the IV/Nonce). This means that for
                     * applications that initialize the counter to a value
                     * like 1 all will be fine, but application that
                     * initialize the counter to a random value and expect
                     * wrapping will see a failure instead of wrapping */
                    maxblocks = (1 << ctrbits) - 1;
                    let fulloctects = ctrbits / 8;
                    let mut idx = 0;
                    while fulloctects > idx {
                        maxblocks -= u128::try_from(iv[15 - idx])? << (idx * 8);
                        idx += 1;
                    }
                    let part = u128::try_from(ctrbits % 8)?;
                    if part > 0 {
                        maxblocks -=
                            (u128::try_from(iv[15 - idx])? & part) << (idx * 8);
                    }
                    if maxblocks == 0 {
                        return err_rv!(CKR_MECHANISM_PARAM_INVALID);
                    }
                } else if ctrbits > (AES_BLOCK_SIZE * 8) {
                    return err_rv!(CKR_MECHANISM_PARAM_INVALID);
                }

                Ok(AesParams {
                    iv: iv,
                    maxblocks: maxblocks,
                    ctsmode: 0,
                    datalen: 0,
                    aad: Vec::new(),
                    taglen: 0,
                })
            }
            CKM_AES_CTS | CKM_AES_CBC | CKM_AES_CBC_PAD => {
                if mech.ulParameterLen != CK_ULONG::try_from(AES_BLOCK_SIZE)? {
                    return err_rv!(CKR_ARGUMENTS_BAD);
                }
                let mut ctsmode = 0u8;
                if mech.mechanism == CKM_AES_CTS {
                    ctsmode = 1u8;
                }
                Ok(AesParams {
                    iv: bytes_to_vec!(mech.pParameter, mech.ulParameterLen),
                    maxblocks: 0,
                    ctsmode: ctsmode,
                    datalen: 0,
                    aad: Vec::new(),
                    taglen: 0,
                })
            }
            CKM_AES_ECB => Ok(AesParams {
                iv: Vec::with_capacity(0),
                maxblocks: 0,
                ctsmode: 0,
                datalen: 0,
                aad: Vec::new(),
                taglen: 0,
            }),
            #[cfg(not(feature = "fips"))]
            CKM_AES_CFB8 | CKM_AES_CFB1 | CKM_AES_CFB128 | CKM_AES_OFB => {
                if mech.ulParameterLen != CK_ULONG::try_from(AES_BLOCK_SIZE)? {
                    return err_rv!(CKR_ARGUMENTS_BAD);
                }
                Ok(AesParams {
                    iv: bytes_to_vec!(mech.pParameter, mech.ulParameterLen),
                    maxblocks: 0,
                    ctsmode: 0,
                    datalen: 0,
                    aad: Vec::new(),
                    taglen: 0,
                })
            }
            CKM_AES_KEY_WRAP => {
                let iv = match mech.ulParameterLen {
                    0 => Vec::new(),
                    8 => bytes_to_vec!(mech.pParameter, mech.ulParameterLen),
                    _ => return err_rv!(CKR_ARGUMENTS_BAD),
                };
                Ok(AesParams {
                    iv: iv,
                    maxblocks: 0,
                    ctsmode: 0,
                    datalen: 0,
                    aad: Vec::new(),
                    taglen: 0,
                })
            }
            CKM_AES_KEY_WRAP_KWP => {
                let iv = match mech.ulParameterLen {
                    0 => Vec::new(),
                    4 => bytes_to_vec!(mech.pParameter, mech.ulParameterLen),
                    _ => return err_rv!(CKR_ARGUMENTS_BAD),
                };
                Ok(AesParams {
                    iv: iv,
                    maxblocks: 0,
                    ctsmode: 0,
                    datalen: 0,
                    aad: Vec::new(),
                    taglen: 0,
                })
            }
            _ => err_rv!(CKR_MECHANISM_INVALID),
        }
    }

    fn init_cipher(
        mech: CK_MECHANISM_TYPE,
        keylen: usize,
    ) -> Result<&'static EvpCipher> {
        Ok(match mech {
            CKM_AES_CCM => match keylen {
                16 => AES_128_CCM.get_cipher()?,
                24 => AES_192_CCM.get_cipher()?,
                32 => AES_256_CCM.get_cipher()?,
                _ => return err_rv!(CKR_MECHANISM_INVALID),
            },
            CKM_AES_GCM => match keylen {
                16 => AES_128_GCM.get_cipher()?,
                24 => AES_192_GCM.get_cipher()?,
                32 => AES_256_GCM.get_cipher()?,
                _ => return err_rv!(CKR_MECHANISM_INVALID),
            },
            CKM_AES_CTS => match keylen {
                16 => AES_128_CTS.get_cipher()?,
                24 => AES_192_CTS.get_cipher()?,
                32 => AES_256_CTS.get_cipher()?,
                _ => return err_rv!(CKR_MECHANISM_INVALID),
            },
            CKM_AES_CTR => match keylen {
                16 => AES_128_CTR.get_cipher()?,
                24 => AES_192_CTR.get_cipher()?,
                32 => AES_256_CTR.get_cipher()?,
                _ => return err_rv!(CKR_MECHANISM_INVALID),
            },
            CKM_AES_CBC => match keylen {
                16 => AES_128_CBC.get_cipher()?,
                24 => AES_192_CBC.get_cipher()?,
                32 => AES_256_CBC.get_cipher()?,
                _ => return err_rv!(CKR_MECHANISM_INVALID),
            },
            CKM_AES_CBC_PAD => match keylen {
                16 => AES_128_CBC.get_cipher()?,
                24 => AES_192_CBC.get_cipher()?,
                32 => AES_256_CBC.get_cipher()?,
                _ => return err_rv!(CKR_MECHANISM_INVALID),
            },
            CKM_AES_ECB => match keylen {
                16 => AES_128_ECB.get_cipher()?,
                24 => AES_192_ECB.get_cipher()?,
                32 => AES_256_ECB.get_cipher()?,
                _ => return err_rv!(CKR_MECHANISM_INVALID),
            },
            #[cfg(not(feature = "fips"))]
            CKM_AES_CFB8 => match keylen {
                16 => AES_128_CFB8.get_cipher()?,
                24 => AES_192_CFB8.get_cipher()?,
                32 => AES_256_CFB8.get_cipher()?,
                _ => return err_rv!(CKR_MECHANISM_INVALID),
            },
            #[cfg(not(feature = "fips"))]
            CKM_AES_CFB1 => match keylen {
                16 => AES_128_CFB1.get_cipher()?,
                24 => AES_192_CFB1.get_cipher()?,
                32 => AES_256_CFB1.get_cipher()?,
                _ => return err_rv!(CKR_MECHANISM_INVALID),
            },
            #[cfg(not(feature = "fips"))]
            CKM_AES_CFB128 => match keylen {
                16 => AES_128_CFB128.get_cipher()?,
                24 => AES_192_CFB128.get_cipher()?,
                32 => AES_256_CFB128.get_cipher()?,
                _ => return err_rv!(CKR_MECHANISM_INVALID),
            },
            #[cfg(not(feature = "fips"))]
            CKM_AES_OFB => match keylen {
                16 => AES_128_OFB.get_cipher()?,
                24 => AES_192_OFB.get_cipher()?,
                32 => AES_256_OFB.get_cipher()?,
                _ => return err_rv!(CKR_MECHANISM_INVALID),
            },
            CKM_AES_KEY_WRAP => match keylen {
                16 => AES_128_WRAP.get_cipher()?,
                24 => AES_192_WRAP.get_cipher()?,
                32 => AES_256_WRAP.get_cipher()?,
                _ => return err_rv!(CKR_MECHANISM_INVALID),
            },
            CKM_AES_KEY_WRAP_KWP => match keylen {
                16 => AES_128_WRAP_PAD.get_cipher()?,
                24 => AES_192_WRAP_PAD.get_cipher()?,
                32 => AES_256_WRAP_PAD.get_cipher()?,
                _ => return err_rv!(CKR_MECHANISM_INVALID),
            },
            _ => return err_rv!(CKR_MECHANISM_INVALID),
        })
    }

    fn encrypt_initialize(&mut self) -> Result<()> {
        let evpcipher = match Self::init_cipher(self.mech, self.key.raw.len()) {
            Ok(c) => c,
            Err(e) => {
                self.finalized = true;
                return Err(e);
            }
        };

        /* Need to initialize the cipher on the ctx first, as some modes
         * will attempt to set parameters that require it on the context,
         * before key and iv can be installed */
        let res = unsafe {
            EVP_EncryptInit_ex2(
                self.ctx.as_mut_ptr(),
                evpcipher.as_ptr(),
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
            )
        };
        if res != 1 {
            self.finalized = true;
            return err_rv!(CKR_DEVICE_ERROR);
        }

        let mut params: Vec<OSSL_PARAM> = Vec::new();
        match self.mech {
            CKM_AES_GCM => {
                /* The IV size must be 12 in FIPS mode and if we try to
                 * actively set it to any value (including 12) in FIPS
                 * mode it will cause a cipher failure due to how
                 * OpenSSL sets internal states. So avoid setting the IVLEN
                 * when the ivsize matches the default */
                if self.params.iv.len() != 12 {
                    let res = unsafe {
                        EVP_CIPHER_CTX_ctrl(
                            self.ctx.as_mut_ptr(),
                            c_int::try_from(EVP_CTRL_AEAD_SET_IVLEN)?,
                            c_int::try_from(self.params.iv.len())?,
                            std::ptr::null_mut(),
                        )
                    };
                    if res != 1 {
                        self.finalized = true;
                        return err_rv!(CKR_DEVICE_ERROR);
                    }
                }
            }
            CKM_AES_CCM => {
                let res = unsafe {
                    EVP_CIPHER_CTX_ctrl(
                        self.ctx.as_mut_ptr(),
                        c_int::try_from(EVP_CTRL_AEAD_SET_IVLEN)?,
                        c_int::try_from(self.params.iv.len())?,
                        std::ptr::null_mut(),
                    )
                };
                if res != 1 {
                    self.finalized = true;
                    return err_rv!(CKR_DEVICE_ERROR);
                }
                let res = unsafe {
                    EVP_CIPHER_CTX_ctrl(
                        self.ctx.as_mut_ptr(),
                        c_int::try_from(EVP_CTRL_AEAD_SET_TAG)?,
                        c_int::try_from(self.params.taglen)?,
                        std::ptr::null_mut(),
                    )
                };
                if res != 1 {
                    self.finalized = true;
                    return err_rv!(CKR_DEVICE_ERROR);
                }
            }
            CKM_AES_CTS => unsafe {
                params =
                    vec![
                        OSSL_PARAM_construct_utf8_string(
                            OSSL_CIPHER_PARAM_CTS_MODE.as_ptr()
                                as *const c_char,
                            match self.params.ctsmode {
                                1 => OSSL_CIPHER_CTS_MODE_CS1.as_ptr()
                                    as *mut c_char,
                                2 => OSSL_CIPHER_CTS_MODE_CS2.as_ptr()
                                    as *mut c_char,
                                3 => OSSL_CIPHER_CTS_MODE_CS3.as_ptr()
                                    as *mut c_char,
                                _ => {
                                    self.finalized = true;
                                    return err_rv!(CKR_GENERAL_ERROR);
                                }
                            },
                            0,
                        ),
                        OSSL_PARAM_construct_end(),
                    ];
            },
            _ => (),
        }
        let params_ptr: *const OSSL_PARAM = if params.len() > 0 {
            params.as_ptr()
        } else {
            std::ptr::null()
        };

        /* set key, iv, additional params */
        let res = unsafe {
            EVP_EncryptInit_ex2(
                self.ctx.as_mut_ptr(),
                std::ptr::null(),
                self.key.raw.as_ptr(),
                if self.params.iv.len() != 0 {
                    self.params.iv.as_ptr()
                } else {
                    std::ptr::null()
                },
                params_ptr,
            )
        };
        if res != 1 {
            self.finalized = true;
            return err_rv!(CKR_DEVICE_ERROR);
        }
        if self.mech == CKM_AES_CBC_PAD {
            let res =
                unsafe { EVP_CIPHER_CTX_set_padding(self.ctx.as_mut_ptr(), 1) };
            if res != 1 {
                self.finalized = true;
                return err_rv!(CKR_DEVICE_ERROR);
            }
        }

        if self.mech == CKM_AES_CCM {
            let mut outl: c_int = 0;
            let res = unsafe {
                EVP_EncryptUpdate(
                    self.ctx.as_mut_ptr(),
                    std::ptr::null_mut(),
                    &mut outl,
                    std::ptr::null(),
                    c_int::try_from(self.params.datalen)?,
                )
            };
            if res != 1 {
                self.finalized = true;
                return err_rv!(CKR_DEVICE_ERROR);
            }
        }

        if self.params.aad.len() > 0 {
            let mut outl: c_int = 0;
            let res = unsafe {
                EVP_EncryptUpdate(
                    self.ctx.as_mut_ptr(),
                    std::ptr::null_mut(),
                    &mut outl,
                    self.params.aad.as_ptr(),
                    c_int::try_from(self.params.aad.len())?,
                )
            };
            if res != 1 {
                self.finalized = true;
                return err_rv!(CKR_DEVICE_ERROR);
            }
        }

        Ok(())
    }

    fn decrypt_initialize(&mut self) -> Result<()> {
        let evpcipher = match Self::init_cipher(self.mech, self.key.raw.len()) {
            Ok(c) => c,
            Err(e) => {
                self.finalized = true;
                return Err(e);
            }
        };

        let res = unsafe {
            EVP_DecryptInit_ex2(
                self.ctx.as_mut_ptr(),
                evpcipher.as_ptr(),
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
            )
        };
        if res != 1 {
            self.finalized = true;
            return err_rv!(CKR_DEVICE_ERROR);
        }
        let mut params: Vec<OSSL_PARAM> = Vec::new();
        match self.mech {
            CKM_AES_GCM => {
                /* The IV size must be 12 in FIPS mode and if we try to
                 * actively set it to any value (including 12) in FIPS
                 * mode it will cause a cipher failure due to how
                 * OpenSSL sets internal states. So avoid setting the IVLEN
                 * when the ivsize matches the default */
                if self.params.iv.len() != 12 {
                    let res = unsafe {
                        EVP_CIPHER_CTX_ctrl(
                            self.ctx.as_mut_ptr(),
                            c_int::try_from(EVP_CTRL_AEAD_SET_IVLEN)?,
                            c_int::try_from(self.params.iv.len())?,
                            std::ptr::null_mut(),
                        )
                    };
                    if res != 1 {
                        self.finalized = true;
                        return err_rv!(CKR_DEVICE_ERROR);
                    }
                }
            }
            CKM_AES_CCM => {
                let res = unsafe {
                    EVP_CIPHER_CTX_ctrl(
                        self.ctx.as_mut_ptr(),
                        c_int::try_from(EVP_CTRL_AEAD_SET_IVLEN)?,
                        c_int::try_from(self.params.iv.len())?,
                        std::ptr::null_mut(),
                    )
                };
                if res != 1 {
                    self.finalized = true;
                    return err_rv!(CKR_DEVICE_ERROR);
                }
                let res = unsafe {
                    EVP_CIPHER_CTX_ctrl(
                        self.ctx.as_mut_ptr(),
                        c_int::try_from(EVP_CTRL_AEAD_SET_TAG)?,
                        c_int::try_from(self.params.taglen)?,
                        std::ptr::null_mut(),
                    )
                };
                if res != 1 {
                    self.finalized = true;
                    return err_rv!(CKR_DEVICE_ERROR);
                }
            }
            CKM_AES_CTS => unsafe {
                params =
                    vec![
                        OSSL_PARAM_construct_utf8_string(
                            OSSL_CIPHER_PARAM_CTS_MODE.as_ptr()
                                as *const c_char,
                            match self.params.ctsmode {
                                1 => OSSL_CIPHER_CTS_MODE_CS1.as_ptr()
                                    as *mut c_char,
                                2 => OSSL_CIPHER_CTS_MODE_CS2.as_ptr()
                                    as *mut c_char,
                                3 => OSSL_CIPHER_CTS_MODE_CS3.as_ptr()
                                    as *mut c_char,
                                _ => {
                                    self.finalized = true;
                                    return err_rv!(CKR_GENERAL_ERROR);
                                }
                            },
                            0,
                        ),
                        OSSL_PARAM_construct_end(),
                    ];
            },
            _ => (),
        }
        let params_ptr: *const OSSL_PARAM = if params.len() > 0 {
            params.as_ptr()
        } else {
            std::ptr::null()
        };

        /* set key, iv, additional params */
        let res = unsafe {
            EVP_DecryptInit_ex2(
                self.ctx.as_mut_ptr(),
                std::ptr::null(),
                self.key.raw.as_ptr(),
                if self.params.iv.len() != 0 {
                    self.params.iv.as_ptr()
                } else {
                    std::ptr::null()
                },
                params_ptr,
            )
        };
        if res != 1 {
            self.finalized = true;
            return err_rv!(CKR_DEVICE_ERROR);
        }
        let res = unsafe {
            EVP_CIPHER_CTX_set_padding(
                self.ctx.as_mut_ptr(),
                if self.mech == CKM_AES_CBC_PAD { 1 } else { 0 },
            )
        };
        if res != 1 {
            self.finalized = true;
            return err_rv!(CKR_DEVICE_ERROR);
        }

        if self.mech == CKM_AES_CCM {
            let mut outl: c_int = 0;
            let res = unsafe {
                EVP_DecryptUpdate(
                    self.ctx.as_mut_ptr(),
                    std::ptr::null_mut(),
                    &mut outl,
                    std::ptr::null(),
                    c_int::try_from(self.params.datalen)?,
                )
            };
            if res != 1 {
                self.finalized = true;
                return err_rv!(CKR_DEVICE_ERROR);
            }
        }

        if self.params.aad.len() > 0 {
            let mut outl: c_int = 0;
            let res = unsafe {
                EVP_DecryptUpdate(
                    self.ctx.as_mut_ptr(),
                    std::ptr::null_mut(),
                    &mut outl,
                    self.params.aad.as_ptr(),
                    c_int::try_from(self.params.aad.len())?,
                )
            };
            if res != 1 {
                self.finalized = true;
                return err_rv!(CKR_DEVICE_ERROR);
            }
        }

        Ok(())
    }

    fn encrypt_new(mech: &CK_MECHANISM, key: &Object) -> Result<AesOperation> {
        Ok(AesOperation {
            mech: mech.mechanism,
            key: object_to_raw_key(key)?,
            params: Self::init_params(mech)?,
            finalized: false,
            in_use: false,
            ctx: EvpCipherCtx::new()?,
            finalbuf: Vec::new(),
            blockctr: 0,
            #[cfg(feature = "fips")]
            fips_approved: None,
        })
    }

    fn decrypt_new(mech: &CK_MECHANISM, key: &Object) -> Result<AesOperation> {
        Ok(AesOperation {
            mech: mech.mechanism,
            key: object_to_raw_key(key)?,
            params: Self::init_params(mech)?,
            finalized: false,
            in_use: false,
            ctx: EvpCipherCtx::new()?,
            finalbuf: Vec::new(),
            blockctr: 0,
            #[cfg(feature = "fips")]
            fips_approved: None,
        })
    }

    fn wrap(
        mech: &CK_MECHANISM,
        wrapping_key: &Object,
        mut keydata: Vec<u8>,
        output: &mut [u8],
    ) -> Result<usize> {
        let mut op = match Self::encrypt_new(mech, wrapping_key) {
            Ok(o) => o,
            Err(e) => {
                keydata.zeroize();
                return Err(e);
            }
        };

        match mech.mechanism {
            CKM_AES_CBC | CKM_AES_ECB => {
                /* non-padding block modes needs 0 padding for the input */
                let pad = keydata.len() % AES_BLOCK_SIZE;
                if pad != 0 {
                    keydata.resize(keydata.len() + AES_BLOCK_SIZE - pad, 0);
                }
            }
            CKM_AES_CCM => {
                /* Check the data length in CCM matches the provided data -- this is one-shot
                 * operation only */
                if op.params.datalen != keydata.len() {
                    return err_rv!(CKR_MECHANISM_PARAM_INVALID);
                }
            }
            _ => (),
        }
        let result = op.encrypt(&keydata, output);
        keydata.zeroize();
        result
    }

    fn unwrap(
        mech: &CK_MECHANISM,
        wrapping_key: &Object,
        data: &[u8],
    ) -> Result<Vec<u8>> {
        let mut op = Self::decrypt_new(mech, wrapping_key)?;
        let mut result = vec![0u8; data.len()];
        let outlen = op.decrypt(data, result.as_mut_slice())?;
        result.resize(outlen, 0);
        Ok(result)
    }

    fn op_err(&mut self, err: CK_RV) -> error::Error {
        self.finalized = true;
        error::Error::ck_rv(err)
    }
}

impl MechOperation for AesOperation {
    fn finalized(&self) -> bool {
        self.finalized
    }
    #[cfg(feature = "fips")]
    fn fips_approved(&self) -> Option<bool> {
        self.fips_approved
    }
}

impl Encryption for AesOperation {
    fn encrypt(&mut self, plain: &[u8], cipher: &mut [u8]) -> Result<usize> {
        if self.finalized {
            return err_rv!(CKR_OPERATION_NOT_INITIALIZED);
        }
        if cipher.len() == 0 {
            return self.encrypt_update(plain, cipher);
        }
        let outl = self.encrypt_update(plain, cipher)?;
        if outl > cipher.len() {
            return Err(self.op_err(CKR_DEVICE_ERROR));
        }
        Ok(outl + self.encrypt_final(&mut cipher[outl..])?)
    }

    fn encrypt_update(
        &mut self,
        plain: &[u8],
        cipher: &mut [u8],
    ) -> Result<usize> {
        if self.finalized {
            return err_rv!(CKR_OPERATION_NOT_INITIALIZED);
        }
        if !self.in_use {
            self.in_use = true;
            self.encrypt_initialize()?;
        }

        let mut outlen = self.encryption_len(plain.len(), false)?;
        match self.mech {
            CKM_AES_CTS => {
                if plain.len() < AES_BLOCK_SIZE {
                    return Err(self.op_err(CKR_DATA_LEN_RANGE));
                }
                /* some modes are one shot, and we use blockctr to mark that update
                 * has already been called once */
                if self.blockctr == 0 {
                    self.blockctr = 1;
                } else {
                    return Err(self.op_err(CKR_OPERATION_NOT_INITIALIZED));
                }
            }
            CKM_AES_CCM => {
                /* This should allow smaller plain length to update
                 * piecemeal, but CCM is one shot in OpenSSL so we
                 * have to force a full update for large datalens
                 * (we accumulate on behalf of OpenSSL up to 1 MiB)
                 */
                if self.params.datalen > MAX_CCM_BUF {
                    if plain.len() != self.params.datalen {
                        return Err(self.op_err(CKR_DATA_LEN_RANGE));
                    }
                }
                if plain.len() + self.finalbuf.len() > self.params.datalen {
                    return Err(self.op_err(CKR_DATA_LEN_RANGE));
                }
                if plain.len() + self.finalbuf.len() < self.params.datalen {
                    outlen = 0;
                }
            }
            CKM_AES_CTR => {
                if self.params.maxblocks != 0 {
                    let reqblocks = ((plain.len() + AES_BLOCK_SIZE - 1)
                        / AES_BLOCK_SIZE)
                        as u128;
                    if self.blockctr + reqblocks > self.params.maxblocks {
                        return Err(self.op_err(CKR_DATA_LEN_RANGE));
                    }
                    self.blockctr += reqblocks;
                }
            }
            CKM_AES_KEY_WRAP => {
                if plain.len() % 8 != 0 {
                    return Err(self.op_err(CKR_DATA_LEN_RANGE));
                }
            }
            _ => (),
        }
        if cipher.len() < outlen {
            /* This is the only, non-fatal error */
            return Err(error::Error::buf_too_small(outlen));
        }

        let mut plain_buf = plain.as_ptr();
        let mut plain_len = plain.len();
        if self.mech == CKM_AES_CCM {
            if plain.len() < self.params.datalen {
                self.finalbuf.extend_from_slice(plain);
                if self.finalbuf.len() < self.params.datalen {
                    plain_len = 0;
                } else {
                    plain_buf = self.finalbuf.as_ptr();
                    plain_len = self.finalbuf.len();
                }
            }
        }

        let mut outl: c_int = 0;
        if plain_len > 0 {
            let res = unsafe {
                EVP_EncryptUpdate(
                    self.ctx.as_mut_ptr(),
                    cipher.as_mut_ptr(),
                    &mut outl,
                    plain_buf,
                    plain_len as c_int,
                )
            };
            if res != 1 {
                return Err(self.op_err(CKR_DEVICE_ERROR));
            }
        }
        if self.mech == CKM_AES_CCM {
            if plain_len > 0 && plain_buf == self.finalbuf.as_ptr() {
                self.finalbuf.zeroize();
                self.finalbuf.clear();
            }
        }
        outlen = usize::try_from(outl)?;
        Ok(outlen)
    }

    fn encrypt_final(&mut self, cipher: &mut [u8]) -> Result<usize> {
        if self.finalized {
            return err_rv!(CKR_OPERATION_NOT_INITIALIZED);
        }
        if !self.in_use {
            return err_rv!(CKR_OPERATION_NOT_INITIALIZED);
        }

        let mut outlen = 0;
        match self.mech {
            CKM_AES_CCM | CKM_AES_GCM => {
                if cipher.len() < self.params.taglen {
                    /* This is the only, non-fatal error */
                    return Err(error::Error::buf_too_small(
                        self.params.taglen,
                    ));
                }
                let mut outl: c_int = 0;
                let res = unsafe {
                    /* This will normally be a noop (GCM/CCM) */
                    EVP_EncryptFinal_ex(
                        self.ctx.as_mut_ptr(),
                        cipher.as_mut_ptr(),
                        &mut outl,
                    )
                };
                if res != 1 {
                    return Err(self.op_err(CKR_DEVICE_ERROR));
                }
                if outl != 0 {
                    return Err(self.op_err(CKR_DEVICE_ERROR));
                }
                let res = unsafe {
                    EVP_CIPHER_CTX_ctrl(
                        self.ctx.as_mut_ptr(),
                        EVP_CTRL_AEAD_GET_TAG as c_int,
                        self.params.taglen as c_int,
                        cipher.as_mut_ptr() as *mut c_void,
                    )
                };
                if res != 1 {
                    return Err(self.op_err(CKR_DEVICE_ERROR));
                }
                outlen = self.params.taglen;
            }
            CKM_AES_CTR => {
                if self.params.maxblocks > 0 {
                    if self.blockctr >= self.params.maxblocks {
                        return Err(self.op_err(CKR_DATA_LEN_RANGE));
                    }
                }
            }
            CKM_AES_CTS | CKM_AES_CBC | CKM_AES_ECB => (),
            #[cfg(not(feature = "fips"))]
            CKM_AES_CFB8 | CKM_AES_CFB1 | CKM_AES_CFB128 | CKM_AES_OFB => (),
            CKM_AES_CBC_PAD => {
                /* check if this is a second call after
                 * we saved the final buffer */
                if self.finalbuf.len() > 0 {
                    if cipher.len() < self.finalbuf.len() {
                        return Err(error::Error::buf_too_small(
                            self.finalbuf.len(),
                        ));
                    }
                    cipher[..self.finalbuf.len()]
                        .copy_from_slice(&self.finalbuf);
                    outlen = self.finalbuf.len();
                } else {
                    let cipher_buf: *mut u8 = if cipher.len() < AES_BLOCK_SIZE {
                        /* be prepared to hold the final block
                         * size from openssl, and use it later */
                        self.finalbuf.reserve_exact(AES_BLOCK_SIZE);
                        self.finalbuf.as_mut_ptr()
                    } else {
                        cipher.as_mut_ptr()
                    };

                    let mut outl: c_int = 0;
                    let res = unsafe {
                        EVP_EncryptFinal_ex(
                            self.ctx.as_mut_ptr(),
                            cipher_buf,
                            &mut outl,
                        )
                    };
                    if res != 1 {
                        return Err(self.op_err(CKR_DEVICE_ERROR));
                    }
                    outlen = usize::try_from(outl)?;
                    if cipher.len() < AES_BLOCK_SIZE {
                        if outlen > AES_BLOCK_SIZE {
                            return Err(self.op_err(CKR_DEVICE_ERROR));
                        }
                        if cipher.len() >= outlen {
                            cipher[..outlen]
                                .copy_from_slice(&self.finalbuf[..outlen]);
                        } else {
                            unsafe { self.finalbuf.set_len(outlen) };
                            /* This is the only non-fatal error */
                            return Err(error::Error::buf_too_small(outlen));
                        }
                    }
                }
            }
            CKM_AES_KEY_WRAP | CKM_AES_KEY_WRAP_KWP => (),
            _ => {
                return Err(self.op_err(CKR_GENERAL_ERROR));
            }
        };

        #[cfg(feature = "fips")]
        {
            self.fips_approved =
                fips::indicators::check_cipher_fips_indicators(&mut self.ctx)?;
        }
        self.finalized = true;
        Ok(outlen)
    }

    fn encryption_len(&mut self, data_len: usize, fin: bool) -> Result<usize> {
        if self.finalized {
            return err_rv!(CKR_OPERATION_NOT_INITIALIZED);
        }
        let outlen = if fin {
            if !self.in_use {
                return err_rv!(CKR_OPERATION_NOT_INITIALIZED);
            }
            match self.mech {
                CKM_AES_CCM | CKM_AES_GCM => {
                    if self.finalbuf.len() != 0 {
                        return Err(self.op_err(CKR_DATA_LEN_RANGE));
                    }
                    self.params.taglen
                }
                CKM_AES_CTR | CKM_AES_CTS | CKM_AES_CBC | CKM_AES_ECB => 0,
                #[cfg(not(feature = "fips"))]
                CKM_AES_CFB8 | CKM_AES_CFB1 | CKM_AES_CFB128 | CKM_AES_OFB => 0,
                CKM_AES_CBC_PAD => {
                    if self.finalbuf.len() > 0 {
                        self.finalbuf.len()
                    } else {
                        AES_BLOCK_SIZE
                    }
                }
                CKM_AES_KEY_WRAP | CKM_AES_KEY_WRAP_KWP => 0,
                _ => return Err(self.op_err(CKR_GENERAL_ERROR)),
            }
        } else {
            match self.mech {
                CKM_AES_CCM => self.params.datalen + self.params.taglen,
                CKM_AES_GCM => data_len + self.params.taglen,
                CKM_AES_CTR | CKM_AES_CTS => data_len,
                CKM_AES_CBC | CKM_AES_ECB => {
                    ((data_len + AES_BLOCK_SIZE - 1) / AES_BLOCK_SIZE)
                        * AES_BLOCK_SIZE
                }
                CKM_AES_CBC_PAD => {
                    // The PKCS#7 padding adds always at least 1 byte
                    ((data_len + AES_BLOCK_SIZE) / AES_BLOCK_SIZE)
                        * AES_BLOCK_SIZE
                }
                #[cfg(not(feature = "fips"))]
                CKM_AES_CFB8 | CKM_AES_CFB1 | CKM_AES_CFB128 | CKM_AES_OFB => {
                    data_len
                }
                CKM_AES_KEY_WRAP => {
                    if data_len % 8 != 0 {
                        return Err(self.op_err(CKR_DATA_LEN_RANGE));
                    } else {
                        data_len + 8
                    }
                }
                CKM_AES_KEY_WRAP_KWP => ((data_len + 15) / 8) * 8,
                _ => return Err(self.op_err(CKR_GENERAL_ERROR)),
            }
        };
        Ok(outlen)
    }
}

impl Decryption for AesOperation {
    fn decrypt(&mut self, cipher: &[u8], plain: &mut [u8]) -> Result<usize> {
        if self.finalized {
            return err_rv!(CKR_OPERATION_NOT_INITIALIZED);
        }
        if plain.len() == 0 {
            match self.mech {
                CKM_AES_CCM => return Ok(self.params.datalen),
                CKM_AES_GCM => return Ok(cipher.len() - self.params.taglen),
                _ => return self.decrypt_update(cipher, plain),
            }
        }
        let outlen = self.decrypt_update(cipher, plain)?;
        if outlen > plain.len() {
            return Err(self.op_err(CKR_GENERAL_ERROR));
        }
        Ok(outlen + self.decrypt_final(&mut plain[outlen..])?)
    }

    fn decrypt_update(
        &mut self,
        cipher: &[u8],
        plain: &mut [u8],
    ) -> Result<usize> {
        if self.finalized {
            return err_rv!(CKR_OPERATION_NOT_INITIALIZED);
        }
        let mut cipher_buf = cipher.as_ptr();
        match self.mech {
            CKM_AES_CTS => {
                if cipher.len() < AES_BLOCK_SIZE {
                    return Err(self.op_err(CKR_DATA_LEN_RANGE));
                }

                /* CTS mode is one shot, and we use blockctr to mark that update
                 * has already been called once */
                if self.blockctr == 0 {
                    self.blockctr = 1;
                } else {
                    return Err(self.op_err(CKR_OPERATION_NOT_INITIALIZED));
                }
            }
            CKM_AES_CCM => {
                if cipher.len() + self.finalbuf.len()
                    > self.params.datalen + self.params.taglen
                {
                    return Err(self.op_err(CKR_OPERATION_NOT_INITIALIZED));
                }
            }
            CKM_AES_KEY_WRAP | CKM_AES_KEY_WRAP_KWP => {
                if cipher.len() % 8 != 0 {
                    return Err(self.op_err(CKR_DATA_LEN_RANGE));
                }
            }
            _ => (),
        }
        if !self.in_use {
            self.in_use = true;
            self.decrypt_initialize()?;
        }

        let outlen = match self.mech {
            CKM_AES_CCM => {
                let needlen = self.params.datalen + self.params.taglen;
                /* This should allow smaller plain length to update
                 * piecemeal, but CCM is one shot in OpenSSL so we
                 * have to force a full update for large datalens
                 * (we accumulate on behalf of OpenSSL up to 1 MiB)
                 */
                if self.params.datalen > MAX_CCM_BUF {
                    if cipher.len() != needlen {
                        return Err(self.op_err(CKR_DATA_LEN_RANGE));
                    }
                }
                if cipher.len() + self.finalbuf.len() > needlen {
                    return Err(self.op_err(CKR_DATA_LEN_RANGE));
                }
                /* always return the amount we know will be
                 * ultimately needed */
                self.params.datalen
            }
            CKM_AES_CTR => {
                if self.params.maxblocks != 0 {
                    let reqblocks = ((cipher.len() + AES_BLOCK_SIZE - 1)
                        / AES_BLOCK_SIZE)
                        as u128;
                    if self.blockctr + reqblocks > self.params.maxblocks {
                        return Err(self.op_err(CKR_DATA_LEN_RANGE));
                    }
                    self.blockctr += reqblocks;
                }
                cipher.len()
            }
            CKM_AES_GCM => {
                let tlen = cipher.len() + self.finalbuf.len();
                if tlen > self.params.taglen {
                    tlen - self.params.taglen
                } else {
                    0
                }
            }
            CKM_AES_KEY_WRAP | CKM_AES_KEY_WRAP_KWP => cipher.len() - 8,
            _ => cipher.len(),
        };
        if plain.len() < outlen {
            /* This is the only, non-fatal error */
            return Err(error::Error::buf_too_small(outlen));
        }

        let mut outlen = 0;
        let mut cipher_len = cipher.len();
        match self.mech {
            CKM_AES_CCM => {
                let needlen = self.params.datalen + self.params.taglen;
                if cipher_len < needlen {
                    self.finalbuf.extend_from_slice(cipher);
                    if self.finalbuf.len() < needlen {
                        cipher_len = 0;
                    } else {
                        cipher_buf = self.finalbuf.as_ptr();
                        cipher_len = self.params.datalen;
                    }
                } else {
                    cipher_len = self.params.datalen;
                }

                /* if we have the whole buffer, set the tag now,
                 * openssl requires this order of operations for CCM */
                if cipher_len > 0 {
                    let tag_buf =
                        unsafe { cipher_buf.offset(cipher_len as isize) };

                    let res = unsafe {
                        EVP_CIPHER_CTX_ctrl(
                            self.ctx.as_mut_ptr(),
                            EVP_CTRL_AEAD_SET_TAG as c_int,
                            self.params.taglen as c_int,
                            tag_buf as *mut _,
                        )
                    };
                    if res != 1 {
                        return Err(self.op_err(CKR_DEVICE_ERROR));
                    }
                }
            }
            CKM_AES_GCM => {
                /* the tag is appended at the end of the ciphertext,
                 * but we do not know how long the ciphertext is */
                if self.finalbuf.len() > 0 {
                    if cipher_len > self.params.taglen {
                        /* consume the saved buffer now,
                         * so we avoid unnecessary data copy */
                        let mut plen: c_int = 0;
                        let res = unsafe {
                            EVP_DecryptUpdate(
                                self.ctx.as_mut_ptr(),
                                plain.as_mut_ptr(),
                                &mut plen,
                                self.finalbuf.as_ptr(),
                                self.finalbuf.len() as c_int,
                            )
                        };
                        if res != 1 {
                            return Err(self.op_err(CKR_ENCRYPTED_DATA_INVALID));
                        }
                        outlen = usize::try_from(plen)?;
                        self.finalbuf.clear();
                        cipher_len -= self.params.taglen;
                        self.finalbuf.extend_from_slice(&cipher[cipher_len..]);
                    } else {
                        self.finalbuf.extend_from_slice(cipher);
                        if self.finalbuf.len() > self.params.taglen {
                            cipher_buf = self.finalbuf.as_ptr();
                            cipher_len =
                                self.finalbuf.len() - self.params.taglen;
                        }
                    }
                } else if cipher_len > self.params.taglen {
                    cipher_len -= self.params.taglen;
                    self.finalbuf.extend_from_slice(&cipher[cipher_len..]);
                } else {
                    self.finalbuf.extend_from_slice(cipher);
                    cipher_len = 0;
                }
            }
            _ => (),
        }

        if cipher_len > 0 {
            let mut outl: c_int = 0;
            let res = unsafe {
                EVP_DecryptUpdate(
                    self.ctx.as_mut_ptr(),
                    plain[outlen..].as_mut_ptr(),
                    &mut outl,
                    cipher_buf,
                    cipher_len as c_int,
                )
            };
            if res != 1 {
                return Err(self.op_err(CKR_ENCRYPTED_DATA_INVALID));
            }
            outlen += usize::try_from(outl)?;
        }
        /* remove ciphertext if any was stored */
        if cipher_buf == self.finalbuf.as_ptr() {
            match self.mech {
                CKM_AES_CCM => self.finalbuf.clear(),
                CKM_AES_GCM => {
                    let v = self.finalbuf[cipher_len..].to_vec();
                    self.finalbuf = v;
                }
                _ => (),
            }
        }
        Ok(outlen)
    }

    fn decrypt_final(&mut self, plain: &mut [u8]) -> Result<usize> {
        if self.finalized {
            return err_rv!(CKR_OPERATION_NOT_INITIALIZED);
        }
        if !self.in_use {
            return err_rv!(CKR_OPERATION_NOT_INITIALIZED);
        }

        let mut outlen = 0;
        match self.mech {
            CKM_AES_CCM => {
                if self.finalbuf.len() > 0 {
                    return Err(self.op_err(CKR_DATA_LEN_RANGE));
                }
            }
            CKM_AES_GCM => {
                if self.finalbuf.len() != self.params.taglen {
                    return Err(self.op_err(CKR_DATA_LEN_RANGE));
                }
                let res = unsafe {
                    EVP_CIPHER_CTX_ctrl(
                        self.ctx.as_mut_ptr(),
                        c_int::try_from(EVP_CTRL_AEAD_SET_TAG)?,
                        c_int::try_from(self.params.taglen)?,
                        self.finalbuf.as_ptr() as *mut c_void,
                    )
                };
                if res != 1 {
                    return Err(self.op_err(CKR_DEVICE_ERROR));
                }
                let mut outl: c_int = 0;
                let res = unsafe {
                    EVP_DecryptFinal_ex(
                        self.ctx.as_mut_ptr(),
                        std::ptr::null_mut(),
                        &mut outl,
                    )
                };
                if res != 1 {
                    return Err(self.op_err(CKR_ENCRYPTED_DATA_INVALID));
                }
                if outl != 0 {
                    return Err(self.op_err(CKR_DEVICE_ERROR));
                }
            }
            CKM_AES_CTR => {
                if self.params.maxblocks > 0 {
                    if self.blockctr >= self.params.maxblocks {
                        return Err(self.op_err(CKR_DATA_LEN_RANGE));
                    }
                }
            }
            CKM_AES_CTS | CKM_AES_CBC | CKM_AES_ECB => (),
            #[cfg(not(feature = "fips"))]
            CKM_AES_CFB8 | CKM_AES_CFB1 | CKM_AES_CFB128 | CKM_AES_OFB => (),
            CKM_AES_CBC_PAD => {
                /* check if this is a second call after
                 * we saved the final buffer */
                if self.finalbuf.len() > 0 {
                    if plain.len() < self.finalbuf.len() {
                        return Err(error::Error::buf_too_small(
                            self.finalbuf.len(),
                        ));
                    }
                    plain[..self.finalbuf.len()]
                        .copy_from_slice(&self.finalbuf);
                    outlen = self.finalbuf.len();
                } else {
                    let plain_buf: *mut u8 = if plain.len() < AES_BLOCK_SIZE {
                        /* be prepared to hold the final block
                         * size from openssl, and use it later */
                        self.finalbuf.reserve_exact(AES_BLOCK_SIZE);
                        self.finalbuf.as_mut_ptr()
                    } else {
                        plain.as_mut_ptr()
                    };

                    let mut outl: c_int = 0;
                    let res = unsafe {
                        EVP_DecryptFinal_ex(
                            self.ctx.as_mut_ptr(),
                            plain_buf,
                            &mut outl,
                        )
                    };
                    if res != 1 {
                        return Err(self.op_err(CKR_ENCRYPTED_DATA_INVALID));
                    }
                    outlen = usize::try_from(outl)?;
                    if outlen > 0 && plain.len() < AES_BLOCK_SIZE {
                        if outlen > AES_BLOCK_SIZE {
                            return Err(self.op_err(CKR_DEVICE_ERROR));
                        }
                        if plain.len() >= outlen {
                            plain[..outlen]
                                .copy_from_slice(&self.finalbuf[..outlen]);
                        } else {
                            self.finalbuf.resize(outlen, 0);
                            /* This is the only non-fatal error */
                            return Err(error::Error::buf_too_small(outlen));
                        }
                    }
                }
            }
            CKM_AES_KEY_WRAP | CKM_AES_KEY_WRAP_KWP => (),
            _ => return Err(self.op_err(CKR_GENERAL_ERROR)),
        }

        #[cfg(feature = "fips")]
        {
            self.fips_approved =
                fips::indicators::check_cipher_fips_indicators(&mut self.ctx)?;
        }
        self.finalized = true;
        Ok(outlen)
    }

    fn decryption_len(&mut self, data_len: usize, fin: bool) -> Result<usize> {
        if self.finalized {
            return err_rv!(CKR_OPERATION_NOT_INITIALIZED);
        }
        let outlen = if fin {
            if !self.in_use {
                return err_rv!(CKR_OPERATION_NOT_INITIALIZED);
            }
            match self.mech {
                CKM_AES_GCM => {
                    if self.finalbuf.len() > self.params.taglen {
                        self.finalbuf.len() - self.params.taglen
                    } else {
                        0
                    }
                }
                CKM_AES_CCM | CKM_AES_CTR | CKM_AES_CTS | CKM_AES_CBC
                | CKM_AES_ECB => 0,
                #[cfg(not(feature = "fips"))]
                CKM_AES_CFB8 | CKM_AES_CFB1 | CKM_AES_CFB128 | CKM_AES_OFB => 0,
                CKM_AES_CBC_PAD => {
                    if self.finalbuf.len() > 0 {
                        self.finalbuf.len()
                    } else {
                        AES_BLOCK_SIZE
                    }
                }
                CKM_AES_KEY_WRAP | CKM_AES_KEY_WRAP_KWP => 0,
                _ => return Err(self.op_err(CKR_GENERAL_ERROR)),
            }
        } else {
            match self.mech {
                CKM_AES_CCM => self.params.datalen,
                CKM_AES_GCM => {
                    let len = data_len;
                    if len > self.params.taglen {
                        len - self.params.taglen
                    } else {
                        0
                    }
                }
                CKM_AES_CTR | CKM_AES_CTS => data_len,
                CKM_AES_CBC | CKM_AES_CBC_PAD | CKM_AES_ECB => {
                    (data_len / AES_BLOCK_SIZE) * AES_BLOCK_SIZE
                }
                #[cfg(not(feature = "fips"))]
                CKM_AES_CFB8 | CKM_AES_CFB1 | CKM_AES_CFB128 | CKM_AES_OFB => {
                    data_len
                }
                CKM_AES_KEY_WRAP | CKM_AES_KEY_WRAP_KWP => {
                    if data_len % 8 != 0 {
                        return Err(self.op_err(CKR_DATA_LEN_RANGE));
                    } else {
                        ((data_len / 8) * 8) - 8
                    }
                }
                _ => return Err(self.op_err(CKR_GENERAL_ERROR)),
            }
        };
        Ok(outlen)
    }
}

/* _key and _mac as stored in order to make sure the pointers they
 * hold survive for as long as the operations are going on, as we
 * can't be sure openssl is not holding live pointers to the
 * parameters passed into the init functions */
#[derive(Debug)]
struct AesCmacOperation {
    finalized: bool,
    in_use: bool,
    _key: AesKey,
    ctx: EvpMacCtx,
    maclen: usize,
    #[cfg(feature = "fips")]
    fips_approved: Option<bool>,
}

impl AesCmacOperation {
    fn register_mechanisms(mechs: &mut Mechanisms) {
        for ckm in &[CKM_AES_CMAC, CKM_AES_CMAC_GENERAL] {
            mechs.add_mechanism(*ckm, new_mechanism(CKF_SIGN | CKF_VERIFY));
        }
    }

    fn init(mech: &CK_MECHANISM, key: &Object) -> Result<AesCmacOperation> {
        let maclen = match mech.mechanism {
            CKM_AES_CMAC_GENERAL => {
                let params = cast_params!(mech, CK_MAC_GENERAL_PARAMS);
                let val = params as usize;
                if val > AES_BLOCK_SIZE {
                    return err_rv!(CKR_MECHANISM_PARAM_INVALID);
                }
                val
            }
            CKM_AES_CMAC => {
                if mech.ulParameterLen != 0 {
                    return err_rv!(CKR_ARGUMENTS_BAD);
                }
                AES_BLOCK_SIZE
            }
            _ => return err_rv!(CKR_MECHANISM_INVALID),
        };
        let mackey = object_to_raw_key(key)?;
        let mut ctx = EvpMacCtx::new(name_as_char(OSSL_MAC_NAME_CMAC))?;
        let mut params = OsslParam::with_capacity(1);
        params.add_const_c_string(
            name_as_char(OSSL_MAC_PARAM_CIPHER),
            match mackey.raw.len() {
                16 => name_as_char(CIPHER_NAME_AES128),
                24 => name_as_char(CIPHER_NAME_AES192),
                32 => name_as_char(CIPHER_NAME_AES256),
                _ => return err_rv!(CKR_KEY_INDIGESTIBLE),
            },
        )?;
        params.finalize();

        if unsafe {
            EVP_MAC_init(
                ctx.as_mut_ptr(),
                mackey.raw.as_ptr(),
                mackey.raw.len(),
                params.as_ptr(),
            )
        } != 1
        {
            return err_rv!(CKR_DEVICE_ERROR);
        }
        Ok(AesCmacOperation {
            finalized: false,
            in_use: false,
            _key: mackey,
            ctx: ctx,
            maclen: maclen,
            #[cfg(feature = "fips")]
            fips_approved: None,
        })
    }

    fn begin(&mut self) -> Result<()> {
        if self.in_use {
            return err_rv!(CKR_OPERATION_NOT_INITIALIZED);
        }
        Ok(())
    }

    fn update(&mut self, data: &[u8]) -> Result<()> {
        if self.finalized {
            return err_rv!(CKR_OPERATION_NOT_INITIALIZED);
        }
        self.in_use = true;

        if unsafe {
            EVP_MAC_update(self.ctx.as_mut_ptr(), data.as_ptr(), data.len())
        } != 1
        {
            return err_rv!(CKR_DEVICE_ERROR);
        }

        Ok(())
    }

    fn finalize(&mut self, output: &mut [u8]) -> Result<()> {
        if self.finalized {
            return err_rv!(CKR_OPERATION_NOT_INITIALIZED);
        }
        /* It is valid to finalize without any update */
        self.in_use = true;
        self.finalized = true;

        let mut buf = [0u8; AES_BLOCK_SIZE];
        let mut outlen: usize = 0;
        if unsafe {
            EVP_MAC_final(
                self.ctx.as_mut_ptr(),
                buf.as_mut_ptr(),
                &mut outlen,
                buf.len(),
            )
        } != 1
        {
            return err_rv!(CKR_DEVICE_ERROR);
        }
        if outlen != AES_BLOCK_SIZE {
            return err_rv!(CKR_GENERAL_ERROR);
        }

        output.copy_from_slice(&buf[..output.len()]);
        buf.zeroize();

        #[cfg(feature = "fips")]
        {
            self.fips_approved =
                fips::indicators::check_mac_fips_indicators(&mut self.ctx)?;
        }
        Ok(())
    }
}

impl MechOperation for AesCmacOperation {
    fn finalized(&self) -> bool {
        self.finalized
    }
    #[cfg(feature = "fips")]
    fn fips_approved(&self) -> Option<bool> {
        self.fips_approved
    }
}

impl Mac for AesCmacOperation {
    fn mac(&mut self, data: &[u8], mac: &mut [u8]) -> Result<()> {
        self.begin()?;
        if data.len() > 0 {
            self.update(data)?;
        }
        self.finalize(mac)
    }

    fn mac_update(&mut self, data: &[u8]) -> Result<()> {
        self.update(data)
    }

    fn mac_final(&mut self, mac: &mut [u8]) -> Result<()> {
        self.finalize(mac)
    }

    fn mac_len(&self) -> Result<usize> {
        Ok(self.maclen)
    }
}

impl Sign for AesCmacOperation {
    fn sign(&mut self, data: &[u8], signature: &mut [u8]) -> Result<()> {
        self.begin()?;
        if data.len() > 0 {
            self.update(data)?;
        }
        self.finalize(signature)
    }

    fn sign_update(&mut self, data: &[u8]) -> Result<()> {
        self.update(data)
    }

    fn sign_final(&mut self, signature: &mut [u8]) -> Result<()> {
        self.finalize(signature)
    }

    fn signature_len(&self) -> Result<usize> {
        Ok(self.maclen)
    }
}

impl Verify for AesCmacOperation {
    fn verify(&mut self, data: &[u8], signature: &[u8]) -> Result<()> {
        self.begin()?;
        if data.len() > 0 {
            self.update(data)?;
        }
        self.verify_final(signature)
    }

    fn verify_update(&mut self, data: &[u8]) -> Result<()> {
        self.update(data)
    }

    fn verify_final(&mut self, signature: &[u8]) -> Result<()> {
        let mut verify: Vec<u8> = vec![0; self.maclen];
        self.finalize(verify.as_mut_slice())?;
        if !constant_time_eq(&verify, signature) {
            return err_rv!(CKR_SIGNATURE_INVALID);
        }
        Ok(())
    }

    fn signature_len(&self) -> Result<usize> {
        Ok(self.maclen)
    }
}

#[cfg(not(feature = "fips"))]
include!("aes_mac.rs");
