// Copyright 2024 Simo Sorce
// See LICENSE.txt file for terms

#[cfg(feature = "fips")]
use {super::fips, fips::*};

#[cfg(not(feature = "fips"))]
use {super::ossl, ossl::*};

use super::bytes_to_vec;

use constant_time_eq::constant_time_eq;
use std::ffi::{c_char, c_int, c_void};
use zeroize::Zeroize;

const MAX_CCM_BUF: usize = 1 << 20; /* 1MiB */

const AES_128_CBC_CTS: &[u8; 16] = b"AES-128-CBC-CTS\0";
const AES_192_CBC_CTS: &[u8; 16] = b"AES-192-CBC-CTS\0";
const AES_256_CBC_CTS: &[u8; 16] = b"AES-256-CBC-CTS\0";

/* It is safe to share const ciphers as they do not change once they have been
 * created, and reference satic function pointers and other data that is
 * always valid */
struct AesCipher {
    cipher: EvpCipher,
}

impl AesCipher {
    pub fn new(name: *const u8) -> AesCipher {
        AesCipher {
            cipher: match EvpCipher::from_ptr(unsafe {
                EVP_CIPHER_fetch(
                    get_libctx(),
                    name as *const c_char,
                    std::ptr::null(),
                )
            }) {
                Ok(ec) => ec,
                Err(_) => EvpCipher::empty(),
            },
        }
    }

    pub fn get_cipher(&self) -> KResult<&EvpCipher> {
        let ec = self.cipher.as_ptr();
        if ec.is_null() {
            return err_rv!(CKR_MECHANISM_INVALID);
        }
        Ok(&self.cipher)
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

#[derive(Debug)]
struct AesKey {
    raw: Vec<u8>,
}

impl Drop for AesKey {
    fn drop(&mut self) {
        self.raw.zeroize()
    }
}

fn object_to_raw_key(key: &Object) -> KResult<AesKey> {
    let val = key.get_attr_as_bytes(CKA_VALUE)?;
    check_key_len(val.len())?;
    Ok(AesKey { raw: val.clone() })
}

fn new_mechanism(flags: CK_FLAGS) -> Box<dyn Mechanism> {
    Box::new(AesMechanism {
        info: CK_MECHANISM_INFO {
            ulMinKeySize: MIN_AES_SIZE_BYTES as CK_ULONG,
            ulMaxKeySize: MAX_AES_SIZE_BYTES as CK_ULONG,
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

    fn init_params(mech: &CK_MECHANISM) -> KResult<AesParams> {
        match mech.mechanism {
            CKM_AES_CCM => {
                if mech.ulParameterLen as usize
                    != ::std::mem::size_of::<CK_CCM_PARAMS>()
                {
                    return err_rv!(CKR_ARGUMENTS_BAD);
                }
                let ccm_params = mech.pParameter as *const CK_CCM_PARAMS;
                let datalen = unsafe { (*ccm_params).ulDataLen as usize };
                let nonce = unsafe { (*ccm_params).pNonce };
                let noncelen = unsafe { (*ccm_params).ulNonceLen as usize };
                let maclen = unsafe { (*ccm_params).ulMACLen as usize };
                let aad = unsafe { (*ccm_params).pAAD };
                let aadlen = unsafe { (*ccm_params).ulAADLen as usize };
                if noncelen < 7 || noncelen > 13 {
                    return err_rv!(CKR_MECHANISM_PARAM_INVALID);
                }
                let l = 15 - noncelen;
                if datalen == 0
                    || datalen > (1 << (8 * l))
                    || datalen > (u64::MAX as usize) - maclen
                {
                    return err_rv!(CKR_MECHANISM_PARAM_INVALID);
                }
                if aadlen > (u32::MAX as usize) - 1 {
                    return err_rv!(CKR_MECHANISM_PARAM_INVALID);
                }
                match maclen {
                    4 | 6 | 8 | 10 | 12 | 14 | 16 => (),
                    _ => return err_rv!(CKR_MECHANISM_PARAM_INVALID),
                }
                Ok(AesParams {
                    iv: bytes_to_vec!(nonce, noncelen),
                    maxblocks: 0,
                    ctsmode: 0,
                    datalen: datalen,
                    aad: if aadlen > 0 {
                        bytes_to_vec!(aad, aadlen)
                    } else {
                        Vec::new()
                    },
                    taglen: maclen,
                })
            }
            CKM_AES_GCM => {
                if mech.ulParameterLen as usize
                    != ::std::mem::size_of::<CK_GCM_PARAMS>()
                {
                    return err_rv!(CKR_ARGUMENTS_BAD);
                }
                let gcm_params = mech.pParameter as *const CK_GCM_PARAMS;
                unsafe {
                    if (*gcm_params).ulIvLen == 0
                        || (*gcm_params).ulIvLen > (1 << 32) - 1
                    {
                        return err_rv!(CKR_MECHANISM_PARAM_INVALID);
                    }
                    if (*gcm_params).ulAADLen > (1 << 32) - 1 {
                        return err_rv!(CKR_MECHANISM_PARAM_INVALID);
                    }
                    if (*gcm_params).ulTagBits > 128 {
                        return err_rv!(CKR_MECHANISM_PARAM_INVALID);
                    }
                }
                let iv = unsafe { (*gcm_params).pIv };
                let ivlen = unsafe { (*gcm_params).ulIvLen };
                let aad = unsafe { (*gcm_params).pAAD };
                let aadlen = unsafe { (*gcm_params).ulAADLen };
                let tagbits = unsafe { (*gcm_params).ulTagBits } as usize;
                Ok(AesParams {
                    iv: bytes_to_vec!(iv, ivlen),
                    maxblocks: 0,
                    ctsmode: 0,
                    datalen: 0,
                    aad: if aadlen > 0 {
                        bytes_to_vec!(aad, aadlen)
                    } else {
                        Vec::new()
                    },
                    taglen: (tagbits + 7) / 8,
                })
            }
            CKM_AES_CTR => {
                if mech.ulParameterLen as usize
                    != ::std::mem::size_of::<CK_AES_CTR_PARAMS>()
                {
                    return err_rv!(CKR_ARGUMENTS_BAD);
                }
                let ctr_params = mech.pParameter as *const CK_AES_CTR_PARAMS;
                let iv = unsafe { (*ctr_params).cb.to_vec() };
                let ctrbits = unsafe { (*ctr_params).ulCounterBits } as usize;
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
                        maxblocks -= (iv[15 - idx] as u128) << (idx * 8);
                        idx += 1;
                    }
                    let part = ctrbits % 8;
                    if part > 0 {
                        maxblocks -= ((iv[15 - idx] as u128) & (part as u128))
                            << (idx * 8);
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
                if mech.ulParameterLen != (AES_BLOCK_SIZE as CK_ULONG) {
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
                if mech.ulParameterLen != (AES_BLOCK_SIZE as CK_ULONG) {
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
            _ => err_rv!(CKR_MECHANISM_INVALID),
        }
    }

    fn init_cipher(
        mech: CK_MECHANISM_TYPE,
        keylen: usize,
    ) -> KResult<&'static EvpCipher> {
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
            _ => return err_rv!(CKR_MECHANISM_INVALID),
        })
    }

    fn encrypt_initialize(&mut self) -> KResult<()> {
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
                            EVP_CTRL_AEAD_SET_IVLEN as c_int,
                            self.params.iv.len() as c_int,
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
                        EVP_CTRL_AEAD_SET_IVLEN as c_int,
                        self.params.iv.len() as c_int,
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
                        EVP_CTRL_AEAD_SET_TAG as c_int,
                        self.params.taglen as c_int,
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
                EVP_EncryptUpdate(
                    self.ctx.as_mut_ptr(),
                    std::ptr::null_mut(),
                    &mut outl,
                    std::ptr::null(),
                    self.params.datalen as c_int,
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
                    self.params.aad.len() as c_int,
                )
            };
            if res != 1 {
                self.finalized = true;
                return err_rv!(CKR_DEVICE_ERROR);
            }
        }

        Ok(())
    }

    fn decrypt_initialize(&mut self) -> KResult<()> {
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
                            EVP_CTRL_AEAD_SET_IVLEN as c_int,
                            self.params.iv.len() as c_int,
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
                        EVP_CTRL_AEAD_SET_IVLEN as c_int,
                        self.params.iv.len() as c_int,
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
                        EVP_CTRL_AEAD_SET_TAG as c_int,
                        self.params.taglen as c_int,
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
                    self.params.datalen as c_int,
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
                    self.params.aad.len() as c_int,
                )
            };
            if res != 1 {
                self.finalized = true;
                return err_rv!(CKR_DEVICE_ERROR);
            }
        }

        Ok(())
    }

    fn encrypt_new(mech: &CK_MECHANISM, key: &Object) -> KResult<AesOperation> {
        Ok(AesOperation {
            mech: mech.mechanism,
            key: object_to_raw_key(key)?,
            params: Self::init_params(mech)?,
            finalized: false,
            in_use: false,
            ctx: EvpCipherCtx::from_ptr(unsafe { EVP_CIPHER_CTX_new() })?,
            finalbuf: Vec::new(),
            blockctr: 0,
        })
    }

    fn decrypt_new(mech: &CK_MECHANISM, key: &Object) -> KResult<AesOperation> {
        Ok(AesOperation {
            mech: mech.mechanism,
            key: object_to_raw_key(key)?,
            params: Self::init_params(mech)?,
            finalized: false,
            in_use: false,
            ctx: EvpCipherCtx::from_ptr(unsafe { EVP_CIPHER_CTX_new() })?,
            finalbuf: Vec::new(),
            blockctr: 0,
        })
    }

    fn wrap(
        mech: &CK_MECHANISM,
        wrapping_key: &Object,
        mut keydata: Vec<u8>,
        output: CK_BYTE_PTR,
        output_len: CK_ULONG_PTR,
    ) -> KResult<()> {
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
        let result = op.encrypt(&keydata, output, output_len);
        keydata.zeroize();
        result
    }

    fn unwrap(
        mech: &CK_MECHANISM,
        wrapping_key: &Object,
        data: &[u8],
    ) -> KResult<Vec<u8>> {
        let mut op = Self::decrypt_new(mech, wrapping_key)?;
        let mut result = vec![0u8; data.len()];
        let mut len = result.len() as CK_ULONG;
        op.decrypt(data, result.as_mut_ptr(), &mut len)?;
        unsafe { result.set_len(len as usize) };
        Ok(result)
    }
}

impl MechOperation for AesOperation {
    fn finalized(&self) -> bool {
        self.finalized
    }
}

impl Encryption for AesOperation {
    fn encrypt(
        &mut self,
        plain: &[u8],
        cipher: CK_BYTE_PTR,
        cipher_len: CK_ULONG_PTR,
    ) -> KResult<()> {
        if self.finalized {
            return err_rv!(CKR_OPERATION_NOT_INITIALIZED);
        }
        if cipher.is_null() {
            return self.encrypt_update(plain, cipher, cipher_len);
        }
        let clen: CK_ULONG = unsafe { *cipher_len };
        let mut outb: *mut u8 = cipher;
        let mut outl: CK_ULONG = unsafe { *cipher_len };
        self.encrypt_update(plain, outb, &mut outl)?;
        if outl > clen {
            self.finalized = true;
            return err_rv!(CKR_DEVICE_ERROR);
        }
        let mut foutl = clen - outl;
        outb = unsafe { cipher.offset(outl as isize) };
        self.encrypt_final(outb, &mut foutl)?;
        unsafe { *cipher_len = foutl + outl };
        Ok(())
    }

    fn encrypt_update(
        &mut self,
        plain: &[u8],
        cipher: CK_BYTE_PTR,
        cipher_len: CK_ULONG_PTR,
    ) -> KResult<()> {
        if cipher_len.is_null() {
            return err_rv!(CKR_ARGUMENTS_BAD);
        }
        if self.finalized {
            return err_rv!(CKR_OPERATION_NOT_INITIALIZED);
        }
        let mut outlen = self.encryption_len(plain.len() as u64)?;
        if cipher.is_null() {
            unsafe {
                *cipher_len = outlen as CK_ULONG;
            }
            return Ok(());
        }

        if !self.in_use {
            self.in_use = true;
            self.encrypt_initialize()?;
        }

        match self.mech {
            CKM_AES_CTS => {
                if plain.len() < AES_BLOCK_SIZE {
                    self.finalized = true;
                    return err_rv!(CKR_DATA_LEN_RANGE);
                }
                /* some modes are one shot, and we use blockctr to mark that update
                 * has already been called once */
                if self.blockctr == 0 {
                    self.blockctr = 1;
                } else {
                    self.finalized = true;
                    return err_rv!(CKR_OPERATION_NOT_INITIALIZED);
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
                        self.finalized = true;
                        return err_rv!(CKR_DATA_LEN_RANGE);
                    }
                }
                if plain.len() + self.finalbuf.len() > self.params.datalen {
                    self.finalized = true;
                    return err_rv!(CKR_DATA_LEN_RANGE);
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
                        self.finalized = true;
                        return err_rv!(CKR_DATA_LEN_RANGE);
                    }
                    self.blockctr += reqblocks;
                }
            }
            _ => (),
        }
        if unsafe { *cipher_len as usize } < outlen {
            /* This is the only, non-fatal error */
            unsafe { *cipher_len = outlen as CK_ULONG };
            return err_rv!(CKR_BUFFER_TOO_SMALL);
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
                    cipher,
                    &mut outl,
                    plain_buf,
                    plain_len as c_int,
                )
            };
            if res != 1 {
                self.finalized = true;
                return err_rv!(CKR_DEVICE_ERROR);
            }
        }
        if self.mech == CKM_AES_CCM {
            if plain_len > 0 && plain_buf == self.finalbuf.as_ptr() {
                self.finalbuf.zeroize();
                self.finalbuf.clear();
            }
        }
        unsafe {
            *cipher_len = outl as CK_ULONG;
        }
        Ok(())
    }

    fn encrypt_final(
        &mut self,
        cipher: CK_BYTE_PTR,
        cipher_len: CK_ULONG_PTR,
    ) -> KResult<()> {
        if self.finalized {
            return err_rv!(CKR_OPERATION_NOT_INITIALIZED);
        }
        if !self.in_use {
            return err_rv!(CKR_OPERATION_NOT_INITIALIZED);
        }
        if cipher.is_null() {
            let mut clen: CK_ULONG = 0;
            match self.mech {
                CKM_AES_CCM | CKM_AES_GCM => {
                    if self.finalbuf.len() != 0 {
                        self.finalized = true;
                        return err_rv!(CKR_DATA_LEN_RANGE);
                    }
                    clen = self.params.taglen as CK_ULONG;
                }
                CKM_AES_CTR | CKM_AES_CTS | CKM_AES_CBC | CKM_AES_ECB => (),
                #[cfg(not(feature = "fips"))]
                CKM_AES_CFB8 | CKM_AES_CFB1 | CKM_AES_CFB128 | CKM_AES_OFB => {
                    ()
                }
                CKM_AES_CBC_PAD => {
                    clen = AES_BLOCK_SIZE as CK_ULONG;
                    if self.finalbuf.len() > 0 {
                        clen = self.finalbuf.len() as CK_ULONG;
                    }
                }
                _ => return err_rv!(CKR_GENERAL_ERROR),
            }
            unsafe { *cipher_len = clen };
            return Ok(());
        }

        let mut clen = unsafe { *cipher_len } as usize;
        match self.mech {
            CKM_AES_CCM | CKM_AES_GCM => {
                if clen < self.params.taglen {
                    /* This is the only, non-fatal error */
                    unsafe { *cipher_len = self.params.taglen as CK_ULONG };
                    return err_rv!(CKR_BUFFER_TOO_SMALL);
                }
                let mut outl: c_int = 0;
                let res = unsafe {
                    /* This will normally be a noop (GCM/CCM) */
                    EVP_EncryptFinal_ex(
                        self.ctx.as_mut_ptr(),
                        cipher,
                        &mut outl,
                    )
                };
                if res != 1 {
                    self.finalized = true;
                    return err_rv!(CKR_DEVICE_ERROR);
                }
                if outl as usize != 0 {
                    self.finalized = true;
                    return err_rv!(CKR_DEVICE_ERROR);
                }
                let res = unsafe {
                    EVP_CIPHER_CTX_ctrl(
                        self.ctx.as_mut_ptr(),
                        EVP_CTRL_AEAD_GET_TAG as c_int,
                        self.params.taglen as c_int,
                        cipher as *mut c_void,
                    )
                };
                if res != 1 {
                    self.finalized = true;
                    return err_rv!(CKR_DEVICE_ERROR);
                }
                clen = self.params.taglen;
            }
            CKM_AES_CTR => {
                if self.params.maxblocks > 0 {
                    if self.blockctr >= self.params.maxblocks {
                        return err_rv!(CKR_DATA_LEN_RANGE);
                    }
                }
                clen = 0;
            }
            CKM_AES_CTS | CKM_AES_CBC | CKM_AES_ECB => clen = 0,
            #[cfg(not(feature = "fips"))]
            CKM_AES_CFB8 | CKM_AES_CFB1 | CKM_AES_CFB128 | CKM_AES_OFB => {
                clen = 0
            }
            CKM_AES_CBC_PAD => {
                /* check if this is a second call after
                 * we saved the final buffer */
                if self.finalbuf.len() > 0 {
                    if clen < self.finalbuf.len() {
                        unsafe {
                            *cipher_len = self.finalbuf.len() as CK_ULONG
                        };
                        return err_rv!(CKR_BUFFER_TOO_SMALL);
                    }
                    unsafe {
                        std::ptr::copy_nonoverlapping(
                            self.finalbuf.as_ptr(),
                            cipher,
                            self.finalbuf.len(),
                        );
                    }
                    clen = self.finalbuf.len();
                } else {
                    let mut cipher_buf: *mut u8 = cipher;
                    if clen < AES_BLOCK_SIZE {
                        /* be prepared to hold the final block
                         * size from openssl, and use it later */
                        self.finalbuf.reserve_exact(AES_BLOCK_SIZE);
                        cipher_buf = self.finalbuf.as_mut_ptr();
                    }

                    let mut outl: c_int = 0;
                    let res = unsafe {
                        EVP_EncryptFinal_ex(
                            self.ctx.as_mut_ptr(),
                            cipher_buf,
                            &mut outl,
                        )
                    };
                    if res != 1 {
                        self.finalized = true;
                        return err_rv!(CKR_DEVICE_ERROR);
                    }
                    if outl == 0 {
                        self.finalized = true;
                    } else if cipher_buf != cipher {
                        if outl as usize > AES_BLOCK_SIZE {
                            self.finalized = true;
                            return err_rv!(CKR_DEVICE_ERROR);
                        }
                        if clen >= outl as usize {
                            unsafe {
                                std::ptr::copy_nonoverlapping(
                                    cipher_buf,
                                    cipher,
                                    outl as usize,
                                );
                            }
                            self.finalbuf.zeroize();
                            self.finalbuf.clear();
                        } else {
                            /* This is the only non-fatal error */
                            unsafe { *cipher_len = outl as CK_ULONG };
                            return err_rv!(CKR_BUFFER_TOO_SMALL);
                        }
                    }
                    clen = outl as usize;
                }
            }
            _ => return err_rv!(CKR_GENERAL_ERROR),
        }
        self.finalized = true;
        unsafe { *cipher_len = clen as CK_ULONG };
        Ok(())
    }

    fn encryption_len(&self, data_len: CK_ULONG) -> KResult<usize> {
        let len: usize = match self.mech {
            CKM_AES_CCM => self.params.datalen + self.params.taglen,
            CKM_AES_GCM => data_len as usize + self.params.taglen,
            CKM_AES_CTR | CKM_AES_CTS => data_len as usize,
            CKM_AES_CBC | CKM_AES_ECB => {
                ((data_len as usize + AES_BLOCK_SIZE - 1) / AES_BLOCK_SIZE)
                    * AES_BLOCK_SIZE
            }
            CKM_AES_CBC_PAD => {
                // The PKCS#7 padding adds always at least 1 byte
                ((data_len as usize + AES_BLOCK_SIZE) / AES_BLOCK_SIZE)
                    * AES_BLOCK_SIZE
            }
            #[cfg(not(feature = "fips"))]
            CKM_AES_CFB8 | CKM_AES_CFB1 | CKM_AES_CFB128 | CKM_AES_OFB => {
                data_len as usize
            }
            _ => return err_rv!(CKR_GENERAL_ERROR),
        };
        Ok(len)
    }
}

impl Decryption for AesOperation {
    fn decrypt(
        &mut self,
        cipher: &[u8],
        plain: CK_BYTE_PTR,
        plain_len: CK_ULONG_PTR,
    ) -> KResult<()> {
        if self.finalized {
            return err_rv!(CKR_OPERATION_NOT_INITIALIZED);
        }
        if plain.is_null() {
            match self.mech {
                CKM_AES_CCM => unsafe {
                    *plain_len = self.params.datalen as CK_ULONG
                },
                CKM_AES_GCM => unsafe {
                    *plain_len = (cipher.len() - self.params.taglen) as CK_ULONG
                },
                _ => self.decrypt_update(cipher, plain, plain_len)?,
            }
            return Ok(());
        }
        let plen: CK_ULONG = unsafe { *plain_len };
        let mut outb: *mut u8 = plain;
        let mut outl: CK_ULONG = unsafe { *plain_len };
        self.decrypt_update(cipher, outb, &mut outl)?;
        if outl > plen {
            self.finalized = true;
            return err_rv!(CKR_DEVICE_ERROR);
        }
        let mut foutl = plen - outl;
        outb = unsafe { plain.offset(outl as isize) };
        self.decrypt_final(outb, &mut foutl)?;
        unsafe { *plain_len = foutl + outl };
        Ok(())
    }

    fn decrypt_update(
        &mut self,
        cipher: &[u8],
        plain: CK_BYTE_PTR,
        plain_len: CK_ULONG_PTR,
    ) -> KResult<()> {
        if plain_len.is_null() {
            return err_rv!(CKR_ARGUMENTS_BAD);
        }
        if self.finalized {
            return err_rv!(CKR_OPERATION_NOT_INITIALIZED);
        }
        let outlen = match self.mech {
            CKM_AES_CCM => self.params.datalen,
            CKM_AES_GCM | CKM_AES_CTR | CKM_AES_CTS => cipher.len(),
            CKM_AES_CBC | CKM_AES_CBC_PAD | CKM_AES_ECB => {
                (cipher.len() / AES_BLOCK_SIZE) * AES_BLOCK_SIZE
            }
            #[cfg(not(feature = "fips"))]
            CKM_AES_CFB8 | CKM_AES_CFB1 | CKM_AES_CFB128 | CKM_AES_OFB => {
                cipher.len()
            }
            _ => return err_rv!(CKR_GENERAL_ERROR),
        };
        if plain.is_null() {
            unsafe {
                *plain_len = outlen as CK_ULONG;
            }
            return Ok(());
        }
        let mut cipher_buf = cipher.as_ptr();
        match self.mech {
            CKM_AES_CTS => {
                if cipher.len() < AES_BLOCK_SIZE {
                    self.finalized = true;
                    return err_rv!(CKR_DATA_LEN_RANGE);
                }

                /* CTS mode is one shot, and we use blockctr to mark that update
                 * has already been called once */
                if self.blockctr == 0 {
                    self.blockctr = 1;
                } else {
                    self.finalized = true;
                    return err_rv!(CKR_OPERATION_NOT_INITIALIZED);
                }
            }
            CKM_AES_CCM => {
                if cipher.len() + self.finalbuf.len()
                    > self.params.datalen + self.params.taglen
                {
                    self.finalized = true;
                    return err_rv!(CKR_OPERATION_NOT_INITIALIZED);
                }
            }
            _ => (),
        }
        if !self.in_use {
            self.in_use = true;
            self.decrypt_initialize()?;
        }

        let plen = unsafe { *plain_len } as usize;
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
                        self.finalized = true;
                        return err_rv!(CKR_DATA_LEN_RANGE);
                    }
                }
                if cipher.len() + self.finalbuf.len() > needlen {
                    self.finalized = true;
                    return err_rv!(CKR_DATA_LEN_RANGE);
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
                        self.finalized = true;
                        return err_rv!(CKR_DATA_LEN_RANGE);
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
            _ => cipher.len(),
        };
        if plen < outlen {
            /* This is the only, non-fatal error */
            unsafe { *plain_len = outlen as CK_ULONG };
            return err_rv!(CKR_BUFFER_TOO_SMALL);
        }

        let mut plain_buf = plain;
        let mut plen: c_int = 0;
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
                        self.finalized = true;
                        return err_rv!(CKR_DEVICE_ERROR);
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
                        let res = unsafe {
                            EVP_DecryptUpdate(
                                self.ctx.as_mut_ptr(),
                                plain_buf,
                                &mut plen,
                                self.finalbuf.as_ptr(),
                                self.finalbuf.len() as c_int,
                            )
                        };
                        if res != 1 {
                            self.finalized = true;
                            return err_rv!(CKR_ENCRYPTED_DATA_INVALID);
                        }
                        plain_buf = unsafe { plain.offset(plen as isize) };
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

        let mut outl: c_int = 0;
        if cipher_len > 0 {
            let res = unsafe {
                EVP_DecryptUpdate(
                    self.ctx.as_mut_ptr(),
                    plain_buf,
                    &mut outl,
                    cipher_buf,
                    cipher_len as c_int,
                )
            };
            if res != 1 {
                self.finalized = true;
                return err_rv!(CKR_ENCRYPTED_DATA_INVALID);
            }
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
        unsafe {
            *plain_len = (plen + outl) as CK_ULONG;
        }
        Ok(())
    }

    fn decrypt_final(
        &mut self,
        plain: CK_BYTE_PTR,
        plain_len: CK_ULONG_PTR,
    ) -> KResult<()> {
        if self.finalized {
            return err_rv!(CKR_OPERATION_NOT_INITIALIZED);
        }
        if !self.in_use {
            return err_rv!(CKR_OPERATION_NOT_INITIALIZED);
        }
        if plain.is_null() {
            let mut plen: CK_ULONG = 0;
            match self.mech {
                CKM_AES_GCM => {
                    if self.finalbuf.len() > self.params.taglen {
                        plen = (self.finalbuf.len() - self.params.taglen)
                            as CK_ULONG;
                    }
                }
                CKM_AES_CCM | CKM_AES_CTR | CKM_AES_CTS | CKM_AES_CBC
                | CKM_AES_ECB => (),
                #[cfg(not(feature = "fips"))]
                CKM_AES_CFB8 | CKM_AES_CFB1 | CKM_AES_CFB128 | CKM_AES_OFB => {
                    ()
                }
                CKM_AES_CBC_PAD => {
                    plen = AES_BLOCK_SIZE as CK_ULONG;
                    if self.finalbuf.len() > 0 {
                        plen = self.finalbuf.len() as CK_ULONG;
                    }
                }
                _ => return err_rv!(CKR_GENERAL_ERROR),
            }
            unsafe { *plain_len = plen };
            return Ok(());
        }

        let mut plen = unsafe { *plain_len } as usize;
        match self.mech {
            CKM_AES_CCM => {
                if self.finalbuf.len() > 0 {
                    self.finalized = true;
                    return err_rv!(CKR_DATA_LEN_RANGE);
                }
                plen = 0;
            }
            CKM_AES_GCM => {
                if self.finalbuf.len() != self.params.taglen {
                    self.finalized = true;
                    return err_rv!(CKR_DATA_LEN_RANGE);
                }
                let res = unsafe {
                    EVP_CIPHER_CTX_ctrl(
                        self.ctx.as_mut_ptr(),
                        EVP_CTRL_AEAD_SET_TAG as c_int,
                        self.params.taglen as c_int,
                        self.finalbuf.as_ptr() as *mut c_void,
                    )
                };
                if res != 1 {
                    self.finalized = true;
                    return err_rv!(CKR_DEVICE_ERROR);
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
                    self.finalized = true;
                    return err_rv!(CKR_ENCRYPTED_DATA_INVALID);
                }
                if outl != 0 {
                    self.finalized = true;
                    return err_rv!(CKR_DEVICE_ERROR);
                }
                plen = 0;
            }
            CKM_AES_CTR => {
                if self.params.maxblocks > 0 {
                    if self.blockctr >= self.params.maxblocks {
                        return err_rv!(CKR_DATA_LEN_RANGE);
                    }
                }
                plen = 0;
            }
            CKM_AES_CTS | CKM_AES_CBC | CKM_AES_ECB => plen = 0,
            #[cfg(not(feature = "fips"))]
            CKM_AES_CFB8 | CKM_AES_CFB1 | CKM_AES_CFB128 | CKM_AES_OFB => {
                plen = 0
            }
            CKM_AES_CBC_PAD => {
                /* check if this is a second call after
                 * we saved the final buffer */
                if self.finalbuf.len() > 0 {
                    if plen < self.finalbuf.len() {
                        unsafe { *plain_len = self.finalbuf.len() as CK_ULONG };
                        return err_rv!(CKR_BUFFER_TOO_SMALL);
                    }
                    unsafe {
                        std::ptr::copy_nonoverlapping(
                            self.finalbuf.as_ptr(),
                            plain,
                            self.finalbuf.len(),
                        );
                    }
                    plen = self.finalbuf.len();
                } else {
                    let mut plain_buf: *mut u8 = plain;
                    if plen < AES_BLOCK_SIZE {
                        /* be prepared to hold the final block
                         * size from openssl, and use it later */
                        self.finalbuf.reserve_exact(AES_BLOCK_SIZE);
                        plain_buf = self.finalbuf.as_mut_ptr();
                    }

                    let mut outl: c_int = 0;
                    let res = unsafe {
                        EVP_DecryptFinal_ex(
                            self.ctx.as_mut_ptr(),
                            plain_buf,
                            &mut outl,
                        )
                    };
                    if res != 1 {
                        self.finalized = true;
                        return err_rv!(CKR_ENCRYPTED_DATA_INVALID);
                    }
                    if outl == 0 {
                        self.finalized = true;
                    } else if plain_buf != plain {
                        if outl as usize > AES_BLOCK_SIZE {
                            self.finalized = true;
                            return err_rv!(CKR_DEVICE_ERROR);
                        }
                        if plen >= outl as usize {
                            unsafe {
                                std::ptr::copy_nonoverlapping(
                                    plain_buf,
                                    plain,
                                    outl as usize,
                                );
                            }
                        } else {
                            /* This is the only non-fatal error */
                            unsafe { *plain_len = outl as CK_ULONG };
                            return err_rv!(CKR_BUFFER_TOO_SMALL);
                        }
                    }
                    plen = outl as usize;
                }
            }
            _ => return err_rv!(CKR_GENERAL_ERROR),
        }
        self.finalized = true;
        unsafe { *plain_len = plen as CK_ULONG };
        Ok(())
    }

    fn decryption_len(&self, data_len: CK_ULONG) -> KResult<usize> {
        Ok(match self.mech {
            CKM_AES_CCM => self.params.datalen,
            CKM_AES_GCM => {
                let len = data_len as usize;
                if len > self.params.taglen {
                    len - self.params.taglen
                } else {
                    0
                }
            }
            CKM_AES_CTR | CKM_AES_CTS => data_len as usize,
            CKM_AES_CBC | CKM_AES_CBC_PAD | CKM_AES_ECB => {
                (data_len as usize / AES_BLOCK_SIZE) * AES_BLOCK_SIZE
            }
            #[cfg(not(feature = "fips"))]
            CKM_AES_CFB8 | CKM_AES_CFB1 | CKM_AES_CFB128 | CKM_AES_OFB => {
                data_len as usize
            }
            _ => return err_rv!(CKR_GENERAL_ERROR),
        })
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
    _mac: EvpMac,
    ctx: EvpMacCtx,
    maclen: usize,
}

impl AesCmacOperation {
    fn register_mechanisms(mechs: &mut Mechanisms) {
        for ckm in &[CKM_AES_CMAC, CKM_AES_CMAC_GENERAL] {
            mechs.add_mechanism(*ckm, new_mechanism(CKF_SIGN | CKF_VERIFY));
        }
    }

    fn init(mech: &CK_MECHANISM, key: &Object) -> KResult<AesCmacOperation> {
        let maclen = match mech.mechanism {
            CKM_AES_CMAC_GENERAL => {
                if mech.ulParameterLen as usize
                    != ::std::mem::size_of::<CK_MAC_GENERAL_PARAMS>()
                {
                    return err_rv!(CKR_ARGUMENTS_BAD);
                }
                let val: usize =
                    unsafe { *(mech.pParameter as CK_MAC_GENERAL_PARAMS_PTR) }
                        as usize;
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
        let mut mac = match EvpMac::from_ptr(unsafe {
            EVP_MAC_fetch(
                get_libctx(),
                name_as_char(OSSL_MAC_NAME_CMAC),
                std::ptr::null(),
            )
        }) {
            Ok(em) => em,
            Err(_) => return err_rv!(CKR_DEVICE_ERROR),
        };
        let mut ctx = match EvpMacCtx::from_ptr(unsafe {
            EVP_MAC_CTX_new(mac.as_mut_ptr())
        }) {
            Ok(emc) => emc,
            Err(_) => return err_rv!(CKR_DEVICE_ERROR),
        };
        let params = OsslParam::new()
            .add_const_c_string(
                name_as_char(OSSL_MAC_PARAM_CIPHER),
                match mackey.raw.len() {
                    16 => name_as_char(CIPHER_NAME_AES128),
                    24 => name_as_char(CIPHER_NAME_AES192),
                    32 => name_as_char(CIPHER_NAME_AES256),
                    _ => return err_rv!(CKR_KEY_INDIGESTIBLE),
                },
            )?
            .finalize();

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
            _mac: mac,
            ctx: ctx,
            maclen: maclen,
        })
    }

    fn begin(&mut self) -> KResult<()> {
        if self.in_use {
            return err_rv!(CKR_OPERATION_NOT_INITIALIZED);
        }
        Ok(())
    }

    fn update(&mut self, data: &[u8]) -> KResult<()> {
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

    fn finalize(&mut self, output: &mut [u8]) -> KResult<()> {
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
        Ok(())
    }
}

impl MechOperation for AesCmacOperation {
    fn finalized(&self) -> bool {
        self.finalized
    }
}

impl Mac for AesCmacOperation {
    fn mac(&mut self, data: &[u8], mac: &mut [u8]) -> KResult<()> {
        self.begin()?;
        if data.len() > 0 {
            self.update(data)?;
        }
        self.finalize(mac)
    }

    fn mac_update(&mut self, data: &[u8]) -> KResult<()> {
        self.update(data)
    }

    fn mac_final(&mut self, mac: &mut [u8]) -> KResult<()> {
        self.finalize(mac)
    }

    fn mac_len(&self) -> KResult<usize> {
        Ok(self.maclen)
    }
}

impl Sign for AesCmacOperation {
    fn sign(&mut self, data: &[u8], signature: &mut [u8]) -> KResult<()> {
        self.begin()?;
        if data.len() > 0 {
            self.update(data)?;
        }
        self.finalize(signature)
    }

    fn sign_update(&mut self, data: &[u8]) -> KResult<()> {
        self.update(data)
    }

    fn sign_final(&mut self, signature: &mut [u8]) -> KResult<()> {
        self.finalize(signature)
    }

    fn signature_len(&self) -> KResult<usize> {
        Ok(self.maclen)
    }
}

impl Verify for AesCmacOperation {
    fn verify(&mut self, data: &[u8], signature: &[u8]) -> KResult<()> {
        self.begin()?;
        if data.len() > 0 {
            self.update(data)?;
        }
        self.verify_final(signature)
    }

    fn verify_update(&mut self, data: &[u8]) -> KResult<()> {
        self.update(data)
    }

    fn verify_final(&mut self, signature: &[u8]) -> KResult<()> {
        let mut verify: Vec<u8> = vec![0; self.maclen];
        self.finalize(verify.as_mut_slice())?;
        if !constant_time_eq(&verify, signature) {
            return err_rv!(CKR_SIGNATURE_INVALID);
        }
        Ok(())
    }

    fn signature_len(&self) -> KResult<usize> {
        Ok(self.maclen)
    }
}

#[cfg(not(feature = "fips"))]
include!("aes_mac.rs");
