// Copyright 2024 Simo Sorce
// See LICENSE.txt file for terms

#[cfg(feature = "fips")]
use {super::fips, fips::*};

#[cfg(not(feature = "fips"))]
use {super::ossl, ossl::*};

use std::ffi::{c_char, c_int, c_void};
use zeroize::Zeroize;

const MAX_CCM_BUF: usize = 1 << 20; /* 1MiB */

const AES_BLOCK_SIZE: usize = 16;
const AES_128_CCM_NAME: &[u8; 12] = b"AES-128-CCM\0";
const AES_192_CCM_NAME: &[u8; 12] = b"AES-192-CCM\0";
const AES_256_CCM_NAME: &[u8; 12] = b"AES-256-CCM\0";
const AES_128_GCM_NAME: &[u8; 12] = b"AES-128-GCM\0";
const AES_192_GCM_NAME: &[u8; 12] = b"AES-192-GCM\0";
const AES_256_GCM_NAME: &[u8; 12] = b"AES-256-GCM\0";
const AES_128_CTS_NAME: &[u8; 16] = b"AES-128-CBC-CTS\0";
const AES_192_CTS_NAME: &[u8; 16] = b"AES-192-CBC-CTS\0";
const AES_256_CTS_NAME: &[u8; 16] = b"AES-256-CBC-CTS\0";
const AES_128_CTR_NAME: &[u8; 12] = b"AES-128-CTR\0";
const AES_192_CTR_NAME: &[u8; 12] = b"AES-192-CTR\0";
const AES_256_CTR_NAME: &[u8; 12] = b"AES-256-CTR\0";
const AES_128_CBC_NAME: &[u8; 12] = b"AES-128-CBC\0";
const AES_192_CBC_NAME: &[u8; 12] = b"AES-192-CBC\0";
const AES_256_CBC_NAME: &[u8; 12] = b"AES-256-CBC\0";
const AES_128_ECB_NAME: &[u8; 12] = b"AES-128-ECB\0";
const AES_192_ECB_NAME: &[u8; 12] = b"AES-192-ECB\0";
const AES_256_ECB_NAME: &[u8; 12] = b"AES-256-ECB\0";

cfg_if::cfg_if! {
    if #[cfg(not(feature = "fips"))] {
        const AES_128_CFB8_NAME: &[u8; 13] = b"AES-128-CFB8\0";
        const AES_192_CFB8_NAME: &[u8; 13] = b"AES-192-CFB8\0";
        const AES_256_CFB8_NAME: &[u8; 13] = b"AES-256-CFB8\0";
        const AES_128_CFB1_NAME: &[u8; 13] = b"AES-128-CFB1\0";
        const AES_192_CFB1_NAME: &[u8; 13] = b"AES-192-CFB1\0";
        const AES_256_CFB1_NAME: &[u8; 13] = b"AES-256-CFB1\0";
        const AES_128_CFB_NAME: &[u8; 12] = b"AES-128-CFB\0";
        const AES_192_CFB_NAME: &[u8; 12] = b"AES-192-CFB\0";
        const AES_256_CFB_NAME: &[u8; 12] = b"AES-256-CFB\0";
        const AES_128_OFB_NAME: &[u8; 12] = b"AES-128-OFB\0";
        const AES_192_OFB_NAME: &[u8; 12] = b"AES-192-OFB\0";
        const AES_256_OFB_NAME: &[u8; 12] = b"AES-256-OFB\0";
    }
}

/* FIXME: change this to be a map, and initialize ciphers on demand
 * via accessors */
cfg_if::cfg_if! {
    if #[cfg(feature = "fips")] {
        struct AesCiphers {
            aes128ccm: EvpCipher,
            aes192ccm: EvpCipher,
            aes256ccm: EvpCipher,
            aes128gcm: EvpCipher,
            aes192gcm: EvpCipher,
            aes256gcm: EvpCipher,
            aes128cts: EvpCipher,
            aes192cts: EvpCipher,
            aes256cts: EvpCipher,
            aes128ctr: EvpCipher,
            aes192ctr: EvpCipher,
            aes256ctr: EvpCipher,
            aes128cbc: EvpCipher,
            aes192cbc: EvpCipher,
            aes256cbc: EvpCipher,
            aes128ecb: EvpCipher,
            aes192ecb: EvpCipher,
            aes256ecb: EvpCipher,
        }
    } else {
        struct AesCiphers {
            aes128ccm: EvpCipher,
            aes192ccm: EvpCipher,
            aes256ccm: EvpCipher,
            aes128gcm: EvpCipher,
            aes192gcm: EvpCipher,
            aes256gcm: EvpCipher,
            aes128cts: EvpCipher,
            aes192cts: EvpCipher,
            aes256cts: EvpCipher,
            aes128ctr: EvpCipher,
            aes192ctr: EvpCipher,
            aes256ctr: EvpCipher,
            aes128cbc: EvpCipher,
            aes192cbc: EvpCipher,
            aes256cbc: EvpCipher,
            aes128ecb: EvpCipher,
            aes192ecb: EvpCipher,
            aes256ecb: EvpCipher,
            aes128cfb8: EvpCipher,
            aes192cfb8: EvpCipher,
            aes256cfb8: EvpCipher,
            aes128cfb1: EvpCipher,
            aes192cfb1: EvpCipher,
            aes256cfb1: EvpCipher,
            aes128cfb: EvpCipher,
            aes192cfb: EvpCipher,
            aes256cfb: EvpCipher,
            aes128ofb: EvpCipher,
            aes192ofb: EvpCipher,
            aes256ofb: EvpCipher,
        }
    }
}

/* It is safe to share const ciphers as they do not change once they have been
 * created, and reference satic function pointers and other data that is
 * always valid */
unsafe impl Send for AesCiphers {}
unsafe impl Sync for AesCiphers {}

fn init_cipher(name: &[u8]) -> EvpCipher {
    EvpCipher::from_ptr(unsafe {
        EVP_CIPHER_fetch(
            get_libctx(),
            name.as_ptr() as *const i8,
            std::ptr::null(),
        )
    })
    .unwrap()
}

cfg_if::cfg_if! {
    if #[cfg(feature = "fips")] {
        static AES_CIPHERS: Lazy<AesCiphers> = Lazy::new(|| AesCiphers {
            aes128ccm: init_cipher(AES_128_CCM_NAME),
            aes192ccm: init_cipher(AES_192_CCM_NAME),
            aes256ccm: init_cipher(AES_256_CCM_NAME),
            aes128gcm: init_cipher(AES_128_GCM_NAME),
            aes192gcm: init_cipher(AES_192_GCM_NAME),
            aes256gcm: init_cipher(AES_256_GCM_NAME),
            aes128cts: init_cipher(AES_128_CTS_NAME),
            aes192cts: init_cipher(AES_192_CTS_NAME),
            aes256cts: init_cipher(AES_256_CTS_NAME),
            aes128ctr: init_cipher(AES_128_CTR_NAME),
            aes192ctr: init_cipher(AES_192_CTR_NAME),
            aes256ctr: init_cipher(AES_256_CTR_NAME),
            aes128cbc: init_cipher(AES_128_CBC_NAME),
            aes192cbc: init_cipher(AES_192_CBC_NAME),
            aes256cbc: init_cipher(AES_256_CBC_NAME),
            aes128ecb: init_cipher(AES_128_ECB_NAME),
            aes192ecb: init_cipher(AES_192_ECB_NAME),
            aes256ecb: init_cipher(AES_256_ECB_NAME),
        });
    } else {
        static AES_CIPHERS: Lazy<AesCiphers> = Lazy::new(|| AesCiphers {
            aes128ccm: init_cipher(AES_128_CCM_NAME),
            aes192ccm: init_cipher(AES_192_CCM_NAME),
            aes256ccm: init_cipher(AES_256_CCM_NAME),
            aes128gcm: init_cipher(AES_128_GCM_NAME),
            aes192gcm: init_cipher(AES_192_GCM_NAME),
            aes256gcm: init_cipher(AES_256_GCM_NAME),
            aes128cts: init_cipher(AES_128_CTS_NAME),
            aes192cts: init_cipher(AES_192_CTS_NAME),
            aes256cts: init_cipher(AES_256_CTS_NAME),
            aes128ctr: init_cipher(AES_128_CTR_NAME),
            aes192ctr: init_cipher(AES_192_CTR_NAME),
            aes256ctr: init_cipher(AES_256_CTR_NAME),
            aes128cbc: init_cipher(AES_128_CBC_NAME),
            aes192cbc: init_cipher(AES_192_CBC_NAME),
            aes256cbc: init_cipher(AES_256_CBC_NAME),
            aes128ecb: init_cipher(AES_128_ECB_NAME),
            aes192ecb: init_cipher(AES_192_ECB_NAME),
            aes256ecb: init_cipher(AES_256_ECB_NAME),
            aes128cfb8: init_cipher(AES_128_CFB8_NAME),
            aes192cfb8: init_cipher(AES_192_CFB8_NAME),
            aes256cfb8: init_cipher(AES_256_CFB8_NAME),
            aes128cfb1: init_cipher(AES_128_CFB1_NAME),
            aes192cfb1: init_cipher(AES_192_CFB1_NAME),
            aes256cfb1: init_cipher(AES_256_CFB1_NAME),
            aes128cfb: init_cipher(AES_128_CFB_NAME),
            aes192cfb: init_cipher(AES_192_CFB_NAME),
            aes256cfb: init_cipher(AES_256_CFB_NAME),
            aes128ofb: init_cipher(AES_128_OFB_NAME),
            aes192ofb: init_cipher(AES_192_OFB_NAME),
            aes256ofb: init_cipher(AES_256_OFB_NAME),
        });
    }
}

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

#[derive(Debug)]
struct AesParams {
    pad: bool,
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
    ctx: Option<EvpCipherCtx>,
    blocksize: usize,
    finalbuf: Vec<u8>,
    blockctr: u128,
}

impl Drop for AesOperation {
    fn drop(&mut self) {
        self.finalbuf.zeroize()
    }
}

impl AesOperation {
    fn init_params(mech: &CK_MECHANISM) -> KResult<AesParams> {
        let mut maxblocks = 0u128;
        let pad = match mech.mechanism {
            CKM_AES_CCM | CKM_AES_GCM | CKM_AES_CTS | CKM_AES_CTR
            | CKM_AES_CBC | CKM_AES_ECB => false,
            CKM_AES_CBC_PAD => true,
            #[cfg(not(feature = "fips"))]
            CKM_AES_CFB8 | CKM_AES_CFB1 | CKM_AES_CFB128 | CKM_AES_OFB => false,
            _ => return err_rv!(CKR_MECHANISM_INVALID),
        };
        let mut ctsmode = 0u8;
        if mech.mechanism == CKM_AES_CTS {
            ctsmode = 1u8;
        }
        match mech.mechanism {
            CKM_AES_CCM => {
                if mech.ulParameterLen as usize
                    != ::std::mem::size_of::<CK_CCM_PARAMS>()
                {
                    return err_rv!(CKR_ARGUMENTS_BAD);
                }
                let ccm_params = mech.pParameter as *const CK_CCM_PARAMS;
                let datalen = unsafe { (*ccm_params).ulDataLen as usize };
                let noncelen = unsafe { (*ccm_params).ulNonceLen as usize };
                let maclen = unsafe { (*ccm_params).ulMACLen as usize };
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
                    pad: pad,
                    iv: unsafe {
                        std::slice::from_raw_parts(
                            (*ccm_params).pNonce,
                            noncelen,
                        )
                        .to_vec()
                    },
                    maxblocks: maxblocks,
                    ctsmode: 0,
                    datalen: datalen,
                    aad: unsafe {
                        if aadlen > 0 {
                            std::slice::from_raw_parts(
                                (*ccm_params).pAAD,
                                aadlen,
                            )
                            .to_vec()
                        } else {
                            Vec::new()
                        }
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
                Ok(AesParams {
                    pad: pad,
                    iv: unsafe {
                        std::slice::from_raw_parts(
                            (*gcm_params).pIv,
                            (*gcm_params).ulIvLen as usize,
                        )
                        .to_vec()
                    },
                    maxblocks: maxblocks,
                    ctsmode: 0,
                    datalen: 0,
                    aad: unsafe {
                        if (*gcm_params).ulAADLen > 0 {
                            std::slice::from_raw_parts(
                                (*gcm_params).pAAD,
                                (*gcm_params).ulAADLen as usize,
                            )
                            .to_vec()
                        } else {
                            Vec::new()
                        }
                    },
                    taglen: unsafe { ((*gcm_params).ulTagBits + 7) / 8 }
                        as usize,
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
                if ctrbits < (AES_BLOCK_SIZE * 8) {
                    /* FIXME: support arbitrary counterbits wrapping.
                     * OpenSSL CTR mode is built to handle the whole IV
                     * as a 128bit counter unconditionally.
                     * For callers that want a smaller counterbit size all
                     * we can do is to set a maximum number of blocks so
                     * that the counter space does *not* wrap (because
                     * openssl won't wrap it but proceed to increment the
                     * octects part of the IV/Nonce). This means that for
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
                    pad: pad,
                    iv: iv,
                    maxblocks: maxblocks,
                    ctsmode: 0,
                    datalen: 0,
                    aad: Vec::new(),
                    taglen: 0,
                })
            }
            CKM_AES_CTS | CKM_AES_CBC | CKM_AES_CBC_PAD => {
                if mech.ulParameterLen != 16 {
                    return err_rv!(CKR_ARGUMENTS_BAD);
                }
                Ok(AesParams {
                    pad: pad,
                    iv: unsafe {
                        std::slice::from_raw_parts(
                            mech.pParameter as *mut u8,
                            mech.ulParameterLen as usize,
                        )
                        .to_vec()
                    },
                    maxblocks: maxblocks,
                    ctsmode: ctsmode,
                    datalen: 0,
                    aad: Vec::new(),
                    taglen: 0,
                })
            }
            CKM_AES_ECB => Ok(AesParams {
                pad: pad,
                iv: Vec::with_capacity(0),
                maxblocks: maxblocks,
                ctsmode: 0,
                datalen: 0,
                aad: Vec::new(),
                taglen: 0,
            }),
            #[cfg(not(feature = "fips"))]
            CKM_AES_CFB8 | CKM_AES_CFB1 | CKM_AES_CFB128 | CKM_AES_OFB => {
                if mech.ulParameterLen != 16 {
                    return err_rv!(CKR_ARGUMENTS_BAD);
                }
                Ok(AesParams {
                    pad: pad,
                    iv: unsafe {
                        std::slice::from_raw_parts(
                            mech.pParameter as *mut u8,
                            mech.ulParameterLen as usize,
                        )
                        .to_vec()
                    },
                    maxblocks: maxblocks,
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
                16 => &AES_CIPHERS.aes128ccm,
                24 => &AES_CIPHERS.aes192ccm,
                32 => &AES_CIPHERS.aes256ccm,
                _ => return err_rv!(CKR_MECHANISM_INVALID),
            },
            CKM_AES_GCM => match keylen {
                16 => &AES_CIPHERS.aes128gcm,
                24 => &AES_CIPHERS.aes192gcm,
                32 => &AES_CIPHERS.aes256gcm,
                _ => return err_rv!(CKR_MECHANISM_INVALID),
            },
            CKM_AES_CTS => match keylen {
                16 => &AES_CIPHERS.aes128cts,
                24 => &AES_CIPHERS.aes192cts,
                32 => &AES_CIPHERS.aes256cts,
                _ => return err_rv!(CKR_MECHANISM_INVALID),
            },
            CKM_AES_CTR => match keylen {
                16 => &AES_CIPHERS.aes128ctr,
                24 => &AES_CIPHERS.aes192ctr,
                32 => &AES_CIPHERS.aes256ctr,
                _ => return err_rv!(CKR_MECHANISM_INVALID),
            },
            CKM_AES_CBC => match keylen {
                16 => &AES_CIPHERS.aes128cbc,
                24 => &AES_CIPHERS.aes192cbc,
                32 => &AES_CIPHERS.aes256cbc,
                _ => return err_rv!(CKR_MECHANISM_INVALID),
            },
            CKM_AES_CBC_PAD => match keylen {
                16 => &AES_CIPHERS.aes128cbc,
                24 => &AES_CIPHERS.aes192cbc,
                32 => &AES_CIPHERS.aes256cbc,
                _ => return err_rv!(CKR_MECHANISM_INVALID),
            },
            CKM_AES_ECB => match keylen {
                16 => &AES_CIPHERS.aes128ecb,
                24 => &AES_CIPHERS.aes192ecb,
                32 => &AES_CIPHERS.aes256ecb,
                _ => return err_rv!(CKR_MECHANISM_INVALID),
            },
            #[cfg(not(feature = "fips"))]
            CKM_AES_CFB8 => match keylen {
                16 => &AES_CIPHERS.aes128cfb8,
                24 => &AES_CIPHERS.aes192cfb8,
                32 => &AES_CIPHERS.aes256cfb8,
                _ => return err_rv!(CKR_MECHANISM_INVALID),
            },
            #[cfg(not(feature = "fips"))]
            CKM_AES_CFB1 => match keylen {
                16 => &AES_CIPHERS.aes128cfb1,
                24 => &AES_CIPHERS.aes192cfb1,
                32 => &AES_CIPHERS.aes256cfb1,
                _ => return err_rv!(CKR_MECHANISM_INVALID),
            },
            #[cfg(not(feature = "fips"))]
            CKM_AES_CFB128 => match keylen {
                16 => &AES_CIPHERS.aes128cfb,
                24 => &AES_CIPHERS.aes192cfb,
                32 => &AES_CIPHERS.aes256cfb,
                _ => return err_rv!(CKR_MECHANISM_INVALID),
            },
            #[cfg(not(feature = "fips"))]
            CKM_AES_OFB => match keylen {
                16 => &AES_CIPHERS.aes128ofb,
                24 => &AES_CIPHERS.aes192ofb,
                32 => &AES_CIPHERS.aes256ofb,
                _ => return err_rv!(CKR_MECHANISM_INVALID),
            },
            _ => return err_rv!(CKR_MECHANISM_INVALID),
        })
    }

    fn encrypt_new(mech: &CK_MECHANISM, key: &Object) -> KResult<AesOperation> {
        Ok(AesOperation {
            mech: mech.mechanism,
            key: object_to_raw_key(key)?,
            params: Self::init_params(mech)?,
            finalized: false,
            in_use: false,
            ctx: Some(EvpCipherCtx::from_ptr(unsafe { EVP_CIPHER_CTX_new() })?),
            blocksize: 0,
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
            ctx: Some(EvpCipherCtx::from_ptr(unsafe { EVP_CIPHER_CTX_new() })?),
            blocksize: 0,
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
    fn mechanism(&self) -> CK_MECHANISM_TYPE {
        self.mech
    }
    fn in_use(&self) -> bool {
        self.in_use
    }
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
            self.encrypt_update(plain, cipher, cipher_len)?;
            if self.params.taglen > 0 {
                unsafe {
                    let mut len = *cipher_len;
                    len += self.params.taglen as CK_ULONG;
                    *cipher_len = len;
                }
            }
            return Ok(());
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
        if self.params.ctsmode != 0 {
            if plain.len() < AES_BLOCK_SIZE {
                self.finalized = true;
                return err_rv!(CKR_DATA_LEN_RANGE);
            }
        }
        if self.params.datalen > 0 {
            if plain.len() + self.finalbuf.len() > self.params.datalen {
                self.finalized = true;
                return err_rv!(CKR_DATA_LEN_RANGE);
            }
        }
        if self.mech == CKM_AES_CTS {
            /* some modes are one shot, and we use blockctr to mark that update
             * has already been called once */
            if self.blockctr == 0 {
                self.blockctr = 1;
            } else {
                self.finalized = true;
                return err_rv!(CKR_OPERATION_NOT_INITIALIZED);
            }
        }
        if !self.in_use {
            self.in_use = true;

            let evpcipher =
                match Self::init_cipher(self.mech, self.key.raw.len()) {
                    Ok(c) => c,
                    Err(e) => {
                        self.finalized = true;
                        return Err(e);
                    }
                };

            /* Need to initialize the cipher on the ctx first, as some modes
             * will attempt to set parameters that require it on the contex,
             * before key and iv can be installed */
            if unsafe {
                EVP_EncryptInit_ex2(
                    self.ctx.as_mut().unwrap().as_mut_ptr(),
                    evpcipher.as_ptr(),
                    std::ptr::null(),
                    std::ptr::null(),
                    std::ptr::null(),
                )
            } != 1
            {
                self.finalized = true;
                return err_rv!(CKR_DEVICE_ERROR);
            }

            let mut params: Vec<OSSL_PARAM> = Vec::new();
            if self.mech == CKM_AES_GCM {
                /* The IV size must be 12 in FIPS mode and if we try to
                 * actively set it to any value (including 12) in FIPS
                 * mode it will cause a cipher failure due to how
                 * OpenSSL sets internal states. So avoid setting the IVLEN
                 * when the ivsize matches the default */
                if self.params.iv.len() != 12 {
                    if unsafe {
                        EVP_CIPHER_CTX_ctrl(
                            self.ctx.as_mut().unwrap().as_mut_ptr(),
                            EVP_CTRL_AEAD_SET_IVLEN as c_int,
                            self.params.iv.len() as c_int,
                            std::ptr::null_mut(),
                        )
                    } != 1
                    {
                        self.finalized = true;
                        return err_rv!(CKR_DEVICE_ERROR);
                    }
                }
            } else if self.mech == CKM_AES_CCM {
                if unsafe {
                    EVP_CIPHER_CTX_ctrl(
                        self.ctx.as_mut().unwrap().as_mut_ptr(),
                        EVP_CTRL_AEAD_SET_IVLEN as c_int,
                        self.params.iv.len() as c_int,
                        std::ptr::null_mut(),
                    )
                } != 1
                {
                    self.finalized = true;
                    return err_rv!(CKR_DEVICE_ERROR);
                }
                if unsafe {
                    EVP_CIPHER_CTX_ctrl(
                        self.ctx.as_mut().unwrap().as_mut_ptr(),
                        EVP_CTRL_AEAD_SET_TAG as c_int,
                        self.params.taglen as c_int,
                        std::ptr::null_mut(),
                    )
                } != 1
                {
                    self.finalized = true;
                    return err_rv!(CKR_DEVICE_ERROR);
                }
            } else if self.params.ctsmode != 0 {
                unsafe {
                    params = vec![
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
                }
            }
            let params_ptr: *const OSSL_PARAM = if params.len() > 0 {
                params.as_ptr()
            } else {
                std::ptr::null()
            };

            /* set key, iv, addtional params */
            if unsafe {
                EVP_EncryptInit_ex2(
                    self.ctx.as_mut().unwrap().as_mut_ptr(),
                    std::ptr::null(),
                    self.key.raw.as_ptr(),
                    if self.params.iv.len() != 0 {
                        self.params.iv.as_ptr()
                    } else {
                        std::ptr::null()
                    },
                    params_ptr,
                )
            } != 1
            {
                self.finalized = true;
                return err_rv!(CKR_DEVICE_ERROR);
            }
            if unsafe {
                EVP_CIPHER_CTX_set_padding(
                    self.ctx.as_mut().unwrap().as_mut_ptr(),
                    if self.params.pad { 1 } else { 0 },
                )
            } != 1
            {
                self.finalized = true;
                return err_rv!(CKR_DEVICE_ERROR);
            }
            self.blocksize =
                unsafe { EVP_CIPHER_get_block_size(evpcipher.as_ptr()) }
                    as usize;
            if self.params.ctsmode > 0 {
                /* although CTS has a blocksize of 16, it allows arbitrary
                 * sized output, so we force the apparent blocksize to 1
                 * to make the follwing calculation work out to check
                 * valid buffer lengths */
                self.blocksize = 1;
            }

            if self.params.datalen != 0 {
                let mut outl: c_int = 0;
                if unsafe {
                    EVP_EncryptUpdate(
                        self.ctx.as_mut().unwrap().as_mut_ptr(),
                        std::ptr::null_mut(),
                        &mut outl,
                        std::ptr::null(),
                        self.params.datalen as c_int,
                    )
                } != 1
                {
                    self.finalized = true;
                    return err_rv!(CKR_DEVICE_ERROR);
                }
            }

            if self.params.aad.len() > 0 {
                let mut outl: c_int = 0;
                if unsafe {
                    EVP_EncryptUpdate(
                        self.ctx.as_mut().unwrap().as_mut_ptr(),
                        std::ptr::null_mut(),
                        &mut outl,
                        self.params.aad.as_ptr(),
                        self.params.aad.len() as c_int,
                    )
                } != 1
                {
                    self.finalized = true;
                    return err_rv!(CKR_DEVICE_ERROR);
                }
            }
        }

        let cipher_ulen = unsafe { *cipher_len } as usize;
        let outblocks = plain.len() / self.blocksize;
        let mut outlen = outblocks * self.blocksize;
        if cipher.is_null() {
            if self.params.datalen > 0 {
                outlen = self.params.datalen - self.finalbuf.len();
            }
            unsafe {
                *cipher_len = outlen as CK_ULONG;
            }
            return Ok(());
        } else {
            /* This should allow smaller plain length to update piecemeal,
             * but CCM is one shot in OpenSSL so we have to force a full
             * update for large datalens (we accumulate on behalf of
             * OpenSSL up to 1 MiB) */
            if self.params.datalen > 0 {
                if self.params.datalen > MAX_CCM_BUF {
                    if plain.len() != self.params.datalen {
                        self.finalized = true;
                        return err_rv!(CKR_DATA_LEN_RANGE);
                    }
                    outlen = self.params.datalen;
                } else if self.params.datalen
                    == plain.len() + self.finalbuf.len()
                {
                    outlen = self.params.datalen;
                } else {
                    outlen = 0;
                }
            }

            if cipher_ulen < outlen {
                /* This is the only, non-fatal error */
                return err_rv!(CKR_BUFFER_TOO_SMALL);
            }
        }

        if self.params.maxblocks > 0 {
            let reqblocks =
                ((plain.len() + AES_BLOCK_SIZE - 1) / AES_BLOCK_SIZE) as u128;
            if self.blockctr + reqblocks > self.params.maxblocks {
                self.finalized = true;
                return err_rv!(CKR_DATA_LEN_RANGE);
            }
            self.blockctr += reqblocks;
        }

        let mut plain_buf = plain.as_ptr();
        let mut plain_len = plain.len();
        if self.params.datalen > 0 {
            if plain.len() < self.params.datalen {
                if self.params.datalen > MAX_CCM_BUF {
                    self.finalized = true;
                    return err_rv!(CKR_DATA_LEN_RANGE);
                }
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
        if plain_len > 0
            && unsafe {
                EVP_EncryptUpdate(
                    self.ctx.as_mut().unwrap().as_mut_ptr(),
                    cipher,
                    &mut outl,
                    plain_buf,
                    plain_len as c_int,
                )
            } != 1
        {
            self.finalized = true;
            return err_rv!(CKR_DEVICE_ERROR);
        }
        if plain_len > 0 && plain_buf == self.finalbuf.as_ptr() {
            self.finalbuf.zeroize();
            self.finalbuf.clear();
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
            if self.params.taglen > 0 {
                if self.params.datalen > 0 {
                    if self.finalbuf.len() != 0 {
                        self.finalized = true;
                        return err_rv!(CKR_DATA_LEN_RANGE);
                    }
                }
                unsafe {
                    *cipher_len = self.params.taglen as CK_ULONG;
                }
                return Ok(());
            }
            if !self.params.pad {
                unsafe {
                    *cipher_len = 0;
                }
                return Ok(());
            }
            /* OpenSSL does not let us know if there is remaining data to output, so we always have
             * to report the max if queried, which is a full blocksize */
            let mut clen: CK_ULONG = self.blocksize as CK_ULONG;
            if self.finalbuf.len() > 0 {
                clen = self.finalbuf.len() as CK_ULONG;
            }

            unsafe {
                *cipher_len = clen;
            }
            return Ok(());
        }

        if self.params.taglen > 0 {
            let clen = unsafe { *cipher_len } as usize;
            if clen < self.params.taglen {
                /* This is the only, non-fatal error */
                return err_rv!(CKR_BUFFER_TOO_SMALL);
            }
            let mut outl: c_int = 0;
            if unsafe {
                /* This will normally be a noop (GCM/CCM) */
                EVP_EncryptFinal_ex(
                    self.ctx.as_mut().unwrap().as_mut_ptr(),
                    cipher,
                    &mut outl,
                )
            } != 1
            {
                self.finalized = true;
                return err_rv!(CKR_DEVICE_ERROR);
            }
            if outl as usize != 0 {
                self.finalized = true;
                return err_rv!(CKR_DEVICE_ERROR);
            }
            if unsafe {
                EVP_CIPHER_CTX_ctrl(
                    self.ctx.as_mut().unwrap().as_mut_ptr(),
                    EVP_CTRL_AEAD_GET_TAG as c_int,
                    self.params.taglen as c_int,
                    cipher as *mut c_void,
                )
            } != 1
            {
                self.finalized = true;
                return err_rv!(CKR_DEVICE_ERROR);
            }
            self.finalized = true;
            unsafe {
                *cipher_len = self.params.taglen as CK_ULONG;
            }
            return Ok(());
        }

        if !self.params.pad {
            self.finalized = true;
            unsafe {
                *cipher_len = 0;
            }
            return Ok(());
        }

        if self.params.maxblocks > 0 {
            if self.blockctr >= self.params.maxblocks {
                return err_rv!(CKR_DATA_LEN_RANGE);
            }
        }

        let mut cipher_buf: *mut u8 = cipher;
        let cipher_ulen = unsafe { *cipher_len } as usize;
        /* check if this is a second call where we saved the final buffer */
        if self.finalbuf.len() > 0 {
            if cipher_ulen < self.finalbuf.len() {
                return err_rv!(CKR_BUFFER_TOO_SMALL);
            }
            self.finalized = true;
            unsafe {
                std::ptr::copy_nonoverlapping(
                    self.finalbuf.as_ptr(),
                    cipher,
                    self.finalbuf.len(),
                );
                *cipher_len = self.finalbuf.len() as CK_ULONG;
            }
            return Ok(());
        }

        if cipher_ulen < self.blocksize {
            /* if we get less then we need to be prepared to hold the final block size from
             * openssl, and return it later */
            self.finalbuf.reserve_exact(self.blocksize);
            cipher_buf = self.finalbuf.as_mut_ptr();
        } else {
            self.finalized = true;
        }

        let mut outl: c_int = 0;
        if unsafe {
            EVP_EncryptFinal_ex(
                self.ctx.as_mut().unwrap().as_mut_ptr(),
                cipher_buf,
                &mut outl,
            )
        } != 1
        {
            self.finalized = true;
            return err_rv!(CKR_DEVICE_ERROR);
        }
        if outl == 0 {
            self.finalized = true;
        } else if cipher_buf != cipher {
            if outl as usize > self.blocksize {
                self.finalized = true;
                return err_rv!(CKR_DEVICE_ERROR);
            }
            unsafe {
                self.finalbuf.set_len(outl as usize);
            }
            if cipher_ulen >= outl as usize {
                unsafe {
                    std::ptr::copy_nonoverlapping(
                        cipher_buf,
                        cipher,
                        outl as usize,
                    );
                }
                self.finalized = true;
            } else {
                /* This is the only non-fatal error */
                return err_rv!(CKR_BUFFER_TOO_SMALL);
            }
        }
        unsafe {
            *cipher_len = outl as CK_ULONG;
        }
        Ok(())
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
            if self.params.taglen > 0 {
                if self.params.datalen > 0 {
                    unsafe { *plain_len = self.params.datalen as CK_ULONG }
                } else {
                    unsafe {
                        *plain_len =
                            (cipher.len() - self.params.taglen) as CK_ULONG
                    };
                }
                return Ok(());
            }
            return self.decrypt_update(cipher, plain, plain_len);
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
        let mut cipher_buf = cipher.as_ptr();
        if self.params.ctsmode != 0 {
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
        if !self.in_use {
            self.in_use = true;

            let evpcipher =
                match Self::init_cipher(self.mech, self.key.raw.len()) {
                    Ok(c) => c,
                    Err(e) => {
                        self.finalized = true;
                        return Err(e);
                    }
                };

            if unsafe {
                EVP_DecryptInit_ex2(
                    self.ctx.as_mut().unwrap().as_mut_ptr(),
                    evpcipher.as_ptr(),
                    std::ptr::null(),
                    std::ptr::null(),
                    std::ptr::null(),
                )
            } != 1
            {
                self.finalized = true;
                return err_rv!(CKR_DEVICE_ERROR);
            }
            let mut params: Vec<OSSL_PARAM> = Vec::new();
            if self.mech == CKM_AES_GCM {
                /* The IV size must be 12 in FIPS mode and if we try to
                 * actively set it to any value (including 12) in FIPS
                 * mode it will cause a cipher failure due to how
                 * OpenSSL sets internal states. So avoid setting the IVLEN
                 * when the ivsize matches the default */
                if self.params.iv.len() != 12 {
                    if unsafe {
                        EVP_CIPHER_CTX_ctrl(
                            self.ctx.as_mut().unwrap().as_mut_ptr(),
                            EVP_CTRL_AEAD_SET_IVLEN as c_int,
                            self.params.iv.len() as c_int,
                            std::ptr::null_mut(),
                        )
                    } != 1
                    {
                        self.finalized = true;
                        return err_rv!(CKR_DEVICE_ERROR);
                    }
                }
            } else if self.mech == CKM_AES_CCM {
                if unsafe {
                    EVP_CIPHER_CTX_ctrl(
                        self.ctx.as_mut().unwrap().as_mut_ptr(),
                        EVP_CTRL_AEAD_SET_IVLEN as c_int,
                        self.params.iv.len() as c_int,
                        std::ptr::null_mut(),
                    )
                } != 1
                {
                    self.finalized = true;
                    return err_rv!(CKR_DEVICE_ERROR);
                }
                if unsafe {
                    EVP_CIPHER_CTX_ctrl(
                        self.ctx.as_mut().unwrap().as_mut_ptr(),
                        EVP_CTRL_AEAD_SET_TAG as c_int,
                        self.params.taglen as c_int,
                        std::ptr::null_mut(),
                    )
                } != 1
                {
                    self.finalized = true;
                    return err_rv!(CKR_DEVICE_ERROR);
                }
            } else if self.params.ctsmode != 0 {
                unsafe {
                    params = vec![
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
                }
            }
            let params_ptr: *const OSSL_PARAM = if params.len() > 0 {
                params.as_ptr()
            } else {
                std::ptr::null()
            };

            /* set key, iv, addtional params */
            if unsafe {
                EVP_DecryptInit_ex2(
                    self.ctx.as_mut().unwrap().as_mut_ptr(),
                    std::ptr::null(),
                    self.key.raw.as_ptr(),
                    if self.params.iv.len() != 0 {
                        self.params.iv.as_ptr()
                    } else {
                        std::ptr::null()
                    },
                    params_ptr,
                )
            } != 1
            {
                self.finalized = true;
                return err_rv!(CKR_DEVICE_ERROR);
            }
            if unsafe {
                EVP_CIPHER_CTX_set_padding(
                    self.ctx.as_mut().unwrap().as_mut_ptr(),
                    if self.params.pad { 1 } else { 0 },
                )
            } != 1
            {
                self.finalized = true;
                return err_rv!(CKR_DEVICE_ERROR);
            }
            self.blocksize =
                unsafe { EVP_CIPHER_get_block_size(evpcipher.as_ptr()) }
                    as usize;
            if self.params.ctsmode > 0 {
                /* although CTS has a blocksize of 16, it allows arbitrary
                 * sized output, so we force the apparent blocksize to 1
                 * to make the follwing calculation work out to check
                 * valid buffer lengths */
                self.blocksize = 1;
            }

            if self.params.datalen != 0 {
                let mut outl: c_int = 0;
                if unsafe {
                    EVP_DecryptUpdate(
                        self.ctx.as_mut().unwrap().as_mut_ptr(),
                        std::ptr::null_mut(),
                        &mut outl,
                        std::ptr::null(),
                        self.params.datalen as c_int,
                    )
                } != 1
                {
                    self.finalized = true;
                    return err_rv!(CKR_DEVICE_ERROR);
                }
            }

            if self.params.aad.len() > 0 {
                let mut outl: c_int = 0;
                if unsafe {
                    EVP_DecryptUpdate(
                        self.ctx.as_mut().unwrap().as_mut_ptr(),
                        std::ptr::null_mut(),
                        &mut outl,
                        self.params.aad.as_ptr(),
                        self.params.aad.len() as c_int,
                    )
                } != 1
                {
                    self.finalized = true;
                    return err_rv!(CKR_DEVICE_ERROR);
                }
            }
        }

        let plain_ulen = unsafe { *plain_len } as usize;
        let outblocks = cipher.len() / self.blocksize;
        let mut outlen = outblocks * self.blocksize;
        if self.params.taglen > 0 {
            if self.params.datalen > 0 {
                if outlen > self.params.datalen {
                    outlen = self.params.datalen;
                }
            } else {
                if outlen > self.params.taglen {
                    outlen -= self.params.taglen;
                }
            }
        }
        if plain.is_null() {
            if self.params.datalen > 0 {
                outlen = self.params.datalen - self.finalbuf.len();
            }
            unsafe {
                *plain_len = outlen as CK_ULONG;
            }
            return Ok(());
        } else {
            /* This should allow smaller plain length to update piecemeal,
             * but CCM is one shot in OpenSSL so we have to force a full
             * update for large datalens (we accumulate on behalf of
             * OpenSSL up to 1 MiB) */
            if self.params.datalen > 0 {
                if self.params.datalen > MAX_CCM_BUF {
                    if cipher.len() != self.params.datalen + self.params.taglen
                    {
                        self.finalized = true;
                        return err_rv!(CKR_DATA_LEN_RANGE);
                    }
                    outlen = self.params.datalen;
                } else if cipher.len() + self.finalbuf.len()
                    == self.params.datalen + self.params.taglen
                {
                    outlen = self.params.datalen;
                } else {
                    outlen = 0;
                }
            }
            if plain_ulen < outlen {
                /* This is the only, non-fatal error */
                return err_rv!(CKR_BUFFER_TOO_SMALL);
            }
        }

        if self.params.maxblocks > 0 {
            let reqblocks =
                ((cipher.len() + AES_BLOCK_SIZE - 1) / AES_BLOCK_SIZE) as u128;
            if self.blockctr + reqblocks > self.params.maxblocks {
                self.finalized = true;
                return err_rv!(CKR_DATA_LEN_RANGE);
            }
            self.blockctr += reqblocks;
        }

        let mut plain_buf = plain;
        let mut plen: c_int = 0;
        let mut cipher_len = cipher.len();
        if self.params.datalen > 0 {
            if cipher_len < self.params.datalen + self.params.taglen {
                self.finalbuf.extend_from_slice(cipher);
                if self.finalbuf.len()
                    < self.params.datalen + self.params.taglen
                {
                    cipher_len = 0;
                } else {
                    cipher_buf = self.finalbuf.as_ptr();
                    cipher_len = self.params.datalen;
                }
            } else {
                cipher_len = self.params.datalen;
            }
            /* we have the whole buffer, set the tag now,
             * openssl requires this order of operations for CCM */
            if cipher_len > 0 {
                let tag_buf = unsafe { cipher_buf.offset(cipher_len as isize) };

                if unsafe {
                    EVP_CIPHER_CTX_ctrl(
                        self.ctx.as_mut().unwrap().as_mut_ptr(),
                        EVP_CTRL_AEAD_SET_TAG as c_int,
                        self.params.taglen as c_int,
                        tag_buf as *mut _,
                    )
                } != 1
                {
                    self.finalized = true;
                    return err_rv!(CKR_DEVICE_ERROR);
                }
            }
        } else if self.params.taglen > 0 {
            /* the tag is appended at the end of the ciphertext,
             * but we do not know how long the ciphertext is */
            if self.finalbuf.len() > 0 {
                if cipher_len > self.params.taglen {
                    /* consume the saved buffer now,
                     * so we avoid unnecessary data copy */
                    if unsafe {
                        EVP_DecryptUpdate(
                            self.ctx.as_mut().unwrap().as_mut_ptr(),
                            plain_buf,
                            &mut plen,
                            self.finalbuf.as_ptr(),
                            self.finalbuf.len() as c_int,
                        )
                    } != 1
                    {
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
                        cipher_len = self.finalbuf.len() - self.params.taglen;
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

        let mut outl: c_int = 0;
        if cipher_len > 0
            && unsafe {
                EVP_DecryptUpdate(
                    self.ctx.as_mut().unwrap().as_mut_ptr(),
                    plain_buf,
                    &mut outl,
                    cipher_buf,
                    cipher_len as c_int,
                )
            } != 1
        {
            self.finalized = true;
            return err_rv!(CKR_ENCRYPTED_DATA_INVALID);
        }
        /* remove ciphertext if any was stored */
        if cipher_buf == self.finalbuf.as_ptr() {
            if self.params.datalen > 0 {
                self.finalbuf.clear();
            } else if self.params.taglen > 0 {
                let v = self.finalbuf[cipher_len..].to_vec();
                self.finalbuf = v;
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
            if self.params.taglen > 0 {
                if self.finalbuf.len() > self.params.taglen {
                    unsafe {
                        *plain_len = (self.finalbuf.len() - self.params.taglen)
                            as CK_ULONG;
                    }
                    return Ok(());
                }
            }
            if !self.params.pad {
                unsafe {
                    *plain_len = 0;
                }
                return Ok(());
            }
            /* OpenSSL does not let us know if there is remaining data to output, so we always have
             * to report the max if queried, which is a full blocksize */
            let mut plen: CK_ULONG = self.blocksize as CK_ULONG;
            if self.finalbuf.len() > 0 {
                plen = self.finalbuf.len() as CK_ULONG;
            }

            unsafe {
                *plain_len = plen;
            }
            return Ok(());
        }

        if self.params.datalen > 0 {
            if self.finalbuf.len() > 0 {
                self.finalized = true;
                return err_rv!(CKR_DATA_LEN_RANGE);
            }
            self.finalized = true;
            unsafe {
                *plain_len = 0;
            }
            return Ok(());
        }

        if self.params.taglen > 0 {
            if self.finalbuf.len() < self.params.taglen {
                self.finalized = true;
                return err_rv!(CKR_DATA_LEN_RANGE);
            }
            let mut buf = self.finalbuf.as_ptr();
            let len = self.finalbuf.len() - self.params.taglen;
            let mut outl: c_int = 0;
            if len > 0
                && unsafe {
                    EVP_DecryptUpdate(
                        self.ctx.as_mut().unwrap().as_mut_ptr(),
                        plain,
                        &mut outl,
                        buf as *mut u8,
                        len as c_int,
                    )
                } != 1
            {
                self.finalized = true;
                return err_rv!(CKR_DEVICE_ERROR);
            }
            unsafe {
                *plain_len = outl as CK_ULONG;
            }
            buf = unsafe { buf.offset(len as isize) };
            if unsafe {
                EVP_CIPHER_CTX_ctrl(
                    self.ctx.as_mut().unwrap().as_mut_ptr(),
                    EVP_CTRL_AEAD_SET_TAG as c_int,
                    self.params.taglen as c_int,
                    buf as *mut c_void,
                )
            } != 1
            {
                self.finalized = true;
                return err_rv!(CKR_DEVICE_ERROR);
            }
            outl = 0;
            if unsafe {
                EVP_DecryptFinal_ex(
                    self.ctx.as_mut().unwrap().as_mut_ptr(),
                    std::ptr::null_mut(),
                    &mut outl,
                )
            } != 1
            {
                self.finalized = true;
                return err_rv!(CKR_ENCRYPTED_DATA_INVALID);
            }
            if outl != 0 {
                self.finalized = true;
                return err_rv!(CKR_DEVICE_ERROR);
            }
            self.finalized = true;
            return Ok(());
        }

        if !self.params.pad {
            self.finalized = true;
            unsafe {
                *plain_len = 0;
            }
            return Ok(());
        }

        if self.params.maxblocks > 0 {
            if self.blockctr >= self.params.maxblocks {
                return err_rv!(CKR_DATA_LEN_RANGE);
            }
        }
        let mut plain_buf: *mut u8 = plain;
        let plain_ulen = unsafe { *plain_len } as usize;
        /* check if this is a second call where we saved the final buffer */
        if self.finalbuf.len() > 0 {
            if plain_ulen < self.finalbuf.len() {
                return err_rv!(CKR_BUFFER_TOO_SMALL);
            }
            self.finalized = true;
            unsafe {
                std::ptr::copy_nonoverlapping(
                    self.finalbuf.as_ptr(),
                    plain,
                    self.finalbuf.len(),
                );
                *plain_len = self.finalbuf.len() as CK_ULONG;
            }
            return Ok(());
        }

        if plain_ulen < self.blocksize {
            /* if we get less then we need to be prepared to hold the final block size from
             * openssl, and return it later */
            self.finalbuf.reserve_exact(self.blocksize);
            plain_buf = self.finalbuf.as_mut_ptr();
        } else {
            self.finalized = true;
        }

        let mut outl: c_int = 0;
        if unsafe {
            EVP_DecryptFinal_ex(
                self.ctx.as_mut().unwrap().as_mut_ptr(),
                plain_buf,
                &mut outl,
            )
        } != 1
        {
            self.finalized = true;
            return err_rv!(CKR_ENCRYPTED_DATA_INVALID);
        }
        if outl == 0 {
            self.finalized = true;
        } else if plain_buf != plain {
            if outl as usize > self.blocksize {
                self.finalized = true;
                return err_rv!(CKR_DEVICE_ERROR);
            }
            unsafe {
                self.finalbuf.set_len(outl as usize);
            }
            if plain_ulen >= outl as usize {
                unsafe {
                    std::ptr::copy_nonoverlapping(
                        plain_buf,
                        plain,
                        outl as usize,
                    );
                }
                self.finalized = true;
            } else {
                /* This is the only non-fatal error */
                return err_rv!(CKR_BUFFER_TOO_SMALL);
            }
        }
        unsafe {
            *plain_len = outl as CK_ULONG;
        }
        Ok(())
    }
}
