// Copyright 2024 Simo Sorce
// See LICENSE.txt file for terms

use std::ffi::{c_char, c_int, c_void};

use crate::aes::*;
use crate::error;
use crate::error::{map_err, Result};
use crate::interface::*;
use crate::mechanism::*;
use crate::misc::{
    bytes_to_slice, bytes_to_vec, cast_params, void_ptr, zeromem,
};
use crate::object::Object;
use crate::ossl::bindings::*;
use crate::ossl::common::*;
#[cfg(feature = "fips")]
use crate::ossl::fips::*;

use crate::get_random_data;

use constant_time_eq::constant_time_eq;
use once_cell::sync::Lazy;

const MAX_CCM_BUF: usize = 1 << 20; /* 1MiB */
const MIN_RANDOM_IV_BITS: usize = 64;

const AES_128_CBC_CTS: &[u8; 16] = b"AES-128-CBC-CTS\0";
const AES_192_CBC_CTS: &[u8; 16] = b"AES-192-CBC-CTS\0";
const AES_256_CBC_CTS: &[u8; 16] = b"AES-256-CBC-CTS\0";
const AES_128_WRAP_NAME: &[u8; 13] = b"AES-128-WRAP\0";
const AES_192_WRAP_NAME: &[u8; 13] = b"AES-192-WRAP\0";
const AES_256_WRAP_NAME: &[u8; 13] = b"AES-256-WRAP\0";
const AES_128_WRAP_PAD_NAME: &[u8; 17] = b"AES-128-WRAP-PAD\0";
const AES_192_WRAP_PAD_NAME: &[u8; 17] = b"AES-192-WRAP-PAD\0";
const AES_256_WRAP_PAD_NAME: &[u8; 17] = b"AES-256-WRAP-PAD\0";

/// AES EVP_CIPHER Object Wrapper
///
/// Gives access to the underlying OpenSSL Cipher context for a specific
/// OpenSSL AES cipher mode.
///
/// It is safe to share const ciphers as they do not change once they have
/// been created, and reference static function pointers and other data that
/// is always valid
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
        match self.cipher {
            Some(ref ec) => Ok(ec),
            _ => {
                return Err(CKR_MECHANISM_INVALID)?;
            }
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

/// A raw AES Key wrapper
///
/// Ensures the data is zeroized on deallocation

#[derive(Debug)]
struct AesKey {
    raw: Vec<u8>,
}

impl Drop for AesKey {
    fn drop(&mut self) {
        zeromem(self.raw.as_mut_slice());
    }
}

/// Returns an allocated [AesKey] object, given a AES Key Object
fn object_to_raw_key(key: &Object) -> Result<AesKey> {
    let val = key.get_attr_as_bytes(CKA_VALUE)?;
    check_key_len(val.len())?;
    Ok(AesKey { raw: val.clone() })
}

/// Helper function to allocate AesMechanism definition objects
fn new_mechanism(flags: CK_FLAGS) -> Box<dyn Mechanism> {
    Box::new(AesMechanism::new(
        CK_ULONG::try_from(MIN_AES_SIZE_BYTES).unwrap(),
        CK_ULONG::try_from(MAX_AES_SIZE_BYTES).unwrap(),
        flags,
    ))
}

/// AES Initialization Vector Object
///
/// Defines the characteristics of the IV to be used in the AES operation
/// it is referenced from. Size, generation method, counter, etc..

#[derive(Debug)]
struct AesIvData {
    buf: Vec<u8>,
    fixedbits: usize,
    generator: CK_GENERATOR_FUNCTION,
    counter: u64,
    maxcount: u64,
}

impl AesIvData {
    fn none() -> Result<AesIvData> {
        Ok(AesIvData {
            buf: Vec::new(),
            fixedbits: 0,
            generator: CKG_NO_GENERATE,
            counter: 0,
            maxcount: 0,
        })
    }

    fn simple(iv: Vec<u8>) -> Result<AesIvData> {
        Ok(AesIvData {
            buf: iv,
            fixedbits: 0,
            generator: CKG_NO_GENERATE,
            counter: 0,
            maxcount: 0,
        })
    }
}
impl Drop for AesIvData {
    fn drop(&mut self) {
        zeromem(self.buf.as_mut_slice());
    }
}

/// AES Parameters Object
///
/// Defines the parameters used for the associated AES operation. Holds
/// the IV definitions, maximum number of blocks that can be encrypted,
/// whether Cipher stealing mode is on. As well as data length, Additional
/// Authenticated Data and the Tag length for authenticated modes.

#[derive(Debug)]
struct AesParams {
    iv: AesIvData,
    maxblocks: u128,
    ctsmode: u8,
    datalen: usize,
    aad: Vec<u8>,
    taglen: usize,
}

#[cfg(feature = "fips")]
impl AesParams {
    fn zeroize(&mut self) {
        zeromem(self.iv.buf.as_mut_slice());
        zeromem(self.aad.as_mut_slice());
    }
}

/// The Generic AES Operation data structure
///
/// Provides access to all the low level encryption/decryption/etc functions
/// required to implement the AES cryptosystem

#[derive(Debug)]
pub struct AesOperation {
    mech: CK_MECHANISM_TYPE,
    op: CK_FLAGS,
    key: AesKey,
    params: AesParams,
    finalized: bool,
    in_use: bool,
    ctx: EvpCipherCtx,
    buffer: Vec<u8>,
    blockctr: u128,
    #[cfg(feature = "fips")]
    fips_approved: Option<bool>,
}

impl Drop for AesOperation {
    fn drop(&mut self) {
        zeromem(self.buffer.as_mut_slice());
    }
}

impl AesOperation {
    /// Helper function to register all AES Mechanisms
    pub fn register_mechanisms(mechs: &mut Mechanisms) {
        for ckm in &[
            CKM_AES_ECB,
            CKM_AES_CBC,
            CKM_AES_CBC_PAD,
            CKM_AES_CTR,
            CKM_AES_CTS,
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

        for ckm in &[CKM_AES_GCM, CKM_AES_CCM] {
            mechs.add_mechanism(
                *ckm,
                new_mechanism(
                    CKF_ENCRYPT
                        | CKF_DECRYPT
                        | CKF_WRAP
                        | CKF_UNWRAP
                        | CKF_MESSAGE_ENCRYPT
                        | CKF_MESSAGE_DECRYPT,
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

    /// Helper function to initialize the AES operation parameters based on
    /// the provided CK_MECHANISM structure
    fn init_params(mech: &CK_MECHANISM) -> Result<AesParams> {
        match mech.mechanism {
            CKM_AES_CCM => {
                let params = cast_params!(mech, CK_CCM_PARAMS);
                if params.ulNonceLen < 7 || params.ulNonceLen > 13 {
                    return Err(CKR_MECHANISM_PARAM_INVALID)?;
                }
                let l = 15 - params.ulNonceLen;
                if params.ulDataLen == 0
                    || params.ulDataLen > (1 << (8 * l))
                    || params.ulDataLen > (CK_ULONG::MAX - params.ulMACLen)
                {
                    return Err(CKR_MECHANISM_PARAM_INVALID)?;
                }
                if params.ulAADLen > CK_ULONG::try_from(u32::MAX - 1)? {
                    return Err(CKR_MECHANISM_PARAM_INVALID)?;
                }
                match params.ulMACLen {
                    4 | 6 | 8 | 10 | 12 | 14 | 16 => (),
                    _ => return Err(CKR_MECHANISM_PARAM_INVALID)?,
                }
                Ok(AesParams {
                    iv: AesIvData::simple(bytes_to_vec!(
                        params.pNonce,
                        params.ulNonceLen
                    ))?,
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
                if params.ulIvLen == 0
                    || params.ulIvLen > CK_ULONG::try_from(u32::MAX)?
                {
                    return Err(CKR_MECHANISM_PARAM_INVALID)?;
                }
                if params.ulAADLen > CK_ULONG::try_from(u32::MAX)? {
                    return Err(CKR_MECHANISM_PARAM_INVALID)?;
                }
                if params.ulTagBits > 128 {
                    return Err(CKR_MECHANISM_PARAM_INVALID)?;
                }
                if params.ulIvLen < 1 || params.pIv == std::ptr::null_mut() {
                    return Err(CKR_MECHANISM_PARAM_INVALID)?;
                }
                let tagbits = map_err!(
                    usize::try_from(params.ulTagBits),
                    CKR_MECHANISM_PARAM_INVALID
                )?;
                Ok(AesParams {
                    iv: AesIvData::simple(bytes_to_vec!(
                        params.pIv,
                        params.ulIvLen
                    ))?,
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
                        return Err(CKR_MECHANISM_PARAM_INVALID)?;
                    }
                } else if ctrbits > (AES_BLOCK_SIZE * 8) {
                    return Err(CKR_MECHANISM_PARAM_INVALID)?;
                }

                Ok(AesParams {
                    iv: AesIvData::simple(iv)?,
                    maxblocks: maxblocks,
                    ctsmode: 0,
                    datalen: 0,
                    aad: Vec::new(),
                    taglen: 0,
                })
            }
            CKM_AES_CTS | CKM_AES_CBC | CKM_AES_CBC_PAD => {
                if mech.ulParameterLen != CK_ULONG::try_from(AES_BLOCK_SIZE)? {
                    return Err(CKR_ARGUMENTS_BAD)?;
                }
                let mut ctsmode = 0u8;
                if mech.mechanism == CKM_AES_CTS {
                    ctsmode = 1u8;
                }
                Ok(AesParams {
                    iv: AesIvData::simple(bytes_to_vec!(
                        mech.pParameter,
                        mech.ulParameterLen
                    ))?,
                    maxblocks: 0,
                    ctsmode: ctsmode,
                    datalen: 0,
                    aad: Vec::new(),
                    taglen: 0,
                })
            }
            CKM_AES_ECB => Ok(AesParams {
                iv: AesIvData::none()?,
                maxblocks: 0,
                ctsmode: 0,
                datalen: 0,
                aad: Vec::new(),
                taglen: 0,
            }),
            #[cfg(not(feature = "fips"))]
            CKM_AES_CFB8 | CKM_AES_CFB1 | CKM_AES_CFB128 | CKM_AES_OFB => {
                if mech.ulParameterLen != CK_ULONG::try_from(AES_BLOCK_SIZE)? {
                    return Err(CKR_ARGUMENTS_BAD)?;
                }
                Ok(AesParams {
                    iv: AesIvData::simple(bytes_to_vec!(
                        mech.pParameter,
                        mech.ulParameterLen
                    ))?,
                    maxblocks: 0,
                    ctsmode: 0,
                    datalen: 0,
                    aad: Vec::new(),
                    taglen: 0,
                })
            }
            CKM_AES_KEY_WRAP => {
                let iv = match mech.ulParameterLen {
                    0 => AesIvData::none()?,
                    8 => AesIvData::simple(bytes_to_vec!(
                        mech.pParameter,
                        mech.ulParameterLen
                    ))?,
                    _ => return Err(CKR_ARGUMENTS_BAD)?,
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
                    0 => AesIvData::none()?,
                    4 => AesIvData::simple(bytes_to_vec!(
                        mech.pParameter,
                        mech.ulParameterLen
                    ))?,
                    _ => return Err(CKR_ARGUMENTS_BAD)?,
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
            /* MessageEncrypt/Decrypt uses this at init */
            CK_UNAVAILABLE_INFORMATION => {
                if mech.pParameter != std::ptr::null_mut()
                    || mech.ulParameterLen != 0
                {
                    return Err(CKR_MECHANISM_PARAM_INVALID)?;
                }
                Ok(AesParams {
                    iv: AesIvData::none()?,
                    maxblocks: 0,
                    ctsmode: 0,
                    datalen: 0,
                    aad: Vec::new(),
                    taglen: 0,
                })
            }
            _ => Err(CKR_MECHANISM_INVALID)?,
        }
    }

    /// Helper function to get the correct EVP_CIPHER context from the
    /// provided AES mechanism type.
    fn get_cipher(
        mech: CK_MECHANISM_TYPE,
        keylen: usize,
    ) -> Result<&'static EvpCipher> {
        Ok(match mech {
            CKM_AES_CCM => match keylen {
                16 => AES_128_CCM.get_cipher()?,
                24 => AES_192_CCM.get_cipher()?,
                32 => AES_256_CCM.get_cipher()?,
                _ => return Err(CKR_MECHANISM_INVALID)?,
            },
            CKM_AES_GCM => match keylen {
                16 => AES_128_GCM.get_cipher()?,
                24 => AES_192_GCM.get_cipher()?,
                32 => AES_256_GCM.get_cipher()?,
                _ => return Err(CKR_MECHANISM_INVALID)?,
            },
            CKM_AES_CTS => match keylen {
                16 => AES_128_CTS.get_cipher()?,
                24 => AES_192_CTS.get_cipher()?,
                32 => AES_256_CTS.get_cipher()?,
                _ => return Err(CKR_MECHANISM_INVALID)?,
            },
            CKM_AES_CTR => match keylen {
                16 => AES_128_CTR.get_cipher()?,
                24 => AES_192_CTR.get_cipher()?,
                32 => AES_256_CTR.get_cipher()?,
                _ => return Err(CKR_MECHANISM_INVALID)?,
            },
            CKM_AES_CBC => match keylen {
                16 => AES_128_CBC.get_cipher()?,
                24 => AES_192_CBC.get_cipher()?,
                32 => AES_256_CBC.get_cipher()?,
                _ => return Err(CKR_MECHANISM_INVALID)?,
            },
            CKM_AES_CBC_PAD => match keylen {
                16 => AES_128_CBC.get_cipher()?,
                24 => AES_192_CBC.get_cipher()?,
                32 => AES_256_CBC.get_cipher()?,
                _ => return Err(CKR_MECHANISM_INVALID)?,
            },
            CKM_AES_ECB => match keylen {
                16 => AES_128_ECB.get_cipher()?,
                24 => AES_192_ECB.get_cipher()?,
                32 => AES_256_ECB.get_cipher()?,
                _ => return Err(CKR_MECHANISM_INVALID)?,
            },
            #[cfg(not(feature = "fips"))]
            CKM_AES_CFB8 => match keylen {
                16 => AES_128_CFB8.get_cipher()?,
                24 => AES_192_CFB8.get_cipher()?,
                32 => AES_256_CFB8.get_cipher()?,
                _ => return Err(CKR_MECHANISM_INVALID)?,
            },
            #[cfg(not(feature = "fips"))]
            CKM_AES_CFB1 => match keylen {
                16 => AES_128_CFB1.get_cipher()?,
                24 => AES_192_CFB1.get_cipher()?,
                32 => AES_256_CFB1.get_cipher()?,
                _ => return Err(CKR_MECHANISM_INVALID)?,
            },
            #[cfg(not(feature = "fips"))]
            CKM_AES_CFB128 => match keylen {
                16 => AES_128_CFB128.get_cipher()?,
                24 => AES_192_CFB128.get_cipher()?,
                32 => AES_256_CFB128.get_cipher()?,
                _ => return Err(CKR_MECHANISM_INVALID)?,
            },
            #[cfg(not(feature = "fips"))]
            CKM_AES_OFB => match keylen {
                16 => AES_128_OFB.get_cipher()?,
                24 => AES_192_OFB.get_cipher()?,
                32 => AES_256_OFB.get_cipher()?,
                _ => return Err(CKR_MECHANISM_INVALID)?,
            },
            CKM_AES_KEY_WRAP => match keylen {
                16 => AES_128_WRAP.get_cipher()?,
                24 => AES_192_WRAP.get_cipher()?,
                32 => AES_256_WRAP.get_cipher()?,
                _ => return Err(CKR_MECHANISM_INVALID)?,
            },
            CKM_AES_KEY_WRAP_KWP => match keylen {
                16 => AES_128_WRAP_PAD.get_cipher()?,
                24 => AES_192_WRAP_PAD.get_cipher()?,
                32 => AES_256_WRAP_PAD.get_cipher()?,
                _ => return Err(CKR_MECHANISM_INVALID)?,
            },
            _ => return Err(CKR_MECHANISM_INVALID)?,
        })
    }

    /// Helper function that generate IVs according to the parameters
    /// stored in the object.
    ///
    /// Each call returns the next IV and updates counters or any other
    /// data in the operation object as needed.
    fn generate_iv(&mut self) -> Result<()> {
        let genbits = self.params.iv.buf.len() * 8 - self.params.iv.fixedbits;
        if self.params.iv.counter == 0 {
            self.params.iv.maxcount = if genbits >= 64 {
                u64::MAX
            } else {
                1u64 << genbits
            }
        }

        if self.params.iv.counter >= self.params.iv.maxcount {
            return Err(self.op_err(CKR_DATA_LEN_RANGE));
        }

        let mut genidx = self.params.iv.fixedbits / 8;
        let mask = u8::try_from(genbits % 8)?;
        let genbytes = (genbits + 7) / 8;

        match self.params.iv.generator {
            CKG_GENERATE | CKG_GENERATE_COUNTER => {
                let cntbuf = self.params.iv.counter.to_be_bytes();
                self.params.iv.buf[genidx] &= !mask;
                if genbytes > cntbuf.len() {
                    genidx += 1;
                    let cntidx = self.params.iv.buf.len() - cntbuf.len();
                    self.params.iv.buf[genidx..cntidx].fill(0);
                    self.params.iv.buf[cntidx..].copy_from_slice(&cntbuf);
                } else {
                    let cntidx = cntbuf.len() - genbytes;
                    self.params.iv.buf[genidx] |= cntbuf[cntidx] & mask;
                    self.params.iv.buf[(genidx + 1)..]
                        .copy_from_slice(&cntbuf[(cntidx + 1)..]);
                }
            }
            CKG_GENERATE_COUNTER_XOR => {
                let cntbuf = self.params.iv.counter.to_be_bytes();
                if genbytes > cntbuf.len() {
                    let cntidx = self.params.iv.buf.len() - cntbuf.len();
                    self.params.iv.buf[cntidx..]
                        .iter_mut()
                        .zip(cntbuf.iter())
                        .for_each(|(iv, cn)| *iv ^= *cn);
                } else {
                    let cntidx = cntbuf.len() - genbytes;
                    self.params.iv.buf[genidx] ^= cntbuf[cntidx] & mask;
                    self.params.iv.buf[(genidx + 1)..]
                        .iter_mut()
                        .zip(cntbuf[(cntidx + 1)..].iter())
                        .for_each(|(iv, cn)| *iv ^= *cn);
                }
            }
            CKG_GENERATE_RANDOM => {
                let mut genbuf = vec![0u8; (genbits + 7) / 8];
                get_random_data(&mut genbuf)?;
                self.params.iv.buf[genidx] ^= genbuf[0] & mask;
                self.params.iv.buf[(genidx + 1)..]
                    .copy_from_slice(&genbuf[1..]);
            }
            _ => return Err(self.op_err(CKR_GENERAL_ERROR)),
        }

        self.params.iv.counter += 1;
        Ok(())
    }

    /// Helper function to prepare the IV for the next operation.
    /// It may generate a new IV or use what is provided (eg in the
    /// decryption case)
    fn prep_iv(&mut self) -> Result<()> {
        if self.params.iv.generator != CKG_NO_GENERATE {
            self.generate_iv()?;
        }

        let res = unsafe {
            EVP_CIPHER_CTX_ctrl(
                self.ctx.as_mut_ptr(),
                c_int::try_from(EVP_CTRL_AEAD_SET_IVLEN)?,
                c_int::try_from(self.params.iv.buf.len())?,
                std::ptr::null_mut(),
            )
        };
        if res != 1 {
            return Err(self.op_err(CKR_DEVICE_ERROR));
        }

        Ok(())
    }

    /// Helper function to add CTS mode to the parameters
    /// array to be passed to OpenSSL functions.
    fn cts_params(&mut self, params: &mut OsslParam) -> Result<()> {
        params.add_const_c_string(
            name_as_char(OSSL_CIPHER_PARAM_CTS_MODE),
            match self.params.ctsmode {
                1 => name_as_char(OSSL_CIPHER_CTS_MODE_CS1),
                2 => name_as_char(OSSL_CIPHER_CTS_MODE_CS2),
                3 => name_as_char(OSSL_CIPHER_CTS_MODE_CS3),
                _ => return Err(self.op_err(CKR_GENERAL_ERROR)),
            },
        )
    }

    /// Helper function for setting up CCM tag lengths on the
    /// underlying EVP_CIPHER_CTX OpenSSL context.
    fn ccm_tag_len(&mut self) -> Result<()> {
        let res = unsafe {
            EVP_CIPHER_CTX_ctrl(
                self.ctx.as_mut_ptr(),
                c_int::try_from(EVP_CTRL_AEAD_SET_TAG)?,
                c_int::try_from(self.params.taglen)?,
                std::ptr::null_mut(),
            )
        };
        if res != 1 {
            Err(self.op_err(CKR_DEVICE_ERROR))
        } else {
            Ok(())
        }
    }

    /// Encryption/Decryption Initialization helper
    ///
    /// Sets up all the required context or parameters setting to direct
    /// the underlying OpenSSL crypto library, based on the configured
    /// mechanism and all the parameters stored on the object.
    fn cipher_initialize(&mut self, enc: bool) -> Result<()> {
        let evpcipher = match Self::get_cipher(self.mech, self.key.raw.len()) {
            Ok(c) => c,
            Err(e) => {
                return Err(self.op_err(e.rv()));
            }
        };

        /* Need to initialize the cipher on the ctx first, as some modes
         * will attempt to set parameters that require it on the context,
         * before key and iv can be installed */
        let res = unsafe {
            EVP_CipherInit_ex2(
                self.ctx.as_mut_ptr(),
                evpcipher.as_ptr(),
                std::ptr::null(),
                std::ptr::null(),
                if enc { 1 } else { 0 },
                std::ptr::null(),
            )
        };
        if res != 1 {
            return Err(self.op_err(CKR_DEVICE_ERROR));
        }

        /* Generates IV for some AEAD modes */
        self.prep_iv()?;

        if self.mech == CKM_AES_CCM {
            /* set tag len too */
            self.ccm_tag_len()?;
        }

        let mut params = OsslParam::new();
        let params_ptr = if self.mech == CKM_AES_CTS {
            self.cts_params(&mut params)?;
            params.finalize();
            params.as_ptr()
        } else {
            std::ptr::null()
        };

        /* set key, iv, additional params */
        let res = unsafe {
            EVP_CipherInit_ex2(
                self.ctx.as_mut_ptr(),
                std::ptr::null(),
                self.key.raw.as_ptr(),
                if self.params.iv.buf.len() != 0 {
                    self.params.iv.buf.as_ptr()
                } else {
                    std::ptr::null()
                },
                if enc { 1 } else { 0 },
                params_ptr,
            )
        };
        if res != 1 {
            return Err(self.op_err(CKR_DEVICE_ERROR))?;
        }
        /* OpenSSL defaults to padding on, so we need to turn it explicitly
         * off for mechanisms that do not use it because PKCS#11 does not
         * implicitly provide padding. */
        let res = match self.mech {
            CKM_AES_ECB | CKM_AES_CBC => unsafe {
                EVP_CIPHER_CTX_set_padding(self.ctx.as_mut_ptr(), 0)
            },
            CKM_AES_CBC_PAD => unsafe {
                EVP_CIPHER_CTX_set_padding(self.ctx.as_mut_ptr(), 1)
            },
            _ => 1,
        };
        if res != 1 {
            return Err(self.op_err(CKR_DEVICE_ERROR));
        }

        if self.mech == CKM_AES_CCM {
            let mut outl: c_int = 0;
            let res = unsafe {
                EVP_CipherUpdate(
                    self.ctx.as_mut_ptr(),
                    std::ptr::null_mut(),
                    &mut outl,
                    std::ptr::null(),
                    c_int::try_from(self.params.datalen)?,
                )
            };
            if res != 1 {
                self.finalized = true;
                return Err(CKR_DEVICE_ERROR)?;
            }
        }

        if self.params.aad.len() > 0 {
            let mut outl: c_int = 0;
            let res = unsafe {
                EVP_CipherUpdate(
                    self.ctx.as_mut_ptr(),
                    std::ptr::null_mut(),
                    &mut outl,
                    self.params.aad.as_ptr(),
                    c_int::try_from(self.params.aad.len())?,
                )
            };
            if res != 1 {
                self.finalized = true;
                return Err(CKR_DEVICE_ERROR)?;
            }
        }

        Ok(())
    }

    /// Instantiates a new Encryption AES Operation
    pub fn encrypt_new(
        mech: &CK_MECHANISM,
        key: &Object,
    ) -> Result<AesOperation> {
        Ok(AesOperation {
            mech: mech.mechanism,
            op: CKF_ENCRYPT,
            key: object_to_raw_key(key)?,
            params: Self::init_params(mech)?,
            finalized: false,
            in_use: false,
            ctx: EvpCipherCtx::new()?,
            buffer: Vec::new(),
            blockctr: 0,
            #[cfg(feature = "fips")]
            fips_approved: None,
        })
    }

    /// Instantiates a new Decryption AES Operation
    pub fn decrypt_new(
        mech: &CK_MECHANISM,
        key: &Object,
    ) -> Result<AesOperation> {
        Ok(AesOperation {
            mech: mech.mechanism,
            op: CKF_DECRYPT,
            key: object_to_raw_key(key)?,
            params: Self::init_params(mech)?,
            finalized: false,
            in_use: false,
            ctx: EvpCipherCtx::new()?,
            buffer: Vec::new(),
            blockctr: 0,
            #[cfg(feature = "fips")]
            fips_approved: None,
        })
    }

    /// Instantiates a new AES Key-Wrap Operation
    pub fn wrap(
        mech: &CK_MECHANISM,
        wrapping_key: &Object,
        mut keydata: Vec<u8>,
        output: &mut [u8],
    ) -> Result<usize> {
        let mut op = match Self::encrypt_new(mech, wrapping_key) {
            Ok(o) => o,
            Err(e) => {
                zeromem(keydata.as_mut_slice());
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
                    return Err(CKR_MECHANISM_PARAM_INVALID)?;
                }
            }
            _ => (),
        }
        let result = op.encrypt(&keydata, output);
        zeromem(keydata.as_mut_slice());
        result
    }

    /// Instantiates a new AES Key-Unwrap Operation
    pub fn unwrap(
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

    /// Internal helper for dealing with fatal errors
    fn op_err(&mut self, err: CK_RV) -> error::Error {
        self.finalized = true;
        error::Error::ck_rv(err)
    }

    /// Helper to set parameters for message based operations
    ///
    /// Returns a pointer to the IV/Nonce buffer provided by the application
    fn init_msg_params(
        &mut self,
        parameter: CK_VOID_PTR,
        parameter_len: CK_ULONG,
        aad: &[u8],
    ) -> Result<CK_BYTE_PTR> {
        #[cfg(feature = "fips")]
        {
            zeromem(self.params.iv.buf.as_mut_slice());
            zeromem(self.params.aad.as_mut_slice());
        }
        match self.mech {
            CKM_AES_CCM => {
                let params = cast_params!(
                    parameter,
                    parameter_len,
                    CK_CCM_MESSAGE_PARAMS
                );
                if params.ulNonceLen < 7 || params.ulNonceLen > 13 {
                    return Err(CKR_MECHANISM_PARAM_INVALID)?;
                }
                let l = 15 - params.ulNonceLen;
                if params.ulDataLen == 0
                    || params.ulDataLen > (1 << (8 * l))
                    || params.ulDataLen > (CK_ULONG::MAX - params.ulMACLen)
                {
                    return Err(CKR_MECHANISM_PARAM_INVALID)?;
                }
                if aad.len() > usize::try_from(u32::MAX - 1)? {
                    return Err(CKR_ARGUMENTS_BAD)?;
                }
                match params.ulMACLen {
                    4 | 6 | 8 | 10 | 12 | 14 | 16 => (),
                    _ => return Err(CKR_ARGUMENTS_BAD)?,
                }
                if params.pNonce == std::ptr::null_mut() {
                    return Err(CKR_ARGUMENTS_BAD)?;
                }
                let noncelen = map_err!(
                    usize::try_from(params.ulNonceLen),
                    CKR_ARGUMENTS_BAD
                )?;
                if self.op == CKF_MESSAGE_ENCRYPT {
                    if params.ulNonceFixedBits > params.ulNonceLen * 8 {
                        return Err(CKR_ARGUMENTS_BAD)?;
                    }
                    let noncefixedbits = map_err!(
                        usize::try_from(params.ulNonceFixedBits),
                        CKR_ARGUMENTS_BAD
                    )?;
                    if params.nonceGenerator == CKG_GENERATE_RANDOM {
                        if noncelen * 8 - noncefixedbits < MIN_RANDOM_IV_BITS {
                            return Err(CKR_ARGUMENTS_BAD)?;
                        }
                    }
                    if params.nonceGenerator != CKG_NO_GENERATE {
                        if noncelen * 8 - noncefixedbits == 0 {
                            return Err(CKR_ARGUMENTS_BAD)?;
                        }
                    }
                    self.params.iv = AesIvData {
                        buf: bytes_to_vec!(params.pNonce, noncelen),
                        fixedbits: noncefixedbits,
                        generator: params.nonceGenerator,
                        counter: 0,
                        maxcount: 0,
                    };
                } else {
                    self.params.iv = AesIvData {
                        buf: bytes_to_vec!(params.pNonce, noncelen),
                        fixedbits: 0,
                        generator: CKG_NO_GENERATE,
                        counter: 0,
                        maxcount: 0,
                    };
                }
                self.params.maxblocks = 0;
                self.params.ctsmode = 0;
                self.params.datalen = map_err!(
                    usize::try_from(params.ulDataLen),
                    CKR_ARGUMENTS_BAD
                )?;
                self.params.aad = aad.to_vec();
                self.params.taglen = map_err!(
                    usize::try_from(params.ulMACLen),
                    CKR_ARGUMENTS_BAD
                )?;
                Ok(params.pNonce)
            }
            CKM_AES_GCM => {
                let params = cast_params!(
                    parameter,
                    parameter_len,
                    CK_GCM_MESSAGE_PARAMS
                );
                if params.ulIvLen == 0
                    || params.ulIvLen > CK_ULONG::try_from(u32::MAX)?
                {
                    return Err(CKR_ARGUMENTS_BAD)?;
                }
                if params.pIv == std::ptr::null_mut() {
                    return Err(CKR_ARGUMENTS_BAD)?;
                }
                if params.ulTagBits > 128 {
                    return Err(CKR_ARGUMENTS_BAD)?;
                }
                let tagbits = map_err!(
                    usize::try_from(params.ulTagBits),
                    CKR_ARGUMENTS_BAD
                )?;
                let ivlen = map_err!(
                    usize::try_from(params.ulIvLen),
                    CKR_ARGUMENTS_BAD
                )?;
                if aad.len() > usize::try_from(u32::MAX)? {
                    return Err(CKR_ARGUMENTS_BAD)?;
                }
                if self.op == CKF_MESSAGE_ENCRYPT {
                    if params.ulIvFixedBits > params.ulIvLen * 8 {
                        return Err(CKR_ARGUMENTS_BAD)?;
                    }
                    let ivfixedbits = map_err!(
                        usize::try_from(params.ulIvFixedBits),
                        CKR_ARGUMENTS_BAD
                    )?;
                    if params.ivGenerator == CKG_GENERATE_RANDOM {
                        if ivlen * 8 - ivfixedbits < MIN_RANDOM_IV_BITS {
                            return Err(CKR_ARGUMENTS_BAD)?;
                        }
                    }
                    if params.ivGenerator != CKG_NO_GENERATE {
                        if ivlen * 8 - ivfixedbits == 0 {
                            return Err(CKR_ARGUMENTS_BAD)?;
                        }
                    }
                    self.params.iv = AesIvData {
                        buf: bytes_to_vec!(params.pIv, ivlen),
                        fixedbits: ivfixedbits,
                        generator: params.ivGenerator,
                        counter: 0,
                        maxcount: 0,
                    };
                } else {
                    self.params.iv = AesIvData {
                        buf: bytes_to_vec!(params.pIv, ivlen),
                        fixedbits: 0,
                        generator: CKG_NO_GENERATE,
                        counter: 0,
                        maxcount: 0,
                    };
                }
                self.params.maxblocks = 0;
                self.params.ctsmode = 0;
                self.params.datalen = 0;
                self.params.aad = aad.to_vec();
                self.params.taglen = (tagbits + 7) / 8;
                Ok(params.pIv)
            }
            _ => Err(CKR_MECHANISM_INVALID)?,
        }
    }

    /// Verifies the message encryption parameters on subsequent calls
    ///
    /// Returns a pointer to the Tag/Mac buffer provided by the application
    fn check_msg_params(
        &mut self,
        parameter: CK_VOID_PTR,
        parameter_len: CK_ULONG,
    ) -> Result<CK_BYTE_PTR> {
        match self.mech {
            CKM_AES_CCM => {
                let params = cast_params!(
                    parameter,
                    parameter_len,
                    CK_CCM_MESSAGE_PARAMS
                );
                if params.pNonce == std::ptr::null_mut() {
                    return Err(self.op_err(CKR_ARGUMENTS_BAD));
                }
                let noncelen = map_err!(
                    usize::try_from(params.ulNonceLen),
                    CKR_ARGUMENTS_BAD
                )?;
                if self.params.iv.buf.len() != noncelen {
                    return Err(self.op_err(CKR_ARGUMENTS_BAD));
                }
                if self.op == CKF_MESSAGE_ENCRYPT {
                    let noncefixedbits = map_err!(
                        usize::try_from(params.ulNonceFixedBits),
                        CKR_ARGUMENTS_BAD
                    )?;
                    if self.params.iv.fixedbits != noncefixedbits {
                        return Err(self.op_err(CKR_ARGUMENTS_BAD));
                    }
                    if self.params.iv.generator != params.nonceGenerator {
                        return Err(self.op_err(CKR_ARGUMENTS_BAD));
                    }
                }
                if self.params.taglen
                    != map_err!(
                        usize::try_from(params.ulMACLen),
                        CKR_ARGUMENTS_BAD
                    )?
                {
                    return Err(self.op_err(CKR_ARGUMENTS_BAD));
                }
                Ok(params.pMAC)
            }
            CKM_AES_GCM => {
                let params = cast_params!(
                    parameter,
                    parameter_len,
                    CK_GCM_MESSAGE_PARAMS
                );
                if params.pIv == std::ptr::null_mut() {
                    return Err(self.op_err(CKR_ARGUMENTS_BAD));
                }
                let tagbits = map_err!(
                    usize::try_from(params.ulTagBits),
                    CKR_ARGUMENTS_BAD
                )?;
                let ivlen = map_err!(
                    usize::try_from(params.ulIvLen),
                    CKR_ARGUMENTS_BAD
                )?;
                if self.params.iv.buf.len() != ivlen {
                    return Err(self.op_err(CKR_ARGUMENTS_BAD));
                }
                if self.op == CKF_MESSAGE_ENCRYPT {
                    let ivfixedbits = map_err!(
                        usize::try_from(params.ulIvFixedBits),
                        CKR_ARGUMENTS_BAD
                    )?;
                    if self.params.iv.fixedbits != ivfixedbits {
                        return Err(self.op_err(CKR_ARGUMENTS_BAD));
                    }
                    if self.params.iv.generator != params.ivGenerator {
                        return Err(self.op_err(CKR_ARGUMENTS_BAD));
                    }
                }
                if self.params.taglen != (tagbits + 7) / 8 {
                    return Err(self.op_err(CKR_ARGUMENTS_BAD));
                }
                Ok(params.pTag)
            }
            _ => return Err(self.op_err(CKR_GENERAL_ERROR)),
        }
    }

    /// Instantiates a Messaged Based encryption operation
    pub fn msg_encrypt_init(
        mech: &CK_MECHANISM,
        key: &Object,
    ) -> Result<AesOperation> {
        Ok(AesOperation {
            mech: mech.mechanism,
            op: CKF_MESSAGE_ENCRYPT,
            key: object_to_raw_key(key)?,
            /* params are not set until later */
            params: Self::init_params(&CK_MECHANISM {
                mechanism: CK_UNAVAILABLE_INFORMATION,
                pParameter: std::ptr::null_mut(),
                ulParameterLen: 0,
            })?,
            finalized: false,
            in_use: false,
            ctx: EvpCipherCtx::new()?,
            buffer: Vec::new(),
            blockctr: 0,
            #[cfg(feature = "fips")]
            fips_approved: None,
        })
    }

    /// Initializes a new messaged-based encryption
    fn msg_encrypt_new(
        &mut self,
        parameter: CK_VOID_PTR,
        parameter_len: CK_ULONG,
        aad: &[u8],
    ) -> Result<()> {
        if self.op != CKF_MESSAGE_ENCRYPT {
            return Err(CKR_OPERATION_NOT_INITIALIZED)?;
        }
        if self.in_use {
            return Err(CKR_OPERATION_ACTIVE)?;
        }

        #[cfg(feature = "fips")]
        {
            self.params.zeroize();
            zeromem(self.buffer.as_mut_slice());
        }
        self.finalized = false;
        self.in_use = true;

        let iv_ptr = self.init_msg_params(parameter, parameter_len, aad)?;

        /* reset ctx */
        let res = unsafe { EVP_CIPHER_CTX_reset(self.ctx.as_mut_ptr()) };
        if res != 1 {
            return Err(CKR_DEVICE_ERROR)?;
        }

        self.cipher_initialize(true)?;

        if self.params.iv.generator != CKG_NO_GENERATE {
            let iv = bytes_to_slice!(mut iv_ptr, self.params.iv.buf.len(), u8);
            iv.copy_from_slice(&self.params.iv.buf);
        }

        #[cfg(feature = "fips")]
        self.fips_approval_aead()?;

        Ok(())
    }

    /// Instantiates a messaged-based decryption operation
    pub fn msg_decrypt_init(
        mech: &CK_MECHANISM,
        key: &Object,
    ) -> Result<AesOperation> {
        Ok(AesOperation {
            mech: mech.mechanism,
            op: CKF_MESSAGE_DECRYPT,
            key: object_to_raw_key(key)?,
            /* params are not set until later */
            params: Self::init_params(&CK_MECHANISM {
                mechanism: CK_UNAVAILABLE_INFORMATION,
                pParameter: std::ptr::null_mut(),
                ulParameterLen: 0,
            })?,
            finalized: false,
            in_use: false,
            ctx: EvpCipherCtx::new()?,
            buffer: Vec::new(),
            blockctr: 0,
            #[cfg(feature = "fips")]
            fips_approved: None,
        })
    }

    /// Initializes a new messaged-based decryption
    fn msg_decrypt_new(
        &mut self,
        parameter: CK_VOID_PTR,
        parameter_len: CK_ULONG,
        aad: &[u8],
    ) -> Result<()> {
        if self.op != CKF_MESSAGE_DECRYPT {
            return Err(CKR_OPERATION_NOT_INITIALIZED)?;
        }
        if self.in_use {
            return Err(CKR_OPERATION_ACTIVE)?;
        }

        #[cfg(feature = "fips")]
        {
            self.params.zeroize();
            zeromem(self.buffer.as_mut_slice());
        }
        self.finalized = false;
        self.in_use = true;

        let _ = self.init_msg_params(parameter, parameter_len, aad)?;

        /* reset ctx */
        let res = unsafe { EVP_CIPHER_CTX_reset(self.ctx.as_mut_ptr()) };
        if res != 1 {
            return Err(CKR_DEVICE_ERROR)?;
        }

        self.cipher_initialize(false)?;

        #[cfg(feature = "fips")]
        self.fips_approval_aead()?;

        Ok(())
    }

    /// AEAD specific FIPS checks
    #[cfg(feature = "fips")]
    fn fips_approval_aead(&mut self) -> Result<()> {
        /* For AEAD we handle indicators directly because OpenSSL has an
         * inflexible API that provides incorrect answers when we
         * generate the IV outside of that code */

        /* The IV size must be 12 in FIPS mode */
        if self.params.iv.buf.len() != 12 {
            self.fips_approved = Some(false);
            return Ok(());
        }

        /* The IV must be generated in FIPS mode */
        self.fips_approved = match self.params.iv.generator {
            CKG_NO_GENERATE => match self.op {
                CKF_MESSAGE_ENCRYPT => Some(false),
                CKF_MESSAGE_DECRYPT => Some(true),
                _ => return Err(self.op_err(CKR_GENERAL_ERROR)),
            },
            CKG_GENERATE_RANDOM => Some(true),
            CKG_GENERATE | CKG_GENERATE_COUNTER | CKG_GENERATE_COUNTER_XOR => {
                if self.params.iv.fixedbits < 32 {
                    Some(false)
                } else {
                    Some(true)
                }
            }
            _ => return Err(self.op_err(CKR_GENERAL_ERROR)),
        };

        /*
         * NIST SP 800-38D: 5.2.1.2 Output Data
         * > t may be any one of the following five values: 128, 120, 112,
         * > 104, or 96. For certain applications, t may be 64 or 32;
         *
         * We assume here that 64b (8B) is still acceptable value and since
         * we take the length from user in bytes, we do not have to bother
         * about values non-dividable by 8.
         */
        if self.params.taglen < 8 {
            self.fips_approved = Some(false);
        }
        Ok(())
    }
}

impl MechOperation for AesOperation {
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

impl Encryption for AesOperation {
    /// One shot encryption implementation
    ///
    /// Internally calls [AesOperation::encrypt_update] and
    /// [AesOperation::encrypt_final]
    fn encrypt(&mut self, plain: &[u8], cipher: &mut [u8]) -> Result<usize> {
        if self.finalized {
            return Err(CKR_OPERATION_NOT_INITIALIZED)?;
        }
        let outl = self.encrypt_update(plain, cipher)?;
        if outl > cipher.len() {
            return Err(self.op_err(CKR_GENERAL_ERROR));
        }
        Ok(outl + self.encrypt_final(&mut cipher[outl..])?)
    }

    /// Calls the underlying OpenSSL function to encrypt the plaintext buffer
    /// provided, according to the configured mode
    fn encrypt_update(
        &mut self,
        plain: &[u8],
        cipher: &mut [u8],
    ) -> Result<usize> {
        if self.finalized {
            return Err(CKR_OPERATION_NOT_INITIALIZED)?;
        }
        if !self.in_use {
            self.in_use = true;
            self.cipher_initialize(true)?;
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
                if plain.len() + self.buffer.len() > self.params.datalen {
                    return Err(self.op_err(CKR_DATA_LEN_RANGE));
                }
                if plain.len() + self.buffer.len() < self.params.datalen {
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

        let mut cipher_buf = cipher.as_mut_ptr();
        let mut cipher_len = 0;

        let mut plain_buf = plain.as_ptr();
        let mut plain_len = plain.len();
        match self.mech {
            CKM_AES_CCM => {
                if plain.len() < self.params.datalen {
                    self.buffer.extend_from_slice(plain);
                    if self.buffer.len() < self.params.datalen {
                        plain_len = 0;
                    } else {
                        plain_buf = self.buffer.as_ptr();
                        plain_len = self.buffer.len();
                    }
                }
            }
            CKM_AES_ECB | CKM_AES_CBC | CKM_AES_CBC_PAD => {
                if self.buffer.len() > 0 {
                    /* we do not want to allocate huge buffers, so we deal
                     * with the first block on the auxiliary buffer and
                     * then do the bulk of the data string from the caller
                     * provided buffer */
                    if self.buffer.len() + plain_len > AES_BLOCK_SIZE {
                        let partlen = AES_BLOCK_SIZE - self.buffer.len();
                        self.buffer.extend_from_slice(&plain[..partlen]);
                        let mut outl: c_int = 0;
                        let res = unsafe {
                            EVP_EncryptUpdate(
                                self.ctx.as_mut_ptr(),
                                cipher_buf,
                                &mut outl,
                                self.buffer.as_mut_ptr(),
                                c_int::try_from(AES_BLOCK_SIZE)?,
                            )
                        };
                        if res != 1 {
                            return Err(self.op_err(CKR_DEVICE_ERROR));
                        }
                        if outl != AES_BLOCK_SIZE as c_int {
                            return Err(self.op_err(CKR_DEVICE_ERROR));
                        }
                        zeromem(self.buffer.as_mut_slice());
                        self.buffer.clear();
                        cipher_buf = unsafe {
                            cipher_buf.offset(AES_BLOCK_SIZE as isize)
                        };
                        cipher_len = AES_BLOCK_SIZE;
                        plain_buf =
                            unsafe { plain_buf.offset(partlen as isize) };
                        plain_len -= partlen;
                    }
                }
                /* we only ever encrypt entire blocks, even for Padded CBC, so
                 * we are sure OpenSSL will always encrypt all the data, and we
                 * can predict the outcome correctly */
                if plain_len % AES_BLOCK_SIZE != 0 {
                    plain_len = (plain_len / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;
                    self.buffer.extend_from_slice(&plain[plain_len..]);
                }
            }
            _ => (),
        }

        let mut outl: c_int = 0;
        if plain_len > 0 {
            let res = unsafe {
                EVP_EncryptUpdate(
                    self.ctx.as_mut_ptr(),
                    cipher_buf,
                    &mut outl,
                    plain_buf,
                    c_int::try_from(plain_len)?,
                )
            };
            if res != 1 {
                return Err(self.op_err(CKR_DEVICE_ERROR));
            }
        }
        if self.mech == CKM_AES_CCM {
            if plain_len > 0 && plain_buf == self.buffer.as_ptr() {
                zeromem(self.buffer.as_mut_slice());
                self.buffer.clear();
            }
        }
        Ok(cipher_len + usize::try_from(outl)?)
    }

    /// Calls the underlying OpenSSL function to finalize the encryption
    /// operation, according to the configured mode
    ///
    /// May return additional data in the cipher buffer
    fn encrypt_final(&mut self, cipher: &mut [u8]) -> Result<usize> {
        if self.finalized {
            return Err(CKR_OPERATION_NOT_INITIALIZED)?;
        }
        if !self.in_use {
            return Err(CKR_OPERATION_NOT_INITIALIZED)?;
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
                    /* This will normally return 0 bytes (GCM/CCM) */
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
            CKM_AES_CTS => (),
            #[cfg(not(feature = "fips"))]
            CKM_AES_CFB8 | CKM_AES_CFB1 | CKM_AES_CFB128 | CKM_AES_OFB => (),
            CKM_AES_ECB | CKM_AES_CBC => {
                if self.buffer.len() > 0 {
                    return Err(self.op_err(CKR_DATA_LEN_RANGE));
                }
                let mut outl: c_int = 0;
                let res = unsafe {
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
            }
            CKM_AES_CBC_PAD => {
                if cipher.len() < AES_BLOCK_SIZE {
                    return Err(error::Error::buf_too_small(AES_BLOCK_SIZE));
                }

                if self.buffer.len() > 0 {
                    let mut outl: c_int = 0;
                    let res = unsafe {
                        EVP_EncryptUpdate(
                            self.ctx.as_mut_ptr(),
                            cipher.as_mut_ptr(),
                            &mut outl,
                            self.buffer.as_mut_ptr(),
                            c_int::try_from(self.buffer.len())?,
                        )
                    };
                    if res != 1 {
                        return Err(self.op_err(CKR_DEVICE_ERROR));
                    }
                    /* we do not expect anything in output because
                     * this is a partial block, so the CBC PAD
                     * algorithm update can't return anything until
                     * final is called, where padding is applied */
                    if outl != 0 {
                        return Err(self.op_err(CKR_DEVICE_ERROR));
                    }
                }

                let mut outl: c_int = 0;
                let res = unsafe {
                    EVP_EncryptFinal_ex(
                        self.ctx.as_mut_ptr(),
                        cipher.as_mut_ptr(),
                        &mut outl,
                    )
                };
                if res != 1 {
                    return Err(self.op_err(CKR_DEVICE_ERROR));
                }
                outlen = usize::try_from(outl)?;
                if outlen != AES_BLOCK_SIZE {
                    return Err(self.op_err(CKR_DEVICE_ERROR));
                }
            }
            CKM_AES_KEY_WRAP | CKM_AES_KEY_WRAP_KWP => (),
            _ => {
                return Err(self.op_err(CKR_GENERAL_ERROR));
            }
        };

        #[cfg(feature = "fips")]
        {
            self.fips_approved = check_cipher_fips_indicators(&mut self.ctx)?;
        }
        self.finalized = true;
        Ok(outlen)
    }

    /// Provides the expected output buffer size for the provided input
    /// plaintext length based on the selected mode of operation.
    ///
    /// May return different values depending on the internal status and the
    /// mode of operation.
    fn encryption_len(&mut self, data_len: usize, fin: bool) -> Result<usize> {
        let outlen = if fin {
            match self.mech {
                CKM_AES_CCM => {
                    if data_len + self.buffer.len() > self.params.datalen {
                        return Err(self.op_err(CKR_DATA_LEN_RANGE));
                    }
                    self.buffer.len() + data_len + self.params.taglen
                }
                CKM_AES_GCM => data_len + self.params.taglen,
                CKM_AES_CTR | CKM_AES_CTS => data_len,
                CKM_AES_CBC | CKM_AES_ECB => {
                    if (self.buffer.len() + data_len) % AES_BLOCK_SIZE != 0 {
                        return Err(self.op_err(CKR_DATA_LEN_RANGE));
                    }
                    self.buffer.len() + data_len
                }
                CKM_AES_CBC_PAD => {
                    /*
                     * The PKCS#7 padding adds always at least 1 byte, so it
                     * can emit up to a full block of padding even if there
                     * is no final block data to parse.
                     */
                    ((self.buffer.len() + data_len + AES_BLOCK_SIZE)
                        / AES_BLOCK_SIZE)
                        * AES_BLOCK_SIZE
                }
                CKM_AES_KEY_WRAP => {
                    if data_len % 8 != 0 {
                        return Err(self.op_err(CKR_DATA_LEN_RANGE));
                    } else {
                        data_len + 8
                    }
                }
                CKM_AES_KEY_WRAP_KWP => ((data_len + 15) / 8) * 8,
                #[cfg(not(feature = "fips"))]
                CKM_AES_CFB8 | CKM_AES_CFB1 | CKM_AES_CFB128 | CKM_AES_OFB => {
                    data_len
                }
                _ => return Err(self.op_err(CKR_GENERAL_ERROR)),
            }
        } else {
            match self.mech {
                CKM_AES_CCM => self.params.datalen + self.params.taglen,
                CKM_AES_GCM => data_len + self.params.taglen,
                CKM_AES_CTR | CKM_AES_CTS => data_len,
                CKM_AES_CBC | CKM_AES_ECB | CKM_AES_CBC_PAD => {
                    ((self.buffer.len() + data_len) / AES_BLOCK_SIZE)
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
    /// One shot decryption implementation
    ///
    /// Internally calls [AesOperation::decrypt_update] and
    /// [AesOperation::decrypt_final]
    fn decrypt(&mut self, cipher: &[u8], plain: &mut [u8]) -> Result<usize> {
        if self.finalized {
            return Err(CKR_OPERATION_NOT_INITIALIZED)?;
        }
        let outl = self.decrypt_update(cipher, plain)?;
        if outl > plain.len() {
            return Err(self.op_err(CKR_GENERAL_ERROR));
        }
        Ok(outl + self.decrypt_final(&mut plain[outl..])?)
    }

    /// Calls the underlying OpenSSL function to decrypt the ciphertext buffer
    /// provided, according to the configured mode
    fn decrypt_update(
        &mut self,
        cipher: &[u8],
        plain: &mut [u8],
    ) -> Result<usize> {
        if self.finalized {
            return Err(CKR_OPERATION_NOT_INITIALIZED)?;
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
                if cipher.len() + self.buffer.len()
                    > self.params.datalen + self.params.taglen
                {
                    return Err(self.op_err(CKR_DATA_LEN_RANGE));
                }
            }
            CKM_AES_KEY_WRAP | CKM_AES_KEY_WRAP_KWP => {
                if cipher.len() % (AES_BLOCK_SIZE / 2) != 0 {
                    return Err(self.op_err(CKR_DATA_LEN_RANGE));
                }
            }
            _ => (),
        }
        if !self.in_use {
            self.in_use = true;
            self.cipher_initialize(false)?;
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
                if cipher.len() + self.buffer.len() > needlen {
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
                let tlen = cipher.len() + self.buffer.len();
                if tlen > self.params.taglen {
                    tlen - self.params.taglen
                } else {
                    0
                }
            }
            CKM_AES_ECB | CKM_AES_CBC | CKM_AES_CBC_PAD => {
                ((self.buffer.len() + cipher.len()) / AES_BLOCK_SIZE)
                    * AES_BLOCK_SIZE
            }
            CKM_AES_KEY_WRAP | CKM_AES_KEY_WRAP_KWP => cipher.len(),
            _ => cipher.len(),
        };
        if plain.len() < outlen {
            /* This is the only, non-fatal error */
            return Err(error::Error::buf_too_small(outlen));
        }

        let mut outlen = 0;
        let mut cipher_len = cipher.len();

        let mut plain_buf = plain.as_ptr();
        match self.mech {
            CKM_AES_CCM => {
                let needlen = self.params.datalen + self.params.taglen;
                if cipher_len < needlen {
                    self.buffer.extend_from_slice(cipher);
                    if self.buffer.len() < needlen {
                        cipher_len = 0;
                    } else {
                        cipher_buf = self.buffer.as_ptr();
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
                if self.buffer.len() > 0 {
                    if cipher_len > self.params.taglen {
                        /* consume the saved buffer now,
                         * so we avoid unnecessary data copy */
                        let mut plen: c_int = 0;
                        let res = unsafe {
                            EVP_DecryptUpdate(
                                self.ctx.as_mut_ptr(),
                                plain_buf as *mut _,
                                &mut plen,
                                self.buffer.as_ptr(),
                                self.buffer.len() as c_int,
                            )
                        };
                        if res != 1 {
                            return Err(self.op_err(CKR_ENCRYPTED_DATA_INVALID));
                        }
                        outlen = usize::try_from(plen)?;
                        plain_buf =
                            unsafe { plain_buf.offset(outlen as isize) };
                        self.buffer.clear();
                        cipher_len -= self.params.taglen;
                        self.buffer.extend_from_slice(&cipher[cipher_len..]);
                    } else {
                        self.buffer.extend_from_slice(cipher);
                        if self.buffer.len() > self.params.taglen {
                            cipher_buf = self.buffer.as_ptr();
                            cipher_len = self.buffer.len() - self.params.taglen;
                        }
                    }
                } else if cipher_len > self.params.taglen {
                    cipher_len -= self.params.taglen;
                    self.buffer.extend_from_slice(&cipher[cipher_len..]);
                } else {
                    self.buffer.extend_from_slice(cipher);
                    cipher_len = 0;
                }
            }
            CKM_AES_ECB | CKM_AES_CBC | CKM_AES_CBC_PAD => {
                let mut cipher_pos = 0;
                if self.buffer.len() > 0 {
                    /* we do not want to allocate huge buffers, so we deal
                     * with the first block on the auxiliary buffer and
                     * then do the bulk of the data string from the caller
                     * provided buffer */
                    if self.buffer.len() + cipher_len > AES_BLOCK_SIZE {
                        let partlen = AES_BLOCK_SIZE - self.buffer.len();
                        self.buffer.extend_from_slice(&cipher[..partlen]);
                        cipher_pos = partlen;
                        let mut outl: c_int = 0;
                        let res = unsafe {
                            EVP_DecryptUpdate(
                                self.ctx.as_mut_ptr(),
                                plain_buf as *mut _,
                                &mut outl,
                                self.buffer.as_mut_ptr(),
                                c_int::try_from(AES_BLOCK_SIZE)?,
                            )
                        };
                        if res != 1 {
                            return Err(self.op_err(CKR_ENCRYPTED_DATA_INVALID));
                        }
                        if outl != AES_BLOCK_SIZE as c_int {
                            return Err(self.op_err(CKR_DEVICE_ERROR));
                        }
                        zeromem(self.buffer.as_mut_slice());
                        self.buffer.clear();
                        cipher_buf =
                            unsafe { cipher_buf.offset(cipher_pos as isize) };
                        cipher_len -= cipher_pos;
                        outlen = AES_BLOCK_SIZE;
                        plain_buf =
                            unsafe { plain_buf.offset(outlen as isize) };
                    }
                }
                /* we only ever decrypt entire blocks, even for Padded CBC, so
                 * we are sure OpenSSL will always decrypt all the data, and we
                 * can predict the outcome correctly */
                if cipher_len % AES_BLOCK_SIZE != 0 {
                    cipher_len = (cipher_len / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;
                    self.buffer.extend_from_slice(
                        &cipher[(cipher_pos + cipher_len)..],
                    );
                }
            }
            _ => (),
        }

        if cipher_len > 0 {
            let mut outl: c_int = 0;
            let res = unsafe {
                EVP_DecryptUpdate(
                    self.ctx.as_mut_ptr(),
                    plain_buf as *mut _,
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
        /* remove consumed ciphertext for some mechanisms */
        if cipher_buf == self.buffer.as_ptr() {
            match self.mech {
                CKM_AES_CCM => self.buffer.clear(),
                CKM_AES_GCM => {
                    let v = self.buffer[cipher_len..].to_vec();
                    self.buffer = v;
                }
                _ => (),
            }
        }
        Ok(outlen)
    }

    /// Calls the underlying OpenSSL function to finalize the decryption
    /// operation, according to the configured mode
    ///
    /// May return additional data in the plain buffer
    fn decrypt_final(&mut self, plain: &mut [u8]) -> Result<usize> {
        if self.finalized {
            return Err(CKR_OPERATION_NOT_INITIALIZED)?;
        }
        if !self.in_use {
            return Err(CKR_OPERATION_NOT_INITIALIZED)?;
        }

        let mut outlen = 0;
        match self.mech {
            CKM_AES_CCM => {
                if self.buffer.len() > 0 {
                    return Err(self.op_err(CKR_DATA_LEN_RANGE));
                }
            }
            CKM_AES_GCM => {
                if self.buffer.len() != self.params.taglen {
                    return Err(self.op_err(CKR_DATA_LEN_RANGE));
                }
                let res = unsafe {
                    EVP_CIPHER_CTX_ctrl(
                        self.ctx.as_mut_ptr(),
                        c_int::try_from(EVP_CTRL_AEAD_SET_TAG)?,
                        c_int::try_from(self.params.taglen)?,
                        self.buffer.as_ptr() as *mut c_void,
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
            CKM_AES_CTS => (),
            CKM_AES_ECB | CKM_AES_CBC => {
                if self.buffer.len() != 0 {
                    return Err(self.op_err(CKR_DATA_LEN_RANGE));
                }
                self.buffer.resize(AES_BLOCK_SIZE, 0);
                let mut outl: c_int = 0;
                let res = unsafe {
                    EVP_DecryptFinal_ex(
                        self.ctx.as_mut_ptr(),
                        self.buffer.as_mut_ptr(),
                        &mut outl,
                    )
                };
                if res != 1 {
                    return Err(self.op_err(CKR_ENCRYPTED_DATA_INVALID));
                }
                if outl != 0 {
                    return Err(self.op_err(CKR_DEVICE_ERROR));
                }
                zeromem(self.buffer.as_mut_slice());
                self.buffer.clear();
            }
            CKM_AES_CBC_PAD => {
                if self.buffer.len() != 0 {
                    return Err(self.op_err(CKR_DATA_LEN_RANGE));
                }
                let mut outl: c_int = 0;
                let res = unsafe {
                    EVP_DecryptFinal_ex(
                        self.ctx.as_mut_ptr(),
                        plain.as_mut_ptr(),
                        &mut outl,
                    )
                };
                if res != 1 {
                    return Err(self.op_err(CKR_ENCRYPTED_DATA_INVALID));
                }
                outlen = usize::try_from(outl)?;
            }
            #[cfg(not(feature = "fips"))]
            CKM_AES_CFB8 | CKM_AES_CFB1 | CKM_AES_CFB128 | CKM_AES_OFB => (),
            CKM_AES_KEY_WRAP | CKM_AES_KEY_WRAP_KWP => (),
            _ => return Err(self.op_err(CKR_GENERAL_ERROR)),
        }

        #[cfg(feature = "fips")]
        {
            self.fips_approved = check_cipher_fips_indicators(&mut self.ctx)?;
        }
        self.finalized = true;
        Ok(outlen)
    }

    /// Provides the expected output buffer size for the provided input
    /// cpihertext length based on the selected mode of operation.
    ///
    /// May return different values depending on the internal status and the
    /// mode of operation.
    fn decryption_len(&mut self, data_len: usize, fin: bool) -> Result<usize> {
        let outlen = if fin {
            match self.mech {
                CKM_AES_GCM => {
                    if data_len < self.params.taglen {
                        return Err(self.op_err(CKR_DATA_LEN_RANGE));
                    }
                    data_len - self.params.taglen
                }
                CKM_AES_CCM => {
                    if self.buffer.len() + data_len
                        > self.params.datalen + self.params.taglen
                    {
                        return Err(self.op_err(CKR_DATA_LEN_RANGE));
                    }
                    self.params.datalen + self.params.taglen
                }
                CKM_AES_CTR | CKM_AES_CTS => data_len,
                CKM_AES_CBC | CKM_AES_ECB => {
                    if (self.buffer.len() + data_len) % AES_BLOCK_SIZE != 0 {
                        return Err(self.op_err(CKR_DATA_LEN_RANGE));
                    }
                    self.buffer.len() + data_len
                }
                #[cfg(not(feature = "fips"))]
                CKM_AES_CFB8 | CKM_AES_CFB1 | CKM_AES_CFB128 | CKM_AES_OFB => {
                    data_len
                }
                CKM_AES_CBC_PAD => {
                    if (self.buffer.len() + data_len) % AES_BLOCK_SIZE != 0 {
                        return Err(self.op_err(CKR_DATA_LEN_RANGE));
                    }
                    self.buffer.len() + data_len
                }
                CKM_AES_KEY_WRAP | CKM_AES_KEY_WRAP_KWP => {
                    if data_len % (AES_BLOCK_SIZE / 2) != 0 {
                        return Err(self.op_err(CKR_DATA_LEN_RANGE));
                    }
                    self.buffer.len() + data_len
                }
                _ => return Err(self.op_err(CKR_GENERAL_ERROR)),
            }
        } else {
            match self.mech {
                CKM_AES_CCM => {
                    if self.buffer.len() + data_len < self.params.taglen {
                        return Err(self.op_err(CKR_DATA_LEN_RANGE));
                    }
                    self.buffer.len() + data_len - self.params.taglen
                }
                CKM_AES_GCM => {
                    if self.buffer.len() + data_len < self.params.taglen {
                        0
                    } else {
                        self.buffer.len() + data_len
                    }
                }
                CKM_AES_CTR | CKM_AES_CTS => data_len,
                CKM_AES_CBC | CKM_AES_CBC_PAD | CKM_AES_ECB => {
                    ((self.buffer.len() + data_len) / AES_BLOCK_SIZE)
                        * AES_BLOCK_SIZE
                }
                #[cfg(not(feature = "fips"))]
                CKM_AES_CFB8 | CKM_AES_CFB1 | CKM_AES_CFB128 | CKM_AES_OFB => {
                    data_len
                }
                CKM_AES_KEY_WRAP | CKM_AES_KEY_WRAP_KWP => {
                    if data_len % (AES_BLOCK_SIZE / 2) != 0 {
                        return Err(self.op_err(CKR_DATA_LEN_RANGE));
                    } else {
                        /* Originally this was ((data_len / 8) * 8) - 8
                         * however this caused stack corruption on decryption
                         * failures as in case of errors as OpenSSL's unwrap
                         * function (CRYPTO_128_unwrap_pad) zeroizes outputs
                         * by calling OPENSSL_cleanse(out, inlen). So the
                         * output buffer needs to be always at least as large
                         * as the input buffer regardless of the actual final
                         * length, and needs to be a multiple of 8.
                         */
                        (data_len / 8) * 8
                    }
                }
                _ => return Err(self.op_err(CKR_GENERAL_ERROR)),
            }
        };
        Ok(outlen)
    }
}

impl MessageOperation for AesOperation {
    fn busy(&self) -> bool {
        self.in_use
    }
    fn finalize(&mut self) -> Result<()> {
        if self.in_use {
            return Err(CKR_OPERATION_ACTIVE)?;
        }
        self.finalized = true;
        Ok(())
    }
}

impl MsgEncryption for AesOperation {
    /// One Shot message based encryption implementation
    ///
    /// Internally calls [AesOperation::msg_encrypt_begin] and
    /// [AesOperation::msg_encrypt_final]
    fn msg_encrypt(
        &mut self,
        param: CK_VOID_PTR,
        paramlen: CK_ULONG,
        aad: &[u8],
        plain: &[u8],
        cipher: &mut [u8],
    ) -> Result<usize> {
        self.msg_encrypt_begin(param, paramlen, aad)?;
        self.msg_encrypt_final(param, paramlen, plain, cipher)
    }

    /// Begin a new message based encryption
    fn msg_encrypt_begin(
        &mut self,
        param: CK_VOID_PTR,
        paramlen: CK_ULONG,
        aad: &[u8],
    ) -> Result<()> {
        if self.finalized {
            return Err(CKR_OPERATION_NOT_INITIALIZED)?;
        }
        self.msg_encrypt_new(param, paramlen, aad)
    }

    /// Feeds in the next plaintext buffer to be encrypted
    ///
    /// Returns output data in the provided cipher buffer
    fn msg_encrypt_next(
        &mut self,
        param: CK_VOID_PTR,
        paramlen: CK_ULONG,
        plain: &[u8],
        cipher: &mut [u8],
    ) -> Result<usize> {
        if self.finalized {
            return Err(CKR_OPERATION_NOT_INITIALIZED)?;
        }
        if !self.in_use {
            return Err(CKR_OPERATION_NOT_INITIALIZED)?;
        }
        let _ = self.check_msg_params(param, paramlen)?;

        if self.mech == CKM_AES_CCM {
            if self.params.datalen > MAX_CCM_BUF {
                return Err(self.op_err(CKR_DATA_LEN_RANGE));
            }
            if plain.len() + self.buffer.len() > self.params.datalen {
                return Err(self.op_err(CKR_DATA_LEN_RANGE));
            }

            /* accumulate for CCM case */
            self.buffer.extend_from_slice(plain);
            return Ok(0);
        }

        /* AES GCM */
        if cipher.len() < plain.len() {
            /* This is the only non-fatal error */
            return Err(error::Error::buf_too_small(plain.len()));
        }

        let mut outl: c_int = 0;
        if plain.len() > 0 {
            let res = unsafe {
                EVP_EncryptUpdate(
                    self.ctx.as_mut_ptr(),
                    cipher.as_mut_ptr(),
                    &mut outl,
                    plain.as_ptr(),
                    c_int::try_from(plain.len())?,
                )
            };
            if res != 1 {
                return Err(self.op_err(CKR_DEVICE_ERROR));
            }
        }
        Ok(usize::try_from(outl)?)
    }

    /// Feeds the final plaintext buffer to be encrypted
    ///
    /// Returns output data in the provided cipher buffer
    fn msg_encrypt_final(
        &mut self,
        param: CK_VOID_PTR,
        paramlen: CK_ULONG,
        plain: &[u8],
        cipher: &mut [u8],
    ) -> Result<usize> {
        if self.finalized {
            return Err(CKR_OPERATION_NOT_INITIALIZED)?;
        }
        if !self.in_use {
            return Err(CKR_OPERATION_NOT_INITIALIZED)?;
        }
        if self.mech == CKM_AES_CCM {
            if plain.len() + self.buffer.len() != self.params.datalen {
                return Err(self.op_err(CKR_DATA_LEN_RANGE));
            }
            if cipher.len() < self.params.datalen {
                /* This is the only non-fatal error */
                return Err(error::Error::buf_too_small(self.params.datalen));
            }
        }
        let tag_ptr = self.check_msg_params(param, paramlen)?;
        let outlen = match self.mech {
            CKM_AES_CCM => {
                let mut plain_buf = plain.as_ptr();
                let plain_len = if plain.len() < self.params.datalen {
                    self.buffer.extend_from_slice(plain);
                    plain_buf = self.buffer.as_ptr();
                    self.buffer.len()
                } else {
                    plain.len()
                };
                if plain_len != self.params.datalen {
                    return Err(self.op_err(CKR_DATA_LEN_RANGE));
                }
                let mut outl: c_int = 0;
                let res = unsafe {
                    EVP_EncryptUpdate(
                        self.ctx.as_mut_ptr(),
                        cipher.as_mut_ptr(),
                        &mut outl,
                        plain_buf,
                        c_int::try_from(plain_len)?,
                    )
                };
                if res != 1 {
                    return Err(self.op_err(CKR_DEVICE_ERROR));
                }
                usize::try_from(outl)?
            }
            CKM_AES_GCM => {
                self.msg_encrypt_next(param, paramlen, plain, cipher)?
            }
            _ => return Err(self.op_err(CKR_GENERAL_ERROR)),
        };

        self.in_use = false;

        let mut outl: c_int = 0;
        let res = unsafe {
            /* This will normally return 0 bytes (GCM/CCM) */
            EVP_EncryptFinal_ex(
                self.ctx.as_mut_ptr(),
                cipher.as_mut_ptr(),
                &mut outl,
            )
        };
        if res != 1 {
            zeromem(cipher);
            return Err(self.op_err(CKR_DEVICE_ERROR));
        }
        if outl != 0 {
            zeromem(cipher);
            return Err(self.op_err(CKR_DEVICE_ERROR));
        }
        let res = unsafe {
            EVP_CIPHER_CTX_ctrl(
                self.ctx.as_mut_ptr(),
                EVP_CTRL_AEAD_GET_TAG as c_int,
                self.params.taglen as c_int,
                tag_ptr as *mut c_void,
            )
        };
        if res != 1 {
            zeromem(cipher);
            return Err(self.op_err(CKR_DEVICE_ERROR));
        }

        Ok(outlen)
    }

    /// Provides the expected output buffer size for the provided input
    /// plaintext length based on the selected mode of operation.
    fn msg_encryption_len(
        &mut self,
        data_len: usize,
        _fin: bool,
    ) -> Result<usize> {
        if self.finalized {
            return Err(CKR_OPERATION_NOT_INITIALIZED)?;
        }
        match self.mech {
            CKM_AES_CCM => Ok(self.params.datalen),
            CKM_AES_GCM => Ok(data_len),
            _ => Err(self.op_err(CKR_GENERAL_ERROR)),
        }
    }
}

impl MsgDecryption for AesOperation {
    /// One Shot message based decryption implementation
    ///
    /// Internally calls [AesOperation::msg_decrypt_begin] and
    /// [AesOperation::msg_decrypt_final]
    fn msg_decrypt(
        &mut self,
        param: CK_VOID_PTR,
        paramlen: CK_ULONG,
        aad: &[u8],
        cipher: &[u8],
        plain: &mut [u8],
    ) -> Result<usize> {
        self.msg_decrypt_begin(param, paramlen, aad)?;
        self.msg_decrypt_final(param, paramlen, cipher, plain)
    }

    /// Begin a new message based decryption
    fn msg_decrypt_begin(
        &mut self,
        param: CK_VOID_PTR,
        paramlen: CK_ULONG,
        aad: &[u8],
    ) -> Result<()> {
        if self.finalized {
            return Err(CKR_OPERATION_NOT_INITIALIZED)?;
        }
        self.msg_decrypt_new(param, paramlen, aad)
    }

    /// Feeds in the next ciphertext buffer to be decrypted
    ///
    /// Returns output data in the provided plain buffer
    fn msg_decrypt_next(
        &mut self,
        param: CK_VOID_PTR,
        paramlen: CK_ULONG,
        cipher: &[u8],
        plain: &mut [u8],
    ) -> Result<usize> {
        if self.finalized {
            return Err(CKR_OPERATION_NOT_INITIALIZED)?;
        }
        if !self.in_use {
            return Err(CKR_OPERATION_NOT_INITIALIZED)?;
        }
        let _ = self.check_msg_params(param, paramlen)?;

        if self.mech == CKM_AES_CCM {
            if self.params.datalen > MAX_CCM_BUF {
                return Err(self.op_err(CKR_DATA_LEN_RANGE));
            }
            if cipher.len() + self.buffer.len() > self.params.datalen {
                return Err(self.op_err(CKR_DATA_LEN_RANGE));
            }

            /* accumulate for CCM case */
            self.buffer.extend_from_slice(cipher);
            return Ok(0);
        }

        /* AES GCM */
        if plain.len() < cipher.len() {
            /* This is the only non-fatal error */
            return Err(error::Error::buf_too_small(cipher.len()));
        }

        let mut outl: c_int = 0;
        if cipher.len() > 0 {
            let res = unsafe {
                EVP_DecryptUpdate(
                    self.ctx.as_mut_ptr(),
                    plain.as_mut_ptr(),
                    &mut outl,
                    cipher.as_ptr(),
                    c_int::try_from(cipher.len())?,
                )
            };
            if res != 1 {
                return Err(self.op_err(CKR_DEVICE_ERROR));
            }
        }
        Ok(usize::try_from(outl)?)
    }

    /// Feeds in the final ciphertext buffer to be decrypted
    ///
    /// Returns output data in the provided plain buffer
    fn msg_decrypt_final(
        &mut self,
        param: CK_VOID_PTR,
        paramlen: CK_ULONG,
        cipher: &[u8],
        plain: &mut [u8],
    ) -> Result<usize> {
        if self.finalized {
            return Err(CKR_OPERATION_NOT_INITIALIZED)?;
        }
        if !self.in_use {
            return Err(CKR_OPERATION_NOT_INITIALIZED)?;
        }
        if self.mech == CKM_AES_CCM {
            if cipher.len() + self.buffer.len() != self.params.datalen {
                return Err(self.op_err(CKR_DATA_LEN_RANGE));
            }
            if plain.len() < self.params.datalen {
                /* This is the only non-fatal error */
                return Err(error::Error::buf_too_small(self.params.datalen));
            }
        }
        let tag_ptr = self.check_msg_params(param, paramlen)?;

        /* The tag must to be set first for CCM  and does not hurt GCM */
        let res = unsafe {
            EVP_CIPHER_CTX_ctrl(
                self.ctx.as_mut_ptr(),
                c_int::try_from(EVP_CTRL_AEAD_SET_TAG)?,
                c_int::try_from(self.params.taglen)?,
                tag_ptr as *mut c_void,
            )
        };
        if res != 1 {
            return Err(self.op_err(CKR_DEVICE_ERROR));
        }

        let outlen = match self.mech {
            CKM_AES_CCM => {
                let mut cipher_buf = cipher.as_ptr();
                let cipher_len = if cipher.len() < self.params.datalen {
                    self.buffer.extend_from_slice(cipher);
                    cipher_buf = self.buffer.as_ptr();
                    self.buffer.len()
                } else {
                    cipher.len()
                };
                if cipher_len != self.params.datalen {
                    return Err(self.op_err(CKR_DATA_LEN_RANGE));
                }
                let mut outl: c_int = 0;
                let res = unsafe {
                    EVP_DecryptUpdate(
                        self.ctx.as_mut_ptr(),
                        plain.as_mut_ptr(),
                        &mut outl,
                        cipher_buf,
                        c_int::try_from(cipher_len)?,
                    )
                };
                if res != 1 {
                    return Err(self.op_err(CKR_DEVICE_ERROR));
                }
                usize::try_from(outl)?
            }
            CKM_AES_GCM => {
                let len =
                    self.msg_decrypt_next(param, paramlen, cipher, plain)?;

                /* only AES GCM must and can do this */
                let mut outl: c_int = 0;
                let res = unsafe {
                    EVP_DecryptFinal_ex(
                        self.ctx.as_mut_ptr(),
                        std::ptr::null_mut(),
                        &mut outl,
                    )
                };
                if res != 1 {
                    zeromem(plain);
                    return Err(self.op_err(CKR_ENCRYPTED_DATA_INVALID));
                }
                if outl != 0 {
                    zeromem(plain);
                    return Err(self.op_err(CKR_DEVICE_ERROR));
                }

                len
            }
            _ => return Err(self.op_err(CKR_GENERAL_ERROR)),
        };

        self.in_use = false;
        Ok(outlen)
    }

    /// Provides the expected output buffer size for the provided input
    /// plaintext length based on the selected mode of operation.
    fn msg_decryption_len(
        &mut self,
        data_len: usize,
        _fin: bool,
    ) -> Result<usize> {
        if self.finalized {
            return Err(CKR_OPERATION_NOT_INITIALIZED)?;
        }
        match self.mech {
            CKM_AES_CCM => Ok(self.params.datalen),
            CKM_AES_GCM => Ok(data_len),
            _ => Err(self.op_err(CKR_GENERAL_ERROR)),
        }
    }
}

/* _key and _mac as stored in order to make sure the pointers they
 * hold survive for as long as the operations are going on, as we
 * can't be sure openssl is not holding live pointers to the
 * parameters passed into the init functions */
#[derive(Debug)]
pub struct AesCmacOperation {
    mech: CK_MECHANISM_TYPE,
    finalized: bool,
    in_use: bool,
    _key: AesKey,
    ctx: EvpMacCtx,
    maclen: usize,
    #[cfg(feature = "fips")]
    fips_approved: Option<bool>,
}

impl AesCmacOperation {
    /// Helper to register the CMAC mechanisms
    pub fn register_mechanisms(mechs: &mut Mechanisms) {
        for ckm in &[CKM_AES_CMAC, CKM_AES_CMAC_GENERAL] {
            mechs.add_mechanism(*ckm, new_mechanism(CKF_SIGN | CKF_VERIFY));
        }
    }

    /// Initializes and returns a CMAC operation
    pub fn init(mech: &CK_MECHANISM, key: &Object) -> Result<AesCmacOperation> {
        let maclen = match mech.mechanism {
            CKM_AES_CMAC_GENERAL => {
                let params = cast_params!(mech, CK_MAC_GENERAL_PARAMS);
                let val = params as usize;
                if val > AES_BLOCK_SIZE {
                    return Err(CKR_MECHANISM_PARAM_INVALID)?;
                }
                val
            }
            CKM_AES_CMAC => {
                if mech.ulParameterLen != 0 {
                    return Err(CKR_ARGUMENTS_BAD)?;
                }
                AES_BLOCK_SIZE
            }
            _ => return Err(CKR_MECHANISM_INVALID)?,
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
                _ => return Err(CKR_KEY_INDIGESTIBLE)?,
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
            return Err(CKR_DEVICE_ERROR)?;
        }
        Ok(AesCmacOperation {
            mech: mech.mechanism,
            finalized: false,
            in_use: false,
            _key: mackey,
            ctx: ctx,
            maclen: maclen,
            #[cfg(feature = "fips")]
            fips_approved: None,
        })
    }

    /// Begins a CMAC computation
    fn begin(&mut self) -> Result<()> {
        if self.in_use {
            return Err(CKR_OPERATION_NOT_INITIALIZED)?;
        }
        Ok(())
    }

    /// Feeds in the next data buffer into the CMAC computation
    fn update(&mut self, data: &[u8]) -> Result<()> {
        if self.finalized {
            return Err(CKR_OPERATION_NOT_INITIALIZED)?;
        }
        self.in_use = true;

        if unsafe {
            EVP_MAC_update(self.ctx.as_mut_ptr(), data.as_ptr(), data.len())
        } != 1
        {
            return Err(CKR_DEVICE_ERROR)?;
        }

        Ok(())
    }

    /// Finalizes the CMAC computation and returns the output in the
    /// provided buffer
    fn finalize(&mut self, output: &mut [u8]) -> Result<()> {
        if self.finalized {
            return Err(CKR_OPERATION_NOT_INITIALIZED)?;
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
            return Err(CKR_DEVICE_ERROR)?;
        }
        if outlen != AES_BLOCK_SIZE {
            return Err(CKR_GENERAL_ERROR)?;
        }

        output.copy_from_slice(&buf[..output.len()]);
        zeromem(&mut buf);

        #[cfg(feature = "fips")]
        self.fips_approval_cmac()?;

        Ok(())
    }

    /// CMAC specific FIPS checks
    #[cfg(feature = "fips")]
    fn fips_approval_cmac(&mut self) -> Result<()> {
        /*
         * NIST SP 800-38B A.2:
         * > For most applications, a value for Tlen that is at least 64
         * > should provide sufficient protection against guessing attacks.
         *
         * 64b == 8B
         */
        self.fips_approved = Some(self.maclen >= 8);

        Ok(())
    }
}

impl MechOperation for AesCmacOperation {
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

/// Implements the (internal) Mac interface for the AES CMAC operation
///
/// All methods just call the related the internal method
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

/// Implements the Sign interface for the AES CMAC operation
///
/// All methods just call the related the internal method
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

/// Implements the Verify interface for the AES CMAC operation
///
/// All methods just call the related the internal method
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
            return Err(CKR_SIGNATURE_INVALID)?;
        }
        Ok(())
    }

    fn signature_len(&self) -> Result<usize> {
        Ok(self.maclen)
    }
}

/// The AES MAC operation object
///
/// This object is used to hold data for any AES MAC operation
#[derive(Debug)]
pub struct AesMacOperation {
    mech: CK_MECHANISM_TYPE,
    finalized: bool,
    in_use: bool,
    padbuf: [u8; AES_BLOCK_SIZE],
    padlen: usize,
    macbuf: [u8; AES_BLOCK_SIZE],
    maclen: usize,
    op: AesOperation,
    #[cfg(feature = "fips")]
    fips_approved: Option<bool>,
}

impl Drop for AesMacOperation {
    fn drop(&mut self) {
        zeromem(&mut self.padbuf);
        zeromem(&mut self.macbuf);
    }
}

#[allow(dead_code)]
impl AesMacOperation {
    /// Helper to register the MAC mechanisms
    pub fn register_mechanisms(mechs: &mut Mechanisms) {
        for ckm in &[CKM_AES_MAC, CKM_AES_MAC_GENERAL] {
            mechs.add_mechanism(*ckm, new_mechanism(CKF_SIGN | CKF_VERIFY));
        }
    }

    /// Initializes and returns a MAC operation
    pub fn init(mech: &CK_MECHANISM, key: &Object) -> Result<AesMacOperation> {
        let maclen = match mech.mechanism {
            CKM_AES_MAC_GENERAL => {
                let params = cast_params!(mech, CK_MAC_GENERAL_PARAMS);
                let val = params as usize;
                if val > AES_BLOCK_SIZE {
                    return Err(CKR_MECHANISM_PARAM_INVALID)?;
                }
                val
            }
            CKM_AES_MAC => {
                if mech.ulParameterLen != 0 {
                    return Err(CKR_ARGUMENTS_BAD)?;
                }
                AES_BLOCK_SIZE / 2
            }
            _ => return Err(CKR_MECHANISM_INVALID)?,
        };
        let iv = [0u8; AES_BLOCK_SIZE];
        Ok(AesMacOperation {
            mech: mech.mechanism,
            finalized: false,
            in_use: false,
            padbuf: [0; AES_BLOCK_SIZE],
            padlen: 0,
            macbuf: [0; AES_BLOCK_SIZE],
            maclen: maclen,
            op: AesOperation::encrypt_new(
                &CK_MECHANISM {
                    mechanism: CKM_AES_CBC,
                    pParameter: void_ptr!(iv.as_ptr()),
                    ulParameterLen: iv.len() as CK_ULONG,
                },
                key,
            )?,
            #[cfg(feature = "fips")]
            fips_approved: None,
        })
    }

    /// Begins a MAC computation
    fn begin(&mut self) -> Result<()> {
        if self.in_use {
            return Err(CKR_OPERATION_NOT_INITIALIZED)?;
        }
        Ok(())
    }

    /// Feeds in the next data buffer into the MAC computation
    fn update(&mut self, data: &[u8]) -> Result<()> {
        if self.finalized {
            return Err(CKR_OPERATION_NOT_INITIALIZED)?;
        }
        self.in_use = true;

        let mut data_len = self.padlen + data.len();
        let mut cursor = 0;

        if data_len < AES_BLOCK_SIZE {
            self.padbuf[self.padlen..data_len].copy_from_slice(data);
            self.padlen = data_len;
            return Ok(());
        }
        if self.padlen > 0 {
            /* first full block */
            cursor = AES_BLOCK_SIZE - self.padlen;
            self.padbuf[self.padlen..].copy_from_slice(&data[..cursor]);
            let outlen =
                self.op.encrypt_update(&self.padbuf, &mut self.macbuf)?;
            if outlen != AES_BLOCK_SIZE {
                self.finalized = true;
                return Err(CKR_GENERAL_ERROR)?;
            }
            data_len -= AES_BLOCK_SIZE;
        }

        /* whole blocks */
        while data_len > AES_BLOCK_SIZE {
            let outlen = self.op.encrypt_update(
                &data[cursor..(cursor + AES_BLOCK_SIZE)],
                &mut self.macbuf,
            )?;
            if outlen != AES_BLOCK_SIZE {
                self.finalized = true;
                return Err(CKR_GENERAL_ERROR)?;
            }
            cursor += AES_BLOCK_SIZE;
            data_len -= AES_BLOCK_SIZE;
        }

        if data_len > 0 {
            self.padbuf[..data_len].copy_from_slice(&data[cursor..]);
        }
        self.padlen = data_len;
        Ok(())
    }

    /// Finalizes the MAC computation and returns the output in the
    /// provided buffer
    fn finalize(&mut self, output: &mut [u8]) -> Result<()> {
        if !self.in_use {
            return Err(CKR_OPERATION_NOT_INITIALIZED)?;
        }
        if self.finalized {
            return Err(CKR_OPERATION_NOT_INITIALIZED)?;
        }
        self.finalized = true;

        if output.len() != self.maclen {
            return Err(CKR_GENERAL_ERROR)?;
        }

        if self.padlen > 0 {
            /* last full block */
            self.padbuf[self.padlen..].fill(0);
            let outlen =
                self.op.encrypt_update(&self.padbuf, &mut self.macbuf)?;
            if outlen != AES_BLOCK_SIZE {
                return Err(CKR_GENERAL_ERROR)?;
            }
        }

        output.copy_from_slice(&self.macbuf[..output.len()]);

        #[cfg(feature = "fips")]
        {
            self.fips_approved = self.op.fips_approved();
        }
        Ok(())
    }
}

impl MechOperation for AesMacOperation {
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

/// Implements the Sign interface for the AES MAC operation
///
/// All methods just call the related the internal method
impl Sign for AesMacOperation {
    fn sign(&mut self, data: &[u8], signature: &mut [u8]) -> Result<()> {
        self.begin()?;
        self.update(data)?;
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

/// Implements the Verify interface for the AES MAC operation
///
/// All methods just call the related the internal method
impl Verify for AesMacOperation {
    fn verify(&mut self, data: &[u8], signature: &[u8]) -> Result<()> {
        self.begin()?;
        self.update(data)?;
        self.verify_final(signature)
    }

    fn verify_update(&mut self, data: &[u8]) -> Result<()> {
        self.update(data)
    }

    fn verify_final(&mut self, signature: &[u8]) -> Result<()> {
        let mut verify: Vec<u8> = vec![0; self.maclen];
        self.finalize(verify.as_mut_slice())?;
        if !constant_time_eq(&verify, signature) {
            return Err(CKR_SIGNATURE_INVALID)?;
        }
        Ok(())
    }

    fn signature_len(&self) -> Result<usize> {
        Ok(self.maclen)
    }
}
