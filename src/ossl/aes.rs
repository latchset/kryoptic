// Copyright 2024 Simo Sorce
// See LICENSE.txt file for terms

//! This module implements access to the OpenSSL implementation of AES

use crate::aes::*;
use crate::error;
use crate::error::{map_err, Result};
use crate::get_random_data;
use crate::mechanism::*;
use crate::misc::{
    bytes_to_slice, bytes_to_vec, cast_params, void_ptr, zeromem,
};
use crate::object::Object;
use crate::ossl::common::osslctx;
use crate::pkcs11::*;

use constant_time_eq::constant_time_eq;
use ossl::cipher::{AeadParams, AesCtsMode, AesSize, EncAlg, OsslCipher};
use ossl::mac::{MacAlg, OsslMac};
use ossl::OsslSecret;

#[cfg(feature = "fips")]
use ossl::fips::FipsApproval;

/// Maximum buffer size for accumulating data in CCM mode (1 MiB).
const MAX_CCM_BUF: usize = 1 << 20; /* 1MiB */
/// Minimum number of bits required for random IV generation.
const MIN_RANDOM_IV_BITS: usize = 64;

const AES_KWP_BLOCK: usize = AES_BLOCK_SIZE / 2;

/// A raw AES Key wrapper
///
/// Ensures the data is zeroized on deallocation
#[derive(Debug)]
struct AesKey {
    /// Raw key bytes.
    raw: Vec<u8>,
}

impl Drop for AesKey {
    fn drop(&mut self) {
        zeromem(self.raw.as_mut_slice());
    }
}

/// Extracts the raw key bytes from a PKCS#11 `Object` into an `AesKey`.
/// Validates the key length.
fn object_to_raw_key(key: &Object) -> Result<AesKey> {
    let val = key.get_attr_as_bytes(CKA_VALUE)?;
    check_key_len(val.len())?;
    Ok(AesKey { raw: val.clone() })
}

/// AES Initialization Vector Object
///
/// Defines the characteristics of the IV to be used in the AES operation
/// it is referenced from. Size, generation method, counter, etc..
#[derive(Debug)]
struct AesIvData {
    /// The IV buffer. May hold the initial value or be updated by a generator.
    buf: Vec<u8>,
    /// Number of fixed bits at the start of the IV (for counter modes).
    fixedbits: usize,
    /// IV generation method (e.g., `CKG_GENERATE_COUNTER`).
    generator: CK_GENERATOR_FUNCTION,
    /// Current counter value (if applicable).
    counter: u64,
    /// Maximum counter value before wrapping/error (if applicable).
    maxcount: u64,
}

impl AesIvData {
    /// Returns an empty IV container
    fn none() -> Result<AesIvData> {
        Ok(AesIvData {
            buf: Vec::new(),
            fixedbits: 0,
            generator: CKG_NO_GENERATE,
            counter: 0,
            maxcount: 0,
        })
    }

    /// Returns an IV container with the specified IV
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
    /// Initialization Vector data and generation parameters.
    iv: AesIvData,
    /// Maximum number of blocks allowed for CTR mode before counter wraps.
    maxblocks: u128,
    /// Cipher Text Stealing mode (0=off, 1=CS1, 2=CS2, 3=CS3).
    ctsmode: u8,
    /// Expected total data length for CCM mode.
    datalen: usize,
    /// Additional Authenticated Data (AAD) for AEAD modes (GCM, CCM).
    aad: Vec<u8>,
    /// Expected tag length for AEAD modes (GCM, CCM).
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
    /// The specific AES mechanism being used (e.g., CKM_AES_CBC_PAD).
    mech: CK_MECHANISM_TYPE,
    /// The operation type flags (CKF_ENCRYPT, CKF_DECRYPT, etc.).
    op: CK_FLAGS,
    /// The wrapped AES key being used.
    key: AesKey,
    /// Parameters specific to the current operation (IV, AAD, etc.).
    params: AesParams,
    /// Flag indicating if the operation has been finalized.
    finalized: bool,
    /// Flag indicating if the operation is in progress (update called).
    in_use: bool,
    /// The underlying ossl cipher context.
    ctx: Option<OsslCipher>,
    /// Internal buffer for handling partial blocks or accumulating data.
    buffer: Vec<u8>,
    /// Counter for blocks processed (used for CTR mode limits).
    blockctr: u128,
    /// Option to report fips indicator status
    #[cfg(feature = "fips")]
    fips_approval: FipsApproval,
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
            mechs.add_mechanism(*ckm, &(*AES_MECHS)[0]);
        }

        for ckm in &[CKM_AES_GCM, CKM_AES_CCM] {
            mechs.add_mechanism(*ckm, &(*AES_MECHS)[1]);
        }

        #[cfg(not(feature = "fips"))]
        for ckm in &[
            CKM_AES_OFB,
            CKM_AES_CFB128,
            CKM_AES_CFB1,
            CKM_AES_CFB8,
            /* OpenSSL does not implement AES CFB-64 */
        ] {
            mechs.add_mechanism(*ckm, &(*AES_MECHS)[2]);
        }

        mechs.add_mechanism(CKM_AES_KEY_GEN, &(*AES_MECHS)[3]);
    }

    /// Parses the PKCS#11 mechanism parameters (`CK_MECHANISM`) and initializes
    /// an `AesParams` struct based on the specific AES mechanism type.
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
                // The PKCS#11 specification allows 0-length tags, but OpenSSL
                // does not so we restrict the params to sensible values only
                if params.ulTagBits < 8 {
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

    /// Helper function to get the correct EncAlg from the provided
    /// AES mechanism type.
    fn get_cipher(
        mech: CK_MECHANISM_TYPE,
        params: &AesParams,
        keylen: usize,
    ) -> Result<EncAlg> {
        let size = match keylen {
            16 => AesSize::Aes128,
            24 => AesSize::Aes192,
            32 => AesSize::Aes256,
            _ => return Err(CKR_KEY_INDIGESTIBLE)?,
        };
        Ok(match mech {
            CKM_AES_CCM => EncAlg::AesCcm(size),
            CKM_AES_GCM => EncAlg::AesGcm(size),
            CKM_AES_CTS => match params.ctsmode {
                1 => EncAlg::AesCts(size, AesCtsMode::CtsModeCS1),
                2 => EncAlg::AesCts(size, AesCtsMode::CtsModeCS2),
                3 => EncAlg::AesCts(size, AesCtsMode::CtsModeCS3),
                _ => return Err(CKR_GENERAL_ERROR)?,
            },
            CKM_AES_CTR => EncAlg::AesCtr(size),
            CKM_AES_CBC | CKM_AES_CBC_PAD => EncAlg::AesCbc(size),
            CKM_AES_ECB => EncAlg::AesEcb(size),
            #[cfg(not(feature = "fips"))]
            CKM_AES_CFB8 => EncAlg::AesCfb8(size),
            #[cfg(not(feature = "fips"))]
            CKM_AES_CFB1 => EncAlg::AesCfb1(size),
            #[cfg(not(feature = "fips"))]
            CKM_AES_CFB128 => EncAlg::AesCfb128(size),
            #[cfg(not(feature = "fips"))]
            CKM_AES_OFB => EncAlg::AesOfb(size),
            CKM_AES_KEY_WRAP => EncAlg::AesWrap(size),
            CKM_AES_KEY_WRAP_KWP => EncAlg::AesWrapPad(size),
            _ => return Err(CKR_MECHANISM_INVALID)?,
        })
    }

    /// Helper function that generate IVs according to the parameters
    /// stored in the object.
    ///
    /// Each call returns the next IV and updates counters or any other
    /// data in the operation object as needed.
    fn generate_iv(params: &mut AesParams) -> Result<()> {
        let genbits = params.iv.buf.len() * 8 - params.iv.fixedbits;
        if params.iv.counter == 0 {
            params.iv.maxcount = if genbits >= 64 {
                u64::MAX
            } else {
                1u64 << genbits
            }
        }

        if params.iv.counter >= params.iv.maxcount {
            return Err(CKR_DATA_LEN_RANGE)?;
        }

        let mut genidx = params.iv.fixedbits / 8;
        let mask = u8::try_from(genbits % 8)?;
        let genbytes = (genbits + 7) / 8;

        match params.iv.generator {
            CKG_GENERATE | CKG_GENERATE_COUNTER => {
                let cntbuf = params.iv.counter.to_be_bytes();
                params.iv.buf[genidx] &= !mask;
                if genbytes > cntbuf.len() {
                    genidx += 1;
                    let cntidx = params.iv.buf.len() - cntbuf.len();
                    params.iv.buf[genidx..cntidx].fill(0);
                    params.iv.buf[cntidx..].copy_from_slice(&cntbuf);
                } else {
                    let cntidx = cntbuf.len() - genbytes;
                    params.iv.buf[genidx] |= cntbuf[cntidx] & mask;
                    params.iv.buf[(genidx + 1)..]
                        .copy_from_slice(&cntbuf[(cntidx + 1)..]);
                }
            }
            CKG_GENERATE_COUNTER_XOR => {
                let cntbuf = params.iv.counter.to_be_bytes();
                if genbytes > cntbuf.len() {
                    let cntidx = params.iv.buf.len() - cntbuf.len();
                    params.iv.buf[cntidx..]
                        .iter_mut()
                        .zip(cntbuf.iter())
                        .for_each(|(iv, cn)| *iv ^= *cn);
                } else {
                    let cntidx = cntbuf.len() - genbytes;
                    params.iv.buf[genidx] ^= cntbuf[cntidx] & mask;
                    params.iv.buf[(genidx + 1)..]
                        .iter_mut()
                        .zip(cntbuf[(cntidx + 1)..].iter())
                        .for_each(|(iv, cn)| *iv ^= *cn);
                }
            }
            CKG_GENERATE_RANDOM => {
                let mut genbuf = vec![0u8; (genbits + 7) / 8];
                get_random_data(&mut genbuf)?;
                params.iv.buf[genidx] ^= genbuf[0] & mask;
                params.iv.buf[(genidx + 1)..].copy_from_slice(&genbuf[1..]);
            }
            _ => return Err(CKR_GENERAL_ERROR)?,
        }

        params.iv.counter += 1;
        Ok(())
    }

    /// Encryption/Decryption Initialization helper
    ///
    /// Sets up all the required context or parameters setting to direct
    /// the underlying OpenSSL crypto library, based on the configured
    /// mechanism and all the parameters stored on the object.
    fn cipher_initialize(
        mech: CK_MECHANISM_TYPE,
        params: &mut AesParams,
        key: &Vec<u8>,
        enc: bool,
    ) -> Result<OsslCipher> {
        /* Generates IV for some AEAD modes */
        if params.iv.generator != CKG_NO_GENERATE {
            Self::generate_iv(params)?;
        }

        let mut ctx = OsslCipher::new(
            osslctx(),
            Self::get_cipher(mech, params, key.len())?,
            enc,
            OsslSecret::from_slice(key.as_slice()),
            if params.iv.buf.len() > 0 {
                Some(params.iv.buf.clone())
            } else {
                None
            },
            match mech {
                CKM_AES_CCM | CKM_AES_GCM => Some(AeadParams::new(
                    if params.aad.len() > 0 {
                        Some(params.aad.clone())
                    } else {
                        None
                    },
                    params.taglen,
                    params.datalen,
                )),
                _ => None,
            },
        )?;

        /* OpenSSL defaults to padding on, so we need to turn it explicitly
         * off for mechanisms that do not use it because PKCS#11 does not
         * implicitly provide padding. */
        match mech {
            CKM_AES_ECB | CKM_AES_CBC => ctx.set_padding(false)?,
            CKM_AES_CBC_PAD => ctx.set_padding(true)?,
            _ => (),
        }

        Ok(ctx)
    }

    /// Instantiates a new Encryption AES Operation
    pub fn encrypt_new(
        mech: &CK_MECHANISM,
        key: &Object,
    ) -> Result<AesOperation> {
        #[cfg(feature = "fips")]
        let mut fips_approval = FipsApproval::init();

        let mut params = Self::init_params(mech)?;
        let aeskey = object_to_raw_key(key)?;

        #[cfg(feature = "fips")]
        fips_approval.clear();

        let ctx = Self::cipher_initialize(
            mech.mechanism,
            &mut params,
            &aeskey.raw,
            true,
        )?;

        #[cfg(feature = "fips")]
        fips_approval.update();

        Ok(AesOperation {
            mech: mech.mechanism,
            op: CKF_ENCRYPT,
            key: aeskey,
            params: params,
            finalized: false,
            in_use: false,
            ctx: Some(ctx),
            buffer: Vec::new(),
            blockctr: 0,
            #[cfg(feature = "fips")]
            fips_approval: fips_approval,
        })
    }

    /// Instantiates a new Decryption AES Operation
    pub fn decrypt_new(
        mech: &CK_MECHANISM,
        key: &Object,
    ) -> Result<AesOperation> {
        #[cfg(feature = "fips")]
        let mut fips_approval = FipsApproval::init();

        let mut params = Self::init_params(mech)?;
        let aeskey = object_to_raw_key(key)?;

        #[cfg(feature = "fips")]
        fips_approval.clear();

        let ctx = Self::cipher_initialize(
            mech.mechanism,
            &mut params,
            &aeskey.raw,
            false,
        )?;

        #[cfg(feature = "fips")]
        fips_approval.update();

        Ok(AesOperation {
            mech: mech.mechanism,
            op: CKF_DECRYPT,
            key: aeskey,
            params: params,
            finalized: false,
            in_use: false,
            ctx: Some(ctx),
            buffer: Vec::new(),
            blockctr: 0,
            #[cfg(feature = "fips")]
            fips_approval: fips_approval,
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
                    zeromem(keydata.as_mut_slice());
                    return Err(CKR_MECHANISM_PARAM_INVALID)?;
                }
            }
            _ => (),
        }

        let needed_len = op.encryption_len(keydata.len(), true)?;
        if output.len() == 0 {
            zeromem(keydata.as_mut_slice());
            return Ok(needed_len);
        }
        if output.len() < needed_len {
            zeromem(keydata.as_mut_slice());
            return Err(error::Error::buf_too_small(needed_len));
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
                // The PKCS#11 specification allows 0-length tags, but OpenSSL
                // does not so we restrict the params to sensible values only
                if params.ulTagBits < 8 {
                    return Err(CKR_MECHANISM_PARAM_INVALID)?;
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
            ctx: None,
            buffer: Vec::new(),
            blockctr: 0,
            #[cfg(feature = "fips")]
            fips_approval: FipsApproval::init(),
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
            self.fips_approval.reset();
        }

        let iv_ptr = self.init_msg_params(parameter, parameter_len, aad)?;

        self.finalized = false;
        self.in_use = true;

        self.ctx = Some(Self::cipher_initialize(
            self.mech,
            &mut self.params,
            &self.key.raw,
            true,
        )?);

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
            ctx: None,
            buffer: Vec::new(),
            blockctr: 0,
            #[cfg(feature = "fips")]
            fips_approval: FipsApproval::init(),
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
            self.fips_approval.reset();
        }

        let _ = self.init_msg_params(parameter, parameter_len, aad)?;

        self.finalized = false;
        self.in_use = true;

        self.ctx = Some(Self::cipher_initialize(
            self.mech,
            &mut self.params,
            &self.key.raw,
            false,
        )?);

        #[cfg(feature = "fips")]
        self.fips_approval_aead()?;

        Ok(())
    }

    /// AEAD specific FIPS checks
    #[cfg(feature = "fips")]
    fn fips_approval_aead(&mut self) -> Result<()> {
        if self.fips_approval.is_not_approved() {
            /* if the indicator is already set as not approved,
             * just return, there is no point testing further
             * as we should never overwrite an unapproved state
             */
            return Ok(());
        }

        /* For AEAD we handle indicators directly because OpenSSL has an
         * inflexible API that provides incorrect answers when we
         * generate the IV outside of that code */

        /* The IV size must be 12 in FIPS mode */
        if self.params.iv.buf.len() != 12 {
            self.fips_approval.set(false);
            return Ok(());
        }

        /* The IV must be generated in FIPS mode */
        match self.params.iv.generator {
            CKG_NO_GENERATE => match self.op {
                CKF_MESSAGE_ENCRYPT => self.fips_approval.set(false),
                CKF_MESSAGE_DECRYPT => self.fips_approval.set(true),
                _ => return Err(self.op_err(CKR_GENERAL_ERROR)),
            },
            CKG_GENERATE_RANDOM => self.fips_approval.set(true),
            CKG_GENERATE | CKG_GENERATE_COUNTER | CKG_GENERATE_COUNTER_XOR => {
                if self.params.iv.fixedbits < 32 {
                    self.fips_approval.set(false)
                } else {
                    self.fips_approval.set(true)
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
            self.fips_approval.set(false);
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
        self.fips_approval.approval()
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
        self.in_use = true;

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
                if plain.len() % AES_KWP_BLOCK != 0 {
                    return Err(self.op_err(CKR_DATA_LEN_RANGE));
                }
            }
            _ => (),
        }
        if cipher.len() < outlen {
            /* This is the only, non-fatal error */
            return Err(error::Error::buf_too_small(outlen));
        }

        let ctx = match &mut self.ctx {
            Some(c) => c,
            None => return Err(self.op_err(CKR_GENERAL_ERROR)),
        };

        #[cfg(feature = "fips")]
        self.fips_approval.clear();

        let mut cipher_offset = 0;
        let mut plain_offset = 0;
        let mut plain_end = plain.len();
        match self.mech {
            CKM_AES_CCM => {
                if plain.len() < self.params.datalen {
                    self.buffer.extend_from_slice(plain);
                    if self.buffer.len() == self.params.datalen {
                        cipher_offset = ctx
                            .update(self.buffer.as_slice(), cipher)
                            .or_else(|_| {
                                self.finalized = true;
                                Err(CKR_DEVICE_ERROR)
                            })?;
                        if cipher_offset != self.params.datalen {
                            return Err(self.op_err(CKR_DEVICE_ERROR));
                        }
                        zeromem(self.buffer.as_mut_slice());
                        self.buffer.clear();
                    }
                    plain_offset = plain_end;
                }
            }
            CKM_AES_ECB | CKM_AES_CBC | CKM_AES_CBC_PAD => {
                if self.buffer.len() > 0 {
                    /* we do not want to allocate huge buffers, so we deal
                     * with the first block on the auxiliary buffer and
                     * then do the bulk of the data string from the caller
                     * provided buffer */
                    if self.buffer.len() + plain_end >= AES_BLOCK_SIZE {
                        plain_offset = AES_BLOCK_SIZE - self.buffer.len();
                        self.buffer.extend_from_slice(&plain[..plain_offset]);
                        cipher_offset = ctx
                            .update(self.buffer.as_slice(), cipher)
                            .or_else(|_| {
                                self.finalized = true;
                                Err(CKR_DEVICE_ERROR)
                            })?;
                        if cipher_offset != AES_BLOCK_SIZE {
                            return Err(self.op_err(CKR_DEVICE_ERROR));
                        }
                        zeromem(self.buffer.as_mut_slice());
                        self.buffer.clear();
                    }
                }
                /* we only ever encrypt entire blocks, even for Padded CBC, so
                 * we are sure OpenSSL will always encrypt all the data, and we
                 * can predict the outcome correctly */
                let trailer = (plain_end - plain_offset) % AES_BLOCK_SIZE;
                if trailer != 0 {
                    plain_end -= trailer;
                    self.buffer.extend_from_slice(&plain[plain_end..]);
                }
            }
            CKM_AES_CTS => {
                /* CTS requires a minimum of 2 blocks to perform stealing
                 * so if the output is smaller we need to use a support buffer
                 * to call into OpenSSL */
                if cipher.len() < AES_BLOCK_SIZE * 2 {
                    let mut buffer = [0u8; AES_BLOCK_SIZE * 2];
                    cipher_offset =
                        ctx.update(plain, &mut buffer).or_else(|_| {
                            self.finalized = true;
                            Err(CKR_DEVICE_ERROR)
                        })?;
                    if cipher_offset != plain.len() {
                        return Err(self.op_err(CKR_DEVICE_ERROR));
                    }
                    cipher.copy_from_slice(&buffer[..cipher_offset]);
                    zeromem(&mut buffer);
                    /* input fully consumed */
                    plain_offset = plain_end;
                }
            }
            _ => (),
        }

        if plain_end - plain_offset > 0 {
            let outlen = ctx
                .update(
                    &plain[plain_offset..plain_end],
                    &mut cipher[cipher_offset..],
                )
                .or_else(|_| Err(self.op_err(CKR_DEVICE_ERROR)))?;
            cipher_offset += outlen;
        }

        #[cfg(feature = "fips")]
        self.fips_approval.update();

        Ok(cipher_offset)
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

        let ctx = match &mut self.ctx {
            Some(c) => c,
            None => return Err(self.op_err(CKR_GENERAL_ERROR)),
        };

        #[cfg(feature = "fips")]
        self.fips_approval.clear();

        let mut outlen = 0;
        match self.mech {
            CKM_AES_CCM | CKM_AES_GCM => {
                if cipher.len() < self.params.taglen {
                    /* This is the only, non-fatal error */
                    return Err(error::Error::buf_too_small(
                        self.params.taglen,
                    ));
                }

                outlen = ctx.finalize(cipher)?;
                if outlen != 0 {
                    self.finalized = true;
                    return Err(CKR_DEVICE_ERROR)?;
                }
                outlen = self.params.taglen;
                ctx.get_tag(&mut cipher[..outlen])?;
            }
            CKM_AES_CTR => {
                self.finalized = true;
                if self.params.maxblocks > 0 {
                    if self.blockctr >= self.params.maxblocks {
                        self.finalized = true;
                        return Err(CKR_DATA_LEN_RANGE)?;
                    }
                }
            }
            CKM_AES_CTS => (),
            #[cfg(not(feature = "fips"))]
            CKM_AES_CFB8 | CKM_AES_CFB1 | CKM_AES_CFB128 | CKM_AES_OFB => (),
            CKM_AES_ECB | CKM_AES_CBC => {
                self.finalized = true;
                if self.buffer.len() > 0 {
                    self.finalized = true;
                    return Err(CKR_DATA_LEN_RANGE)?;
                }
                let mut buffer = [0u8; AES_BLOCK_SIZE];
                outlen = ctx.finalize(&mut buffer)?;
                if outlen != 0 {
                    self.finalized = true;
                    zeromem(&mut buffer);
                    return Err(CKR_DEVICE_ERROR)?;
                }
            }
            CKM_AES_CBC_PAD => {
                if cipher.len() < AES_BLOCK_SIZE {
                    return Err(error::Error::buf_too_small(AES_BLOCK_SIZE));
                }

                self.finalized = true;

                if self.buffer.len() > 0 {
                    outlen = ctx.update(self.buffer.as_slice(), cipher)?;
                    /* we do not expect anything in output because
                     * this is a partial block, so the CBC PAD
                     * algorithm update can't return anything until
                     * final is called, where padding is applied */
                    if outlen != 0 {
                        self.finalized = true;
                        return Err(CKR_DEVICE_ERROR)?;
                    }
                }

                outlen = ctx.finalize(cipher)?;
                if outlen != AES_BLOCK_SIZE {
                    self.finalized = true;
                    return Err(CKR_DEVICE_ERROR)?;
                }
            }
            CKM_AES_KEY_WRAP | CKM_AES_KEY_WRAP_KWP => (),
            _ => {
                self.finalized = true;
                return Err(CKR_GENERAL_ERROR)?;
            }
        };

        #[cfg(feature = "fips")]
        self.fips_approval.finalize();

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
                    if data_len % AES_KWP_BLOCK != 0 {
                        return Err(self.op_err(CKR_DATA_LEN_RANGE));
                    } else {
                        data_len + AES_KWP_BLOCK
                    }
                }
                CKM_AES_KEY_WRAP_KWP => {
                    ((data_len + AES_BLOCK_SIZE - 1) / AES_KWP_BLOCK)
                        * AES_KWP_BLOCK
                }
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
                    if data_len % AES_KWP_BLOCK != 0 {
                        return Err(self.op_err(CKR_DATA_LEN_RANGE));
                    } else {
                        data_len + AES_KWP_BLOCK
                    }
                }
                CKM_AES_KEY_WRAP_KWP => {
                    ((data_len + AES_BLOCK_SIZE - 1) / AES_KWP_BLOCK)
                        * AES_KWP_BLOCK
                }
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
                if cipher.len() % AES_KWP_BLOCK != 0 {
                    return Err(self.op_err(CKR_DATA_LEN_RANGE));
                }
            }
            _ => (),
        }
        self.in_use = true;

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

        let ctx = match &mut self.ctx {
            Some(c) => c,
            None => return Err(self.op_err(CKR_GENERAL_ERROR)),
        };

        #[cfg(feature = "fips")]
        self.fips_approval.clear();

        let mut plain_offset = 0;
        let mut cipher_offset = 0;
        let mut cipher_end = cipher.len();
        match self.mech {
            CKM_AES_CCM => {
                let needlen = self.params.datalen + self.params.taglen;
                let cbuf = if cipher_end < needlen {
                    self.buffer.extend_from_slice(cipher);
                    self.buffer.as_slice()
                } else {
                    if cipher.len() != needlen {
                        return Err(self.op_err(CKR_DATA_LEN_RANGE));
                    }
                    cipher
                };

                if cbuf.len() == needlen {
                    /* if we have the whole buffer, set the tag now,
                     * openssl requires this order of operations for CCM */
                    /* The tag is at the tail of the cipher buffer */
                    cipher_end = self.params.datalen;
                    ctx.set_tag(&cbuf[cipher_end..]).or_else(|_| {
                        self.finalized = true;
                        Err(CKR_DEVICE_ERROR)
                    })?;

                    plain_offset = ctx
                        .update(&cbuf[..cipher_end], plain)
                        .or_else(|_| {
                            self.finalized = true;
                            Err(CKR_DEVICE_ERROR)
                        })?;

                    zeromem(self.buffer.as_mut_slice());
                    self.buffer.clear();
                }

                /* One way or another the cipher buffer has been utilized */
                cipher_offset = cipher_end;
            }
            CKM_AES_GCM => {
                /* the tag is appended at the end of the ciphertext,
                 * but we do not know how long the ciphertext is */
                if self.buffer.len() > 0 {
                    if cipher_end > self.params.taglen {
                        /* consume the saved buffer now,
                         * so we avoid unnecessary data copy */
                        plain_offset = ctx
                            .update(self.buffer.as_slice(), plain)
                            .or_else(|_| {
                                self.finalized = true;
                                Err(CKR_DEVICE_ERROR)
                            })?;
                        zeromem(self.buffer.as_mut_slice());
                        self.buffer.clear();
                        cipher_end -= self.params.taglen;
                        self.buffer.extend_from_slice(&cipher[cipher_end..]);
                    } else {
                        self.buffer.extend_from_slice(cipher);
                        if self.buffer.len() > self.params.taglen {
                            let buflen = self.buffer.len() - self.params.taglen;
                            plain_offset = ctx
                                .update(
                                    &self.buffer.as_slice()[..buflen],
                                    plain,
                                )
                                .or_else(|_| {
                                    self.finalized = true;
                                    Err(CKR_DEVICE_ERROR)
                                })?;
                            zeromem(&mut self.buffer.as_mut_slice()[..buflen]);
                            let _ = self.buffer.drain(..buflen);
                        }
                    }
                    /* The cipher buffer has been utilized */
                    cipher_offset = cipher_end;
                } else if cipher_end > self.params.taglen {
                    cipher_end -= self.params.taglen;
                    self.buffer.extend_from_slice(&cipher[cipher_end..]);
                } else {
                    self.buffer.extend_from_slice(cipher);
                    /* The cipher buffer has been utilized */
                    cipher_offset = cipher_end;
                }
            }
            CKM_AES_ECB | CKM_AES_CBC | CKM_AES_CBC_PAD => {
                if self.buffer.len() > 0 {
                    /* we do not want to allocate huge buffers, so we deal
                     * with the first block on the auxiliary buffer and
                     * then do the bulk of the data string from the caller
                     * provided buffer */
                    if self.buffer.len() + cipher_end >= AES_BLOCK_SIZE {
                        cipher_offset = AES_BLOCK_SIZE - self.buffer.len();
                        self.buffer.extend_from_slice(&cipher[..cipher_offset]);
                        plain_offset = ctx
                            .update(self.buffer.as_slice(), plain)
                            .or_else(|_| {
                                self.finalized = true;
                                Err(CKR_DEVICE_ERROR)
                            })?;
                        if plain_offset != AES_BLOCK_SIZE {
                            return Err(self.op_err(CKR_DEVICE_ERROR));
                        }
                        zeromem(self.buffer.as_mut_slice());
                        self.buffer.clear();
                    }
                }
                /* we only ever decrypt entire blocks, even for Padded CBC, so
                 * we are sure OpenSSL will always decrypt all the data, and we
                 * can predict the outcome correctly */
                let remainder = (cipher_end - cipher_offset) % AES_BLOCK_SIZE;
                if remainder != 0 {
                    cipher_end -= remainder;
                    self.buffer.extend_from_slice(&cipher[cipher_end..]);
                }
            }
            CKM_AES_CTS => {
                /* CTS requires a minimum of 2 blocks to perform stealing
                 * so if the output is smaller we need to use a support buffer
                 * to call into OpenSSL */
                if plain.len() < AES_BLOCK_SIZE * 2 {
                    let mut buffer = [0u8; AES_BLOCK_SIZE * 2];
                    plain_offset =
                        ctx.update(cipher, &mut buffer).or_else(|_| {
                            self.finalized = true;
                            Err(CKR_DEVICE_ERROR)
                        })?;
                    if plain_offset != cipher.len() {
                        return Err(self.op_err(CKR_DEVICE_ERROR));
                    }
                    plain.copy_from_slice(&buffer[..plain_offset]);
                    zeromem(&mut buffer);
                    /* input fully consumed */
                    cipher_offset = cipher_end;
                }
            }
            _ => (),
        }

        if cipher_end - cipher_offset > 0 {
            let outlen = ctx
                .update(
                    &cipher[cipher_offset..cipher_end],
                    &mut plain[plain_offset..],
                )
                .or_else(|_| {
                    self.finalized = true;
                    Err(CKR_DEVICE_ERROR)
                })?;
            plain_offset += outlen;
        }

        #[cfg(feature = "fips")]
        self.fips_approval.update();

        Ok(plain_offset)
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

        let ctx = match &mut self.ctx {
            Some(c) => c,
            None => return Err(self.op_err(CKR_GENERAL_ERROR)),
        };

        self.finalized = true;

        #[cfg(feature = "fips")]
        self.fips_approval.clear();

        let mut outlen = 0;
        match self.mech {
            CKM_AES_CCM => {
                if self.buffer.len() > 0 {
                    return Err(CKR_DATA_LEN_RANGE)?;
                }
            }
            CKM_AES_GCM => {
                if self.buffer.len() != self.params.taglen {
                    return Err(CKR_DATA_LEN_RANGE)?;
                }
                ctx.set_tag(self.buffer.as_slice())?;
                match ctx.finalize(plain) {
                    Ok(len) => {
                        if len != 0 {
                            return Err(CKR_DEVICE_ERROR)?;
                        }
                    }
                    Err(_) => return Err(CKR_ENCRYPTED_DATA_INVALID)?,
                }
            }
            CKM_AES_CTR => {
                if self.params.maxblocks > 0 {
                    if self.blockctr >= self.params.maxblocks {
                        return Err(CKR_DATA_LEN_RANGE)?;
                    }
                }
            }
            CKM_AES_CTS => (),
            CKM_AES_ECB | CKM_AES_CBC => {
                if self.buffer.len() != 0 {
                    return Err(CKR_DATA_LEN_RANGE)?;
                }
                self.buffer.resize(AES_BLOCK_SIZE, 0);
                match ctx.finalize(self.buffer.as_mut_slice()) {
                    Ok(len) => {
                        if len != 0 {
                            zeromem(self.buffer.as_mut_slice());
                            return Err(CKR_DEVICE_ERROR)?;
                        }
                    }
                    Err(_) => return Err(CKR_ENCRYPTED_DATA_INVALID)?,
                }
                self.buffer.clear();
            }
            CKM_AES_CBC_PAD => {
                if self.buffer.len() != 0 {
                    return Err(CKR_DATA_LEN_RANGE)?;
                }
                outlen = match ctx.finalize(plain) {
                    Ok(len) => len,
                    Err(_) => return Err(CKR_ENCRYPTED_DATA_INVALID)?,
                };
            }
            #[cfg(not(feature = "fips"))]
            CKM_AES_CFB8 | CKM_AES_CFB1 | CKM_AES_CFB128 | CKM_AES_OFB => (),
            CKM_AES_KEY_WRAP | CKM_AES_KEY_WRAP_KWP => (),
            _ => return Err(CKR_GENERAL_ERROR)?,
        }

        #[cfg(feature = "fips")]
        self.fips_approval.finalize();

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
                    if data_len % AES_KWP_BLOCK != 0 {
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
                    if data_len % AES_KWP_BLOCK != 0 {
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
                        (data_len / AES_KWP_BLOCK) * AES_KWP_BLOCK
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

        let ctx = match &mut self.ctx {
            Some(c) => c,
            None => return Err(self.op_err(CKR_GENERAL_ERROR)),
        };

        #[cfg(feature = "fips")]
        self.fips_approval.clear();

        let mut outlen = 0;
        if plain.len() > 0 {
            outlen = ctx
                .update(plain, cipher)
                .or_else(|_| Err(self.op_err(CKR_DEVICE_ERROR)))?;
        }

        #[cfg(feature = "fips")]
        self.fips_approval.update();

        Ok(outlen)
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

        #[cfg(feature = "fips")]
        self.fips_approval.clear();

        if self.mech == CKM_AES_CCM {
            if plain.len() + self.buffer.len() != self.params.datalen {
                return Err(self.op_err(CKR_DATA_LEN_RANGE));
            }
            if cipher.len() < self.params.datalen {
                /* This is the only non-fatal error */
                return Err(error::Error::buf_too_small(self.params.datalen));
            }
        }

        let tagptr = self.check_msg_params(param, paramlen)?;

        let outlen = match self.mech {
            CKM_AES_CCM => {
                let pbuf = if plain.len() < self.params.datalen {
                    self.buffer.extend_from_slice(plain);
                    self.buffer.as_slice()
                } else {
                    plain
                };
                if pbuf.len() != self.params.datalen {
                    return Err(self.op_err(CKR_DATA_LEN_RANGE));
                }
                if let Some(ctx) = &mut self.ctx {
                    ctx.update(pbuf, cipher).or_else(|_| {
                        self.finalized = true;
                        Err(CKR_DEVICE_ERROR)
                    })?
                } else {
                    return Err(self.op_err(CKR_GENERAL_ERROR));
                }
            }
            CKM_AES_GCM => {
                self.msg_encrypt_next(param, paramlen, plain, cipher)?
            }
            _ => return Err(self.op_err(CKR_GENERAL_ERROR)),
        };

        let ctx = match &mut self.ctx {
            Some(c) => c,
            None => return Err(self.op_err(CKR_GENERAL_ERROR)),
        };

        if !ctx.finalize(cipher).is_ok_and(|len| len == 0) {
            zeromem(cipher);
            return Err(self.op_err(CKR_DEVICE_ERROR));
        }

        let tagbuf = bytes_to_slice!(mut tagptr, self.params.taglen, u8);

        if !ctx.get_tag(tagbuf).is_ok() {
            zeromem(cipher);
            return Err(self.op_err(CKR_DEVICE_ERROR));
        }

        #[cfg(feature = "fips")]
        self.fips_approval.finalize();

        self.in_use = false;
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

        let ctx = match &mut self.ctx {
            Some(c) => c,
            None => return Err(self.op_err(CKR_GENERAL_ERROR)),
        };

        #[cfg(feature = "fips")]
        self.fips_approval.clear();

        let mut outlen = 0;
        if cipher.len() > 0 {
            outlen = ctx
                .update(cipher, plain)
                .or_else(|_| Err(self.op_err(CKR_DEVICE_ERROR)))?;
        }

        #[cfg(feature = "fips")]
        self.fips_approval.update();

        Ok(outlen)
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

        let tagptr = self.check_msg_params(param, paramlen)?;

        #[cfg(feature = "fips")]
        self.fips_approval.clear();

        if self.mech == CKM_AES_CCM {
            if cipher.len() + self.buffer.len() != self.params.datalen {
                return Err(self.op_err(CKR_DATA_LEN_RANGE));
            }
            if plain.len() < self.params.datalen {
                /* This is the only non-fatal error */
                return Err(error::Error::buf_too_small(self.params.datalen));
            }
        }

        let tagbuf = bytes_to_slice!(tagptr, self.params.taglen, u8);

        /* The tag must be set first for CCM and does not hurt GCM */
        if let Some(ctx) = &mut self.ctx {
            if ctx.set_tag(tagbuf).is_err() {
                return Err(self.op_err(CKR_DEVICE_ERROR));
            }
        } else {
            return Err(self.op_err(CKR_GENERAL_ERROR));
        }

        let outlen = match self.mech {
            CKM_AES_CCM => {
                let cbuf = if cipher.len() < self.params.datalen {
                    self.buffer.extend_from_slice(cipher);
                    self.buffer.as_slice()
                } else {
                    cipher
                };
                if cbuf.len() != self.params.datalen {
                    return Err(self.op_err(CKR_DATA_LEN_RANGE));
                }
                if let Some(ctx) = &mut self.ctx {
                    ctx.update(cbuf, plain).or_else(|_| {
                        self.finalized = true;
                        Err(CKR_DEVICE_ERROR)
                    })?
                } else {
                    return Err(self.op_err(CKR_GENERAL_ERROR));
                }
            }
            CKM_AES_GCM => {
                let len =
                    self.msg_decrypt_next(param, paramlen, cipher, plain)?;

                /* only AES GCM must and can do this */
                if let Some(ctx) = &mut self.ctx {
                    match ctx.finalize(&mut []) {
                        Ok(len) => {
                            if len != 0 {
                                zeromem(plain);
                                return Err(self.op_err(CKR_DEVICE_ERROR));
                            }
                        }
                        Err(_) => {
                            return Err(self.op_err(CKR_ENCRYPTED_DATA_INVALID))
                        }
                    }
                } else {
                    return Err(self.op_err(CKR_GENERAL_ERROR));
                }

                len
            }
            _ => return Err(self.op_err(CKR_GENERAL_ERROR)),
        };

        #[cfg(feature = "fips")]
        self.fips_approval.finalize();

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

/// Represents an active AES-CMAC operation (RFC 4493).
///
/// _key and _mac as stored in order to make sure the pointers they
/// hold survive for as long as the operations are going on, as we
/// can't be sure openssl is not holding live pointers to the
/// parameters passed into the init functions
#[derive(Debug)]
pub struct AesCmacOperation {
    /// The specific CMAC mechanism being used.
    mech: CK_MECHANISM_TYPE,
    /// Flag indicating if the operation has been finalized.
    finalized: bool,
    /// Flag indicating if the operation is in progress (update called).
    in_use: bool,
    /// The OsslMac context
    ctx: OsslMac,
    /// The MAC length
    maclen: usize,
    /// Option that holds the FIPS indicator
    #[cfg(feature = "fips")]
    fips_approval: FipsApproval,
    /// Optional storage for signatures, used when the signature to verify
    /// is provided at initialization
    signature: Option<Vec<u8>>,
}

impl AesCmacOperation {
    /// Helper to register the CMAC mechanisms
    pub fn register_mechanisms(mechs: &mut Mechanisms) {
        for ckm in &[CKM_AES_CMAC, CKM_AES_CMAC_GENERAL] {
            mechs.add_mechanism(*ckm, &(*AES_MECHS)[4]);
        }
    }

    /// Initializes and returns a CMAC operation
    pub fn init(
        mech: &CK_MECHANISM,
        key: &Object,
        signature: Option<&[u8]>,
    ) -> Result<AesCmacOperation> {
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

        let key = key.get_attr_as_bytes(CKA_VALUE)?.clone();
        let mac = match key.len() {
            16 => MacAlg::CmacAes128,
            24 => MacAlg::CmacAes192,
            32 => MacAlg::CmacAes256,
            _ => return Err(CKR_KEY_INDIGESTIBLE)?,
        };

        #[cfg(feature = "fips")]
        let mut fips_approval = FipsApproval::init();

        let ctx = OsslMac::new(osslctx(), mac, key)?;

        #[cfg(feature = "fips")]
        fips_approval.update();

        Ok(AesCmacOperation {
            mech: mech.mechanism,
            finalized: false,
            in_use: false,
            ctx: ctx,
            maclen: maclen,
            #[cfg(feature = "fips")]
            fips_approval: fips_approval,
            signature: match signature {
                Some(s) => {
                    if s.len() != maclen {
                        return Err(CKR_SIGNATURE_LEN_RANGE)?;
                    }
                    Some(s.to_vec())
                }
                None => None,
            },
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

        #[cfg(feature = "fips")]
        self.fips_approval.clear();

        let ret = self.ctx.update(data);

        #[cfg(feature = "fips")]
        self.fips_approval.update();

        Ok(ret?)
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

        #[cfg(feature = "fips")]
        self.fips_approval.clear();

        let mut buf = [0u8; AES_BLOCK_SIZE];
        let outlen = self.ctx.finalize(&mut buf)?;
        if outlen != AES_BLOCK_SIZE {
            return Err(CKR_GENERAL_ERROR)?;
        }

        output.copy_from_slice(&buf[..output.len()]);
        zeromem(&mut buf);

        #[cfg(feature = "fips")]
        self.fips_approval_cmac();

        Ok(())
    }

    /// CMAC specific FIPS checks
    #[cfg(feature = "fips")]
    fn fips_approval_cmac(&mut self) {
        /*
         * NIST SP 800-38B A.2:
         * > For most applications, a value for Tlen that is at least 64
         * > should provide sufficient protection against guessing attacks.
         *
         * 64b == 8B
         */
        if self.maclen < 8 {
            self.fips_approval.set(false);
        }
        self.fips_approval.finalize();
    }

    /// Finalizes the CMAC computation and checks the signature
    fn finalize_ver(&mut self, signature: Option<&[u8]>) -> Result<()> {
        let mut computed = vec![0u8; self.maclen];
        self.finalize(computed.as_mut_slice())?;

        let sig = match signature {
            Some(sig) => sig,
            None => match &self.signature {
                Some(sig) => sig.as_slice(),
                None => return Err(CKR_GENERAL_ERROR)?,
            },
        };
        if !constant_time_eq(&computed, sig) {
            return Err(CKR_SIGNATURE_INVALID)?;
        }
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
        self.fips_approval.approval()
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
        Verify::verify_final(self, signature)
    }

    fn verify_update(&mut self, data: &[u8]) -> Result<()> {
        self.update(data)
    }

    fn verify_final(&mut self, signature: &[u8]) -> Result<()> {
        self.finalize_ver(Some(signature))
    }

    fn signature_len(&self) -> Result<usize> {
        Ok(self.maclen)
    }
}

/// Implements the VerifySignature interface for the AES CMAC operation
///
/// All methods call the internal methods for computation, and then compare
/// the result with the signature stashed by the init function
impl VerifySignature for AesCmacOperation {
    fn verify(&mut self, data: &[u8]) -> Result<()> {
        self.begin()?;
        if data.len() > 0 {
            self.update(data)?;
        }
        VerifySignature::verify_final(self)
    }

    fn verify_update(&mut self, data: &[u8]) -> Result<()> {
        self.update(data)
    }

    fn verify_final(&mut self) -> Result<()> {
        self.finalize_ver(None)
    }
}

/// The AES MAC operation object
///
/// This object is used to hold data for any AES MAC operation
#[derive(Debug)]
pub struct AesMacOperation {
    /// The specific MAC mechanism being used.
    mech: CK_MECHANISM_TYPE,
    /// Flag indicating if the operation has been finalized.
    finalized: bool,
    /// Flag indicating if the operation is in progress (update called).
    in_use: bool,
    /// Buffer to hold one full block of data, will be padded
    padbuf: [u8; AES_BLOCK_SIZE],
    /// Size of the data stiore in the padbuf at any give time
    padlen: usize,
    /// Temporary buffer to hold the output until the last block is returned
    macbuf: [u8; AES_BLOCK_SIZE],
    /// Size of the requested MAC output
    maclen: usize,
    /// Internal encryption operation
    op: AesOperation,
    /// FIPS approval status for the operation.
    #[cfg(feature = "fips")]
    fips_approval: FipsApproval,
    /// Optional storage for signatures, used when the signature to verify
    /// is provided at initialization
    signature: Option<Vec<u8>>,
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
            mechs.add_mechanism(*ckm, &(*AES_MECHS)[4]);
        }
    }

    /// Initializes and returns a MAC operation
    pub fn init(
        mech: &CK_MECHANISM,
        key: &Object,
        signature: Option<&[u8]>,
    ) -> Result<AesMacOperation> {
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
            fips_approval: FipsApproval::init(),
            signature: match signature {
                Some(s) => {
                    if s.len() != maclen {
                        return Err(CKR_SIGNATURE_LEN_RANGE)?;
                    }
                    Some(s.to_vec())
                }
                None => None,
            },
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
            if self.op.fips_approved().is_some_and(|b| b == false) {
                self.fips_approval.set(false);
            }
            self.fips_approval.finalize();
        }
        Ok(())
    }

    /// Finalizes the MAC computation and checks the signature
    fn finalize_ver(&mut self, signature: Option<&[u8]>) -> Result<()> {
        let mut computed = vec![0u8; self.maclen];
        self.finalize(computed.as_mut_slice())?;

        let sig = match signature {
            Some(sig) => sig,
            None => match &self.signature {
                Some(sig) => sig.as_slice(),
                None => return Err(CKR_GENERAL_ERROR)?,
            },
        };
        if !constant_time_eq(&computed, sig) {
            return Err(CKR_SIGNATURE_INVALID)?;
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
        self.fips_approval.approval()
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
        Verify::verify_final(self, signature)
    }

    fn verify_update(&mut self, data: &[u8]) -> Result<()> {
        self.update(data)
    }

    fn verify_final(&mut self, signature: &[u8]) -> Result<()> {
        self.finalize_ver(Some(signature))
    }

    fn signature_len(&self) -> Result<usize> {
        Ok(self.maclen)
    }
}

/// Implements the VerifySignature interface for the AES MAC operation
///
/// All methods call the internal methods for computation, and then compare
/// the result with the signature stashed by the init function
impl VerifySignature for AesMacOperation {
    fn verify(&mut self, data: &[u8]) -> Result<()> {
        self.begin()?;
        self.update(data)?;
        VerifySignature::verify_final(self)
    }

    fn verify_update(&mut self, data: &[u8]) -> Result<()> {
        self.update(data)
    }

    fn verify_final(&mut self) -> Result<()> {
        self.finalize_ver(None)
    }
}
