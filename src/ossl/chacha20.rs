// Copyright 2026 Alexandre Laroche
// See LICENSE.txt file for terms

//! This module implements access to the OpenSSL implementation of ChaCha20
//! and ChaCha20-Poly1305, as defined in
//! [RFC 8439](https://www.rfc-editor.org/rfc/rfc8439): _ChaCha20 and
//! Poly1305 for IETF Protocols_.

use crate::chacha20::*;
use crate::error;
use crate::error::Result;
use crate::mechanism::*;
use crate::misc::{bytes_to_slice, bytes_to_slice_mut, bytes_to_vec, zeromem};
use crate::object::Object;
use crate::ossl::common::osslctx;
use crate::pkcs11::*;

use ossl::cipher::{AeadParams, EncAlg, OsslCipher};
use ossl::OsslSecret;

/// IETF ChaCha20 nonce size (96 bits) -- the layout OpenSSL's "ChaCha20"
/// and "ChaCha20-Poly1305" ciphers expect. PKCS#11 v3.0's alternative,
/// original (64-bit-nonce/64-bit-counter) layout is not supported.
const CHACHA20_NONCE_SIZE: usize = 12;
/// IETF ChaCha20 block-counter size (32 bits).
const CHACHA20_COUNTER_SIZE: usize = 4;
/// Poly1305 tag size (128 bits), fixed by RFC 8439.
const POLY1305_TAG_SIZE: usize = 16;

/// Convenience function to cast mechanism parameters passed as separate
/// pointer/length variables into the structure they represent.
///
/// A length check on len is performed to validate that the correct
/// parameter structure is being casted. No other validation is performed,
/// this is an UNSAFE operation that requires further content validation.
unsafe fn cast_params<T: Copy + Clone>(
    ptr: CK_VOID_PTR,
    len: CK_ULONG,
) -> Result<T> {
    let Ok(len) = usize::try_from(len) else {
        return Err(CKR_ARGUMENTS_BAD)?;
    };
    if len != std::mem::size_of::<T>() {
        return Err(CKR_ARGUMENTS_BAD)?;
    }
    Ok(unsafe { std::ptr::read_unaligned(ptr as *const T) })
}

/// Extracts the raw key bytes from a PKCS#11 `Object` into a ChaCha20 key.
/// Validates the key length.
fn object_to_raw_key(key: &Object) -> Result<OsslSecret> {
    let val = key.get_attr_as_bytes(CKA_VALUE)?;
    if val.len() != CHACHA20_KEY_SIZE {
        return Err(CKR_KEY_INDIGESTIBLE)?;
    }
    Ok(OsslSecret::from_slice(&val))
}

/// Parameters for the active ChaCha20 / ChaCha20-Poly1305 operation.
#[derive(Debug)]
struct ChaChaParams {
    /// The IV passed to OpenSSL: 16 bytes (4-byte block counter || 12-byte
    /// nonce) for plain ChaCha20, or 12 bytes (the nonce alone) for
    /// ChaCha20-Poly1305, whose counter always starts at 1 internally.
    iv: Vec<u8>,
    /// Additional Authenticated Data, ChaCha20-Poly1305 only.
    aad: Vec<u8>,
}

/// Parses the PKCS#11 mechanism parameters (`CK_MECHANISM`) and initializes
/// a `ChaChaParams` struct based on the specific mechanism type: either
/// `CK_CHACHA20_PARAMS` (`CKM_CHACHA20`) or
/// `CK_SALSA20_CHACHA20_POLY1305_PARAMS` (`CKM_CHACHA20_POLY1305`).
fn init_params(mech: &CK_MECHANISM) -> Result<ChaChaParams> {
    match mech.mechanism {
        CKM_CHACHA20 => {
            let params = mech.get_parameters::<CK_CHACHA20_PARAMS>()?;
            if params.blockCounterBits != 32 || params.ulNonceBits != 96 {
                return Err(CKR_MECHANISM_PARAM_INVALID)?;
            }
            if params.pBlockCounter.is_null() || params.pNonce.is_null() {
                return Err(CKR_MECHANISM_PARAM_INVALID)?;
            }
            let mut iv =
                bytes_to_vec(params.pBlockCounter, CHACHA20_COUNTER_SIZE);
            iv.extend_from_slice(&bytes_to_vec(
                params.pNonce,
                CHACHA20_NONCE_SIZE,
            ));
            Ok(ChaChaParams {
                iv: iv,
                aad: Vec::new(),
            })
        }
        CKM_CHACHA20_POLY1305 => {
            let params =
                mech.get_parameters::<CK_SALSA20_CHACHA20_POLY1305_PARAMS>()?;
            if params.pNonce.is_null()
                || usize::try_from(params.ulNonceLen)? != CHACHA20_NONCE_SIZE
            {
                return Err(CKR_MECHANISM_PARAM_INVALID)?;
            }
            if params.ulAADLen > 0 && params.pAAD.is_null() {
                return Err(CKR_MECHANISM_PARAM_INVALID)?;
            }
            Ok(ChaChaParams {
                iv: bytes_to_vec(params.pNonce, CHACHA20_NONCE_SIZE),
                aad: bytes_to_vec(
                    params.pAAD,
                    usize::try_from(params.ulAADLen)?,
                ),
            })
        }
        _ => Err(CKR_MECHANISM_INVALID)?,
    }
}

/// Maps a PKCS#11 mechanism type to the `ossl` crate's cipher selector.
fn get_cipher(mech: CK_MECHANISM_TYPE) -> Result<EncAlg> {
    match mech {
        CKM_CHACHA20 => Ok(EncAlg::ChaCha20),
        CKM_CHACHA20_POLY1305 => Ok(EncAlg::ChaCha20Poly1305),
        _ => Err(CKR_MECHANISM_INVALID)?,
    }
}

/// A ChaCha20 or ChaCha20-Poly1305 Encryption/Decryption Operation
#[derive(Debug)]
pub struct ChaChaOperation {
    /// The specific mechanism being used (`CKM_CHACHA20` or
    /// `CKM_CHACHA20_POLY1305`).
    mech: CK_MECHANISM_TYPE,
    /// The operation type flags (`CKF_ENCRYPT`, `CKF_MESSAGE_ENCRYPT`,
    /// etc.), distinguishing classic from message-mode operations that
    /// share this same struct.
    op: CK_FLAGS,
    /// The wrapped ChaCha20 key. Retained (unlike the classic-only path,
    /// which can discard it once `ctx` is built) because message-mode
    /// rebuilds `ctx` fresh for every message via
    /// [ChaChaOperation::msg_encrypt_new]/[msg_decrypt_new], each with its
    /// own nonce, while reusing the same key across the whole session.
    key: OsslSecret,
    /// Flag indicating if the operation has been finalized.
    finalized: bool,
    /// Flag indicating if the operation is in progress (update called).
    in_use: bool,
    /// The underlying ossl cipher context. `None` between
    /// `msg_encrypt_init`/`msg_decrypt_init` and the first
    /// `msg_encrypt_begin`/`msg_decrypt_begin` of a message-mode session.
    ctx: Option<OsslCipher>,
    /// Accumulates the tail of the ciphertext during multi-part
    /// ChaCha20-Poly1305 decryption: the tag has a fixed length but its
    /// position is only known once no more data follows, since it is
    /// appended to the end of the ciphertext.
    buffer: Vec<u8>,
}

impl Drop for ChaChaOperation {
    fn drop(&mut self) {
        zeromem(self.buffer.as_mut_slice());
    }
}

impl ChaChaOperation {
    /// Helper function to register the ChaCha20 mechanisms
    pub fn register_mechanisms(mechs: &mut Mechanisms) {
        mechs.add_mechanism(CKM_CHACHA20, &(*CHACHA20_MECHS)[0]);
        mechs.add_mechanism(CKM_CHACHA20_POLY1305, &(*CHACHA20_MECHS)[1]);
        mechs.add_mechanism(CKM_CHACHA20_KEY_GEN, &(*CHACHA20_MECHS)[2]);
    }

    /// Encryption/Decryption Initialization helper
    fn cipher_initialize(
        mech: CK_MECHANISM_TYPE,
        params: &ChaChaParams,
        key: &[u8],
        enc: bool,
    ) -> Result<OsslCipher> {
        Ok(OsslCipher::new(
            osslctx(),
            get_cipher(mech)?,
            enc,
            OsslSecret::from_slice(key),
            Some(params.iv.clone()),
            match mech {
                CKM_CHACHA20_POLY1305 => Some(AeadParams::new(
                    if params.aad.len() > 0 {
                        Some(params.aad.clone())
                    } else {
                        None
                    },
                    POLY1305_TAG_SIZE,
                    0,
                )),
                _ => None,
            },
        )?)
    }

    /// Instantiates a new Encryption ChaCha20/ChaCha20-Poly1305 Operation
    pub fn encrypt_new(
        mech: &CK_MECHANISM,
        key: &Object,
    ) -> Result<ChaChaOperation> {
        let params = init_params(mech)?;
        let chachakey = object_to_raw_key(key)?;
        let ctx =
            Self::cipher_initialize(mech.mechanism, &params, &chachakey, true)?;
        Ok(ChaChaOperation {
            mech: mech.mechanism,
            op: CKF_ENCRYPT,
            key: chachakey,
            finalized: false,
            in_use: false,
            ctx: Some(ctx),
            buffer: Vec::new(),
        })
    }

    /// Instantiates a new Decryption ChaCha20/ChaCha20-Poly1305 Operation
    pub fn decrypt_new(
        mech: &CK_MECHANISM,
        key: &Object,
    ) -> Result<ChaChaOperation> {
        let params = init_params(mech)?;
        let chachakey = object_to_raw_key(key)?;
        let ctx = Self::cipher_initialize(
            mech.mechanism,
            &params,
            &chachakey,
            false,
        )?;
        Ok(ChaChaOperation {
            mech: mech.mechanism,
            op: CKF_DECRYPT,
            key: chachakey,
            finalized: false,
            in_use: false,
            ctx: Some(ctx),
            buffer: Vec::new(),
        })
    }

    /// Instantiates a new message-based Encryption Operation
    /// (`C_MessageEncryptInit`). The cipher context itself is not created
    /// until the first `msg_encrypt_begin`, since each message supplies
    /// its own nonce.
    pub fn msg_encrypt_init(
        mech: &CK_MECHANISM,
        key: &Object,
    ) -> Result<ChaChaOperation> {
        if mech.mechanism != CKM_CHACHA20_POLY1305 {
            return Err(CKR_MECHANISM_INVALID)?;
        }
        Ok(ChaChaOperation {
            mech: mech.mechanism,
            op: CKF_MESSAGE_ENCRYPT,
            key: object_to_raw_key(key)?,
            finalized: false,
            in_use: false,
            ctx: None,
            buffer: Vec::new(),
        })
    }

    /// Instantiates a new message-based Decryption Operation
    /// (`C_MessageDecryptInit`).
    pub fn msg_decrypt_init(
        mech: &CK_MECHANISM,
        key: &Object,
    ) -> Result<ChaChaOperation> {
        if mech.mechanism != CKM_CHACHA20_POLY1305 {
            return Err(CKR_MECHANISM_INVALID)?;
        }
        Ok(ChaChaOperation {
            mech: mech.mechanism,
            op: CKF_MESSAGE_DECRYPT,
            key: object_to_raw_key(key)?,
            finalized: false,
            in_use: false,
            ctx: None,
            buffer: Vec::new(),
        })
    }

    /// Parses `CK_SALSA20_CHACHA20_POLY1305_MSG_PARAMS`. Unlike
    /// `CK_GCM_MESSAGE_PARAMS`/`CK_CCM_MESSAGE_PARAMS`, this struct has no
    /// generator field -- the caller always supplies the nonce -- and
    /// carries the tag out-of-band in `pTag` (never appended to the
    /// ciphertext, unlike the classic, non-message path).
    ///
    /// Only the fields needed by the caller are read here: the nonce (used
    /// by `msg_encrypt_new`/`msg_decrypt_new` to (re)initialize `ctx`) or
    /// the tag pointer (used by `msg_encrypt_final`/`msg_decrypt_final`),
    /// never both -- so this returns the whole parsed struct and leaves it
    /// to the caller to use only the field(s) valid for that call. Per
    /// PKCS#11 semantics the pointers inside are valid only for the
    /// duration of the current call and must not be retained afterward.
    fn parse_msg_params(
        parameter: CK_VOID_PTR,
        parameter_len: CK_ULONG,
    ) -> Result<CK_SALSA20_CHACHA20_POLY1305_MSG_PARAMS> {
        let params = unsafe {
            cast_params::<CK_SALSA20_CHACHA20_POLY1305_MSG_PARAMS>(
                parameter,
                parameter_len,
            )
        }?;
        if params.pNonce.is_null()
            || usize::try_from(params.ulNonceLen)? != CHACHA20_NONCE_SIZE
        {
            return Err(CKR_MECHANISM_PARAM_INVALID)?;
        }
        if params.pTag.is_null() {
            return Err(CKR_MECHANISM_PARAM_INVALID)?;
        }
        Ok(params)
    }

    /// Initializes a new message-based encryption, building `ctx` fresh
    /// from this message's nonce and AAD.
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

        let params = Self::parse_msg_params(parameter, parameter_len)?;
        let chacha_params = ChaChaParams {
            iv: bytes_to_vec(params.pNonce, CHACHA20_NONCE_SIZE),
            aad: aad.to_vec(),
        };

        self.ctx = Some(Self::cipher_initialize(
            self.mech,
            &chacha_params,
            &self.key,
            true,
        )?);
        self.finalized = false;
        self.in_use = true;
        Ok(())
    }

    /// Initializes a new message-based decryption, building `ctx` fresh
    /// from this message's nonce and AAD.
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

        let params = Self::parse_msg_params(parameter, parameter_len)?;
        let chacha_params = ChaChaParams {
            iv: bytes_to_vec(params.pNonce, CHACHA20_NONCE_SIZE),
            aad: aad.to_vec(),
        };

        self.ctx = Some(Self::cipher_initialize(
            self.mech,
            &chacha_params,
            &self.key,
            false,
        )?);
        self.finalized = false;
        self.in_use = true;
        Ok(())
    }

    fn op_err(&mut self, err: CK_RV) -> error::Error {
        self.finalized = true;
        error::Error::ck_rv(err)
    }
}

impl MechOperation for ChaChaOperation {
    fn mechanism(&self) -> Result<CK_MECHANISM_TYPE> {
        Ok(self.mech)
    }

    fn finalized(&self) -> bool {
        self.finalized
    }
}

impl Encryption for ChaChaOperation {
    /// One shot encryption implementation
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

    /// Calls the underlying OpenSSL function to encrypt the plaintext
    /// buffer provided
    fn encrypt_update(
        &mut self,
        plain: &[u8],
        cipher: &mut [u8],
    ) -> Result<usize> {
        if self.finalized {
            return Err(CKR_OPERATION_NOT_INITIALIZED)?;
        }
        self.in_use = true;

        let outlen = self.encryption_len(plain.len(), false)?;
        if cipher.len() < outlen {
            /* This is the only, non-fatal error */
            return Err(error::Error::buf_too_small(outlen));
        }

        let ctx = match &mut self.ctx {
            Some(c) => c,
            None => return Err(self.op_err(CKR_GENERAL_ERROR)),
        };

        if plain.len() == 0 {
            return Ok(0);
        }
        ctx.update(plain, cipher)
            .or_else(|_| Err(self.op_err(CKR_DEVICE_ERROR)))
    }

    /// Calls the underlying OpenSSL function to finalize the encryption
    /// operation. For `CKM_CHACHA20_POLY1305` this returns the Poly1305
    /// tag; plain `CKM_CHACHA20` has no finalization output.
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

        let outlen = match self.mech {
            CKM_CHACHA20_POLY1305 => {
                if cipher.len() < POLY1305_TAG_SIZE {
                    /* This is the only, non-fatal error */
                    return Err(error::Error::buf_too_small(POLY1305_TAG_SIZE));
                }
                let outlen = ctx.finalize(cipher)?;
                if outlen != 0 {
                    self.finalized = true;
                    return Err(CKR_DEVICE_ERROR)?;
                }
                ctx.get_tag(&mut cipher[..POLY1305_TAG_SIZE])?;
                POLY1305_TAG_SIZE
            }
            CKM_CHACHA20 => 0,
            _ => {
                self.finalized = true;
                return Err(CKR_GENERAL_ERROR)?;
            }
        };

        self.finalized = true;
        Ok(outlen)
    }

    /// Provides the expected output buffer size for the provided input
    /// plaintext length.
    fn encryption_len(&mut self, data_len: usize, _fin: bool) -> Result<usize> {
        match self.mech {
            CKM_CHACHA20 => Ok(data_len),
            CKM_CHACHA20_POLY1305 => Ok(data_len + POLY1305_TAG_SIZE),
            _ => Err(self.op_err(CKR_GENERAL_ERROR)),
        }
    }
}

impl Decryption for ChaChaOperation {
    /// One shot decryption implementation
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

    /// Calls the underlying OpenSSL function to decrypt the ciphertext
    /// buffer provided. For `CKM_CHACHA20_POLY1305`, since the Poly1305
    /// tag is appended at the end of the ciphertext and its position is
    /// only known once no more data follows, the trailing
    /// `POLY1305_TAG_SIZE` bytes seen so far are always held back in
    /// `self.buffer` until a later call (or `decrypt_final`) proves they
    /// were not the tag after all.
    fn decrypt_update(
        &mut self,
        cipher: &[u8],
        plain: &mut [u8],
    ) -> Result<usize> {
        if self.finalized {
            return Err(CKR_OPERATION_NOT_INITIALIZED)?;
        }
        self.in_use = true;

        let outlen = match self.mech {
            CKM_CHACHA20 => cipher.len(),
            CKM_CHACHA20_POLY1305 => {
                let tlen = cipher.len() + self.buffer.len();
                if tlen > POLY1305_TAG_SIZE {
                    tlen - POLY1305_TAG_SIZE
                } else {
                    0
                }
            }
            _ => return Err(self.op_err(CKR_GENERAL_ERROR)),
        };
        if plain.len() < outlen {
            /* This is the only, non-fatal error */
            return Err(error::Error::buf_too_small(outlen));
        }

        let ctx = match &mut self.ctx {
            Some(c) => c,
            None => return Err(self.op_err(CKR_GENERAL_ERROR)),
        };

        let mut plain_offset = 0;
        let mut cipher_offset = 0;
        let mut cipher_end = cipher.len();
        match self.mech {
            CKM_CHACHA20_POLY1305 => {
                /* the tag is appended at the end of the ciphertext,
                 * but we do not know how long the ciphertext is */
                if self.buffer.len() > 0 {
                    if cipher_end > POLY1305_TAG_SIZE {
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
                        cipher_end -= POLY1305_TAG_SIZE;
                        self.buffer.extend_from_slice(&cipher[cipher_end..]);
                    } else {
                        self.buffer.extend_from_slice(cipher);
                        if self.buffer.len() > POLY1305_TAG_SIZE {
                            let buflen = self.buffer.len() - POLY1305_TAG_SIZE;
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
                } else if cipher_end > POLY1305_TAG_SIZE {
                    cipher_end -= POLY1305_TAG_SIZE;
                    self.buffer.extend_from_slice(&cipher[cipher_end..]);
                } else {
                    self.buffer.extend_from_slice(cipher);
                    /* The cipher buffer has been utilized */
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

        Ok(plain_offset)
    }

    /// Calls the underlying OpenSSL function to finalize the decryption
    /// operation. For `CKM_CHACHA20_POLY1305` this verifies the buffered
    /// Poly1305 tag and returns any trailing plaintext.
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

        let outlen = 0;
        match self.mech {
            CKM_CHACHA20_POLY1305 => {
                if self.buffer.len() != POLY1305_TAG_SIZE {
                    return Err(CKR_ENCRYPTED_DATA_LEN_RANGE)?;
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
            CKM_CHACHA20 => (),
            _ => return Err(CKR_GENERAL_ERROR)?,
        }

        Ok(outlen)
    }

    /// Provides the expected output buffer size for the provided input
    /// ciphertext length.
    fn decryption_len(&mut self, data_len: usize, fin: bool) -> Result<usize> {
        let outlen = if fin {
            match self.mech {
                CKM_CHACHA20_POLY1305 => {
                    if self.buffer.len() + data_len < POLY1305_TAG_SIZE {
                        return Err(self.op_err(CKR_ENCRYPTED_DATA_LEN_RANGE));
                    }
                    self.buffer.len() + data_len - POLY1305_TAG_SIZE
                }
                CKM_CHACHA20 => data_len,
                _ => return Err(self.op_err(CKR_GENERAL_ERROR)),
            }
        } else {
            match self.mech {
                CKM_CHACHA20_POLY1305 => {
                    if self.buffer.len() + data_len < POLY1305_TAG_SIZE {
                        0
                    } else {
                        self.buffer.len() + data_len
                    }
                }
                CKM_CHACHA20 => data_len,
                _ => return Err(self.op_err(CKR_GENERAL_ERROR)),
            }
        };
        Ok(outlen)
    }
}

impl MessageOperation for ChaChaOperation {
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

impl MsgEncryption for ChaChaOperation {
    /// One-shot message-based encryption implementation
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

    /// Begins a new message-based encryption: parses this message's nonce
    /// and AAD and (re)initializes `ctx`.
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

    /// Feeds in the next plaintext chunk of the current message. The
    /// Poly1305 tag is not part of this output -- it is written
    /// separately, into `pTag`, by `msg_encrypt_final`.
    fn msg_encrypt_next(
        &mut self,
        _param: CK_VOID_PTR,
        _paramlen: CK_ULONG,
        plain: &[u8],
        cipher: &mut [u8],
    ) -> Result<usize> {
        if self.finalized {
            return Err(CKR_OPERATION_NOT_INITIALIZED)?;
        }
        if !self.in_use {
            return Err(CKR_OPERATION_NOT_INITIALIZED)?;
        }
        if cipher.len() < plain.len() {
            /* This is the only non-fatal error */
            return Err(error::Error::buf_too_small(plain.len()));
        }

        let ctx = match &mut self.ctx {
            Some(c) => c,
            None => return Err(self.op_err(CKR_GENERAL_ERROR)),
        };

        if plain.len() == 0 {
            return Ok(0);
        }
        ctx.update(plain, cipher)
            .or_else(|_| Err(self.op_err(CKR_DEVICE_ERROR)))
    }

    /// Feeds the final plaintext chunk, then writes the Poly1305 tag into
    /// the current message's `pTag`.
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

        let params = Self::parse_msg_params(param, paramlen)?;
        let outlen = self.msg_encrypt_next(param, paramlen, plain, cipher)?;

        let ctx = match &mut self.ctx {
            Some(c) => c,
            None => return Err(self.op_err(CKR_GENERAL_ERROR)),
        };

        if !ctx.finalize(cipher).is_ok_and(|len| len == 0) {
            zeromem(cipher);
            return Err(self.op_err(CKR_DEVICE_ERROR));
        }

        let tagbuf =
            unsafe { bytes_to_slice_mut(params.pTag, POLY1305_TAG_SIZE) }?;
        if ctx.get_tag(tagbuf).is_err() {
            zeromem(cipher);
            return Err(self.op_err(CKR_DEVICE_ERROR));
        }

        self.in_use = false;
        Ok(outlen)
    }

    /// Provides the expected output buffer size. The Poly1305 tag is not
    /// included -- it goes into `pTag`, not the cipher buffer.
    fn msg_encryption_len(
        &mut self,
        data_len: usize,
        _fin: bool,
    ) -> Result<usize> {
        if self.finalized {
            return Err(CKR_OPERATION_NOT_INITIALIZED)?;
        }
        Ok(data_len)
    }
}

impl MsgDecryption for ChaChaOperation {
    /// One-shot message-based decryption implementation
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

    /// Begins a new message-based decryption: parses this message's nonce
    /// and AAD and (re)initializes `ctx`.
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

    /// Feeds in the next ciphertext chunk of the current message. The
    /// Poly1305 tag is not part of this input -- it is supplied separately,
    /// via `pTag`, to `msg_decrypt_final`.
    fn msg_decrypt_next(
        &mut self,
        _param: CK_VOID_PTR,
        _paramlen: CK_ULONG,
        cipher: &[u8],
        plain: &mut [u8],
    ) -> Result<usize> {
        if self.finalized {
            return Err(CKR_OPERATION_NOT_INITIALIZED)?;
        }
        if !self.in_use {
            return Err(CKR_OPERATION_NOT_INITIALIZED)?;
        }
        if plain.len() < cipher.len() {
            /* This is the only non-fatal error */
            return Err(error::Error::buf_too_small(cipher.len()));
        }

        let ctx = match &mut self.ctx {
            Some(c) => c,
            None => return Err(self.op_err(CKR_GENERAL_ERROR)),
        };

        if cipher.len() == 0 {
            return Ok(0);
        }
        ctx.update(cipher, plain)
            .or_else(|_| Err(self.op_err(CKR_DEVICE_ERROR)))
    }

    /// Feeds the final ciphertext chunk, sets the Poly1305 tag from this
    /// message's `pTag`, and verifies it.
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

        let params = Self::parse_msg_params(param, paramlen)?;
        let outlen = self.msg_decrypt_next(param, paramlen, cipher, plain)?;

        let tag = unsafe { bytes_to_slice(params.pTag, POLY1305_TAG_SIZE) };

        let ctx = match &mut self.ctx {
            Some(c) => c,
            None => return Err(self.op_err(CKR_GENERAL_ERROR)),
        };

        ctx.set_tag(tag).or_else(|_| {
            self.finalized = true;
            Err(CKR_DEVICE_ERROR)
        })?;

        match ctx.finalize(&mut plain[outlen..]) {
            Ok(len) => {
                if len != 0 {
                    self.finalized = true;
                    return Err(CKR_DEVICE_ERROR)?;
                }
            }
            Err(_) => {
                self.finalized = true;
                return Err(CKR_ENCRYPTED_DATA_INVALID)?;
            }
        }

        self.in_use = false;
        Ok(outlen)
    }

    /// Provides the expected output buffer size. The Poly1305 tag is not
    /// included -- it comes from `pTag`, not the cipher buffer.
    fn msg_decryption_len(
        &mut self,
        data_len: usize,
        _fin: bool,
    ) -> Result<usize> {
        if self.finalized {
            return Err(CKR_OPERATION_NOT_INITIALIZED)?;
        }
        Ok(data_len)
    }
}
