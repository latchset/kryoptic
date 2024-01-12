// Copyright 2024 Simo Sorce
// See LICENSE.txt file for terms

#[cfg(feature = "fips")]
use {super::fips, fips::*};

#[cfg(not(feature = "fips"))]
use {super::ossl, ossl::*};

use zeroize::Zeroize;

const AES_BLOCK_SIZE: usize = 16;
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

cfg_if::cfg_if! {
    if #[cfg(feature = "fips")] {
        struct AesCiphers {
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
}

impl Drop for AesOperation {
    fn drop(&mut self) {
        self.finalbuf.zeroize()
    }
}

impl AesOperation {
    fn init_params(mech: &CK_MECHANISM) -> KResult<AesParams> {
        let pad = match mech.mechanism {
            CKM_AES_CTR | CKM_AES_CBC | CKM_AES_ECB => false,
            CKM_AES_CBC_PAD => true,
            #[cfg(not(feature = "fips"))]
            CKM_AES_CFB8 | CKM_AES_CFB1 | CKM_AES_CFB128 | CKM_AES_OFB => false,
            _ => return err_rv!(CKR_MECHANISM_INVALID),
        };
        match mech.mechanism {
            CKM_AES_CTR => {
                if mech.ulParameterLen as usize
                    != ::std::mem::size_of::<CK_AES_CTR_PARAMS>()
                {
                    err_rv!(CKR_ARGUMENTS_BAD)
                } else {
                    let ctr_params =
                        mech.pParameter as *const CK_AES_CTR_PARAMS;
                    let ctrbits =
                        unsafe { (*ctr_params).ulCounterBits } as usize;
                    if ctrbits != (AES_BLOCK_SIZE * 8) {
                        /* FIXME: support arbitrary counterbits.
                         * OpenSSL CTR mode is built to handle the whole IV
                         * as a 128bit counter unconditionally, so we can
                         * only support 128 as the allowed value for now. */
                        return err_rv!(CKR_MECHANISM_PARAM_INVALID);
                    }

                    Ok(AesParams {
                        pad: pad,
                        iv: unsafe { (*ctr_params).cb.to_vec() },
                    })
                }
            }
            CKM_AES_CBC | CKM_AES_CBC_PAD => {
                if mech.ulParameterLen != 16 {
                    err_rv!(CKR_ARGUMENTS_BAD)
                } else {
                    Ok(AesParams {
                        pad: pad,
                        iv: unsafe {
                            std::slice::from_raw_parts(
                                mech.pParameter as *mut u8,
                                mech.ulParameterLen as usize,
                            )
                            .to_vec()
                        },
                    })
                }
            }
            CKM_AES_ECB => Ok(AesParams {
                pad: pad,
                iv: Vec::with_capacity(0),
            }),
            #[cfg(not(feature = "fips"))]
            CKM_AES_CFB8 | CKM_AES_CFB1 | CKM_AES_CFB128 | CKM_AES_OFB => {
                if mech.ulParameterLen != 16 {
                    err_rv!(CKR_ARGUMENTS_BAD)
                } else {
                    Ok(AesParams {
                        pad: pad,
                        iv: unsafe {
                            std::slice::from_raw_parts(
                                mech.pParameter as *mut u8,
                                mech.ulParameterLen as usize,
                            )
                            .to_vec()
                        },
                    })
                }
            }
            _ => err_rv!(CKR_MECHANISM_INVALID),
        }
    }

    fn init_cipher(
        mech: CK_MECHANISM_TYPE,
        keylen: usize,
    ) -> KResult<&'static EvpCipher> {
        Ok(match mech {
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
        })
    }

    fn wrap(
        _mech: &CK_MECHANISM,
        _wrapping_key: &Object,
        _key: &Object,
        _data: CK_BYTE_PTR,
        _data_len: CK_ULONG_PTR,
    ) -> KResult<()> {
        return err_rv!(CKR_DEVICE_ERROR);
    }

    fn unwrap(
        _mech: &CK_MECHANISM,
        _wrapping_key: &Object,
        _data: &[u8],
    ) -> KResult<Vec<u8>> {
        return err_rv!(CKR_DEVICE_ERROR);
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
        if self.in_use {
            return err_rv!(CKR_OPERATION_NOT_INITIALIZED);
        }
        if self.finalized {
            return err_rv!(CKR_OPERATION_NOT_INITIALIZED);
        }
        let clen: CK_ULONG = unsafe { *cipher_len };
        let mut outb: *mut u8 = cipher;
        let mut outl: CK_ULONG = unsafe { *cipher_len };
        self.encrypt_update(plain, outb, &mut outl)?;
        if outl > clen {
            self.finalized = true;
            return err_rv!(CKR_DEVICE_ERROR);
        }
        if !self.params.pad {
            self.finalized = true;
            unsafe { *cipher_len = outl };
            return Ok(());
        }
        let mut foutl = clen - outl;
        outb = unsafe { cipher.add(outl as usize) };
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
                EVP_EncryptInit_ex(
                    self.ctx.as_mut().unwrap().as_mut_ptr(),
                    evpcipher.as_ptr(),
                    std::ptr::null_mut(),
                    self.key.raw.as_ptr(),
                    if self.params.iv.len() != 0 {
                        self.params.iv.as_ptr()
                    } else {
                        std::ptr::null()
                    },
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
        }

        let cipher_ulen = unsafe { *cipher_len } as usize;
        let outblocks = plain.len() / self.blocksize;
        let outlen = outblocks * self.blocksize;
        if cipher.is_null() {
            unsafe {
                *cipher_len = outlen as CK_ULONG;
            }
            return Ok(());
        } else {
            if !self.params.pad && plain.len() != outlen {
                self.finalized = true;
                return err_rv!(CKR_DATA_LEN_RANGE);
            }
            if cipher_ulen < outlen {
                /* This is the only, non-fatal error */
                return err_rv!(CKR_BUFFER_TOO_SMALL);
            }
        }

        let mut outl: std::os::raw::c_int = 0;
        if unsafe {
            EVP_EncryptUpdate(
                self.ctx.as_mut().unwrap().as_mut_ptr(),
                cipher,
                &mut outl,
                plain.as_ptr(),
                plain.len() as std::os::raw::c_int,
            )
        } != 1
        {
            self.finalized = true;
            return err_rv!(CKR_DEVICE_ERROR);
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

        if !self.params.pad {
            self.finalized = true;
            return Ok(());
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

        let mut outl: std::os::raw::c_int = 0;
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
        if self.in_use {
            return err_rv!(CKR_OPERATION_NOT_INITIALIZED);
        }
        if self.finalized {
            return err_rv!(CKR_OPERATION_NOT_INITIALIZED);
        }
        let plen: CK_ULONG = unsafe { *plain_len };
        let mut outb: *mut u8 = plain;
        let mut outl: CK_ULONG = unsafe { *plain_len };
        self.decrypt_update(cipher, outb, &mut outl)?;
        if outl > plen {
            self.finalized = true;
            return err_rv!(CKR_DEVICE_ERROR);
        }
        if !self.params.pad {
            self.finalized = true;
            unsafe { *plain_len = outl };
            return Ok(());
        }
        let mut foutl = plen - outl;
        outb = unsafe { plain.add(outl as usize) };
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
                EVP_DecryptInit_ex(
                    self.ctx.as_mut().unwrap().as_mut_ptr(),
                    evpcipher.as_ptr(),
                    std::ptr::null_mut(),
                    self.key.raw.as_ptr(),
                    if self.params.iv.len() != 0 {
                        self.params.iv.as_ptr()
                    } else {
                        std::ptr::null()
                    },
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
        }

        let plain_ulen = unsafe { *plain_len } as usize;
        let outblocks = cipher.len() / self.blocksize;
        let outlen = outblocks * self.blocksize;
        if plain.is_null() {
            unsafe {
                *plain_len = outlen as CK_ULONG;
            }
            return Ok(());
        } else {
            if !self.params.pad && cipher.len() != outlen {
                self.finalized = true;
                return err_rv!(CKR_DATA_LEN_RANGE);
            }
            if plain_ulen < outlen {
                /* This is the only, non-fatal error */
                return err_rv!(CKR_BUFFER_TOO_SMALL);
            }
        }

        let mut outl: std::os::raw::c_int = 0;
        if unsafe {
            EVP_DecryptUpdate(
                self.ctx.as_mut().unwrap().as_mut_ptr(),
                plain,
                &mut outl,
                cipher.as_ptr(),
                cipher.len() as std::os::raw::c_int,
            )
        } != 1
        {
            self.finalized = true;
            return err_rv!(CKR_DEVICE_ERROR);
        }
        unsafe {
            *plain_len = outl as CK_ULONG;
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

        if !self.params.pad {
            self.finalized = true;
            return Ok(());
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

        let mut outl: std::os::raw::c_int = 0;
        if unsafe {
            EVP_DecryptFinal_ex(
                self.ctx.as_mut().unwrap().as_mut_ptr(),
                plain_buf,
                &mut outl,
            )
        } != 1
        {
            self.finalized = true;
            return err_rv!(CKR_DEVICE_ERROR);
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
