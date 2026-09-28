// HMAC, wrapping AWS-LC's `HMAC_CTX` API.

use crate::digest::{digest_alg_to_md, DigestAlg};
use crate::error::{Error, ErrorKind};
use crate::ffi;

#[derive(Debug)]
pub struct Hmac {
    ctx: *mut ffi::HMAC_CTX,
    size: usize,
}

impl Hmac {
    pub fn new(alg: DigestAlg, key: &[u8]) -> Result<Hmac, Error> {
        let md = digest_alg_to_md(alg);
        if md.is_null() {
            return Err(Error::new(ErrorKind::NullPtr));
        }
        let ctx = unsafe { ffi::HMAC_CTX_new() };
        if ctx.is_null() {
            return Err(Error::new(ErrorKind::NullPtr));
        }
        let ret = unsafe {
            ffi::HMAC_Init_ex(
                ctx,
                key.as_ptr() as *const std::os::raw::c_void,
                key.len(),
                md,
                std::ptr::null_mut(),
            )
        };
        if ret != 1 {
            unsafe { ffi::HMAC_CTX_free(ctx) };
            return Err(Error::new(ErrorKind::BackendError));
        }
        let size = unsafe { ffi::HMAC_size(ctx) };
        Ok(Hmac { ctx, size })
    }

    pub fn update(&mut self, data: &[u8]) -> Result<(), Error> {
        let ret =
            unsafe { ffi::HMAC_Update(self.ctx, data.as_ptr(), data.len()) };
        if ret != 1 {
            return Err(Error::new(ErrorKind::BackendError));
        }
        Ok(())
    }

    pub fn finalize(&mut self, out: &mut [u8]) -> Result<usize, Error> {
        if out.len() < self.size {
            return Err(Error::new(ErrorKind::BufferSize));
        }
        let mut outlen: u32 = 0;
        let ret =
            unsafe { ffi::HMAC_Final(self.ctx, out.as_mut_ptr(), &mut outlen) };
        if ret != 1 {
            return Err(Error::new(ErrorKind::BackendError));
        }
        Ok(outlen as usize)
    }

    pub fn size(&self) -> usize {
        self.size
    }

    /// One-shot HMAC, used by the HMAC_DRBG implementation.
    pub fn mac(
        alg: DigestAlg,
        key: &[u8],
        data: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let mut h = Hmac::new(alg, key)?;
        h.update(data)?;
        let mut out = vec![0u8; h.size()];
        let n = h.finalize(&mut out)?;
        out.truncate(n);
        Ok(out)
    }
}

impl Drop for Hmac {
    fn drop(&mut self) {
        unsafe { ffi::HMAC_CTX_free(self.ctx) };
    }
}

// SAFETY: `Hmac` exclusively owns its `*mut HMAC_CTX`, so Send is sound.
// Sync is technically sound too but not actually load-bearing:
// `update`/`finalize` both take `&mut self` -- this type's `HMAC_CTX`
// genuinely mutates across calls (streaming MAC state) -- so Rust's own
// borrow checker never allows concurrent calls through a shared `&Self`
// regardless of this impl; only `Send` is practically meaningful here
// (mirrors `BlockCipher`'s/`Digest`'s identical situation).
unsafe impl Send for Hmac {}
unsafe impl Sync for Hmac {}

fn aes_cbc_cipher_for_key(
    key_len: usize,
) -> Result<*const ffi::EVP_CIPHER, Error> {
    let cipher = unsafe {
        match key_len {
            16 => ffi::EVP_aes_128_cbc(),
            24 => ffi::EVP_aes_192_cbc(),
            32 => ffi::EVP_aes_256_cbc(),
            _ => return Err(Error::new(ErrorKind::WrapperError)),
        }
    };
    if cipher.is_null() {
        return Err(Error::new(ErrorKind::NullPtr));
    }
    Ok(cipher)
}

#[derive(Debug)]
pub struct Cmac {
    ctx: *mut ffi::CMAC_CTX,
}

impl Cmac {
    pub fn new(key: &[u8]) -> Result<Cmac, Error> {
        let cipher = aes_cbc_cipher_for_key(key.len())?;
        let ctx = unsafe { ffi::CMAC_CTX_new() };
        if ctx.is_null() {
            return Err(Error::new(ErrorKind::NullPtr));
        }
        let ret = unsafe {
            ffi::CMAC_Init(
                ctx,
                key.as_ptr() as *const std::os::raw::c_void,
                key.len(),
                cipher,
                std::ptr::null_mut(),
            )
        };
        if ret != 1 {
            unsafe { ffi::CMAC_CTX_free(ctx) };
            return Err(Error::new(ErrorKind::BackendError));
        }
        Ok(Cmac { ctx })
    }

    pub fn update(&mut self, data: &[u8]) -> Result<(), Error> {
        let ret =
            unsafe { ffi::CMAC_Update(self.ctx, data.as_ptr(), data.len()) };
        if ret != 1 {
            return Err(Error::new(ErrorKind::BackendError));
        }
        Ok(())
    }

    pub fn finalize(&mut self, out: &mut [u8]) -> Result<usize, Error> {
        if out.len() < 16 {
            return Err(Error::new(ErrorKind::BufferSize));
        }
        let mut outl: usize = 0;
        let ret =
            unsafe { ffi::CMAC_Final(self.ctx, out.as_mut_ptr(), &mut outl) };
        if ret != 1 {
            return Err(Error::new(ErrorKind::BackendError));
        }
        Ok(outl)
    }

    pub fn size(&self) -> usize {
        16 // AES block size; CMAC output is always one block.
    }
}

impl Drop for Cmac {
    fn drop(&mut self) {
        unsafe { ffi::CMAC_CTX_free(self.ctx) };
    }
}

// SAFETY: same reasoning as `Hmac` above -- `Cmac` exclusively owns its
// `*mut CMAC_CTX` (Send is sound), and `update`/`finalize` both take
// `&mut self`, so Sync is sound but not load-bearing (the borrow checker
// already prevents concurrent `&mut self` calls regardless).
unsafe impl Send for Cmac {}
unsafe impl Sync for Cmac {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::digest::DigestAlg;

    #[test]
    fn hmac_sha256_rfc4231_case1() {
        // RFC 4231 Test Case 1.
        let key = [0x0bu8; 20];
        let data = b"Hi There";
        let mac = Hmac::mac(DigestAlg::Sha2_256, &key, data).unwrap();
        let expected = [
            0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53, 0x5c, 0xa8, 0xaf,
            0xce, 0xaf, 0x0b, 0xf1, 0x2b, 0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83,
            0x3d, 0xa7, 0x26, 0xe9, 0x37, 0x6c, 0x2e, 0x32, 0xcf, 0xf7,
        ];
        assert_eq!(mac, expected);
    }

    #[test]
    fn incremental_update_matches_one_shot() {
        let key = b"secret-key";
        let one_shot =
            Hmac::mac(DigestAlg::Sha2_256, key, b"hello world").unwrap();

        let mut h = Hmac::new(DigestAlg::Sha2_256, key).unwrap();
        h.update(b"hello").unwrap();
        h.update(b" world").unwrap();
        let mut out = vec![0u8; h.size()];
        h.finalize(&mut out).unwrap();

        assert_eq!(one_shot, out);
    }

    #[test]
    fn cmac_aes128_rfc4493_example1() {
        // RFC 4493 Section 4, Example 1: AES-128 CMAC of the empty message.
        let key = [
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15,
            0x88, 0x09, 0xcf, 0x4f, 0x3c,
        ];
        let expected = [
            0xbb, 0x1d, 0x69, 0x29, 0xe9, 0x59, 0x37, 0x28, 0x7f, 0xa3, 0x7d,
            0x12, 0x9b, 0x75, 0x67, 0x46,
        ];
        let mut cmac = Cmac::new(&key).unwrap();
        let mut out = [0u8; 16];
        cmac.finalize(&mut out).unwrap();
        assert_eq!(out, expected);
    }
}
