// Message digest primitives, wrapping AWS-LC's `EVP_MD`/`EVP_MD_CTX` API.

use crate::ffi;
use std::os::raw::c_void;

use crate::error::{Error, ErrorKind};

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum DigestAlg {
    Sha1,
    Sha2_224,
    Sha2_256,
    Sha2_384,
    Sha2_512,
    Sha2_512_224,
    Sha2_512_256,
    Sha3_224,
    Sha3_256,
    Sha3_384,
    Sha3_512,
}

pub(crate) fn digest_alg_to_md(alg: DigestAlg) -> *const ffi::EVP_MD {
    unsafe {
        match alg {
            DigestAlg::Sha1 => ffi::EVP_sha1(),
            DigestAlg::Sha2_224 => ffi::EVP_sha224(),
            DigestAlg::Sha2_256 => ffi::EVP_sha256(),
            DigestAlg::Sha2_384 => ffi::EVP_sha384(),
            DigestAlg::Sha2_512 => ffi::EVP_sha512(),
            DigestAlg::Sha2_512_224 => ffi::EVP_sha512_224(),
            DigestAlg::Sha2_512_256 => ffi::EVP_sha512_256(),
            DigestAlg::Sha3_224 => ffi::EVP_sha3_224(),
            DigestAlg::Sha3_256 => ffi::EVP_sha3_256(),
            DigestAlg::Sha3_384 => ffi::EVP_sha3_384(),
            DigestAlg::Sha3_512 => ffi::EVP_sha3_512(),
        }
    }
}

#[derive(Debug)]
pub struct Digest {
    ctx: *mut ffi::EVP_MD_CTX,
    md: *const ffi::EVP_MD,
    size: usize,
}

impl Digest {
    pub fn new(alg: DigestAlg) -> Result<Digest, Error> {
        let md = digest_alg_to_md(alg);
        if md.is_null() {
            return Err(Error::new(ErrorKind::NullPtr));
        }
        let ctx = unsafe { ffi::EVP_MD_CTX_new() };
        if ctx.is_null() {
            return Err(Error::new(ErrorKind::NullPtr));
        }
        let size = unsafe { ffi::EVP_MD_size(md) };
        let mut d = Digest { ctx, md, size };
        d.reset()?;
        Ok(d)
    }

    pub fn reset(&mut self) -> Result<(), Error> {
        let ret = unsafe {
            ffi::EVP_DigestInit_ex(self.ctx, self.md, std::ptr::null_mut())
        };
        if ret != 1 {
            return Err(Error::new(ErrorKind::BackendError));
        }
        Ok(())
    }

    pub fn update(&mut self, data: &[u8]) -> Result<(), Error> {
        let ret = unsafe {
            ffi::EVP_DigestUpdate(
                self.ctx,
                data.as_ptr() as *const c_void,
                data.len(),
            )
        };
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
        let ret = unsafe {
            ffi::EVP_DigestFinal_ex(self.ctx, out.as_mut_ptr(), &mut outlen)
        };
        if ret != 1 {
            return Err(Error::new(ErrorKind::BackendError));
        }
        Ok(outlen as usize)
    }

    pub fn size(&self) -> usize {
        self.size
    }
}

impl Drop for Digest {
    fn drop(&mut self) {
        unsafe { ffi::EVP_MD_CTX_free(self.ctx) };
    }
}

// SAFETY: `Digest` exclusively owns its `*mut EVP_MD_CTX`, so Send is
// sound. Sync is technically sound too but not actually load-bearing:
// `reset`/`update`/`finalize` (the only methods that touch AWS-LC state)
// all take `&mut self` -- this type's `EVP_MD_CTX` genuinely mutates
// across calls (streaming hash state) -- so Rust's own borrow checker
// never allows two threads to call them concurrently through a shared
// `&Self` regardless of this impl; only `Send` is practically meaningful
// here (mirrors `BlockCipher`'s identical situation in `cipher.rs`).
unsafe impl Send for Digest {}
unsafe impl Sync for Digest {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_abc() {
        let mut d = Digest::new(DigestAlg::Sha2_256).unwrap();
        d.update(b"abc").unwrap();
        let mut out = [0u8; 32];
        let n = d.finalize(&mut out).unwrap();
        assert_eq!(n, 32);
        // NIST FIPS 180-4 example vector for SHA-256("abc").
        let expected = [
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40,
            0xde, 0x5d, 0xae, 0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17,
            0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
        ];
        assert_eq!(out, expected);
    }

    #[test]
    fn chunked_update_matches_single_update() {
        let mut whole = Digest::new(DigestAlg::Sha2_256).unwrap();
        whole.update(b"hello world").unwrap();
        let mut out_whole = [0u8; 32];
        whole.finalize(&mut out_whole).unwrap();

        let mut chunked = Digest::new(DigestAlg::Sha2_256).unwrap();
        chunked.update(b"hello").unwrap();
        chunked.update(b" world").unwrap();
        let mut out_chunked = [0u8; 32];
        chunked.finalize(&mut out_chunked).unwrap();

        assert_eq!(out_whole, out_chunked);
    }

    #[test]
    fn size_matches_algorithm() {
        assert_eq!(Digest::new(DigestAlg::Sha1).unwrap().size(), 20);
        assert_eq!(Digest::new(DigestAlg::Sha2_256).unwrap().size(), 32);
        assert_eq!(Digest::new(DigestAlg::Sha2_512).unwrap().size(), 64);
    }
}
