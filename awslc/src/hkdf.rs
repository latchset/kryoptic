// HMAC-based Key Derivation Function (HKDF, RFC 5869), wrapping AWS-LC's
// classic HKDF/HKDF_extract/HKDF_expand API.

use crate::cipher::zeromem;
use crate::digest::{digest_alg_to_md, DigestAlg};
use crate::error::{Error, ErrorKind};
use crate::ffi;

/// AWS-LC's own documented maximum output size for `HKDF_extract` --
/// **not** any specific digest's own output size. The caller's buffer
/// must always be this large; `HKDF_extract` does not validate the
/// buffer against the digest in use, only against this fixed maximum.
/// Confirmed by triggering a real buffer overflow with an undersized
/// (digest-size) buffer during this crate's research -- see the design
/// spec for the full account. Do not "optimize" this down to a
/// digest-specific size.
const EVP_MAX_MD_SIZE: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HkdfMode {
    ExtractOnly,
    ExpandOnly,
    ExtractAndExpand,
}

pub struct HkdfDerive<'a> {
    digest: DigestAlg,
    mode: HkdfMode,
    key: &'a [u8],
    salt: Option<&'a [u8]>,
    info: Option<&'a [u8]>,
}

impl<'a> HkdfDerive<'a> {
    pub fn new(digest: DigestAlg) -> Result<HkdfDerive<'a>, Error> {
        Ok(HkdfDerive {
            digest,
            mode: HkdfMode::ExtractAndExpand,
            key: &[],
            salt: None,
            info: None,
        })
    }

    pub fn set_mode(&mut self, mode: HkdfMode) {
        self.mode = mode;
    }
    pub fn set_key(&mut self, key: &'a [u8]) {
        self.key = key;
    }
    pub fn set_salt(&mut self, salt: &'a [u8]) {
        self.salt = Some(salt);
    }
    pub fn set_info(&mut self, info: &'a [u8]) {
        self.info = Some(info);
    }

    /// Derives into `out`, whose length selects the output size for
    /// `ExpandOnly`/`ExtractAndExpand` modes. For `ExtractOnly`, `out`
    /// must be exactly the digest's own output length (the caller --
    /// `src/awslc/hkdf.rs` -- is responsible for enforcing this via
    /// `CK_HKDF_PARAMS`/`common_derive_key_object`'s size logic, mirroring
    /// the reference's own `HkdfMode::ExtractOnly && keysize !=
    /// self.prflen` check; this function itself just derives into
    /// whatever length `out` already is).
    pub fn derive(&self, out: &mut [u8]) -> Result<(), Error> {
        let md = digest_alg_to_md(self.digest);
        let salt = self.salt.unwrap_or(&[]);
        let info = self.info.unwrap_or(&[]);

        match self.mode {
            HkdfMode::ExtractAndExpand => {
                let ret = unsafe {
                    ffi::HKDF(
                        out.as_mut_ptr(),
                        out.len(),
                        md,
                        self.key.as_ptr(),
                        self.key.len(),
                        salt.as_ptr(),
                        salt.len(),
                        info.as_ptr(),
                        info.len(),
                    )
                };
                if ret != 1 {
                    return Err(Error::new(ErrorKind::BackendError));
                }
            }
            HkdfMode::ExtractOnly => {
                let mut buf = [0u8; EVP_MAX_MD_SIZE];
                let mut buf_len: usize = 0;
                let ret = unsafe {
                    ffi::HKDF_extract(
                        buf.as_mut_ptr(),
                        &mut buf_len,
                        md,
                        self.key.as_ptr(),
                        self.key.len(),
                        salt.as_ptr(),
                        salt.len(),
                    )
                };
                if ret != 1 {
                    zeromem(&mut buf);
                    return Err(Error::new(ErrorKind::BackendError));
                }
                if buf_len != out.len() {
                    // Caller (src/awslc/hkdf.rs) is expected to have
                    // already sized `out` to the digest's own output
                    // length for ExtractOnly mode; a mismatch here means
                    // that invariant was violated upstream.
                    zeromem(&mut buf);
                    return Err(Error::new(ErrorKind::WrapperError));
                }
                out.copy_from_slice(&buf[..buf_len]);
                zeromem(&mut buf);
            }
            HkdfMode::ExpandOnly => {
                let ret = unsafe {
                    ffi::HKDF_expand(
                        out.as_mut_ptr(),
                        out.len(),
                        md,
                        self.key.as_ptr(),
                        self.key.len(),
                        info.as_ptr(),
                        info.len(),
                    )
                };
                if ret != 1 {
                    return Err(Error::new(ErrorKind::BackendError));
                }
            }
        }
        Ok(())
    }
}

impl std::fmt::Debug for HkdfDerive<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HkdfDerive")
            .field("digest", &self.digest)
            .field("mode", &self.mode)
            .field("key", &"[redacted]")
            .field("salt", &self.salt.map(|_| "[redacted]"))
            .field("info", &self.info.map(|_| "[redacted]"))
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 5869 Test Case 1 (SHA-256)
    const IKM: [u8; 22] = [0x0b; 22];
    const SALT: [u8; 13] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
        0x0c,
    ];
    const INFO: [u8; 10] =
        [0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9];
    const EXPECTED_PRK: [u8; 32] = [
        0x07, 0x77, 0x09, 0x36, 0x2c, 0x2e, 0x32, 0xdf, 0x0d, 0xdc, 0x3f, 0x0d,
        0xc4, 0x7b, 0xba, 0x63, 0x90, 0xb6, 0xc7, 0x3b, 0xb5, 0x0f, 0x9c, 0x31,
        0x22, 0xec, 0x84, 0x4a, 0xd7, 0xc2, 0xb3, 0xe5,
    ];
    const EXPECTED_OKM: [u8; 42] = [
        0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a, 0x90, 0x43, 0x4f, 0x64,
        0xd0, 0x36, 0x2f, 0x2a, 0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c,
        0x5d, 0xb0, 0x2d, 0x56, 0xec, 0xc4, 0xc5, 0xbf, 0x34, 0x00, 0x72, 0x08,
        0xd5, 0xb8, 0x87, 0x18, 0x58, 0x65,
    ];

    #[test]
    fn extract_and_expand_matches_rfc5869_test_case_1() {
        let mut d = HkdfDerive::new(DigestAlg::Sha2_256).unwrap();
        d.set_mode(HkdfMode::ExtractAndExpand);
        d.set_key(&IKM);
        d.set_salt(&SALT);
        d.set_info(&INFO);
        let mut okm = [0u8; 42];
        d.derive(&mut okm).unwrap();
        assert_eq!(okm, EXPECTED_OKM);
    }

    #[test]
    fn extract_only_matches_rfc5869_test_case_1() {
        let mut d = HkdfDerive::new(DigestAlg::Sha2_256).unwrap();
        d.set_mode(HkdfMode::ExtractOnly);
        d.set_key(&IKM);
        d.set_salt(&SALT);
        let mut prk = [0u8; 32];
        d.derive(&mut prk).unwrap();
        assert_eq!(prk, EXPECTED_PRK);
    }

    #[test]
    fn expand_only_matches_rfc5869_test_case_1() {
        let mut d = HkdfDerive::new(DigestAlg::Sha2_256).unwrap();
        d.set_mode(HkdfMode::ExpandOnly);
        d.set_key(&EXPECTED_PRK);
        d.set_info(&INFO);
        let mut okm = [0u8; 42];
        d.derive(&mut okm).unwrap();
        assert_eq!(okm, EXPECTED_OKM);
    }

    #[test]
    fn extract_then_expand_equals_one_shot() {
        let mut extractor = HkdfDerive::new(DigestAlg::Sha2_256).unwrap();
        extractor.set_mode(HkdfMode::ExtractOnly);
        extractor.set_key(&IKM);
        extractor.set_salt(&SALT);
        let mut prk = [0u8; 32];
        extractor.derive(&mut prk).unwrap();

        let mut expander = HkdfDerive::new(DigestAlg::Sha2_256).unwrap();
        expander.set_mode(HkdfMode::ExpandOnly);
        expander.set_key(&prk);
        expander.set_info(&INFO);
        let mut okm = [0u8; 42];
        expander.derive(&mut okm).unwrap();

        assert_eq!(okm, EXPECTED_OKM);
    }

    #[test]
    fn no_salt_defaults_to_empty_not_error() {
        // RFC 5869: salt is optional; HKDF treats a missing salt as a
        // zero-length byte string, not an error.
        let mut d = HkdfDerive::new(DigestAlg::Sha2_256).unwrap();
        d.set_mode(HkdfMode::ExtractAndExpand);
        d.set_key(&IKM);
        d.set_info(&INFO);
        let mut okm = [0u8; 42];
        assert!(d.derive(&mut okm).is_ok());
    }

    #[test]
    fn different_output_lengths_produce_consistent_prefixes() {
        // HKDF-Expand is a stream construction: a longer output's first
        // N bytes must equal a shorter output's N bytes, for the same
        // inputs.
        let mut short = HkdfDerive::new(DigestAlg::Sha2_256).unwrap();
        short.set_mode(HkdfMode::ExtractAndExpand);
        short.set_key(&IKM);
        short.set_salt(&SALT);
        short.set_info(&INFO);
        let mut short_out = [0u8; 16];
        short.derive(&mut short_out).unwrap();

        assert_eq!(&short_out[..], &EXPECTED_OKM[..16]);
    }
}
