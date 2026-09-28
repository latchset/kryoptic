use crate::digest::{digest_alg_to_md, DigestAlg};
use crate::error::{Error, ErrorKind};
use crate::ffi;

/// Computes PBKDF2-HMAC via AWS-LC's `PKCS5_PBKDF2_HMAC`, writing
/// `out_key.len()` bytes of derived key material.
pub fn pbkdf2(
    password: &[u8],
    salt: &[u8],
    iterations: u32,
    digest: DigestAlg,
    out_key: &mut [u8],
) -> Result<(), Error> {
    let md = digest_alg_to_md(digest);
    let ret = unsafe {
        ffi::PKCS5_PBKDF2_HMAC(
            password.as_ptr() as *const std::os::raw::c_char,
            password.len(),
            salt.as_ptr(),
            salt.len(),
            iterations,
            md,
            out_key.len(),
            out_key.as_mut_ptr(),
        )
    };
    if ret != 1 {
        return Err(Error::new(ErrorKind::BackendError));
    }
    Ok(())
}
