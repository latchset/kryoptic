// Copyright 2026
// See LICENSE.txt file for terms

use crate::digest::{digest_alg_to_md, DigestAlg};
use crate::error::{Error, ErrorKind};
use crate::ffi;

/// Derives keying material using AWS-LC's `KBKDF_ctr_hmac()`, which
/// implements the counter-mode construction of NIST SP 800-108 Revision 1
/// Update 1 §4.1 with a hardcoded 32-bit big-endian counter placed before
/// a single flat `info` buffer, and HMAC as the only PRF.
///
/// `KBKDF_ctr_hmac()` does not structure `info` any further, so a caller
/// wanting kryoptic's PKCS#11-level Label/Context/L semantics is
/// responsible for assembling `info` itself as
/// `Label || 0x00 (if separator used) || Context || [L] (if used)` --
/// see `crate::awslc::kbkdf`, which does so and rejects configurations
/// this primitive can't express (any counter width other than 32 bits,
/// or a CMAC PRF).
pub fn kbkdf_ctr_hmac(
    digest: DigestAlg,
    key: &[u8],
    info: &[u8],
    out: &mut [u8],
) -> Result<(), Error> {
    let md = digest_alg_to_md(digest);
    let ret = unsafe {
        ffi::KBKDF_ctr_hmac(
            out.as_mut_ptr(),
            out.len(),
            md,
            key.as_ptr(),
            key.len(),
            info.as_ptr(),
            info.len(),
        )
    };
    if ret != 1 {
        return Err(Error::new(ErrorKind::BackendError));
    }
    Ok(())
}
