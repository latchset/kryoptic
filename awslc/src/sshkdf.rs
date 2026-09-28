// Copyright 2026
// See LICENSE.txt file for terms

use crate::digest::{digest_alg_to_md, DigestAlg};
use crate::error::{Error, ErrorKind};
use crate::ffi;

/// SSH key purposes per RFC 4253 §7.2, matching the `type` byte
/// `SSHKDF()` expects (see `sshkdf.h`'s `EVP_KDF_SSHKDF_TYPE_*` constants).
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum SshKdfPurpose {
    InitialIVClientToServer,
    InitialIVServerToClient,
    EncryptionKeyClientToServer,
    EncryptionKeyServerToClient,
    IntegrityKeyClientToServer,
    IntegrityKeyServerToClient,
}

fn purpose_to_type(purpose: SshKdfPurpose) -> std::os::raw::c_char {
    (match purpose {
        SshKdfPurpose::InitialIVClientToServer => b'A',
        SshKdfPurpose::InitialIVServerToClient => b'B',
        SshKdfPurpose::EncryptionKeyClientToServer => b'C',
        SshKdfPurpose::EncryptionKeyServerToClient => b'D',
        SshKdfPurpose::IntegrityKeyClientToServer => b'E',
        SshKdfPurpose::IntegrityKeyServerToClient => b'F',
    }) as std::os::raw::c_char
}

// Declared by hand against `csrc/sshkdf_shim.c`, which
// this crate's build.rs compiles: see that file for why a shim is
// needed instead of calling `ffi::SSHKDF` directly.
unsafe extern "C" {
    fn kryoptic_awslc_sshkdf(
        evp_md: *const ffi::EVP_MD,
        key: *const u8,
        key_len: usize,
        xcghash: *const u8,
        xcghash_len: usize,
        session_id: *const u8,
        session_id_len: usize,
        type_: std::os::raw::c_char,
        out: *mut u8,
        out_len: usize,
    ) -> std::os::raw::c_int;
}

/// Derives SSH transport-layer key material via AWS-LC's `SSHKDF()`.
pub fn sshkdf(
    digest: DigestAlg,
    key: &[u8],
    exchange_hash: &[u8],
    session_id: &[u8],
    purpose: SshKdfPurpose,
    out: &mut [u8],
) -> Result<(), Error> {
    let md = digest_alg_to_md(digest);
    let ret = unsafe {
        kryoptic_awslc_sshkdf(
            md,
            key.as_ptr(),
            key.len(),
            exchange_hash.as_ptr(),
            exchange_hash.len(),
            session_id.as_ptr(),
            session_id.len(),
            purpose_to_type(purpose),
            out.as_mut_ptr(),
            out.len(),
        )
    };
    if ret != 1 {
        return Err(Error::new(ErrorKind::BackendError));
    }
    Ok(())
}
