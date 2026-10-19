// Copyright 2026 Simo Sorce
// See LICENSE.txt file for terms

//! Dual-function cryptographic functions
//!
//! This module contains the implementation of dual-function operations

use crate::error::Result;
use crate::fns::digest::internal_digest_update;
use crate::fns::encryption::{
    internal_decrypt_update, internal_encrypt_update,
};
use crate::fns::log_debug;
use crate::fns::signing::{internal_sign_update, internal_verify_update};
use crate::mechanism::{Decryption, Digest, Encryption, Sign, Verify};
use crate::pkcs11::*;
use crate::STATE;

/// Implementation of C_DigestEncryptUpdate function
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203347](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203347)

#[inline(always)]
fn digest_encrypt_update(
    s_handle: CK_SESSION_HANDLE,
    part: CK_BYTE_PTR,
    part_len: CK_ULONG,
    encrypted_part: CK_BYTE_PTR,
    pul_encrypted_part_len: CK_ULONG_PTR,
) -> Result<()> {
    let rstate = STATE.rlock()?;
    let mut session = rstate.get_session_mut(s_handle)?;

    let res = session
        .check_op::<dyn Digest>()
        .and_then(|_| session.check_op::<dyn Encryption>())
        .and_then(|_| {
            internal_encrypt_update(
                &mut session,
                part,
                part_len,
                encrypted_part,
                pul_encrypted_part_len,
            )
        });
    if let Err(e) = res {
        if e.kind() != crate::error::ErrorKind::BufferTooSmall {
            let _ = session.cancel_operation::<dyn Digest>();
            let _ = session.cancel_operation::<dyn Encryption>();
        }
        return Err(e);
    }
    if encrypted_part.is_null() {
        return Ok(());
    }

    if let Err(e) = internal_digest_update(&mut session, part, part_len) {
        let _ = session.cancel_operation::<dyn Encryption>();
        return Err(e);
    }
    Ok(())
}

pub extern "C" fn fn_digest_encrypt_update(
    s_handle: CK_SESSION_HANDLE,
    part: CK_BYTE_PTR,
    part_len: CK_ULONG,
    encrypted_part: CK_BYTE_PTR,
    pul_encrypted_part_len: CK_ULONG_PTR,
) -> CK_RV {
    log_debug!(
        "C_DigestEncryptUpdate: s_handle={} part={:?} part_len={} encrypted_part={:?} pul_encrypted_part_len={:?}",
        s_handle,
        part,
        part_len,
        encrypted_part,
        pul_encrypted_part_len
    );
    let rv = match digest_encrypt_update(
        s_handle,
        part,
        part_len,
        encrypted_part,
        pul_encrypted_part_len,
    ) {
        Ok(()) => CKR_OK,
        Err(e) => e.rv(),
    };
    log_debug!("C_DigestEncryptUpdate: ret={}", rv);
    rv
}

/// Implementation of C_DecryptDigestUpdate function
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203348](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203348)

#[inline(always)]
fn decrypt_digest_update(
    s_handle: CK_SESSION_HANDLE,
    encrypted_part: CK_BYTE_PTR,
    encrypted_part_len: CK_ULONG,
    part: CK_BYTE_PTR,
    pul_part_len: CK_ULONG_PTR,
) -> Result<()> {
    let rstate = STATE.rlock()?;
    let mut session = rstate.get_session_mut(s_handle)?;

    let res = session
        .check_op::<dyn Digest>()
        .and_then(|_| session.check_op::<dyn Decryption>())
        .and_then(|_| {
            internal_decrypt_update(
                &mut session,
                encrypted_part,
                encrypted_part_len,
                part,
                pul_part_len,
            )
        });
    if let Err(e) = res {
        if e.kind() != crate::error::ErrorKind::BufferTooSmall {
            let _ = session.cancel_operation::<dyn Digest>();
            let _ = session.cancel_operation::<dyn Decryption>();
        }
        return Err(e);
    }
    if part.is_null() {
        return Ok(());
    }

    let part_len: CK_ULONG = unsafe { *pul_part_len };
    if let Err(e) = internal_digest_update(&mut session, part, part_len) {
        let _ = session.cancel_operation::<dyn Decryption>();
        return Err(e);
    }
    Ok(())
}

pub extern "C" fn fn_decrypt_digest_update(
    s_handle: CK_SESSION_HANDLE,
    encrypted_part: CK_BYTE_PTR,
    encrypted_part_len: CK_ULONG,
    part: CK_BYTE_PTR,
    pul_part_len: CK_ULONG_PTR,
) -> CK_RV {
    log_debug!(
        "C_DecryptDigestUpdate: s_handle={} encrypted_part={:?} encrypted_part_len={} part={:?} pul_part_len={:?}",
        s_handle,
        encrypted_part,
        encrypted_part_len,
        part,
        pul_part_len
    );
    let rv = match decrypt_digest_update(
        s_handle,
        encrypted_part,
        encrypted_part_len,
        part,
        pul_part_len,
    ) {
        Ok(()) => CKR_OK,
        Err(e) => e.rv(),
    };
    log_debug!("C_DecryptDigestUpdate: ret={}", rv);
    rv
}

/// Implementation of C_SignEncryptUpdate function
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203349](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203349)

#[inline(always)]
fn sign_encrypt_update(
    s_handle: CK_SESSION_HANDLE,
    part: CK_BYTE_PTR,
    part_len: CK_ULONG,
    encrypted_part: CK_BYTE_PTR,
    pul_encrypted_part_len: CK_ULONG_PTR,
) -> Result<()> {
    let rstate = STATE.rlock()?;
    let mut session = rstate.get_session_mut(s_handle)?;

    let res = session
        .check_op::<dyn Sign>()
        .and_then(|_| session.check_op::<dyn Encryption>())
        .and_then(|_| {
            internal_encrypt_update(
                &mut session,
                part,
                part_len,
                encrypted_part,
                pul_encrypted_part_len,
            )
        });
    if let Err(e) = res {
        if e.kind() != crate::error::ErrorKind::BufferTooSmall {
            let _ = session.cancel_operation::<dyn Sign>();
            let _ = session.cancel_operation::<dyn Encryption>();
        }
        return Err(e);
    }
    if encrypted_part.is_null() {
        return Ok(());
    }

    if let Err(e) = internal_sign_update(&mut session, part, part_len) {
        let _ = session.cancel_operation::<dyn Encryption>();
        return Err(e);
    }
    Ok(())
}

pub extern "C" fn fn_sign_encrypt_update(
    s_handle: CK_SESSION_HANDLE,
    part: CK_BYTE_PTR,
    part_len: CK_ULONG,
    encrypted_part: CK_BYTE_PTR,
    pul_encrypted_part_len: CK_ULONG_PTR,
) -> CK_RV {
    log_debug!(
        "C_SignEncryptUpdate: s_handle={} part={:?} part_len={} encrypted_part={:?} pul_encrypted_part_len={:?}",
        s_handle,
        part,
        part_len,
        encrypted_part,
        pul_encrypted_part_len
    );
    let rv = match sign_encrypt_update(
        s_handle,
        part,
        part_len,
        encrypted_part,
        pul_encrypted_part_len,
    ) {
        Ok(()) => CKR_OK,
        Err(e) => e.rv(),
    };
    log_debug!("C_SignEncryptUpdate: ret={}", rv);
    rv
}

/// Implementation of C_DecryptVerifyUpdate function
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203350](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203350)

#[inline(always)]
fn decrypt_verify_update(
    s_handle: CK_SESSION_HANDLE,
    encrypted_part: CK_BYTE_PTR,
    encrypted_part_len: CK_ULONG,
    part: CK_BYTE_PTR,
    pul_part_len: CK_ULONG_PTR,
) -> Result<()> {
    let rstate = STATE.rlock()?;
    let mut session = rstate.get_session_mut(s_handle)?;

    let res = session
        .check_op::<dyn Verify>()
        .and_then(|_| session.check_op::<dyn Decryption>())
        .and_then(|_| {
            internal_decrypt_update(
                &mut session,
                encrypted_part,
                encrypted_part_len,
                part,
                pul_part_len,
            )
        });
    if let Err(e) = res {
        if e.kind() != crate::error::ErrorKind::BufferTooSmall {
            let _ = session.cancel_operation::<dyn Verify>();
            let _ = session.cancel_operation::<dyn Decryption>();
        }
        return Err(e);
    }
    if part.is_null() {
        return Ok(());
    }

    let part_len: CK_ULONG = unsafe { *pul_part_len };
    if let Err(e) = internal_verify_update(&mut session, part, part_len) {
        let _ = session.cancel_operation::<dyn Decryption>();
        return Err(e);
    }
    Ok(())
}

pub extern "C" fn fn_decrypt_verify_update(
    s_handle: CK_SESSION_HANDLE,
    encrypted_part: CK_BYTE_PTR,
    encrypted_part_len: CK_ULONG,
    part: CK_BYTE_PTR,
    pul_part_len: CK_ULONG_PTR,
) -> CK_RV {
    log_debug!(
        "C_DecryptVerifyUpdate: s_handle={} encrypted_part={:?} encrypted_part_len={} part={:?} pul_part_len={:?}",
        s_handle,
        encrypted_part,
        encrypted_part_len,
        part,
        pul_part_len
    );
    let rv = match decrypt_verify_update(
        s_handle,
        encrypted_part,
        encrypted_part_len,
        part,
        pul_part_len,
    ) {
        Ok(()) => CKR_OK,
        Err(e) => e.rv(),
    };
    log_debug!("C_DecryptVerifyUpdate: ret={}", rv);
    rv
}
