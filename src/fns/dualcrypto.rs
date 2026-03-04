// Copyright 2026 Simo Sorce
// See LICENSE.txt file for terms

//! Dual-function cryptographic functions
//!
//! This module contains the implementation of dual-function operations

use crate::fns::digest::internal_digest_update;
use crate::fns::encryption::{
    internal_decrypt_update, internal_encrypt_update,
};
use crate::fns::signing::{internal_sign_update, internal_verify_update};
use crate::fns::{global_rlock, res_or_ret, ret_to_rv};
use crate::mechanism::{Digest, Sign, Verify};
use crate::pkcs11::*;

/// Implementation of C_DigestEncryptUpdate function
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203347](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203347)

pub extern "C" fn fn_digest_encrypt_update(
    s_handle: CK_SESSION_HANDLE,
    part: CK_BYTE_PTR,
    part_len: CK_ULONG,
    encrypted_part: CK_BYTE_PTR,
    pul_encrypted_part_len: CK_ULONG_PTR,
) -> CK_RV {
    if part.is_null() || pul_encrypted_part_len.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    let rstate = global_rlock!((*crate::STATE));
    let mut session = res_or_ret!(rstate.get_session_mut(s_handle));

    res_or_ret!(session.check_op::<dyn Digest>());

    res_or_ret!(internal_encrypt_update(
        &mut session,
        part,
        part_len,
        encrypted_part,
        pul_encrypted_part_len,
    ));
    if encrypted_part.is_null() {
        return CKR_OK;
    }

    ret_to_rv!(internal_digest_update(&mut session, part, part_len))
}

/// Implementation of C_DecryptDigestUpdate function
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203348](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203348)

pub extern "C" fn fn_decrypt_digest_update(
    s_handle: CK_SESSION_HANDLE,
    encrypted_part: CK_BYTE_PTR,
    encrypted_part_len: CK_ULONG,
    part: CK_BYTE_PTR,
    pul_part_len: CK_ULONG_PTR,
) -> CK_RV {
    if encrypted_part.is_null() || pul_part_len.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    let rstate = global_rlock!((*crate::STATE));
    let mut session = res_or_ret!(rstate.get_session_mut(s_handle));

    res_or_ret!(session.check_op::<dyn Digest>());

    res_or_ret!(internal_decrypt_update(
        &mut session,
        encrypted_part,
        encrypted_part_len,
        part,
        pul_part_len,
    ));
    if part.is_null() {
        return CKR_OK;
    }

    let part_len: CK_ULONG = unsafe { *pul_part_len };
    ret_to_rv!(internal_digest_update(&mut session, part, part_len))
}

/// Implementation of C_SignEncryptUpdate function
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203349](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203349)

pub extern "C" fn fn_sign_encrypt_update(
    s_handle: CK_SESSION_HANDLE,
    part: CK_BYTE_PTR,
    part_len: CK_ULONG,
    encrypted_part: CK_BYTE_PTR,
    pul_encrypted_part_len: CK_ULONG_PTR,
) -> CK_RV {
    if part.is_null() || pul_encrypted_part_len.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    let rstate = global_rlock!((*crate::STATE));
    let mut session = res_or_ret!(rstate.get_session_mut(s_handle));

    res_or_ret!(session.check_op::<dyn Sign>());

    res_or_ret!(internal_encrypt_update(
        &mut session,
        part,
        part_len,
        encrypted_part,
        pul_encrypted_part_len,
    ));
    if encrypted_part.is_null() {
        return CKR_OK;
    }

    ret_to_rv!(internal_sign_update(&mut session, part, part_len))
}

/// Implementation of C_DecryptVerifyUpdate function
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203350](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203350)

pub extern "C" fn fn_decrypt_verify_update(
    s_handle: CK_SESSION_HANDLE,
    encrypted_part: CK_BYTE_PTR,
    encrypted_part_len: CK_ULONG,
    part: CK_BYTE_PTR,
    pul_part_len: CK_ULONG_PTR,
) -> CK_RV {
    if encrypted_part.is_null() || pul_part_len.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    let rstate = global_rlock!((*crate::STATE));
    let mut session = res_or_ret!(rstate.get_session_mut(s_handle));

    res_or_ret!(session.check_op::<dyn Verify>());

    res_or_ret!(internal_decrypt_update(
        &mut session,
        encrypted_part,
        encrypted_part_len,
        part,
        pul_part_len,
    ));
    if part.is_null() {
        return CKR_OK;
    }

    let part_len: CK_ULONG = unsafe { *pul_part_len };
    ret_to_rv!(internal_verify_update(&mut session, part, part_len))
}
