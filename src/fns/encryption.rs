// Copyright 2026 Simo Sorce
// See LICENSE.txt file for terms

//! Encryption and Decryption functions
//!
//! This module contains the implementation of the Encryption and Decryption functions
//! as defined in the PKCS#11 specification.

use std::sync::RwLockWriteGuard;

use crate::check_allowed_mechs;
use crate::error::{arg_bad, Result};
use crate::fns::{
    cast_or_ret, check_op_empty_or_fail, global_rlock, ok_or_ret, res_or_ret,
    ret_to_rv,
};
use crate::mechanism::{Decryption, Encryption, MsgDecryption, MsgEncryption};
use crate::pkcs11::*;
use crate::session::Session;

#[cfg(feature = "fips")]
use crate::{finalize_fips_approval, init_fips_approval};

/// Implementation of C_EncryptInit function
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203293](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203293)

pub extern "C" fn fn_encrypt_init(
    s_handle: CK_SESSION_HANDLE,
    mechptr: CK_MECHANISM_PTR,
    key_handle: CK_OBJECT_HANDLE,
) -> CK_RV {
    let rstate = global_rlock!((*crate::STATE));
    let mut session = res_or_ret!(rstate.get_session_mut(s_handle));
    check_op_empty_or_fail!(session; Encryption; mechptr);
    let mechanism: &CK_MECHANISM = unsafe { &*mechptr };
    let slot_id = session.get_slot_id();
    let mut token = res_or_ret!(rstate.get_token_from_slot_mut(slot_id));
    let key = res_or_ret!(token.get_object_by_handle(key_handle));
    ok_or_ret!(check_allowed_mechs(mechanism, &key));
    let mech = res_or_ret!(token.get_mechanisms().get(mechanism.mechanism));
    if mech.info().flags & CKF_ENCRYPT == CKF_ENCRYPT {
        let operation = res_or_ret!(mech.encryption_new(mechanism, &key));
        session.set_operation::<dyn Encryption>(operation, false);

        #[cfg(feature = "fips")]
        init_fips_approval(session, mechanism.mechanism, CKF_ENCRYPT, &key);

        CKR_OK
    } else {
        CKR_MECHANISM_INVALID
    }
}

/// Implementation of C_Encrypt function
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203294](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203294)

pub extern "C" fn fn_encrypt(
    s_handle: CK_SESSION_HANDLE,
    pdata: CK_BYTE_PTR,
    data_len: CK_ULONG,
    encrypted_data: CK_BYTE_PTR,
    pul_encrypted_data_len: CK_ULONG_PTR,
) -> CK_RV {
    if pdata.is_null() || pul_encrypted_data_len.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    let rstate = global_rlock!((*crate::STATE));
    let mut session = res_or_ret!(rstate.get_session_mut(s_handle));
    let operation = res_or_ret!(session.get_operation::<dyn Encryption>());
    let dlen = cast_or_ret!(usize from data_len => CKR_ARGUMENTS_BAD);
    if encrypted_data.is_null() {
        let encryption_len = cast_or_ret!(
            CK_ULONG from res_or_ret!(operation.encryption_len(dlen, true))
        );
        unsafe {
            *pul_encrypted_data_len = encryption_len;
        }
        return CKR_OK;
    }
    let data: &[u8] = unsafe { std::slice::from_raw_parts(pdata, dlen) };
    let penclen = unsafe { *pul_encrypted_data_len as CK_ULONG };
    let enclen = cast_or_ret!(usize from penclen => CKR_ARGUMENTS_BAD);
    let encdata: &mut [u8] =
        unsafe { std::slice::from_raw_parts_mut(encrypted_data, enclen) };
    let outlen = res_or_ret!(operation.encrypt(data, encdata));
    let retlen = cast_or_ret!(CK_ULONG from outlen);
    unsafe { *pul_encrypted_data_len = retlen };

    #[cfg(feature = "fips")]
    {
        let approved = operation.fips_approved();
        finalize_fips_approval(session, approved);
    }
    CKR_OK
}

/// Helper to perform "encrypt_update" in multiple places,

pub(crate) fn internal_encrypt_update(
    session: &mut RwLockWriteGuard<'_, Session>,
    part: CK_BYTE_PTR,
    part_len: CK_ULONG,
    encrypted_part: CK_BYTE_PTR,
    pul_encrypted_part_len: CK_ULONG_PTR,
) -> Result<()> {
    let operation = session.get_operation::<dyn Encryption>()?;
    let plen = usize::try_from(part_len).map_err(arg_bad)?;
    let len = if encrypted_part.is_null() {
        operation.encryption_len(plen, false)?
    } else {
        let data: &[u8] = unsafe { std::slice::from_raw_parts(part, plen) };
        let penclen = unsafe { *pul_encrypted_part_len as CK_ULONG };
        let enclen = usize::try_from(penclen).map_err(arg_bad)?;
        let encpart: &mut [u8] =
            unsafe { std::slice::from_raw_parts_mut(encrypted_part, enclen) };
        operation.encrypt_update(data, encpart)?
    };
    let cklen = CK_ULONG::try_from(len).map_err(arg_bad)?;
    unsafe { *pul_encrypted_part_len = cklen };
    Ok(())
}

/// Implementation of C_EncryptUpdate function
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203295](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203295)

pub extern "C" fn fn_encrypt_update(
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
    ret_to_rv!(internal_encrypt_update(
        &mut session,
        part,
        part_len,
        encrypted_part,
        pul_encrypted_part_len,
    ))
}

/// Implementation of C_EncryptFinal function
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203296](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203296)

pub extern "C" fn fn_encrypt_final(
    s_handle: CK_SESSION_HANDLE,
    last_encrypted_part: CK_BYTE_PTR,
    pul_last_encrypted_part_len: CK_ULONG_PTR,
) -> CK_RV {
    let rstate = global_rlock!((*crate::STATE));
    if last_encrypted_part.is_null() && pul_last_encrypted_part_len.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    let mut session = res_or_ret!(rstate.get_session_mut(s_handle));
    let operation = res_or_ret!(session.get_operation::<dyn Encryption>());
    if last_encrypted_part.is_null() {
        let encryption_len = cast_or_ret!(
            CK_ULONG from res_or_ret!(operation.encryption_len(0, true))
        );
        unsafe {
            *pul_last_encrypted_part_len = encryption_len;
        }
        return CKR_OK;
    }
    let penclen = unsafe { *pul_last_encrypted_part_len as CK_ULONG };
    let enclen = cast_or_ret!(usize from penclen => CKR_ARGUMENTS_BAD);
    let enclast: &mut [u8] =
        unsafe { std::slice::from_raw_parts_mut(last_encrypted_part, enclen) };
    let outlen = res_or_ret!(operation.encrypt_final(enclast));
    let retlen = cast_or_ret!(CK_ULONG from outlen);
    unsafe { *pul_last_encrypted_part_len = retlen };

    #[cfg(feature = "fips")]
    {
        let approved = operation.fips_approved();
        finalize_fips_approval(session, approved);
    }
    CKR_OK
}

/// Implementation of C_DecryptInit function
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203304](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203304)

pub extern "C" fn fn_decrypt_init(
    s_handle: CK_SESSION_HANDLE,
    mechptr: CK_MECHANISM_PTR,
    key_handle: CK_OBJECT_HANDLE,
) -> CK_RV {
    let rstate = global_rlock!((*crate::STATE));
    let mut session = res_or_ret!(rstate.get_session_mut(s_handle));
    check_op_empty_or_fail!(session; Decryption; mechptr);
    let mechanism: &CK_MECHANISM = unsafe { &*mechptr };
    let slot_id = session.get_slot_id();
    let mut token = res_or_ret!(rstate.get_token_from_slot_mut(slot_id));
    let key = res_or_ret!(token.get_object_by_handle(key_handle));
    ok_or_ret!(check_allowed_mechs(mechanism, &key));
    let mech = res_or_ret!(token.get_mechanisms().get(mechanism.mechanism));
    if mech.info().flags & CKF_DECRYPT == CKF_DECRYPT {
        let operation = res_or_ret!(mech.decryption_new(mechanism, &key));
        session.set_operation::<dyn Decryption>(operation, key.always_auth());

        #[cfg(feature = "fips")]
        init_fips_approval(session, mechanism.mechanism, CKF_DECRYPT, &key);

        CKR_OK
    } else {
        CKR_MECHANISM_INVALID
    }
}

/// Implementation of C_Decrypt function
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203305](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203305)

pub extern "C" fn fn_decrypt(
    s_handle: CK_SESSION_HANDLE,
    encrypted_data: CK_BYTE_PTR,
    encrypted_data_len: CK_ULONG,
    data: CK_BYTE_PTR,
    pul_data_len: CK_ULONG_PTR,
) -> CK_RV {
    if encrypted_data.is_null() || pul_data_len.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    let rstate = global_rlock!((*crate::STATE));
    let mut session = res_or_ret!(rstate.get_session_mut(s_handle));
    let operation = res_or_ret!(session.get_operation::<dyn Decryption>());
    let elen = cast_or_ret!(usize from encrypted_data_len => CKR_ARGUMENTS_BAD);
    if data.is_null() {
        let decryption_len = cast_or_ret!(
            CK_ULONG from res_or_ret!(operation.decryption_len(elen, true))
        );
        unsafe {
            *pul_data_len = decryption_len;
        }
        return CKR_OK;
    }
    let enc: &[u8] =
        unsafe { std::slice::from_raw_parts(encrypted_data, elen) };
    let pdlen = unsafe { *pul_data_len as CK_ULONG };
    let dlen = cast_or_ret!(usize from pdlen => CKR_ARGUMENTS_BAD);
    let ddata: &mut [u8] =
        unsafe { std::slice::from_raw_parts_mut(data, dlen) };
    let outlen = res_or_ret!(operation.decrypt(enc, ddata));
    let retlen = cast_or_ret!(CK_ULONG from outlen);
    unsafe { *pul_data_len = retlen };

    #[cfg(feature = "fips")]
    {
        let approved = operation.fips_approved();
        finalize_fips_approval(session, approved);
    }
    CKR_OK
}

/// Helper to perform "decrypt_update" in multiple places,

pub(crate) fn internal_decrypt_update(
    session: &mut RwLockWriteGuard<'_, Session>,
    encrypted_part: CK_BYTE_PTR,
    encrypted_part_len: CK_ULONG,
    part: CK_BYTE_PTR,
    pul_part_len: CK_ULONG_PTR,
) -> Result<()> {
    let operation = session.get_operation::<dyn Decryption>()?;
    let elen = usize::try_from(encrypted_part_len).map_err(arg_bad)?;
    let len = if part.is_null() {
        operation.decryption_len(elen, false)?
    } else {
        let enc: &[u8] =
            unsafe { std::slice::from_raw_parts(encrypted_part, elen) };
        let pplen = unsafe { *pul_part_len as CK_ULONG };
        let plen = usize::try_from(pplen).map_err(arg_bad)?;
        let dpart: &mut [u8] =
            unsafe { std::slice::from_raw_parts_mut(part, plen) };
        operation.decrypt_update(enc, dpart)?
    };
    let cklen = CK_ULONG::try_from(len).map_err(arg_bad)?;
    unsafe { *pul_part_len = cklen };
    Ok(())
}

/// Implementation of C_DecryptUpdate function
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203306](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203306)

pub extern "C" fn fn_decrypt_update(
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
    ret_to_rv!(internal_decrypt_update(
        &mut session,
        encrypted_part,
        encrypted_part_len,
        part,
        pul_part_len,
    ))
}

/// Implementation of C_DecryptFinal function
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203307](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203307)

pub extern "C" fn fn_decrypt_final(
    s_handle: CK_SESSION_HANDLE,
    last_part: CK_BYTE_PTR,
    pul_last_part_len: CK_ULONG_PTR,
) -> CK_RV {
    if last_part.is_null() && pul_last_part_len.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    let rstate = global_rlock!((*crate::STATE));
    let mut session = res_or_ret!(rstate.get_session_mut(s_handle));
    let operation = res_or_ret!(session.get_operation::<dyn Decryption>());
    if last_part.is_null() {
        let decryption_len = cast_or_ret!(
            CK_ULONG from res_or_ret!(operation.decryption_len(0, true))
        );
        unsafe {
            *pul_last_part_len = decryption_len;
        }
        return CKR_OK;
    }
    let pplen = unsafe { *pul_last_part_len as CK_ULONG };
    let plen = cast_or_ret!(usize from pplen => CKR_ARGUMENTS_BAD);
    let dlast: &mut [u8] =
        unsafe { std::slice::from_raw_parts_mut(last_part, plen) };
    let outlen = res_or_ret!(operation.decrypt_final(dlast));
    let retlen = cast_or_ret!(CK_ULONG from outlen);
    unsafe { *pul_last_part_len = retlen };

    #[cfg(feature = "fips")]
    {
        let approved = operation.fips_approved();
        finalize_fips_approval(session, approved);
    }
    CKR_OK
}

/// Implementation of C_MessageEncryptInit function
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203298](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203298)

pub extern "C" fn fn_message_encrypt_init(
    s_handle: CK_SESSION_HANDLE,
    mechptr: CK_MECHANISM_PTR,
    key_handle: CK_OBJECT_HANDLE,
) -> CK_RV {
    let rstate = global_rlock!((*crate::STATE));
    let mut session = res_or_ret!(rstate.get_session_mut(s_handle));
    check_op_empty_or_fail!(session; MsgEncryption; mechptr);
    let mechanism: &CK_MECHANISM = unsafe { &*mechptr };
    let slot_id = session.get_slot_id();
    let mut token = res_or_ret!(rstate.get_token_from_slot_mut(slot_id));
    let key = res_or_ret!(token.get_object_by_handle(key_handle));
    ok_or_ret!(check_allowed_mechs(mechanism, &key));
    let mech = res_or_ret!(token.get_mechanisms().get(mechanism.mechanism));
    if mech.info().flags & CKF_MESSAGE_ENCRYPT != 0 {
        let operation = res_or_ret!(mech.msg_encryption_op(mechanism, &key));
        session.set_operation::<dyn MsgEncryption>(operation, false);
        #[cfg(feature = "fips")]
        init_fips_approval(session, mechanism.mechanism, CKF_ENCRYPT, &key);

        CKR_OK
    } else {
        CKR_MECHANISM_INVALID
    }
}

/// Implementation of C_EncryptMessage function
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203299](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203299)

pub extern "C" fn fn_encrypt_message(
    s_handle: CK_SESSION_HANDLE,
    parameter: CK_VOID_PTR,
    parameter_len: CK_ULONG,
    associated_data: CK_BYTE_PTR,
    associated_data_len: CK_ULONG,
    plaintext: CK_BYTE_PTR,
    plaintext_len: CK_ULONG,
    ciphertext: CK_BYTE_PTR,
    pul_ciphertext_len: CK_ULONG_PTR,
) -> CK_RV {
    if parameter.is_null()
        || parameter_len == 0
        || plaintext.is_null()
        || plaintext_len == 0
        || pul_ciphertext_len.is_null()
    {
        return CKR_ARGUMENTS_BAD;
    }

    let alen = cast_or_ret!(
        usize from associated_data_len => CKR_ARGUMENTS_BAD
    );
    let plen = cast_or_ret!(usize from plaintext_len => CKR_ARGUMENTS_BAD);
    let pclen = unsafe { *pul_ciphertext_len as CK_ULONG };
    let clen = cast_or_ret!(usize from pclen => CKR_ARGUMENTS_BAD);

    let rstate = global_rlock!((*crate::STATE));
    let mut session = res_or_ret!(rstate.get_session_mut(s_handle));
    let operation = res_or_ret!(session.get_operation::<dyn MsgEncryption>());
    if operation.busy() {
        return CKR_OPERATION_ACTIVE;
    }

    if ciphertext.is_null() {
        let retlen = cast_or_ret!(
            CK_ULONG from res_or_ret!(operation.msg_encryption_len(plen, false))
        );
        unsafe {
            *pul_ciphertext_len = retlen;
        }
        return CKR_OK;
    }

    let adata: &[u8] = if associated_data.is_null() {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(associated_data, alen) }
    };
    let plain: &[u8] = unsafe { std::slice::from_raw_parts(plaintext, plen) };
    let cipher: &mut [u8] =
        unsafe { std::slice::from_raw_parts_mut(ciphertext, clen) };

    let outlen = res_or_ret!(operation.msg_encrypt(
        parameter,
        parameter_len,
        adata,
        plain,
        cipher
    ));
    let retlen = cast_or_ret!(CK_ULONG from outlen);
    unsafe { *pul_ciphertext_len = retlen };

    #[cfg(feature = "fips")]
    {
        let approved = operation.fips_approved();
        finalize_fips_approval(session, approved);
    }
    CKR_OK
}

/// Implementation of C_EncryptMessageBegin function
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203300](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203300)

pub extern "C" fn fn_encrypt_message_begin(
    s_handle: CK_SESSION_HANDLE,
    parameter: CK_VOID_PTR,
    parameter_len: CK_ULONG,
    associated_data: CK_BYTE_PTR,
    associated_data_len: CK_ULONG,
) -> CK_RV {
    if parameter.is_null() || parameter_len == 0 {
        return CKR_ARGUMENTS_BAD;
    }

    let alen = cast_or_ret!(
        usize from associated_data_len => CKR_ARGUMENTS_BAD
    );

    let rstate = global_rlock!((*crate::STATE));
    let mut session = res_or_ret!(rstate.get_session_mut(s_handle));
    let slot_id = session.get_slot_id();

    #[cfg(feature = "fips")]
    session.reset_fips_indicator();

    let operation = res_or_ret!(session.get_operation::<dyn MsgEncryption>());
    if operation.busy() {
        return CKR_OPERATION_ACTIVE;
    }

    let token = res_or_ret!(rstate.get_token_from_slot_mut(slot_id));
    let mechanism = res_or_ret!(operation.mechanism());
    let mech = res_or_ret!(token.get_mechanisms().get(mechanism));
    if mech.info().flags & CKF_MULTI_MESSAGE == 0 {
        return CKR_MECHANISM_INVALID;
    }

    let adata: &[u8] = if associated_data.is_null() {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(associated_data, alen) }
    };
    ret_to_rv!(operation.msg_encrypt_begin(parameter, parameter_len, adata))
}

/// Implementation of C_EncryptMessageNext function
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203301](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203301)

pub extern "C" fn fn_encrypt_message_next(
    s_handle: CK_SESSION_HANDLE,
    parameter: CK_VOID_PTR,
    parameter_len: CK_ULONG,
    plaintext_part: CK_BYTE_PTR,
    plaintext_part_len: CK_ULONG,
    ciphertext_part: CK_BYTE_PTR,
    pul_ciphertext_part_len: CK_ULONG_PTR,
    flags: CK_FLAGS,
) -> CK_RV {
    if parameter.is_null()
        || parameter_len == 0
        || plaintext_part.is_null()
        || plaintext_part_len == 0
        || pul_ciphertext_part_len.is_null()
    {
        return CKR_ARGUMENTS_BAD;
    }

    let plen = cast_or_ret!(usize from plaintext_part_len => CKR_ARGUMENTS_BAD);
    let pclen = unsafe { *pul_ciphertext_part_len as CK_ULONG };
    let clen = cast_or_ret!(usize from pclen => CKR_ARGUMENTS_BAD);

    let fin = match flags {
        CKF_END_OF_MESSAGE => true,
        0 => false,
        _ => return CKR_ARGUMENTS_BAD,
    };

    let rstate = global_rlock!((*crate::STATE));
    let mut session = res_or_ret!(rstate.get_session_mut(s_handle));
    let operation = res_or_ret!(session.get_operation::<dyn MsgEncryption>());
    if !operation.busy() {
        return CKR_OPERATION_NOT_INITIALIZED;
    }

    if ciphertext_part.is_null() {
        let retlen = cast_or_ret!(
            CK_ULONG from res_or_ret!(operation.msg_encryption_len(plen, fin))
        );
        unsafe {
            *pul_ciphertext_part_len = retlen;
        }
        return CKR_OK;
    }

    let plain: &[u8] =
        unsafe { std::slice::from_raw_parts(plaintext_part, plen) };
    let cipher: &mut [u8] =
        unsafe { std::slice::from_raw_parts_mut(ciphertext_part, clen) };

    let outlen = match fin {
        false => res_or_ret!(operation.msg_encrypt_next(
            parameter,
            parameter_len,
            plain,
            cipher
        )),
        true => res_or_ret!(operation.msg_encrypt_final(
            parameter,
            parameter_len,
            plain,
            cipher
        )),
    };
    let retlen = cast_or_ret!(CK_ULONG from outlen);
    unsafe { *pul_ciphertext_part_len = retlen };

    #[cfg(feature = "fips")]
    {
        let approved = operation.fips_approved();
        finalize_fips_approval(session, approved);
    }
    CKR_OK
}

/// Implementation of C_MessageEncryptFinal function
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203302](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203302)

pub extern "C" fn fn_message_encrypt_final(
    s_handle: CK_SESSION_HANDLE,
) -> CK_RV {
    let rstate = global_rlock!((*crate::STATE));
    let mut session = res_or_ret!(rstate.get_session_mut(s_handle));
    let operation = res_or_ret!(session.get_operation::<dyn MsgEncryption>());
    ret_to_rv!(operation.finalize())
}

/// Implementation of C_MessageDecryptInit function
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203309](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203309)

pub extern "C" fn fn_message_decrypt_init(
    s_handle: CK_SESSION_HANDLE,
    mechptr: CK_MECHANISM_PTR,
    key_handle: CK_OBJECT_HANDLE,
) -> CK_RV {
    let rstate = global_rlock!((*crate::STATE));
    let mut session = res_or_ret!(rstate.get_session_mut(s_handle));
    check_op_empty_or_fail!(session; MsgDecryption; mechptr);
    let mechanism: &CK_MECHANISM = unsafe { &*mechptr };
    let slot_id = session.get_slot_id();
    let mut token = res_or_ret!(rstate.get_token_from_slot_mut(slot_id));
    let key = res_or_ret!(token.get_object_by_handle(key_handle));
    ok_or_ret!(check_allowed_mechs(mechanism, &key));
    let mech = res_or_ret!(token.get_mechanisms().get(mechanism.mechanism));
    if mech.info().flags & CKF_MESSAGE_DECRYPT != 0 {
        let operation = res_or_ret!(mech.msg_decryption_op(mechanism, &key));
        session.set_operation::<dyn MsgDecryption>(operation, false);
        #[cfg(feature = "fips")]
        init_fips_approval(session, mechanism.mechanism, CKF_DECRYPT, &key);

        CKR_OK
    } else {
        CKR_MECHANISM_INVALID
    }
}

/// Implementation of C_DecryptMessage function
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203310](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203310)

pub extern "C" fn fn_decrypt_message(
    s_handle: CK_SESSION_HANDLE,
    parameter: CK_VOID_PTR,
    parameter_len: CK_ULONG,
    associated_data: CK_BYTE_PTR,
    associated_data_len: CK_ULONG,
    ciphertext: CK_BYTE_PTR,
    ciphertext_len: CK_ULONG,
    plaintext: CK_BYTE_PTR,
    pul_plaintext_len: CK_ULONG_PTR,
) -> CK_RV {
    if parameter.is_null()
        || parameter_len == 0
        || ciphertext.is_null()
        || ciphertext_len == 0
        || pul_plaintext_len.is_null()
    {
        return CKR_ARGUMENTS_BAD;
    }

    let alen = cast_or_ret!(
        usize from associated_data_len => CKR_ARGUMENTS_BAD
    );
    let clen = cast_or_ret!(usize from ciphertext_len => CKR_ARGUMENTS_BAD);
    let pplen = unsafe { *pul_plaintext_len as CK_ULONG };
    let plen = cast_or_ret!(usize from pplen => CKR_ARGUMENTS_BAD);

    let rstate = global_rlock!((*crate::STATE));
    let mut session = res_or_ret!(rstate.get_session_mut(s_handle));
    let operation = res_or_ret!(session.get_operation::<dyn MsgDecryption>());
    if operation.busy() {
        return CKR_OPERATION_ACTIVE;
    }

    if plaintext.is_null() {
        let retlen = cast_or_ret!(
            CK_ULONG from res_or_ret!(operation.msg_decryption_len(clen, false))
        );
        unsafe {
            *pul_plaintext_len = retlen;
        }
        return CKR_OK;
    }

    let adata: &[u8] = if associated_data.is_null() {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(associated_data, alen) }
    };
    let cipher: &[u8] = unsafe { std::slice::from_raw_parts(ciphertext, clen) };
    let plain: &mut [u8] =
        unsafe { std::slice::from_raw_parts_mut(plaintext, plen) };

    let outlen = res_or_ret!(operation.msg_decrypt(
        parameter,
        parameter_len,
        adata,
        cipher,
        plain
    ));
    let retlen = cast_or_ret!(CK_ULONG from outlen);
    unsafe { *pul_plaintext_len = retlen };

    #[cfg(feature = "fips")]
    {
        let approved = operation.fips_approved();
        finalize_fips_approval(session, approved);
    }
    CKR_OK
}

/// Implementation of C_DecryptMessageBegin function
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203311](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203311)

pub extern "C" fn fn_decrypt_message_begin(
    s_handle: CK_SESSION_HANDLE,
    parameter: CK_VOID_PTR,
    parameter_len: CK_ULONG,
    associated_data: CK_BYTE_PTR,
    associated_data_len: CK_ULONG,
) -> CK_RV {
    if parameter.is_null() || parameter_len == 0 {
        return CKR_ARGUMENTS_BAD;
    }

    let alen = cast_or_ret!(
        usize from associated_data_len => CKR_ARGUMENTS_BAD
    );

    let rstate = global_rlock!((*crate::STATE));
    let mut session = res_or_ret!(rstate.get_session_mut(s_handle));
    let slot_id = session.get_slot_id();

    #[cfg(feature = "fips")]
    session.reset_fips_indicator();

    let operation = res_or_ret!(session.get_operation::<dyn MsgDecryption>());
    if operation.busy() {
        return CKR_OPERATION_ACTIVE;
    }

    let token = res_or_ret!(rstate.get_token_from_slot_mut(slot_id));
    let mechanism = res_or_ret!(operation.mechanism());
    let mech = res_or_ret!(token.get_mechanisms().get(mechanism));
    if mech.info().flags & CKF_MULTI_MESSAGE == 0 {
        return CKR_MECHANISM_INVALID;
    }

    let adata: &[u8] = if associated_data.is_null() {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(associated_data, alen) }
    };
    ret_to_rv!(operation.msg_decrypt_begin(parameter, parameter_len, adata))
}

/// Implementation of C_DecryptMessageNext function
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203312](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203312)

pub extern "C" fn fn_decrypt_message_next(
    s_handle: CK_SESSION_HANDLE,
    parameter: CK_VOID_PTR,
    parameter_len: CK_ULONG,
    ciphertext_part: CK_BYTE_PTR,
    ciphertext_part_len: CK_ULONG,
    plaintext_part: CK_BYTE_PTR,
    pul_plaintext_part_len: CK_ULONG_PTR,
    flags: CK_FLAGS,
) -> CK_RV {
    if parameter.is_null()
        || parameter_len == 0
        || ciphertext_part.is_null()
        || ciphertext_part_len == 0
        || pul_plaintext_part_len.is_null()
    {
        return CKR_ARGUMENTS_BAD;
    }

    let clen =
        cast_or_ret!(usize from ciphertext_part_len => CKR_ARGUMENTS_BAD);
    let pplen = unsafe { *pul_plaintext_part_len as CK_ULONG };
    let plen = cast_or_ret!(usize from pplen => CKR_ARGUMENTS_BAD);

    let fin = match flags {
        CKF_END_OF_MESSAGE => true,
        0 => false,
        _ => return CKR_ARGUMENTS_BAD,
    };

    let rstate = global_rlock!((*crate::STATE));
    let mut session = res_or_ret!(rstate.get_session_mut(s_handle));
    let operation = res_or_ret!(session.get_operation::<dyn MsgDecryption>());
    if !operation.busy() {
        return CKR_OPERATION_NOT_INITIALIZED;
    }

    if plaintext_part.is_null() {
        let retlen = cast_or_ret!(
            CK_ULONG from res_or_ret!(operation.msg_decryption_len(clen, fin))
        );
        unsafe {
            *pul_plaintext_part_len = retlen;
        }
        return CKR_OK;
    }

    let cipher: &[u8] =
        unsafe { std::slice::from_raw_parts(ciphertext_part, clen) };
    let plain: &mut [u8] =
        unsafe { std::slice::from_raw_parts_mut(plaintext_part, plen) };

    let outlen = match fin {
        false => res_or_ret!(operation.msg_decrypt_next(
            parameter,
            parameter_len,
            cipher,
            plain
        )),
        true => res_or_ret!(operation.msg_decrypt_final(
            parameter,
            parameter_len,
            cipher,
            plain
        )),
    };
    let retlen = cast_or_ret!(CK_ULONG from outlen);
    unsafe { *pul_plaintext_part_len = retlen };

    #[cfg(feature = "fips")]
    {
        let approved = operation.fips_approved();
        finalize_fips_approval(session, approved);
    }
    CKR_OK
}

/// Implementation of C_MessageDecryptFinal function
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203313](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203313)

pub extern "C" fn fn_message_decrypt_final(
    s_handle: CK_SESSION_HANDLE,
) -> CK_RV {
    let rstate = global_rlock!((*crate::STATE));
    let mut session = res_or_ret!(rstate.get_session_mut(s_handle));
    let operation = res_or_ret!(session.get_operation::<dyn MsgDecryption>());
    ret_to_rv!(operation.finalize())
}
