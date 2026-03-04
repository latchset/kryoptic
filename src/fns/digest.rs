// Copyright 2026 Simo Sorce
// See LICENSE.txt file for terms

//! Message digesting functions
//!
//! This module contains the implementation of the Message Digesting functions
//! as defined in the PKCS#11 specification.

use std::sync::RwLockWriteGuard;

use crate::error::{arg_bad, Result};
use crate::mechanism::Digest;
use crate::pkcs11::*;
use crate::session::Session;
use crate::{cast_or_ret, res_or_ret, ret_to_rv, STATE};

#[cfg(feature = "fips")]
use crate::{finalize_fips_approval, init_fips_approval};

macro_rules! check_op_empty_or_fail {
    ($sess:expr; $op:ident; $ptr:expr) => {
        if $ptr.is_null() {
            res_or_ret!($sess.cancel_operation::<dyn $op>());
            return CKR_OK;
        }
        res_or_ret!($sess.check_no_op::<dyn $op>());
    };
}

/// Implementation of C_DigestInit function
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203315](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203315)

pub extern "C" fn fn_digest_init(
    s_handle: CK_SESSION_HANDLE,
    mechptr: CK_MECHANISM_PTR,
) -> CK_RV {
    let rstate = res_or_ret!(STATE.rlock());
    let mut session = res_or_ret!(rstate.get_session_mut(s_handle));
    check_op_empty_or_fail!(session; Digest; mechptr);
    let mechanism: &CK_MECHANISM = unsafe { &*mechptr };
    let token = res_or_ret!(rstate.get_token_from_slot(session.get_slot_id()));
    let mech = res_or_ret!(token.get_mechanisms().get(mechanism.mechanism));
    if mech.info().flags & CKF_DIGEST == CKF_DIGEST {
        let operation = res_or_ret!(mech.digest_new(mechanism));
        session.set_operation::<dyn Digest>(operation, false);

        CKR_OK
    } else {
        CKR_MECHANISM_INVALID
    }
}

/// Implementation of C_Digest function
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203316](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203316)

pub extern "C" fn fn_digest(
    s_handle: CK_SESSION_HANDLE,
    pdata: CK_BYTE_PTR,
    data_len: CK_ULONG,
    pdigest: CK_BYTE_PTR,
    pul_digest_len: CK_ULONG_PTR,
) -> CK_RV {
    if pdata.is_null() || pul_digest_len.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    let rstate = res_or_ret!(STATE.rlock());
    let mut session = res_or_ret!(rstate.get_session_mut(s_handle));
    let operation = res_or_ret!(session.get_operation::<dyn Digest>());
    let digest_len = res_or_ret!(operation.digest_len());
    let dgst_len = cast_or_ret!(CK_ULONG from digest_len);
    if pdigest.is_null() {
        unsafe {
            *pul_digest_len = dgst_len;
        }
        return CKR_OK;
    }
    unsafe {
        if *pul_digest_len < dgst_len {
            return CKR_BUFFER_TOO_SMALL;
        }
    }
    let dlen = cast_or_ret!(usize from data_len);
    let data: &[u8] = unsafe { std::slice::from_raw_parts(pdata, dlen) };
    let digest: &mut [u8] =
        unsafe { std::slice::from_raw_parts_mut(pdigest, digest_len) };
    let ret = ret_to_rv!(operation.digest(data, digest));
    if ret == CKR_OK {
        unsafe {
            *pul_digest_len = dgst_len;
        }

        #[cfg(feature = "fips")]
        {
            let approved = operation.fips_approved();
            finalize_fips_approval(session, approved);
        }
    }
    ret
}

/// Helper to perform "digest_update" in multiple places,

pub(crate) fn internal_digest_update(
    session: &mut RwLockWriteGuard<'_, Session>,
    part: CK_BYTE_PTR,
    part_len: CK_ULONG,
) -> Result<()> {
    let operation = session.get_operation::<dyn Digest>()?;
    let plen = usize::try_from(part_len).map_err(arg_bad)?;
    let data: &[u8] = unsafe { std::slice::from_raw_parts(part, plen) };
    operation.digest_update(data)
}

/// Implementation of C_DigestUpdate function
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203317](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203317)

pub extern "C" fn fn_digest_update(
    s_handle: CK_SESSION_HANDLE,
    part: CK_BYTE_PTR,
    part_len: CK_ULONG,
) -> CK_RV {
    if part.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    let rstate = res_or_ret!(STATE.rlock());
    let mut session = res_or_ret!(rstate.get_session_mut(s_handle));
    ret_to_rv!(internal_digest_update(&mut session, part, part_len))
}

/// Implementation of C_DigestKey function
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203318](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203318)

pub extern "C" fn fn_digest_key(
    s_handle: CK_SESSION_HANDLE,
    key_handle: CK_OBJECT_HANDLE,
) -> CK_RV {
    let rstate = res_or_ret!(STATE.rlock());
    let mut session = res_or_ret!(rstate.get_session_mut(s_handle));
    let slot_id = session.get_slot_id();
    let operation = res_or_ret!(session.get_operation::<dyn Digest>());
    let mut token = res_or_ret!(rstate.get_token_from_slot_mut(slot_id));
    let key = res_or_ret!(token.get_object_by_handle(key_handle));
    if res_or_ret!(key.get_attr_as_ulong(CKA_CLASS)) != CKO_SECRET_KEY {
        return CKR_KEY_HANDLE_INVALID;
    }
    match res_or_ret!(key.get_attr_as_ulong(CKA_KEY_TYPE)) {
        CKK_GENERIC_SECRET | CKK_AES => (),
        _ => return CKR_KEY_INDIGESTIBLE,
    };

    let data = res_or_ret!(key.get_attr_as_bytes(CKA_VALUE));
    res_or_ret!(operation.digest_update(data));

    #[cfg(feature = "fips")]
    {
        /* need to do this last as we need to drop operation
         * before we can pass session mutably to a caller */
        let mech = res_or_ret!(operation.mechanism());
        init_fips_approval(session, mech, CKF_DIGEST, &key);
    }

    CKR_OK
}

/// Implementation of C_DigestFinal function
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203319](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203319)

pub extern "C" fn fn_digest_final(
    s_handle: CK_SESSION_HANDLE,
    pdigest: CK_BYTE_PTR,
    pul_digest_len: CK_ULONG_PTR,
) -> CK_RV {
    if pul_digest_len.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    let rstate = res_or_ret!(STATE.rlock());
    let mut session = res_or_ret!(rstate.get_session_mut(s_handle));
    let operation = res_or_ret!(session.get_operation::<dyn Digest>());
    let digest_len = res_or_ret!(operation.digest_len());
    let dgst_len = cast_or_ret!(CK_ULONG from digest_len);
    if pdigest.is_null() {
        unsafe {
            *pul_digest_len = dgst_len;
        }
        return CKR_OK;
    }
    unsafe {
        if *pul_digest_len < dgst_len {
            return CKR_BUFFER_TOO_SMALL;
        }
    }
    let digest: &mut [u8] =
        unsafe { std::slice::from_raw_parts_mut(pdigest, digest_len) };
    let ret = ret_to_rv!(operation.digest_final(digest));
    if ret == CKR_OK {
        unsafe {
            *pul_digest_len = dgst_len;
        }

        #[cfg(feature = "fips")]
        {
            let approved = operation.fips_approved();
            finalize_fips_approval(session, approved);
        }
    }
    ret
}
