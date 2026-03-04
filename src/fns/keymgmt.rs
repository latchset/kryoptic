// Copyright 2026 Simo Sorce
// See LICENSE.txt file for terms

//! Key management functions
//!
//! This module contains the implementation of the Key Management functions
//! as defined in the PKCS#11 specification.

use crate::check_allowed_mechs;
use crate::error::Result;
use crate::log_debug;
use crate::misc::bytes_to_slice;
use crate::object;
use crate::pkcs11::*;
use crate::{fail_if_cka_token_true, STATE};

#[cfg(feature = "fips")]
use crate::fips;

#[inline(always)]
fn generate_key(
    s_handle: CK_SESSION_HANDLE,
    mechptr: CK_MECHANISM_PTR,
    template: CK_ATTRIBUTE_PTR,
    count: CK_ULONG,
    key_handle: CK_OBJECT_HANDLE_PTR,
) -> Result<()> {
    if mechptr.is_null() || template.is_null() || key_handle.is_null() {
        return Err(CKR_ARGUMENTS_BAD)?;
    }

    let rstate = STATE.rlock()?;
    #[cfg(not(feature = "fips"))]
    let session = rstate.get_session(s_handle)?;
    #[cfg(feature = "fips")]
    let mut session = {
        let mut s = rstate.get_session_mut(s_handle)?;
        /* ensure we reset the fips indicator which may be left dirty by
         * a previous operation */
        s.reset_fips_indicator();
        s
    };

    let mechanism: &CK_MECHANISM = unsafe { &*mechptr };
    let cnt = usize::try_from(count).map_err(|_| CKR_GENERAL_ERROR)?;
    let tmpl: &mut [CK_ATTRIBUTE] =
        unsafe { std::slice::from_raw_parts_mut(template, cnt) };
    if !session.is_writable() {
        fail_if_cka_token_true(tmpl)?;
    }

    let slot_id = session.get_slot_id();

    #[cfg(feature = "fips")]
    fips::check_key_template(tmpl, rstate.get_fips_behavior(slot_id)?)?;

    let mut token = rstate.get_token_from_slot_mut(slot_id)?;

    let mechanisms = token.get_mechanisms();
    let factories = token.get_object_factories();
    let mech = mechanisms.get(mechanism.mechanism)?;
    if mech.info().flags & CKF_GENERATE != CKF_GENERATE {
        return Err(CKR_MECHANISM_INVALID)?;
    }

    let key = match mech.generate_key(mechanism, tmpl, mechanisms, factories) {
        #[allow(unused_mut)]
        Ok(mut k) => {
            #[cfg(feature = "fips")]
            session.set_fips_indicator(fips::indicators::is_approved(
                mechanism.mechanism,
                CKF_GENERATE,
                None,
                Some(&mut k),
            ));
            k
        }
        Err(e) => return Err(e)?,
    };

    let kh = token.insert_object(s_handle, key)?;
    unsafe {
        core::ptr::write(key_handle as *mut _, kh);
    }
    Ok(())
}

/// Implementation of C_GenerateKey function
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203352](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203352)
pub extern "C" fn fn_generate_key(
    s_handle: CK_SESSION_HANDLE,
    mechptr: CK_MECHANISM_PTR,
    template: CK_ATTRIBUTE_PTR,
    count: CK_ULONG,
    key_handle: CK_OBJECT_HANDLE_PTR,
) -> CK_RV {
    log_debug!(
        "C_GenerateKey: s_handle={} mechptr={:?} template={:?} count={} key_handle={:?}",
        s_handle,
        mechptr,
        template,
        count,
        key_handle
    );
    let rv = match generate_key(s_handle, mechptr, template, count, key_handle)
    {
        Ok(()) => CKR_OK,
        Err(e) => e.rv(),
    };
    log_debug!("C_GenerateKey: ret={}", rv);
    rv
}

#[inline(always)]
fn generate_key_pair(
    s_handle: CK_SESSION_HANDLE,
    mechptr: CK_MECHANISM_PTR,
    public_key_template: CK_ATTRIBUTE_PTR,
    public_key_attribute_count: CK_ULONG,
    private_key_template: CK_ATTRIBUTE_PTR,
    private_key_attribute_count: CK_ULONG,
    public_key: CK_OBJECT_HANDLE_PTR,
    private_key: CK_OBJECT_HANDLE_PTR,
) -> Result<()> {
    if mechptr.is_null()
        || public_key_template.is_null()
        || private_key_template.is_null()
        || public_key.is_null()
        || private_key.is_null()
    {
        return Err(CKR_ARGUMENTS_BAD)?;
    }

    let rstate = STATE.rlock()?;
    #[cfg(not(feature = "fips"))]
    let session = rstate.get_session(s_handle)?;
    #[cfg(feature = "fips")]
    let mut session = {
        let mut s = rstate.get_session_mut(s_handle)?;
        /* ensure we reset the fips indicator which may be left dirty by
         * a previous operation */
        s.reset_fips_indicator();
        s
    };

    let mechanism: &CK_MECHANISM = unsafe { &*mechptr };
    let pubcnt = usize::try_from(public_key_attribute_count)
        .map_err(|_| CKR_GENERAL_ERROR)?;
    let pubtmpl: &mut [CK_ATTRIBUTE] =
        unsafe { std::slice::from_raw_parts_mut(public_key_template, pubcnt) };
    let pricnt = usize::try_from(private_key_attribute_count)
        .map_err(|_| CKR_GENERAL_ERROR)?;
    let pritmpl: &mut [CK_ATTRIBUTE] =
        unsafe { std::slice::from_raw_parts_mut(private_key_template, pricnt) };
    if !session.is_writable() {
        fail_if_cka_token_true(pritmpl)?;
        fail_if_cka_token_true(pubtmpl)?;
    }

    let slot_id = session.get_slot_id();

    #[cfg(feature = "fips")]
    fips::check_key_template(pritmpl, rstate.get_fips_behavior(slot_id)?)?;

    let mut token = rstate.get_token_from_slot_mut(slot_id)?;

    let mech = token.get_mechanisms().get(mechanism.mechanism)?;
    if mech.info().flags & CKF_GENERATE_KEY_PAIR != CKF_GENERATE_KEY_PAIR {
        return Err(CKR_MECHANISM_INVALID)?;
    }

    let result = mech.generate_keypair(mechanism, pubtmpl, pritmpl);
    match result {
        #[allow(unused_mut)]
        Ok((mut pubkey, mut privkey)) => {
            #[cfg(feature = "fips")]
            {
                let mut approved = fips::indicators::is_approved(
                    mechanism.mechanism,
                    CKF_GENERATE_KEY_PAIR,
                    None,
                    Some(&mut pubkey),
                );
                approved &= fips::indicators::is_approved(
                    mechanism.mechanism,
                    CKF_GENERATE_KEY_PAIR,
                    None,
                    Some(&mut privkey),
                );
                session.set_fips_indicator(approved);
            }
            let pubh = token.insert_object(s_handle, pubkey)?;
            match token.insert_object(s_handle, privkey) {
                Ok(privh) => {
                    unsafe {
                        core::ptr::write(public_key as *mut _, pubh);
                        core::ptr::write(private_key as *mut _, privh);
                    }
                    Ok(())
                }
                Err(e) => {
                    let _ = token.destroy_object(pubh);
                    Err(e)?
                }
            }
        }
        Err(e) => Err(e)?,
    }
}

/// Implementation of C_GenerateKeyPair function
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203353](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203353)
pub extern "C" fn fn_generate_key_pair(
    s_handle: CK_SESSION_HANDLE,
    mechptr: CK_MECHANISM_PTR,
    public_key_template: CK_ATTRIBUTE_PTR,
    public_key_attribute_count: CK_ULONG,
    private_key_template: CK_ATTRIBUTE_PTR,
    private_key_attribute_count: CK_ULONG,
    public_key: CK_OBJECT_HANDLE_PTR,
    private_key: CK_OBJECT_HANDLE_PTR,
) -> CK_RV {
    log_debug!(
        "C_GenerateKeyPair: s_handle={} mechptr={:?} public_key_template={:?} public_key_attribute_count={} private_key_template={:?} private_key_attribute_count={} public_key={:?} private_key={:?}",
        s_handle,
        mechptr,
        public_key_template,
        public_key_attribute_count,
        private_key_template,
        private_key_attribute_count,
        public_key,
        private_key
    );
    let rv = match generate_key_pair(
        s_handle,
        mechptr,
        public_key_template,
        public_key_attribute_count,
        private_key_template,
        private_key_attribute_count,
        public_key,
        private_key,
    ) {
        Ok(()) => CKR_OK,
        Err(e) => e.rv(),
    };
    log_debug!("C_GenerateKeyPair: ret={}", rv);
    rv
}

#[inline(always)]
fn wrap_key(
    s_handle: CK_SESSION_HANDLE,
    mechptr: CK_MECHANISM_PTR,
    wrapping_key_handle: CK_OBJECT_HANDLE,
    key_handle: CK_OBJECT_HANDLE,
    wrapped_key: CK_BYTE_PTR,
    pul_wrapped_key_len: CK_ULONG_PTR,
) -> Result<()> {
    if mechptr.is_null() || pul_wrapped_key_len.is_null() {
        return Err(CKR_ARGUMENTS_BAD)?;
    }

    let rstate = STATE.rlock()?;
    #[cfg(not(feature = "fips"))]
    let session = rstate.get_session(s_handle)?;
    #[cfg(feature = "fips")]
    let mut session = {
        let mut s = rstate.get_session_mut(s_handle)?;
        /* ensure we reset the fips indicator which may be left dirty by
         * a previous operation */
        s.reset_fips_indicator();
        s
    };

    let mechanism: &CK_MECHANISM = unsafe { &*mechptr };
    let slot_id = session.get_slot_id();
    let mut token = rstate.get_token_from_slot_mut(slot_id)?;
    let key = token.get_object_by_handle(key_handle)?;
    let wkey = token.get_object_by_handle(wrapping_key_handle)?;

    match check_allowed_mechs(mechanism, &wkey) {
        CKR_OK => (),
        err => return Err(err)?,
    }

    let factories = token.get_object_factories();
    let factory = factories.get_object_factory(&key)?;
    let mech = token.get_mechanisms().get(mechanism.mechanism)?;
    if mech.info().flags & CKF_WRAP != CKF_WRAP {
        return Err(CKR_MECHANISM_INVALID)?;
    }

    /* key checks */
    if !wkey.get_attr_as_bool(CKA_WRAP)? {
        return Err(CKR_WRAPPING_KEY_HANDLE_INVALID)?;
    }
    let require_trusted = key.get_attr_as_bool(CKA_WRAP_WITH_TRUSTED)?;
    if require_trusted {
        if !wkey.get_attr_as_bool(CKA_TRUSTED)? {
            return Err(CKR_WRAPPING_KEY_HANDLE_INVALID)?;
        }
    }

    let pwraplen = unsafe { *pul_wrapped_key_len as CK_ULONG };
    let wrapped: &mut [u8] = if wrapped_key.is_null() {
        &mut [] /* empty buffer will be always too small */
    } else {
        let wraplen =
            usize::try_from(pwraplen).map_err(|_| CKR_ARGUMENTS_BAD)?;
        unsafe { std::slice::from_raw_parts_mut(wrapped_key, wraplen) }
    };
    let outlen = match mech.wrap_key(mechanism, &wkey, &key, wrapped, factory) {
        Ok(len) => {
            #[cfg(feature = "fips")]
            session.set_fips_indicator(fips::indicators::is_approved(
                mechanism.mechanism,
                CKF_WRAP,
                Some(&wkey),
                None,
            ));
            len
        }
        Err(e) => return Err(e)?,
    };
    let retlen = CK_ULONG::try_from(outlen).map_err(|_| CKR_GENERAL_ERROR)?;
    unsafe { *pul_wrapped_key_len = retlen };
    Ok(())
}

/// Implementation of C_WrapKey function
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203354](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203354)
pub extern "C" fn fn_wrap_key(
    s_handle: CK_SESSION_HANDLE,
    mechptr: CK_MECHANISM_PTR,
    wrapping_key_handle: CK_OBJECT_HANDLE,
    key_handle: CK_OBJECT_HANDLE,
    wrapped_key: CK_BYTE_PTR,
    pul_wrapped_key_len: CK_ULONG_PTR,
) -> CK_RV {
    log_debug!(
        "C_WrapKey: s_handle={} mechptr={:?} wrapping_key_handle={} key_handle={} wrapped_key={:?} pul_wrapped_key_len={:?}",
        s_handle,
        mechptr,
        wrapping_key_handle,
        key_handle,
        wrapped_key,
        pul_wrapped_key_len
    );
    let rv = match wrap_key(
        s_handle,
        mechptr,
        wrapping_key_handle,
        key_handle,
        wrapped_key,
        pul_wrapped_key_len,
    ) {
        Ok(()) => CKR_OK,
        Err(e) => e.rv(),
    };
    log_debug!("C_WrapKey: ret={}", rv);
    rv
}

#[inline(always)]
fn unwrap_key(
    s_handle: CK_SESSION_HANDLE,
    mechptr: CK_MECHANISM_PTR,
    unwrapping_key_handle: CK_OBJECT_HANDLE,
    wrapped_key: CK_BYTE_PTR,
    wrapped_key_len: CK_ULONG,
    template: CK_ATTRIBUTE_PTR,
    attribute_count: CK_ULONG,
    key_handle: CK_OBJECT_HANDLE_PTR,
) -> Result<()> {
    if mechptr.is_null()
        || wrapped_key.is_null()
        || template.is_null()
        || key_handle.is_null()
    {
        return Err(CKR_ARGUMENTS_BAD)?;
    }

    let rstate = STATE.rlock()?;
    #[cfg(not(feature = "fips"))]
    let session = rstate.get_session(s_handle)?;
    #[cfg(feature = "fips")]
    let mut session = {
        let mut s = rstate.get_session_mut(s_handle)?;
        /* ensure we reset the fips indicator which may be left dirty by
         * a previous operation */
        s.reset_fips_indicator();
        s
    };

    let mechanism: &CK_MECHANISM = unsafe { &*mechptr };
    let cnt =
        usize::try_from(attribute_count).map_err(|_| CKR_GENERAL_ERROR)?;
    let tmpl: &mut [CK_ATTRIBUTE] =
        unsafe { std::slice::from_raw_parts_mut(template, cnt) };
    if !session.is_writable() {
        fail_if_cka_token_true(tmpl)?;
    }

    let slot_id = session.get_slot_id();

    #[cfg(feature = "fips")]
    fips::check_key_template(tmpl, rstate.get_fips_behavior(slot_id)?)?;

    let mut token = rstate.get_token_from_slot_mut(slot_id)?;
    let key = token.get_object_by_handle(unwrapping_key_handle)?;

    match check_allowed_mechs(mechanism, &key) {
        CKR_OK => (),
        err => return Err(err)?,
    }

    let factories = token.get_object_factories();
    let factory = factories.get_obj_factory_from_key_template(tmpl)?;
    let wklen =
        usize::try_from(wrapped_key_len).map_err(|_| CKR_GENERAL_ERROR)?;
    let data: &[u8] = unsafe { std::slice::from_raw_parts(wrapped_key, wklen) };
    let mech = token.get_mechanisms().get(mechanism.mechanism)?;
    if mech.info().flags & CKF_WRAP != CKF_WRAP {
        return Err(CKR_MECHANISM_INVALID)?;
    }

    /* key checks */
    if !key.get_attr_as_bool(CKA_UNWRAP)? {
        return Err(CKR_WRAPPING_KEY_HANDLE_INVALID)?;
    }

    let result = mech.unwrap_key(mechanism, &key, data, tmpl, factory);
    match result {
        #[allow(unused_mut)]
        Ok(mut obj) => {
            #[cfg(feature = "fips")]
            session.set_fips_indicator(fips::indicators::is_approved(
                mechanism.mechanism,
                CKF_UNWRAP,
                Some(&key),
                Some(&mut obj),
            ));
            let kh = token.insert_object(s_handle, obj)?;
            unsafe {
                core::ptr::write(key_handle as *mut _, kh);
            }
            Ok(())
        }
        Err(e) => Err(e)?,
    }
}

/// Implementation of C_UnwrapKey function
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203355](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203355)
pub extern "C" fn fn_unwrap_key(
    s_handle: CK_SESSION_HANDLE,
    mechptr: CK_MECHANISM_PTR,
    unwrapping_key_handle: CK_OBJECT_HANDLE,
    wrapped_key: CK_BYTE_PTR,
    wrapped_key_len: CK_ULONG,
    template: CK_ATTRIBUTE_PTR,
    attribute_count: CK_ULONG,
    key_handle: CK_OBJECT_HANDLE_PTR,
) -> CK_RV {
    log_debug!(
        "C_UnwrapKey: s_handle={} mechptr={:?} unwrapping_key_handle={} wrapped_key={:?} wrapped_key_len={} template={:?} attribute_count={} key_handle={:?}",
        s_handle,
        mechptr,
        unwrapping_key_handle,
        wrapped_key,
        wrapped_key_len,
        template,
        attribute_count,
        key_handle
    );
    let rv = match unwrap_key(
        s_handle,
        mechptr,
        unwrapping_key_handle,
        wrapped_key,
        wrapped_key_len,
        template,
        attribute_count,
        key_handle,
    ) {
        Ok(()) => CKR_OK,
        Err(e) => e.rv(),
    };
    log_debug!("C_UnwrapKey: ret={}", rv);
    rv
}

#[inline(always)]
fn derive_key(
    s_handle: CK_SESSION_HANDLE,
    mechptr: CK_MECHANISM_PTR,
    base_key_handle: CK_OBJECT_HANDLE,
    template: CK_ATTRIBUTE_PTR,
    attribute_count: CK_ULONG,
    key_handle: CK_OBJECT_HANDLE_PTR,
) -> Result<()> {
    if mechptr.is_null() || template.is_null() {
        return Err(CKR_ARGUMENTS_BAD)?;
    }

    let rstate = STATE.rlock()?;
    let session = rstate.get_session(s_handle)?;

    let mechanism: &CK_MECHANISM = unsafe { &*mechptr };
    let cnt =
        usize::try_from(attribute_count).map_err(|_| CKR_GENERAL_ERROR)?;
    let tmpl: &mut [CK_ATTRIBUTE] =
        unsafe { std::slice::from_raw_parts_mut(template, cnt) };
    if !session.is_writable() {
        fail_if_cka_token_true(tmpl)?;
    }

    let slot_id = session.get_slot_id();

    #[cfg(feature = "fips")]
    fips::check_key_template(tmpl, rstate.get_fips_behavior(slot_id)?)?;

    let mut token = rstate.get_token_from_slot_mut(slot_id)?;
    let key = token.get_object_by_handle(base_key_handle)?;

    /* key checks
     * NOTE: we avoid checking for CKA_DERIVE for CKM_PUB_KEY_FROM_PRIV_KEY
     * because we think this operation should alays be possible regardless
     * of whether private key should generally allow key derivation. This
     * is our (Kryoptic team) interpretation and may change if/when the
     * OASIS PKCS#11 TC clarifies the spec in this regard */
    if mechanism.mechanism != CKM_PUB_KEY_FROM_PRIV_KEY {
        if !key.get_attr_as_bool(CKA_DERIVE)? {
            return Err(CKR_KEY_FUNCTION_NOT_PERMITTED)?;
        }
    }

    match check_allowed_mechs(mechanism, &key) {
        CKR_OK => (),
        err => return Err(err)?,
    }

    let mech = token.get_mechanisms().get(mechanism.mechanism)?;
    if mech.info().flags & CKF_DERIVE != CKF_DERIVE {
        return Err(CKR_MECHANISM_INVALID)?;
    }

    let mut operation = mech.derive_operation(mechanism)?;

    /* some derive operation requires additional keys */
    match operation.requires_objects() {
        Ok(handles) => {
            let mut objs = Vec::<object::Object>::with_capacity(handles.len());
            for h in handles {
                objs.push(token.get_object_by_handle(*h)?);
            }
            /* shenanigans to deal with borrow checkr on token */
            let mut send = Vec::<&object::Object>::with_capacity(objs.len());
            for o in &objs {
                send.push(o);
            }
            operation.receives_objects(send.as_slice())?;
        }
        Err(e) => match e.rv() {
            CKR_OK => (),
            _ => return Err(e)?,
        },
    }

    let mut result = operation.derive(
        &key,
        tmpl,
        token.get_mechanisms(),
        token.get_object_factories(),
    )?;
    if result.len() == 0 {
        return Err(CKR_GENERAL_ERROR)?;
    }

    #[cfg(feature = "fips")]
    {
        /* must drop here or we deadlock trying to re-acquire for writing */
        drop(session);

        let mut session = rstate.get_session_mut(s_handle)?;
        /* ensure we reset the fips indicator which may be left dirty by
         * a previous operation */
        session.reset_fips_indicator();

        /* op approval, may still change later */
        let mut approval = match operation.fips_approved() {
            Some(s) => s,
            None => true,
        };
        if approval {
            for rkey in &mut result {
                let approved = fips::indicators::is_approved(
                    mechanism.mechanism,
                    CKF_DERIVE,
                    Some(&key),
                    Some(rkey),
                );
                if !approved {
                    approval = false;
                }
            }
        }
        session.set_fips_indicator(approval);
    }

    match mechanism.mechanism {
        CKM_SP800_108_COUNTER_KDF
        | CKM_SP800_108_FEEDBACK_KDF
        | CKM_SP800_108_DOUBLE_PIPELINE_KDF => {
            let kh = token.insert_object(s_handle, result.remove(0))?;
            if result.len() > 0 {
                let adk = match mechanism.mechanism {
                    CKM_SP800_108_COUNTER_KDF => {
                        let params = mechanism
                            .get_parameters::<CK_SP800_108_KDF_PARAMS>()?;
                        unsafe {
                            bytes_to_slice(
                                params.pAdditionalDerivedKeys
                                    as *const CK_DERIVED_KEY,
                                params.ulAdditionalDerivedKeys as usize,
                            )
                        }
                    }
                    CKM_SP800_108_FEEDBACK_KDF => {
                        let params = mechanism
                            .get_parameters::<CK_SP800_108_FEEDBACK_KDF_PARAMS>(
                        )?;
                        unsafe {
                            bytes_to_slice(
                                params.pAdditionalDerivedKeys
                                    as *const CK_DERIVED_KEY,
                                params.ulAdditionalDerivedKeys as usize,
                            )
                        }
                    }

                    _ => return Err(CKR_MECHANISM_INVALID)?,
                };
                if adk.len() != result.len() {
                    return Err(CKR_GENERAL_ERROR)?;
                }
                let mut ah = Vec::<CK_OBJECT_HANDLE>::with_capacity(adk.len());
                let mut iter_result = result.into_iter();
                while let Some(obj) = iter_result.next() {
                    match token.insert_object(s_handle, obj) {
                        Ok(h) => ah.push(h),
                        Err(e) => {
                            for h in ah {
                                let _ = token.destroy_object(h);
                            }
                            let _ = token.destroy_object(kh);
                            return Err(e)?;
                        }
                    }
                }
                for i in 0..adk.len() {
                    unsafe {
                        core::ptr::write(adk[i].phKey, ah[i]);
                    }
                }
            }

            if !key_handle.is_null() {
                unsafe {
                    core::ptr::write(key_handle, kh);
                }
            }
            Ok(())
        }
        CKM_TLS12_KEY_AND_MAC_DERIVE | CKM_TLS12_KEY_SAFE_DERIVE => {
            /* TODO: check that key_handle is NULL ? */
            let params =
                mechanism.get_parameters::<CK_TLS12_KEY_MAT_PARAMS>()?;
            let mat_out = params.pReturnedKeyMaterial;

            match result.len() {
                2 | 4 => (),
                _ => return Err(CKR_GENERAL_ERROR)?,
            }

            let mut ah = Vec::<CK_OBJECT_HANDLE>::with_capacity(result.len());
            let mut iter_result = result.into_iter();
            while let Some(obj) = iter_result.next() {
                match token.insert_object(s_handle, obj) {
                    Ok(h) => ah.push(h),
                    Err(e) => {
                        for h in ah {
                            let _ = token.destroy_object(h);
                        }
                        return Err(e)?;
                    }
                }
            }
            if ah.len() == 4 {
                unsafe {
                    (*mat_out).hClientMacSecret = ah.remove(0);
                    (*mat_out).hServerMacSecret = ah.remove(0);
                }
            }
            unsafe {
                (*mat_out).hClientKey = ah.remove(0);
                (*mat_out).hServerKey = ah.remove(0);
            }
            Ok(())
        }
        _ => {
            if result.len() != 1 {
                return Err(CKR_GENERAL_ERROR)?;
            }
            let kh = token.insert_object(s_handle, result.remove(0))?;
            if !key_handle.is_null() {
                unsafe {
                    core::ptr::write(key_handle, kh);
                }
            }
            Ok(())
        }
    }
}

/// Implementation of C_DeriveKey function
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203356](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203356)
pub extern "C" fn fn_derive_key(
    s_handle: CK_SESSION_HANDLE,
    mechptr: CK_MECHANISM_PTR,
    base_key_handle: CK_OBJECT_HANDLE,
    template: CK_ATTRIBUTE_PTR,
    attribute_count: CK_ULONG,
    key_handle: CK_OBJECT_HANDLE_PTR,
) -> CK_RV {
    log_debug!(
        "C_DeriveKey: s_handle={} mechptr={:?} base_key_handle={} template={:?} attribute_count={} key_handle={:?}",
        s_handle,
        mechptr,
        base_key_handle,
        template,
        attribute_count,
        key_handle
    );
    let rv = match derive_key(
        s_handle,
        mechptr,
        base_key_handle,
        template,
        attribute_count,
        key_handle,
    ) {
        Ok(()) => CKR_OK,
        Err(e) => e.rv(),
    };
    log_debug!("C_DeriveKey: ret={}", rv);
    rv
}

#[inline(always)]
fn encapsulate_key(
    s_handle: CK_SESSION_HANDLE,
    mechptr: *mut CK_MECHANISM,
    pubkey_handle: CK_OBJECT_HANDLE,
    template: *mut CK_ATTRIBUTE,
    attribute_count: CK_ULONG,
    encrypted_part: *mut CK_BYTE,
    encrypted_part_len: *mut CK_ULONG,
    key_handle: *mut CK_OBJECT_HANDLE,
) -> Result<()> {
    if mechptr.is_null()
        || template.is_null()
        || encrypted_part_len.is_null()
        || key_handle.is_null()
    {
        return Err(CKR_ARGUMENTS_BAD)?;
    }

    let rstate = STATE.rlock()?;
    let session = rstate.get_session(s_handle)?;

    let mechanism: &CK_MECHANISM = unsafe { &*mechptr };
    let cnt =
        usize::try_from(attribute_count).map_err(|_| CKR_GENERAL_ERROR)?;
    let tmpl: &[CK_ATTRIBUTE] =
        unsafe { std::slice::from_raw_parts(template, cnt) };
    if !session.is_writable() {
        fail_if_cka_token_true(tmpl)?;
    }

    let penclen = unsafe { *encrypted_part_len as CK_ULONG };
    let enclen = usize::try_from(penclen).map_err(|_| CKR_ARGUMENTS_BAD)?;

    let slot_id = session.get_slot_id();

    #[cfg(feature = "fips")]
    fips::check_key_template(tmpl, rstate.get_fips_behavior(slot_id)?)?;

    let mut token = rstate.get_token_from_slot_mut(slot_id)?;
    let key = token.get_object_by_handle(pubkey_handle)?;
    match check_allowed_mechs(mechanism, &key) {
        CKR_OK => (),
        err => return Err(err)?,
    }
    let factories = token.get_object_factories();
    let factory = factories.get_obj_factory_from_key_template(tmpl)?;
    let mech = token.get_mechanisms().get(mechanism.mechanism)?;
    if mech.info().flags & CKF_ENCAPSULATE != CKF_ENCAPSULATE {
        return Err(CKR_MECHANISM_INVALID)?;
    }

    let ciphertext_len = mech.encapsulate_ciphertext_len(&key)?;
    let ctext_len =
        CK_ULONG::try_from(ciphertext_len).map_err(|_| CKR_GENERAL_ERROR)?;
    if encrypted_part.is_null() {
        unsafe {
            *encrypted_part_len = ctext_len;
        }
        return Ok(());
    }
    if ciphertext_len > enclen {
        return Err(CKR_BUFFER_TOO_SMALL)?;
    }

    let encpart: &mut [u8] =
        unsafe { std::slice::from_raw_parts_mut(encrypted_part, enclen) };

    #[allow(unused_mut)]
    let (mut obj, outlen) =
        mech.encapsulate(mechanism, &key, factory, tmpl, encpart)?;

    #[cfg(feature = "fips")]
    {
        /* must drop here or we deadlock trying to re-acquire for writing */
        drop(session);

        let mut session = rstate.get_session_mut(s_handle)?;
        /* ensure we reset the fips indicator which may be left dirty by
         * a previous operation */
        session.reset_fips_indicator();

        session.set_fips_indicator(fips::indicators::is_approved(
            mechanism.mechanism,
            CKF_ENCAPSULATE,
            Some(&key),
            Some(&mut obj),
        ));
    }
    let retlen = CK_ULONG::try_from(outlen).map_err(|_| CKR_GENERAL_ERROR)?;

    let kh = token.insert_object(s_handle, obj)?;
    unsafe {
        *key_handle = kh;
        *encrypted_part_len = retlen;
    }
    Ok(())
}

/// Implementation of C_EncapsulateKey function
///
/// Version 3.2 Specification: [link TBD]
pub extern "C" fn fn_encapsulate_key(
    s_handle: CK_SESSION_HANDLE,
    mechptr: *mut CK_MECHANISM,
    pubkey_handle: CK_OBJECT_HANDLE,
    template: *mut CK_ATTRIBUTE,
    attribute_count: CK_ULONG,
    encrypted_part: *mut CK_BYTE,
    encrypted_part_len: *mut CK_ULONG,
    key_handle: *mut CK_OBJECT_HANDLE,
) -> CK_RV {
    log_debug!(
        "C_EncapsulateKey: s_handle={} mechptr={:?} pubkey_handle={} template={:?} attribute_count={} encrypted_part={:?} encrypted_part_len={:?} key_handle={:?}",
        s_handle,
        mechptr,
        pubkey_handle,
        template,
        attribute_count,
        encrypted_part,
        encrypted_part_len,
        key_handle
    );
    let rv = match encapsulate_key(
        s_handle,
        mechptr,
        pubkey_handle,
        template,
        attribute_count,
        encrypted_part,
        encrypted_part_len,
        key_handle,
    ) {
        Ok(()) => CKR_OK,
        Err(e) => e.rv(),
    };
    log_debug!("C_EncapsulateKey: ret={}", rv);
    rv
}

#[inline(always)]
fn decapsulate_key(
    s_handle: CK_SESSION_HANDLE,
    mechptr: *mut CK_MECHANISM,
    privkey_handle: CK_OBJECT_HANDLE,
    template: *mut CK_ATTRIBUTE,
    attribute_count: CK_ULONG,
    encrypted_part: *mut CK_BYTE,
    encrypted_part_len: CK_ULONG,
    key_handle: *mut CK_OBJECT_HANDLE,
) -> Result<()> {
    if mechptr.is_null()
        || template.is_null()
        || encrypted_part.is_null()
        || key_handle.is_null()
    {
        return Err(CKR_ARGUMENTS_BAD)?;
    }

    let rstate = STATE.rlock()?;
    let session = rstate.get_session(s_handle)?;

    let mechanism: &CK_MECHANISM = unsafe { &*mechptr };
    let cnt =
        usize::try_from(attribute_count).map_err(|_| CKR_GENERAL_ERROR)?;
    let tmpl: &[CK_ATTRIBUTE] =
        unsafe { std::slice::from_raw_parts(template, cnt) };
    if !session.is_writable() {
        fail_if_cka_token_true(tmpl)?;
    }

    let enclen =
        usize::try_from(encrypted_part_len).map_err(|_| CKR_ARGUMENTS_BAD)?;
    let encpart: &[u8] =
        unsafe { std::slice::from_raw_parts(encrypted_part, enclen) };

    let slot_id = session.get_slot_id();

    #[cfg(feature = "fips")]
    fips::check_key_template(tmpl, rstate.get_fips_behavior(slot_id)?)?;

    let mut token = rstate.get_token_from_slot_mut(slot_id)?;
    let key = token.get_object_by_handle(privkey_handle)?;
    match check_allowed_mechs(mechanism, &key) {
        CKR_OK => (),
        err => return Err(err)?,
    }
    let factories = token.get_object_factories();
    let factory = factories.get_obj_factory_from_key_template(tmpl)?;
    let mech = token.get_mechanisms().get(mechanism.mechanism)?;
    if mech.info().flags & CKF_DECAPSULATE != CKF_DECAPSULATE {
        return Err(CKR_MECHANISM_INVALID)?;
    }

    #[allow(unused_mut)]
    let mut obj = mech.decapsulate(mechanism, &key, factory, tmpl, encpart)?;

    #[cfg(feature = "fips")]
    {
        /* must drop here or we deadlock trying to re-acquire for writing */
        drop(session);

        let mut session = rstate.get_session_mut(s_handle)?;
        /* ensure we reset the fips indicator which may be left dirty by
         * a previous operation */
        session.reset_fips_indicator();

        session.set_fips_indicator(fips::indicators::is_approved(
            mechanism.mechanism,
            CKF_DECAPSULATE,
            Some(&key),
            Some(&mut obj),
        ));
    }

    let kh = token.insert_object(s_handle, obj)?;
    unsafe {
        *key_handle = kh;
    }
    Ok(())
}

/// Implementation of C_DecapsulateKey function
///
/// Version 3.2 Specification: [link TBD]
pub extern "C" fn fn_decapsulate_key(
    s_handle: CK_SESSION_HANDLE,
    mechptr: *mut CK_MECHANISM,
    privkey_handle: CK_OBJECT_HANDLE,
    template: *mut CK_ATTRIBUTE,
    attribute_count: CK_ULONG,
    encrypted_part: *mut CK_BYTE,
    encrypted_part_len: CK_ULONG,
    key_handle: *mut CK_OBJECT_HANDLE,
) -> CK_RV {
    log_debug!(
        "C_DecapsulateKey: s_handle={} mechptr={:?} privkey_handle={} template={:?} attribute_count={} encrypted_part={:?} encrypted_part_len={} key_handle={:?}",
        s_handle,
        mechptr,
        privkey_handle,
        template,
        attribute_count,
        encrypted_part,
        encrypted_part_len,
        key_handle
    );
    let rv = match decapsulate_key(
        s_handle,
        mechptr,
        privkey_handle,
        template,
        attribute_count,
        encrypted_part,
        encrypted_part_len,
        key_handle,
    ) {
        Ok(()) => CKR_OK,
        Err(e) => e.rv(),
    };
    log_debug!("C_DecapsulateKey: ret={}", rv);
    rv
}

pub extern "C" fn fn_wrap_key_authenticated(
    _s_handle: CK_SESSION_HANDLE,
    _mechptr: CK_MECHANISM_PTR,
    _wrapping_key_handle: CK_OBJECT_HANDLE,
    _key_handle: CK_OBJECT_HANDLE,
    _auth_data: CK_BYTE_PTR,
    _auth_data_len: CK_ULONG,
    _wrapped_key: CK_BYTE_PTR,
    _pul_wrapped_key_len: CK_ULONG_PTR,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

pub extern "C" fn fn_unwrap_key_authenticated(
    _s_handle: CK_SESSION_HANDLE,
    _mechptr: CK_MECHANISM_PTR,
    _unwrapping_key_handle: CK_OBJECT_HANDLE,
    _wrapped_key: CK_BYTE_PTR,
    _wrapped_key_len: CK_ULONG,
    _template: CK_ATTRIBUTE_PTR,
    _attribute_count: CK_ULONG,
    _auth_data: CK_BYTE_PTR,
    _auth_data_len: CK_ULONG,
    _key_handle: CK_OBJECT_HANDLE_PTR,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
