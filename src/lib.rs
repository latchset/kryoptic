// Copyright 2023 Simo Sorce
// See LICENSE.txt file for terms

use std::sync::RwLock;
use std::ffi::CStr;

mod interface {
    #![allow(non_upper_case_globals)]
    #![allow(non_camel_case_types)]
    #![allow(non_snake_case)]
    #![allow(dead_code)]
    include!("pkcs11_bindings.rs");

    // types that need different mutability than bindgen provides
    pub type CK_FUNCTION_LIST_PTR = *const CK_FUNCTION_LIST;
    pub type CK_FUNCTION_LIST_3_0_PTR = *const CK_FUNCTION_LIST_3_0;
    #[repr(C)]
    #[derive(Debug, Copy, Clone)]
    pub struct CK_INTERFACE {
        pub pInterfaceName: *const CK_CHAR,
        pub pFunctionList: *const ::std::os::raw::c_void,
        pub flags: CK_FLAGS,
    }
}

mod error;
mod slot;
mod token;
mod object;
mod session;

use interface::{CK_RV, CKR_OK, CKR_FUNCTION_NOT_SUPPORTED};
use session::Session;
use error::{KResult, KError};

struct State {
    filename: String,
    slots: Vec<slot::Slot>,
    sessions: Vec<Session>,
    next_handle: interface::CK_SESSION_HANDLE,
}

impl State {
    fn new_session(&mut self, flags: interface::CK_FLAGS) -> KResult<&Session> {
        let handle = self.next_handle;
        self.next_handle += 1;
        let session = match Session::new(handle, flags) {
            Ok(s) => s,
            Err(e) => return Err(e),
        };
        self.sessions.push(session);

        Ok(self.sessions.last().unwrap())
    }

    fn get_session(&self, handle: interface::CK_SESSION_HANDLE) -> KResult<&Session> {
        if handle >= self.next_handle {
            return Err(KError::RvError(error::CkRvError{rv: interface::CKR_SESSION_HANDLE_INVALID}))
        }
        let iter = self.sessions.iter();
        for s in iter {
            let h = s.get_handle();
            if h == handle {
                return Ok(s);
            }
        }
        Err(KError::RvError(error::CkRvError{rv: interface::CKR_SESSION_CLOSED}))
    }

    fn get_session_mut(&mut self, handle: interface::CK_SESSION_HANDLE) -> KResult<&mut Session> {
        if handle >= self.next_handle {
            return Err(KError::RvError(error::CkRvError{rv: interface::CKR_SESSION_HANDLE_INVALID}))
        }
        for s in self.sessions.iter_mut() {
            let h = s.get_handle();
            if h == handle {
                return Ok(s);
            }
        }
        Err(KError::RvError(error::CkRvError{rv: interface::CKR_SESSION_CLOSED}))
    }
}

static STATE: RwLock<State> = RwLock::new(State {
    filename: String::new(),
    slots: Vec::new(),
    sessions: Vec::new(),
    next_handle: 1,
});

extern "C" fn fn_initialize(_init_args: interface::CK_VOID_PTR) -> CK_RV {
    if _init_args.is_null() {
        println!("_init_args is null");
        return interface::CKR_ARGUMENTS_BAD;
    }
    let args = _init_args as *const interface::CK_C_INITIALIZE_ARGS;

    let mut wstate = match STATE.write() {
        Ok(s) => s,
        Err(e) => {
            println!("Can't get state lock {}", e);
            return interface::CKR_GENERAL_ERROR;
        },
    };
    if unsafe {(*args).pReserved.is_null()} {
        println!("reserved arg is null");
        return interface::CKR_ARGUMENTS_BAD;
    }
    let filename = match unsafe {CStr::from_ptr((*args).pReserved as *const _)}.to_str() {
        Ok(f) => f,
        Err(_e) => return interface::CKR_ARGUMENTS_BAD,
    };
    println!("{}", filename.to_string());
    wstate.filename = filename.to_string();
    let slot = match slot::Slot::new(&wstate.filename) {
        Ok(s) => s,
        Err(e) => {
            println!("{}", e);
            match e {
                KError::RvError(e) => return e.rv,
                _ => return interface::CKR_GENERAL_ERROR,
            }
        }
    };
    wstate.slots.push(slot);
    CKR_OK
}
extern "C" fn fn_finalize(_reserved: interface::CK_VOID_PTR) -> CK_RV {
    let rstate = match STATE.read() {
        Ok(s) => s,
        Err(_e) => return interface::CKR_GENERAL_ERROR,
    };
    match rstate.slots[0].token_save(&rstate.filename) {
        Ok(_) => CKR_OK,
        Err(e) => {
            println!("{}", e);
            match e {
                KError::RvError(e) => return e.rv,
                _ => return interface::CKR_GENERAL_ERROR,
            }
        }
    }
}
extern "C" fn fn_get_mechanism_list(
        _slot_id: interface::CK_SLOT_ID,
        _mechanism_list: interface::CK_MECHANISM_TYPE_PTR,
        _pul_count: interface::CK_ULONG_PTR,
    ) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_get_mechanism_info(
        _slot_id: interface::CK_SLOT_ID,
        _type_: interface::CK_MECHANISM_TYPE,
        _info: interface::CK_MECHANISM_INFO_PTR,
    ) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_init_token(
        _slot_id: interface::CK_SLOT_ID,
        _pin: interface::CK_UTF8CHAR_PTR,
        _pin_len: interface::CK_ULONG,
        _label: interface::CK_UTF8CHAR_PTR,
    ) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_init_pin(
        _session: interface::CK_SESSION_HANDLE,
        _pin: interface::CK_UTF8CHAR_PTR,
        _pin_len: interface::CK_ULONG,
    ) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_set_pin(
        _session: interface::CK_SESSION_HANDLE,
        _old_pin: interface::CK_UTF8CHAR_PTR,
        _old_len: interface::CK_ULONG,
        _new_pin: interface::CK_UTF8CHAR_PTR,
        _new_len: interface::CK_ULONG,
    ) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_open_session(
        slot_id: interface::CK_SLOT_ID,
        flags: interface::CK_FLAGS,
        _application: interface::CK_VOID_PTR,
        _notify: interface::CK_NOTIFY,
        ph_session: interface::CK_SESSION_HANDLE_PTR,
    ) -> CK_RV {
    if slot_id != 0 {
        return interface::CKR_SLOT_ID_INVALID;
    }
    let mut wstate = STATE.write().unwrap();
    let session = match wstate.new_session(flags) {
        Ok(s) => s,
        Err(e) => match e {
            KError::RvError(r) => return r.rv,
            _ => return interface::CKR_GENERAL_ERROR,
        },
    };
    unsafe {
        core::ptr::write(ph_session as *mut _, session.get_handle());
    }
    CKR_OK
}
extern "C" fn fn_close_session(_session: interface::CK_SESSION_HANDLE) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_close_all_sessions(_slot_id: interface::CK_SLOT_ID) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_get_session_info(
        _session: interface::CK_SESSION_HANDLE,
        _info: interface::CK_SESSION_INFO_PTR,
    ) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_get_operation_state(
        _session: interface::CK_SESSION_HANDLE,
        _operation_state: interface::CK_BYTE_PTR,
        _pul_operation_state_len: interface::CK_ULONG_PTR,
    ) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_set_operation_state(
        _session: interface::CK_SESSION_HANDLE,
        _operation_state: interface::CK_BYTE_PTR,
        _operation_state_len: interface::CK_ULONG,
        _encryption_key: interface::CK_OBJECT_HANDLE,
        _authentication_key: interface::CK_OBJECT_HANDLE,
    ) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_login(
        _session: interface::CK_SESSION_HANDLE,
        _user_type: interface::CK_USER_TYPE,
        _pin: interface::CK_UTF8CHAR_PTR,
        _pin_len: interface::CK_ULONG,
    ) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_logout(_session: interface::CK_SESSION_HANDLE) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_create_object(
        _session: interface::CK_SESSION_HANDLE,
        _template: interface::CK_ATTRIBUTE_PTR,
        _count: interface::CK_ULONG,
        _ph_object: interface::CK_OBJECT_HANDLE_PTR,
    ) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_copy_object(
        _session: interface::CK_SESSION_HANDLE,
        _object: interface::CK_OBJECT_HANDLE,
        _template: interface::CK_ATTRIBUTE_PTR,
        _count: interface::CK_ULONG,
        _ph_new_object: interface::CK_OBJECT_HANDLE_PTR,
    ) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_destroy_object(
        _session: interface::CK_SESSION_HANDLE,
        _object: interface::CK_OBJECT_HANDLE,
    ) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_get_object_size(
        _session: interface::CK_SESSION_HANDLE,
        _object: interface::CK_OBJECT_HANDLE,
        _pul_size: interface::CK_ULONG_PTR,
    ) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_get_attribute_value(
        _session: interface::CK_SESSION_HANDLE,
        _object: interface::CK_OBJECT_HANDLE,
        _template: interface::CK_ATTRIBUTE_PTR,
        _count: interface::CK_ULONG,
    ) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_set_attribute_value(
        _session: interface::CK_SESSION_HANDLE,
        _object: interface::CK_OBJECT_HANDLE,
        _template: interface::CK_ATTRIBUTE_PTR,
        _count: interface::CK_ULONG,
    ) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_find_objects_init(
        handle: interface::CK_SESSION_HANDLE,
        template: interface::CK_ATTRIBUTE_PTR,
        count: interface::CK_ULONG,
    ) -> CK_RV {
    let mut wstate = STATE.write().unwrap();
    /* check that session is ok */
    match wstate.get_session(handle) {
        Ok(_) => (),
        Err(e) => match e {
            KError::RvError(r) => return r.rv,
            _ => return interface::CKR_GENERAL_ERROR,
        },
    };
    let slot = &wstate.slots[0];

    let tmpl: &[interface::CK_ATTRIBUTE] = unsafe {
        std::slice::from_raw_parts(template, count as usize)
    };

    /* find if specific object class is requested */
    let mut class = interface::CK_UNAVAILABLE_INFORMATION;
    let mut idx = 0;
    while idx < tmpl.len() {
        if tmpl[idx].type_ == interface::CKA_CLASS {
            class = match tmpl[idx].to_ulong() {
                Ok(v) => v,
                Err(e) => match e {
                    KError::RvError(r) => return r.rv,
                    _ => return interface::CKR_GENERAL_ERROR,
                },
            };
            break;
        }
        idx += 1;
    }

    let mut handles = Vec::<interface::CK_OBJECT_HANDLE>::new();
    let res = match class {
        interface::CKO_DATA => { CKR_OK },
        interface::CKO_CERTIFICATE => { CKR_OK },
        interface::CKO_PUBLIC_KEY => {
            slot.search_keys(tmpl, &mut handles)
        },
        interface::CKO_PRIVATE_KEY => {
            slot.search_keys(tmpl, &mut handles)
        },
        interface::CKO_SECRET_KEY => { CKR_OK },
        interface::CKO_HW_FEATURE => { CKR_OK },
        interface::CKO_DOMAIN_PARAMETERS => { CKR_OK },
        interface::CKO_MECHANISM => { CKR_OK },
        interface::CKO_OTP_KEY => { CKR_OK },
        interface::CKO_PROFILE => { CKR_OK },
        _ => {
            slot.search_keys(tmpl, &mut handles)
        },
    };
    if res == CKR_OK {
        let session = match wstate.get_session_mut(handle) {
            Ok(s) => s,
            Err(e) => match e {
                KError::RvError(r) => return r.rv,
                _ => return interface::CKR_GENERAL_ERROR,
            },
        };
        session.reset_object_handles();
        session.append_object_handles(&mut handles);
    }
    res
}

extern "C" fn fn_find_objects(
        handle: interface::CK_SESSION_HANDLE,
        ph_object: interface::CK_OBJECT_HANDLE_PTR,
        max_object_count: interface::CK_ULONG,
        pul_object_count: interface::CK_ULONG_PTR,
    ) -> CK_RV {
    if ph_object.is_null() {
        return interface::CKR_ARGUMENTS_BAD;
    }
    let mut wstate = STATE.write().unwrap();
    let session = match wstate.get_session_mut(handle) {
        Ok(s) => s,
        Err(e) => match e {
            KError::RvError(r) => return r.rv,
            _ => return interface::CKR_GENERAL_ERROR,
        },
    };
    let handles = match session.get_object_handles(max_object_count as usize) {
        Ok(h) => h,
        Err(e) => match e {
            KError::RvError(r) => return r.rv,
            _ => return interface::CKR_GENERAL_ERROR,
        },
    };
    let hlen = handles.len();
    if hlen > 0 {
        let mut idx = 0;
        while idx < hlen {
            unsafe {
                core::ptr::write(ph_object.offset(idx as isize), handles[idx]);
            }
            idx += 1;
        }
    }
    unsafe {
        core::ptr::write(pul_object_count.offset(0), hlen as interface::CK_ULONG);
    }
    CKR_OK
}
extern "C" fn fn_find_objects_final(handle: interface::CK_SESSION_HANDLE) -> CK_RV {
    let mut wstate = STATE.write().unwrap();
    let session = match wstate.get_session_mut(handle) {
        Ok(s) => s,
        Err(e) => match e {
            KError::RvError(r) => return r.rv,
            _ => return interface::CKR_GENERAL_ERROR,
        },
    };
    session.reset_object_handles();
    CKR_OK
}
extern "C" fn fn_encrypt_init(
        _session: interface::CK_SESSION_HANDLE,
        _mechanism: interface::CK_MECHANISM_PTR,
        _key: interface::CK_OBJECT_HANDLE,
    ) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_encrypt(
        _session: interface::CK_SESSION_HANDLE,
        _data: interface::CK_BYTE_PTR,
        _data_len: interface::CK_ULONG,
        _encrypted_data: interface::CK_BYTE_PTR,
        _pul_encrypted_data_len: interface::CK_ULONG_PTR,
    ) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_encrypt_update(
        _session: interface::CK_SESSION_HANDLE,
        _part: interface::CK_BYTE_PTR,
        _part_len: interface::CK_ULONG,
        _encrypted_part: interface::CK_BYTE_PTR,
        _pul_encrypted_part_len: interface::CK_ULONG_PTR,
    ) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_encrypt_final(
        _session: interface::CK_SESSION_HANDLE,
        _last_encrypted_part: interface::CK_BYTE_PTR,
        _pul_last_encrypted_part_len: interface::CK_ULONG_PTR,
    ) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_decrypt_init(
        _session: interface::CK_SESSION_HANDLE,
        _mechanism: interface::CK_MECHANISM_PTR,
        _key: interface::CK_OBJECT_HANDLE,
    ) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_decrypt(
        _session: interface::CK_SESSION_HANDLE,
        _encrypted_data: interface::CK_BYTE_PTR,
        _encrypted_data_len: interface::CK_ULONG,
        _data: interface::CK_BYTE_PTR,
        _pul_data_len: interface::CK_ULONG_PTR,
    ) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_decrypt_update(
        _session: interface::CK_SESSION_HANDLE,
        _encrypted_part: interface::CK_BYTE_PTR,
        _encrypted_part_len: interface::CK_ULONG,
        _part: interface::CK_BYTE_PTR,
        _pul_part_len: interface::CK_ULONG_PTR,
    ) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_decrypt_final(
        _session: interface::CK_SESSION_HANDLE,
        _last_part: interface::CK_BYTE_PTR,
        _pul_last_part_len: interface::CK_ULONG_PTR,
    ) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_digest_init(
        _session: interface::CK_SESSION_HANDLE,
        _mechanism: interface::CK_MECHANISM_PTR,
    ) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_digest(
        _session: interface::CK_SESSION_HANDLE,
        _data: interface::CK_BYTE_PTR,
        _data_len: interface::CK_ULONG,
        _digest: interface::CK_BYTE_PTR,
        _pul_digest_len: interface::CK_ULONG_PTR,
    ) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_digest_update(
        _session: interface::CK_SESSION_HANDLE,
        _part: interface::CK_BYTE_PTR,
        _part_len: interface::CK_ULONG,
    ) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_digest_key(_session: interface::CK_SESSION_HANDLE, _key: interface::CK_OBJECT_HANDLE) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_digest_final(
        _session: interface::CK_SESSION_HANDLE,
        _digest: interface::CK_BYTE_PTR,
        _pul_digest_len: interface::CK_ULONG_PTR,
    ) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_sign_init(
        _session: interface::CK_SESSION_HANDLE,
        _mechanism: interface::CK_MECHANISM_PTR,
        _key: interface::CK_OBJECT_HANDLE,
    ) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_sign(
        _session: interface::CK_SESSION_HANDLE,
        _data: interface::CK_BYTE_PTR,
        _data_len: interface::CK_ULONG,
        _signature: interface::CK_BYTE_PTR,
        _pul_signature_len: interface::CK_ULONG_PTR,
    ) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_sign_update(
        _session: interface::CK_SESSION_HANDLE,
        _part: interface::CK_BYTE_PTR,
        _part_len: interface::CK_ULONG,
    ) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_sign_final(
        _session: interface::CK_SESSION_HANDLE,
        _signature: interface::CK_BYTE_PTR,
        _pul_signature_len: interface::CK_ULONG_PTR,
    ) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_sign_recover_init(
        _session: interface::CK_SESSION_HANDLE,
        _mechanism: interface::CK_MECHANISM_PTR,
        _key: interface::CK_OBJECT_HANDLE,
    ) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_sign_recover(
        _session: interface::CK_SESSION_HANDLE,
        _data: interface::CK_BYTE_PTR,
        _data_len: interface::CK_ULONG,
        _signature: interface::CK_BYTE_PTR,
        _pul_signature_len: interface::CK_ULONG_PTR,
    ) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_verify_init(
        _session: interface::CK_SESSION_HANDLE,
        _mechanism: interface::CK_MECHANISM_PTR,
        _key: interface::CK_OBJECT_HANDLE,
    ) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_verify(
        _session: interface::CK_SESSION_HANDLE,
        _data: interface::CK_BYTE_PTR,
        _data_len: interface::CK_ULONG,
        _signature: interface::CK_BYTE_PTR,
        _signature_len: interface::CK_ULONG,
    ) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_verify_update(
        _session: interface::CK_SESSION_HANDLE,
        _part: interface::CK_BYTE_PTR,
        _part_len: interface::CK_ULONG,
    ) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_verify_final(
        _session: interface::CK_SESSION_HANDLE,
        _signature: interface::CK_BYTE_PTR,
        _signature_len: interface::CK_ULONG,
    ) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_verify_recover_init(
        _session: interface::CK_SESSION_HANDLE,
        _mechanism: interface::CK_MECHANISM_PTR,
        _key: interface::CK_OBJECT_HANDLE,
    ) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_verify_recover(
        _session: interface::CK_SESSION_HANDLE,
        _signature: interface::CK_BYTE_PTR,
        _signature_len: interface::CK_ULONG,
        _data: interface::CK_BYTE_PTR,
        _pul_data_len: interface::CK_ULONG_PTR,
    ) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_digest_encrypt_update(
        _session: interface::CK_SESSION_HANDLE,
        _part: interface::CK_BYTE_PTR,
        _part_len: interface::CK_ULONG,
        _encrypted_part: interface::CK_BYTE_PTR,
        _pul_encrypted_part_len: interface::CK_ULONG_PTR,
    ) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_decrypt_digest_update(
        _session: interface::CK_SESSION_HANDLE,
        _encrypted_part: interface::CK_BYTE_PTR,
        _encrypted_part_len: interface::CK_ULONG,
        _part: interface::CK_BYTE_PTR,
        _pul_part_len: interface::CK_ULONG_PTR,
    ) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_sign_encrypt_update(
        _session: interface::CK_SESSION_HANDLE,
        _part: interface::CK_BYTE_PTR,
        _part_len: interface::CK_ULONG,
        _encrypted_part: interface::CK_BYTE_PTR,
        _pul_encrypted_part_len: interface::CK_ULONG_PTR,
    ) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_decrypt_verify_update(
        _session: interface::CK_SESSION_HANDLE,
        _encrypted_part: interface::CK_BYTE_PTR,
        _encrypted_part_len: interface::CK_ULONG,
        _part: interface::CK_BYTE_PTR,
        _pul_part_len: interface::CK_ULONG_PTR,
    ) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_generate_key(
        _session: interface::CK_SESSION_HANDLE,
        _mechanism: interface::CK_MECHANISM_PTR,
        _template: interface::CK_ATTRIBUTE_PTR,
        _count: interface::CK_ULONG,
        _ph_key: interface::CK_OBJECT_HANDLE_PTR,
    ) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_generate_key_pair(
        _session: interface::CK_SESSION_HANDLE,
        _mechanism: interface::CK_MECHANISM_PTR,
        _public_key_template: interface::CK_ATTRIBUTE_PTR,
        _public_key_attribute_count: interface::CK_ULONG,
        _private_key_template: interface::CK_ATTRIBUTE_PTR,
        _private_key_attribute_count: interface::CK_ULONG,
        _ph_public_key: interface::CK_OBJECT_HANDLE_PTR,
        _ph_private_key: interface::CK_OBJECT_HANDLE_PTR,
    ) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_wrap_key(
        _session: interface::CK_SESSION_HANDLE,
        _mechanism: interface::CK_MECHANISM_PTR,
        _wrapping_key: interface::CK_OBJECT_HANDLE,
        _key: interface::CK_OBJECT_HANDLE,
        _wrapped_key: interface::CK_BYTE_PTR,
        _pul_wrapped_key_len: interface::CK_ULONG_PTR,
    ) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_unwrap_key(
        _session: interface::CK_SESSION_HANDLE,
        _mechanism: interface::CK_MECHANISM_PTR,
        _unwrapping_key: interface::CK_OBJECT_HANDLE,
        _wrapped_key: interface::CK_BYTE_PTR,
        _wrapped_key_len: interface::CK_ULONG,
        _template: interface::CK_ATTRIBUTE_PTR,
        _attribute_count: interface::CK_ULONG,
        _ph_key: interface::CK_OBJECT_HANDLE_PTR,
    ) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_derive_key(
        _session: interface::CK_SESSION_HANDLE,
        _mechanism: interface::CK_MECHANISM_PTR,
        _base_key: interface::CK_OBJECT_HANDLE,
        _template: interface::CK_ATTRIBUTE_PTR,
        _attribute_count: interface::CK_ULONG,
        _ph_key: interface::CK_OBJECT_HANDLE_PTR,
    ) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_seed_random(
        _session: interface::CK_SESSION_HANDLE,
        _seed: interface::CK_BYTE_PTR,
        _seed_len: interface::CK_ULONG,
    ) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_generate_random(
        _session: interface::CK_SESSION_HANDLE,
        _random_data: interface::CK_BYTE_PTR,
        _random_len: interface::CK_ULONG,
    ) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_get_function_status(_session: interface::CK_SESSION_HANDLE) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_cancel_function(_session: interface::CK_SESSION_HANDLE) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_wait_for_slot_event(
        _flags: interface::CK_FLAGS,
        _slot: interface::CK_SLOT_ID_PTR,
        _rserved: interface::CK_VOID_PTR,
    ) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

pub static FNLIST_240: interface::CK_FUNCTION_LIST = interface::CK_FUNCTION_LIST {
    version: interface::CK_VERSION {
        major: 2,
        minor: 40},
    C_Initialize: Some(fn_initialize),
    C_Finalize: Some(fn_finalize),
    C_GetInfo: Some(fn_get_info),
    C_GetFunctionList: Some(C_GetFunctionList),
    C_GetSlotList: Some(fn_get_slot_list),
    C_GetSlotInfo: Some(fn_get_slot_info),
    C_GetTokenInfo: Some(fn_get_token_info),
    C_GetMechanismList: Some(fn_get_mechanism_list),
    C_GetMechanismInfo: Some(fn_get_mechanism_info),
    C_InitToken: Some(fn_init_token),
    C_InitPIN: Some(fn_init_pin),
    C_SetPIN: Some(fn_set_pin),
    C_OpenSession: Some(fn_open_session),
    C_CloseSession: Some(fn_close_session),
    C_CloseAllSessions: Some(fn_close_all_sessions),
    C_GetSessionInfo: Some(fn_get_session_info),
    C_GetOperationState: Some(fn_get_operation_state),
    C_SetOperationState: Some(fn_set_operation_state),
    C_Login: Some(fn_login),
    C_Logout: Some(fn_logout),
    C_CreateObject: Some(fn_create_object),
    C_CopyObject: Some(fn_copy_object),
    C_DestroyObject: Some(fn_destroy_object),
    C_GetObjectSize: Some(fn_get_object_size),
    C_GetAttributeValue: Some(fn_get_attribute_value),
    C_SetAttributeValue: Some(fn_set_attribute_value),
    C_FindObjectsInit: Some(fn_find_objects_init),
    C_FindObjects: Some(fn_find_objects),
    C_FindObjectsFinal: Some(fn_find_objects_final),
    C_EncryptInit: Some(fn_encrypt_init),
    C_Encrypt: Some(fn_encrypt),
    C_EncryptUpdate: Some(fn_encrypt_update),
    C_EncryptFinal: Some(fn_encrypt_final),
    C_DecryptInit: Some(fn_decrypt_init),
    C_Decrypt: Some(fn_decrypt),
    C_DecryptUpdate: Some(fn_decrypt_update),
    C_DecryptFinal: Some(fn_decrypt_final),
    C_DigestInit: Some(fn_digest_init),
    C_Digest: Some(fn_digest),
    C_DigestUpdate: Some(fn_digest_update),
    C_DigestKey: Some(fn_digest_key),
    C_DigestFinal: Some(fn_digest_final),
    C_SignInit: Some(fn_sign_init),
    C_Sign: Some(fn_sign),
    C_SignUpdate: Some(fn_sign_update),
    C_SignFinal: Some(fn_sign_final),
    C_SignRecoverInit: Some(fn_sign_recover_init),
    C_SignRecover: Some(fn_sign_recover),
    C_VerifyInit: Some(fn_verify_init),
    C_Verify: Some(fn_verify),
    C_VerifyUpdate: Some(fn_verify_update),
    C_VerifyFinal: Some(fn_verify_final),
    C_VerifyRecoverInit: Some(fn_verify_recover_init),
    C_VerifyRecover: Some(fn_verify_recover),
    C_DigestEncryptUpdate: Some(fn_digest_encrypt_update),
    C_DecryptDigestUpdate: Some(fn_decrypt_digest_update),
    C_SignEncryptUpdate: Some(fn_sign_encrypt_update),
    C_DecryptVerifyUpdate: Some(fn_decrypt_verify_update),
    C_GenerateKey: Some(fn_generate_key),
    C_GenerateKeyPair: Some(fn_generate_key_pair),
    C_WrapKey: Some(fn_wrap_key),
    C_UnwrapKey: Some(fn_unwrap_key),
    C_DeriveKey: Some(fn_derive_key),
    C_SeedRandom: Some(fn_seed_random),
    C_GenerateRandom: Some(fn_generate_random),
    C_GetFunctionStatus: Some(fn_get_function_status),
    C_CancelFunction: Some(fn_cancel_function),
    C_WaitForSlotEvent: Some(fn_wait_for_slot_event),
};

extern "C" fn fn_get_slot_list(
        _token_present: interface::CK_BBOOL,
        slot_list: interface::CK_SLOT_ID_PTR,
        count: interface::CK_ULONG_PTR,
    ) -> CK_RV {
    if count.is_null() {
        return interface::CKR_ARGUMENTS_BAD;
    }
    // Mock up list for now
    let slotids: &[interface::CK_SLOT_ID] = &[0];

    if slot_list.is_null() {
        unsafe {
            *count = slotids.len() as u64;
        }
        return CKR_OK;
    }
    unsafe {
        let num: interface::CK_ULONG = *count;
        if num < slotids.len() as u64 {
            return interface::CKR_BUFFER_TOO_SMALL;
        }
    }
    for item in slotids.iter().enumerate() {
        let (idx, slotid): (usize, &interface::CK_SLOT_ID) = item;
        unsafe {
            core::ptr::write(slot_list.offset(idx as isize), *slotid);
        }
    }
    unsafe {
        *count = slotids.len() as u64;
    }
    CKR_OK
}

extern "C" fn fn_get_slot_info(slot_id: interface::CK_SLOT_ID, info: interface::CK_SLOT_INFO_PTR) -> CK_RV {
    if slot_id != 0 {
        return interface::CKR_SLOT_ID_INVALID;
    }
    let rstate = STATE.read().unwrap();
    let slot = &rstate.slots[0];
    let slotinfo = slot.get_slot_info();
    unsafe {
        core::ptr::write(info as *mut _, *slotinfo);
    }
    CKR_OK
}

extern "C" fn fn_get_token_info(slot_id: interface::CK_SLOT_ID, info: interface::CK_TOKEN_INFO_PTR) -> CK_RV {
    if slot_id != 0 {
        return interface::CKR_SLOT_ID_INVALID;
    }
    let rstate = STATE.read().unwrap();
    let slot = &rstate.slots[0];
    let tokinfo = slot.get_token_info();
    unsafe {
        core::ptr::write(info as *mut _, tokinfo);
    }
    CKR_OK
}

static IMPLEMENTED_VERSION: interface::CK_VERSION = interface::CK_VERSION { major: 3, minor: 0 };
static MANUFACTURER_ID: [interface::CK_UTF8CHAR; 32usize] = *b"Kryoptic                        ";
static LIBRARY_DESCRIPTION: [interface::CK_UTF8CHAR; 32usize] = *b"Kryoptic PKCS11 Module          ";
static LIBRARY_VERSION: interface::CK_VERSION = interface::CK_VERSION { major: 0, minor: 0 };

static MODULE_INFO: interface::CK_INFO = interface::CK_INFO {
    cryptokiVersion: IMPLEMENTED_VERSION,
    manufacturerID: MANUFACTURER_ID,
    flags: 0,
    libraryDescription: LIBRARY_DESCRIPTION,
    libraryVersion: LIBRARY_VERSION,
};

extern "C" fn fn_get_info(info: interface::CK_INFO_PTR) -> CK_RV {
    unsafe {
        *info = MODULE_INFO;
    }
    CKR_OK
}

#[no_mangle]
pub extern "C" fn C_GetFunctionList(fnlist: interface::CK_FUNCTION_LIST_PTR_PTR) -> CK_RV {
    unsafe {
        *fnlist = &FNLIST_240;
    };
    CKR_OK
}

// Additional 3.0 functions

extern "C" fn fn_login_user(
        _session: interface::CK_SESSION_HANDLE,
        _user_type: interface::CK_USER_TYPE,
        _pin: interface::CK_UTF8CHAR_PTR,
        _pin_len: interface::CK_ULONG,
        _username: interface::CK_UTF8CHAR_PTR,
        _username_len: interface::CK_ULONG,
    ) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_session_cancel(_session: interface::CK_SESSION_HANDLE, _flags: interface::CK_FLAGS) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_message_encrypt_init(
        _session: interface::CK_SESSION_HANDLE,
        _mechanism: interface::CK_MECHANISM_PTR,
        _key: interface::CK_OBJECT_HANDLE,
    ) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_encrypt_message(
        _session: interface::CK_SESSION_HANDLE,
        _parameter: interface::CK_VOID_PTR,
        _parameter_len: interface::CK_ULONG,
        _associated_data: interface::CK_BYTE_PTR,
        _associated_data_len: interface::CK_ULONG,
        _plaintext: interface::CK_BYTE_PTR,
        _plaintext_len: interface::CK_ULONG,
        _ciphertext: interface::CK_BYTE_PTR,
        _pul_ciphertext_len: interface::CK_ULONG_PTR,
    ) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_encrypt_message_begin(
        _session: interface::CK_SESSION_HANDLE,
        _parameter: interface::CK_VOID_PTR,
        _parameter_len: interface::CK_ULONG,
        _associated_data: interface::CK_BYTE_PTR,
        _associated_data_len: interface::CK_ULONG,
    ) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_encrypt_message_next(
        _session: interface::CK_SESSION_HANDLE,
        _parameter: interface::CK_VOID_PTR,
        _parameter_len: interface::CK_ULONG,
        _plaintext_part: interface::CK_BYTE_PTR,
        _plaintext_part_len: interface::CK_ULONG,
        _ciphertext_part: interface::CK_BYTE_PTR,
        _pul_ciphertext_part_len: interface::CK_ULONG_PTR,
        _flags: interface::CK_FLAGS,
    ) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_message_encrypt_final(_session: interface::CK_SESSION_HANDLE) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_message_decrypt_init(
        _session: interface::CK_SESSION_HANDLE,
        _mechanism: interface::CK_MECHANISM_PTR,
        _key: interface::CK_OBJECT_HANDLE,
    ) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_decrypt_message(
        _session: interface::CK_SESSION_HANDLE,
        _parameter: interface::CK_VOID_PTR,
        _parameter_len: interface::CK_ULONG,
        _associated_data: interface::CK_BYTE_PTR,
        _associated_data_len: interface::CK_ULONG,
        _ciphertext: interface::CK_BYTE_PTR,
        _ciphertext_len: interface::CK_ULONG,
        _plaintext: interface::CK_BYTE_PTR,
        _pul_plaintext_len: interface::CK_ULONG_PTR,
    ) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_decrypt_message_begin(
        _session: interface::CK_SESSION_HANDLE,
        _parameter: interface::CK_VOID_PTR,
        _parameter_len: interface::CK_ULONG,
        _associated_data: interface::CK_BYTE_PTR,
        _associated_data_len: interface::CK_ULONG,
    ) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_decrypt_message_next(
        _session: interface::CK_SESSION_HANDLE,
        _parameter: interface::CK_VOID_PTR,
        _parameter_len: interface::CK_ULONG,
        _ciphertext_part: interface::CK_BYTE_PTR,
        _ciphertext_part_len: interface::CK_ULONG,
        _plaintext_part: interface::CK_BYTE_PTR,
        _pul_plaintext_part_len: interface::CK_ULONG_PTR,
        _flags: interface::CK_FLAGS,
    ) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_message_decrypt_final(_session: interface::CK_SESSION_HANDLE) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_message_sign_init(
        _session: interface::CK_SESSION_HANDLE,
        _mechanism: interface::CK_MECHANISM_PTR,
        _key: interface::CK_OBJECT_HANDLE,
    ) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_sign_message(
        _session: interface::CK_SESSION_HANDLE,
        _parameter: interface::CK_VOID_PTR,
        _parameter_len: interface::CK_ULONG,
        _data: interface::CK_BYTE_PTR,
        _data_len: interface::CK_ULONG,
        _signature: interface::CK_BYTE_PTR,
        _pul_signature_len: interface::CK_ULONG_PTR,
    ) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_sign_message_begin(
        _session: interface::CK_SESSION_HANDLE,
        _parameter: interface::CK_VOID_PTR,
        _parameter_len: interface::CK_ULONG,
    ) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_sign_message_next(
        _session: interface::CK_SESSION_HANDLE,
        _parameter: interface::CK_VOID_PTR,
        _parameter_len: interface::CK_ULONG,
        _data: interface::CK_BYTE_PTR,
        _data_len: interface::CK_ULONG,
        _signature: interface::CK_BYTE_PTR,
        _pul_signature_len: interface::CK_ULONG_PTR,
    ) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_message_sign_final(_session: interface::CK_SESSION_HANDLE) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_message_verify_init(
        _session: interface::CK_SESSION_HANDLE,
        _mechanism: interface::CK_MECHANISM_PTR,
        _key: interface::CK_OBJECT_HANDLE,
    ) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_verify_message(
        _session: interface::CK_SESSION_HANDLE,
        _parameter: interface::CK_VOID_PTR,
        _parameter_len: interface::CK_ULONG,
        _data: interface::CK_BYTE_PTR,
        _data_len: interface::CK_ULONG,
        _signature: interface::CK_BYTE_PTR,
        _signature_len: interface::CK_ULONG,
    ) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_verify_message_begin(
        _session: interface::CK_SESSION_HANDLE,
        _parameter: interface::CK_VOID_PTR,
        _parameter_len: interface::CK_ULONG,
    ) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_verify_message_next(
        _session: interface::CK_SESSION_HANDLE,
        _parameter: interface::CK_VOID_PTR,
        _parameter_len: interface::CK_ULONG,
        _data: interface::CK_BYTE_PTR,
        _data_len: interface::CK_ULONG,
        _signature: interface::CK_BYTE_PTR,
        _signature_len: interface::CK_ULONG,
    ) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_message_verify_final(_session: interface::CK_SESSION_HANDLE) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

pub static FNLIST_300: interface::CK_FUNCTION_LIST_3_0 = interface::CK_FUNCTION_LIST_3_0 {
    version: interface::CK_VERSION {
        major: 3,
        minor: 0},
    C_Initialize: Some(fn_initialize),
    C_Finalize: Some(fn_finalize),
    C_GetInfo: Some(fn_get_info),
    C_GetFunctionList: Some(C_GetFunctionList),
    C_GetSlotList: Some(fn_get_slot_list),
    C_GetSlotInfo: Some(fn_get_slot_info),
    C_GetTokenInfo: Some(fn_get_token_info),
    C_GetMechanismList: Some(fn_get_mechanism_list),
    C_GetMechanismInfo: Some(fn_get_mechanism_info),
    C_InitToken: Some(fn_init_token),
    C_InitPIN: Some(fn_init_pin),
    C_SetPIN: Some(fn_set_pin),
    C_OpenSession: Some(fn_open_session),
    C_CloseSession: Some(fn_close_session),
    C_CloseAllSessions: Some(fn_close_all_sessions),
    C_GetSessionInfo: Some(fn_get_session_info),
    C_GetOperationState: Some(fn_get_operation_state),
    C_SetOperationState: Some(fn_set_operation_state),
    C_Login: Some(fn_login),
    C_Logout: Some(fn_logout),
    C_CreateObject: Some(fn_create_object),
    C_CopyObject: Some(fn_copy_object),
    C_DestroyObject: Some(fn_destroy_object),
    C_GetObjectSize: Some(fn_get_object_size),
    C_GetAttributeValue: Some(fn_get_attribute_value),
    C_SetAttributeValue: Some(fn_set_attribute_value),
    C_FindObjectsInit: Some(fn_find_objects_init),
    C_FindObjects: Some(fn_find_objects),
    C_FindObjectsFinal: Some(fn_find_objects_final),
    C_EncryptInit: Some(fn_encrypt_init),
    C_Encrypt: Some(fn_encrypt),
    C_EncryptUpdate: Some(fn_encrypt_update),
    C_EncryptFinal: Some(fn_encrypt_final),
    C_DecryptInit: Some(fn_decrypt_init),
    C_Decrypt: Some(fn_decrypt),
    C_DecryptUpdate: Some(fn_decrypt_update),
    C_DecryptFinal: Some(fn_decrypt_final),
    C_DigestInit: Some(fn_digest_init),
    C_Digest: Some(fn_digest),
    C_DigestUpdate: Some(fn_digest_update),
    C_DigestKey: Some(fn_digest_key),
    C_DigestFinal: Some(fn_digest_final),
    C_SignInit: Some(fn_sign_init),
    C_Sign: Some(fn_sign),
    C_SignUpdate: Some(fn_sign_update),
    C_SignFinal: Some(fn_sign_final),
    C_SignRecoverInit: Some(fn_sign_recover_init),
    C_SignRecover: Some(fn_sign_recover),
    C_VerifyInit: Some(fn_verify_init),
    C_Verify: Some(fn_verify),
    C_VerifyUpdate: Some(fn_verify_update),
    C_VerifyFinal: Some(fn_verify_final),
    C_VerifyRecoverInit: Some(fn_verify_recover_init),
    C_VerifyRecover: Some(fn_verify_recover),
    C_DigestEncryptUpdate: Some(fn_digest_encrypt_update),
    C_DecryptDigestUpdate: Some(fn_decrypt_digest_update),
    C_SignEncryptUpdate: Some(fn_sign_encrypt_update),
    C_DecryptVerifyUpdate: Some(fn_decrypt_verify_update),
    C_GenerateKey: Some(fn_generate_key),
    C_GenerateKeyPair: Some(fn_generate_key_pair),
    C_WrapKey: Some(fn_wrap_key),
    C_UnwrapKey: Some(fn_unwrap_key),
    C_DeriveKey: Some(fn_derive_key),
    C_SeedRandom: Some(fn_seed_random),
    C_GenerateRandom: Some(fn_generate_random),
    C_GetFunctionStatus: Some(fn_get_function_status),
    C_CancelFunction: Some(fn_cancel_function),
    C_WaitForSlotEvent: Some(fn_wait_for_slot_event),
    C_GetInterfaceList: Some(C_GetInterfaceList),
    C_GetInterface: Some(C_GetInterface),
    C_LoginUser: Some(fn_login_user),
    C_SessionCancel: Some(fn_session_cancel),
    C_MessageEncryptInit: Some(fn_message_encrypt_init),
    C_EncryptMessage: Some(fn_encrypt_message),
    C_EncryptMessageBegin: Some(fn_encrypt_message_begin),
    C_EncryptMessageNext: Some(fn_encrypt_message_next),
    C_MessageEncryptFinal: Some(fn_message_encrypt_final),
    C_MessageDecryptInit: Some(fn_message_decrypt_init),
    C_DecryptMessage: Some(fn_decrypt_message),
    C_DecryptMessageBegin: Some(fn_decrypt_message_begin),
    C_DecryptMessageNext: Some(fn_decrypt_message_next),
    C_MessageDecryptFinal: Some(fn_message_decrypt_final),
    C_MessageSignInit: Some(fn_message_sign_init),
    C_SignMessage: Some(fn_sign_message),
    C_SignMessageBegin: Some(fn_sign_message_begin),
    C_SignMessageNext: Some(fn_sign_message_next),
    C_MessageSignFinal: Some(fn_message_sign_final),
    C_MessageVerifyInit: Some(fn_message_verify_init),
    C_VerifyMessage: Some(fn_verify_message),
    C_VerifyMessageBegin: Some(fn_verify_message_begin),
    C_VerifyMessageNext: Some(fn_verify_message_next),
    C_MessageVerifyFinal: Some(fn_message_verify_final),
};

static INTERFACE_NAME_STD: &str = "PKCS 11";
static INTERFACE_NAME_STD_NUL: &str = "PKCS 11\0";

static mut INTERFACE_240: interface::CK_INTERFACE = interface::CK_INTERFACE {
    pInterfaceName: INTERFACE_NAME_STD_NUL.as_ptr() as *mut u8,
    pFunctionList: &FNLIST_240 as *const _ as *const ::std::os::raw::c_void,
    flags: 0,
};

static mut INTERFACE_300: interface::CK_INTERFACE = interface::CK_INTERFACE {
    pInterfaceName: INTERFACE_NAME_STD_NUL.as_ptr() as *mut u8,
    pFunctionList: &FNLIST_300 as *const _ as *const ::std::os::raw::c_void,
    flags: 0,
};

#[no_mangle]
pub extern "C" fn C_GetInterfaceList(
        interfaces_list: interface::CK_INTERFACE_PTR,
        count: interface::CK_ULONG_PTR,
    ) -> CK_RV {
    if count.is_null() {
        return interface::CKR_ARGUMENTS_BAD;
    }
    if interfaces_list.is_null() {
        unsafe {
            *count = 2;
        }
        return CKR_OK;
    }
    unsafe {
        let num: interface::CK_ULONG = *count;
        if num < 2 {
            return interface::CKR_BUFFER_TOO_SMALL;
        }
    }
    unsafe {
        core::ptr::write(interfaces_list.offset(0) as *mut _, INTERFACE_300);
        core::ptr::write(interfaces_list.offset(1) as *mut _, INTERFACE_240);
        *count = 2;
    }
    CKR_OK
}

#[no_mangle]
pub extern "C" fn C_GetInterface(
        interface_name: interface::CK_UTF8CHAR_PTR,
        version: interface::CK_VERSION_PTR,
        interface: interface::CK_INTERFACE_PTR_PTR,
        flags: interface::CK_FLAGS,
    ) -> CK_RV {

    // default to 3.0
    let mut ver: interface::CK_VERSION = interface::CK_VERSION {
        major: 3,
        minor: 0
    };

    if interface.is_null() {
        return interface::CKR_ARGUMENTS_BAD;
    }
    if !interface_name.is_null() {
        let name: &str = unsafe { std::ffi::CStr::from_ptr(interface_name as *const i8).to_str().unwrap() };
        if name != INTERFACE_NAME_STD {
            return interface::CKR_ARGUMENTS_BAD;
        }
    }
    if !version.is_null() {
        unsafe {
            ver.major = (*version).major;
            ver.minor = (*version).minor;
        }
    }
    if flags != 0 {
        return interface::CKR_ARGUMENTS_BAD;
    }

    if ver.major == 3 && ver.minor == 0 {
        unsafe{
            *interface = &mut INTERFACE_300 as *mut _ as *mut interface::CK_INTERFACE;
        }
    } else if ver.major == 2 && ver.minor == 40 {
        unsafe{
            *interface = &mut INTERFACE_240 as *mut _ as *mut interface::CK_INTERFACE;
        }
    } else {
        return interface::CKR_ARGUMENTS_BAD;
    }

    CKR_OK
}

unsafe extern "C" fn dummy_create_mutex(_mutex: *mut *mut std::ffi::c_void) -> CK_RV {
    interface::CKR_GENERAL_ERROR
}

unsafe extern "C" fn dummy_destroy_mutex(_mutex: *mut std::ffi::c_void) -> CK_RV {
    interface::CKR_GENERAL_ERROR
}

unsafe extern "C" fn dummy_lock_mutex(_mutex: *mut std::ffi::c_void) -> CK_RV {
    interface::CKR_GENERAL_ERROR
}

unsafe extern "C" fn dummy_unlock_mutex(_mutex: *mut std::ffi::c_void) -> CK_RV {
    interface::CKR_GENERAL_ERROR
}

#[cfg(test)]
mod tests {
    use std::ffi::CString;
    use super::*;
    #[test]
    fn a_test_token() {

        let test_token = serde_json::json!({
            "key_objects": [{
                "handle": 4030201,
                "class": 2,
                "key_type": 0,
                "attributes": {
                    "CKA_DESTROYABLE": false,
                    "CKA_ID": "AQ==",
                    "CKA_LABEL": "Test RSA Key",
                    "CKA_MODIFIABLE": false,
                    "CKA_MODULUS": "AQIDBAUGBwg=",
                    "CKA_PRIVATE": false,
                    "CKA_PUBLIC_EXPONENT": "AQAB",
                    "CKA_TOKEN": true
                }
            }]
        });
        let file = std::fs::File::create("test.json").unwrap();
        serde_json::to_writer_pretty(file, &test_token).unwrap();

        let mut plist :interface::CK_FUNCTION_LIST_PTR = std::ptr::null_mut();
        let pplist = &mut plist;
        let result = C_GetFunctionList(&mut *pplist);
        assert_eq!(result, 0);
        unsafe {
            let list :interface::CK_FUNCTION_LIST = *plist;
            match list.C_Initialize{
                Some(value) => {
                    let filename = CString::new("test.json");
                    let mut args = interface::CK_C_INITIALIZE_ARGS {
                        CreateMutex: Some(dummy_create_mutex),
                        DestroyMutex: Some(dummy_destroy_mutex),
                        LockMutex: Some(dummy_lock_mutex),
                        UnlockMutex: Some(dummy_unlock_mutex),
                        flags: 0,
                        pReserved: filename.unwrap().into_raw() as *mut std::ffi::c_void,
                    };
                    let mut args_ptr = &mut args as *mut interface::CK_C_INITIALIZE_ARGS;
                    let ret = value(args_ptr as *mut std::ffi::c_void);
                    assert_eq!(ret, CKR_OK)
                }
                None => todo!()
            }
        }
    }

    fn b_test_init_fini() {
        let filename = CString::new("test.json");
        let mut args = interface::CK_C_INITIALIZE_ARGS {
            CreateMutex: Some(dummy_create_mutex),
            DestroyMutex: Some(dummy_destroy_mutex),
            LockMutex: Some(dummy_lock_mutex),
            UnlockMutex: Some(dummy_unlock_mutex),
            flags: 0,
            pReserved: filename.unwrap().into_raw() as *mut std::ffi::c_void,
        };
        let mut args_ptr = &mut args as *mut interface::CK_C_INITIALIZE_ARGS;
        let mut ret = fn_initialize(args_ptr as *mut std::ffi::c_void);
        assert_eq!(ret, CKR_OK);
        ret = fn_finalize(std::ptr::null_mut());
        assert_eq!(ret, CKR_OK);
    }
}
