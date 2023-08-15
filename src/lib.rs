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
mod attribute;

use interface::*;
use session::Session;
use error::{KResult, KError};

macro_rules! err_to_rv {
    ($err:expr) => {
        match $err {
            KError::RvError(e) => e.rv,
            _ => CKR_GENERAL_ERROR,
        }
    }
}

struct State {
    filename: String,
    slots: Vec<slot::Slot>,
    sessions: Vec<Session>,
    next_handle: CK_SESSION_HANDLE,
}

impl State {
    fn new_session(&mut self, slotid: CK_SLOT_ID, flags: CK_FLAGS) -> KResult<&Session> {
        let handle = self.next_handle;
        self.next_handle += 1;
        let session = Session::new(slotid, handle, flags)?;
        self.sessions.push(session);

        Ok(self.sessions.last().unwrap())
    }

    fn get_session(&self, handle: CK_SESSION_HANDLE) -> KResult<&Session> {
        if handle >= self.next_handle {
            return err_rv!(CKR_SESSION_HANDLE_INVALID)
        }
        let iter = self.sessions.iter();
        for s in iter {
            let h = s.get_handle();
            if h == handle {
                return Ok(s);
            }
        }
        err_rv!(CKR_SESSION_CLOSED)
    }

    fn get_session_mut(&mut self, handle: CK_SESSION_HANDLE) -> KResult<&mut Session> {
        if handle >= self.next_handle {
            return err_rv!(CKR_SESSION_HANDLE_INVALID)
        }
        for s in self.sessions.iter_mut() {
            let h = s.get_handle();
            if h == handle {
                return Ok(s);
            }
        }
        err_rv!(CKR_SESSION_CLOSED)
    }

    fn drop_session(&mut self, handle: CK_SESSION_HANDLE) -> KResult<()> {
        if handle >= self.next_handle {
            return err_rv!(CKR_SESSION_HANDLE_INVALID)
        }
        let mut idx = 0;
        while idx < self.sessions.len() {
            if handle == self.sessions[idx].get_handle() {
                self.sessions.swap_remove(idx);
                return Ok(());
            }
            idx += 1;
        }
        err_rv!(CKR_SESSION_CLOSED)
    }

    fn drop_all_sessions(&mut self) {
        self.sessions.clear();
    }
}

static STATE: RwLock<State> = RwLock::new(State {
    filename: String::new(),
    slots: Vec::new(),
    sessions: Vec::new(),
    next_handle: 1,
});

extern "C" fn fn_initialize(_init_args: CK_VOID_PTR) -> CK_RV {
    if _init_args.is_null() {
        println!("_init_args is null");
        return CKR_ARGUMENTS_BAD;
    }
    let args = _init_args as *const CK_C_INITIALIZE_ARGS;

    let mut wstate = match STATE.write() {
        Ok(s) => s,
        Err(e) => {
            println!("Can't get state lock {}", e);
            return CKR_GENERAL_ERROR;
        },
    };
    if unsafe {(*args).pReserved.is_null()} {
        println!("reserved arg is null");
        return CKR_ARGUMENTS_BAD;
    }
    let filename = match unsafe {CStr::from_ptr((*args).pReserved as *const _)}.to_str() {
        Ok(f) => f,
        Err(_e) => return CKR_ARGUMENTS_BAD,
    };
    println!("{}", filename.to_string());
    wstate.filename = filename.to_string();
    let slot = match slot::Slot::new(&wstate.filename) {
        Ok(s) => s,
        Err(e) => return err_to_rv!(e),
    };
    wstate.slots.push(slot);
    CKR_OK
}
extern "C" fn fn_finalize(_reserved: CK_VOID_PTR) -> CK_RV {
    let rstate = match STATE.read() {
        Ok(s) => s,
        Err(_e) => return CKR_GENERAL_ERROR,
    };
    match rstate.slots[0].token_save(&rstate.filename) {
        Ok(_) => CKR_OK,
        Err(e) => return err_to_rv!(e),
    }
}
extern "C" fn fn_get_mechanism_list(
        _slot_id: CK_SLOT_ID,
        _mechanism_list: CK_MECHANISM_TYPE_PTR,
        _pul_count: CK_ULONG_PTR,
    ) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_get_mechanism_info(
        _slot_id: CK_SLOT_ID,
        _type_: CK_MECHANISM_TYPE,
        _info: CK_MECHANISM_INFO_PTR,
    ) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_init_token(
        _slot_id: CK_SLOT_ID,
        _pin: CK_UTF8CHAR_PTR,
        _pin_len: CK_ULONG,
        _label: CK_UTF8CHAR_PTR,
    ) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_init_pin(
        _session: CK_SESSION_HANDLE,
        _pin: CK_UTF8CHAR_PTR,
        _pin_len: CK_ULONG,
    ) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_set_pin(
        _session: CK_SESSION_HANDLE,
        _old_pin: CK_UTF8CHAR_PTR,
        _old_len: CK_ULONG,
        _new_pin: CK_UTF8CHAR_PTR,
        _new_len: CK_ULONG,
    ) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_open_session(
        slot_id: CK_SLOT_ID,
        flags: CK_FLAGS,
        _application: CK_VOID_PTR,
        _notify: CK_NOTIFY,
        ph_session: CK_SESSION_HANDLE_PTR,
    ) -> CK_RV {
    if slot_id != 0 {
        return CKR_SLOT_ID_INVALID;
    }
    let mut wstate = STATE.write().unwrap();
    let session = match wstate.new_session(slot_id, flags) {
        Ok(s) => s,
        Err(e) => return err_to_rv!(e),
    };
    unsafe {
        core::ptr::write(ph_session as *mut _, session.get_handle());
    }
    CKR_OK
}
extern "C" fn fn_close_session(handle: CK_SESSION_HANDLE) -> CK_RV {
    let mut wstate = STATE.write().unwrap();
    match wstate.drop_session(handle) {
        Ok(_) => CKR_OK,
        Err(e) => return err_to_rv!(e),
    }
}
extern "C" fn fn_close_all_sessions(_slot_id: CK_SLOT_ID) -> CK_RV {
    let mut wstate = STATE.write().unwrap();
    wstate.drop_all_sessions();
    CKR_OK
}
extern "C" fn fn_get_session_info(
        handle: CK_SESSION_HANDLE,
        info: CK_SESSION_INFO_PTR,
    ) -> CK_RV {
    let rstate = STATE.read().unwrap();
    let session = match rstate.get_session(handle) {
        Ok(s) => s,
        Err(e) => return err_to_rv!(e),
    };
    unsafe {
        core::ptr::write(info as *mut _, session.get_session_info());
    }
    CKR_OK
}
extern "C" fn fn_get_operation_state(
        _session: CK_SESSION_HANDLE,
        _operation_state: CK_BYTE_PTR,
        _pul_operation_state_len: CK_ULONG_PTR,
    ) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_set_operation_state(
        _session: CK_SESSION_HANDLE,
        _operation_state: CK_BYTE_PTR,
        _operation_state_len: CK_ULONG,
        _encryption_key: CK_OBJECT_HANDLE,
        _authentication_key: CK_OBJECT_HANDLE,
    ) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_login(
        _session: CK_SESSION_HANDLE,
        _user_type: CK_USER_TYPE,
        _pin: CK_UTF8CHAR_PTR,
        _pin_len: CK_ULONG,
    ) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_logout(_session: CK_SESSION_HANDLE) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_create_object(
        _session: CK_SESSION_HANDLE,
        _template: CK_ATTRIBUTE_PTR,
        _count: CK_ULONG,
        _ph_object: CK_OBJECT_HANDLE_PTR,
    ) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_copy_object(
        _session: CK_SESSION_HANDLE,
        _object: CK_OBJECT_HANDLE,
        _template: CK_ATTRIBUTE_PTR,
        _count: CK_ULONG,
        _ph_new_object: CK_OBJECT_HANDLE_PTR,
    ) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_destroy_object(
        _session: CK_SESSION_HANDLE,
        _object: CK_OBJECT_HANDLE,
    ) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_get_object_size(
        _session: CK_SESSION_HANDLE,
        _object: CK_OBJECT_HANDLE,
        _pul_size: CK_ULONG_PTR,
    ) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_get_attribute_value(
        s_handle: CK_SESSION_HANDLE,
        o_handle: CK_OBJECT_HANDLE,
        template: CK_ATTRIBUTE_PTR,
        count: CK_ULONG,
    ) -> CK_RV {
    let rstate = STATE.read().unwrap();
    let session = match rstate.get_session(s_handle) {
        Ok(s) => s,
        Err(e) => return err_to_rv!(e),
    };
    let info = session.get_session_info();
    let slot = &rstate.slots[info.slotID as usize];

    let mut tmpl: &mut [CK_ATTRIBUTE] = unsafe {
        std::slice::from_raw_parts_mut(template, count as usize)
    };

    let token = slot.get_token();

    match token.get_object_attrs(o_handle, &mut tmpl) {
        Ok(_) => CKR_OK,
        Err(e) => return err_to_rv!(e),
    }
}
extern "C" fn fn_set_attribute_value(
        _session: CK_SESSION_HANDLE,
        _object: CK_OBJECT_HANDLE,
        _template: CK_ATTRIBUTE_PTR,
        _count: CK_ULONG,
    ) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_find_objects_init(
        handle: CK_SESSION_HANDLE,
        template: CK_ATTRIBUTE_PTR,
        count: CK_ULONG,
    ) -> CK_RV {
    let mut wstate = STATE.write().unwrap();
    /* check that session is ok */
    match wstate.get_session(handle) {
        Ok(_) => (),
        Err(e) => return err_to_rv!(e),
    };
    let slot = &wstate.slots[0];
    let token = slot.get_token();

    let tmpl: &[CK_ATTRIBUTE] = unsafe {
        std::slice::from_raw_parts(template, count as usize)
    };

    let mut handles = match token.search(tmpl) {
        Ok(h) => h,
        Err(e) => return err_to_rv!(e),
    };
    drop(token);
    let session = match wstate.get_session_mut(handle) {
        Ok(s) => s,
        Err(e) => return err_to_rv!(e),
    };
    session.reset_object_handles();
    session.append_object_handles(&mut handles);
    CKR_OK
}

extern "C" fn fn_find_objects(
        handle: CK_SESSION_HANDLE,
        ph_object: CK_OBJECT_HANDLE_PTR,
        max_object_count: CK_ULONG,
        pul_object_count: CK_ULONG_PTR,
    ) -> CK_RV {
    if ph_object.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    let mut wstate = STATE.write().unwrap();
    let session = match wstate.get_session_mut(handle) {
        Ok(s) => s,
        Err(e) => return err_to_rv!(e),
    };
    let handles = match session.get_object_handles(max_object_count as usize) {
        Ok(h) => h,
        Err(e) => return err_to_rv!(e),
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
        core::ptr::write(pul_object_count.offset(0), hlen as CK_ULONG);
    }
    CKR_OK
}
extern "C" fn fn_find_objects_final(handle: CK_SESSION_HANDLE) -> CK_RV {
    let mut wstate = STATE.write().unwrap();
    let session = match wstate.get_session_mut(handle) {
        Ok(s) => s,
        Err(e) => return err_to_rv!(e),
    };
    session.reset_object_handles();
    CKR_OK
}
extern "C" fn fn_encrypt_init(
        _session: CK_SESSION_HANDLE,
        _mechanism: CK_MECHANISM_PTR,
        _key: CK_OBJECT_HANDLE,
    ) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_encrypt(
        _session: CK_SESSION_HANDLE,
        _data: CK_BYTE_PTR,
        _data_len: CK_ULONG,
        _encrypted_data: CK_BYTE_PTR,
        _pul_encrypted_data_len: CK_ULONG_PTR,
    ) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_encrypt_update(
        _session: CK_SESSION_HANDLE,
        _part: CK_BYTE_PTR,
        _part_len: CK_ULONG,
        _encrypted_part: CK_BYTE_PTR,
        _pul_encrypted_part_len: CK_ULONG_PTR,
    ) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_encrypt_final(
        _session: CK_SESSION_HANDLE,
        _last_encrypted_part: CK_BYTE_PTR,
        _pul_last_encrypted_part_len: CK_ULONG_PTR,
    ) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_decrypt_init(
        _session: CK_SESSION_HANDLE,
        _mechanism: CK_MECHANISM_PTR,
        _key: CK_OBJECT_HANDLE,
    ) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_decrypt(
        _session: CK_SESSION_HANDLE,
        _encrypted_data: CK_BYTE_PTR,
        _encrypted_data_len: CK_ULONG,
        _data: CK_BYTE_PTR,
        _pul_data_len: CK_ULONG_PTR,
    ) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_decrypt_update(
        _session: CK_SESSION_HANDLE,
        _encrypted_part: CK_BYTE_PTR,
        _encrypted_part_len: CK_ULONG,
        _part: CK_BYTE_PTR,
        _pul_part_len: CK_ULONG_PTR,
    ) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_decrypt_final(
        _session: CK_SESSION_HANDLE,
        _last_part: CK_BYTE_PTR,
        _pul_last_part_len: CK_ULONG_PTR,
    ) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_digest_init(
        _session: CK_SESSION_HANDLE,
        _mechanism: CK_MECHANISM_PTR,
    ) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_digest(
        _session: CK_SESSION_HANDLE,
        _data: CK_BYTE_PTR,
        _data_len: CK_ULONG,
        _digest: CK_BYTE_PTR,
        _pul_digest_len: CK_ULONG_PTR,
    ) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_digest_update(
        _session: CK_SESSION_HANDLE,
        _part: CK_BYTE_PTR,
        _part_len: CK_ULONG,
    ) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_digest_key(_session: CK_SESSION_HANDLE, _key: CK_OBJECT_HANDLE) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_digest_final(
        _session: CK_SESSION_HANDLE,
        _digest: CK_BYTE_PTR,
        _pul_digest_len: CK_ULONG_PTR,
    ) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_sign_init(
        _session: CK_SESSION_HANDLE,
        _mechanism: CK_MECHANISM_PTR,
        _key: CK_OBJECT_HANDLE,
    ) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_sign(
        _session: CK_SESSION_HANDLE,
        _data: CK_BYTE_PTR,
        _data_len: CK_ULONG,
        _signature: CK_BYTE_PTR,
        _pul_signature_len: CK_ULONG_PTR,
    ) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_sign_update(
        _session: CK_SESSION_HANDLE,
        _part: CK_BYTE_PTR,
        _part_len: CK_ULONG,
    ) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_sign_final(
        _session: CK_SESSION_HANDLE,
        _signature: CK_BYTE_PTR,
        _pul_signature_len: CK_ULONG_PTR,
    ) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_sign_recover_init(
        _session: CK_SESSION_HANDLE,
        _mechanism: CK_MECHANISM_PTR,
        _key: CK_OBJECT_HANDLE,
    ) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_sign_recover(
        _session: CK_SESSION_HANDLE,
        _data: CK_BYTE_PTR,
        _data_len: CK_ULONG,
        _signature: CK_BYTE_PTR,
        _pul_signature_len: CK_ULONG_PTR,
    ) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_verify_init(
        _session: CK_SESSION_HANDLE,
        _mechanism: CK_MECHANISM_PTR,
        _key: CK_OBJECT_HANDLE,
    ) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_verify(
        _session: CK_SESSION_HANDLE,
        _data: CK_BYTE_PTR,
        _data_len: CK_ULONG,
        _signature: CK_BYTE_PTR,
        _signature_len: CK_ULONG,
    ) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_verify_update(
        _session: CK_SESSION_HANDLE,
        _part: CK_BYTE_PTR,
        _part_len: CK_ULONG,
    ) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_verify_final(
        _session: CK_SESSION_HANDLE,
        _signature: CK_BYTE_PTR,
        _signature_len: CK_ULONG,
    ) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_verify_recover_init(
        _session: CK_SESSION_HANDLE,
        _mechanism: CK_MECHANISM_PTR,
        _key: CK_OBJECT_HANDLE,
    ) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_verify_recover(
        _session: CK_SESSION_HANDLE,
        _signature: CK_BYTE_PTR,
        _signature_len: CK_ULONG,
        _data: CK_BYTE_PTR,
        _pul_data_len: CK_ULONG_PTR,
    ) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_digest_encrypt_update(
        _session: CK_SESSION_HANDLE,
        _part: CK_BYTE_PTR,
        _part_len: CK_ULONG,
        _encrypted_part: CK_BYTE_PTR,
        _pul_encrypted_part_len: CK_ULONG_PTR,
    ) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_decrypt_digest_update(
        _session: CK_SESSION_HANDLE,
        _encrypted_part: CK_BYTE_PTR,
        _encrypted_part_len: CK_ULONG,
        _part: CK_BYTE_PTR,
        _pul_part_len: CK_ULONG_PTR,
    ) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_sign_encrypt_update(
        _session: CK_SESSION_HANDLE,
        _part: CK_BYTE_PTR,
        _part_len: CK_ULONG,
        _encrypted_part: CK_BYTE_PTR,
        _pul_encrypted_part_len: CK_ULONG_PTR,
    ) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_decrypt_verify_update(
        _session: CK_SESSION_HANDLE,
        _encrypted_part: CK_BYTE_PTR,
        _encrypted_part_len: CK_ULONG,
        _part: CK_BYTE_PTR,
        _pul_part_len: CK_ULONG_PTR,
    ) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_generate_key(
        _session: CK_SESSION_HANDLE,
        _mechanism: CK_MECHANISM_PTR,
        _template: CK_ATTRIBUTE_PTR,
        _count: CK_ULONG,
        _ph_key: CK_OBJECT_HANDLE_PTR,
    ) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_generate_key_pair(
        _session: CK_SESSION_HANDLE,
        _mechanism: CK_MECHANISM_PTR,
        _public_key_template: CK_ATTRIBUTE_PTR,
        _public_key_attribute_count: CK_ULONG,
        _private_key_template: CK_ATTRIBUTE_PTR,
        _private_key_attribute_count: CK_ULONG,
        _ph_public_key: CK_OBJECT_HANDLE_PTR,
        _ph_private_key: CK_OBJECT_HANDLE_PTR,
    ) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_wrap_key(
        _session: CK_SESSION_HANDLE,
        _mechanism: CK_MECHANISM_PTR,
        _wrapping_key: CK_OBJECT_HANDLE,
        _key: CK_OBJECT_HANDLE,
        _wrapped_key: CK_BYTE_PTR,
        _pul_wrapped_key_len: CK_ULONG_PTR,
    ) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_unwrap_key(
        _session: CK_SESSION_HANDLE,
        _mechanism: CK_MECHANISM_PTR,
        _unwrapping_key: CK_OBJECT_HANDLE,
        _wrapped_key: CK_BYTE_PTR,
        _wrapped_key_len: CK_ULONG,
        _template: CK_ATTRIBUTE_PTR,
        _attribute_count: CK_ULONG,
        _ph_key: CK_OBJECT_HANDLE_PTR,
    ) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_derive_key(
        _session: CK_SESSION_HANDLE,
        _mechanism: CK_MECHANISM_PTR,
        _base_key: CK_OBJECT_HANDLE,
        _template: CK_ATTRIBUTE_PTR,
        _attribute_count: CK_ULONG,
        _ph_key: CK_OBJECT_HANDLE_PTR,
    ) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_seed_random(
        _session: CK_SESSION_HANDLE,
        _seed: CK_BYTE_PTR,
        _seed_len: CK_ULONG,
    ) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_generate_random(
        _session: CK_SESSION_HANDLE,
        _random_data: CK_BYTE_PTR,
        _random_len: CK_ULONG,
    ) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_get_function_status(_session: CK_SESSION_HANDLE) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_cancel_function(_session: CK_SESSION_HANDLE) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_wait_for_slot_event(
        _flags: CK_FLAGS,
        _slot: CK_SLOT_ID_PTR,
        _rserved: CK_VOID_PTR,
    ) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

pub static FNLIST_240: CK_FUNCTION_LIST = CK_FUNCTION_LIST {
    version: CK_VERSION {
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
        _token_present: CK_BBOOL,
        slot_list: CK_SLOT_ID_PTR,
        count: CK_ULONG_PTR,
    ) -> CK_RV {
    if count.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    // Mock up list for now
    let slotids: &[CK_SLOT_ID] = &[0];

    if slot_list.is_null() {
        unsafe {
            *count = slotids.len() as u64;
        }
        return CKR_OK;
    }
    unsafe {
        let num: CK_ULONG = *count;
        if num < slotids.len() as u64 {
            return CKR_BUFFER_TOO_SMALL;
        }
    }
    for item in slotids.iter().enumerate() {
        let (idx, slotid): (usize, &CK_SLOT_ID) = item;
        unsafe {
            core::ptr::write(slot_list.offset(idx as isize), *slotid);
        }
    }
    unsafe {
        *count = slotids.len() as u64;
    }
    CKR_OK
}

extern "C" fn fn_get_slot_info(slot_id: CK_SLOT_ID, info: CK_SLOT_INFO_PTR) -> CK_RV {
    if slot_id != 0 {
        return CKR_SLOT_ID_INVALID;
    }
    let rstate = STATE.read().unwrap();
    let slot = &rstate.slots[0];
    let slotinfo = slot.get_slot_info();
    unsafe {
        core::ptr::write(info as *mut _, *slotinfo);
    }
    CKR_OK
}

extern "C" fn fn_get_token_info(slot_id: CK_SLOT_ID, info: CK_TOKEN_INFO_PTR) -> CK_RV {
    if slot_id != 0 {
        return CKR_SLOT_ID_INVALID;
    }
    let rstate = STATE.read().unwrap();
    let slot = &rstate.slots[0];
    let tokinfo = slot.get_token_info();
    unsafe {
        core::ptr::write(info as *mut _, tokinfo);
    }
    CKR_OK
}

static IMPLEMENTED_VERSION: CK_VERSION = CK_VERSION { major: 3, minor: 0 };
static MANUFACTURER_ID: [CK_UTF8CHAR; 32usize] = *b"Kryoptic                        ";
static LIBRARY_DESCRIPTION: [CK_UTF8CHAR; 32usize] = *b"Kryoptic PKCS11 Module          ";
static LIBRARY_VERSION: CK_VERSION = CK_VERSION { major: 0, minor: 0 };

static MODULE_INFO: CK_INFO = CK_INFO {
    cryptokiVersion: IMPLEMENTED_VERSION,
    manufacturerID: MANUFACTURER_ID,
    flags: 0,
    libraryDescription: LIBRARY_DESCRIPTION,
    libraryVersion: LIBRARY_VERSION,
};

extern "C" fn fn_get_info(info: CK_INFO_PTR) -> CK_RV {
    unsafe {
        *info = MODULE_INFO;
    }
    CKR_OK
}

#[no_mangle]
pub extern "C" fn C_GetFunctionList(fnlist: CK_FUNCTION_LIST_PTR_PTR) -> CK_RV {
    unsafe {
        *fnlist = &FNLIST_240;
    };
    CKR_OK
}

// Additional 3.0 functions

extern "C" fn fn_login_user(
        _session: CK_SESSION_HANDLE,
        _user_type: CK_USER_TYPE,
        _pin: CK_UTF8CHAR_PTR,
        _pin_len: CK_ULONG,
        _username: CK_UTF8CHAR_PTR,
        _username_len: CK_ULONG,
    ) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_session_cancel(_session: CK_SESSION_HANDLE, _flags: CK_FLAGS) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_message_encrypt_init(
        _session: CK_SESSION_HANDLE,
        _mechanism: CK_MECHANISM_PTR,
        _key: CK_OBJECT_HANDLE,
    ) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_encrypt_message(
        _session: CK_SESSION_HANDLE,
        _parameter: CK_VOID_PTR,
        _parameter_len: CK_ULONG,
        _associated_data: CK_BYTE_PTR,
        _associated_data_len: CK_ULONG,
        _plaintext: CK_BYTE_PTR,
        _plaintext_len: CK_ULONG,
        _ciphertext: CK_BYTE_PTR,
        _pul_ciphertext_len: CK_ULONG_PTR,
    ) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_encrypt_message_begin(
        _session: CK_SESSION_HANDLE,
        _parameter: CK_VOID_PTR,
        _parameter_len: CK_ULONG,
        _associated_data: CK_BYTE_PTR,
        _associated_data_len: CK_ULONG,
    ) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_encrypt_message_next(
        _session: CK_SESSION_HANDLE,
        _parameter: CK_VOID_PTR,
        _parameter_len: CK_ULONG,
        _plaintext_part: CK_BYTE_PTR,
        _plaintext_part_len: CK_ULONG,
        _ciphertext_part: CK_BYTE_PTR,
        _pul_ciphertext_part_len: CK_ULONG_PTR,
        _flags: CK_FLAGS,
    ) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_message_encrypt_final(_session: CK_SESSION_HANDLE) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_message_decrypt_init(
        _session: CK_SESSION_HANDLE,
        _mechanism: CK_MECHANISM_PTR,
        _key: CK_OBJECT_HANDLE,
    ) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_decrypt_message(
        _session: CK_SESSION_HANDLE,
        _parameter: CK_VOID_PTR,
        _parameter_len: CK_ULONG,
        _associated_data: CK_BYTE_PTR,
        _associated_data_len: CK_ULONG,
        _ciphertext: CK_BYTE_PTR,
        _ciphertext_len: CK_ULONG,
        _plaintext: CK_BYTE_PTR,
        _pul_plaintext_len: CK_ULONG_PTR,
    ) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_decrypt_message_begin(
        _session: CK_SESSION_HANDLE,
        _parameter: CK_VOID_PTR,
        _parameter_len: CK_ULONG,
        _associated_data: CK_BYTE_PTR,
        _associated_data_len: CK_ULONG,
    ) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_decrypt_message_next(
        _session: CK_SESSION_HANDLE,
        _parameter: CK_VOID_PTR,
        _parameter_len: CK_ULONG,
        _ciphertext_part: CK_BYTE_PTR,
        _ciphertext_part_len: CK_ULONG,
        _plaintext_part: CK_BYTE_PTR,
        _pul_plaintext_part_len: CK_ULONG_PTR,
        _flags: CK_FLAGS,
    ) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_message_decrypt_final(_session: CK_SESSION_HANDLE) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_message_sign_init(
        _session: CK_SESSION_HANDLE,
        _mechanism: CK_MECHANISM_PTR,
        _key: CK_OBJECT_HANDLE,
    ) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_sign_message(
        _session: CK_SESSION_HANDLE,
        _parameter: CK_VOID_PTR,
        _parameter_len: CK_ULONG,
        _data: CK_BYTE_PTR,
        _data_len: CK_ULONG,
        _signature: CK_BYTE_PTR,
        _pul_signature_len: CK_ULONG_PTR,
    ) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_sign_message_begin(
        _session: CK_SESSION_HANDLE,
        _parameter: CK_VOID_PTR,
        _parameter_len: CK_ULONG,
    ) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_sign_message_next(
        _session: CK_SESSION_HANDLE,
        _parameter: CK_VOID_PTR,
        _parameter_len: CK_ULONG,
        _data: CK_BYTE_PTR,
        _data_len: CK_ULONG,
        _signature: CK_BYTE_PTR,
        _pul_signature_len: CK_ULONG_PTR,
    ) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_message_sign_final(_session: CK_SESSION_HANDLE) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_message_verify_init(
        _session: CK_SESSION_HANDLE,
        _mechanism: CK_MECHANISM_PTR,
        _key: CK_OBJECT_HANDLE,
    ) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_verify_message(
        _session: CK_SESSION_HANDLE,
        _parameter: CK_VOID_PTR,
        _parameter_len: CK_ULONG,
        _data: CK_BYTE_PTR,
        _data_len: CK_ULONG,
        _signature: CK_BYTE_PTR,
        _signature_len: CK_ULONG,
    ) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_verify_message_begin(
        _session: CK_SESSION_HANDLE,
        _parameter: CK_VOID_PTR,
        _parameter_len: CK_ULONG,
    ) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_verify_message_next(
        _session: CK_SESSION_HANDLE,
        _parameter: CK_VOID_PTR,
        _parameter_len: CK_ULONG,
        _data: CK_BYTE_PTR,
        _data_len: CK_ULONG,
        _signature: CK_BYTE_PTR,
        _signature_len: CK_ULONG,
    ) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_message_verify_final(_session: CK_SESSION_HANDLE) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

pub static FNLIST_300: CK_FUNCTION_LIST_3_0 = CK_FUNCTION_LIST_3_0 {
    version: CK_VERSION {
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

static mut INTERFACE_240: CK_INTERFACE = CK_INTERFACE {
    pInterfaceName: INTERFACE_NAME_STD_NUL.as_ptr() as *mut u8,
    pFunctionList: &FNLIST_240 as *const _ as *const ::std::os::raw::c_void,
    flags: 0,
};

static mut INTERFACE_300: CK_INTERFACE = CK_INTERFACE {
    pInterfaceName: INTERFACE_NAME_STD_NUL.as_ptr() as *mut u8,
    pFunctionList: &FNLIST_300 as *const _ as *const ::std::os::raw::c_void,
    flags: 0,
};

#[no_mangle]
pub extern "C" fn C_GetInterfaceList(
        interfaces_list: CK_INTERFACE_PTR,
        count: CK_ULONG_PTR,
    ) -> CK_RV {
    if count.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    if interfaces_list.is_null() {
        unsafe {
            *count = 2;
        }
        return CKR_OK;
    }
    unsafe {
        let num: CK_ULONG = *count;
        if num < 2 {
            return CKR_BUFFER_TOO_SMALL;
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
        interface_name: CK_UTF8CHAR_PTR,
        version: CK_VERSION_PTR,
        interface: CK_INTERFACE_PTR_PTR,
        flags: CK_FLAGS,
    ) -> CK_RV {

    // default to 3.0
    let mut ver: CK_VERSION = CK_VERSION {
        major: 3,
        minor: 0
    };

    if interface.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    if !interface_name.is_null() {
        let name: &str = unsafe { std::ffi::CStr::from_ptr(interface_name as *const i8).to_str().unwrap() };
        if name != INTERFACE_NAME_STD {
            return CKR_ARGUMENTS_BAD;
        }
    }
    if !version.is_null() {
        unsafe {
            ver.major = (*version).major;
            ver.minor = (*version).minor;
        }
    }
    if flags != 0 {
        return CKR_ARGUMENTS_BAD;
    }

    if ver.major == 3 && ver.minor == 0 {
        unsafe{
            *interface = &mut INTERFACE_300 as *mut _ as *mut CK_INTERFACE;
        }
    } else if ver.major == 2 && ver.minor == 40 {
        unsafe{
            *interface = &mut INTERFACE_240 as *mut _ as *mut CK_INTERFACE;
        }
    } else {
        return CKR_ARGUMENTS_BAD;
    }

    CKR_OK
}

unsafe extern "C" fn dummy_create_mutex(_mutex: *mut *mut std::ffi::c_void) -> CK_RV {
    CKR_GENERAL_ERROR
}

unsafe extern "C" fn dummy_destroy_mutex(_mutex: *mut std::ffi::c_void) -> CK_RV {
    CKR_GENERAL_ERROR
}

unsafe extern "C" fn dummy_lock_mutex(_mutex: *mut std::ffi::c_void) -> CK_RV {
    CKR_GENERAL_ERROR
}

unsafe extern "C" fn dummy_unlock_mutex(_mutex: *mut std::ffi::c_void) -> CK_RV {
    CKR_GENERAL_ERROR
}

#[cfg(test)]
mod tests {
    use std::ffi::CString;
    use super::*;
    #[test]
    fn a_test_token() {

        let test_token = serde_json::json!({
            "objects": [{
                "handle": 4030201,
                "attributes": {
                    "CKA_CLASS": 2,
                    "CKA_KEY_TYPE": 0,
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

        let mut plist :CK_FUNCTION_LIST_PTR = std::ptr::null_mut();
        let pplist = &mut plist;
        let result = C_GetFunctionList(&mut *pplist);
        assert_eq!(result, 0);
        unsafe {
            let list :CK_FUNCTION_LIST = *plist;
            match list.C_Initialize{
                Some(value) => {
                    let filename = CString::new("test.json");
                    let mut args = CK_C_INITIALIZE_ARGS {
                        CreateMutex: Some(dummy_create_mutex),
                        DestroyMutex: Some(dummy_destroy_mutex),
                        LockMutex: Some(dummy_lock_mutex),
                        UnlockMutex: Some(dummy_unlock_mutex),
                        flags: 0,
                        pReserved: filename.unwrap().into_raw() as *mut std::ffi::c_void,
                    };
                    let mut args_ptr = &mut args as *mut CK_C_INITIALIZE_ARGS;
                    let ret = value(args_ptr as *mut std::ffi::c_void);
                    assert_eq!(ret, CKR_OK)
                }
                None => todo!()
            }
        }
    }

    fn b_test_init_fini() {
        let filename = CString::new("test.json");
        let mut args = CK_C_INITIALIZE_ARGS {
            CreateMutex: Some(dummy_create_mutex),
            DestroyMutex: Some(dummy_destroy_mutex),
            LockMutex: Some(dummy_lock_mutex),
            UnlockMutex: Some(dummy_unlock_mutex),
            flags: 0,
            pReserved: filename.unwrap().into_raw() as *mut std::ffi::c_void,
        };
        let mut args_ptr = &mut args as *mut CK_C_INITIALIZE_ARGS;
        let mut ret = fn_initialize(args_ptr as *mut std::ffi::c_void);
        assert_eq!(ret, CKR_OK);
        ret = fn_finalize(std::ptr::null_mut());
        assert_eq!(ret, CKR_OK);
    }
}
