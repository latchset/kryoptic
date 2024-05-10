// Copyright 2023 Simo Sorce
// See LICENSE.txt file for terms

use std::cell::RefCell;
use std::collections::HashMap;
use std::env;
use std::ffi::CStr;
use std::str::FromStr;
use std::sync::{RwLock, RwLockReadGuard, RwLockWriteGuard};

use once_cell::sync::Lazy;

mod interface {
    #![allow(non_upper_case_globals)]
    #![allow(non_camel_case_types)]
    #![allow(non_snake_case)]
    #![allow(dead_code)]
    include!("pkcs11/interface.rs");
}

mod attribute;
mod error;
mod mechanism;
mod object;
mod rng;
mod session;
mod slot;
mod storage;
mod token;

use error::{KError, KResult};
use interface::*;
use mechanism::Operation;
use rng::RNG;
use session::Session;
use slot::Slot;
use token::Token;

/* algorithms and ciphers */
#[cfg(feature = "fips")]
mod fips;

#[cfg(not(feature = "fips"))]
mod ossl;

mod aes;
mod drbg;
mod ecc;
mod hash;
mod hmac;
mod kdf;
mod rsa;

/* Helper code */
mod kasn1;

macro_rules! err_to_rv {
    ($err:expr) => {
        match $err {
            KError::RvError(e) => e.rv,
            _ => CKR_GENERAL_ERROR,
        }
    };
}

macro_rules! ret_to_rv {
    ($ret:expr) => {
        match $ret {
            Ok(()) => CKR_OK,
            Err(e) => err_to_rv!(e),
        }
    };
}

macro_rules! res_or_ret {
    ($ret:expr) => {
        match $ret {
            Ok(x) => x,
            Err(e) => return err_to_rv!(e),
        }
    };
}

#[macro_export]
macro_rules! bytes_to_vec {
    ($ptr:expr, $len:expr) => {{
        let ptr = $ptr as *const u8;
        let size = $len as usize;
        let mut v = Vec::<u8>::with_capacity(size);
        unsafe {
            std::ptr::copy_nonoverlapping(ptr, v.as_mut_ptr(), size);
            v.set_len(size);
        }
        v
    }};
}

thread_local!(static CSPRNG: RefCell<RNG> = RefCell::new(RNG::new("HMAC DRBG SHA256").unwrap()));

struct State {
    slots: HashMap<CK_SLOT_ID, Slot>,
    sessionmap: HashMap<CK_SESSION_HANDLE, CK_SLOT_ID>,
    next_handle: CK_ULONG,
}

impl State {
    fn initialize(&mut self) {
        #[cfg(feature = "fips")]
        fips::init();

        self.slots.clear();
        self.sessionmap.clear();
        self.next_handle = 1;
    }

    fn finalize(&mut self) -> CK_RV {
        if !self.is_initialized() {
            return CKR_CRYPTOKI_NOT_INITIALIZED;
        }
        let mut ret = CKR_OK;
        for (_key, slot) in self.slots.iter_mut() {
            let err = ret_to_rv!(slot.finalize());
            /* record the first error only */
            if ret == CKR_OK {
                ret = err;
            }
        }
        self.slots.clear();
        self.sessionmap.clear();
        self.next_handle = 0;
        ret
    }

    fn is_initialized(&self) -> bool {
        self.next_handle != 0
    }

    fn get_slot(&self, slot_id: CK_SLOT_ID) -> KResult<&Slot> {
        if !self.is_initialized() {
            return err_rv!(CKR_CRYPTOKI_NOT_INITIALIZED);
        }
        match self.slots.get(&slot_id) {
            Some(ref s) => Ok(s),
            None => err_rv!(CKR_SLOT_ID_INVALID),
        }
    }

    fn get_slot_mut(&mut self, slot_id: CK_SLOT_ID) -> KResult<&mut Slot> {
        if !self.is_initialized() {
            return err_rv!(CKR_CRYPTOKI_NOT_INITIALIZED);
        }
        match self.slots.get_mut(&slot_id) {
            Some(s) => Ok(s),
            None => err_rv!(CKR_SLOT_ID_INVALID),
        }
    }

    fn get_slots_ids(&self) -> Vec<CK_SLOT_ID> {
        let mut slotids = Vec::<CK_SLOT_ID>::with_capacity(self.slots.len());
        for k in self.slots.keys() {
            slotids.push(*k)
        }
        slotids.sort_unstable();
        slotids
    }

    fn add_slot(&mut self, slot_id: CK_SLOT_ID, slot: Slot) -> CK_RV {
        if self.slots.contains_key(&slot_id) {
            return CKR_CRYPTOKI_ALREADY_INITIALIZED;
        }
        self.slots.insert(slot_id, slot);
        CKR_OK
    }

    fn get_session(
        &self,
        handle: CK_SESSION_HANDLE,
    ) -> KResult<RwLockReadGuard<'_, Session>> {
        let slot_id = match self.sessionmap.get(&handle) {
            Some(s) => *s,
            None => return err_rv!(CKR_SESSION_HANDLE_INVALID),
        };
        self.get_slot(slot_id)?.get_session(handle)
    }

    fn get_session_mut(
        &self,
        handle: CK_SESSION_HANDLE,
    ) -> KResult<RwLockWriteGuard<'_, Session>> {
        let slot_id = match self.sessionmap.get(&handle) {
            Some(s) => *s,
            None => return err_rv!(CKR_SESSION_HANDLE_INVALID),
        };
        self.get_slot(slot_id)?.get_session_mut(handle)
    }

    fn new_session(
        &mut self,
        slot_id: CK_SLOT_ID,
        user_type: CK_USER_TYPE,
        flags: CK_FLAGS,
    ) -> KResult<CK_SESSION_HANDLE> {
        let handle = self.next_handle;
        self.get_slot_mut(slot_id)?
            .add_session(handle, Session::new(slot_id, user_type, flags)?);
        self.sessionmap.insert(handle, slot_id);
        self.next_handle += 1;
        Ok(handle)
    }

    fn has_sessions(&self, slot_id: CK_SLOT_ID) -> KResult<bool> {
        Ok(self.get_slot(slot_id)?.has_sessions())
    }

    fn has_ro_sessions(&self, slot_id: CK_SLOT_ID) -> KResult<bool> {
        Ok(self.get_slot(slot_id)?.has_ro_sessions())
    }

    pub fn change_session_states(
        &self,
        slot_id: CK_SLOT_ID,
        user_type: CK_USER_TYPE,
    ) -> KResult<()> {
        self.get_slot(slot_id)?.change_session_states(user_type)
    }

    pub fn invalidate_session_states(
        &self,
        slot_id: CK_SLOT_ID,
    ) -> KResult<()> {
        self.get_slot(slot_id)?.invalidate_session_states();
        Ok(())
    }

    fn drop_session(&mut self, handle: CK_SESSION_HANDLE) -> KResult<()> {
        let slot_id = match self.sessionmap.get(&handle) {
            Some(s) => *s,
            None => return err_rv!(CKR_SESSION_HANDLE_INVALID),
        };
        self.get_slot_mut(slot_id)?.drop_session(handle);
        self.sessionmap.remove(&handle);
        Ok(())
    }

    fn drop_all_sessions_slot(
        &mut self,
        slot_id: CK_SLOT_ID,
    ) -> KResult<Vec<CK_SESSION_HANDLE>> {
        self.sessionmap.retain(|_key, val| *val != slot_id);
        Ok(self.get_slot_mut(slot_id)?.drop_all_sessions())
    }

    fn get_token_from_slot(
        &self,
        slot_id: CK_SLOT_ID,
    ) -> KResult<RwLockReadGuard<'_, Token>> {
        self.get_slot(slot_id)?.get_token()
    }

    fn get_token_from_slot_mut(
        &self,
        slot_id: CK_SLOT_ID,
    ) -> KResult<RwLockWriteGuard<'_, Token>> {
        self.get_slot(slot_id)?.get_token_mut(false)
    }

    fn get_token_from_slot_mut_nochecks(
        &self,
        slot_id: CK_SLOT_ID,
    ) -> KResult<RwLockWriteGuard<'_, Token>> {
        self.get_slot(slot_id)?.get_token_mut(true)
    }

    fn get_token_from_session(
        &self,
        handle: CK_SESSION_HANDLE,
    ) -> KResult<RwLockReadGuard<'_, Token>> {
        let slot_id = match self.sessionmap.get(&handle) {
            Some(s) => *s,
            None => return err_rv!(CKR_SESSION_HANDLE_INVALID),
        };
        self.get_slot(slot_id)?.get_token()
    }

    fn get_token_from_session_mut(
        &self,
        handle: CK_SESSION_HANDLE,
    ) -> KResult<RwLockWriteGuard<'_, Token>> {
        let slot_id = match self.sessionmap.get(&handle) {
            Some(s) => *s,
            None => return err_rv!(CKR_SESSION_HANDLE_INVALID),
        };
        self.get_slot(slot_id)?.get_token_mut(false)
    }
}

static STATE: Lazy<RwLock<State>> = Lazy::new(|| {
    RwLock::new(State {
        slots: HashMap::new(),
        sessionmap: HashMap::new(),
        next_handle: 0,
    })
});

macro_rules! global_rlock {
    ($GLOBAL:expr) => {
        match $GLOBAL.read() {
            Ok(r) => {
                if (!r.is_initialized()) {
                    return CKR_CRYPTOKI_NOT_INITIALIZED;
                }
                r
            }
            Err(_) => return CKR_GENERAL_ERROR,
        }
    };
}

macro_rules! global_wlock {
    ($GLOBAL:expr) => {{
        match $GLOBAL.write() {
            Ok(w) => {
                if (!w.is_initialized()) {
                    return CKR_CRYPTOKI_NOT_INITIALIZED;
                }
                w
            }
            Err(_) => return CKR_GENERAL_ERROR,
        }
    }};
    (noinitcheck $GLOBAL:expr) => {{
        match $GLOBAL.write() {
            Ok(w) => w,
            Err(_) => return CKR_GENERAL_ERROR,
        }
    }};
}

extern "C" fn fn_initialize(_init_args: CK_VOID_PTR) -> CK_RV {
    let mut slotnum: CK_SLOT_ID = 0;
    let conf: &str;
    let e: String;

    if _init_args.is_null() {
        e = match env::var("KRYOPTIC_CONF") {
            Ok(f) => f,
            Err(_e) => return CKR_ARGUMENTS_BAD,
        };
        conf = &e;
    } else {
        let args = _init_args as *const CK_C_INITIALIZE_ARGS;
        if unsafe { (*args).pReserved.is_null() } {
            e = match env::var("KRYOPTIC_CONF") {
                Ok(f) => f,
                Err(_e) => return CKR_ARGUMENTS_BAD,
            };
            conf = &e;
        } else {
            conf =
                match unsafe { CStr::from_ptr((*args).pReserved as *const _) }
                    .to_str()
                {
                    Ok(f) => f,
                    Err(_e) => return CKR_ARGUMENTS_BAD,
                };
        }
    }

    let v: Vec<&str> = conf.split(':').collect();
    if v.len() > 1 {
        slotnum = match CK_SLOT_ID::from_str(v[1]) {
            Ok(n) => n,
            Err(_) => return CKR_ARGUMENTS_BAD,
        };
    }
    let filename = v[0].to_string();

    let mut wstate = global_wlock!(noinitcheck STATE);
    if !wstate.is_initialized() {
        wstate.initialize();
    }

    /* check that this slot was not already initialized with a different db */
    match wstate.get_token_from_slot(slotnum) {
        Ok(token) => {
            if filename.eq(token.get_filename()) {
                return CKR_CRYPTOKI_ALREADY_INITIALIZED;
            } else {
                return CKR_ARGUMENTS_BAD;
            }
        }
        Err(e) => match e {
            KError::RvError(cke) => match cke.rv {
                CKR_SLOT_ID_INVALID => (),
                CKR_CRYPTOKI_NOT_INITIALIZED => (),
                _ => return cke.rv,
            },
            _ => return CKR_GENERAL_ERROR,
        },
    }

    /* will initialize a memory only token if filename is empty */
    wstate.add_slot(slotnum, res_or_ret!(Slot::new(filename)))
}
extern "C" fn fn_finalize(_reserved: CK_VOID_PTR) -> CK_RV {
    global_wlock!(STATE).finalize()
}

extern "C" fn fn_get_mechanism_list(
    slot_id: CK_SLOT_ID,
    mechanism_list: CK_MECHANISM_TYPE_PTR,
    count: CK_ULONG_PTR,
) -> CK_RV {
    if count.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    let rstate = global_rlock!(STATE);
    let token = res_or_ret!(rstate.get_token_from_slot(slot_id));
    if mechanism_list.is_null() {
        unsafe {
            *count = token.get_mechs_num() as CK_ULONG;
        }
        return CKR_OK;
    }
    let mechs = token.get_mechs_list();
    unsafe {
        let num: CK_ULONG = *count;
        if num < mechs.len() as CK_ULONG {
            return CKR_BUFFER_TOO_SMALL;
        }
    }
    for item in mechs.iter().enumerate() {
        let (idx, mech): (usize, &CK_MECHANISM_TYPE) = item;
        unsafe {
            core::ptr::write(mechanism_list.offset(idx as isize), *mech);
        }
    }
    unsafe {
        *count = mechs.len() as CK_ULONG;
    }
    CKR_OK
}
extern "C" fn fn_get_mechanism_info(
    slot_id: CK_SLOT_ID,
    typ: CK_MECHANISM_TYPE,
    info: CK_MECHANISM_INFO_PTR,
) -> CK_RV {
    let rstate = global_rlock!(STATE);
    let token = res_or_ret!(rstate.get_token_from_slot(slot_id));
    let mech = res_or_ret!(token.get_mech_info(typ));
    unsafe {
        core::ptr::write(info as *mut _, *mech);
    }
    CKR_OK
}
extern "C" fn fn_init_token(
    slot_id: CK_SLOT_ID,
    pin: CK_UTF8CHAR_PTR,
    pin_len: CK_ULONG,
    label: CK_UTF8CHAR_PTR,
) -> CK_RV {
    let rstate = global_rlock!(STATE);
    if res_or_ret!(rstate.has_sessions(slot_id)) {
        return CKR_SESSION_EXISTS;
    }
    let vpin: Vec<u8> = bytes_to_vec!(pin, pin_len);
    let vlabel: Vec<u8> = if label.is_null() {
        vec![0x20 as u8; 32]
    } else {
        bytes_to_vec!(label, 32)
    };
    let mut token =
        res_or_ret!(rstate.get_token_from_slot_mut_nochecks(slot_id));
    token.initialize(&vpin, &vlabel)
}
extern "C" fn fn_init_pin(
    s_handle: CK_SESSION_HANDLE,
    pin: CK_UTF8CHAR_PTR,
    pin_len: CK_ULONG,
) -> CK_RV {
    let rstate = global_rlock!(STATE);
    let mut token = res_or_ret!(rstate.get_token_from_session_mut(s_handle));
    if !token.is_logged_in(CKU_SO) {
        return CKR_USER_NOT_LOGGED_IN;
    }

    let vpin: Vec<u8> = bytes_to_vec!(pin, pin_len);

    token.set_pin(CKU_USER, &vpin, None)
}
extern "C" fn fn_set_pin(
    s_handle: CK_SESSION_HANDLE,
    old_pin: CK_UTF8CHAR_PTR,
    old_len: CK_ULONG,
    new_pin: CK_UTF8CHAR_PTR,
    new_len: CK_ULONG,
) -> CK_RV {
    let rstate = global_rlock!(STATE);
    let session = res_or_ret!(rstate.get_session(s_handle));
    if !session.is_writable() {
        return CKR_SESSION_READ_ONLY;
    }
    let vpin: Vec<u8> = bytes_to_vec!(new_pin, new_len);
    let vold: Vec<u8> = bytes_to_vec!(old_pin, old_len);

    let slot_id = session.get_slot_id();
    let mut token = res_or_ret!(rstate.get_token_from_slot_mut(slot_id));
    token.set_pin(CK_UNAVAILABLE_INFORMATION, &vpin, Some(&vold))
}
extern "C" fn fn_open_session(
    slot_id: CK_SLOT_ID,
    flags: CK_FLAGS,
    _application: CK_VOID_PTR,
    _notify: CK_NOTIFY,
    ph_session: CK_SESSION_HANDLE_PTR,
) -> CK_RV {
    let mut wstate = global_wlock!(STATE);
    let token = res_or_ret!(wstate.get_token_from_slot(slot_id));
    let mut user_type = CK_UNAVAILABLE_INFORMATION;
    if token.is_logged_in(CKU_SO) {
        if flags & CKF_RW_SESSION == 0 {
            return CKR_SESSION_READ_WRITE_SO_EXISTS;
        }
        user_type = CKU_SO;
    } else if token.is_logged_in(CKU_USER) {
        user_type = CKU_USER;
    }
    drop(token);
    let handle = res_or_ret!(wstate.new_session(slot_id, user_type, flags));
    unsafe {
        core::ptr::write(ph_session as *mut _, handle);
    }
    CKR_OK
}
extern "C" fn fn_close_session(s_handle: CK_SESSION_HANDLE) -> CK_RV {
    let mut wstate = global_wlock!(STATE);
    let mut token = res_or_ret!(wstate.get_token_from_session_mut(s_handle));
    token.drop_session_objects(s_handle);
    drop(token);
    let _ = res_or_ret!(wstate.drop_session(s_handle));
    CKR_OK
}
extern "C" fn fn_close_all_sessions(slot_id: CK_SLOT_ID) -> CK_RV {
    let mut wstate = global_wlock!(STATE);
    let dropped_sessions = res_or_ret!(wstate.drop_all_sessions_slot(slot_id));
    let mut token = res_or_ret!(wstate.get_token_from_slot_mut(slot_id));
    for handle in dropped_sessions {
        token.drop_session_objects(handle);
    }
    CKR_OK
}
extern "C" fn fn_get_session_info(
    s_handle: CK_SESSION_HANDLE,
    info: CK_SESSION_INFO_PTR,
) -> CK_RV {
    let rstate = global_rlock!(STATE);
    let session = res_or_ret!(rstate.get_session(s_handle));
    unsafe {
        core::ptr::write(info as *mut _, *session.get_session_info());
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
    s_handle: CK_SESSION_HANDLE,
    user_type: CK_USER_TYPE,
    pin: CK_UTF8CHAR_PTR,
    pin_len: CK_ULONG,
) -> CK_RV {
    let rstate = global_rlock!(STATE);
    let session = res_or_ret!(rstate.get_session(s_handle));
    let slot_id = session.get_slot_id();
    /* avoid deadlock later when we change all sessions */
    drop(session);
    if user_type == CKU_SO {
        if res_or_ret!(rstate.has_ro_sessions(slot_id)) {
            return CKR_SESSION_READ_ONLY_EXISTS;
        }
    }
    let vpin: Vec<u8> = bytes_to_vec!(pin, pin_len);
    let mut token = res_or_ret!(rstate.get_token_from_slot_mut(slot_id));
    match token.login(user_type, &vpin) {
        CKR_OK => match rstate.change_session_states(slot_id, user_type) {
            Ok(()) => CKR_OK,
            Err(e) => {
                token.logout();
                let _ = rstate.invalidate_session_states(slot_id);
                err_to_rv!(e)
            }
        },
        err => err,
    }
}
extern "C" fn fn_logout(s_handle: CK_SESSION_HANDLE) -> CK_RV {
    let rstate = global_rlock!(STATE);
    let session = res_or_ret!(rstate.get_session(s_handle));
    let slot_id = session.get_slot_id();
    /* avoid deadlock later when we change all sessions */
    drop(session);
    let mut token = res_or_ret!(rstate.get_token_from_slot_mut(slot_id));
    let ret = token.logout();
    if ret == CKR_OK {
        let _ = rstate.invalidate_session_states(slot_id);
    }
    ret
}

macro_rules! fail_if_cka_token_true {
    ($template:expr) => {
        for ck_attr in $template {
            if ck_attr.type_ == CKA_TOKEN {
                if res_or_ret!(ck_attr.to_bool()) {
                    return CKR_SESSION_READ_ONLY;
                }
            }
        }
    };
}

extern "C" fn fn_create_object(
    s_handle: CK_SESSION_HANDLE,
    template: CK_ATTRIBUTE_PTR,
    count: CK_ULONG,
    object_handle: CK_OBJECT_HANDLE_PTR,
) -> CK_RV {
    let rstate = global_rlock!(STATE);
    let session = res_or_ret!(rstate.get_session(s_handle));
    let tmpl: &mut [CK_ATTRIBUTE] =
        unsafe { std::slice::from_raw_parts_mut(template, count as usize) };
    if !session.is_writable() {
        fail_if_cka_token_true!(&*tmpl);
    }
    let slot_id = session.get_slot_id();
    let mut token = res_or_ret!(rstate.get_token_from_slot_mut(slot_id));

    let oh = match token.create_object(s_handle, tmpl) {
        Ok(h) => h,
        Err(e) => return err_to_rv!(e),
    };

    unsafe {
        core::ptr::write(object_handle as *mut _, oh);
    }

    CKR_OK
}
extern "C" fn fn_copy_object(
    s_handle: CK_SESSION_HANDLE,
    o_handle: CK_OBJECT_HANDLE,
    template: CK_ATTRIBUTE_PTR,
    count: CK_ULONG,
    ph_new_object: CK_OBJECT_HANDLE_PTR,
) -> CK_RV {
    let rstate = global_rlock!(STATE);
    let session = res_or_ret!(rstate.get_session(s_handle));
    let tmpl: &mut [CK_ATTRIBUTE] =
        unsafe { std::slice::from_raw_parts_mut(template, count as usize) };
    if !session.is_writable() {
        fail_if_cka_token_true!(&*tmpl);
    }
    let slot_id = session.get_slot_id();
    let mut token = res_or_ret!(rstate.get_token_from_slot_mut(slot_id));

    /* TODO: return CKR_ACTION_PROHIBITED instead of CKR_USER_NOT_LOGGED_IN ? */
    let oh = res_or_ret!(token.copy_object(s_handle, o_handle, tmpl));

    unsafe {
        core::ptr::write(ph_new_object as *mut _, oh);
    }

    CKR_OK
}
extern "C" fn fn_destroy_object(
    s_handle: CK_SESSION_HANDLE,
    o_handle: CK_OBJECT_HANDLE,
) -> CK_RV {
    let rstate = global_rlock!(STATE);
    let session = res_or_ret!(rstate.get_session(s_handle));
    let slot_id = session.get_slot_id();
    let mut token = res_or_ret!(rstate.get_token_from_slot_mut(slot_id));
    /* TODO: return CKR_ACTION_PROHIBITED instead of CKR_USER_NOT_LOGGED_IN ? */
    let obj = res_or_ret!(token.get_object_by_handle(o_handle));
    if obj.is_token() && !session.is_writable() {
        return CKR_ACTION_PROHIBITED;
    }
    ret_to_rv!(token.destroy_object(o_handle))
}

extern "C" fn fn_get_object_size(
    s_handle: CK_SESSION_HANDLE,
    o_handle: CK_OBJECT_HANDLE,
    size: CK_ULONG_PTR,
) -> CK_RV {
    let rstate = global_rlock!(STATE);
    let token = res_or_ret!(rstate.get_token_from_session(s_handle));
    let len = res_or_ret!(token.get_object_size(o_handle));
    unsafe {
        *size = len as CK_ULONG;
    }
    CKR_OK
}

extern "C" fn fn_get_attribute_value(
    s_handle: CK_SESSION_HANDLE,
    o_handle: CK_OBJECT_HANDLE,
    template: CK_ATTRIBUTE_PTR,
    count: CK_ULONG,
) -> CK_RV {
    let rstate = global_rlock!(STATE);
    let mut token = res_or_ret!(rstate.get_token_from_session_mut(s_handle));
    let mut tmpl: &mut [CK_ATTRIBUTE] =
        unsafe { std::slice::from_raw_parts_mut(template, count as usize) };
    ret_to_rv!(token.get_object_attrs(o_handle, &mut tmpl))
}
extern "C" fn fn_set_attribute_value(
    s_handle: CK_SESSION_HANDLE,
    o_handle: CK_OBJECT_HANDLE,
    template: CK_ATTRIBUTE_PTR,
    count: CK_ULONG,
) -> CK_RV {
    let rstate = global_rlock!(STATE);
    let session = res_or_ret!(rstate.get_session(s_handle));
    let slot_id = session.get_slot_id();
    let mut token = res_or_ret!(rstate.get_token_from_slot_mut(slot_id));
    let obj = res_or_ret!(token.get_object_by_handle(o_handle));
    if obj.is_token() {
        if !token.is_logged_in(KRY_UNSPEC) {
            return CKR_USER_NOT_LOGGED_IN;
        }
        if !session.is_writable() {
            return CKR_SESSION_READ_ONLY;
        }
    }
    let mut tmpl: &mut [CK_ATTRIBUTE] =
        unsafe { std::slice::from_raw_parts_mut(template, count as usize) };
    ret_to_rv!(token.set_object_attrs(o_handle, &mut tmpl))
}
extern "C" fn fn_find_objects_init(
    s_handle: CK_SESSION_HANDLE,
    template: CK_ATTRIBUTE_PTR,
    count: CK_ULONG,
) -> CK_RV {
    let rstate = global_rlock!(STATE);
    let mut session = res_or_ret!(rstate.get_session_mut(s_handle));
    let slot_id = session.get_slot_id();
    let mut token = res_or_ret!(rstate.get_token_from_slot_mut(slot_id));
    let tmpl: &[CK_ATTRIBUTE] =
        unsafe { std::slice::from_raw_parts(template, count as usize) };
    ret_to_rv!(session.new_search_operation(&mut token, tmpl))
}

extern "C" fn fn_find_objects(
    s_handle: CK_SESSION_HANDLE,
    ph_object: CK_OBJECT_HANDLE_PTR,
    max_object_count: CK_ULONG,
    pul_object_count: CK_ULONG_PTR,
) -> CK_RV {
    if ph_object.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    let rstate = global_rlock!(STATE);
    let mut session = res_or_ret!(rstate.get_session_mut(s_handle));
    let operation = match session.get_operation_mut() {
        Operation::Search(op) => op,
        Operation::Empty => return CKR_OPERATION_NOT_INITIALIZED,
        _ => return CKR_OPERATION_ACTIVE,
    };
    let handles = res_or_ret!(operation.results(max_object_count as usize));
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
extern "C" fn fn_find_objects_final(s_handle: CK_SESSION_HANDLE) -> CK_RV {
    let rstate = global_rlock!(STATE);
    let mut session = res_or_ret!(rstate.get_session_mut(s_handle));
    match session.get_operation_mut() {
        Operation::Search(_) => (),
        Operation::Empty => return CKR_OPERATION_NOT_INITIALIZED,
        _ => return CKR_OPERATION_ACTIVE,
    };
    session.set_operation(Operation::Empty);
    CKR_OK
}

macro_rules! check_op_empty_or_fail {
    ($sess:expr; $optype:ident; $ptr:expr) => {
        let op = $sess.get_operation();
        if !op.finalized() {
            if $ptr.is_null() {
                match op {
                    Operation::$optype(_) => {
                        $sess.set_operation(Operation::Empty);
                        return CKR_OK;
                    }
                    _ => (),
                }
            }
            return CKR_OPERATION_ACTIVE;
        }
    };
}

extern "C" fn fn_encrypt_init(
    s_handle: CK_SESSION_HANDLE,
    mechanism: CK_MECHANISM_PTR,
    key: CK_OBJECT_HANDLE,
) -> CK_RV {
    let rstate = global_rlock!(STATE);
    let mut session = res_or_ret!(rstate.get_session_mut(s_handle));
    check_op_empty_or_fail!(session; Encryption; mechanism);
    let data: &CK_MECHANISM = unsafe { &*mechanism };
    let slot_id = session.get_slot_id();
    let mut token = res_or_ret!(rstate.get_token_from_slot_mut(slot_id));
    let obj = res_or_ret!(token.get_object_by_handle(key)).clone();
    let mech = res_or_ret!(token.get_mechanisms().get(data.mechanism));
    if mech.info().flags & CKF_ENCRYPT == CKF_ENCRYPT {
        let operation = res_or_ret!(mech.encryption_new(data, &obj));
        session.set_operation(Operation::Encryption(operation));
        CKR_OK
    } else {
        CKR_MECHANISM_INVALID
    }
}

extern "C" fn fn_encrypt(
    s_handle: CK_SESSION_HANDLE,
    pdata: CK_BYTE_PTR,
    data_len: CK_ULONG,
    encrypted_data: CK_BYTE_PTR,
    pul_encrypted_data_len: CK_ULONG_PTR,
) -> CK_RV {
    if pdata.is_null() || pul_encrypted_data_len.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    let rstate = global_rlock!(STATE);
    let mut session = res_or_ret!(rstate.get_session_mut(s_handle));
    let operation = match session.get_operation_mut() {
        Operation::Encryption(op) => op,
        _ => return CKR_OPERATION_NOT_INITIALIZED,
    };
    if operation.finalized() {
        return CKR_OPERATION_NOT_INITIALIZED;
    }
    if encrypted_data.is_null() {
        let encryption_len = res_or_ret!(operation.encryption_len(data_len));
        unsafe {
            *pul_encrypted_data_len = encryption_len as CK_ULONG;
        }
        return CKR_OK;
    }
    let data: &[u8] =
        unsafe { std::slice::from_raw_parts(pdata, data_len as usize) };
    ret_to_rv!(operation.encrypt(data, encrypted_data, pul_encrypted_data_len))
}
extern "C" fn fn_encrypt_update(
    s_handle: CK_SESSION_HANDLE,
    part: CK_BYTE_PTR,
    part_len: CK_ULONG,
    encrypted_part: CK_BYTE_PTR,
    pul_encrypted_part_len: CK_ULONG_PTR,
) -> CK_RV {
    if part.is_null() || pul_encrypted_part_len.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    let rstate = global_rlock!(STATE);
    let mut session = res_or_ret!(rstate.get_session_mut(s_handle));
    let operation = match session.get_operation_mut() {
        Operation::Encryption(op) => op,
        _ => return CKR_OPERATION_NOT_INITIALIZED,
    };
    if operation.finalized() {
        return CKR_OPERATION_NOT_INITIALIZED;
    }
    if encrypted_part.is_null() {
        let encryption_len = res_or_ret!(operation.encryption_len(part_len));
        unsafe {
            *pul_encrypted_part_len = encryption_len as CK_ULONG;
        }
        return CKR_OK;
    }
    let data: &[u8] =
        unsafe { std::slice::from_raw_parts(part, part_len as usize) };
    ret_to_rv!(operation.encrypt_update(
        data,
        encrypted_part,
        pul_encrypted_part_len
    ))
}
extern "C" fn fn_encrypt_final(
    s_handle: CK_SESSION_HANDLE,
    last_encrypted_part: CK_BYTE_PTR,
    pul_last_encrypted_part_len: CK_ULONG_PTR,
) -> CK_RV {
    let rstate = global_rlock!(STATE);
    if last_encrypted_part.is_null() && pul_last_encrypted_part_len.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    let mut session = res_or_ret!(rstate.get_session_mut(s_handle));
    let operation = match session.get_operation_mut() {
        Operation::Encryption(op) => op,
        _ => return CKR_OPERATION_NOT_INITIALIZED,
    };
    if operation.finalized() {
        return CKR_OPERATION_NOT_INITIALIZED;
    }
    if last_encrypted_part.is_null() {
        let encryption_len = res_or_ret!(operation.encryption_len(0));
        unsafe {
            *pul_last_encrypted_part_len = encryption_len as CK_ULONG;
        }
        return CKR_OK;
    }
    ret_to_rv!(operation
        .encrypt_final(last_encrypted_part, pul_last_encrypted_part_len))
}

extern "C" fn fn_decrypt_init(
    s_handle: CK_SESSION_HANDLE,
    mechanism: CK_MECHANISM_PTR,
    key: CK_OBJECT_HANDLE,
) -> CK_RV {
    let rstate = global_rlock!(STATE);
    let mut session = res_or_ret!(rstate.get_session_mut(s_handle));
    check_op_empty_or_fail!(session; Decryption; mechanism);
    let data: &CK_MECHANISM = unsafe { &*mechanism };
    let slot_id = session.get_slot_id();
    let mut token = res_or_ret!(rstate.get_token_from_slot_mut(slot_id));
    let obj = res_or_ret!(token.get_object_by_handle(key)).clone();
    let mech = res_or_ret!(token.get_mechanisms().get(data.mechanism));
    if mech.info().flags & CKF_DECRYPT == CKF_DECRYPT {
        let operation = res_or_ret!(mech.decryption_new(data, &obj));
        session.set_operation(Operation::Decryption(operation));
        CKR_OK
    } else {
        CKR_MECHANISM_INVALID
    }
}
extern "C" fn fn_decrypt(
    s_handle: CK_SESSION_HANDLE,
    encrypted_data: CK_BYTE_PTR,
    encrypted_data_len: CK_ULONG,
    data: CK_BYTE_PTR,
    pul_data_len: CK_ULONG_PTR,
) -> CK_RV {
    if encrypted_data.is_null() || pul_data_len.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    let rstate = global_rlock!(STATE);
    let mut session = res_or_ret!(rstate.get_session_mut(s_handle));
    let operation = match session.get_operation_mut() {
        Operation::Decryption(op) => op,
        _ => return CKR_OPERATION_NOT_INITIALIZED,
    };
    if operation.finalized() {
        return CKR_OPERATION_NOT_INITIALIZED;
    }
    if data.is_null() {
        let decryption_len =
            res_or_ret!(operation.decryption_len(encrypted_data_len));
        unsafe {
            *pul_data_len = decryption_len as CK_ULONG;
        }
        return CKR_OK;
    }
    let enc: &[u8] = unsafe {
        std::slice::from_raw_parts(encrypted_data, encrypted_data_len as usize)
    };
    ret_to_rv!(operation.decrypt(enc, data, pul_data_len,))
}
extern "C" fn fn_decrypt_update(
    s_handle: CK_SESSION_HANDLE,
    encrypted_part: CK_BYTE_PTR,
    encrypted_part_len: CK_ULONG,
    part: CK_BYTE_PTR,
    pul_part_len: CK_ULONG_PTR,
) -> CK_RV {
    if encrypted_part.is_null() || pul_part_len.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    let rstate = global_rlock!(STATE);
    let mut session = res_or_ret!(rstate.get_session_mut(s_handle));
    let operation = match session.get_operation_mut() {
        Operation::Decryption(op) => op,
        _ => return CKR_OPERATION_NOT_INITIALIZED,
    };
    if operation.finalized() {
        return CKR_OPERATION_NOT_INITIALIZED;
    }
    if part.is_null() {
        let decryption_len =
            res_or_ret!(operation.decryption_len(encrypted_part_len));
        unsafe {
            *pul_part_len = decryption_len as CK_ULONG;
        }
        return CKR_OK;
    }
    let enc: &[u8] = unsafe {
        std::slice::from_raw_parts(encrypted_part, encrypted_part_len as usize)
    };
    ret_to_rv!(operation.decrypt_update(enc, part, pul_part_len,))
}
extern "C" fn fn_decrypt_final(
    s_handle: CK_SESSION_HANDLE,
    last_part: CK_BYTE_PTR,
    pul_last_part_len: CK_ULONG_PTR,
) -> CK_RV {
    if last_part.is_null() && pul_last_part_len.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    let rstate = global_rlock!(STATE);
    let mut session = res_or_ret!(rstate.get_session_mut(s_handle));
    let operation = match session.get_operation_mut() {
        Operation::Decryption(op) => op,
        _ => return CKR_OPERATION_NOT_INITIALIZED,
    };
    if operation.finalized() {
        return CKR_OPERATION_NOT_INITIALIZED;
    }
    if last_part.is_null() {
        let decryption_len = res_or_ret!(operation.decryption_len(0));
        unsafe {
            *pul_last_part_len = decryption_len as CK_ULONG;
        }
        return CKR_OK;
    }
    ret_to_rv!(operation.decrypt_final(last_part, pul_last_part_len))
}

extern "C" fn fn_digest_init(
    s_handle: CK_SESSION_HANDLE,
    mechanism: CK_MECHANISM_PTR,
) -> CK_RV {
    let rstate = global_rlock!(STATE);
    let mut session = res_or_ret!(rstate.get_session_mut(s_handle));
    check_op_empty_or_fail!(session; Digest; mechanism);
    let data: &CK_MECHANISM = unsafe { &*mechanism };
    let token = res_or_ret!(rstate.get_token_from_slot(session.get_slot_id()));
    let mech = res_or_ret!(token.get_mechanisms().get(data.mechanism));
    if mech.info().flags & CKF_DIGEST == CKF_DIGEST {
        let operation = res_or_ret!(mech.digest_new(data));
        session.set_operation(Operation::Digest(operation));
        CKR_OK
    } else {
        CKR_MECHANISM_INVALID
    }
}

extern "C" fn fn_digest(
    s_handle: CK_SESSION_HANDLE,
    pdata: CK_BYTE_PTR,
    data_len: CK_ULONG,
    pdigest: CK_BYTE_PTR,
    pul_digest_len: CK_ULONG_PTR,
) -> CK_RV {
    if pdata.is_null() || pul_digest_len.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    let rstate = global_rlock!(STATE);
    let mut session = res_or_ret!(rstate.get_session_mut(s_handle));
    let operation = match session.get_operation_mut() {
        Operation::Digest(op) => op,
        _ => return CKR_OPERATION_NOT_INITIALIZED,
    };
    if operation.finalized() {
        return CKR_OPERATION_NOT_INITIALIZED;
    }
    let digest_len = res_or_ret!(operation.digest_len());
    if pdigest.is_null() {
        unsafe {
            *pul_digest_len = digest_len as CK_ULONG;
        }
        return CKR_OK;
    }
    unsafe {
        if *pul_digest_len < digest_len as CK_ULONG {
            return CKR_BUFFER_TOO_SMALL;
        }
    }
    let data: &[u8] =
        unsafe { std::slice::from_raw_parts(pdata, data_len as usize) };
    let digest: &mut [u8] =
        unsafe { std::slice::from_raw_parts_mut(pdigest, digest_len) };
    let ret = ret_to_rv!(operation.digest(data, digest));
    if ret == CKR_OK {
        unsafe {
            *pul_digest_len = digest_len as u64;
        }
    }
    ret
}
extern "C" fn fn_digest_update(
    s_handle: CK_SESSION_HANDLE,
    part: CK_BYTE_PTR,
    part_len: CK_ULONG,
) -> CK_RV {
    if part.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    let rstate = global_rlock!(STATE);
    let mut session = res_or_ret!(rstate.get_session_mut(s_handle));
    let operation = match session.get_operation_mut() {
        Operation::Digest(op) => op,
        _ => return CKR_OPERATION_NOT_INITIALIZED,
    };
    if operation.finalized() {
        return CKR_OPERATION_NOT_INITIALIZED;
    }
    let data: &[u8] =
        unsafe { std::slice::from_raw_parts(part, part_len as usize) };
    ret_to_rv!(operation.digest_update(data))
}
extern "C" fn fn_digest_key(
    s_handle: CK_SESSION_HANDLE,
    key: CK_OBJECT_HANDLE,
) -> CK_RV {
    let rstate = global_rlock!(STATE);
    let mut session = res_or_ret!(rstate.get_session_mut(s_handle));
    let slot_id = session.get_slot_id();
    let operation = match session.get_operation_mut() {
        Operation::Digest(op) => op,
        _ => return CKR_OPERATION_NOT_INITIALIZED,
    };
    if operation.finalized() {
        return CKR_OPERATION_NOT_INITIALIZED;
    }
    let mut token = res_or_ret!(rstate.get_token_from_slot_mut(slot_id));
    let obj = res_or_ret!(token.get_object_by_handle(key));
    if res_or_ret!(obj.get_attr_as_ulong(CKA_CLASS)) != CKO_SECRET_KEY {
        return CKR_KEY_HANDLE_INVALID;
    }
    if res_or_ret!(obj.get_attr_as_ulong(CKA_KEY_TYPE)) != CKK_GENERIC_SECRET {
        return CKR_KEY_INDIGESTIBLE;
    }
    let data = res_or_ret!(obj.get_attr_as_bytes(CKA_VALUE));
    ret_to_rv!(operation.digest_update(data))
}
extern "C" fn fn_digest_final(
    s_handle: CK_SESSION_HANDLE,
    pdigest: CK_BYTE_PTR,
    pul_digest_len: CK_ULONG_PTR,
) -> CK_RV {
    if pul_digest_len.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    let rstate = global_rlock!(STATE);
    let mut session = res_or_ret!(rstate.get_session_mut(s_handle));
    let operation = match session.get_operation_mut() {
        Operation::Digest(op) => op,
        _ => return CKR_OPERATION_NOT_INITIALIZED,
    };
    if operation.finalized() {
        return CKR_OPERATION_NOT_INITIALIZED;
    }
    let digest_len = res_or_ret!(operation.digest_len());
    if pdigest.is_null() {
        unsafe {
            *pul_digest_len = digest_len as CK_ULONG;
        }
        return CKR_OK;
    }
    unsafe {
        if *pul_digest_len < digest_len as CK_ULONG {
            return CKR_BUFFER_TOO_SMALL;
        }
    }
    let digest: &mut [u8] =
        unsafe { std::slice::from_raw_parts_mut(pdigest, digest_len) };
    let ret = ret_to_rv!(operation.digest_final(digest));
    if ret == CKR_OK {
        unsafe {
            *pul_digest_len = digest_len as u64;
        }
    }
    ret
}

extern "C" fn fn_sign_init(
    s_handle: CK_SESSION_HANDLE,
    mechanism: CK_MECHANISM_PTR,
    key: CK_OBJECT_HANDLE,
) -> CK_RV {
    let rstate = global_rlock!(STATE);
    let mut session = res_or_ret!(rstate.get_session_mut(s_handle));
    check_op_empty_or_fail!(session; Sign; mechanism);
    let data: &CK_MECHANISM = unsafe { &*mechanism };
    let slot_id = session.get_slot_id();
    let mut token = res_or_ret!(rstate.get_token_from_slot_mut(slot_id));
    let obj = res_or_ret!(token.get_object_by_handle(key)).clone();
    let mech = res_or_ret!(token.get_mechanisms().get(data.mechanism));
    if mech.info().flags & CKF_SIGN == CKF_SIGN {
        let operation = res_or_ret!(mech.sign_new(data, &obj));
        session.set_operation(Operation::Sign(operation));
        CKR_OK
    } else {
        CKR_MECHANISM_INVALID
    }
}
extern "C" fn fn_sign(
    s_handle: CK_SESSION_HANDLE,
    pdata: CK_BYTE_PTR,
    data_len: CK_ULONG,
    psignature: CK_BYTE_PTR,
    pul_signature_len: CK_ULONG_PTR,
) -> CK_RV {
    if pdata.is_null() || pul_signature_len.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    let rstate = global_rlock!(STATE);
    let mut session = res_or_ret!(rstate.get_session_mut(s_handle));
    let operation = match session.get_operation_mut() {
        Operation::Sign(op) => op,
        _ => return CKR_OPERATION_NOT_INITIALIZED,
    };
    if operation.finalized() {
        return CKR_OPERATION_NOT_INITIALIZED;
    }
    let signature_len = res_or_ret!(operation.signature_len());
    if psignature.is_null() {
        unsafe {
            *pul_signature_len = signature_len as CK_ULONG;
        }
        return CKR_OK;
    }
    unsafe {
        if *pul_signature_len < signature_len as CK_ULONG {
            return CKR_BUFFER_TOO_SMALL;
        }
    }
    let data: &[u8] =
        unsafe { std::slice::from_raw_parts(pdata, data_len as usize) };
    let signature: &mut [u8] =
        unsafe { std::slice::from_raw_parts_mut(psignature, signature_len) };

    let ret = ret_to_rv!(operation.sign(data, signature));
    if ret == CKR_OK {
        unsafe {
            *pul_signature_len = signature_len as CK_ULONG;
        }
    }
    ret
}
extern "C" fn fn_sign_update(
    s_handle: CK_SESSION_HANDLE,
    part: CK_BYTE_PTR,
    part_len: CK_ULONG,
) -> CK_RV {
    if part.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    let rstate = global_rlock!(STATE);
    let mut session = res_or_ret!(rstate.get_session_mut(s_handle));
    let operation = match session.get_operation_mut() {
        Operation::Sign(op) => op,
        _ => return CKR_OPERATION_NOT_INITIALIZED,
    };
    if operation.finalized() {
        return CKR_OPERATION_NOT_INITIALIZED;
    }
    let data: &[u8] =
        unsafe { std::slice::from_raw_parts(part, part_len as usize) };
    ret_to_rv!(operation.sign_update(data))
}
extern "C" fn fn_sign_final(
    s_handle: CK_SESSION_HANDLE,
    psignature: CK_BYTE_PTR,
    pul_signature_len: CK_ULONG_PTR,
) -> CK_RV {
    if pul_signature_len.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    let rstate = global_rlock!(STATE);
    let mut session = res_or_ret!(rstate.get_session_mut(s_handle));
    let operation = match session.get_operation_mut() {
        Operation::Sign(op) => op,
        _ => return CKR_OPERATION_NOT_INITIALIZED,
    };
    if operation.finalized() {
        return CKR_OPERATION_NOT_INITIALIZED;
    }
    let signature_len = res_or_ret!(operation.signature_len());
    if psignature.is_null() {
        unsafe {
            *pul_signature_len = signature_len as CK_ULONG;
        }
        return CKR_OK;
    }
    unsafe {
        if *pul_signature_len < signature_len as CK_ULONG {
            return CKR_BUFFER_TOO_SMALL;
        }
    }
    let signature: &mut [u8] =
        unsafe { std::slice::from_raw_parts_mut(psignature, signature_len) };
    let ret = ret_to_rv!(operation.sign_final(signature));
    if ret == CKR_OK {
        unsafe {
            *pul_signature_len = signature_len as CK_ULONG;
        }
    }
    ret
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
    s_handle: CK_SESSION_HANDLE,
    mechanism: CK_MECHANISM_PTR,
    key: CK_OBJECT_HANDLE,
) -> CK_RV {
    let rstate = global_rlock!(STATE);
    let mut session = res_or_ret!(rstate.get_session_mut(s_handle));
    check_op_empty_or_fail!(session; Verify; mechanism);
    let data: &CK_MECHANISM = unsafe { &*mechanism };
    let slot_id = session.get_slot_id();
    let mut token = res_or_ret!(rstate.get_token_from_slot_mut(slot_id));
    let obj = res_or_ret!(token.get_object_by_handle(key)).clone();
    let mech = res_or_ret!(token.get_mechanisms().get(data.mechanism));
    if mech.info().flags & CKF_VERIFY == CKF_VERIFY {
        let operation = res_or_ret!(mech.verify_new(data, &obj));
        session.set_operation(Operation::Verify(operation));
        CKR_OK
    } else {
        CKR_MECHANISM_INVALID
    }
}
extern "C" fn fn_verify(
    s_handle: CK_SESSION_HANDLE,
    pdata: CK_BYTE_PTR,
    data_len: CK_ULONG,
    psignature: CK_BYTE_PTR,
    psignature_len: CK_ULONG,
) -> CK_RV {
    if pdata.is_null() || psignature.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    let rstate = global_rlock!(STATE);
    let mut session = res_or_ret!(rstate.get_session_mut(s_handle));
    let operation = match session.get_operation_mut() {
        Operation::Verify(op) => op,
        _ => return CKR_OPERATION_NOT_INITIALIZED,
    };
    if operation.finalized() {
        return CKR_OPERATION_NOT_INITIALIZED;
    }
    let signature_len = res_or_ret!(operation.signature_len());
    if psignature_len != signature_len as CK_ULONG {
        return CKR_SIGNATURE_LEN_RANGE;
    }
    let data: &[u8] =
        unsafe { std::slice::from_raw_parts(pdata, data_len as usize) };
    let signature: &[u8] =
        unsafe { std::slice::from_raw_parts(psignature, signature_len) };
    ret_to_rv!(operation.verify(data, signature))
}
extern "C" fn fn_verify_update(
    s_handle: CK_SESSION_HANDLE,
    part: CK_BYTE_PTR,
    part_len: CK_ULONG,
) -> CK_RV {
    if part.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    let rstate = global_rlock!(STATE);
    let mut session = res_or_ret!(rstate.get_session_mut(s_handle));
    let operation = match session.get_operation_mut() {
        Operation::Verify(op) => op,
        _ => return CKR_OPERATION_NOT_INITIALIZED,
    };
    if operation.finalized() {
        return CKR_OPERATION_NOT_INITIALIZED;
    }
    let data: &[u8] =
        unsafe { std::slice::from_raw_parts(part, part_len as usize) };
    ret_to_rv!(operation.verify_update(data))
}
extern "C" fn fn_verify_final(
    s_handle: CK_SESSION_HANDLE,
    psignature: CK_BYTE_PTR,
    psignature_len: CK_ULONG,
) -> CK_RV {
    if psignature.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    let rstate = global_rlock!(STATE);
    let mut session = res_or_ret!(rstate.get_session_mut(s_handle));
    let operation = match session.get_operation_mut() {
        Operation::Verify(op) => op,
        _ => return CKR_OPERATION_NOT_INITIALIZED,
    };
    if operation.finalized() {
        return CKR_OPERATION_NOT_INITIALIZED;
    }
    let signature_len = res_or_ret!(operation.signature_len());
    if psignature_len != signature_len as CK_ULONG {
        return CKR_SIGNATURE_LEN_RANGE;
    }
    let signature: &mut [u8] =
        unsafe { std::slice::from_raw_parts_mut(psignature, signature_len) };
    ret_to_rv!(operation.verify_final(signature))
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
    s_handle: CK_SESSION_HANDLE,
    mechanism: CK_MECHANISM_PTR,
    template: CK_ATTRIBUTE_PTR,
    count: CK_ULONG,
    key_handle: CK_OBJECT_HANDLE_PTR,
) -> CK_RV {
    let rstate = global_rlock!(STATE);
    let session = res_or_ret!(rstate.get_session(s_handle));

    let data: &CK_MECHANISM = unsafe { &*mechanism };
    let tmpl: &mut [CK_ATTRIBUTE] =
        unsafe { std::slice::from_raw_parts_mut(template, count as usize) };
    if !session.is_writable() {
        fail_if_cka_token_true!(&*tmpl);
    }

    let slot_id = session.get_slot_id();
    let mut token = res_or_ret!(rstate.get_token_from_slot_mut(slot_id));

    let mech = res_or_ret!(token.get_mechanisms().get(data.mechanism));
    if mech.info().flags & CKF_GENERATE != CKF_GENERATE {
        return CKR_MECHANISM_INVALID;
    }

    let result = mech.generate_key(data, tmpl);
    match result {
        Ok(obj) => {
            let kh = res_or_ret!(token.insert_object(s_handle, obj));
            unsafe {
                core::ptr::write(key_handle as *mut _, kh);
            }
            CKR_OK
        }
        Err(e) => err_to_rv!(e),
    }
}

extern "C" fn fn_generate_key_pair(
    s_handle: CK_SESSION_HANDLE,
    mechanism: CK_MECHANISM_PTR,
    public_key_template: CK_ATTRIBUTE_PTR,
    public_key_attribute_count: CK_ULONG,
    private_key_template: CK_ATTRIBUTE_PTR,
    private_key_attribute_count: CK_ULONG,
    public_key: CK_OBJECT_HANDLE_PTR,
    private_key: CK_OBJECT_HANDLE_PTR,
) -> CK_RV {
    let rstate = global_rlock!(STATE);
    let session = res_or_ret!(rstate.get_session(s_handle));

    let data: &CK_MECHANISM = unsafe { &*mechanism };
    let pubtmpl: &mut [CK_ATTRIBUTE] = unsafe {
        std::slice::from_raw_parts_mut(
            public_key_template,
            public_key_attribute_count as usize,
        )
    };
    let pritmpl: &mut [CK_ATTRIBUTE] = unsafe {
        std::slice::from_raw_parts_mut(
            private_key_template,
            private_key_attribute_count as usize,
        )
    };
    if !session.is_writable() {
        fail_if_cka_token_true!(&*pritmpl);
        fail_if_cka_token_true!(&*pubtmpl);
    }

    let slot_id = session.get_slot_id();
    let mut token = res_or_ret!(rstate.get_token_from_slot_mut(slot_id));

    let mech = res_or_ret!(token.get_mechanisms().get(data.mechanism));
    if mech.info().flags & CKF_GENERATE_KEY_PAIR != CKF_GENERATE_KEY_PAIR {
        return CKR_MECHANISM_INVALID;
    }

    let result = mech.generate_keypair(data, pubtmpl, pritmpl);
    match result {
        Ok((pubkey, privkey)) => {
            let pubh = res_or_ret!(token.insert_object(s_handle, pubkey));
            match token.insert_object(s_handle, privkey) {
                Ok(privh) => {
                    unsafe {
                        core::ptr::write(public_key as *mut _, pubh);
                        core::ptr::write(private_key as *mut _, privh);
                    }
                    CKR_OK
                }
                Err(e) => {
                    let _ = token.destroy_object(pubh);
                    err_to_rv!(e)
                }
            }
        }
        Err(e) => err_to_rv!(e),
    }
}

extern "C" fn fn_wrap_key(
    s_handle: CK_SESSION_HANDLE,
    mechanism: CK_MECHANISM_PTR,
    wrapping_key: CK_OBJECT_HANDLE,
    key: CK_OBJECT_HANDLE,
    wrapped_key: CK_BYTE_PTR,
    pul_wrapped_key_len: CK_ULONG_PTR,
) -> CK_RV {
    let rstate = global_rlock!(STATE);
    let session = res_or_ret!(rstate.get_session(s_handle));

    let ck_mech: &CK_MECHANISM = unsafe { &*mechanism };
    let slot_id = session.get_slot_id();
    let mut token = res_or_ret!(rstate.get_token_from_slot_mut(slot_id));
    let kobj = res_or_ret!(token.get_object_by_handle(key)).clone();
    let wkobj = res_or_ret!(token.get_object_by_handle(wrapping_key)).clone();
    let factories = token.get_object_factories();
    let factory = res_or_ret!(factories.get_object_factory(&kobj));
    let mech = res_or_ret!(token.get_mechanisms().get(ck_mech.mechanism));
    if mech.info().flags & CKF_WRAP != CKF_WRAP {
        return CKR_MECHANISM_INVALID;
    }

    /* key checks */
    if !res_or_ret!(wkobj.get_attr_as_bool(CKA_WRAP)) {
        return CKR_WRAPPING_KEY_HANDLE_INVALID;
    }
    let require_trusted =
        res_or_ret!(kobj.get_attr_as_bool(CKA_WRAP_WITH_TRUSTED));
    if require_trusted {
        if !res_or_ret!(wkobj.get_attr_as_bool(CKA_TRUSTED)) {
            return CKR_WRAPPING_KEY_HANDLE_INVALID;
        }
    }

    ret_to_rv!(mech.wrap_key(
        ck_mech,
        &wkobj,
        &kobj,
        wrapped_key,
        pul_wrapped_key_len,
        factory,
    ))
}

extern "C" fn fn_unwrap_key(
    s_handle: CK_SESSION_HANDLE,
    mechanism: CK_MECHANISM_PTR,
    unwrapping_key: CK_OBJECT_HANDLE,
    wrapped_key: CK_BYTE_PTR,
    wrapped_key_len: CK_ULONG,
    template: CK_ATTRIBUTE_PTR,
    attribute_count: CK_ULONG,
    key_handle: CK_OBJECT_HANDLE_PTR,
) -> CK_RV {
    let rstate = global_rlock!(STATE);
    let session = res_or_ret!(rstate.get_session(s_handle));

    let ck_mech: &CK_MECHANISM = unsafe { &*mechanism };
    let tmpl: &mut [CK_ATTRIBUTE] = unsafe {
        std::slice::from_raw_parts_mut(template, attribute_count as usize)
    };
    if !session.is_writable() {
        fail_if_cka_token_true!(&*tmpl);
    }
    let slot_id = session.get_slot_id();
    let mut token = res_or_ret!(rstate.get_token_from_slot_mut(slot_id));
    let kobj = res_or_ret!(token.get_object_by_handle(unwrapping_key)).clone();
    let factories = token.get_object_factories();
    let factory =
        res_or_ret!(factories.get_obj_factory_from_key_template(tmpl));
    let data: &[u8] = unsafe {
        std::slice::from_raw_parts(wrapped_key, wrapped_key_len as usize)
    };
    let mech = res_or_ret!(token.get_mechanisms().get(ck_mech.mechanism));
    if mech.info().flags & CKF_WRAP != CKF_WRAP {
        return CKR_MECHANISM_INVALID;
    }

    /* key checks */
    if !res_or_ret!(kobj.get_attr_as_bool(CKA_UNWRAP)) {
        return CKR_WRAPPING_KEY_HANDLE_INVALID;
    }

    let result = mech.unwrap_key(ck_mech, &kobj, data, tmpl, factory);
    match result {
        Ok(obj) => {
            let kh = res_or_ret!(token.insert_object(s_handle, obj));
            unsafe {
                core::ptr::write(key_handle as *mut _, kh);
            }
            CKR_OK
        }
        Err(e) => err_to_rv!(e),
    }
}

extern "C" fn fn_derive_key(
    s_handle: CK_SESSION_HANDLE,
    mechanism: CK_MECHANISM_PTR,
    base_key: CK_OBJECT_HANDLE,
    template: CK_ATTRIBUTE_PTR,
    attribute_count: CK_ULONG,
    key_handle: CK_OBJECT_HANDLE_PTR,
) -> CK_RV {
    let rstate = global_rlock!(STATE);
    let session = res_or_ret!(rstate.get_session(s_handle));

    let ck_mech: &CK_MECHANISM = unsafe { &*mechanism };
    let tmpl: &mut [CK_ATTRIBUTE] = unsafe {
        std::slice::from_raw_parts_mut(template, attribute_count as usize)
    };
    if !session.is_writable() {
        fail_if_cka_token_true!(&*tmpl);
    }
    let slot_id = session.get_slot_id();
    let mut token = res_or_ret!(rstate.get_token_from_slot_mut(slot_id));
    let bkey = res_or_ret!(token.get_object_by_handle(base_key)).clone();

    /* key checks */
    if !res_or_ret!(bkey.get_attr_as_bool(CKA_DERIVE)) {
        return CKR_KEY_FUNCTION_NOT_PERMITTED;
    }

    let mech = res_or_ret!(token.get_mechanisms().get(ck_mech.mechanism));
    if mech.info().flags & CKF_DERIVE != CKF_DERIVE {
        return CKR_MECHANISM_INVALID;
    }

    let mut operation = match res_or_ret!(mech.derive_operation(ck_mech)) {
        Operation::Derive(op) => op,
        _ => return CKR_MECHANISM_INVALID,
    };

    let result = operation.derive(
        &bkey,
        tmpl,
        token.get_mechanisms(),
        token.get_object_factories(),
    );
    let (kh, addtl) = match result {
        Ok((obj, addtl)) => {
            let h = res_or_ret!(token.insert_object(s_handle, obj));
            (h, addtl)
        }
        Err(e) => return err_to_rv!(e),
    };

    let mut rv = CKR_OK;
    if addtl > 0 {
        let mut o = Vec::<CK_OBJECT_HANDLE>::with_capacity(addtl);
        for _ in 0..addtl {
            let r = operation.derive_additional_key();
            match r {
                Ok((obj, hptr)) => match token.insert_object(s_handle, obj) {
                    Ok(h) => {
                        unsafe { core::ptr::write(hptr as *mut _, h) };
                        o.push(h);
                    }
                    Err(e) => rv = err_to_rv!(e),
                },
                Err(_) => rv = CKR_GENERAL_ERROR,
            }
            if rv != CKR_OK {
                break;
            }
        }
        if rv != CKR_OK {
            for h in o {
                let _ = token.destroy_object(h);
            }
            let _ = token.destroy_object(kh);
            return rv;
        }
    }

    unsafe {
        core::ptr::write(key_handle as *mut _, kh);
    }
    CKR_OK
}

extern "C" fn fn_seed_random(
    _session: CK_SESSION_HANDLE,
    _seed: CK_BYTE_PTR,
    _seed_len: CK_ULONG,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_generate_random(
    s_handle: CK_SESSION_HANDLE,
    random_data: CK_BYTE_PTR,
    random_len: CK_ULONG,
) -> CK_RV {
    /* check session is valid */
    drop(global_rlock!(STATE).get_session(s_handle));
    let data: &mut [u8] = unsafe {
        std::slice::from_raw_parts_mut(random_data, random_len as usize)
    };
    CSPRNG.with(|rng| ret_to_rv!(rng.borrow_mut().generate_random(data)))
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
        minor: 40,
    },
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
    let slotids = global_rlock!(STATE).get_slots_ids();
    if slot_list.is_null() {
        unsafe {
            *count = slotids.len() as CK_ULONG;
        }
        return CKR_OK;
    }
    unsafe {
        let num: CK_ULONG = *count;
        if num < slotids.len() as CK_ULONG {
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
        *count = slotids.len() as CK_ULONG;
    }
    CKR_OK
}

extern "C" fn fn_get_slot_info(
    slot_id: CK_SLOT_ID,
    info: CK_SLOT_INFO_PTR,
) -> CK_RV {
    let rstate = global_rlock!(STATE);
    let slot = match rstate.get_slot(slot_id) {
        Ok(s) => s,
        Err(e) => return err_to_rv!(e),
    };
    let slotinfo = slot.get_slot_info();
    unsafe {
        core::ptr::write(info as *mut _, *slotinfo);
    }
    CKR_OK
}

extern "C" fn fn_get_token_info(
    slot_id: CK_SLOT_ID,
    info: CK_TOKEN_INFO_PTR,
) -> CK_RV {
    let rstate = global_rlock!(STATE);
    let slot = match rstate.get_slot(slot_id) {
        Ok(s) => s,
        Err(e) => return err_to_rv!(e),
    };
    let tokinfo = slot.get_token_info();
    unsafe {
        core::ptr::write(info as *mut _, tokinfo);
    }
    CKR_OK
}

static IMPLEMENTED_VERSION: CK_VERSION = CK_VERSION { major: 3, minor: 0 };
static MANUFACTURER_ID: [CK_UTF8CHAR; 32usize] =
    *b"Kryoptic                        ";
static LIBRARY_DESCRIPTION: [CK_UTF8CHAR; 32usize] =
    *b"Kryoptic PKCS11 Module          ";
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
        *fnlist = &FNLIST_240 as *const _ as *mut _;
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
extern "C" fn fn_session_cancel(
    _session: CK_SESSION_HANDLE,
    _flags: CK_FLAGS,
) -> CK_RV {
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
    version: CK_VERSION { major: 3, minor: 0 },
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
    let mut ver: CK_VERSION = CK_VERSION { major: 3, minor: 0 };

    if interface.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    if !interface_name.is_null() {
        let name: &str = unsafe {
            std::ffi::CStr::from_ptr(interface_name as *const i8)
                .to_str()
                .unwrap()
        };
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
        unsafe {
            *interface = std::ptr::addr_of!(INTERFACE_300) as *mut CK_INTERFACE;
        }
    } else if ver.major == 2 && ver.minor == 40 {
        unsafe {
            *interface = std::ptr::addr_of!(INTERFACE_240) as *mut CK_INTERFACE;
        }
    } else {
        return CKR_ARGUMENTS_BAD;
    }

    CKR_OK
}

#[cfg(feature = "fips")]
#[no_mangle]
pub extern "C" fn OSSL_provider_init(
    handle: *const fips::OSSL_CORE_HANDLE,
    in_: *const fips::OSSL_DISPATCH,
    out: *mut *const fips::OSSL_DISPATCH,
    provctx: *mut *mut ::std::os::raw::c_void,
) -> ::std::os::raw::c_int {
    unsafe { fips::OSSL_provider_init_int(handle, in_, out, provctx) }
}

#[cfg(test)]
mod tests;
