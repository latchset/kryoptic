// Copyright 2023 Simo Sorce
// See LICENSE.txt file for terms

#![warn(missing_docs)]

//! This is Kryoptic
//!
//! A cryptographic software token using the PKCS#11 standard API

use std::cell::RefCell;
use std::collections::HashMap;
use std::ffi::{c_char, CStr};
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
mod config;
mod error;
mod mechanism;
mod object;
mod rng;
mod session;
mod slot;
mod storage;
mod token;

use config::Config;
use error::Result;
use interface::*;
use mechanism::Operation;
use rng::RNG;
use session::Session;
use slot::Slot;
use token::Token;

mod native;
mod ossl;

#[cfg(feature = "fips")]
mod fips;

/* Include algorithms based on selected features */
include!("enabled.rs");

/* Helper code */
mod kasn1;
mod misc;

use crate::misc::{bytes_to_slice, bytes_to_vec, cast_params};

macro_rules! ret_to_rv {
    ($ret:expr) => {
        match $ret {
            Ok(()) => CKR_OK,
            Err(e) => e.rv(),
        }
    };
}

macro_rules! res_or_ret {
    ($ret:expr) => {
        match $ret {
            Ok(x) => x,
            Err(e) => return e.rv(),
        }
    };
}

macro_rules! ok_or_ret {
    ($ret:expr) => {
        match $ret {
            CKR_OK => (),
            err => return err,
        }
    };
}

macro_rules! cast_or_ret {
    ($type:tt from $val:expr) => {{
        match $type::try_from($val) {
            Ok(cast) => cast,
            Err(_) => return CKR_GENERAL_ERROR,
        }
    }};
    ($type:tt from $val:expr => $err:expr) => {{
        match $type::try_from($val) {
            Ok(cast) => cast,
            Err(_) => return $err,
        }
    }};
}

thread_local!(static CSPRNG: RefCell<RNG> = RefCell::new(RNG::new("HMAC DRBG SHA256").unwrap()));

/// Fill a buffer with random data
///
/// Uses the instantaited CSPRNG to fill the buffer with random data

fn get_random_data(data: &mut [u8]) -> Result<()> {
    CSPRNG.with(|rng| rng.borrow_mut().generate_random(data))
}

/// Add seed data to the CSPRNG
///
/// This is not counted as entropy but just as additional data

fn random_add_seed(data: &[u8]) -> Result<()> {
    CSPRNG.with(|rng| rng.borrow_mut().add_seed(data))
}

struct State {
    slots: HashMap<CK_SLOT_ID, Slot>,
    sessionmap: HashMap<CK_SESSION_HANDLE, CK_SLOT_ID>,
    next_handle: CK_ULONG,
}

impl State {
    fn initialize(&mut self) {
        #[cfg(feature = "fips")]
        ossl::fips::init();

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

    fn get_slot(&self, slot_id: CK_SLOT_ID) -> Result<&Slot> {
        if !self.is_initialized() {
            return Err(CKR_CRYPTOKI_NOT_INITIALIZED)?;
        }
        match self.slots.get(&slot_id) {
            Some(ref s) => Ok(s),
            None => Err(CKR_SLOT_ID_INVALID)?,
        }
    }

    fn get_slot_mut(&mut self, slot_id: CK_SLOT_ID) -> Result<&mut Slot> {
        if !self.is_initialized() {
            return Err(CKR_CRYPTOKI_NOT_INITIALIZED)?;
        }
        match self.slots.get_mut(&slot_id) {
            Some(s) => Ok(s),
            None => Err(CKR_SLOT_ID_INVALID)?,
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

    fn add_slot(&mut self, slot_id: CK_SLOT_ID, slot: Slot) -> Result<()> {
        if self.slots.contains_key(&slot_id) {
            return Err(CKR_CRYPTOKI_ALREADY_INITIALIZED)?;
        }
        self.slots.insert(slot_id, slot);
        Ok(())
    }

    fn get_session(
        &self,
        handle: CK_SESSION_HANDLE,
    ) -> Result<RwLockReadGuard<'_, Session>> {
        let slot_id = match self.sessionmap.get(&handle) {
            Some(s) => *s,
            None => return Err(CKR_SESSION_HANDLE_INVALID)?,
        };
        self.get_slot(slot_id)?.get_session(handle)
    }

    fn get_session_mut(
        &self,
        handle: CK_SESSION_HANDLE,
    ) -> Result<RwLockWriteGuard<'_, Session>> {
        let slot_id = match self.sessionmap.get(&handle) {
            Some(s) => *s,
            None => return Err(CKR_SESSION_HANDLE_INVALID)?,
        };
        self.get_slot(slot_id)?.get_session_mut(handle)
    }

    fn new_session(
        &mut self,
        slot_id: CK_SLOT_ID,
        user_type: CK_USER_TYPE,
        flags: CK_FLAGS,
    ) -> Result<CK_SESSION_HANDLE> {
        let handle = self.next_handle;
        self.get_slot_mut(slot_id)?
            .add_session(handle, Session::new(slot_id, user_type, flags)?);
        self.sessionmap.insert(handle, slot_id);
        self.next_handle += 1;
        Ok(handle)
    }

    fn has_sessions(&self, slot_id: CK_SLOT_ID) -> Result<bool> {
        Ok(self.get_slot(slot_id)?.has_sessions())
    }

    fn has_ro_sessions(&self, slot_id: CK_SLOT_ID) -> Result<bool> {
        Ok(self.get_slot(slot_id)?.has_ro_sessions())
    }

    pub fn change_session_states(
        &self,
        slot_id: CK_SLOT_ID,
        user_type: CK_USER_TYPE,
    ) -> Result<()> {
        self.get_slot(slot_id)?.change_session_states(user_type)
    }

    pub fn invalidate_session_states(&self, slot_id: CK_SLOT_ID) -> Result<()> {
        self.get_slot(slot_id)?.invalidate_session_states();
        Ok(())
    }

    fn drop_session(&mut self, handle: CK_SESSION_HANDLE) -> Result<()> {
        let slot_id = match self.sessionmap.get(&handle) {
            Some(s) => *s,
            None => return Err(CKR_SESSION_HANDLE_INVALID)?,
        };
        self.get_slot_mut(slot_id)?.drop_session(handle);
        self.sessionmap.remove(&handle);
        /* The specs requires the last session to logout the token */
        if !self.has_sessions(slot_id)? {
            self.get_token_from_slot_mut(slot_id)?.logout();
        }
        Ok(())
    }

    fn drop_all_sessions_slot(
        &mut self,
        slot_id: CK_SLOT_ID,
    ) -> Result<Vec<CK_SESSION_HANDLE>> {
        self.sessionmap.retain(|_key, val| *val != slot_id);
        Ok(self.get_slot_mut(slot_id)?.drop_all_sessions())
    }

    fn get_token_from_slot(
        &self,
        slot_id: CK_SLOT_ID,
    ) -> Result<RwLockReadGuard<'_, Token>> {
        self.get_slot(slot_id)?.get_token()
    }

    fn get_token_from_slot_mut(
        &self,
        slot_id: CK_SLOT_ID,
    ) -> Result<RwLockWriteGuard<'_, Token>> {
        self.get_slot(slot_id)?.get_token_mut(false)
    }

    fn get_token_from_slot_mut_nochecks(
        &self,
        slot_id: CK_SLOT_ID,
    ) -> Result<RwLockWriteGuard<'_, Token>> {
        self.get_slot(slot_id)?.get_token_mut(true)
    }

    fn get_token_from_session(
        &self,
        handle: CK_SESSION_HANDLE,
    ) -> Result<RwLockReadGuard<'_, Token>> {
        let slot_id = match self.sessionmap.get(&handle) {
            Some(s) => *s,
            None => return Err(CKR_SESSION_HANDLE_INVALID)?,
        };
        self.get_slot(slot_id)?.get_token()
    }

    fn get_token_from_session_mut(
        &self,
        handle: CK_SESSION_HANDLE,
    ) -> Result<RwLockWriteGuard<'_, Token>> {
        let slot_id = match self.sessionmap.get(&handle) {
            Some(s) => *s,
            None => return Err(CKR_SESSION_HANDLE_INVALID)?,
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
    (noinitcheck $GLOBAL:expr) => {{
        match $GLOBAL.read() {
            Ok(r) => r,
            Err(_) => return CKR_GENERAL_ERROR,
        }
    }};
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

/// tests helper
#[cfg(test)]
pub fn check_test_slot_busy(slot: CK_SLOT_ID) -> bool {
    let state = match STATE.read() {
        Ok(r) => {
            if !r.is_initialized() {
                return false;
            }
            r
        }
        Err(_) => return false,
    };

    match state.get_slot(slot) {
        Ok(_) => true,
        Err(_) => false,
    }
}

/* initial assessment on FIPS indicator, useful when an input key needs
 * to be checked at operation initialization */
#[cfg(feature = "fips")]
fn init_fips_approval(
    mut session: RwLockWriteGuard<'_, Session>,
    mechanism: CK_MECHANISM_TYPE,
    op: CK_FLAGS,
    key: &object::Object,
) {
    let key_ok = fips::indicators::is_approved(mechanism, op, Some(key), None);
    session.set_fips_indicator(key_ok);
}

/* final assessment on FIPS indicator, after the operation is complete */
#[cfg(feature = "fips")]
fn finalize_fips_approval(
    mut session: RwLockWriteGuard<'_, Session>,
    operation_approved: Option<bool>,
) {
    let provisional = match session.get_fips_indicator() {
        Some(b) => b,
        None => true,
    };
    if provisional {
        session.set_fips_indicator(match operation_approved {
            Some(b) => b,
            None => false,
        });
    }
}

struct GlobalConfig {
    conf: Config,
}

static CONFIG: Lazy<RwLock<GlobalConfig>> = Lazy::new(|| {
    /* if there is no config file or the configuration is malformed,
     * set an empty config, an error will be returned later at
     * fn_initialize() time */
    let mut global_conf = GlobalConfig {
        conf: match Config::default_config() {
            Ok(conf) => conf,
            Err(_) => Config::new(),
        },
    };
    global_conf.conf.load_env_vars_overrides();
    RwLock::new(global_conf)
});

/// tests helper
#[cfg(test)]
pub fn add_slot(slot: config::Slot) -> CK_RV {
    let mut gconf = global_wlock!(noinitcheck CONFIG);
    if gconf.conf.add_slot(slot).is_err() {
        return CKR_GENERAL_ERROR;
    }
    CKR_OK
}

/// Implementation of C_Initialize function
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203255](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203255)

extern "C" fn fn_initialize(_init_args: CK_VOID_PTR) -> CK_RV {
    let mut gconf = global_wlock!(noinitcheck CONFIG);

    if !_init_args.is_null() {
        let args = unsafe { *(_init_args as *const CK_C_INITIALIZE_ARGS) };

        if !args.pReserved.is_null() {
            let reserved =
                unsafe { CStr::from_ptr(args.pReserved as *const _) };
            let init_arg = match reserved.to_str() {
                Ok(s) => s,
                Err(_) => return CKR_ARGUMENTS_BAD,
            };
            res_or_ret!(gconf.conf.from_init_args(init_arg));
        }
    }

    let mut wstate = global_wlock!(noinitcheck STATE);
    if !wstate.is_initialized() {
        wstate.initialize();
    }

    /* create slots for any new slot specified in the configuration
     * that has not been created yet, new slots can be added via
     * init args so we check this every time */
    for slot in &gconf.conf.slots {
        let slotnum = cast_or_ret!(CK_SLOT_ID from slot.slot);
        match wstate.add_slot(slotnum, res_or_ret!(Slot::new(slot))) {
            Ok(_) => (),
            Err(e) => {
                let ret = e.rv();
                if ret != CKR_CRYPTOKI_ALREADY_INITIALIZED {
                    return ret;
                }
            }
        }
    }

    CKR_OK
}

#[cfg(test)]
fn force_load_config() -> CK_RV {
    let testconf = GlobalConfig {
        conf: match Config::default_config() {
            Ok(conf) => conf,
            Err(e) => return e.rv(),
        },
    };
    if testconf.conf.slots.len() == 0 {
        return CKR_GENERAL_ERROR;
    }
    let mut gconf = global_wlock!(noinitcheck CONFIG);
    for slot in testconf.conf.slots {
        res_or_ret!(gconf.conf.add_slot(slot));
    }
    return CKR_OK;
}

#[cfg(all(test, feature = "eddsa"))]
fn get_ec_point_encoding(save: &mut config::EcPointEncoding) -> CK_RV {
    let gconf = global_rlock!(noinitcheck CONFIG);
    *save = gconf.conf.ec_point_encoding;
    CKR_OK
}

#[cfg(all(test, feature = "eddsa"))]
fn set_ec_point_encoding(val: config::EcPointEncoding) -> CK_RV {
    let mut gconf = global_wlock!(noinitcheck CONFIG);
    gconf.conf.ec_point_encoding = val;
    CKR_OK
}

/// Implementation of C_Finalize function
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203256](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203256)

extern "C" fn fn_finalize(_reserved: CK_VOID_PTR) -> CK_RV {
    global_wlock!(STATE).finalize()
}

/// Implementation of C_GetMechanismList function
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203266](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203266)

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
        let cnt = cast_or_ret!(CK_ULONG from token.get_mechs_num());
        unsafe {
            *count = cnt;
        }
        return CKR_OK;
    }
    let mechs = token.get_mechs_list();
    let num = cast_or_ret!(
        usize from unsafe { *count as CK_ULONG } => CKR_ARGUMENTS_BAD
    );
    if num < mechs.len() {
        return CKR_BUFFER_TOO_SMALL;
    }
    for (udx, mech) in mechs.iter().enumerate() {
        let idx = cast_or_ret!(isize from udx);
        unsafe {
            core::ptr::write(mechanism_list.offset(idx), *mech);
        }
    }
    let cnt = cast_or_ret!(CK_ULONG from mechs.len());
    unsafe {
        *count = cnt;
    }
    CKR_OK
}

/// Implementation of C_GetMechanismInfo function
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203267](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203267)

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

/// Implementation of C_InitToken function
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203268](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203268)

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
    let vpin = bytes_to_slice!(pin, pin_len, u8);
    let vlabel: Vec<u8> = if label.is_null() {
        vec![0x20u8; 32]
    } else {
        bytes_to_vec!(label, 32)
    };
    let mut token =
        res_or_ret!(rstate.get_token_from_slot_mut_nochecks(slot_id));
    match ret_to_rv!(token.initialize(&vpin, &vlabel)) {
        CKR_OK => CKR_OK,
        CKR_PIN_LOCKED => CKR_PIN_LOCKED,
        CKR_PIN_INCORRECT => CKR_PIN_INCORRECT,
        CKR_PIN_INVALID => CKR_PIN_INVALID,
        CKR_PIN_EXPIRED => CKR_PIN_EXPIRED,
        _ => CKR_GENERAL_ERROR,
    }
}

/// Implementation of C_InitPIN function
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203269](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203269)

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

    let vpin = bytes_to_slice!(pin, pin_len, u8);

    ret_to_rv!(token.set_pin(CKU_USER, &vpin, &vec![0u8; 0]))
}

/// Implementation of C_SetPIN function
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203270](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203270)

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
    let vpin = bytes_to_slice!(new_pin, new_len, u8);
    let vold = bytes_to_slice!(old_pin, old_len, u8);

    if vpin.len() == 0 || vold.len() == 0 {
        return CKR_PIN_INVALID;
    }

    let slot_id = session.get_slot_id();
    let mut token = res_or_ret!(rstate.get_token_from_slot_mut(slot_id));
    let do_logout = if token.is_logged_in(KRY_UNSPEC) {
        false
    } else {
        ok_or_ret!(token.login(CKU_USER, &vold));
        true
    };

    let ret =
        ret_to_rv!(token.set_pin(CK_UNAVAILABLE_INFORMATION, &vpin, &vold));

    if do_logout {
        let _ = token.logout();
    }

    ret
}

/// Implementation of C_OpenSession function
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203272](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203272)

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

/// Implementation of C_CloseSession function
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203273](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203273)

extern "C" fn fn_close_session(s_handle: CK_SESSION_HANDLE) -> CK_RV {
    let mut wstate = global_wlock!(STATE);
    let mut token = res_or_ret!(wstate.get_token_from_session_mut(s_handle));
    token.drop_session_objects(s_handle);
    drop(token);
    let _ = res_or_ret!(wstate.drop_session(s_handle));
    CKR_OK
}

/// Implementation of C_CloseAllSessions function
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203274](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203274)

extern "C" fn fn_close_all_sessions(slot_id: CK_SLOT_ID) -> CK_RV {
    let mut wstate = global_wlock!(STATE);
    let dropped_sessions = res_or_ret!(wstate.drop_all_sessions_slot(slot_id));
    let mut token = res_or_ret!(wstate.get_token_from_slot_mut(slot_id));
    for handle in dropped_sessions {
        token.drop_session_objects(handle);
    }
    /* The spec requires the token to logout once the last session is closed */
    token.logout();
    CKR_OK
}

/// Implementation of C_GetSessionInfo function
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203275](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203275)

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

/// Implementation of C_GetOperationState function (Not Implemented Yet)
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203277](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203277)

extern "C" fn fn_get_operation_state(
    _session: CK_SESSION_HANDLE,
    _operation_state: CK_BYTE_PTR,
    _pul_operation_state_len: CK_ULONG_PTR,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

/// Implementation of C_SetOperationState function (Not Implemented Yet)
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203278](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203278)

extern "C" fn fn_set_operation_state(
    _session: CK_SESSION_HANDLE,
    _operation_state: CK_BYTE_PTR,
    _operation_state_len: CK_ULONG,
    _encryption_key: CK_OBJECT_HANDLE,
    _authentication_key: CK_OBJECT_HANDLE,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

/// Implementation of C_Login function
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203279](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203279)

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
    let vpin = bytes_to_slice!(pin, pin_len, u8);
    let mut token = res_or_ret!(rstate.get_token_from_slot_mut(slot_id));
    if user_type == CKU_CONTEXT_SPECIFIC {
        let session = res_or_ret!(rstate.get_session_mut(s_handle));
        match session.get_operation() {
            Err(e) => match e.rv() {
                CKR_USER_NOT_LOGGED_IN => (),
                _ => return CKR_OPERATION_NOT_INITIALIZED,
            },
            Ok(_) => return CKR_OPERATION_NOT_INITIALIZED,
        }
    }

    let result = token.login(user_type, &vpin);

    if user_type == CKU_CONTEXT_SPECIFIC {
        match result {
            CKR_OK => {
                let mut session = res_or_ret!(rstate.get_session_mut(s_handle));
                session.set_login_ok();
            }
            CKR_PIN_LOCKED => {
                token.logout();
                let _ = rstate.invalidate_session_states(slot_id);
            }
            _ => (),
        }
        result
    } else {
        match result {
            CKR_OK => match rstate.change_session_states(slot_id, user_type) {
                Ok(()) => CKR_OK,
                Err(e) => {
                    token.logout();
                    let _ = rstate.invalidate_session_states(slot_id);
                    e.rv()
                }
            },
            err => err,
        }
    }
}

/// Implementation of C_Logout function
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203281](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203281)

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

/// Implementation of C_CreateObject function
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203283](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203283)

extern "C" fn fn_create_object(
    s_handle: CK_SESSION_HANDLE,
    template: CK_ATTRIBUTE_PTR,
    count: CK_ULONG,
    object_handle: CK_OBJECT_HANDLE_PTR,
) -> CK_RV {
    let rstate = global_rlock!(STATE);
    #[cfg(not(feature = "fips"))]
    let session = res_or_ret!(rstate.get_session(s_handle));
    #[cfg(feature = "fips")]
    let mut session = {
        let mut s = res_or_ret!(rstate.get_session_mut(s_handle));
        /* ensure we reset the fips indicator which may be left dirty by
         * a previous operation */
        s.reset_fips_indicator();
        s
    };
    let cnt = cast_or_ret!(usize from count => CKR_ARGUMENTS_BAD);
    let tmpl: &mut [CK_ATTRIBUTE] =
        unsafe { std::slice::from_raw_parts_mut(template, cnt) };
    if !session.is_writable() {
        fail_if_cka_token_true!(&*tmpl);
    }
    let slot_id = session.get_slot_id();
    let mut token = res_or_ret!(rstate.get_token_from_slot_mut(slot_id));

    let key_handle = match token.create_object(s_handle, tmpl) {
        Ok(h) => h,
        Err(e) => return e.rv(),
    };

    #[cfg(feature = "fips")]
    {
        let mut key = res_or_ret!(token.get_object_by_handle(key_handle));
        /* ignore if not a key */
        match key.get_attr_as_ulong(CKA_KEY_TYPE) {
            /* check as if the key were generated, the same considerations
             * as for key generation apply here, so we use the the same
             * mechanism that would be used if this key was generated */
            Ok(key_type) => {
                let mechanism = match key_type {
                    CKK_AES => CKM_AES_KEY_GEN,
                    CKK_GENERIC_SECRET => CKM_GENERIC_SECRET_KEY_GEN,
                    CKK_HKDF => CKM_HKDF_KEY_GEN,
                    CKK_RSA => CKM_RSA_PKCS_KEY_PAIR_GEN,
                    CKK_EC => CKM_EC_KEY_PAIR_GEN,
                    CKK_EC_EDWARDS => CKM_EC_EDWARDS_KEY_PAIR_GEN,
                    _ => CK_UNAVAILABLE_INFORMATION,
                };
                session.set_fips_indicator(fips::indicators::is_approved(
                    mechanism,
                    CKF_GENERATE,
                    None,
                    Some(&mut key),
                ));
            }
            Err(_) => (),
        }
    }

    unsafe {
        core::ptr::write(object_handle as *mut _, key_handle);
    }

    CKR_OK
}

/// Implementation of C_CopyObject function
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203284](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203284)

extern "C" fn fn_copy_object(
    s_handle: CK_SESSION_HANDLE,
    o_handle: CK_OBJECT_HANDLE,
    template: CK_ATTRIBUTE_PTR,
    count: CK_ULONG,
    ph_new_object: CK_OBJECT_HANDLE_PTR,
) -> CK_RV {
    let rstate = global_rlock!(STATE);
    let session = res_or_ret!(rstate.get_session(s_handle));
    let cnt = cast_or_ret!(usize from count => CKR_ARGUMENTS_BAD);
    let tmpl: &mut [CK_ATTRIBUTE] =
        unsafe { std::slice::from_raw_parts_mut(template, cnt) };
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

/// Implementation of C_DestroyObject function
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203285](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203285)

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

/// Implementation of C_GetObjectSize function
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203286](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203286)

extern "C" fn fn_get_object_size(
    s_handle: CK_SESSION_HANDLE,
    o_handle: CK_OBJECT_HANDLE,
    size: CK_ULONG_PTR,
) -> CK_RV {
    let rstate = global_rlock!(STATE);
    let token = res_or_ret!(rstate.get_token_from_session(s_handle));
    let len = cast_or_ret!(
        CK_ULONG from res_or_ret!(token.get_object_size(o_handle))
    );
    unsafe { *size = len }
    CKR_OK
}

/// Implementation of C_GetAttributeValue function
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203287](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203287)

extern "C" fn fn_get_attribute_value(
    s_handle: CK_SESSION_HANDLE,
    o_handle: CK_OBJECT_HANDLE,
    template: CK_ATTRIBUTE_PTR,
    count: CK_ULONG,
) -> CK_RV {
    let cnt = cast_or_ret!(usize from count => CKR_ARGUMENTS_BAD);
    let mut tmpl: &mut [CK_ATTRIBUTE] =
        unsafe { std::slice::from_raw_parts_mut(template, cnt) };

    /* must do this before we lock STATE or risk deadlocking in tests with
     * a parallel thread calling fn_initialize() */
    #[cfg(any(feature = "eddsa", feature = "ec_montgomery"))]
    let ec_point_len = match tmpl.iter().find(|a| a.type_ == CKA_EC_POINT) {
        Some(a) => {
            let gconf = global_rlock!(noinitcheck CONFIG);
            /* enable the whole thing only if we need to convert to backwards
             * compatible DER encoding */
            if gconf.conf.ec_point_encoding == config::EcPointEncoding::Der {
                let buflen =
                    cast_or_ret!(usize from a.ulValueLen => CKR_ARGUMENTS_BAD);
                Some(buflen)
            } else {
                None
            }
        }
        None => None,
    };

    let rstate = global_rlock!(STATE);
    let mut token = res_or_ret!(rstate.get_token_from_session_mut(s_handle));
    let result = ret_to_rv!(token.get_object_attrs(o_handle, &mut tmpl));

    #[cfg(any(feature = "eddsa", feature = "ec_montgomery"))]
    if let Some(bufsize) = ec_point_len {
        use ec::{point_buf_to_der, point_len_to_der};

        match tmpl.iter_mut().find(|a| a.type_ == CKA_EC_POINT) {
            Some(a) => {
                if a.ulValueLen == CK_UNAVAILABLE_INFORMATION {
                    /* do not touch this */
                    return result;
                }
                let buflen =
                    cast_or_ret!(usize from a.ulValueLen => CKR_GENERAL_ERROR);
                if a.pValue == std::ptr::null_mut() {
                    let len = point_len_to_der(buflen);
                    if len != buflen {
                        a.ulValueLen = cast_or_ret!(CK_ULONG from len);
                    }
                } else {
                    let buf: &mut [u8] = unsafe {
                        std::slice::from_raw_parts_mut(
                            a.pValue as *mut u8,
                            buflen,
                        )
                    };
                    let out = res_or_ret!(point_buf_to_der(buf, bufsize));
                    if let Some(v) = out {
                        if v.len() > bufsize {
                            return CKR_GENERAL_ERROR;
                        }
                        unsafe {
                            /* update buffer with the DER encoded version */
                            std::ptr::copy_nonoverlapping(
                                v.as_ptr(),
                                a.pValue as *mut u8,
                                v.len(),
                            );
                        }
                        a.ulValueLen = cast_or_ret!(CK_ULONG from v.len());
                    }
                }
            }
            None => (),
        }
    }
    result
}

/// Implementation of C_SetAttributeValue function
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203288](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203288)

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
    let cnt = cast_or_ret!(usize from count => CKR_ARGUMENTS_BAD);
    let mut tmpl: &mut [CK_ATTRIBUTE] =
        unsafe { std::slice::from_raw_parts_mut(template, cnt) };
    ret_to_rv!(token.set_object_attrs(o_handle, &mut tmpl))
}

/// Implementation of C_FindObjectsInit function
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203289](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203289)

extern "C" fn fn_find_objects_init(
    s_handle: CK_SESSION_HANDLE,
    template: CK_ATTRIBUTE_PTR,
    count: CK_ULONG,
) -> CK_RV {
    let rstate = global_rlock!(STATE);
    let mut session = res_or_ret!(rstate.get_session_mut(s_handle));
    let slot_id = session.get_slot_id();
    let mut token = res_or_ret!(rstate.get_token_from_slot_mut(slot_id));
    let cnt = cast_or_ret!(usize from count => CKR_ARGUMENTS_BAD);
    let tmpl: &mut [CK_ATTRIBUTE] =
        unsafe { std::slice::from_raw_parts_mut(template, cnt) };
    ret_to_rv!(session.new_search_operation(&mut token, tmpl))
}

/// Implementation of C_FindObjects function
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203290](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203290)

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
    let operation = match res_or_ret!(session.get_operation_mut()) {
        Operation::Search(op) => op,
        Operation::Empty => return CKR_OPERATION_NOT_INITIALIZED,
        _ => return CKR_OPERATION_ACTIVE,
    };
    let moc = cast_or_ret!(usize from max_object_count => CKR_ARGUMENTS_BAD);
    let handles = res_or_ret!(operation.results(moc));
    let hlen = handles.len();
    if hlen > 0 {
        let mut idx = 0;
        while idx < hlen {
            let offset = cast_or_ret!(isize from idx);
            unsafe {
                core::ptr::write(ph_object.offset(offset), handles[idx]);
            }
            idx += 1;
        }
    }
    let poc = cast_or_ret!(CK_ULONG from hlen);
    unsafe {
        core::ptr::write(pul_object_count.offset(0), poc);
    }
    CKR_OK
}

/// Implementation of C_FindObjectsFinal function
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203291](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203291)

extern "C" fn fn_find_objects_final(s_handle: CK_SESSION_HANDLE) -> CK_RV {
    let rstate = global_rlock!(STATE);
    let mut session = res_or_ret!(rstate.get_session_mut(s_handle));
    match res_or_ret!(session.get_operation_mut()) {
        Operation::Search(_) => (),
        Operation::Empty => return CKR_OPERATION_NOT_INITIALIZED,
        _ => return CKR_OPERATION_ACTIVE,
    };
    session.set_operation(Operation::Empty, false);
    CKR_OK
}

macro_rules! check_op_empty_or_fail {
    ($sess:expr; $optype:ident; $ptr:expr) => {
        let op = $sess.get_operation_nocheck();
        if !op.finalized() {
            if $ptr.is_null() {
                match op {
                    Operation::$optype(_) => {
                        $sess.set_operation(Operation::Empty, false);
                        return CKR_OK;
                    }
                    _ => (),
                }
            }
            return CKR_OPERATION_ACTIVE;
        }
    };
}

/// Check that the mechanism is allowed by the Key object
///
/// Verifies that the mechanism is listed in the CKA_ALLOWED_MECHANISMS
/// attribute if such attribute is present, otherwise allows everything.

fn check_allowed_mechs(mech: &CK_MECHANISM, key: &object::Object) -> CK_RV {
    let allowed = match key.get_attr(CKA_ALLOWED_MECHANISMS) {
        Some(attr) => attr,
        None => return CKR_OK,
    };

    let mechsvec = allowed.get_value();
    if mechsvec.len() % misc::CK_ULONG_SIZE != 0 {
        /* not a multiple of CK_MECHANISM_TYPE values,
         * bail out, this should never happen, malformed key */
        return CKR_GENERAL_ERROR;
    }
    let mechsnum = mechsvec.len() / misc::CK_ULONG_SIZE;
    for n in 0..mechsnum {
        let cursor = n * misc::CK_ULONG_SIZE;
        let mut mslice = [0u8; misc::CK_ULONG_SIZE];
        mslice
            .copy_from_slice(&mechsvec[cursor..(cursor + misc::CK_ULONG_SIZE)]);
        let m = unsafe {
            std::mem::transmute::<[u8; misc::CK_ULONG_SIZE], CK_MECHANISM_TYPE>(
                mslice,
            )
        };
        if mech.mechanism == m {
            return CKR_OK;
        }
    }
    return CKR_MECHANISM_INVALID;
}

/// Implementation of C_EncryptInit function
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203293](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203293)

extern "C" fn fn_encrypt_init(
    s_handle: CK_SESSION_HANDLE,
    mechptr: CK_MECHANISM_PTR,
    key_handle: CK_OBJECT_HANDLE,
) -> CK_RV {
    let rstate = global_rlock!(STATE);
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

        session.set_operation(Operation::Encryption(operation), false);

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
    let operation = match res_or_ret!(session.get_operation_mut()) {
        Operation::Encryption(op) => op,
        _ => return CKR_OPERATION_NOT_INITIALIZED,
    };
    if operation.finalized() {
        return CKR_OPERATION_NOT_INITIALIZED;
    }
    let dlen = cast_or_ret!(usize from data_len => CKR_ARGUMENTS_BAD);
    if encrypted_data.is_null() {
        let encryption_len = cast_or_ret!(
            CK_ULONG from res_or_ret!(operation.encryption_len(dlen, false))
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

/// Implementation of C_EncryptUpdate function
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203295](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203295)

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
    let operation = match res_or_ret!(session.get_operation_mut()) {
        Operation::Encryption(op) => op,
        _ => return CKR_OPERATION_NOT_INITIALIZED,
    };
    if operation.finalized() {
        return CKR_OPERATION_NOT_INITIALIZED;
    }
    let plen = cast_or_ret!(usize from part_len => CKR_ARGUMENTS_BAD);
    if encrypted_part.is_null() {
        let encryption_len = cast_or_ret!(
            CK_ULONG from res_or_ret!(operation.encryption_len(plen, false))
        );
        unsafe {
            *pul_encrypted_part_len = encryption_len;
        }
        return CKR_OK;
    }
    let data: &[u8] = unsafe { std::slice::from_raw_parts(part, plen) };
    let penclen = unsafe { *pul_encrypted_part_len as CK_ULONG };
    let enclen = cast_or_ret!(usize from penclen => CKR_ARGUMENTS_BAD);
    let encpart: &mut [u8] =
        unsafe { std::slice::from_raw_parts_mut(encrypted_part, enclen) };
    let outlen = res_or_ret!(operation.encrypt_update(data, encpart));
    let retlen = cast_or_ret!(CK_ULONG from outlen);
    unsafe { *pul_encrypted_part_len = retlen };
    CKR_OK
}

/// Implementation of C_EncryptFinal function
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203296](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203296)

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
    let operation = match res_or_ret!(session.get_operation_mut()) {
        Operation::Encryption(op) => op,
        _ => return CKR_OPERATION_NOT_INITIALIZED,
    };
    if operation.finalized() {
        return CKR_OPERATION_NOT_INITIALIZED;
    }
    let penclen = unsafe { *pul_last_encrypted_part_len as CK_ULONG };
    let enclen = cast_or_ret!(usize from penclen => CKR_ARGUMENTS_BAD);
    if last_encrypted_part.is_null() {
        let encryption_len = cast_or_ret!(
            CK_ULONG from res_or_ret!(operation.encryption_len(enclen, true))
        );
        unsafe {
            *pul_last_encrypted_part_len = encryption_len;
        }
        return CKR_OK;
    }
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

extern "C" fn fn_decrypt_init(
    s_handle: CK_SESSION_HANDLE,
    mechptr: CK_MECHANISM_PTR,
    key_handle: CK_OBJECT_HANDLE,
) -> CK_RV {
    let rstate = global_rlock!(STATE);
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
        session
            .set_operation(Operation::Decryption(operation), key.always_auth());

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
    let operation = match res_or_ret!(session.get_operation_mut()) {
        Operation::Decryption(op) => op,
        _ => return CKR_OPERATION_NOT_INITIALIZED,
    };
    if operation.finalized() {
        return CKR_OPERATION_NOT_INITIALIZED;
    }
    let elen = cast_or_ret!(usize from encrypted_data_len => CKR_ARGUMENTS_BAD);
    if data.is_null() {
        let decryption_len = cast_or_ret!(
            CK_ULONG from res_or_ret!(operation.decryption_len(elen, false))
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

/// Implementation of C_DecryptUpdate function
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203306](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203306)

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
    let operation = match res_or_ret!(session.get_operation_mut()) {
        Operation::Decryption(op) => op,
        _ => return CKR_OPERATION_NOT_INITIALIZED,
    };
    if operation.finalized() {
        return CKR_OPERATION_NOT_INITIALIZED;
    }
    let elen = cast_or_ret!(usize from encrypted_part_len => CKR_ARGUMENTS_BAD);
    if part.is_null() {
        let decryption_len = cast_or_ret!(
            CK_ULONG from res_or_ret!(operation.decryption_len(elen, false))
        );
        unsafe {
            *pul_part_len = decryption_len;
        }
        return CKR_OK;
    }
    let enc: &[u8] =
        unsafe { std::slice::from_raw_parts(encrypted_part, elen) };
    let pplen = unsafe { *pul_part_len as CK_ULONG };
    let plen = cast_or_ret!(usize from pplen => CKR_ARGUMENTS_BAD);
    let dpart: &mut [u8] =
        unsafe { std::slice::from_raw_parts_mut(part, plen) };
    let outlen = res_or_ret!(operation.decrypt_update(enc, dpart));
    let retlen = cast_or_ret!(CK_ULONG from outlen);
    unsafe { *pul_part_len = retlen };
    CKR_OK
}

/// Implementation of C_DecryptFinal function
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203307](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203307)

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
    let operation = match res_or_ret!(session.get_operation_mut()) {
        Operation::Decryption(op) => op,
        _ => return CKR_OPERATION_NOT_INITIALIZED,
    };
    if operation.finalized() {
        return CKR_OPERATION_NOT_INITIALIZED;
    }
    let pplen = unsafe { *pul_last_part_len as CK_ULONG };
    let plen = cast_or_ret!(usize from pplen => CKR_ARGUMENTS_BAD);
    if last_part.is_null() {
        let decryption_len = cast_or_ret!(
            CK_ULONG from res_or_ret!(operation.decryption_len(plen, true))
        );
        unsafe {
            *pul_last_part_len = decryption_len;
        }
        return CKR_OK;
    }
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

/// Implementation of C_DigestInit
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203315](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203315)

extern "C" fn fn_digest_init(
    s_handle: CK_SESSION_HANDLE,
    mechptr: CK_MECHANISM_PTR,
) -> CK_RV {
    let rstate = global_rlock!(STATE);
    let mut session = res_or_ret!(rstate.get_session_mut(s_handle));
    check_op_empty_or_fail!(session; Digest; mechptr);
    let mechanism: &CK_MECHANISM = unsafe { &*mechptr };
    let token = res_or_ret!(rstate.get_token_from_slot(session.get_slot_id()));
    let mech = res_or_ret!(token.get_mechanisms().get(mechanism.mechanism));
    if mech.info().flags & CKF_DIGEST == CKF_DIGEST {
        let operation = res_or_ret!(mech.digest_new(mechanism));
        session.set_operation(Operation::Digest(operation), false);

        CKR_OK
    } else {
        CKR_MECHANISM_INVALID
    }
}

/// Implementation of C_Digest function
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203316](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203316)

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
    let operation = match res_or_ret!(session.get_operation_mut()) {
        Operation::Digest(op) => op,
        _ => return CKR_OPERATION_NOT_INITIALIZED,
    };
    if operation.finalized() {
        return CKR_OPERATION_NOT_INITIALIZED;
    }
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

/// Implementation of C_DigestUpdate function
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203317](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203317)

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
    let operation = match res_or_ret!(session.get_operation_mut()) {
        Operation::Digest(op) => op,
        _ => return CKR_OPERATION_NOT_INITIALIZED,
    };
    if operation.finalized() {
        return CKR_OPERATION_NOT_INITIALIZED;
    }
    let plen = cast_or_ret!(usize from part_len);
    let data: &[u8] = unsafe { std::slice::from_raw_parts(part, plen) };
    ret_to_rv!(operation.digest_update(data))
}

/// Implementation of C_DigestKey function
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203318](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203318)

extern "C" fn fn_digest_key(
    s_handle: CK_SESSION_HANDLE,
    key_handle: CK_OBJECT_HANDLE,
) -> CK_RV {
    let rstate = global_rlock!(STATE);
    let mut session = res_or_ret!(rstate.get_session_mut(s_handle));
    let slot_id = session.get_slot_id();
    let operation = match res_or_ret!(session.get_operation_mut()) {
        Operation::Digest(op) => op,
        _ => return CKR_OPERATION_NOT_INITIALIZED,
    };
    if operation.finalized() {
        return CKR_OPERATION_NOT_INITIALIZED;
    }
    let mut token = res_or_ret!(rstate.get_token_from_slot_mut(slot_id));
    let key = res_or_ret!(token.get_object_by_handle(key_handle));
    if res_or_ret!(key.get_attr_as_ulong(CKA_CLASS)) != CKO_SECRET_KEY {
        return CKR_KEY_HANDLE_INVALID;
    }
    if res_or_ret!(key.get_attr_as_ulong(CKA_KEY_TYPE)) != CKK_GENERIC_SECRET {
        return CKR_KEY_INDIGESTIBLE;
    }

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
    let operation = match res_or_ret!(session.get_operation_mut()) {
        Operation::Digest(op) => op,
        _ => return CKR_OPERATION_NOT_INITIALIZED,
    };
    if operation.finalized() {
        return CKR_OPERATION_NOT_INITIALIZED;
    }
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

/// Implementation of C_SignInit function
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203321](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203321)

extern "C" fn fn_sign_init(
    s_handle: CK_SESSION_HANDLE,
    mechptr: CK_MECHANISM_PTR,
    key_handle: CK_OBJECT_HANDLE,
) -> CK_RV {
    let rstate = global_rlock!(STATE);
    let mut session = res_or_ret!(rstate.get_session_mut(s_handle));
    check_op_empty_or_fail!(session; Sign; mechptr);
    let mechanism: &CK_MECHANISM = unsafe { &*mechptr };
    let slot_id = session.get_slot_id();
    let mut token = res_or_ret!(rstate.get_token_from_slot_mut(slot_id));
    let key = res_or_ret!(token.get_object_by_handle(key_handle));
    ok_or_ret!(check_allowed_mechs(mechanism, &key));
    let mech = res_or_ret!(token.get_mechanisms().get(mechanism.mechanism));
    if mech.info().flags & CKF_SIGN == CKF_SIGN {
        let operation = res_or_ret!(mech.sign_new(mechanism, &key));
        session.set_operation(Operation::Sign(operation), key.always_auth());

        #[cfg(feature = "fips")]
        init_fips_approval(session, mechanism.mechanism, CKF_SIGN, &key);

        CKR_OK
    } else {
        CKR_MECHANISM_INVALID
    }
}

/// Implementation of C_Sign function
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203322](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203322)

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
    let operation = match res_or_ret!(session.get_operation_mut()) {
        Operation::Sign(op) => op,
        _ => return CKR_OPERATION_NOT_INITIALIZED,
    };
    if operation.finalized() {
        return CKR_OPERATION_NOT_INITIALIZED;
    }
    let signature_len = res_or_ret!(operation.signature_len());
    let sig_len = cast_or_ret!(CK_ULONG from signature_len);
    if psignature.is_null() {
        unsafe {
            *pul_signature_len = sig_len;
        }
        return CKR_OK;
    }
    unsafe {
        if *pul_signature_len < sig_len {
            return CKR_BUFFER_TOO_SMALL;
        }
    }
    let dlen = cast_or_ret!(usize from data_len => CKR_ARGUMENTS_BAD);
    let data: &[u8] = unsafe { std::slice::from_raw_parts(pdata, dlen) };
    let signature: &mut [u8] =
        unsafe { std::slice::from_raw_parts_mut(psignature, signature_len) };

    let ret = ret_to_rv!(operation.sign(data, signature));
    if ret == CKR_OK {
        unsafe {
            *pul_signature_len = sig_len;
        }

        #[cfg(feature = "fips")]
        {
            let approved = operation.fips_approved();
            finalize_fips_approval(session, approved);
        }
    }
    ret
}

/// Implementation of C_SignUpdate function
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203323](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203323)

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
    let operation = match res_or_ret!(session.get_operation_mut()) {
        Operation::Sign(op) => op,
        _ => return CKR_OPERATION_NOT_INITIALIZED,
    };
    if operation.finalized() {
        return CKR_OPERATION_NOT_INITIALIZED;
    }
    let plen = cast_or_ret!(usize from part_len);
    let data: &[u8] = unsafe { std::slice::from_raw_parts(part, plen) };
    ret_to_rv!(operation.sign_update(data))
}

/// Implementation of C_SignFinal function
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203324](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203324)

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
    let operation = match res_or_ret!(session.get_operation_mut()) {
        Operation::Sign(op) => op,
        _ => return CKR_OPERATION_NOT_INITIALIZED,
    };
    if operation.finalized() {
        return CKR_OPERATION_NOT_INITIALIZED;
    }
    let signature_len = res_or_ret!(operation.signature_len());
    let sig_len = cast_or_ret!(CK_ULONG from signature_len);
    if psignature.is_null() {
        unsafe {
            *pul_signature_len = sig_len;
        }
        return CKR_OK;
    }
    unsafe {
        if *pul_signature_len < sig_len {
            return CKR_BUFFER_TOO_SMALL;
        }
    }
    let signature: &mut [u8] =
        unsafe { std::slice::from_raw_parts_mut(psignature, signature_len) };
    let ret = ret_to_rv!(operation.sign_final(signature));
    if ret == CKR_OK {
        unsafe {
            *pul_signature_len = sig_len;
        }

        #[cfg(feature = "fips")]
        {
            let approved = operation.fips_approved();
            finalize_fips_approval(session, approved);
        }
    }
    ret
}

/// Implementation of C_SignRecoverInit function (Not Implemented Yet)
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203325](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203325)

extern "C" fn fn_sign_recover_init(
    _session: CK_SESSION_HANDLE,
    _mechanism: CK_MECHANISM_PTR,
    _key: CK_OBJECT_HANDLE,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

/// Implementation of C_SignRecover function (Not Implemented Yet)
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203326](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203326)

extern "C" fn fn_sign_recover(
    _session: CK_SESSION_HANDLE,
    _data: CK_BYTE_PTR,
    _data_len: CK_ULONG,
    _signature: CK_BYTE_PTR,
    _pul_signature_len: CK_ULONG_PTR,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

/// Implementation of C_VerifyInit function
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203334](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203334)

extern "C" fn fn_verify_init(
    s_handle: CK_SESSION_HANDLE,
    mechptr: CK_MECHANISM_PTR,
    key_handle: CK_OBJECT_HANDLE,
) -> CK_RV {
    let rstate = global_rlock!(STATE);
    let mut session = res_or_ret!(rstate.get_session_mut(s_handle));
    check_op_empty_or_fail!(session; Verify; mechptr);
    let mechanism: &CK_MECHANISM = unsafe { &*mechptr };
    let slot_id = session.get_slot_id();
    let mut token = res_or_ret!(rstate.get_token_from_slot_mut(slot_id));
    let key = res_or_ret!(token.get_object_by_handle(key_handle));
    ok_or_ret!(check_allowed_mechs(mechanism, &key));
    let mech = res_or_ret!(token.get_mechanisms().get(mechanism.mechanism));
    if mech.info().flags & CKF_VERIFY == CKF_VERIFY {
        let operation = res_or_ret!(mech.verify_new(mechanism, &key));
        session.set_operation(Operation::Verify(operation), false);

        #[cfg(feature = "fips")]
        init_fips_approval(session, mechanism.mechanism, CKF_VERIFY, &key);

        CKR_OK
    } else {
        CKR_MECHANISM_INVALID
    }
}

/// Implementation of C_Verify function
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203335](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203335)

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
    let operation = match res_or_ret!(session.get_operation_mut()) {
        Operation::Verify(op) => op,
        _ => return CKR_OPERATION_NOT_INITIALIZED,
    };
    if operation.finalized() {
        return CKR_OPERATION_NOT_INITIALIZED;
    }
    let signature_len = res_or_ret!(operation.signature_len());
    let sig_len = cast_or_ret!(CK_ULONG from signature_len);
    if psignature_len != sig_len {
        return CKR_SIGNATURE_LEN_RANGE;
    }
    let dlen = cast_or_ret!(usize from data_len);
    let data: &[u8] = unsafe { std::slice::from_raw_parts(pdata, dlen) };
    let signature: &[u8] =
        unsafe { std::slice::from_raw_parts(psignature, signature_len) };
    let ret = ret_to_rv!(operation.verify(data, signature));

    #[cfg(feature = "fips")]
    if ret == CKR_OK {
        let approved = operation.fips_approved();
        finalize_fips_approval(session, approved);
    }

    ret
}

/// Implementation of C_VerifyUpdate function
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203336](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203336)

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
    let operation = match res_or_ret!(session.get_operation_mut()) {
        Operation::Verify(op) => op,
        _ => return CKR_OPERATION_NOT_INITIALIZED,
    };
    if operation.finalized() {
        return CKR_OPERATION_NOT_INITIALIZED;
    }
    let plen = cast_or_ret!(usize from part_len);
    let data: &[u8] = unsafe { std::slice::from_raw_parts(part, plen) };
    ret_to_rv!(operation.verify_update(data))
}

/// Implementation of C_VerifyFinal function
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203337](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203337)

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
    let operation = match res_or_ret!(session.get_operation_mut()) {
        Operation::Verify(op) => op,
        _ => return CKR_OPERATION_NOT_INITIALIZED,
    };
    if operation.finalized() {
        return CKR_OPERATION_NOT_INITIALIZED;
    }
    let signature_len = res_or_ret!(operation.signature_len());
    let sig_len = cast_or_ret!(CK_ULONG from signature_len);
    if psignature_len != sig_len {
        return CKR_SIGNATURE_LEN_RANGE;
    }
    let signature: &mut [u8] =
        unsafe { std::slice::from_raw_parts_mut(psignature, signature_len) };
    let ret = ret_to_rv!(operation.verify_final(signature));

    #[cfg(feature = "fips")]
    if ret == CKR_OK {
        let approved = operation.fips_approved();
        finalize_fips_approval(session, approved);
    }

    ret
}

/// Implementation of C_VerifyRecoverInit function (Not Implemented Yet)
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203338](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203338)

extern "C" fn fn_verify_recover_init(
    _session: CK_SESSION_HANDLE,
    _mechanism: CK_MECHANISM_PTR,
    _key: CK_OBJECT_HANDLE,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

/// Implementation of C_VerifyRecover function (Not Implemented Yet)
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203339](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203339)

extern "C" fn fn_verify_recover(
    _session: CK_SESSION_HANDLE,
    _signature: CK_BYTE_PTR,
    _signature_len: CK_ULONG,
    _data: CK_BYTE_PTR,
    _pul_data_len: CK_ULONG_PTR,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

/// Implementation of C_DigestEncryptUpdate function (Not Implemented Yet)
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203347](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203347)

extern "C" fn fn_digest_encrypt_update(
    _session: CK_SESSION_HANDLE,
    _part: CK_BYTE_PTR,
    _part_len: CK_ULONG,
    _encrypted_part: CK_BYTE_PTR,
    _pul_encrypted_part_len: CK_ULONG_PTR,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

/// Implementation of C_DecryptDigestUpdate function (Not Implemented Yet)
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203348](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203348)

extern "C" fn fn_decrypt_digest_update(
    _session: CK_SESSION_HANDLE,
    _encrypted_part: CK_BYTE_PTR,
    _encrypted_part_len: CK_ULONG,
    _part: CK_BYTE_PTR,
    _pul_part_len: CK_ULONG_PTR,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

/// Implementation of C_SignEncryptUpdate function (Not Implemented Yet)
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203349](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203349)

extern "C" fn fn_sign_encrypt_update(
    _session: CK_SESSION_HANDLE,
    _part: CK_BYTE_PTR,
    _part_len: CK_ULONG,
    _encrypted_part: CK_BYTE_PTR,
    _pul_encrypted_part_len: CK_ULONG_PTR,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

/// Implementation of C_DecryptVerifyUpdate function (Not Implemented Yet)
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203350](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203350)

extern "C" fn fn_decrypt_verify_update(
    _session: CK_SESSION_HANDLE,
    _encrypted_part: CK_BYTE_PTR,
    _encrypted_part_len: CK_ULONG,
    _part: CK_BYTE_PTR,
    _pul_part_len: CK_ULONG_PTR,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

/// Implementation of C_GenerateKey function
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203352](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203352)

extern "C" fn fn_generate_key(
    s_handle: CK_SESSION_HANDLE,
    mechptr: CK_MECHANISM_PTR,
    template: CK_ATTRIBUTE_PTR,
    count: CK_ULONG,
    key_handle: CK_OBJECT_HANDLE_PTR,
) -> CK_RV {
    let rstate = global_rlock!(STATE);
    #[cfg(not(feature = "fips"))]
    let session = res_or_ret!(rstate.get_session(s_handle));
    #[cfg(feature = "fips")]
    let mut session = {
        let mut s = res_or_ret!(rstate.get_session_mut(s_handle));
        /* ensure we reset the fips indicator which may be left dirty by
         * a previous operation */
        s.reset_fips_indicator();
        s
    };

    let mechanism: &CK_MECHANISM = unsafe { &*mechptr };
    let cnt = cast_or_ret!(usize from count);
    let tmpl: &mut [CK_ATTRIBUTE] =
        unsafe { std::slice::from_raw_parts_mut(template, cnt) };
    if !session.is_writable() {
        fail_if_cka_token_true!(&*tmpl);
    }

    let slot_id = session.get_slot_id();
    let mut token = res_or_ret!(rstate.get_token_from_slot_mut(slot_id));

    let mechanisms = token.get_mechanisms();
    let factories = token.get_object_factories();
    let mech = res_or_ret!(mechanisms.get(mechanism.mechanism));
    if mech.info().flags & CKF_GENERATE != CKF_GENERATE {
        return CKR_MECHANISM_INVALID;
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
        Err(e) => return e.rv(),
    };

    let kh = res_or_ret!(token.insert_object(s_handle, key));
    unsafe {
        core::ptr::write(key_handle as *mut _, kh);
    }
    CKR_OK
}

/// Implementation of C_GeneateKeyPair function
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203353](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203353)

extern "C" fn fn_generate_key_pair(
    s_handle: CK_SESSION_HANDLE,
    mechptr: CK_MECHANISM_PTR,
    public_key_template: CK_ATTRIBUTE_PTR,
    public_key_attribute_count: CK_ULONG,
    private_key_template: CK_ATTRIBUTE_PTR,
    private_key_attribute_count: CK_ULONG,
    public_key: CK_OBJECT_HANDLE_PTR,
    private_key: CK_OBJECT_HANDLE_PTR,
) -> CK_RV {
    let rstate = global_rlock!(STATE);
    #[cfg(not(feature = "fips"))]
    let session = res_or_ret!(rstate.get_session(s_handle));
    #[cfg(feature = "fips")]
    let mut session = {
        let mut s = res_or_ret!(rstate.get_session_mut(s_handle));
        /* ensure we reset the fips indicator which may be left dirty by
         * a previous operation */
        s.reset_fips_indicator();
        s
    };

    let mechanism: &CK_MECHANISM = unsafe { &*mechptr };
    let pubcnt = cast_or_ret!(usize from public_key_attribute_count);
    let pubtmpl: &mut [CK_ATTRIBUTE] =
        unsafe { std::slice::from_raw_parts_mut(public_key_template, pubcnt) };
    let pricnt = cast_or_ret!(usize from private_key_attribute_count);
    let pritmpl: &mut [CK_ATTRIBUTE] =
        unsafe { std::slice::from_raw_parts_mut(private_key_template, pricnt) };
    if !session.is_writable() {
        fail_if_cka_token_true!(&*pritmpl);
        fail_if_cka_token_true!(&*pubtmpl);
    }

    let slot_id = session.get_slot_id();
    let mut token = res_or_ret!(rstate.get_token_from_slot_mut(slot_id));

    let mech = res_or_ret!(token.get_mechanisms().get(mechanism.mechanism));
    if mech.info().flags & CKF_GENERATE_KEY_PAIR != CKF_GENERATE_KEY_PAIR {
        return CKR_MECHANISM_INVALID;
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
                    e.rv()
                }
            }
        }
        Err(e) => e.rv(),
    }
}

/// Implementation of C_WrapKey function
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203354](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203354)

extern "C" fn fn_wrap_key(
    s_handle: CK_SESSION_HANDLE,
    mechptr: CK_MECHANISM_PTR,
    wrapping_key_handle: CK_OBJECT_HANDLE,
    key_handle: CK_OBJECT_HANDLE,
    wrapped_key: CK_BYTE_PTR,
    pul_wrapped_key_len: CK_ULONG_PTR,
) -> CK_RV {
    let rstate = global_rlock!(STATE);
    #[cfg(not(feature = "fips"))]
    let session = res_or_ret!(rstate.get_session(s_handle));
    #[cfg(feature = "fips")]
    let mut session = {
        let mut s = res_or_ret!(rstate.get_session_mut(s_handle));
        /* ensure we reset the fips indicator which may be left dirty by
         * a previous operation */
        s.reset_fips_indicator();
        s
    };

    let mechanism: &CK_MECHANISM = unsafe { &*mechptr };
    let slot_id = session.get_slot_id();
    let mut token = res_or_ret!(rstate.get_token_from_slot_mut(slot_id));
    let key = res_or_ret!(token.get_object_by_handle(key_handle));
    let wkey = res_or_ret!(token.get_object_by_handle(wrapping_key_handle));
    ok_or_ret!(check_allowed_mechs(mechanism, &wkey));
    let factories = token.get_object_factories();
    let factory = res_or_ret!(factories.get_object_factory(&key));
    let mech = res_or_ret!(token.get_mechanisms().get(mechanism.mechanism));
    if mech.info().flags & CKF_WRAP != CKF_WRAP {
        return CKR_MECHANISM_INVALID;
    }

    /* key checks */
    if !res_or_ret!(wkey.get_attr_as_bool(CKA_WRAP)) {
        return CKR_WRAPPING_KEY_HANDLE_INVALID;
    }
    let require_trusted =
        res_or_ret!(key.get_attr_as_bool(CKA_WRAP_WITH_TRUSTED));
    if require_trusted {
        if !res_or_ret!(wkey.get_attr_as_bool(CKA_TRUSTED)) {
            return CKR_WRAPPING_KEY_HANDLE_INVALID;
        }
    }

    let pwraplen = unsafe { *pul_wrapped_key_len as CK_ULONG };
    let wraplen = cast_or_ret!(usize from pwraplen => CKR_ARGUMENTS_BAD);
    let wrapped: &mut [u8] =
        unsafe { std::slice::from_raw_parts_mut(wrapped_key, wraplen) };
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
        Err(e) => return e.rv(),
    };
    let retlen = cast_or_ret!(CK_ULONG from outlen);
    unsafe { *pul_wrapped_key_len = retlen };
    CKR_OK
}

/// Implementation of C_UnwrapKey function
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203355](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203355)

extern "C" fn fn_unwrap_key(
    s_handle: CK_SESSION_HANDLE,
    mechptr: CK_MECHANISM_PTR,
    unwrapping_key_handle: CK_OBJECT_HANDLE,
    wrapped_key: CK_BYTE_PTR,
    wrapped_key_len: CK_ULONG,
    template: CK_ATTRIBUTE_PTR,
    attribute_count: CK_ULONG,
    key_handle: CK_OBJECT_HANDLE_PTR,
) -> CK_RV {
    let rstate = global_rlock!(STATE);
    #[cfg(not(feature = "fips"))]
    let session = res_or_ret!(rstate.get_session(s_handle));
    #[cfg(feature = "fips")]
    let mut session = {
        let mut s = res_or_ret!(rstate.get_session_mut(s_handle));
        /* ensure we reset the fips indicator which may be left dirty by
         * a previous operation */
        s.reset_fips_indicator();
        s
    };

    let mechanism: &CK_MECHANISM = unsafe { &*mechptr };
    let cnt = cast_or_ret!(usize from attribute_count);
    let tmpl: &mut [CK_ATTRIBUTE] =
        unsafe { std::slice::from_raw_parts_mut(template, cnt) };
    if !session.is_writable() {
        fail_if_cka_token_true!(&*tmpl);
    }
    let slot_id = session.get_slot_id();
    let mut token = res_or_ret!(rstate.get_token_from_slot_mut(slot_id));
    let key = res_or_ret!(token.get_object_by_handle(unwrapping_key_handle));
    ok_or_ret!(check_allowed_mechs(mechanism, &key));
    let factories = token.get_object_factories();
    let factory =
        res_or_ret!(factories.get_obj_factory_from_key_template(tmpl));
    let wklen = cast_or_ret!(usize from wrapped_key_len);
    let data: &[u8] = unsafe { std::slice::from_raw_parts(wrapped_key, wklen) };
    let mech = res_or_ret!(token.get_mechanisms().get(mechanism.mechanism));
    if mech.info().flags & CKF_WRAP != CKF_WRAP {
        return CKR_MECHANISM_INVALID;
    }

    /* key checks */
    if !res_or_ret!(key.get_attr_as_bool(CKA_UNWRAP)) {
        return CKR_WRAPPING_KEY_HANDLE_INVALID;
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
            let kh = res_or_ret!(token.insert_object(s_handle, obj));
            unsafe {
                core::ptr::write(key_handle as *mut _, kh);
            }
            CKR_OK
        }
        Err(e) => e.rv(),
    }
}

/// Implementation of C_DeriveKey function
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203356](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203356)

extern "C" fn fn_derive_key(
    s_handle: CK_SESSION_HANDLE,
    mechptr: CK_MECHANISM_PTR,
    base_key_handle: CK_OBJECT_HANDLE,
    template: CK_ATTRIBUTE_PTR,
    attribute_count: CK_ULONG,
    key_handle: CK_OBJECT_HANDLE_PTR,
) -> CK_RV {
    let rstate = global_rlock!(STATE);
    let session = res_or_ret!(rstate.get_session(s_handle));

    let mechanism: &CK_MECHANISM = unsafe { &*mechptr };
    let cnt = cast_or_ret!(usize from attribute_count);
    let tmpl: &mut [CK_ATTRIBUTE] =
        unsafe { std::slice::from_raw_parts_mut(template, cnt) };
    if !session.is_writable() {
        fail_if_cka_token_true!(&*tmpl);
    }
    let slot_id = session.get_slot_id();
    let mut token = res_or_ret!(rstate.get_token_from_slot_mut(slot_id));
    let key = res_or_ret!(token.get_object_by_handle(base_key_handle));

    /* key checks */
    if !res_or_ret!(key.get_attr_as_bool(CKA_DERIVE)) {
        return CKR_KEY_FUNCTION_NOT_PERMITTED;
    }
    ok_or_ret!(check_allowed_mechs(mechanism, &key));

    let mech = res_or_ret!(token.get_mechanisms().get(mechanism.mechanism));
    if mech.info().flags & CKF_DERIVE != CKF_DERIVE {
        return CKR_MECHANISM_INVALID;
    }

    let mut operation = match res_or_ret!(mech.derive_operation(mechanism)) {
        Operation::Derive(op) => op,
        _ => return CKR_MECHANISM_INVALID,
    };

    /* some derive operation requires additional keys */
    match operation.requires_objects() {
        Ok(handles) => {
            let mut objs = Vec::<object::Object>::with_capacity(handles.len());
            for h in handles {
                objs.push(res_or_ret!(token.get_object_by_handle(*h)));
            }
            /* shenanigans to deal with borrow checkr on token */
            let mut send = Vec::<&object::Object>::with_capacity(objs.len());
            for o in &objs {
                send.push(o);
            }
            res_or_ret!(operation.receives_objects(send.as_slice()));
        }
        Err(e) => match e.rv() {
            CKR_OK => (),
            err => return err,
        },
    }

    let mut result = res_or_ret!(operation.derive(
        &key,
        tmpl,
        token.get_mechanisms(),
        token.get_object_factories(),
    ));
    if result.len() == 0 {
        return CKR_GENERAL_ERROR;
    }

    #[cfg(feature = "fips")]
    {
        /* must drop here or we deadlock trying to re-acquire for writing */
        drop(session);

        let mut session = res_or_ret!(rstate.get_session_mut(s_handle));
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
            let kh =
                res_or_ret!(token.insert_object(s_handle, result.remove(0)));
            if result.len() > 0 {
                let adk = match mechanism.mechanism {
                    CKM_SP800_108_COUNTER_KDF => {
                        let params = cast_params!(raw_err mechanism, CK_SP800_108_KDF_PARAMS);
                        bytes_to_slice!(
                            params.pAdditionalDerivedKeys,
                            params.ulAdditionalDerivedKeys,
                            CK_DERIVED_KEY
                        )
                    }
                    CKM_SP800_108_FEEDBACK_KDF => {
                        let params = cast_params!(raw_err mechanism, CK_SP800_108_FEEDBACK_KDF_PARAMS);
                        bytes_to_slice!(
                            params.pAdditionalDerivedKeys,
                            params.ulAdditionalDerivedKeys,
                            CK_DERIVED_KEY
                        )
                    }
                    _ => return CKR_MECHANISM_INVALID,
                };
                if adk.len() != result.len() {
                    return CKR_GENERAL_ERROR;
                }
                let mut rv = CKR_OK;
                let mut ah = Vec::<CK_OBJECT_HANDLE>::with_capacity(adk.len());
                while result.len() > 0 {
                    match token.insert_object(s_handle, result.remove(0)) {
                        Ok(h) => ah.push(h),
                        Err(e) => rv = e.rv(),
                    }
                    if rv != CKR_OK {
                        break;
                    }
                }
                if rv != CKR_OK {
                    for h in ah {
                        let _ = token.destroy_object(h);
                    }
                    let _ = token.destroy_object(kh);
                    return rv;
                }
                for i in 0..adk.len() {
                    unsafe {
                        core::ptr::write(adk[i].phKey, ah[i]);
                    }
                }
            }

            unsafe {
                core::ptr::write(key_handle, kh);
            }
            CKR_OK
        }
        CKM_TLS12_KEY_AND_MAC_DERIVE | CKM_TLS12_KEY_SAFE_DERIVE => {
            /* TODO: check that key_handle is NULL ? */
            let params =
                cast_params!(raw_err mechanism, CK_TLS12_KEY_MAT_PARAMS);
            let mat_out = params.pReturnedKeyMaterial;
            match result.len() {
                2 | 4 => (),
                _ => return CKR_GENERAL_ERROR,
            }
            let mut ah = Vec::<CK_OBJECT_HANDLE>::with_capacity(result.len());
            while result.len() > 0 {
                match token.insert_object(s_handle, result.remove(0)) {
                    Ok(h) => ah.push(h),
                    Err(e) => {
                        for h in ah {
                            let _ = token.destroy_object(h);
                        }
                        return e.rv();
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
            CKR_OK
        }
        _ => {
            if result.len() != 1 {
                return CKR_GENERAL_ERROR;
            }
            let kh =
                res_or_ret!(token.insert_object(s_handle, result.remove(0)));
            unsafe {
                core::ptr::write(key_handle, kh);
            }
            CKR_OK
        }
    }
}

/// Implementation of C_SeedRandom function
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203358](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203358)

extern "C" fn fn_seed_random(
    s_handle: CK_SESSION_HANDLE,
    seed: CK_BYTE_PTR,
    seed_len: CK_ULONG,
) -> CK_RV {
    /* check session is valid */
    drop(global_rlock!(STATE).get_session(s_handle));
    let len = cast_or_ret!(usize from seed_len);
    let data: &[u8] = unsafe { std::slice::from_raw_parts(seed, len) };
    ret_to_rv!(random_add_seed(data))
}

/// Implementation of C_GeneateRandom function
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203359](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203359)

extern "C" fn fn_generate_random(
    s_handle: CK_SESSION_HANDLE,
    random_data: CK_BYTE_PTR,
    random_len: CK_ULONG,
) -> CK_RV {
    /* check session is valid */
    drop(global_rlock!(STATE).get_session(s_handle));
    let rndlen = cast_or_ret!(usize from random_len);
    let data: &mut [u8] =
        unsafe { std::slice::from_raw_parts_mut(random_data, rndlen) };
    ret_to_rv!(get_random_data(data))
}

/// Implementation of C_GetFunctionStatus function (Not Implemented Yet)
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203361](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203361)

extern "C" fn fn_get_function_status(_session: CK_SESSION_HANDLE) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

/// Implementation of C_CancelFunction function (Not Implemented Yet)
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203362](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203362)

extern "C" fn fn_cancel_function(_session: CK_SESSION_HANDLE) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

/// Implementation of C_WaitForSlotEvent function (Not Implemented Yet)
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203265](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203265)

extern "C" fn fn_wait_for_slot_event(
    _flags: CK_FLAGS,
    _slot: CK_SLOT_ID_PTR,
    _rserved: CK_VOID_PTR,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

static FNLIST_240: CK_FUNCTION_LIST = CK_FUNCTION_LIST {
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

/// Implementation of C_GetSlotList function
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203262](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203262)

extern "C" fn fn_get_slot_list(
    _token_present: CK_BBOOL,
    slot_list: CK_SLOT_ID_PTR,
    count: CK_ULONG_PTR,
) -> CK_RV {
    if count.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    let slotids = global_rlock!(STATE).get_slots_ids();
    let silen = cast_or_ret!(CK_ULONG from slotids.len());
    if slot_list.is_null() {
        unsafe {
            *count = silen;
        }
        return CKR_OK;
    }
    unsafe {
        let num: CK_ULONG = *count;
        if num < silen {
            return CKR_BUFFER_TOO_SMALL;
        }
    }
    for (udx, slotid) in slotids.iter().enumerate() {
        let idx = cast_or_ret!(isize from udx);
        unsafe {
            core::ptr::write(slot_list.offset(idx), *slotid);
        }
    }
    unsafe {
        *count = silen;
    }
    CKR_OK
}

/// Implementation of C_GetSlotInfo function
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203263](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203263)

extern "C" fn fn_get_slot_info(
    slot_id: CK_SLOT_ID,
    info: CK_SLOT_INFO_PTR,
) -> CK_RV {
    let rstate = global_rlock!(STATE);
    let slot = match rstate.get_slot(slot_id) {
        Ok(s) => s,
        Err(e) => return e.rv(),
    };
    let slotinfo = slot.get_slot_info();
    unsafe {
        core::ptr::write(info as *mut _, *slotinfo);
    }
    CKR_OK
}

/// Implementation of C_GetTokenInfo function
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203264](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203264)

extern "C" fn fn_get_token_info(
    slot_id: CK_SLOT_ID,
    info: CK_TOKEN_INFO_PTR,
) -> CK_RV {
    let rstate = global_rlock!(STATE);
    let slot = match rstate.get_slot(slot_id) {
        Ok(s) => s,
        Err(e) => return e.rv(),
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

/// Implementation of C_GetInfo function
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203257](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203257)

extern "C" fn fn_get_info(info: CK_INFO_PTR) -> CK_RV {
    unsafe {
        *info = MODULE_INFO;
    }
    CKR_OK
}

/// Provides access to the functions defined in the API specification
///
/// The vtable returned by this function includes a version specifier as
/// the first element of this table. This version number determines the
/// length and contents of the rest of the vtable.
///
/// Often for backwards compatibility reasons the table returned by this
/// function is the table specified in PKCS#11 v2.40.
///
/// While access to later versions of the table is deferred to the
/// `C_GeInterfaceList` function available starting with version 3.0 of the
/// specification.
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203258](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203258)

#[no_mangle]
pub extern "C" fn C_GetFunctionList(fnlist: CK_FUNCTION_LIST_PTR_PTR) -> CK_RV {
    unsafe {
        *fnlist = &FNLIST_240 as *const _ as *mut _;
    };
    CKR_OK
}

// Additional 3.0 functions

/// Implementation of C_LoginUser function (Not Implemented Yet)
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203280](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203280)

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

/// Implementation of C_SessionCancel function (Not Implemented Yet)
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203276](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203276)

extern "C" fn fn_session_cancel(
    _session: CK_SESSION_HANDLE,
    _flags: CK_FLAGS,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

/// Implementation of C_MessageEncryptInit function
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203298](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203298)

extern "C" fn fn_message_encrypt_init(
    s_handle: CK_SESSION_HANDLE,
    mechptr: CK_MECHANISM_PTR,
    key_handle: CK_OBJECT_HANDLE,
) -> CK_RV {
    let rstate = global_rlock!(STATE);
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
        session.set_operation(Operation::MsgEncryption(operation), false);
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

extern "C" fn fn_encrypt_message(
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

    let rstate = global_rlock!(STATE);
    let mut session = res_or_ret!(rstate.get_session_mut(s_handle));
    let operation = match res_or_ret!(session.get_operation_mut()) {
        Operation::MsgEncryption(op) => op,
        _ => return CKR_OPERATION_NOT_INITIALIZED,
    };
    if operation.finalized() {
        return CKR_OPERATION_NOT_INITIALIZED;
    }
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

extern "C" fn fn_encrypt_message_begin(
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

    let rstate = global_rlock!(STATE);
    let mut session = res_or_ret!(rstate.get_session_mut(s_handle));

    #[cfg(feature = "fips")]
    session.reset_fips_indicator();

    let operation = match res_or_ret!(session.get_operation_mut()) {
        Operation::MsgEncryption(op) => op,
        _ => return CKR_OPERATION_NOT_INITIALIZED,
    };
    if operation.finalized() {
        return CKR_OPERATION_NOT_INITIALIZED;
    }
    if operation.busy() {
        return CKR_OPERATION_ACTIVE;
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

extern "C" fn fn_encrypt_message_next(
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

    let rstate = global_rlock!(STATE);
    let mut session = res_or_ret!(rstate.get_session_mut(s_handle));
    let operation = match res_or_ret!(session.get_operation_mut()) {
        Operation::MsgEncryption(op) => op,
        _ => return CKR_OPERATION_NOT_INITIALIZED,
    };
    if operation.finalized() {
        return CKR_OPERATION_NOT_INITIALIZED;
    }
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

extern "C" fn fn_message_encrypt_final(s_handle: CK_SESSION_HANDLE) -> CK_RV {
    let rstate = global_rlock!(STATE);
    let mut session = res_or_ret!(rstate.get_session_mut(s_handle));
    let operation = match res_or_ret!(session.get_operation_mut()) {
        Operation::MsgEncryption(op) => op,
        _ => return CKR_OPERATION_NOT_INITIALIZED,
    };
    if operation.finalized() {
        return CKR_OPERATION_NOT_INITIALIZED;
    }
    ret_to_rv!(operation.finalize())
}

/// Implementation of C_MessageDecryptInit function
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203309](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203309)

extern "C" fn fn_message_decrypt_init(
    s_handle: CK_SESSION_HANDLE,
    mechptr: CK_MECHANISM_PTR,
    key_handle: CK_OBJECT_HANDLE,
) -> CK_RV {
    let rstate = global_rlock!(STATE);
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
        session.set_operation(Operation::MsgDecryption(operation), false);
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

extern "C" fn fn_decrypt_message(
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

    let rstate = global_rlock!(STATE);
    let mut session = res_or_ret!(rstate.get_session_mut(s_handle));
    let operation = match res_or_ret!(session.get_operation_mut()) {
        Operation::MsgDecryption(op) => op,
        _ => return CKR_OPERATION_NOT_INITIALIZED,
    };
    if operation.finalized() {
        return CKR_OPERATION_NOT_INITIALIZED;
    }
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

extern "C" fn fn_decrypt_message_begin(
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

    let rstate = global_rlock!(STATE);
    let mut session = res_or_ret!(rstate.get_session_mut(s_handle));

    #[cfg(feature = "fips")]
    session.reset_fips_indicator();

    let operation = match res_or_ret!(session.get_operation_mut()) {
        Operation::MsgDecryption(op) => op,
        _ => return CKR_OPERATION_NOT_INITIALIZED,
    };
    if operation.finalized() {
        return CKR_OPERATION_NOT_INITIALIZED;
    }
    if operation.busy() {
        return CKR_OPERATION_ACTIVE;
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

extern "C" fn fn_decrypt_message_next(
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

    let rstate = global_rlock!(STATE);
    let mut session = res_or_ret!(rstate.get_session_mut(s_handle));
    let operation = match res_or_ret!(session.get_operation_mut()) {
        Operation::MsgDecryption(op) => op,
        _ => return CKR_OPERATION_NOT_INITIALIZED,
    };
    if operation.finalized() {
        return CKR_OPERATION_NOT_INITIALIZED;
    }
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

extern "C" fn fn_message_decrypt_final(s_handle: CK_SESSION_HANDLE) -> CK_RV {
    let rstate = global_rlock!(STATE);
    let mut session = res_or_ret!(rstate.get_session_mut(s_handle));
    let operation = match res_or_ret!(session.get_operation_mut()) {
        Operation::MsgDecryption(op) => op,
        _ => return CKR_OPERATION_NOT_INITIALIZED,
    };
    if operation.finalized() {
        return CKR_OPERATION_NOT_INITIALIZED;
    }
    ret_to_rv!(operation.finalize())
}

/// Implementation of C_MessageSignInit function (Not Implemented Yet)
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203328](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203328)

extern "C" fn fn_message_sign_init(
    _session: CK_SESSION_HANDLE,
    _mechanism: CK_MECHANISM_PTR,
    _key: CK_OBJECT_HANDLE,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

/// Implementation of C_SignMessage function (Not Implemented Yet)
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203329](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203329)

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

/// Implementation of C_SignMessageBegin function (Not Implemented Yet)
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203330](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203330)

extern "C" fn fn_sign_message_begin(
    _session: CK_SESSION_HANDLE,
    _parameter: CK_VOID_PTR,
    _parameter_len: CK_ULONG,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

/// Implementation of C_SignMessageNext function (Not Implemented Yet)
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203331](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203331)

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

/// Implementation of C_MessageSignFinal function (Not Implemented Yet)
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203332](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203332)

extern "C" fn fn_message_sign_final(_session: CK_SESSION_HANDLE) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

/// Implementation of C_MessageVerifyInit function (Not Implemented Yet)
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203341](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203341)

extern "C" fn fn_message_verify_init(
    _session: CK_SESSION_HANDLE,
    _mechanism: CK_MECHANISM_PTR,
    _key: CK_OBJECT_HANDLE,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

/// Implementation of C_VerifyMessage function (Not Implemented Yet)
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203342](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203342)

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

/// Implementation of C_VerifyMessageBegin function (Not Implemented Yet)
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203343](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203343)

extern "C" fn fn_verify_message_begin(
    _session: CK_SESSION_HANDLE,
    _parameter: CK_VOID_PTR,
    _parameter_len: CK_ULONG,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

/// Implementation of C_VerifyMessageNext function (Not Implemented Yet)
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203344](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203344)

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

/// Implementation of C_MessageVerifyFinal function (Not Implemented Yet)
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203345](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203345)

extern "C" fn fn_message_verify_final(_session: CK_SESSION_HANDLE) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

static FNLIST_300: CK_FUNCTION_LIST_3_0 = CK_FUNCTION_LIST_3_0 {
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

static INTERFACE_NAME_STD_NUL: &str = "PKCS 11\0";

static INTERFACE_240: CK_INTERFACE = CK_INTERFACE {
    pInterfaceName: INTERFACE_NAME_STD_NUL.as_ptr() as *mut u8,
    pFunctionList: &FNLIST_240 as *const _ as *const ::std::os::raw::c_void,
    flags: 0,
};

static INTERFACE_300: CK_INTERFACE = CK_INTERFACE {
    pInterfaceName: INTERFACE_NAME_STD_NUL.as_ptr() as *mut u8,
    pFunctionList: &FNLIST_300 as *const _ as *const ::std::os::raw::c_void,
    flags: 0,
};

#[cfg(feature = "fips")]
include!("fips/interface.rs");

#[derive(Debug, Copy, Clone)]
struct InterfaceData {
    interface: *const CK_INTERFACE,
    version: CK_VERSION,
}
unsafe impl Sync for CK_INTERFACE {}
unsafe impl Send for CK_INTERFACE {}
unsafe impl Sync for InterfaceData {}
unsafe impl Send for InterfaceData {}

static INTERFACE_SET: Lazy<Vec<InterfaceData>> = Lazy::new(|| {
    let mut v = Vec::with_capacity(3);
    v.push(InterfaceData {
        interface: std::ptr::addr_of!(INTERFACE_300),
        version: FNLIST_300.version,
    });
    v.push(InterfaceData {
        interface: std::ptr::addr_of!(INTERFACE_240),
        version: FNLIST_240.version,
    });
    #[cfg(feature = "fips")]
    v.push(InterfaceData {
        interface: std::ptr::addr_of!(INTERFACE_VAL),
        version: FNLIST_VAL.version,
    });
    v
});

/// Provides access to the list of interfaces defined by this implementation
///
/// Starting with PKCS#11 version 3.0 modules provide a list of interfaces
/// that can be fetched. Each interface provides a name and a pointer to a
/// vtable containing the functions defined for that interface.
/// Additionally flags are returned as well.
/// Custom interfaces can be defined by any vendor by specifying a custom
/// interface name. The name "PKCS 11" is reserved for official standard
/// interfaces.
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203259](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203259)

#[no_mangle]
pub extern "C" fn C_GetInterfaceList(
    interfaces_list: CK_INTERFACE_PTR,
    count: CK_ULONG_PTR,
) -> CK_RV {
    if count.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    let iflen = cast_or_ret!(CK_ULONG from INTERFACE_SET.len());
    if interfaces_list.is_null() {
        unsafe {
            *count = iflen;
        }
        return CKR_OK;
    }
    unsafe {
        if *count < iflen {
            return CKR_BUFFER_TOO_SMALL;
        }
    }
    for i in 0..INTERFACE_SET.len() {
        let offset = cast_or_ret!(isize from i);
        unsafe {
            core::ptr::write(
                interfaces_list.offset(offset) as *mut CK_INTERFACE,
                *(INTERFACE_SET[i].interface),
            );
        }
    }
    unsafe {
        *count = iflen;
    }
    CKR_OK
}

/// Returns a specific interface identified by name and version
///
/// Applications that wants to immediately access a specific interface name,
/// optionally a specific version too.
/// The `interface` argument returns the pointer to the requested vtable
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203260](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203260)

#[no_mangle]
pub extern "C" fn C_GetInterface(
    interface_name: CK_UTF8CHAR_PTR,
    version: CK_VERSION_PTR,
    interface: CK_INTERFACE_PTR_PTR,
    flags: CK_FLAGS,
) -> CK_RV {
    if interface.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    /* currently flags is always 0 */
    if flags != 0 {
        return CKR_ARGUMENTS_BAD;
    }
    let ver: CK_VERSION = if version.is_null() {
        IMPLEMENTED_VERSION
    } else {
        unsafe { *version }
    };

    let request_name: *const CK_UTF8CHAR = if interface_name.is_null() {
        INTERFACE_NAME_STD_NUL.as_ptr()
    } else {
        interface_name
    };

    for intf in INTERFACE_SET.iter() {
        let found: bool = unsafe {
            let name = (*intf.interface).pInterfaceName as *const c_char;
            libc::strcmp(request_name as *const c_char, name) == 0
        };

        if found {
            if ver.major != intf.version.major {
                continue;
            }
            if ver.minor != intf.version.minor {
                continue;
            }
            unsafe { *interface = intf.interface as *mut _ }
            return CKR_OK;
        }
    }

    CKR_ARGUMENTS_BAD
}

/// Implementation of the OpenSSL provider initialization function
///
/// This function allows OpenSSL to use this module as an OpenSSL FIPS
/// provider

#[cfg(feature = "fips")]
#[no_mangle]
pub extern "C" fn OSSL_provider_init(
    handle: *const ossl::bindings::OSSL_CORE_HANDLE,
    in_: *const ossl::bindings::OSSL_DISPATCH,
    out: *mut *const ossl::bindings::OSSL_DISPATCH,
    provctx: *mut *mut ::std::ffi::c_void,
) -> ::std::ffi::c_int {
    unsafe { ossl::bindings::OSSL_provider_init_int(handle, in_, out, provctx) }
}

#[cfg(test)]
mod tests;
