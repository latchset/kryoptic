// Copyright 2023 Simo Sorce
// See LICENSE.txt file for terms

//#![warn(missing_docs)]

//! This is Kryoptic
//!
//! A cryptographic software token using the PKCS#11 standard API

use std::cell::RefCell;
use std::collections::HashMap;
use std::sync::{LazyLock, RwLock, RwLockReadGuard, RwLockWriteGuard};

mod attribute;
mod config;
mod defaults;
mod encryption;
mod error;
mod mechanism;
mod object;
pub mod pkcs11;
mod rng;
mod session;
mod slot;
mod storage;
mod token;

use config::Config;
use error::{arg_bad, Result};
use mechanism::*;
use pkcs11::*;
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

use crate::misc::{bytes_to_slice, cast_params};

pub mod fns;
use fns::encryption::*;
use fns::general::*;
use fns::objmgmt::*;
use fns::sessmgmt::*;
use fns::stmgmt::*;
use fns::{
    cast_or_ret, global_rlock, global_wlock, ok_or_ret, res_or_ret, ret_to_rv,
};

thread_local!(
    /// Thread-local instance of the Cryptographically Secure Pseudo-Random Number
    /// Generator (CSPRNG). This is used to avoid contention and locking between
    /// different threads.
    static CSPRNG: RefCell<RNG> = RefCell::new(
        RNG::new("HMAC DRBG SHA256").unwrap()
    )
);

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

/// Global state for the PKCS#11 library.
/// Manages slots, sessions, and handle generation.
pub(crate) struct State {
    /// Hash map that stores actual slots, indexed by their Slot ID number.
    slots: HashMap<CK_SLOT_ID, Slot>,
    /// Map that holds mappings between session handles and slot ids.
    /// Sessions are stored in slots, so this allows to quickly find the
    /// correct slot when there is a need to get a session from a handle.
    sessionmap: HashMap<CK_SESSION_HANDLE, CK_SLOT_ID>,
    /// Holds the next available session handle number. Session handles are
    /// unique and never repeating for the life time of the program.
    next_handle: CK_ULONG,
}

impl State {
    /// Initializes the global state. Clears existing slots and sessions.
    pub(crate) fn initialize(&mut self) {
        #[cfg(feature = "fips")]
        fips::provider::init();

        self.slots.clear();
        self.sessionmap.clear();
        self.next_handle = 1;
    }

    /// Finalizes the global state. Finalizes all slots and clears state.
    /// Returns the first error encountered during slot finalization, if any.
    pub(crate) fn finalize(&mut self) -> CK_RV {
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

    /// Checks if the global state has been initialized.
    pub(crate) fn is_initialized(&self) -> bool {
        self.next_handle != 0
    }

    /// Gets a reference to a slot by its ID.
    fn get_slot(&self, slot_id: CK_SLOT_ID) -> Result<&Slot> {
        if !self.is_initialized() {
            return Err(CKR_CRYPTOKI_NOT_INITIALIZED)?;
        }
        match self.slots.get(&slot_id) {
            Some(ref s) => Ok(s),
            None => Err(CKR_SLOT_ID_INVALID)?,
        }
    }

    /// Gets a mutable reference to a slot by its ID.
    fn get_slot_mut(&mut self, slot_id: CK_SLOT_ID) -> Result<&mut Slot> {
        if !self.is_initialized() {
            return Err(CKR_CRYPTOKI_NOT_INITIALIZED)?;
        }
        match self.slots.get_mut(&slot_id) {
            Some(s) => Ok(s),
            None => Err(CKR_SLOT_ID_INVALID)?,
        }
    }

    /// Returns a sorted vector of all configured slot IDs.
    pub(crate) fn get_slots_ids(&self) -> Vec<CK_SLOT_ID> {
        let mut slotids = Vec::<CK_SLOT_ID>::with_capacity(self.slots.len());
        for k in self.slots.keys() {
            slotids.push(*k)
        }
        slotids.sort_unstable();
        slotids
    }

    /// Adds a new slot to the global state.
    pub(crate) fn add_slot(
        &mut self,
        slot_id: CK_SLOT_ID,
        slot: Slot,
    ) -> Result<()> {
        if self.slots.contains_key(&slot_id) {
            return Err(CKR_CRYPTOKI_ALREADY_INITIALIZED)?;
        }
        self.slots.insert(slot_id, slot);
        Ok(())
    }

    /// Gets a read lock guard for a session by its handle.
    pub(crate) fn get_session(
        &self,
        handle: CK_SESSION_HANDLE,
    ) -> Result<RwLockReadGuard<'_, Session>> {
        let slot_id = match self.sessionmap.get(&handle) {
            Some(s) => *s,
            None => return Err(CKR_SESSION_HANDLE_INVALID)?,
        };
        self.get_slot(slot_id)?.get_session(handle)
    }

    /// Gets a write lock guard for a session by its handle.
    pub(crate) fn get_session_mut(
        &self,
        handle: CK_SESSION_HANDLE,
    ) -> Result<RwLockWriteGuard<'_, Session>> {
        let slot_id = match self.sessionmap.get(&handle) {
            Some(s) => *s,
            None => return Err(CKR_SESSION_HANDLE_INVALID)?,
        };
        self.get_slot(slot_id)?.get_session_mut(handle)
    }

    /// Creates a new session on a specified slot and returns its handle.
    /// Associates the session handle with the slot ID.
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

    /// Checks if a slot has any active sessions.
    fn has_sessions(&self, slot_id: CK_SLOT_ID) -> Result<bool> {
        Ok(self.get_slot(slot_id)?.has_sessions())
    }

    /// Checks if a slot has any active read-only sessions.
    fn has_ro_sessions(&self, slot_id: CK_SLOT_ID) -> Result<bool> {
        Ok(self.get_slot(slot_id)?.has_ro_sessions())
    }

    /// Changes the state for all sessions associated with a given slot ID
    /// based on the provided user type.
    pub fn change_session_states(
        &self,
        slot_id: CK_SLOT_ID,
        user_type: CK_USER_TYPE,
    ) -> Result<()> {
        self.get_slot(slot_id)?.change_session_states(user_type)
    }

    /// Invalidates the session state for all sessions on a slot.
    pub fn invalidate_session_states(&self, slot_id: CK_SLOT_ID) -> Result<()> {
        self.get_slot(slot_id)?.invalidate_session_states();
        Ok(())
    }

    /// Drops a session by its handle.
    ///
    /// Logs out the token if it's the last session.
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

    /// Drops all sessions associated with a specific slot and returns their
    /// handles.
    fn drop_all_sessions_slot(
        &mut self,
        slot_id: CK_SLOT_ID,
    ) -> Result<Vec<CK_SESSION_HANDLE>> {
        self.sessionmap.retain(|_key, val| *val != slot_id);
        Ok(self.get_slot_mut(slot_id)?.drop_all_sessions())
    }

    /// Gets a read lock guard for the token on a specified slot.
    pub(crate) fn get_token_from_slot(
        &self,
        slot_id: CK_SLOT_ID,
    ) -> Result<RwLockReadGuard<'_, Token>> {
        self.get_slot(slot_id)?.get_token()
    }

    /// Gets a write lock guard for the token on a specified slot.
    pub(crate) fn get_token_from_slot_mut(
        &self,
        slot_id: CK_SLOT_ID,
    ) -> Result<RwLockWriteGuard<'_, Token>> {
        self.get_slot(slot_id)?.get_token_mut(false)
    }

    /// Gets a write lock guard for the token on a specified slot, bypassing
    /// initialization checks (used during initialization itself).
    pub(crate) fn get_token_from_slot_mut_nochecks(
        &self,
        slot_id: CK_SLOT_ID,
    ) -> Result<RwLockWriteGuard<'_, Token>> {
        self.get_slot(slot_id)?.get_token_mut(true)
    }

    /// Gets a read lock guard for the token associated with a session handle.
    pub(crate) fn get_token_from_session(
        &self,
        handle: CK_SESSION_HANDLE,
    ) -> Result<RwLockReadGuard<'_, Token>> {
        let slot_id = match self.sessionmap.get(&handle) {
            Some(s) => *s,
            None => return Err(CKR_SESSION_HANDLE_INVALID)?,
        };
        self.get_slot(slot_id)?.get_token()
    }

    /// Gets a write lock guard for the token associated with a session handle.
    pub(crate) fn get_token_from_session_mut(
        &self,
        handle: CK_SESSION_HANDLE,
    ) -> Result<RwLockWriteGuard<'_, Token>> {
        let slot_id = match self.sessionmap.get(&handle) {
            Some(s) => *s,
            None => return Err(CKR_SESSION_HANDLE_INVALID)?,
        };
        self.get_slot(slot_id)?.get_token_mut(false)
    }

    /// Gets the FIPS behavior configuration for a specific slot.
    #[cfg(feature = "fips")]
    pub fn get_fips_behavior(
        &self,
        slot_id: CK_SLOT_ID,
    ) -> Result<&config::FipsBehavior> {
        Ok(self.get_slot(slot_id)?.get_fips_behavior())
    }

    /// Sets the FIPS behavior configuration for a specific slot.
    #[cfg(all(test, feature = "fips"))]
    pub fn set_fips_behavior(
        &mut self,
        slot_id: CK_SLOT_ID,
        behavior: config::FipsBehavior,
    ) -> Result<()> {
        Ok(self.get_slot_mut(slot_id)?.set_fips_behavior(behavior))
    }
}

/// Global, lazily initialized, read-write locked state for the PKCS#11 library.
pub(crate) static STATE: LazyLock<RwLock<State>> = LazyLock::new(|| {
    RwLock::new(State {
        slots: HashMap::new(),
        sessionmap: HashMap::new(),
        next_handle: 0,
    })
});

/// tests helper
#[cfg(test)]
pub fn check_test_slot_busy(slot: CK_SLOT_ID) -> bool {
    let state = match (*STATE).read() {
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

/// Initializes the FIPS approval indicator on a session based on the key and
/// operation. Used at the beginning of a cryptographic operation.
/// (useful when an input key needs to be checked at initialization) */
#[cfg(feature = "fips")]
pub(crate) fn init_fips_approval(
    mut session: RwLockWriteGuard<'_, Session>,
    mechanism: CK_MECHANISM_TYPE,
    op: CK_FLAGS,
    key: &object::Object,
) {
    let key_ok = fips::indicators::is_approved(mechanism, op, Some(key), None);
    session.set_fips_indicator(key_ok);
}

/// Finalizes the FIPS approval indicator on a session based on the outcome
/// of the cryptographic operation. Used at the end of an operation.
/// Only downgrades an approval status, never upgrades a non-approved status.
#[cfg(feature = "fips")]
pub(crate) fn finalize_fips_approval(
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

/// Global configuration holder for the library.
pub(crate) struct GlobalConfig {
    pub(crate) conf: Config,
}

/// Global, lazily initialized, read-write locked configuration instance.
pub(crate) static CONFIG: LazyLock<RwLock<GlobalConfig>> =
    LazyLock::new(|| {
        RwLock::new(GlobalConfig {
            conf: Config::new(),
        })
    });

/// tests helper
#[cfg(test)]
pub fn add_slot(slot: config::Slot) -> CK_RV {
    let mut gconf = global_wlock!(noinitcheck; (*CONFIG));
    if gconf.conf.add_slot(slot).is_err() {
        return CKR_GENERAL_ERROR;
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
    let mut gconf = global_wlock!(noinitcheck; (*CONFIG));
    for slot in testconf.conf.slots {
        res_or_ret!(gconf.conf.add_slot(slot));
    }
    return CKR_OK;
}

#[cfg(all(test, feature = "fips", feature = "nssdb"))]
fn get_fips_behavior(
    slot_id: CK_SLOT_ID,
    save: &mut config::FipsBehavior,
) -> CK_RV {
    let rstate = global_rlock!((*STATE));
    let behavior = res_or_ret!(rstate.get_fips_behavior(slot_id));
    *save = behavior.clone();
    CKR_OK
}

#[cfg(all(test, feature = "fips"))]
fn set_fips_behavior(slot_id: CK_SLOT_ID, val: config::FipsBehavior) -> CK_RV {
    let mut wstate = global_wlock!((*STATE));
    ret_to_rv!(wstate.set_fips_behavior(slot_id, val))
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

macro_rules! check_op_empty_or_fail {
    ($sess:expr; $op:ident; $ptr:expr) => {
        if $ptr.is_null() {
            res_or_ret!($sess.cancel_operation::<dyn $op>());
            return CKR_OK;
        }
        res_or_ret!($sess.check_no_op::<dyn $op>());
    };
}

/// Check that the mechanism is allowed by the Key object
///
/// Verifies that the mechanism is listed in the CKA_ALLOWED_MECHANISMS
/// attribute if such attribute is present, otherwise allows everything.

pub(crate) fn check_allowed_mechs(
    mech: &CK_MECHANISM,
    key: &object::Object,
) -> CK_RV {
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
        let m = CK_MECHANISM_TYPE::from_ne_bytes(mslice);
        if mech.mechanism == m {
            return CKR_OK;
        }
    }
    return CKR_MECHANISM_INVALID;
}

/// Implementation of C_DigestInit
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203315](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203315)

extern "C" fn fn_digest_init(
    s_handle: CK_SESSION_HANDLE,
    mechptr: CK_MECHANISM_PTR,
) -> CK_RV {
    let rstate = global_rlock!((*STATE));
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
    let rstate = global_rlock!((*STATE));
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

fn internal_digest_update(
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

extern "C" fn fn_digest_update(
    s_handle: CK_SESSION_HANDLE,
    part: CK_BYTE_PTR,
    part_len: CK_ULONG,
) -> CK_RV {
    if part.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    let rstate = global_rlock!((*STATE));
    let mut session = res_or_ret!(rstate.get_session_mut(s_handle));
    ret_to_rv!(internal_digest_update(&mut session, part, part_len))
}

/// Implementation of C_DigestKey function
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203318](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203318)

extern "C" fn fn_digest_key(
    s_handle: CK_SESSION_HANDLE,
    key_handle: CK_OBJECT_HANDLE,
) -> CK_RV {
    let rstate = global_rlock!((*STATE));
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

extern "C" fn fn_digest_final(
    s_handle: CK_SESSION_HANDLE,
    pdigest: CK_BYTE_PTR,
    pul_digest_len: CK_ULONG_PTR,
) -> CK_RV {
    if pul_digest_len.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    let rstate = global_rlock!((*STATE));
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

/// Implementation of C_SignInit function
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203321](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203321)

extern "C" fn fn_sign_init(
    s_handle: CK_SESSION_HANDLE,
    mechptr: CK_MECHANISM_PTR,
    key_handle: CK_OBJECT_HANDLE,
) -> CK_RV {
    let rstate = global_rlock!((*STATE));
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
        session.set_operation::<dyn Sign>(operation, key.always_auth());

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
    let rstate = global_rlock!((*STATE));
    let mut session = res_or_ret!(rstate.get_session_mut(s_handle));
    let operation = res_or_ret!(session.get_operation::<dyn Sign>());
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

/// Helper to perform "sign_update" in multiple places,

fn internal_sign_update(
    session: &mut RwLockWriteGuard<'_, Session>,
    part: CK_BYTE_PTR,
    part_len: CK_ULONG,
) -> Result<()> {
    let operation = session.get_operation::<dyn Sign>()?;
    let plen = usize::try_from(part_len).map_err(arg_bad)?;
    let data: &[u8] = unsafe { std::slice::from_raw_parts(part, plen) };
    operation.sign_update(data)
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
    let rstate = global_rlock!((*STATE));
    let mut session = res_or_ret!(rstate.get_session_mut(s_handle));
    ret_to_rv!(internal_sign_update(&mut session, part, part_len))
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
    let rstate = global_rlock!((*STATE));
    let mut session = res_or_ret!(rstate.get_session_mut(s_handle));
    let operation = res_or_ret!(session.get_operation::<dyn Sign>());
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
    let rstate = global_rlock!((*STATE));
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
        session.set_operation::<dyn Verify>(operation, false);

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
    let rstate = global_rlock!((*STATE));
    let mut session = res_or_ret!(rstate.get_session_mut(s_handle));
    let operation = res_or_ret!(session.get_operation::<dyn Verify>());
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

/// Helper to perform "verify_update" in multiple places,

fn internal_verify_update(
    session: &mut RwLockWriteGuard<'_, Session>,
    part: CK_BYTE_PTR,
    part_len: CK_ULONG,
) -> Result<()> {
    let operation = session.get_operation::<dyn Verify>()?;
    let plen = usize::try_from(part_len).map_err(arg_bad)?;
    let data: &[u8] = unsafe { std::slice::from_raw_parts(part, plen) };
    operation.verify_update(data)
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
    let rstate = global_rlock!((*STATE));
    let mut session = res_or_ret!(rstate.get_session_mut(s_handle));
    ret_to_rv!(internal_verify_update(&mut session, part, part_len))
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
    let rstate = global_rlock!((*STATE));
    let mut session = res_or_ret!(rstate.get_session_mut(s_handle));
    let operation = res_or_ret!(session.get_operation::<dyn Verify>());
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

/// Implementation of C_DigestEncryptUpdate function
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203347](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203347)

extern "C" fn fn_digest_encrypt_update(
    s_handle: CK_SESSION_HANDLE,
    part: CK_BYTE_PTR,
    part_len: CK_ULONG,
    encrypted_part: CK_BYTE_PTR,
    pul_encrypted_part_len: CK_ULONG_PTR,
) -> CK_RV {
    if part.is_null() || pul_encrypted_part_len.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    let rstate = global_rlock!((*STATE));
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

extern "C" fn fn_decrypt_digest_update(
    s_handle: CK_SESSION_HANDLE,
    encrypted_part: CK_BYTE_PTR,
    encrypted_part_len: CK_ULONG,
    part: CK_BYTE_PTR,
    pul_part_len: CK_ULONG_PTR,
) -> CK_RV {
    if encrypted_part.is_null() || pul_part_len.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    let rstate = global_rlock!((*STATE));
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

extern "C" fn fn_sign_encrypt_update(
    s_handle: CK_SESSION_HANDLE,
    part: CK_BYTE_PTR,
    part_len: CK_ULONG,
    encrypted_part: CK_BYTE_PTR,
    pul_encrypted_part_len: CK_ULONG_PTR,
) -> CK_RV {
    if part.is_null() || pul_encrypted_part_len.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    let rstate = global_rlock!((*STATE));
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

extern "C" fn fn_decrypt_verify_update(
    s_handle: CK_SESSION_HANDLE,
    encrypted_part: CK_BYTE_PTR,
    encrypted_part_len: CK_ULONG,
    part: CK_BYTE_PTR,
    pul_part_len: CK_ULONG_PTR,
) -> CK_RV {
    if encrypted_part.is_null() || pul_part_len.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    let rstate = global_rlock!((*STATE));
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
    let rstate = global_rlock!((*STATE));
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

    #[cfg(feature = "fips")]
    res_or_ret!(fips::check_key_template(
        tmpl,
        res_or_ret!(rstate.get_fips_behavior(slot_id))
    ));

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
    let rstate = global_rlock!((*STATE));
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

    #[cfg(feature = "fips")]
    res_or_ret!(fips::check_key_template(
        pritmpl,
        res_or_ret!(rstate.get_fips_behavior(slot_id))
    ));

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
    let rstate = global_rlock!((*STATE));
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
    let wrapped: &mut [u8] = if wrapped_key.is_null() {
        &mut [] /* empty buffer will be always too small */
    } else {
        let wraplen = cast_or_ret!(usize from pwraplen => CKR_ARGUMENTS_BAD);
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
    let rstate = global_rlock!((*STATE));
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

    #[cfg(feature = "fips")]
    res_or_ret!(fips::check_key_template(
        tmpl,
        res_or_ret!(rstate.get_fips_behavior(slot_id))
    ));

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
    let rstate = global_rlock!((*STATE));
    let session = res_or_ret!(rstate.get_session(s_handle));

    let mechanism: &CK_MECHANISM = unsafe { &*mechptr };
    let cnt = cast_or_ret!(usize from attribute_count);
    let tmpl: &mut [CK_ATTRIBUTE] =
        unsafe { std::slice::from_raw_parts_mut(template, cnt) };
    if !session.is_writable() {
        fail_if_cka_token_true!(&*tmpl);
    }

    let slot_id = session.get_slot_id();

    #[cfg(feature = "fips")]
    res_or_ret!(fips::check_key_template(
        tmpl,
        res_or_ret!(rstate.get_fips_behavior(slot_id))
    ));

    let mut token = res_or_ret!(rstate.get_token_from_slot_mut(slot_id));
    let key = res_or_ret!(token.get_object_by_handle(base_key_handle));

    /* key checks
     * NOTE: we avoid checking for CKA_DERIVE for CKM_PUB_KEY_FROM_PRIV_KEY
     * because we think this operation should alays be possible regardless
     * of whether private key should generally allow key derivation. This
     * is our (Kryoptic team) interpretation and may change if/when the
     * OASIS PKCS#11 TC clarifies the spec in this regard */
    if mechanism.mechanism != CKM_PUB_KEY_FROM_PRIV_KEY {
        if !res_or_ret!(key.get_attr_as_bool(CKA_DERIVE)) {
            return CKR_KEY_FUNCTION_NOT_PERMITTED;
        }
    }
    ok_or_ret!(check_allowed_mechs(mechanism, &key));

    let mech = res_or_ret!(token.get_mechanisms().get(mechanism.mechanism));
    if mech.info().flags & CKF_DERIVE != CKF_DERIVE {
        return CKR_MECHANISM_INVALID;
    }

    let mut operation = res_or_ret!(mech.derive_operation(mechanism));

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

            if !key_handle.is_null() {
                unsafe {
                    core::ptr::write(key_handle, kh);
                }
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
            if !key_handle.is_null() {
                unsafe {
                    core::ptr::write(key_handle, kh);
                }
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
    drop(res_or_ret!(global_rlock!((*STATE)).get_session(s_handle)));
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
    drop(res_or_ret!(global_rlock!((*STATE)).get_session(s_handle)));
    let rndlen = cast_or_ret!(usize from random_len);
    let data: &mut [u8] =
        unsafe { std::slice::from_raw_parts_mut(random_data, rndlen) };
    ret_to_rv!(get_random_data(data))
}

/// Implementation of C_GetFunctionStatus function
/// (Legacy function. Always returns `CKR_FUNCTION_NOT_PARALLEL`)
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203361](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203361)

extern "C" fn fn_get_function_status(_session: CK_SESSION_HANDLE) -> CK_RV {
    CKR_FUNCTION_NOT_PARALLEL
}

/// Implementation of C_CancelFunction function
/// (Legacy function. Always returns `CKR_FUNCTION_NOT_PARALLEL`)
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203362](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203362)

extern "C" fn fn_cancel_function(_session: CK_SESSION_HANDLE) -> CK_RV {
    CKR_FUNCTION_NOT_PARALLEL
}

/// FFI Compatible structure that holds the PKCS#11 v2.40 functions table
pub(crate) static FNLIST_240: CK_FUNCTION_LIST = CK_FUNCTION_LIST {
    version: CK_VERSION {
        major: 2,
        minor: 40,
    },
    C_Initialize: Some(fn_initialize),
    C_Finalize: Some(fn_finalize),
    C_GetInfo: Some(fn_get_info),
    C_GetFunctionList: Some(fn_get_function_list),
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

/// Holds the version of the implemented interface to return by default
pub(crate) static IMPLEMENTED_VERSION: CK_VERSION =
    CK_VERSION { major: 3, minor: 2 };

static MANUFACTURER_ID: [CK_UTF8CHAR; 32usize] =
    *b"Kryoptic                        ";
static LIBRARY_DESCRIPTION: [CK_UTF8CHAR; 32usize] =
    *b"Kryoptic PKCS11 Module          ";
static LIBRARY_VERSION: CK_VERSION = CK_VERSION { major: 0, minor: 0 };

/// The default module info data
pub(crate) static MODULE_INFO: CK_INFO = CK_INFO {
    cryptokiVersion: IMPLEMENTED_VERSION,
    manufacturerID: MANUFACTURER_ID,
    flags: 0,
    libraryDescription: LIBRARY_DESCRIPTION,
    libraryVersion: LIBRARY_VERSION,
};

// Additional 3.0 functions

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

/// FFI Compatible structure that holds the PKCS#11 v3.0 functions table
pub(crate) static FNLIST_300: CK_FUNCTION_LIST_3_0 = CK_FUNCTION_LIST_3_0 {
    version: CK_VERSION { major: 3, minor: 0 },
    C_Initialize: Some(fn_initialize),
    C_Finalize: Some(fn_finalize),
    C_GetInfo: Some(fn_get_info),
    C_GetFunctionList: Some(fn_get_function_list),
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
    C_GetInterfaceList: Some(fn_get_interface_list),
    C_GetInterface: Some(fn_get_interface),
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

/// Implementation of C_EncapsulateKey function
///
/// Version 3.2 Specification: [link TBD]

extern "C" fn fn_encapsulate_key(
    s_handle: CK_SESSION_HANDLE,
    mechptr: *mut CK_MECHANISM,
    pubkey_handle: CK_OBJECT_HANDLE,
    template: *mut CK_ATTRIBUTE,
    attribute_count: CK_ULONG,
    encrypted_part: *mut CK_BYTE,
    encrypted_part_len: *mut CK_ULONG,
    key_handle: *mut CK_OBJECT_HANDLE,
) -> CK_RV {
    let rstate = global_rlock!((*STATE));
    let session = res_or_ret!(rstate.get_session(s_handle));

    let mechanism: &CK_MECHANISM = unsafe { &*mechptr };
    let cnt = cast_or_ret!(usize from attribute_count);
    let tmpl: &[CK_ATTRIBUTE] =
        unsafe { std::slice::from_raw_parts(template, cnt) };
    if !session.is_writable() {
        fail_if_cka_token_true!(tmpl);
    }

    let penclen = unsafe { *encrypted_part_len as CK_ULONG };
    let enclen = cast_or_ret!(usize from penclen => CKR_ARGUMENTS_BAD);

    let slot_id = session.get_slot_id();

    #[cfg(feature = "fips")]
    res_or_ret!(fips::check_key_template(
        tmpl,
        res_or_ret!(rstate.get_fips_behavior(slot_id))
    ));

    let mut token = res_or_ret!(rstate.get_token_from_slot_mut(slot_id));
    let key = res_or_ret!(token.get_object_by_handle(pubkey_handle));
    ok_or_ret!(check_allowed_mechs(mechanism, &key));
    let factories = token.get_object_factories();
    let factory =
        res_or_ret!(factories.get_obj_factory_from_key_template(tmpl));
    let mech = res_or_ret!(token.get_mechanisms().get(mechanism.mechanism));
    if mech.info().flags & CKF_ENCAPSULATE != CKF_ENCAPSULATE {
        return CKR_MECHANISM_INVALID;
    }

    let ciphertext_len = res_or_ret!(mech.encapsulate_ciphertext_len(&key));
    let ctext_len = cast_or_ret!(CK_ULONG from ciphertext_len);
    if encrypted_part.is_null() {
        unsafe {
            *encrypted_part_len = ctext_len;
        }
        return CKR_OK;
    }
    if ciphertext_len > enclen {
        return CKR_BUFFER_TOO_SMALL;
    }

    let encpart: &mut [u8] =
        unsafe { std::slice::from_raw_parts_mut(encrypted_part, enclen) };

    #[allow(unused_mut)]
    let (mut obj, outlen) =
        res_or_ret!(mech.encapsulate(mechanism, &key, factory, tmpl, encpart));

    #[cfg(feature = "fips")]
    {
        /* must drop here or we deadlock trying to re-acquire for writing */
        drop(session);

        let mut session = res_or_ret!(rstate.get_session_mut(s_handle));
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
    let retlen = cast_or_ret!(CK_ULONG from outlen);

    let kh = res_or_ret!(token.insert_object(s_handle, obj));
    unsafe {
        *key_handle = kh;
        *encrypted_part_len = retlen;
    }
    CKR_OK
}

/// Implementation of C_DecapsulateKey function
///
/// Version 3.2 Specification: [link TBD]

extern "C" fn fn_decapsulate_key(
    s_handle: CK_SESSION_HANDLE,
    mechptr: *mut CK_MECHANISM,
    privkey_handle: CK_OBJECT_HANDLE,
    template: *mut CK_ATTRIBUTE,
    attribute_count: CK_ULONG,
    encrypted_part: *mut CK_BYTE,
    encrypted_part_len: CK_ULONG,
    key_handle: *mut CK_OBJECT_HANDLE,
) -> CK_RV {
    let rstate = global_rlock!((*STATE));
    let session = res_or_ret!(rstate.get_session(s_handle));

    let mechanism: &CK_MECHANISM = unsafe { &*mechptr };
    let cnt = cast_or_ret!(usize from attribute_count);
    let tmpl: &[CK_ATTRIBUTE] =
        unsafe { std::slice::from_raw_parts(template, cnt) };
    if !session.is_writable() {
        fail_if_cka_token_true!(tmpl);
    }

    let enclen =
        cast_or_ret!(usize from encrypted_part_len => CKR_ARGUMENTS_BAD);
    let encpart: &[u8] =
        unsafe { std::slice::from_raw_parts(encrypted_part, enclen) };

    let slot_id = session.get_slot_id();

    #[cfg(feature = "fips")]
    res_or_ret!(fips::check_key_template(
        tmpl,
        res_or_ret!(rstate.get_fips_behavior(slot_id))
    ));

    let mut token = res_or_ret!(rstate.get_token_from_slot_mut(slot_id));
    let key = res_or_ret!(token.get_object_by_handle(privkey_handle));
    ok_or_ret!(check_allowed_mechs(mechanism, &key));
    let factories = token.get_object_factories();
    let factory =
        res_or_ret!(factories.get_obj_factory_from_key_template(tmpl));
    let mech = res_or_ret!(token.get_mechanisms().get(mechanism.mechanism));
    if mech.info().flags & CKF_DECAPSULATE != CKF_DECAPSULATE {
        return CKR_MECHANISM_INVALID;
    }

    #[allow(unused_mut)]
    let mut obj =
        res_or_ret!(mech.decapsulate(mechanism, &key, factory, tmpl, encpart));

    #[cfg(feature = "fips")]
    {
        /* must drop here or we deadlock trying to re-acquire for writing */
        drop(session);

        let mut session = res_or_ret!(rstate.get_session_mut(s_handle));
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

    let kh = res_or_ret!(token.insert_object(s_handle, obj));
    unsafe {
        *key_handle = kh;
    }
    CKR_OK
}

/// Implementation of C_VerifySignatureInit
///
/// Version 3.2 Specification: [Link TBD]

extern "C" fn fn_verify_signature_init(
    s_handle: CK_SESSION_HANDLE,
    mechptr: *mut CK_MECHANISM,
    key_handle: CK_OBJECT_HANDLE,
    psignature: *mut CK_BYTE,
    psignature_len: CK_ULONG,
) -> CK_RV {
    let rstate = global_rlock!((*STATE));
    let mut session = res_or_ret!(rstate.get_session_mut(s_handle));
    check_op_empty_or_fail!(session; Verify; mechptr);
    let mechanism: &CK_MECHANISM = unsafe { &*mechptr };
    let slot_id = session.get_slot_id();
    let mut token = res_or_ret!(rstate.get_token_from_slot_mut(slot_id));
    let key = res_or_ret!(token.get_object_by_handle(key_handle));
    ok_or_ret!(check_allowed_mechs(mechanism, &key));
    let mech = res_or_ret!(token.get_mechanisms().get(mechanism.mechanism));
    if mech.info().flags & CKF_VERIFY != CKF_VERIFY {
        return CKR_MECHANISM_INVALID;
    }

    let sig_len = cast_or_ret!(usize from psignature_len);
    let signature: &[u8] =
        unsafe { std::slice::from_raw_parts(psignature, sig_len) };
    let operation =
        res_or_ret!(mech.verify_signature_new(mechanism, &key, signature));
    session.set_operation::<dyn VerifySignature>(operation, false);

    #[cfg(feature = "fips")]
    init_fips_approval(session, mechanism.mechanism, CKF_VERIFY, &key);

    CKR_OK
}

/// Implementation of C_VerifySignature
///
/// Version 3.2 Specification: [Link TBD]

extern "C" fn fn_verify_signature(
    s_handle: CK_SESSION_HANDLE,
    pdata: *mut CK_BYTE,
    data_len: CK_ULONG,
) -> CK_RV {
    if pdata.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    let rstate = global_rlock!((*STATE));
    let mut session = res_or_ret!(rstate.get_session_mut(s_handle));
    let operation = res_or_ret!(session.get_operation::<dyn VerifySignature>());
    let dlen = cast_or_ret!(usize from data_len => CKR_ARGUMENTS_BAD);
    let data: &[u8] = unsafe { std::slice::from_raw_parts(pdata, dlen) };
    let ret = ret_to_rv!(operation.verify(data));

    #[cfg(feature = "fips")]
    if ret == CKR_OK {
        let approved = operation.fips_approved();
        finalize_fips_approval(session, approved);
    }

    ret
}

/// Implementation of C_VerifySignatureUpdate
///
/// Version 3.2 Specification: [Link TBD]

extern "C" fn fn_verify_signature_update(
    s_handle: CK_SESSION_HANDLE,
    part: *mut CK_BYTE,
    part_len: CK_ULONG,
) -> CK_RV {
    if part.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    let rstate = global_rlock!((*STATE));
    let mut session = res_or_ret!(rstate.get_session_mut(s_handle));
    let operation = res_or_ret!(session.get_operation::<dyn VerifySignature>());
    let plen = cast_or_ret!(usize from part_len => CKR_ARGUMENTS_BAD);
    let data: &[u8] = unsafe { std::slice::from_raw_parts(part, plen) };
    ret_to_rv!(operation.verify_update(data))
}

/// Implementation of C_VerifySignatureFinal
///
/// Version 3.2 Specification: [Link TBD]

extern "C" fn fn_verify_signature_final(s_handle: CK_SESSION_HANDLE) -> CK_RV {
    let rstate = global_rlock!((*STATE));
    let mut session = res_or_ret!(rstate.get_session_mut(s_handle));
    let operation = res_or_ret!(session.get_operation::<dyn VerifySignature>());
    let ret = ret_to_rv!(operation.verify_final());

    #[cfg(feature = "fips")]
    if ret == CKR_OK {
        let approved = operation.fips_approved();
        finalize_fips_approval(session, approved);
    }

    ret
}

extern "C" fn fn_async_complete(
    _s_handle: CK_SESSION_HANDLE,
    _function_name: *mut CK_UTF8CHAR,
    _result: *mut CK_ASYNC_DATA,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

extern "C" fn fn_async_get_id(
    _s_handle: CK_SESSION_HANDLE,
    _function_name: *mut CK_UTF8CHAR,
    _operation_id: *mut CK_ULONG,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

extern "C" fn fn_async_join(
    _s_handle: CK_SESSION_HANDLE,
    _function_name: *mut CK_UTF8CHAR,
    _operation_id: CK_ULONG,
    _data: *mut CK_BYTE,
    _data_len: CK_ULONG,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

extern "C" fn fn_wrap_key_authenticated(
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

extern "C" fn fn_unwrap_key_authenticated(
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

/// FFI Compatible structure that holds the PKCS#11 v3.2 functions table
static FNLIST_320: CK_FUNCTION_LIST_3_2 = CK_FUNCTION_LIST_3_2 {
    version: CK_VERSION { major: 3, minor: 2 },
    C_Initialize: Some(fn_initialize),
    C_Finalize: Some(fn_finalize),
    C_GetInfo: Some(fn_get_info),
    C_GetFunctionList: Some(fn_get_function_list),
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
    C_GetInterfaceList: Some(fn_get_interface_list),
    C_GetInterface: Some(fn_get_interface),
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
    C_EncapsulateKey: Some(fn_encapsulate_key),
    C_DecapsulateKey: Some(fn_decapsulate_key),
    C_VerifySignatureInit: Some(fn_verify_signature_init),
    C_VerifySignature: Some(fn_verify_signature),
    C_VerifySignatureUpdate: Some(fn_verify_signature_update),
    C_VerifySignatureFinal: Some(fn_verify_signature_final),
    C_GetSessionValidationFlags: Some(fn_get_session_validation_flags),
    C_AsyncComplete: Some(fn_async_complete),
    C_AsyncGetID: Some(fn_async_get_id),
    C_AsyncJoin: Some(fn_async_join),
    C_WrapKeyAuthenticated: Some(fn_wrap_key_authenticated),
    C_UnwrapKeyAuthenticated: Some(fn_unwrap_key_authenticated),
};

/// PKCS#11 reserved name for the standard official interfaces
static INTERFACE_NAME_STD_NUL: &str = "PKCS 11\0";

/// Holds pointers to v2.40 interface
static INTERFACE_240: CK_INTERFACE = CK_INTERFACE {
    pInterfaceName: INTERFACE_NAME_STD_NUL.as_ptr() as *mut u8,
    pFunctionList: &FNLIST_240 as *const _ as *const ::std::os::raw::c_void,
    flags: 0,
};

/// Holds pointers to v3.0 interface
static INTERFACE_300: CK_INTERFACE = CK_INTERFACE {
    pInterfaceName: INTERFACE_NAME_STD_NUL.as_ptr() as *mut u8,
    pFunctionList: &FNLIST_300 as *const _ as *const ::std::os::raw::c_void,
    flags: 0,
};

/// Holds pointers to v3.2 interface
static INTERFACE_320: CK_INTERFACE = CK_INTERFACE {
    pInterfaceName: INTERFACE_NAME_STD_NUL.as_ptr() as *mut u8,
    pFunctionList: &FNLIST_320 as *const _ as *const ::std::os::raw::c_void,
    flags: 0,
};

/// Structure that holds a pointer to the interface structure.
/// It is used when applications request a specific interface version,
/// and we need to return the associated structure via FFI.

#[derive(Debug, Copy, Clone)]
struct InterfaceData {
    interface: *const CK_INTERFACE,
    version: CK_VERSION,
}
unsafe impl Sync for InterfaceData {}
unsafe impl Send for InterfaceData {}

/// The set of known interfaces we can return to applications

static INTERFACE_SET: LazyLock<Vec<InterfaceData>> = LazyLock::new(|| {
    let mut v = Vec::with_capacity(3);
    v.push(InterfaceData {
        interface: std::ptr::addr_of!(INTERFACE_320),
        version: FNLIST_320.version,
    });
    v.push(InterfaceData {
        interface: std::ptr::addr_of!(INTERFACE_300),
        version: FNLIST_300.version,
    });
    v.push(InterfaceData {
        interface: std::ptr::addr_of!(INTERFACE_240),
        version: FNLIST_240.version,
    });
    v
});

#[cfg(feature = "log")]
mod log;

#[cfg(test)]
mod tests;
