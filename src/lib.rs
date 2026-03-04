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
mod kasn1;
mod mechanism;
mod misc;
mod native;
mod object;
mod ossl;
mod rng;
mod session;
mod slot;
mod storage;
mod token;

/* Include algorithms based on selected features */
include!("enabled.rs");

#[cfg(feature = "fips")]
mod fips;

#[cfg(feature = "log")]
mod log;

pub mod fns;
pub mod pkcs11;

use config::Config;
use error::Result;
use pkcs11::*;
use rng::RNG;
use session::Session;
use slot::Slot;
use token::Token;

use fns::digest::*;
use fns::dualcrypto::*;
use fns::encryption::*;
use fns::general::*;
use fns::keymgmt::*;
use fns::objmgmt::*;
use fns::sessmgmt::*;
use fns::signing::*;
use fns::stmgmt::*;
use fns::*;

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

#[cfg(test)]
mod tests;
