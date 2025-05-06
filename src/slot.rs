// Copyright 2023 Simo Sorce
// See LICENSE.txt file for terms

//! This module defines the `Slot` structure, which represents a PKCS#11 slot.
//! It manages the associated token and the sessions opened against that token.

use std::collections::HashMap;
use std::sync::{RwLock, RwLockReadGuard, RwLockWriteGuard};

use crate::config;
use crate::defaults;
use crate::error::Result;
use crate::interface::*;
use crate::misc::copy_sized_string;
use crate::session::Session;
use crate::token::Token;

/// Represents a PKCS#11 Slot, containing information about the slot itself,
/// the `Token` present in the slot, and currently open `Session`s.
#[derive(Debug)]
pub struct Slot {
    /// Static information about the slot.
    slot_info: CK_SLOT_INFO,
    /// The token associated with this slot, protected by a RwLock.
    token: RwLock<Token>,
    /// Map of active sessions associated with this slot, keyed by session handle.
    sessions: HashMap<CK_SESSION_HANDLE, RwLock<Session>>,
}

impl Slot {
    /// Creates a new Slot instance based on the provided configuration.
    ///
    /// Initializes the contained `Token` with its database backend.
    pub fn new(config: &config::Slot) -> Result<Slot> {
        let dbtype: &str;
        let dbargs: Option<String>;

        match &config.dbtype {
            Some(t) => dbtype = t.as_str(),
            None => return Err(CKR_GENERAL_ERROR)?,
        }
        match &config.dbargs {
            Some(p) => dbargs = Some(p.clone()),
            None => dbargs = None,
        }

        let mut slot = Slot {
            slot_info: CK_SLOT_INFO {
                slotDescription: [0; 64],
                manufacturerID: [0; 32],
                flags: CKF_TOKEN_PRESENT,
                hardwareVersion: defaults::hardware_version(),
                firmwareVersion: defaults::firmware_version(),
            },
            token: RwLock::new(Token::new(dbtype, dbargs)?),
            sessions: HashMap::new(),
        };

        /* fill strings */
        copy_sized_string(
            match &config.description {
                Some(d) => d.as_bytes(),
                None => defaults::SLOT_DESCRIPTION.as_bytes(),
            },
            &mut slot.slot_info.slotDescription,
        );
        copy_sized_string(
            match &config.manufacturer {
                Some(m) => m.as_bytes(),
                None => defaults::MANUFACTURER_ID.as_bytes(),
            },
            &mut slot.slot_info.manufacturerID,
        );
        Ok(slot)
    }

    /// Returns a reference to the static slot information (`CK_SLOT_INFO`).
    pub fn get_slot_info(&self) -> &CK_SLOT_INFO {
        &self.slot_info
    }

    /// Returns a copy of the token information (`CK_TOKEN_INFO`) for the
    /// token within this slot. Acquires a read lock on the token.
    pub fn get_token_info(&self) -> CK_TOKEN_INFO {
        let tok = self.token.read().unwrap();
        *tok.get_token_info()
    }

    /// Gets a read lock guard for the `Token` in this slot.
    /// Returns an error if the token is not initialized.
    pub fn get_token(&self) -> Result<RwLockReadGuard<'_, Token>> {
        match self.token.read() {
            Ok(token) => {
                if token.is_initialized() {
                    Ok(token)
                } else {
                    /* FIXME: once we have CKR_TOKEN_NOT_INITIALIZED as an
                     * available error, we should rreturn that instead */
                    Err(KRR_TOKEN_NOT_INITIALIZED)?
                }
            }
            Err(_) => Err(CKR_GENERAL_ERROR)?,
        }
    }

    /// Gets a write lock guard for the `Token` in this slot.
    /// Returns an error if the token is not initialized, unless `nochecks`
    /// is true (used during initialization).
    pub fn get_token_mut(
        &self,
        nochecks: bool,
    ) -> Result<RwLockWriteGuard<'_, Token>> {
        match self.token.write() {
            Ok(token) => {
                if nochecks {
                    Ok(token)
                } else if token.is_initialized() {
                    Ok(token)
                } else {
                    /* FIXME: once we have CKR_TOKEN_NOT_INITIALIZED as an
                     * available error, we should rreturn that instead */
                    Err(KRR_TOKEN_NOT_INITIALIZED)?
                }
            }
            Err(_) => Err(CKR_GENERAL_ERROR)?,
        }
    }

    /// Adds a newly created session to this slot's session map.
    pub fn add_session(&mut self, handle: CK_SESSION_HANDLE, session: Session) {
        self.sessions.insert(handle, RwLock::new(session));
    }

    /// Gets a read lock guard for a specific `Session` identified by its
    /// handle. Returns an error if the handle is invalid.
    pub fn get_session(
        &self,
        handle: CK_SESSION_HANDLE,
    ) -> Result<RwLockReadGuard<'_, Session>> {
        match self.sessions.get(&handle) {
            Some(s) => match s.read() {
                Ok(sess) => Ok(sess),
                Err(_) => Err(CKR_GENERAL_ERROR)?,
            },
            None => Err(CKR_SESSION_HANDLE_INVALID)?,
        }
    }

    /// Gets a write lock guard for a specific `Session` identified by its
    /// handle. Returns an error if the handle is invalid or the lock cannot
    /// be acquired.
    pub fn get_session_mut(
        &self,
        handle: CK_SESSION_HANDLE,
    ) -> Result<RwLockWriteGuard<'_, Session>> {
        match self.sessions.get(&handle) {
            Some(s) => match s.write() {
                Ok(sess) => Ok(sess),
                Err(_) => Err(CKR_GENERAL_ERROR)?,
            },
            None => Err(CKR_SESSION_HANDLE_INVALID)?,
        }
    }

    /// Returns true if there are any active sessions associated with this slot.
    pub fn has_sessions(&self) -> bool {
        self.sessions.len() > 0
    }

    /// Returns true if there are any active read-only sessions associated
    /// with this slot.
    pub fn has_ro_sessions(&self) -> bool {
        for (_key, val) in self.sessions.iter() {
            match val.read().unwrap().get_session_info().state {
                CKS_RO_PUBLIC_SESSION | CKS_RO_USER_FUNCTIONS => return true,
                _ => (),
            }
        }
        false
    }

    /// Changes the session state for all active sessions associated with this
    /// slot based on the provided user type.
    pub fn change_session_states(&self, user_type: CK_USER_TYPE) -> Result<()> {
        for (_key, val) in self.sessions.iter() {
            let ret = val.write().unwrap().change_session_state(user_type);
            if ret != CKR_OK {
                return Err(ret)?;
            }
        }
        Ok(())
    }

    /// Invalidates the session state for all sessions (sets them to public state).
    pub fn invalidate_session_states(&self) {
        for (_key, val) in self.sessions.iter() {
            let _ = val
                .write()
                .unwrap()
                .change_session_state(CK_UNAVAILABLE_INFORMATION);
        }
    }

    /// Removes a specific session identified by its handle.
    pub fn drop_session(&mut self, handle: CK_SESSION_HANDLE) {
        self.sessions.remove(&handle);
    }

    /// Removes all sessions associated with this slot, returning a vector of
    /// their handles.
    pub fn drop_all_sessions(&mut self) -> Vec<CK_SESSION_HANDLE> {
        let mut handles =
            Vec::<CK_SESSION_HANDLE>::with_capacity(self.sessions.len());
        for key in self.sessions.keys() {
            handles.push(*key);
        }
        self.sessions.clear();
        handles
    }

    /// Finalizes the slot. This drops all sessions and attempts to save the
    /// token state.
    pub fn finalize(&mut self) -> Result<()> {
        self.drop_all_sessions();
        self.token.write().unwrap().save()
    }
}
