// Copyright 2023 Simo Sorce
// See LICENSE.txt file for terms

use std::collections::HashMap;
use std::sync::{RwLock, RwLockReadGuard, RwLockWriteGuard};

use super::error;
use super::interface;
use super::session::Session;
use super::token::Token;

use super::err_rv;
use error::{KError, KResult};
use interface::*;

static SLOT_DESCRIPTION: [CK_UTF8CHAR; 64usize] =
    *b"Kryoptic SLot                                                   ";
static MANUFACTURER_ID: [CK_UTF8CHAR; 32usize] =
    *b"Kryoptic                        ";

#[derive(Debug)]
pub struct Slot {
    slot_info: CK_SLOT_INFO,
    token: RwLock<Token>,
    sessions: HashMap<CK_SESSION_HANDLE, RwLock<Session>>,
}

impl Slot {
    pub fn new(filename: String) -> KResult<Slot> {
        Ok(Slot {
            slot_info: CK_SLOT_INFO {
                slotDescription: SLOT_DESCRIPTION,
                manufacturerID: MANUFACTURER_ID,
                flags: CKF_TOKEN_PRESENT,
                hardwareVersion: CK_VERSION { major: 0, minor: 0 },
                firmwareVersion: CK_VERSION { major: 0, minor: 0 },
            },
            token: RwLock::new(Token::new(filename)?),
            sessions: HashMap::new(),
        })
    }

    pub fn get_slot_info(&self) -> &CK_SLOT_INFO {
        &self.slot_info
    }

    pub fn get_token_info(&self) -> CK_TOKEN_INFO {
        let tok = self.token.read().unwrap();
        *tok.get_token_info()
    }

    pub fn get_token(&self) -> KResult<RwLockReadGuard<'_, Token>> {
        match self.token.read() {
            Ok(token) => {
                if token.is_initialized() {
                    Ok(token)
                } else {
                    /* FIXME: once we have CKR_TOKEN_NOT_INITIALIZED as an
                     * available error, we should rreturn that instead */
                    err_rv!(KRYERR_TOKEN_NOT_INITIALIZED)
                }
            }
            Err(_) => err_rv!(CKR_GENERAL_ERROR),
        }
    }

    pub fn get_token_mut(
        &self,
        nochecks: bool,
    ) -> KResult<RwLockWriteGuard<'_, Token>> {
        match self.token.write() {
            Ok(token) => {
                if nochecks {
                    Ok(token)
                } else if token.is_initialized() {
                    Ok(token)
                } else {
                    /* FIXME: once we have CKR_TOKEN_NOT_INITIALIZED as an
                     * available error, we should rreturn that instead */
                    err_rv!(KRYERR_TOKEN_NOT_INITIALIZED)
                }
            }
            Err(_) => err_rv!(CKR_GENERAL_ERROR),
        }
    }

    pub fn add_session(&mut self, handle: CK_SESSION_HANDLE, session: Session) {
        self.sessions.insert(handle, RwLock::new(session));
    }

    pub fn get_session(
        &self,
        handle: CK_SESSION_HANDLE,
    ) -> KResult<RwLockReadGuard<'_, Session>> {
        match self.sessions.get(&handle) {
            Some(s) => match s.read() {
                Ok(sess) => Ok(sess),
                Err(_) => err_rv!(CKR_GENERAL_ERROR),
            },
            None => err_rv!(CKR_SESSION_HANDLE_INVALID),
        }
    }

    pub fn get_session_mut(
        &self,
        handle: CK_SESSION_HANDLE,
    ) -> KResult<RwLockWriteGuard<'_, Session>> {
        match self.sessions.get(&handle) {
            Some(s) => match s.write() {
                Ok(sess) => Ok(sess),
                Err(_) => err_rv!(CKR_GENERAL_ERROR),
            },
            None => err_rv!(CKR_SESSION_HANDLE_INVALID),
        }
    }

    pub fn has_sessions(&self) -> bool {
        self.sessions.len() > 0
    }

    pub fn has_ro_sessions(&self) -> bool {
        for (_key, val) in self.sessions.iter() {
            match val.read().unwrap().get_session_info().state {
                CKS_RO_PUBLIC_SESSION | CKS_RO_USER_FUNCTIONS => return true,
                _ => (),
            }
        }
        false
    }

    pub fn change_session_states(
        &self,
        user_type: CK_USER_TYPE,
    ) -> KResult<()> {
        for (_key, val) in self.sessions.iter() {
            let ret = val.write().unwrap().change_session_state(user_type);
            if ret != CKR_OK {
                return err_rv!(ret);
            }
        }
        Ok(())
    }

    pub fn invalidate_session_states(&self) {
        for (_key, val) in self.sessions.iter() {
            let _ = val
                .write()
                .unwrap()
                .change_session_state(CK_UNAVAILABLE_INFORMATION);
        }
    }

    pub fn drop_session(&mut self, handle: CK_SESSION_HANDLE) {
        self.sessions.remove(&handle);
    }

    pub fn drop_all_sessions(&mut self) -> Vec<CK_SESSION_HANDLE> {
        let mut handles =
            Vec::<CK_SESSION_HANDLE>::with_capacity(self.sessions.len());
        for key in self.sessions.keys() {
            handles.push(*key);
        }
        self.sessions.clear();
        handles
    }

    pub fn finalize(&mut self) -> KResult<()> {
        self.drop_all_sessions();
        self.token.read().unwrap().save()
    }
}
