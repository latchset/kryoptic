// Copyright 2023 Simo Sorce
// See LICENSE.txt file for terms

use std::vec::Vec;

use super::interface;
use super::error;

use interface::*;
use error::{KResult, KError};
use super::err_rv;

#[derive(Debug, Clone)]
pub struct Session {
    handle: CK_SESSION_HANDLE,

    info: CK_SESSION_INFO,
    //application: CK_VOID_PTR,
    //notify: CK_NOTIFY,

    session_handles: Vec<CK_OBJECT_HANDLE>,
    search_handles: Vec<CK_OBJECT_HANDLE>,
}

impl Session {
    pub fn new(slotid: CK_SLOT_ID,
               handle: CK_SESSION_HANDLE,
               flags: CK_FLAGS) -> KResult<Session> {
        if handle == CK_INVALID_HANDLE {
            return err_rv!(CKR_GENERAL_ERROR);
        }
        if flags & CKF_SERIAL_SESSION != CKF_SERIAL_SESSION {
            return err_rv!(CKR_ARGUMENTS_BAD);
        }

        let mut s = Session {
            handle: handle,
            info: CK_SESSION_INFO {
                slotID: slotid,
                state: CKS_RO_PUBLIC_SESSION,
                flags: flags,
                ulDeviceError: 0,
            },
            //application: std::ptr::null_mut(),
            //notify: unsafe { std::ptr::null_mut() },
            session_handles: Vec::<CK_OBJECT_HANDLE>::new(),
            search_handles: Vec::<CK_OBJECT_HANDLE>::new(),
        };

        // FIXME check Login status
        if flags & CKF_RW_SESSION == CKF_RW_SESSION {
            if s.info.state == CKS_RO_PUBLIC_SESSION {
                s.info.state = CKS_RW_PUBLIC_SESSION;
            } else if s.info.state == CKS_RO_USER_FUNCTIONS {
                s.info.state = CKS_RW_USER_FUNCTIONS;
            }
        }

        Ok(s)
    }

    pub fn get_handle(&self) -> CK_SESSION_HANDLE {
        self.handle
    }

    pub fn add_handle(&mut self, handle: CK_OBJECT_HANDLE) {
        self.session_handles.push(handle);
    }

    pub fn reset_search_handles(&mut self) {
        self.search_handles.clear();
    }

    pub fn add_search_handle(&mut self, handle: CK_OBJECT_HANDLE) {
        self.search_handles.push(handle);
    }

    pub fn get_search_handles(&mut self, max: usize) -> KResult<Vec<CK_OBJECT_HANDLE>> {
        let mut amount = self.search_handles.len();
        if max < amount {
            amount = max;
        }
        Ok(self.search_handles.drain(0..amount).collect())
    }

    pub fn get_session_info(&self) -> &CK_SESSION_INFO {
        &self.info
    }

    pub fn set_user_functions(&mut self, on: bool) {
        match on {
            true => match self.info.state {
                CKS_RO_PUBLIC_SESSION => self.info.state = CKS_RO_USER_FUNCTIONS,
                CKS_RW_PUBLIC_SESSION => self.info.state = CKS_RW_USER_FUNCTIONS,
                _ => (),
            },
            false => match self.info.state {
                CKS_RO_USER_FUNCTIONS => self.info.state = CKS_RO_PUBLIC_SESSION,
                CKS_RW_USER_FUNCTIONS => self.info.state = CKS_RW_PUBLIC_SESSION,
                _ => (),
            }
        };
    }

    pub fn is_writable(&self) -> bool {
        match self.info.state {
            CKS_RW_PUBLIC_SESSION => true,
            CKS_RW_USER_FUNCTIONS => true,
            _ => false,
        }
    }
}
