// Copyright 2023 Simo Sorce
// See LICENSE.txt file for terms

use std::vec::Vec;

use super::interface;
use super::error;

use error::{KResult, KError};

#[derive(Debug, Clone)]
pub struct Session {
    info: interface::CK_SESSION_INFO,

    //application: interface::CK_VOID_PTR,
    //notify: interface::CK_NOTIFY,

    handle: interface::CK_SESSION_HANDLE,
    object_handles: Vec<interface::CK_OBJECT_HANDLE>,
}

impl Session {
    pub fn new(slotid: interface::CK_SLOT_ID,
               handle: interface::CK_SESSION_HANDLE,
               flags: interface::CK_FLAGS) -> KResult<Session> {
        if handle == interface::CK_INVALID_HANDLE {
            return Err(KError::RvError(error::CkRvError{rv: interface::CKR_GENERAL_ERROR}));
        }
        if flags & interface::CKF_SERIAL_SESSION != interface::CKF_SERIAL_SESSION {
            return Err(KError::RvError(error::CkRvError{rv: interface::CKR_ARGUMENTS_BAD}));
        }

        let mut s = Session {
            info: interface::CK_SESSION_INFO {
                slotID: slotid,
                state: interface::CKS_RO_PUBLIC_SESSION,
                flags: flags,
                ulDeviceError: 0,
            },
            //application: std::ptr::null_mut(),
            //notify: unsafe { std::ptr::null_mut() },
            handle: handle,
            object_handles: Vec::new(),
        };

        // FIXME check Login status
        if flags & interface::CKF_RW_SESSION == interface::CKF_RW_SESSION {
            if s.info.state == interface::CKS_RO_PUBLIC_SESSION {
                s.info.state = interface::CKS_RW_PUBLIC_SESSION;
            } else if s.info.state == interface::CKS_RO_USER_FUNCTIONS {
                s.info.state = interface::CKS_RW_USER_FUNCTIONS;
            }
        }

        Ok(s)
    }

    pub fn get_handle(&self) -> interface::CK_SESSION_HANDLE {
        self.handle
    }

    pub fn reset_object_handles(&mut self) {
        self.object_handles.clear();
    }

    pub fn append_object_handles(&mut self, handles: &mut Vec<interface::CK_OBJECT_HANDLE>) {
        self.object_handles.append(handles);
    }

    pub fn get_object_handles(&mut self, max: usize) -> KResult<Vec<interface::CK_OBJECT_HANDLE>> {
        let mut amount = max;
        if self.object_handles.len() < amount {
            amount = self.object_handles.len();
        }
        Ok(self.object_handles.drain(0..amount).collect())
    }

    pub fn get_session_info(&self) -> &interface::CK_SESSION_INFO {
        &self.info
    }
}
