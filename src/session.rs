// Copyright 2023 Simo Sorce
// See LICENSE.txt file for terms

use super::interface;

use interface::{CK_RV, CKR_OK};

#[derive(Debug, Clone, Copy)]
pub struct Session {
    handle: interface::CK_SESSION_HANDLE,

    flags: interface::CK_FLAGS,
    //application: interface::CK_VOID_PTR,
    //notify: interface::CK_NOTIFY,

    state: interface::CK_STATE,
    device_error: interface::CK_ULONG,
}

impl Session {
    pub fn new(handle: interface::CK_SESSION_HANDLE,
               flags: interface::CK_FLAGS) -> (Option<Session>, CK_RV) {
        if handle == interface::CK_INVALID_HANDLE {
            return (None, interface::CKR_GENERAL_ERROR);
        }
        if flags & interface::CKF_SERIAL_SESSION != interface::CKF_SERIAL_SESSION {
            return (None, interface::CKR_ARGUMENTS_BAD);
        }

        let mut s = Session {
            handle: handle,
            flags: flags,
            //application: std::ptr::null_mut(),
            //notify: unsafe { std::ptr::null_mut() },
            state: interface::CKS_RO_PUBLIC_SESSION,
            device_error: 0
        };

        // FIXME check Login status
        if flags & interface::CKF_RW_SESSION == interface::CKF_RW_SESSION {
            if s.state == interface::CKS_RO_PUBLIC_SESSION {
                s.state = interface::CKS_RW_PUBLIC_SESSION;
            } else if s.state == interface::CKS_RO_USER_FUNCTIONS {
                s.state = interface::CKS_RW_USER_FUNCTIONS;
            }
        }

        (Some(s), CKR_OK)
    }
}
