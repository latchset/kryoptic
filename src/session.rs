// Copyright 2023 Simo Sorce
// See LICENSE.txt file for terms

use std::vec::Vec;

use super::error;
use super::interface;
use super::mechanism;
use super::token;

use super::err_rv;
use error::{KError, KResult};
use interface::*;
use mechanism::{Operation, SearchOperation};
use token::Token;

#[derive(Debug)]
pub struct SessionSearch {
    handles: Vec<CK_OBJECT_HANDLE>,
    in_use: bool,
}

impl SearchOperation for SessionSearch {
    fn results(&mut self, max: usize) -> KResult<Vec<CK_OBJECT_HANDLE>> {
        if !self.in_use {
            return err_rv!(CKR_OPERATION_NOT_INITIALIZED);
        }
        let mut amount = self.handles.len();
        if max < amount {
            amount = max;
        }
        Ok(self.handles.drain(0..amount).collect())
    }

    fn finalized(&self) -> bool {
        self.handles.len() == 0
    }
}

#[derive(Debug)]
pub struct Session {
    info: CK_SESSION_INFO,
    //application: CK_VOID_PTR,
    //notify: CK_NOTIFY,
    operation: Operation,
}

impl Session {
    pub fn new(
        slotid: CK_SLOT_ID,
        user_type: CK_USER_TYPE,
        flags: CK_FLAGS,
    ) -> KResult<Session> {
        if flags & CKF_SERIAL_SESSION != CKF_SERIAL_SESSION {
            return err_rv!(CKR_ARGUMENTS_BAD);
        }
        let rw = flags & CKF_RW_SESSION == CKF_RW_SESSION;

        Ok(Session {
            info: CK_SESSION_INFO {
                slotID: slotid,
                state: match user_type {
                    CK_UNAVAILABLE_INFORMATION => {
                        if rw {
                            CKS_RW_PUBLIC_SESSION
                        } else {
                            CKS_RO_PUBLIC_SESSION
                        }
                    }
                    CKU_USER => {
                        if rw {
                            CKS_RW_USER_FUNCTIONS
                        } else {
                            CKS_RO_USER_FUNCTIONS
                        }
                    }
                    CKU_SO => {
                        if rw {
                            CKS_RW_USER_FUNCTIONS
                        } else {
                            return err_rv!(CKR_OPERATION_NOT_INITIALIZED);
                        }
                    }
                    _ => return err_rv!(CKR_GENERAL_ERROR),
                },
                flags: flags,
                ulDeviceError: 0,
            },
            //application: std::ptr::null_mut(),
            //notify: unsafe { std::ptr::null_mut() },
            operation: Operation::Empty,
        })
    }

    pub fn get_session_info(&self) -> &CK_SESSION_INFO {
        &self.info
    }

    pub fn get_slot_id(&self) -> CK_SLOT_ID {
        self.info.slotID
    }

    /* a user type of CK_UNAVAILABLE_INFORMATION effects a "logout" to public */
    pub fn change_session_state(&mut self, user_type: CK_USER_TYPE) -> CK_RV {
        match self.info.state {
            CKS_RO_PUBLIC_SESSION => match user_type {
                CK_UNAVAILABLE_INFORMATION => CKR_OK,
                CKU_USER => {
                    self.info.state = CKS_RO_USER_FUNCTIONS;
                    CKR_OK
                }
                CKU_SO => CKR_OPERATION_NOT_INITIALIZED,
                _ => CKR_USER_TYPE_INVALID,
            },
            CKS_RW_PUBLIC_SESSION => match user_type {
                CK_UNAVAILABLE_INFORMATION => CKR_OK,
                CKU_USER => {
                    self.info.state = CKS_RW_USER_FUNCTIONS;
                    CKR_OK
                }
                CKU_SO => {
                    self.info.state = CKS_RW_SO_FUNCTIONS;
                    CKR_OK
                }
                _ => CKR_USER_TYPE_INVALID,
            },
            CKS_RO_USER_FUNCTIONS => match user_type {
                CK_UNAVAILABLE_INFORMATION => {
                    self.info.state = CKS_RO_PUBLIC_SESSION;
                    CKR_OK
                }
                CKU_USER => CKR_OK,
                CKU_SO => CKR_USER_ANOTHER_ALREADY_LOGGED_IN,
                _ => CKR_USER_TYPE_INVALID,
            },
            CKS_RW_USER_FUNCTIONS => match user_type {
                CK_UNAVAILABLE_INFORMATION => {
                    self.info.state = CKS_RW_PUBLIC_SESSION;
                    CKR_OK
                }
                CKU_USER => CKR_OK,
                CKU_SO => CKR_USER_ANOTHER_ALREADY_LOGGED_IN,
                _ => CKR_USER_TYPE_INVALID,
            },
            CKS_RW_SO_FUNCTIONS => match user_type {
                CK_UNAVAILABLE_INFORMATION => {
                    self.info.state = CKS_RW_PUBLIC_SESSION;
                    CKR_OK
                }
                CKU_USER => CKR_USER_ANOTHER_ALREADY_LOGGED_IN,
                CKU_SO => CKR_OK,
                _ => CKR_USER_TYPE_INVALID,
            },
            _ => CKR_GENERAL_ERROR,
        }
    }

    pub fn is_writable(&self) -> bool {
        match self.info.state {
            CKS_RW_PUBLIC_SESSION => true,
            CKS_RW_USER_FUNCTIONS => true,
            CKS_RW_SO_FUNCTIONS => true,
            _ => false,
        }
    }

    pub fn new_search_operation(
        &mut self,
        token: &mut Token,
        template: &[CK_ATTRIBUTE],
    ) -> KResult<()> {
        if !self.operation.finalized() {
            return err_rv!(CKR_OPERATION_ACTIVE);
        }
        self.operation = Operation::Search(Box::new(SessionSearch {
            handles: token.search_objects(template)?,
            in_use: true,
        }));
        Ok(())
    }

    pub fn get_operation(&self) -> &Operation {
        &self.operation
    }

    pub fn get_operation_mut(&mut self) -> &mut Operation {
        &mut self.operation
    }

    pub fn set_operation(&mut self, op: Operation) {
        self.operation = op;
    }
}
