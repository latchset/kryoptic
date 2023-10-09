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
use token::TokenObjects;

use std::slice::IterMut;

#[derive(Debug)]
pub struct SessionSearch {
    handles: Vec<CK_OBJECT_HANDLE>,
    in_use: bool,
    logged_in: bool,
}

impl SearchOperation for SessionSearch {
    fn search(
        &mut self,
        objects: &mut TokenObjects,
        template: &[CK_ATTRIBUTE],
    ) -> KResult<()> {
        if self.in_use {
            return err_rv!(CKR_OPERATION_ACTIVE);
        }
        self.in_use = true;
        let mut needs_handle = Vec::<String>::new();
        for (_, o) in objects.iter() {
            if !self.logged_in && o.is_private() {
                continue;
            }

            if o.match_template(template) {
                let oh = o.get_handle();
                if oh == CK_UNAVAILABLE_INFORMATION {
                    let uid = match o.get_attr_as_string(CKA_UNIQUE_ID) {
                        Ok(s) => s,
                        Err(_) => return err_rv!(CKR_GENERAL_ERROR),
                    };
                    needs_handle.push(uid.clone());
                } else {
                    self.handles.push(oh);
                }
            }
        }
        while let Some(uid) = needs_handle.pop() {
            let oh = objects.next_handle();
            let obj = match objects.get_mut(&uid) {
                Some(o) => o,
                None => continue,
            };
            obj.set_handle(oh);
            objects.insert_handle(oh, uid);
            self.handles.push(oh);
        }
        Ok(())
    }

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
}

#[derive(Debug)]
pub struct Session {
    handle: CK_SESSION_HANDLE,

    info: CK_SESSION_INFO,
    //application: CK_VOID_PTR,
    //notify: CK_NOTIFY,
    object_handles: Vec<CK_OBJECT_HANDLE>,

    operation: Operation,
}

impl Session {
    pub fn new(
        slotid: CK_SLOT_ID,
        handle: CK_SESSION_HANDLE,
        flags: CK_FLAGS,
    ) -> KResult<Session> {
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
            object_handles: Vec::<CK_OBJECT_HANDLE>::new(),
            operation: Operation::Empty,
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
        self.object_handles.push(handle);
    }

    pub fn set_object_handles(&mut self, handles: Vec<CK_OBJECT_HANDLE>) {
        self.object_handles = handles;
    }

    pub fn get_object_handles(&self) -> &Vec<CK_OBJECT_HANDLE> {
        &self.object_handles
    }

    pub fn get_session_info(&self) -> &CK_SESSION_INFO {
        &self.info
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

    pub fn new_search_operation(&mut self, logged_in: bool) -> KResult<()> {
        match self.operation {
            Operation::Empty => {
                self.operation = Operation::Search(Box::new(SessionSearch {
                    handles: Vec::new(),
                    in_use: false,
                    logged_in: logged_in,
                }));
                Ok(())
            }
            _ => err_rv!(CKR_OPERATION_ACTIVE),
        }
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

#[derive(Debug)]
pub struct Sessions {
    store: Vec<Session>,
}

impl Sessions {
    pub fn new() -> Sessions {
        Sessions { store: Vec::new() }
    }

    pub fn new_session(
        &mut self,
        slotid: CK_SLOT_ID,
        handle: CK_SESSION_HANDLE,
        flags: CK_FLAGS,
    ) -> KResult<&Session> {
        let session = Session::new(slotid, handle, flags)?;
        self.store.push(session);

        Ok(self.store.last().unwrap())
    }

    pub fn get_session(&self, handle: CK_SESSION_HANDLE) -> KResult<&Session> {
        for s in self.store.iter() {
            let h = s.get_handle();
            if h == handle {
                return Ok(s);
            }
        }
        err_rv!(CKR_SESSION_HANDLE_INVALID)
    }

    pub fn get_session_mut(
        &mut self,
        handle: CK_SESSION_HANDLE,
    ) -> KResult<&mut Session> {
        for s in self.store.iter_mut() {
            let h = s.get_handle();
            if h == handle {
                return Ok(s);
            }
        }
        err_rv!(CKR_SESSION_HANDLE_INVALID)
    }

    pub fn get_sessions_iter_mut(&mut self) -> IterMut<'_, Session> {
        self.store.iter_mut()
    }

    pub fn drop_session(&mut self, handle: CK_SESSION_HANDLE) -> KResult<()> {
        let mut idx = 0;
        while idx < self.store.len() {
            if handle == self.store[idx].get_handle() {
                self.store.swap_remove(idx);
                return Ok(());
            }
            idx += 1;
        }
        err_rv!(CKR_SESSION_HANDLE_INVALID)
    }

    pub fn drop_all_sessions(&mut self) {
        self.store.clear();
    }

    pub fn has_sessions(&self) -> bool {
        self.store.len() != 0
    }

    pub fn has_ro_sessions(&self) -> bool {
        for s in self.store.iter() {
            match s.get_session_info().state {
                CKS_RO_PUBLIC_SESSION => return true,
                CKS_RO_USER_FUNCTIONS => return true,
                _ => continue,
            }
        }
        false
    }

    pub fn change_session_states(&mut self, user_type: CK_USER_TYPE) -> CK_RV {
        for s in self.store.iter_mut() {
            let ret = s.change_session_state(user_type);
            if ret != CKR_OK {
                return ret;
            }
        }
        CKR_OK
    }

    pub fn invalidate_session_states(&mut self) {
        for s in self.store.iter_mut() {
            let _ = s.change_session_state(CK_UNAVAILABLE_INFORMATION);
        }
    }
}
