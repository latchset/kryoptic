// Copyright 2023 Simo Sorce
// See LICENSE.txt file for terms

use std::vec::Vec;

use crate::error::Result;
use crate::interface::*;
use crate::mechanism::*;
use crate::token::Token;

#[cfg(feature = "fips")]
use crate::fips;

#[derive(Debug)]
pub struct SessionSearch {
    handles: Vec<CK_OBJECT_HANDLE>,
    in_use: bool,
}

impl SearchOperation for SessionSearch {
    fn results(&mut self, max: usize) -> Result<Vec<CK_OBJECT_HANDLE>> {
        if !self.in_use {
            return Err(CKR_OPERATION_NOT_INITIALIZED)?;
        }
        let mut amount = self.handles.len();
        if max < amount {
            amount = max;
        }
        Ok(self.handles.drain(0..amount).collect())
    }

    fn finalized(&self) -> bool {
        false
    }
}

#[derive(Debug)]
pub enum OpLoginStatus {
    NotInitialized,
    NotRequired,
    Required,
    LoginOk,
}

pub trait ManageOperation {
    fn cancel_operation(so: &mut SessionOperations) -> Result<()>;
    fn check_no_op(so: &SessionOperations) -> Result<()>;
    fn get_op(so: &mut SessionOperations) -> Result<&mut Self>;
    fn set_op(so: &mut SessionOperations, op: Box<Self>);
}

macro_rules! impl_mop {
    ($optype:ident, $($opname:ident).+) => {
        impl ManageOperation for dyn $optype {
            fn cancel_operation(so: &mut SessionOperations) -> Result<()> {
                so.$($opname).+ = None;
                Ok(())
            }

            fn check_no_op(so: &SessionOperations) -> Result<()> {
                if let Some(ref o) = so.$($opname).+ {
                    if ! o.finalized() {
                        return Err(CKR_OPERATION_ACTIVE)?;
                    }
                }
                Ok(())
            }

            fn get_op(so: &mut SessionOperations) -> Result<&mut Self> {
                match so.$($opname).+ {
                    Some(ref mut o) => if o.finalized() {
                        Err(CKR_OPERATION_NOT_INITIALIZED)?
                    } else {
                        Ok(&mut **o)
                    },
                    None => Err(CKR_OPERATION_NOT_INITIALIZED)?,
                }
            }

            fn set_op(so: &mut SessionOperations, op: Box<Self>) {
                so.$($opname).+ = Some(op);
            }
        }
    };
}

/// Operations that span more than one function call and that
/// can be in flight at the same time in the same session
#[derive(Debug)]
pub struct SessionOperations {
    msg_encryption: Option<Box<dyn MsgEncryption>>,
    msg_decryption: Option<Box<dyn MsgDecryption>>,
    search: Option<Box<dyn SearchOperation>>,
    encryption: Option<Box<dyn Encryption>>,
    decryption: Option<Box<dyn Decryption>>,
    digest: Option<Box<dyn Digest>>,
    sign: Option<Box<dyn Sign>>,
    verify: Option<Box<dyn Verify>>,
}

impl_mop!(MsgEncryption, msg_encryption);
impl_mop!(MsgDecryption, msg_decryption);
impl_mop!(SearchOperation, search);
impl_mop!(Encryption, encryption);
impl_mop!(Decryption, decryption);
impl_mop!(Digest, digest);
impl_mop!(Sign, sign);
impl_mop!(Verify, verify);

impl SessionOperations {
    pub fn new() -> SessionOperations {
        SessionOperations {
            msg_encryption: None,
            msg_decryption: None,
            search: None,
            encryption: None,
            decryption: None,
            digest: None,
            sign: None,
            verify: None,
        }
    }
}

#[derive(Debug)]
pub struct Session {
    info: CK_SESSION_INFO,
    //application: CK_VOID_PTR,
    //notify: CK_NOTIFY,
    operations: SessionOperations,
    login_status: OpLoginStatus,
    fips_indicator: Option<bool>,
}

impl Session {
    pub fn new(
        slotid: CK_SLOT_ID,
        user_type: CK_USER_TYPE,
        flags: CK_FLAGS,
    ) -> Result<Session> {
        if flags & CKF_SERIAL_SESSION != CKF_SERIAL_SESSION {
            return Err(CKR_ARGUMENTS_BAD)?;
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
                            return Err(CKR_OPERATION_NOT_INITIALIZED)?;
                        }
                    }
                    _ => return Err(CKR_GENERAL_ERROR)?,
                },
                flags: flags,
                ulDeviceError: 0,
            },
            //application: std::ptr::null_mut(),
            //notify: unsafe { std::ptr::null_mut() },
            operations: SessionOperations::new(),
            login_status: OpLoginStatus::NotInitialized,
            fips_indicator: None,
        })
    }

    pub fn get_session_info(&self) -> &CK_SESSION_INFO {
        &self.info
    }

    #[cfg(feature = "fips")]
    pub fn set_fips_indicator(&mut self, flag: bool) {
        /* only allow to downgrade to false, never upgrade to true */
        match self.fips_indicator {
            Some(b) => {
                if !b {
                    return;
                }
            }
            None => (),
        }
        self.fips_indicator = Some(flag)
    }

    #[cfg(feature = "fips")]
    pub fn get_fips_indicator(&self) -> Option<bool> {
        self.fips_indicator
    }

    #[cfg(feature = "fips")]
    pub fn get_last_validation_flags(&self) -> CK_FLAGS {
        if self.fips_indicator == Some(true) {
            return fips::indicators::KRF_FIPS;
        }

        0
    }

    #[cfg(feature = "fips")]
    pub fn reset_fips_indicator(&mut self) {
        self.fips_indicator = None;
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
    ) -> Result<()> {
        self.check_no_op::<dyn SearchOperation>()?;
        self.set_operation::<dyn SearchOperation>(
            Box::new(SessionSearch {
                handles: token.search_objects(template)?,
                in_use: true,
            }),
            false,
        );
        Ok(())
    }

    pub fn cancel_operation<O: ManageOperation + ?Sized>(
        &mut self,
    ) -> Result<()> {
        O::cancel_operation(&mut self.operations)
    }

    pub fn check_no_op<O: ManageOperation + ?Sized>(&self) -> Result<()> {
        O::check_no_op(&self.operations)
    }

    pub fn check_login_status(&self) -> Result<()> {
        match self.login_status {
            OpLoginStatus::NotInitialized => Err(CKR_GENERAL_ERROR)?,
            OpLoginStatus::NotRequired => Ok(()),
            OpLoginStatus::Required => Err(CKR_USER_NOT_LOGGED_IN)?,
            OpLoginStatus::LoginOk => Ok(()),
        }
    }

    pub fn get_operation<O: ManageOperation + ?Sized>(
        &mut self,
    ) -> Result<&mut O> {
        self.check_login_status()?;
        O::get_op(&mut self.operations)
    }

    pub fn set_operation<O: ManageOperation + ?Sized>(
        &mut self,
        op: Box<O>,
        needs_login: bool,
    ) {
        self.fips_indicator = None; /* FIXME: per operation ? */
        self.login_status = if needs_login {
            OpLoginStatus::Required
        } else {
            OpLoginStatus::NotRequired
        };

        O::set_op(&mut self.operations, op);
    }

    pub fn set_login_ok(&mut self) {
        self.login_status = OpLoginStatus::LoginOk;
    }
}
