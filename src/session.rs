// Copyright 2023 Simo Sorce
// See LICENSE.txt file for terms

//! This module defines the PKCS#11 session concept (`Session`), manages
//! session state (login status, active operations), and handles
//! session-specific operations like object searching.

use std::vec::Vec;

use crate::error::Result;
use crate::mechanism::*;
use crate::token::Token;

use pkcs11::*;

#[cfg(feature = "fips")]
use crate::fips;

/// Represents an active object search operation within a session.
#[derive(Debug)]
pub struct SessionSearch {
    /// The handles found by the search.
    handles: Vec<CK_OBJECT_HANDLE>,
    /// Flag indicating if the search has been initialized and results are
    /// available.
    in_use: bool,
}

impl SearchOperation for SessionSearch {
    /// Retrieves a subset of the search results.
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

    /// Indicates if the search operation is finalized (always false for
    /// search).
    fn finalized(&self) -> bool {
        false
    }
}

/// Represents the login status requirement for an active operation.
#[derive(Debug)]
pub enum OpLoginStatus {
    /// No operation active.
    NotInitialized,
    /// Active operation does not require login.
    NotRequired,
    /// Active operation requires login, but user is not logged in.
    Required,
    /// Active operation requires login, and user is logged in.
    LoginOk,
}

/// Trait defining helper methods for managing specific active operation types
/// within a `SessionOperations` struct.
pub trait ManageOperation {
    fn cancel_operation(so: &mut SessionOperations) -> Result<()>;
    fn check_op(so: &SessionOperations) -> Result<()>;
    fn check_no_op(so: &SessionOperations) -> Result<()>;
    fn get_op(so: &mut SessionOperations) -> Result<&mut Self>;
    fn set_op(so: &mut SessionOperations, op: Box<Self>);
}

/// Macro to implement the `ManageOperation` trait for a specific operation
/// type.
macro_rules! impl_mop {
    ($optype:ident, $($opname:ident).+) => {
        impl ManageOperation for dyn $optype {
            fn cancel_operation(so: &mut SessionOperations) -> Result<()> {
                so.$($opname).+ = None;
                Ok(())
            }

            fn check_op(so: &SessionOperations) -> Result<()> {
                if let Some(ref o) = so.$($opname).+ {
                    if ! o.finalized() {
                        return Ok(());
                    }
                }
                Err(CKR_OPERATION_NOT_INITIALIZED)?
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
    #[cfg(feature = "pkcs11_3_2")]
    verifysig: Option<Box<dyn VerifySignature>>,
}

impl_mop!(MsgEncryption, msg_encryption);
impl_mop!(MsgDecryption, msg_decryption);
impl_mop!(SearchOperation, search);
impl_mop!(Encryption, encryption);
impl_mop!(Decryption, decryption);
impl_mop!(Digest, digest);
impl_mop!(Sign, sign);
impl_mop!(Verify, verify);
#[cfg(feature = "pkcs11_3_2")]
impl_mop!(VerifySignature, verifysig);

impl SessionOperations {
    /// Creates a new, empty `SessionOperations` object.
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
            #[cfg(feature = "pkcs11_3_2")]
            verifysig: None,
        }
    }
}

/// Represents a PKCS#11 session.
#[derive(Debug)]
pub struct Session {
    /// Session information (state, flags, slot ID).
    info: CK_SESSION_INFO,
    //application: CK_VOID_PTR,
    //notify: CK_NOTIFY,
    /// Container for active cryptographic operations.
    operations: SessionOperations,
    /// Tracks login requirement status for the current operation.
    login_status: OpLoginStatus,
    /// Tracks FIPS approval status for the current operation.
    fips_indicator: Option<bool>,
}

impl Session {
    /// Creates a new session for a given slot ID and flags.
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

    /// Returns a reference to the session's information structure.
    pub fn get_session_info(&self) -> &CK_SESSION_INFO {
        &self.info
    }

    /// Sets the FIPS indicator flag for the current operation.
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

    /// Gets the current FIPS indicator flag status.
    #[cfg(feature = "fips")]
    pub fn get_fips_indicator(&self) -> Option<bool> {
        self.fips_indicator
    }

    /// Gets the last validation flags.
    ///
    /// Sets the FIPS flag if the last operation was FIPS approved.
    ///
    /// No other validation types are support at this time.
    #[cfg(feature = "pkcs11_3_2")]
    pub fn get_last_validation_flags(&self) -> CK_FLAGS {
        #[cfg(feature = "fips")]
        if self.fips_indicator == Some(true) {
            return fips::indicators::KRF_FIPS;
        }

        0
    }

    /// Resets the FIPS indicator (e.g., when starting a new operation).
    #[cfg(feature = "fips")]
    pub fn reset_fips_indicator(&mut self) {
        self.fips_indicator = None;
    }

    /// Gets the slot ID associated with this session.
    pub fn get_slot_id(&self) -> CK_SLOT_ID {
        self.info.slotID
    }

    /// Changes the session state based on the provided user type.
    ///
    /// A user type of CK_UNAVAILABLE_INFORMATION effects a "logout" to public
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

    /// Checks if the session is read-write.
    pub fn is_writable(&self) -> bool {
        match self.info.state {
            CKS_RW_PUBLIC_SESSION => true,
            CKS_RW_USER_FUNCTIONS => true,
            CKS_RW_SO_FUNCTIONS => true,
            _ => false,
        }
    }

    /// Initializes a new object search operation within the session.
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

    /// Cancels the active operation of the specified type `O`.
    pub fn cancel_operation<O: ManageOperation + ?Sized>(
        &mut self,
    ) -> Result<()> {
        O::cancel_operation(&mut self.operations)
    }

    /// Checks if an operation of type `O` is currently active.
    pub fn check_op<O: ManageOperation + ?Sized>(&self) -> Result<()> {
        O::check_op(&self.operations)
    }

    /// Checks that *no* operation of type `O` is currently active.
    pub fn check_no_op<O: ManageOperation + ?Sized>(&self) -> Result<()> {
        O::check_no_op(&self.operations)
    }

    /// Checks if the current login state permits the active operation.
    ///
    /// Returns `CKR_USER_NOT_LOGGED_IN` if login is required but not satisfied.
    pub fn check_login_status(&self) -> Result<()> {
        match self.login_status {
            OpLoginStatus::NotInitialized => {
                Err(CKR_OPERATION_NOT_INITIALIZED)?
            }
            OpLoginStatus::NotRequired => Ok(()),
            OpLoginStatus::Required => Err(CKR_USER_NOT_LOGGED_IN)?,
            OpLoginStatus::LoginOk => Ok(()),
        }
    }

    /// Gets a mutable reference to the currently active operation of type `O`.
    ///
    /// Checks login status before returning the operation.
    pub fn get_operation<O: ManageOperation + ?Sized>(
        &mut self,
    ) -> Result<&mut O> {
        self.check_login_status()?;
        O::get_op(&mut self.operations)
    }

    /// Sets the active operation of type `O`.
    ///
    /// Also resets the FIPS indicator and sets the login requirement status
    /// based on `needs_login`.
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

    /// Marks the current operation's login requirement as satisfied.
    pub fn set_login_ok(&mut self) {
        self.login_status = OpLoginStatus::LoginOk;
    }
}
