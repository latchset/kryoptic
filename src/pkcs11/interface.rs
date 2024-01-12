// Copyright 2023 Simo Sorce
// See LICENSE.txt file for terms

include!("bindings.rs");

// types that need different mutability than bindgen provides
pub type CK_FUNCTION_LIST_PTR = *const CK_FUNCTION_LIST;
pub type CK_FUNCTION_LIST_3_0_PTR = *const CK_FUNCTION_LIST_3_0;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct CK_INTERFACE {
    pub pInterfaceName: *const CK_CHAR,
    pub pFunctionList: *const ::std::os::raw::c_void,
    pub flags: CK_FLAGS,
}

pub const KRYATTR_OFFSET: CK_ULONG = 485259;
pub const KRYATTR_MAX_LOGIN_ATTEMPTS: CK_ULONG =
    CKA_VENDOR_DEFINED + KRYATTR_OFFSET + 1;

pub const KRYERR_OFFSET: CK_ULONG = 485259;
pub const KRYERR_TOKEN_NOT_INITIALIZED: CK_ULONG =
    CKR_VENDOR_DEFINED + KRYERR_OFFSET + 1;

pub const KRY_UNSPEC: CK_ULONG = CK_UNAVAILABLE_INFORMATION;
