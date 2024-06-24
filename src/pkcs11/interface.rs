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

pub const KRY_VENDOR_OFFSET: CK_ULONG = CKA_VENDOR_DEFINED + 485259;

/* Object types */
pub const KRO_TOKEN_DATA: CK_OBJECT_CLASS = KRY_VENDOR_OFFSET + 1;

/* Attributes */
pub const KRA_MAX_LOGIN_ATTEMPTS: CK_ATTRIBUTE_TYPE = KRY_VENDOR_OFFSET + 1;
pub const KRA_LOGIN_ATTEMPTS: CK_ATTRIBUTE_TYPE = KRY_VENDOR_OFFSET + 2;
pub const KRA_FLAGS: CK_ATTRIBUTE_TYPE = KRY_VENDOR_OFFSET + 3;
pub const KRA_MANUFACTURER_ID: CK_ATTRIBUTE_TYPE = KRY_VENDOR_OFFSET + 4;
pub const KRA_MODEL: CK_ATTRIBUTE_TYPE = KRY_VENDOR_OFFSET + 5;
pub const KRA_SERIAL_NUMBER: CK_ATTRIBUTE_TYPE = KRY_VENDOR_OFFSET + 6;

/* Errors */
pub const KRR_TOKEN_NOT_INITIALIZED: CK_ULONG = KRY_VENDOR_OFFSET + 1;

pub const KRY_UNSPEC: CK_ULONG = CK_UNAVAILABLE_INFORMATION;
