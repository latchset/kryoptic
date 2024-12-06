// Copyright 2023 Simo Sorce
// See LICENSE.txt file for terms

include!("bindings.rs");

// types that need different mutability than bindgen provides
pub type CK_FUNCTION_LIST_PTR = *const CK_FUNCTION_LIST;
pub type CK_FUNCTION_LIST_3_0_PTR = *const CK_FUNCTION_LIST_3_0;
// this is wrongly converted on 32b architecture to too large value
// which can not be represented in CK_ULONG.
pub const CK_UNAVAILABLE_INFORMATION: CK_ULONG = CK_ULONG::MAX;
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
/* + 10 taken by pkcs11/validation_draft.rs */

/* Attributes */
pub const KRA_MAX_LOGIN_ATTEMPTS: CK_ATTRIBUTE_TYPE = KRY_VENDOR_OFFSET + 1;
pub const KRA_LOGIN_ATTEMPTS: CK_ATTRIBUTE_TYPE = KRY_VENDOR_OFFSET + 2;
/* + 10 taken by pkcs11/validation_draft.rs */

/* Errors */
pub const KRR_TOKEN_NOT_INITIALIZED: CK_ULONG = KRY_VENDOR_OFFSET + 1;
pub const KRR_SLOT_CONFIG: CK_ULONG = KRY_VENDOR_OFFSET + 2;
pub const KRR_CONFIG_ERROR: CK_ULONG = KRY_VENDOR_OFFSET + 3;

pub const KRY_UNSPEC: CK_ULONG = CK_UNAVAILABLE_INFORMATION;

/* ======================================================================= *
 * ======================== CUSTOM EXTENSIONS ============================ *
 * ======================================================================= */

/* SSH Key Derivation Function */

/* Mechanisms */
pub const KRM_SSHKDF_DERIVE: CK_ULONG = KRY_VENDOR_OFFSET + 1;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct KR_SSHKDF_PARAMS {
    pub prfHashMechanism: CK_MECHANISM_TYPE,
    pub derivedKeyType: CK_BYTE,
    pub pExchangeHash: *mut CK_BYTE,
    pub ulExchangeHashLen: CK_ULONG,
    pub pSessionId: *mut CK_BYTE,
    pub ulSessionIdLen: CK_ULONG,
}

/* ======================================================================= *
 * ====================== v3.2 VALIDATION DRAFT ========================== *
 * ======================================================================= */

/* Draft Attributes for FIPS Indicators
 * PKCS#11 3.2 will provide official numbers for the following new
 * types, once that happens we'll remove them from here and rebuild
 * with the official ones */
pub type CK_VALIDATION_TYPE = CK_ULONG;
pub type CK_VALIDATION_TYPE_PTR = *mut CK_VALIDATION_TYPE;

pub const CKV_TYPE_UNSPECIFIED: CK_VALIDATION_TYPE = KRY_VENDOR_OFFSET + 0;
pub const CKV_TYPE_SOFTWARE: CK_VALIDATION_TYPE = KRY_VENDOR_OFFSET + 1;
pub const CKV_TYPE_HARDWARE: CK_VALIDATION_TYPE = KRY_VENDOR_OFFSET + 2;
pub const CKV_TYPE_FIRMWARE: CK_VALIDATION_TYPE = KRY_VENDOR_OFFSET + 3;
pub const CKV_TYPE_HYBRID: CK_VALIDATION_TYPE = KRY_VENDOR_OFFSET + 4;

pub type CK_VALIDATION_AUTHORITY_TYPE = CK_ULONG;
pub type CK_VALIDATION_AUTHORITY_TYPE_PTR = *mut CK_VALIDATION_AUTHORITY_TYPE;

pub const CKV_AUTHORITY_TYPE_UNSPECIFIED: CK_VALIDATION_AUTHORITY_TYPE =
    KRY_VENDOR_OFFSET + 0;
pub const CKV_AUTHORITY_TYPE_NIST_CMVP: CK_VALIDATION_AUTHORITY_TYPE =
    KRY_VENDOR_OFFSET + 1;
pub const CKV_AUTHORITY_TYPE_COMMON_CRITERIA: CK_VALIDATION_AUTHORITY_TYPE =
    KRY_VENDOR_OFFSET + 2;

pub type CK_SESSION_VALIDATION_FLAGS_TYPE = CK_ULONG;
pub const CKS_LAST_VALIDATION_OK: CK_SESSION_VALIDATION_FLAGS_TYPE =
    KRY_VENDOR_OFFSET + 0;

pub const CKO_VALIDATION: CK_OBJECT_CLASS = KRY_VENDOR_OFFSET + 10;

pub const CKA_VALIDATION_TYPE: CK_ATTRIBUTE_TYPE = KRY_VENDOR_OFFSET + 10;
pub const CKA_VALIDATION_VERSION: CK_ATTRIBUTE_TYPE = KRY_VENDOR_OFFSET + 11;
pub const CKA_VALIDATION_LEVEL: CK_ATTRIBUTE_TYPE = KRY_VENDOR_OFFSET + 12;
pub const CKA_VALIDATION_MODULE_ID: CK_ATTRIBUTE_TYPE = KRY_VENDOR_OFFSET + 13;
pub const CKA_VALIDATION_FLAG: CK_ATTRIBUTE_TYPE = KRY_VENDOR_OFFSET + 14;
pub const CKA_VALIDATION_AUTHORITY_TYPE: CK_ATTRIBUTE_TYPE =
    KRY_VENDOR_OFFSET + 15;
pub const CKA_VALIDATION_COUNTRY: CK_ATTRIBUTE_TYPE = KRY_VENDOR_OFFSET + 16;
pub const CKA_VALIDATION_CERTIFICATE_IDENTIFIER: CK_ATTRIBUTE_TYPE =
    KRY_VENDOR_OFFSET + 17;
pub const CKA_VALIDATION_CERTIFICATE_URI: CK_ATTRIBUTE_TYPE =
    KRY_VENDOR_OFFSET + 18;
pub const CKA_VALIDATION_VENDOR_URI: CK_ATTRIBUTE_TYPE = KRY_VENDOR_OFFSET + 19;
pub const CKA_VALIDATION_PROFILE: CK_ATTRIBUTE_TYPE = KRY_VENDOR_OFFSET + 20;
pub const CKA_VALIDATION_FLAGS: CK_ATTRIBUTE_TYPE = KRY_VENDOR_OFFSET + 21;

pub const CKR_OPERATION_NOT_VALIDATED: CK_RV = KRY_VENDOR_OFFSET + 10;
