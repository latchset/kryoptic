// Copyright 2025 Simo Sorce
// See LICENSE.txt file for terms

//! PKCS#11 API Vendor extensions

use crate::pkcs11::*;

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
