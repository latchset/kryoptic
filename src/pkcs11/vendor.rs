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

/* NSS Vendor attributes */
#[cfg(feature = "nssdb")]
pub mod nss {
    use crate::pkcs11::{
        CKA_VENDOR_DEFINED, CK_ATTRIBUTE_TYPE, CK_OBJECT_CLASS, CK_ULONG,
    };

    const NSS_VENDOR_OFFSET: CK_ULONG = CKA_VENDOR_DEFINED + 0x4E534350;
    const NSS_VENDOR_TRUST: CK_ULONG = NSS_VENDOR_OFFSET + 0x2000;

    /* Object Classes */
    pub const CKO_NSS_TRUST: CK_OBJECT_CLASS = NSS_VENDOR_OFFSET + 3;

    /* Attributes */
    pub const CKA_NSS_TRUST_DIGITAL_SIGNATURE: CK_ATTRIBUTE_TYPE =
        NSS_VENDOR_TRUST + 1;
    pub const CKA_NSS_TRUST_NON_REPUDIATION: CK_ATTRIBUTE_TYPE =
        NSS_VENDOR_TRUST + 2;
    pub const CKA_NSS_TRUST_KEY_ENCIPHERMENT: CK_ATTRIBUTE_TYPE =
        NSS_VENDOR_TRUST + 3;
    pub const CKA_NSS_TRUST_DATA_ENCIPHERMENT: CK_ATTRIBUTE_TYPE =
        NSS_VENDOR_TRUST + 4;
    pub const CKA_NSS_TRUST_KEY_AGREEMENT: CK_ATTRIBUTE_TYPE =
        NSS_VENDOR_TRUST + 5;
    pub const CKA_NSS_TRUST_KEY_CERT_SIGN: CK_ATTRIBUTE_TYPE =
        NSS_VENDOR_TRUST + 6;
    pub const CKA_NSS_TRUST_CRL_SIGN: CK_ATTRIBUTE_TYPE = NSS_VENDOR_TRUST + 7;
    pub const CKA_NSS_TRUST_SERVER_AUTH: CK_ATTRIBUTE_TYPE =
        NSS_VENDOR_TRUST + 8;
    pub const CKA_NSS_TRUST_CLIENT_AUTH: CK_ATTRIBUTE_TYPE =
        NSS_VENDOR_TRUST + 9;
    pub const CKA_NSS_TRUST_CODE_SIGNING: CK_ATTRIBUTE_TYPE =
        NSS_VENDOR_TRUST + 10;
    pub const CKA_NSS_TRUST_EMAIL_PROTECTION: CK_ATTRIBUTE_TYPE =
        NSS_VENDOR_TRUST + 11;
    pub const CKA_NSS_TRUST_IPSEC_END_SYSTEM: CK_ATTRIBUTE_TYPE =
        NSS_VENDOR_TRUST + 12;
    pub const CKA_NSS_TRUST_IPSEC_TUNNEL: CK_ATTRIBUTE_TYPE =
        NSS_VENDOR_TRUST + 13;
    pub const CKA_NSS_TRUST_IPSEC_USER: CK_ATTRIBUTE_TYPE =
        NSS_VENDOR_TRUST + 14;
    pub const CKA_NSS_TRUST_TIME_STAMPING: CK_ATTRIBUTE_TYPE =
        NSS_VENDOR_TRUST + 15;
    pub const CKA_NSS_TRUST_STEP_UP_APPROVED: CK_ATTRIBUTE_TYPE =
        NSS_VENDOR_TRUST + 16;
    pub const CKA_NSS_CERT_SHA1_HASH: CK_ATTRIBUTE_TYPE =
        NSS_VENDOR_TRUST + 100;
    pub const CKA_NSS_CERT_MD5_HASH: CK_ATTRIBUTE_TYPE = NSS_VENDOR_TRUST + 101;

    /* CKT Trsut Values */
    pub const CKT_NSS_TRUSTED: CK_ULONG = NSS_VENDOR_OFFSET + 1;
    pub const CKT_NSS_TRUSTED_DELEGATOR: CK_ULONG = NSS_VENDOR_OFFSET + 2;
    pub const CKT_NSS_MUST_VERIFY_TRUST: CK_ULONG = NSS_VENDOR_OFFSET + 3;
    pub const CKT_NSS_TRUST_UNKNOWN: CK_ULONG = NSS_VENDOR_OFFSET + 5;
    pub const CKT_NSS_NOT_TRUSTED: CK_ULONG = NSS_VENDOR_OFFSET + 10;
}
