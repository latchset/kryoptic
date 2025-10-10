// Copyright 2024 Simo Sorce
// See LICENSE.txt file for terms

//! This module defines PKCS#11 attribute type constants specific to or
//! commonly used within NSS databases, including standard, vendor-defined
//! (NSS), and trust object attributes. It also provides a unified table of
//! these attributes with their properties (authenticated, sensitive, vendor,
//! skippable, etc.) and helper functions to check attribute classifications.

use crate::pkcs11::*;

const DEPRECATED_CKA_SECONDARY_AUTH: CK_ULONG = 512;
const DEPRECATED_CKA_AUTH_PIN_FLAGS: CK_ULONG = 513;

/* we use the CKA_NSS prefix instead of the preferred NSS_CKA one
 * to allow for easy search in the NSS codebase */

/* off the regular NSS vendor offset for historical reasons */
const CKA_NSS_DB: CK_ATTRIBUTE_TYPE = 0xD5A0DB00;
const CKA_NSS_TRUST: CK_ATTRIBUTE_TYPE = 0x80000001;

/* NSS Vendor Offset attributes */
const NSS_VENDOR_OFFSET: CK_ULONG = CKA_VENDOR_DEFINED + 0x4E534350;
const CKA_NSS_URL: CK_ATTRIBUTE_TYPE = NSS_VENDOR_OFFSET + 1;
const CKA_NSS_EMAIL: CK_ATTRIBUTE_TYPE = NSS_VENDOR_OFFSET + 2;
const CKA_NSS_SMIME_INFO: CK_ATTRIBUTE_TYPE = NSS_VENDOR_OFFSET + 3;
const CKA_NSS_SMIME_TIMESTAMP: CK_ATTRIBUTE_TYPE = NSS_VENDOR_OFFSET + 4;
const CKA_NSS_PKCS8_SALT: CK_ATTRIBUTE_TYPE = NSS_VENDOR_OFFSET + 5;
const CKA_NSS_PASSWORD_CHECK: CK_ATTRIBUTE_TYPE = NSS_VENDOR_OFFSET + 6;
const CKA_NSS_EXPIRES: CK_ATTRIBUTE_TYPE = NSS_VENDOR_OFFSET + 7;
const CKA_NSS_KRL: CK_ATTRIBUTE_TYPE = NSS_VENDOR_OFFSET + 8;

const CKA_NSS_PQG_COUNTER: CK_ATTRIBUTE_TYPE = NSS_VENDOR_OFFSET + 20;
const CKA_NSS_PQG_SEED: CK_ATTRIBUTE_TYPE = NSS_VENDOR_OFFSET + 21;
const CKA_NSS_PQG_H: CK_ATTRIBUTE_TYPE = NSS_VENDOR_OFFSET + 22;
const CKA_NSS_PQG_SEED_BITS: CK_ATTRIBUTE_TYPE = NSS_VENDOR_OFFSET + 23;
const CKA_NSS_MODULE_SPEC: CK_ATTRIBUTE_TYPE = NSS_VENDOR_OFFSET + 24;
const CKA_NSS_OVERRIDE_EXTENSIONS: CK_ATTRIBUTE_TYPE = NSS_VENDOR_OFFSET + 25;

const CKA_NSS_SERVER_DISTRUST_AFTER: CK_ATTRIBUTE_TYPE = NSS_VENDOR_OFFSET + 35;
const CKA_NSS_EMAIL_DISTRUST_AFTER: CK_ATTRIBUTE_TYPE = NSS_VENDOR_OFFSET + 36;

const NSS_VENDOR_TRUST: CK_ULONG = NSS_VENDOR_OFFSET + 0x2000;

const CKA_NSS_TRUST_DIGITAL_SIGNATURE: CK_ATTRIBUTE_TYPE = NSS_VENDOR_TRUST + 1;
const CKA_NSS_TRUST_NON_REPUDIATION: CK_ATTRIBUTE_TYPE = NSS_VENDOR_TRUST + 2;
const CKA_NSS_TRUST_KEY_ENCIPHERMENT: CK_ATTRIBUTE_TYPE = NSS_VENDOR_TRUST + 3;
const CKA_NSS_TRUST_DATA_ENCIPHERMENT: CK_ATTRIBUTE_TYPE = NSS_VENDOR_TRUST + 4;
const CKA_NSS_TRUST_KEY_AGREEMENT: CK_ATTRIBUTE_TYPE = NSS_VENDOR_TRUST + 5;
const CKA_NSS_TRUST_KEY_CERT_SIGN: CK_ATTRIBUTE_TYPE = NSS_VENDOR_TRUST + 6;
const CKA_NSS_TRUST_CRL_SIGN: CK_ATTRIBUTE_TYPE = NSS_VENDOR_TRUST + 7;
const CKA_NSS_TRUST_SERVER_AUTH: CK_ATTRIBUTE_TYPE = NSS_VENDOR_TRUST + 8;
const CKA_NSS_TRUST_CLIENT_AUTH: CK_ATTRIBUTE_TYPE = NSS_VENDOR_TRUST + 9;
const CKA_NSS_TRUST_CODE_SIGNING: CK_ATTRIBUTE_TYPE = NSS_VENDOR_TRUST + 10;
const CKA_NSS_TRUST_EMAIL_PROTECTION: CK_ATTRIBUTE_TYPE = NSS_VENDOR_TRUST + 11;
const CKA_NSS_TRUST_IPSEC_END_SYSTEM: CK_ATTRIBUTE_TYPE = NSS_VENDOR_TRUST + 12;
const CKA_NSS_TRUST_IPSEC_TUNNEL: CK_ATTRIBUTE_TYPE = NSS_VENDOR_TRUST + 13;
const CKA_NSS_TRUST_IPSEC_USER: CK_ATTRIBUTE_TYPE = NSS_VENDOR_TRUST + 14;
const CKA_NSS_TRUST_TIME_STAMPING: CK_ATTRIBUTE_TYPE = NSS_VENDOR_TRUST + 15;
const CKA_NSS_TRUST_STEP_UP_APPROVED: CK_ATTRIBUTE_TYPE = NSS_VENDOR_TRUST + 16;

const CKA_NSS_CERT_SHA1_HASH: CK_ATTRIBUTE_TYPE = NSS_VENDOR_TRUST + 100;
const CKA_NSS_CERT_MD5_HASH: CK_ATTRIBUTE_TYPE = NSS_VENDOR_TRUST + 101;

/// Holds all properties of an NSS attribute
#[derive(Debug, Clone, Copy)]
pub struct NssAttributeInfo {
    /// The PKCS#11 attribute type value
    pub attr_type: CK_ATTRIBUTE_TYPE,
    /// Is an authenticated attribute
    pub authenticated: bool,
    /// Is a sensitive attribute
    pub sensitive: bool,
    /// Is an NSS vendor-specific attribute
    pub vendor: bool,
    /// Is an attribute to be skipped (not stored in DB)
    pub skippable: bool,
    /// Is a deprecated attribute
    pub deprecated: bool,
}

macro_rules! nssattrinfo_regular {
    ($attr:ident) => {
        NssAttributeInfo {
            attr_type: $attr,
            authenticated: false,
            sensitive: false,
            vendor: false,
            skippable: false,
            deprecated: false,
        }
    };
}

macro_rules! nssattrinfo_authenticated {
    ($attr:ident) => {
        NssAttributeInfo {
            attr_type: $attr,
            authenticated: true,
            sensitive: false,
            vendor: false,
            skippable: false,
            deprecated: false,
        }
    };
}

macro_rules! nssattrinfo_sensitive {
    ($attr:ident) => {
        NssAttributeInfo {
            attr_type: $attr,
            authenticated: false,
            sensitive: true,
            vendor: false,
            skippable: false,
            deprecated: false,
        }
    };
}

macro_rules! nssattrinfo_vendor {
    ($attr:ident) => {
        NssAttributeInfo {
            attr_type: $attr,
            authenticated: false,
            sensitive: false,
            vendor: true,
            skippable: false,
            deprecated: false,
        }
    };
}

macro_rules! nssattrinfo_skippable {
    ($attr:ident) => {
        NssAttributeInfo {
            attr_type: $attr,
            authenticated: false,
            sensitive: false,
            vendor: false,
            skippable: true,
            deprecated: false,
        }
    };
}

macro_rules! nssattrinfo_deprecated {
    ($attr:ident) => {
        NssAttributeInfo {
            attr_type: $attr,
            authenticated: false,
            sensitive: false,
            vendor: false,
            skippable: false,
            deprecated: true,
        }
    };
}

macro_rules! nssattrinfo_auth_vendor {
    ($attr:ident) => {
        NssAttributeInfo {
            attr_type: $attr,
            authenticated: true,
            sensitive: false,
            vendor: true,
            skippable: false,
            deprecated: false,
        }
    };
}

/// Combined table of all attributes and their properties
pub static ALL_ATTRIBUTES: &[NssAttributeInfo] = &[
    nssattrinfo_regular!(CKA_CLASS),
    nssattrinfo_regular!(CKA_TOKEN),
    nssattrinfo_regular!(CKA_PRIVATE),
    nssattrinfo_regular!(CKA_LABEL),
    nssattrinfo_regular!(CKA_UNIQUE_ID),
    nssattrinfo_regular!(CKA_APPLICATION),
    nssattrinfo_sensitive!(CKA_VALUE),
    nssattrinfo_regular!(CKA_OBJECT_ID),
    nssattrinfo_regular!(CKA_CERTIFICATE_TYPE),
    nssattrinfo_regular!(CKA_ISSUER),
    nssattrinfo_regular!(CKA_SERIAL_NUMBER),
    nssattrinfo_regular!(CKA_AC_ISSUER),
    nssattrinfo_regular!(CKA_OWNER),
    nssattrinfo_regular!(CKA_ATTR_TYPES),
    nssattrinfo_regular!(CKA_TRUSTED),
    nssattrinfo_regular!(CKA_CERTIFICATE_CATEGORY),
    nssattrinfo_regular!(CKA_JAVA_MIDP_SECURITY_DOMAIN),
    nssattrinfo_regular!(CKA_URL),
    nssattrinfo_regular!(CKA_HASH_OF_SUBJECT_PUBLIC_KEY),
    nssattrinfo_regular!(CKA_HASH_OF_ISSUER_PUBLIC_KEY),
    nssattrinfo_authenticated!(CKA_NAME_HASH_ALGORITHM),
    nssattrinfo_regular!(CKA_CHECK_VALUE),
    nssattrinfo_regular!(CKA_KEY_TYPE),
    nssattrinfo_regular!(CKA_SUBJECT),
    nssattrinfo_regular!(CKA_ID),
    nssattrinfo_regular!(CKA_SENSITIVE),
    nssattrinfo_regular!(CKA_ENCRYPT),
    nssattrinfo_regular!(CKA_DECRYPT),
    nssattrinfo_regular!(CKA_WRAP),
    nssattrinfo_regular!(CKA_UNWRAP),
    nssattrinfo_regular!(CKA_SIGN),
    nssattrinfo_regular!(CKA_SIGN_RECOVER),
    nssattrinfo_regular!(CKA_VERIFY),
    nssattrinfo_regular!(CKA_VERIFY_RECOVER),
    nssattrinfo_regular!(CKA_DERIVE),
    nssattrinfo_regular!(CKA_START_DATE),
    nssattrinfo_regular!(CKA_END_DATE),
    nssattrinfo_authenticated!(CKA_MODULUS),
    nssattrinfo_regular!(CKA_MODULUS_BITS),
    nssattrinfo_authenticated!(CKA_PUBLIC_EXPONENT),
    nssattrinfo_sensitive!(CKA_PRIVATE_EXPONENT),
    nssattrinfo_sensitive!(CKA_PRIME_1),
    nssattrinfo_sensitive!(CKA_PRIME_2),
    nssattrinfo_sensitive!(CKA_EXPONENT_1),
    nssattrinfo_sensitive!(CKA_EXPONENT_2),
    nssattrinfo_sensitive!(CKA_COEFFICIENT),
    nssattrinfo_regular!(CKA_PUBLIC_KEY_INFO),
    nssattrinfo_regular!(CKA_PRIME),
    nssattrinfo_regular!(CKA_SUBPRIME),
    nssattrinfo_regular!(CKA_BASE),
    nssattrinfo_regular!(CKA_PRIME_BITS),
    nssattrinfo_regular!(CKA_SUB_PRIME_BITS),
    nssattrinfo_regular!(CKA_VALUE_BITS),
    nssattrinfo_regular!(CKA_VALUE_LEN),
    nssattrinfo_regular!(CKA_EXTRACTABLE),
    nssattrinfo_regular!(CKA_LOCAL),
    nssattrinfo_regular!(CKA_NEVER_EXTRACTABLE),
    nssattrinfo_regular!(CKA_ALWAYS_SENSITIVE),
    nssattrinfo_regular!(CKA_KEY_GEN_MECHANISM),
    nssattrinfo_regular!(CKA_MODIFIABLE),
    nssattrinfo_regular!(CKA_COPYABLE),
    nssattrinfo_regular!(CKA_DESTROYABLE),
    nssattrinfo_regular!(CKA_EC_PARAMS),
    nssattrinfo_regular!(CKA_EC_POINT),
    nssattrinfo_deprecated!(DEPRECATED_CKA_SECONDARY_AUTH),
    nssattrinfo_deprecated!(DEPRECATED_CKA_AUTH_PIN_FLAGS),
    nssattrinfo_regular!(CKA_ALWAYS_AUTHENTICATE),
    nssattrinfo_regular!(CKA_WRAP_WITH_TRUSTED),
    nssattrinfo_regular!(CKA_WRAP_TEMPLATE),
    nssattrinfo_regular!(CKA_UNWRAP_TEMPLATE),
    nssattrinfo_regular!(CKA_DERIVE_TEMPLATE),
    nssattrinfo_regular!(CKA_OTP_FORMAT),
    nssattrinfo_regular!(CKA_OTP_LENGTH),
    nssattrinfo_regular!(CKA_OTP_TIME_INTERVAL),
    nssattrinfo_regular!(CKA_OTP_USER_FRIENDLY_MODE),
    nssattrinfo_regular!(CKA_OTP_CHALLENGE_REQUIREMENT),
    nssattrinfo_regular!(CKA_OTP_TIME_REQUIREMENT),
    nssattrinfo_regular!(CKA_OTP_COUNTER_REQUIREMENT),
    nssattrinfo_regular!(CKA_OTP_PIN_REQUIREMENT),
    nssattrinfo_regular!(CKA_OTP_COUNTER),
    nssattrinfo_regular!(CKA_OTP_TIME),
    nssattrinfo_regular!(CKA_OTP_USER_IDENTIFIER),
    nssattrinfo_regular!(CKA_OTP_SERVICE_IDENTIFIER),
    nssattrinfo_regular!(CKA_OTP_SERVICE_LOGO),
    nssattrinfo_regular!(CKA_OTP_SERVICE_LOGO_TYPE),
    nssattrinfo_regular!(CKA_GOSTR3410_PARAMS),
    nssattrinfo_regular!(CKA_GOSTR3411_PARAMS),
    nssattrinfo_regular!(CKA_GOST28147_PARAMS),
    nssattrinfo_regular!(CKA_HW_FEATURE_TYPE),
    nssattrinfo_regular!(CKA_RESET_ON_INIT),
    nssattrinfo_regular!(CKA_HAS_RESET),
    nssattrinfo_regular!(CKA_PIXEL_X),
    nssattrinfo_regular!(CKA_PIXEL_Y),
    nssattrinfo_regular!(CKA_RESOLUTION),
    nssattrinfo_regular!(CKA_CHAR_ROWS),
    nssattrinfo_regular!(CKA_CHAR_COLUMNS),
    nssattrinfo_regular!(CKA_COLOR),
    nssattrinfo_regular!(CKA_BITS_PER_PIXEL),
    nssattrinfo_regular!(CKA_CHAR_SETS),
    nssattrinfo_regular!(CKA_ENCODING_METHODS),
    nssattrinfo_regular!(CKA_MIME_TYPES),
    nssattrinfo_regular!(CKA_MECHANISM_TYPE),
    nssattrinfo_regular!(CKA_REQUIRED_CMS_ATTRIBUTES),
    nssattrinfo_regular!(CKA_DEFAULT_CMS_ATTRIBUTES),
    nssattrinfo_regular!(CKA_SUPPORTED_CMS_ATTRIBUTES),
    nssattrinfo_regular!(CKA_PROFILE_ID),
    nssattrinfo_regular!(CKA_X2RATCHET_BAG),
    nssattrinfo_regular!(CKA_X2RATCHET_BAGSIZE),
    nssattrinfo_regular!(CKA_X2RATCHET_BOBS1STMSG),
    nssattrinfo_regular!(CKA_X2RATCHET_CKR),
    nssattrinfo_regular!(CKA_X2RATCHET_CKS),
    nssattrinfo_regular!(CKA_X2RATCHET_DHP),
    nssattrinfo_regular!(CKA_X2RATCHET_DHR),
    nssattrinfo_regular!(CKA_X2RATCHET_DHS),
    nssattrinfo_regular!(CKA_X2RATCHET_HKR),
    nssattrinfo_regular!(CKA_X2RATCHET_HKS),
    nssattrinfo_regular!(CKA_X2RATCHET_ISALICE),
    nssattrinfo_regular!(CKA_X2RATCHET_NHKR),
    nssattrinfo_regular!(CKA_X2RATCHET_NHKS),
    nssattrinfo_regular!(CKA_X2RATCHET_NR),
    nssattrinfo_regular!(CKA_X2RATCHET_NS),
    nssattrinfo_regular!(CKA_X2RATCHET_PNS),
    nssattrinfo_regular!(CKA_X2RATCHET_RK),
    nssattrinfo_regular!(CKA_HSS_LEVELS),
    nssattrinfo_regular!(CKA_HSS_LMS_TYPE),
    nssattrinfo_regular!(CKA_HSS_LMOTS_TYPE),
    nssattrinfo_regular!(CKA_HSS_LMS_TYPES),
    nssattrinfo_regular!(CKA_HSS_LMOTS_TYPES),
    nssattrinfo_regular!(CKA_HSS_KEYS_REMAINING),
    nssattrinfo_regular!(CKA_OBJECT_VALIDATION_FLAGS),
    nssattrinfo_regular!(CKA_VALIDATION_TYPE),
    nssattrinfo_regular!(CKA_VALIDATION_VERSION),
    nssattrinfo_regular!(CKA_VALIDATION_LEVEL),
    nssattrinfo_regular!(CKA_VALIDATION_MODULE_ID),
    nssattrinfo_regular!(CKA_VALIDATION_FLAG),
    nssattrinfo_regular!(CKA_VALIDATION_AUTHORITY_TYPE),
    nssattrinfo_regular!(CKA_VALIDATION_COUNTRY),
    nssattrinfo_regular!(CKA_VALIDATION_CERTIFICATE_IDENTIFIER),
    nssattrinfo_regular!(CKA_VALIDATION_CERTIFICATE_URI),
    nssattrinfo_regular!(CKA_VALIDATION_PROFILE),
    nssattrinfo_regular!(CKA_VALIDATION_VENDOR_URI),
    nssattrinfo_regular!(CKA_ENCAPSULATE_TEMPLATE),
    nssattrinfo_regular!(CKA_DECAPSULATE_TEMPLATE),
    nssattrinfo_authenticated!(CKA_TRUST_SERVER_AUTH),
    nssattrinfo_authenticated!(CKA_TRUST_CLIENT_AUTH),
    nssattrinfo_authenticated!(CKA_TRUST_CODE_SIGNING),
    nssattrinfo_authenticated!(CKA_TRUST_EMAIL_PROTECTION),
    nssattrinfo_authenticated!(CKA_TRUST_IPSEC_IKE),
    nssattrinfo_authenticated!(CKA_TRUST_TIME_STAMPING),
    nssattrinfo_authenticated!(CKA_TRUST_OCSP_SIGNING),
    nssattrinfo_regular!(CKA_ENCAPSULATE),
    nssattrinfo_regular!(CKA_DECAPSULATE),
    nssattrinfo_authenticated!(CKA_HASH_OF_CERTIFICATE),
    nssattrinfo_regular!(CKA_PUBLIC_CRC64_VALUE),
    nssattrinfo_sensitive!(CKA_SEED),
    nssattrinfo_vendor!(CKA_NSS_TRUST),
    nssattrinfo_vendor!(CKA_NSS_URL),
    nssattrinfo_vendor!(CKA_NSS_EMAIL),
    nssattrinfo_vendor!(CKA_NSS_SMIME_INFO),
    nssattrinfo_vendor!(CKA_NSS_SMIME_TIMESTAMP),
    nssattrinfo_vendor!(CKA_NSS_PKCS8_SALT),
    nssattrinfo_vendor!(CKA_NSS_PASSWORD_CHECK),
    nssattrinfo_vendor!(CKA_NSS_EXPIRES),
    nssattrinfo_vendor!(CKA_NSS_KRL),
    nssattrinfo_vendor!(CKA_NSS_PQG_COUNTER),
    nssattrinfo_vendor!(CKA_NSS_PQG_SEED),
    nssattrinfo_vendor!(CKA_NSS_PQG_H),
    nssattrinfo_vendor!(CKA_NSS_PQG_SEED_BITS),
    nssattrinfo_vendor!(CKA_NSS_MODULE_SPEC),
    nssattrinfo_auth_vendor!(CKA_NSS_OVERRIDE_EXTENSIONS),
    nssattrinfo_vendor!(CKA_NSS_SERVER_DISTRUST_AFTER),
    nssattrinfo_vendor!(CKA_NSS_EMAIL_DISTRUST_AFTER),
    nssattrinfo_vendor!(CKA_NSS_TRUST_DIGITAL_SIGNATURE),
    nssattrinfo_vendor!(CKA_NSS_TRUST_NON_REPUDIATION),
    nssattrinfo_vendor!(CKA_NSS_TRUST_KEY_ENCIPHERMENT),
    nssattrinfo_vendor!(CKA_NSS_TRUST_DATA_ENCIPHERMENT),
    nssattrinfo_vendor!(CKA_NSS_TRUST_KEY_AGREEMENT),
    nssattrinfo_vendor!(CKA_NSS_TRUST_KEY_CERT_SIGN),
    nssattrinfo_vendor!(CKA_NSS_TRUST_CRL_SIGN),
    nssattrinfo_auth_vendor!(CKA_NSS_TRUST_SERVER_AUTH),
    nssattrinfo_auth_vendor!(CKA_NSS_TRUST_CLIENT_AUTH),
    nssattrinfo_auth_vendor!(CKA_NSS_TRUST_CODE_SIGNING),
    nssattrinfo_auth_vendor!(CKA_NSS_TRUST_EMAIL_PROTECTION),
    nssattrinfo_vendor!(CKA_NSS_TRUST_IPSEC_END_SYSTEM),
    nssattrinfo_vendor!(CKA_NSS_TRUST_IPSEC_TUNNEL),
    nssattrinfo_vendor!(CKA_NSS_TRUST_IPSEC_USER),
    nssattrinfo_vendor!(CKA_NSS_TRUST_TIME_STAMPING),
    nssattrinfo_auth_vendor!(CKA_NSS_TRUST_STEP_UP_APPROVED),
    nssattrinfo_auth_vendor!(CKA_NSS_CERT_SHA1_HASH),
    nssattrinfo_auth_vendor!(CKA_NSS_CERT_MD5_HASH),
    nssattrinfo_vendor!(CKA_NSS_DB),
    // Skippable attributes
    nssattrinfo_skippable!(CKA_ALLOWED_MECHANISMS),
];

fn get_attr_info(attr: CK_ATTRIBUTE_TYPE) -> Option<&'static NssAttributeInfo> {
    ALL_ATTRIBUTES.iter().find(|&a| a.attr_type == attr)
}

/// Checks if an attribute type is an NSS vendor-defined attribute or
/// deprecated and should generally be ignored.
pub fn ignore_attribute(attr: CK_ATTRIBUTE_TYPE) -> bool {
    get_attr_info(attr)
        .map(|info| info.vendor || info.deprecated)
        .unwrap_or(false)
}

/// Checks if an attribute type is considered sensitive by NSS (and should be
/// encrypted).
pub fn is_sensitive_attribute(attr: CK_ATTRIBUTE_TYPE) -> bool {
    get_attr_info(attr)
        .map(|info| info.sensitive)
        .unwrap_or(false)
}

/// Checks if an attribute type is known and potentially stored in the NSS DB.
pub fn is_db_attribute(attr: CK_ATTRIBUTE_TYPE) -> bool {
    !get_attr_info(attr).is_none()
}

/// Checks if an attribute type is one that should be skipped (not directly
/// stored or retrieved as a column) when interacting with the NSS DB.
pub fn is_skippable_attribute(attr: CK_ATTRIBUTE_TYPE) -> bool {
    get_attr_info(attr)
        .map(|info| info.skippable)
        .unwrap_or(false)
}
