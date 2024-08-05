// Copyright 2024 Simo Sorce
// See LICENSE.txt file for terms

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
