mod interface {
    #![allow(non_upper_case_globals)]
    #![allow(non_camel_case_types)]
    #![allow(non_snake_case)]
    #![allow(dead_code)]
    include!("pkcs11_bindings.rs");
}

use interface::{CK_RV, CKR_OK};

pub static mut FNLIST_240: interface::CK_FUNCTION_LIST = interface::CK_FUNCTION_LIST {
    version: interface::CK_VERSION {
        major: 2,
        minor: 40},
    C_Initialize: Some(fn_initialize),
    C_Finalize: Some(interface::C_Finalize),
    C_GetInfo: Some(interface::C_GetInfo),
    C_GetFunctionList: Some(C_GetFunctionList),
    C_GetSlotList: Some(interface::C_GetSlotList),
    C_GetSlotInfo: Some(interface::C_GetSlotInfo),
    C_GetTokenInfo: Some(interface::C_GetTokenInfo),
    C_GetMechanismList: Some(interface::C_GetMechanismList),
    C_GetMechanismInfo: Some(interface::C_GetMechanismInfo),
    C_InitToken: Some(interface::C_InitToken),
    C_InitPIN: Some(interface::C_InitPIN),
    C_SetPIN: Some(interface::C_SetPIN),
    C_OpenSession: Some(interface::C_OpenSession),
    C_CloseSession: Some(interface::C_CloseSession),
    C_CloseAllSessions: Some(interface::C_CloseAllSessions),
    C_GetSessionInfo: Some(interface::C_GetSessionInfo),
    C_GetOperationState: Some(interface::C_GetOperationState),
    C_SetOperationState: Some(interface::C_SetOperationState),
    C_Login: Some(interface::C_Login),
    C_Logout: Some(interface::C_Logout),
    C_CreateObject: Some(interface::C_CreateObject),
    C_CopyObject: Some(interface::C_CopyObject),
    C_DestroyObject: Some(interface::C_DestroyObject),
    C_GetObjectSize: Some(interface::C_GetObjectSize),
    C_GetAttributeValue: Some(interface::C_GetAttributeValue),
    C_SetAttributeValue: Some(interface::C_SetAttributeValue),
    C_FindObjectsInit: Some(interface::C_FindObjectsInit),
    C_FindObjects: Some(interface::C_FindObjects),
    C_FindObjectsFinal: Some(interface::C_FindObjectsFinal),
    C_EncryptInit: Some(interface::C_EncryptInit),
    C_Encrypt: Some(interface::C_Encrypt),
    C_EncryptUpdate: Some(interface::C_EncryptUpdate),
    C_EncryptFinal: Some(interface::C_EncryptFinal),
    C_DecryptInit: Some(interface::C_DecryptInit),
    C_Decrypt: Some(interface::C_Decrypt),
    C_DecryptUpdate: Some(interface::C_DecryptUpdate),
    C_DecryptFinal: Some(interface::C_DecryptFinal),
    C_DigestInit: Some(interface::C_DigestInit),
    C_Digest: Some(interface::C_Digest),
    C_DigestUpdate: Some(interface::C_DigestUpdate),
    C_DigestKey: Some(interface::C_DigestKey),
    C_DigestFinal: Some(interface::C_DigestFinal),
    C_SignInit: Some(interface::C_SignInit),
    C_Sign: Some(interface::C_Sign),
    C_SignUpdate: Some(interface::C_SignUpdate),
    C_SignFinal: Some(interface::C_SignFinal),
    C_SignRecoverInit: Some(interface::C_SignRecoverInit),
    C_SignRecover: Some(interface::C_SignRecover),
    C_VerifyInit: Some(interface::C_VerifyInit),
    C_Verify: Some(interface::C_Verify),
    C_VerifyUpdate: Some(interface::C_VerifyUpdate),
    C_VerifyFinal: Some(interface::C_VerifyFinal),
    C_VerifyRecoverInit: Some(interface::C_VerifyRecoverInit),
    C_VerifyRecover: Some(interface::C_VerifyRecover),
    C_DigestEncryptUpdate: Some(interface::C_DigestEncryptUpdate),
    C_DecryptDigestUpdate: Some(interface::C_DecryptDigestUpdate),
    C_SignEncryptUpdate: Some(interface::C_SignEncryptUpdate),
    C_DecryptVerifyUpdate: Some(interface::C_DecryptVerifyUpdate),
    C_GenerateKey: Some(interface::C_GenerateKey),
    C_GenerateKeyPair: Some(interface::C_GenerateKeyPair),
    C_WrapKey: Some(interface::C_WrapKey),
    C_UnwrapKey: Some(interface::C_UnwrapKey),
    C_DeriveKey: Some(interface::C_DeriveKey),
    C_SeedRandom: Some(interface::C_SeedRandom),
    C_GenerateRandom: Some(interface::C_GenerateRandom),
    C_GetFunctionStatus: Some(interface::C_GetFunctionStatus),
    C_CancelFunction: Some(interface::C_CancelFunction),
    C_WaitForSlotEvent: Some(interface::C_WaitForSlotEvent),
};

extern "C" fn fn_initialize(_init_args: interface::CK_VOID_PTR) -> CK_RV {
    CKR_OK
}

#[no_mangle]
pub extern "C" fn C_GetFunctionList(fnlist: interface::CK_FUNCTION_LIST_PTR_PTR) -> CK_RV {
    unsafe { *fnlist = &mut FNLIST_240 };
    CKR_OK
}


#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn it_works() {
        let list :nterface::CK_FUNCTION_LIST_PTR_PTR = std::ptr::null_mut();
        let result = C_GetFunctionList(list);
        assert_eq!(result, 0);
    }
}
