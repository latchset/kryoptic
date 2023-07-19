mod interface {
    #![allow(non_upper_case_globals)]
    #![allow(non_camel_case_types)]
    #![allow(non_snake_case)]
    #![allow(dead_code)]
    include!("pkcs11_bindings.rs");
}

use interface::{CK_RV, CKR_OK, CKR_FUNCTION_NOT_SUPPORTED};

extern "C" fn fn_initialize(_init_args: interface::CK_VOID_PTR) -> CK_RV {
    CKR_OK
}
extern "C" fn fn_finalize(_reserved: interface::CK_VOID_PTR) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_get_info(_info: interface::CK_INFO_PTR) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_get_slot_list(
        _token_present: interface::CK_BBOOL,
        _slot_list: interface::CK_SLOT_ID_PTR,
        _pul_count: interface::CK_ULONG_PTR,
    ) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_get_slot_info(_slot_id: interface::CK_SLOT_ID, _info: interface::CK_SLOT_INFO_PTR) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_get_token_info(_slot_id: interface::CK_SLOT_ID, _info: interface::CK_TOKEN_INFO_PTR) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_get_mechanism_list(
        _slot_id: interface::CK_SLOT_ID,
        _mechanism_list: interface::CK_MECHANISM_TYPE_PTR,
        _pul_count: interface::CK_ULONG_PTR,
    ) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_get_mechanism_info(
        _slot_id: interface::CK_SLOT_ID,
        _type_: interface::CK_MECHANISM_TYPE,
        _info: interface::CK_MECHANISM_INFO_PTR,
    ) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_init_token(
        _slot_id: interface::CK_SLOT_ID,
        _pin: interface::CK_UTF8CHAR_PTR,
        _pin_len: interface::CK_ULONG,
        _label: interface::CK_UTF8CHAR_PTR,
    ) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_init_pin(
        _session: interface::CK_SESSION_HANDLE,
        _pin: interface::CK_UTF8CHAR_PTR,
        _pin_len: interface::CK_ULONG,
    ) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_set_pin(
        _session: interface::CK_SESSION_HANDLE,
        _old_pin: interface::CK_UTF8CHAR_PTR,
        _old_len: interface::CK_ULONG,
        _new_pin: interface::CK_UTF8CHAR_PTR,
        _new_len: interface::CK_ULONG,
    ) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_open_session(
        _slot_id: interface::CK_SLOT_ID,
        _flags: interface::CK_FLAGS,
        _application: interface::CK_VOID_PTR,
        _notify: interface::CK_NOTIFY,
        _ph_session: interface::CK_SESSION_HANDLE_PTR,
    ) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_close_session(_session: interface::CK_SESSION_HANDLE) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_close_all_sessions(_slot_id: interface::CK_SLOT_ID) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_get_session_info(
        _session: interface::CK_SESSION_HANDLE,
        _info: interface::CK_SESSION_INFO_PTR,
    ) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_get_operation_state(
        _session: interface::CK_SESSION_HANDLE,
        _operation_state: interface::CK_BYTE_PTR,
        _pul_operation_state_len: interface::CK_ULONG_PTR,
    ) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_set_operation_state(
        _session: interface::CK_SESSION_HANDLE,
        _operation_state: interface::CK_BYTE_PTR,
        _operation_state_len: interface::CK_ULONG,
        _encryption_key: interface::CK_OBJECT_HANDLE,
        _authentication_key: interface::CK_OBJECT_HANDLE,
    ) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_login(
        _session: interface::CK_SESSION_HANDLE,
        _user_type: interface::CK_USER_TYPE,
        _pin: interface::CK_UTF8CHAR_PTR,
        _pin_len: interface::CK_ULONG,
    ) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_logout(_session: interface::CK_SESSION_HANDLE) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_create_object(
        _session: interface::CK_SESSION_HANDLE,
        _template: interface::CK_ATTRIBUTE_PTR,
        _count: interface::CK_ULONG,
        _ph_object: interface::CK_OBJECT_HANDLE_PTR,
    ) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_copy_object(
        _session: interface::CK_SESSION_HANDLE,
        _object: interface::CK_OBJECT_HANDLE,
        _template: interface::CK_ATTRIBUTE_PTR,
        _count: interface::CK_ULONG,
        _ph_new_object: interface::CK_OBJECT_HANDLE_PTR,
    ) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_destroy_object(
        _session: interface::CK_SESSION_HANDLE,
        _object: interface::CK_OBJECT_HANDLE,
    ) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_get_object_size(
        _session: interface::CK_SESSION_HANDLE,
        _object: interface::CK_OBJECT_HANDLE,
        _pul_size: interface::CK_ULONG_PTR,
    ) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_get_attribute_value(
        _session: interface::CK_SESSION_HANDLE,
        _object: interface::CK_OBJECT_HANDLE,
        _template: interface::CK_ATTRIBUTE_PTR,
        _count: interface::CK_ULONG,
    ) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_set_attribute_value(
        _session: interface::CK_SESSION_HANDLE,
        _object: interface::CK_OBJECT_HANDLE,
        _template: interface::CK_ATTRIBUTE_PTR,
        _count: interface::CK_ULONG,
    ) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_find_objects_init(
        _session: interface::CK_SESSION_HANDLE,
        _template: interface::CK_ATTRIBUTE_PTR,
        _count: interface::CK_ULONG,
    ) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_find_objects(
        _session: interface::CK_SESSION_HANDLE,
        _ph_object: interface::CK_OBJECT_HANDLE_PTR,
        _max_object_count: interface::CK_ULONG,
        _pul_object_count: interface::CK_ULONG_PTR,
    ) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_find_objects_final(_session: interface::CK_SESSION_HANDLE) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_encrypt_init(
        _session: interface::CK_SESSION_HANDLE,
        _mechanism: interface::CK_MECHANISM_PTR,
        _key: interface::CK_OBJECT_HANDLE,
    ) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_encrypt(
        _session: interface::CK_SESSION_HANDLE,
        _data: interface::CK_BYTE_PTR,
        _data_len: interface::CK_ULONG,
        _encrypted_data: interface::CK_BYTE_PTR,
        _pul_encrypted_data_len: interface::CK_ULONG_PTR,
    ) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_encrypt_update(
        _session: interface::CK_SESSION_HANDLE,
        _part: interface::CK_BYTE_PTR,
        _part_len: interface::CK_ULONG,
        _encrypted_part: interface::CK_BYTE_PTR,
        _pul_encrypted_part_len: interface::CK_ULONG_PTR,
    ) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_encrypt_final(
        _session: interface::CK_SESSION_HANDLE,
        _last_encrypted_part: interface::CK_BYTE_PTR,
        _pul_last_encrypted_part_len: interface::CK_ULONG_PTR,
    ) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_decrypt_init(
        _session: interface::CK_SESSION_HANDLE,
        _mechanism: interface::CK_MECHANISM_PTR,
        _key: interface::CK_OBJECT_HANDLE,
    ) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_decrypt(
        _session: interface::CK_SESSION_HANDLE,
        _encrypted_data: interface::CK_BYTE_PTR,
        _encrypted_data_len: interface::CK_ULONG,
        _data: interface::CK_BYTE_PTR,
        _pul_data_len: interface::CK_ULONG_PTR,
    ) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_decrypt_update(
        _session: interface::CK_SESSION_HANDLE,
        _encrypted_part: interface::CK_BYTE_PTR,
        _encrypted_part_len: interface::CK_ULONG,
        _part: interface::CK_BYTE_PTR,
        _pul_part_len: interface::CK_ULONG_PTR,
    ) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_decrypt_final(
        _session: interface::CK_SESSION_HANDLE,
        _last_part: interface::CK_BYTE_PTR,
        _pul_last_part_len: interface::CK_ULONG_PTR,
    ) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_digest_init(
        _session: interface::CK_SESSION_HANDLE,
        _mechanism: interface::CK_MECHANISM_PTR,
    ) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_digest(
        _session: interface::CK_SESSION_HANDLE,
        _data: interface::CK_BYTE_PTR,
        _data_len: interface::CK_ULONG,
        _digest: interface::CK_BYTE_PTR,
        _pul_digest_len: interface::CK_ULONG_PTR,
    ) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_digest_update(
        _session: interface::CK_SESSION_HANDLE,
        _part: interface::CK_BYTE_PTR,
        _part_len: interface::CK_ULONG,
    ) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_digest_key(_session: interface::CK_SESSION_HANDLE, _key: interface::CK_OBJECT_HANDLE) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_digest_final(
        _session: interface::CK_SESSION_HANDLE,
        _digest: interface::CK_BYTE_PTR,
        _pul_digest_len: interface::CK_ULONG_PTR,
    ) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_sign_init(
        _session: interface::CK_SESSION_HANDLE,
        _mechanism: interface::CK_MECHANISM_PTR,
        _key: interface::CK_OBJECT_HANDLE,
    ) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_sign(
        _session: interface::CK_SESSION_HANDLE,
        _data: interface::CK_BYTE_PTR,
        _data_len: interface::CK_ULONG,
        _signature: interface::CK_BYTE_PTR,
        _pul_signature_len: interface::CK_ULONG_PTR,
    ) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_sign_update(
        _session: interface::CK_SESSION_HANDLE,
        _part: interface::CK_BYTE_PTR,
        _part_len: interface::CK_ULONG,
    ) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_sign_final(
        _session: interface::CK_SESSION_HANDLE,
        _signature: interface::CK_BYTE_PTR,
        _pul_signature_len: interface::CK_ULONG_PTR,
    ) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_sign_recover_init(
        _session: interface::CK_SESSION_HANDLE,
        _mechanism: interface::CK_MECHANISM_PTR,
        _key: interface::CK_OBJECT_HANDLE,
    ) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_sign_recover(
        _session: interface::CK_SESSION_HANDLE,
        _data: interface::CK_BYTE_PTR,
        _data_len: interface::CK_ULONG,
        _signature: interface::CK_BYTE_PTR,
        _pul_signature_len: interface::CK_ULONG_PTR,
    ) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_verify_init(
        _session: interface::CK_SESSION_HANDLE,
        _mechanism: interface::CK_MECHANISM_PTR,
        _key: interface::CK_OBJECT_HANDLE,
    ) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_verify(
        _session: interface::CK_SESSION_HANDLE,
        _data: interface::CK_BYTE_PTR,
        _data_len: interface::CK_ULONG,
        _signature: interface::CK_BYTE_PTR,
        _signature_len: interface::CK_ULONG,
    ) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_verify_update(
        _session: interface::CK_SESSION_HANDLE,
        _part: interface::CK_BYTE_PTR,
        _part_len: interface::CK_ULONG,
    ) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_verify_final(
        _session: interface::CK_SESSION_HANDLE,
        _signature: interface::CK_BYTE_PTR,
        _signature_len: interface::CK_ULONG,
    ) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_verify_recover_init(
        _session: interface::CK_SESSION_HANDLE,
        _mechanism: interface::CK_MECHANISM_PTR,
        _key: interface::CK_OBJECT_HANDLE,
    ) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_verify_recover(
        _session: interface::CK_SESSION_HANDLE,
        _signature: interface::CK_BYTE_PTR,
        _signature_len: interface::CK_ULONG,
        _data: interface::CK_BYTE_PTR,
        _pul_data_len: interface::CK_ULONG_PTR,
    ) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_digest_encrypt_update(
        _session: interface::CK_SESSION_HANDLE,
        _part: interface::CK_BYTE_PTR,
        _part_len: interface::CK_ULONG,
        _encrypted_part: interface::CK_BYTE_PTR,
        _pul_encrypted_part_len: interface::CK_ULONG_PTR,
    ) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_decrypt_digest_update(
        _session: interface::CK_SESSION_HANDLE,
        _encrypted_part: interface::CK_BYTE_PTR,
        _encrypted_part_len: interface::CK_ULONG,
        _part: interface::CK_BYTE_PTR,
        _pul_part_len: interface::CK_ULONG_PTR,
    ) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_sign_encrypt_update(
        _session: interface::CK_SESSION_HANDLE,
        _part: interface::CK_BYTE_PTR,
        _part_len: interface::CK_ULONG,
        _encrypted_part: interface::CK_BYTE_PTR,
        _pul_encrypted_part_len: interface::CK_ULONG_PTR,
    ) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_decrypt_verify_update(
        _session: interface::CK_SESSION_HANDLE,
        _encrypted_part: interface::CK_BYTE_PTR,
        _encrypted_part_len: interface::CK_ULONG,
        _part: interface::CK_BYTE_PTR,
        _pul_part_len: interface::CK_ULONG_PTR,
    ) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_generate_key(
        _session: interface::CK_SESSION_HANDLE,
        _mechanism: interface::CK_MECHANISM_PTR,
        _template: interface::CK_ATTRIBUTE_PTR,
        _count: interface::CK_ULONG,
        _ph_key: interface::CK_OBJECT_HANDLE_PTR,
    ) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_generate_key_pair(
        _session: interface::CK_SESSION_HANDLE,
        _mechanism: interface::CK_MECHANISM_PTR,
        _public_key_template: interface::CK_ATTRIBUTE_PTR,
        _public_key_attribute_count: interface::CK_ULONG,
        _private_key_template: interface::CK_ATTRIBUTE_PTR,
        _private_key_attribute_count: interface::CK_ULONG,
        _ph_public_key: interface::CK_OBJECT_HANDLE_PTR,
        _ph_private_key: interface::CK_OBJECT_HANDLE_PTR,
    ) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_wrap_key(
        _session: interface::CK_SESSION_HANDLE,
        _mechanism: interface::CK_MECHANISM_PTR,
        _wrapping_key: interface::CK_OBJECT_HANDLE,
        _key: interface::CK_OBJECT_HANDLE,
        _wrapped_key: interface::CK_BYTE_PTR,
        _pul_wrapped_key_len: interface::CK_ULONG_PTR,
    ) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_unwrap_key(
        _session: interface::CK_SESSION_HANDLE,
        _mechanism: interface::CK_MECHANISM_PTR,
        _unwrapping_key: interface::CK_OBJECT_HANDLE,
        _wrapped_key: interface::CK_BYTE_PTR,
        _wrapped_key_len: interface::CK_ULONG,
        _template: interface::CK_ATTRIBUTE_PTR,
        _attribute_count: interface::CK_ULONG,
        _ph_key: interface::CK_OBJECT_HANDLE_PTR,
    ) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_derive_key(
        _session: interface::CK_SESSION_HANDLE,
        _mechanism: interface::CK_MECHANISM_PTR,
        _base_key: interface::CK_OBJECT_HANDLE,
        _template: interface::CK_ATTRIBUTE_PTR,
        _attribute_count: interface::CK_ULONG,
        _ph_key: interface::CK_OBJECT_HANDLE_PTR,
    ) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_seed_random(
        _session: interface::CK_SESSION_HANDLE,
        _seed: interface::CK_BYTE_PTR,
        _seed_len: interface::CK_ULONG,
    ) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_generate_random(
        _session: interface::CK_SESSION_HANDLE,
        _random_data: interface::CK_BYTE_PTR,
        _random_len: interface::CK_ULONG,
    ) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_get_function_status(_session: interface::CK_SESSION_HANDLE) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_cancel_function(_session: interface::CK_SESSION_HANDLE) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn fn_wait_for_slot_event(
        _flags: interface::CK_FLAGS,
        _slot: interface::CK_SLOT_ID_PTR,
        _rserved: interface::CK_VOID_PTR,
    ) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

pub static mut FNLIST_240: interface::CK_FUNCTION_LIST = interface::CK_FUNCTION_LIST {
    version: interface::CK_VERSION {
        major: 2,
        minor: 40},
    C_Initialize: Some(fn_initialize),
    C_Finalize: Some(fn_finalize),
    C_GetInfo: Some(fn_get_info),
    C_GetFunctionList: Some(C_GetFunctionList),
    C_GetSlotList: Some(fn_get_slot_list),
    C_GetSlotInfo: Some(fn_get_slot_info),
    C_GetTokenInfo: Some(fn_get_token_info),
    C_GetMechanismList: Some(fn_get_mechanism_list),
    C_GetMechanismInfo: Some(fn_get_mechanism_info),
    C_InitToken: Some(fn_init_token),
    C_InitPIN: Some(fn_init_pin),
    C_SetPIN: Some(fn_set_pin),
    C_OpenSession: Some(fn_open_session),
    C_CloseSession: Some(fn_close_session),
    C_CloseAllSessions: Some(fn_close_all_sessions),
    C_GetSessionInfo: Some(fn_get_session_info),
    C_GetOperationState: Some(fn_get_operation_state),
    C_SetOperationState: Some(fn_set_operation_state),
    C_Login: Some(fn_login),
    C_Logout: Some(fn_logout),
    C_CreateObject: Some(fn_create_object),
    C_CopyObject: Some(fn_copy_object),
    C_DestroyObject: Some(fn_destroy_object),
    C_GetObjectSize: Some(fn_get_object_size),
    C_GetAttributeValue: Some(fn_get_attribute_value),
    C_SetAttributeValue: Some(fn_set_attribute_value),
    C_FindObjectsInit: Some(fn_find_objects_init),
    C_FindObjects: Some(fn_find_objects),
    C_FindObjectsFinal: Some(fn_find_objects_final),
    C_EncryptInit: Some(fn_encrypt_init),
    C_Encrypt: Some(fn_encrypt),
    C_EncryptUpdate: Some(fn_encrypt_update),
    C_EncryptFinal: Some(fn_encrypt_final),
    C_DecryptInit: Some(fn_decrypt_init),
    C_Decrypt: Some(fn_decrypt),
    C_DecryptUpdate: Some(fn_decrypt_update),
    C_DecryptFinal: Some(fn_decrypt_final),
    C_DigestInit: Some(fn_digest_init),
    C_Digest: Some(fn_digest),
    C_DigestUpdate: Some(fn_digest_update),
    C_DigestKey: Some(fn_digest_key),
    C_DigestFinal: Some(fn_digest_final),
    C_SignInit: Some(fn_sign_init),
    C_Sign: Some(fn_sign),
    C_SignUpdate: Some(fn_sign_update),
    C_SignFinal: Some(fn_sign_final),
    C_SignRecoverInit: Some(fn_sign_recover_init),
    C_SignRecover: Some(fn_sign_recover),
    C_VerifyInit: Some(fn_verify_init),
    C_Verify: Some(fn_verify),
    C_VerifyUpdate: Some(fn_verify_update),
    C_VerifyFinal: Some(fn_verify_final),
    C_VerifyRecoverInit: Some(fn_verify_recover_init),
    C_VerifyRecover: Some(fn_verify_recover),
    C_DigestEncryptUpdate: Some(fn_digest_encrypt_update),
    C_DecryptDigestUpdate: Some(fn_decrypt_digest_update),
    C_SignEncryptUpdate: Some(fn_sign_encrypt_update),
    C_DecryptVerifyUpdate: Some(fn_decrypt_verify_update),
    C_GenerateKey: Some(fn_generate_key),
    C_GenerateKeyPair: Some(fn_generate_key_pair),
    C_WrapKey: Some(fn_wrap_key),
    C_UnwrapKey: Some(fn_unwrap_key),
    C_DeriveKey: Some(fn_derive_key),
    C_SeedRandom: Some(fn_seed_random),
    C_GenerateRandom: Some(fn_generate_random),
    C_GetFunctionStatus: Some(fn_get_function_status),
    C_CancelFunction: Some(fn_cancel_function),
    C_WaitForSlotEvent: Some(fn_wait_for_slot_event),
};

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
