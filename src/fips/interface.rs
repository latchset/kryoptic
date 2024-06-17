// Copyright 2024 Simo Sorce
// See LICENSE.txt file for terms

#[allow(non_camel_case_types)]
pub type CK_C_GetSessionValidationFlags = ::std::option::Option<
    unsafe extern "C" fn(
        arg1: CK_SESSION_HANDLE,
        arg2: CK_SESSION_VALIDATION_FLAGS_TYPE,
        arg3: CK_FLAGS_PTR,
    ) -> CK_RV,
>;

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
#[allow(non_snake_case)]
pub struct CK_FUNCTION_LIST_VAL {
    pub version: CK_VERSION,
    pub C_GetSessionValidationFlags: CK_C_GetSessionValidationFlags,
}

extern "C" fn fn_get_session_validation_flags(
    s_handle: CK_SESSION_HANDLE,
    flags_type: CK_SESSION_VALIDATION_FLAGS_TYPE,
    pflags: CK_FLAGS_PTR,
) -> CK_RV {
    let flags: CK_FLAGS = if flags_type != CKS_LAST_VALIDATION_OK {
        0
    } else {
        let rstate = global_rlock!(STATE);
        let session = res_or_ret!(rstate.get_session(s_handle));

        session.get_last_validation_flags()
    };
    unsafe { *pflags = flags };
    CKR_OK
}

pub static FNLIST_VAL: CK_FUNCTION_LIST_VAL = CK_FUNCTION_LIST_VAL {
    version: CK_VERSION { major: 0, minor: 1 },
    C_GetSessionValidationFlags: Some(fn_get_session_validation_flags),
};

static INTERFACE_NAME_VAL_NUL: &str = "Kryoptic Validation v1\0";
pub static INTERFACE_VAL: CK_INTERFACE = CK_INTERFACE {
    pInterfaceName: INTERFACE_NAME_VAL_NUL.as_ptr() as *mut u8,
    pFunctionList: &FNLIST_VAL as *const _ as *const ::std::os::raw::c_void,
    flags: 0,
};
