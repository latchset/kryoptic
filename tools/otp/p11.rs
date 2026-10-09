// Copyright 2026 Simo Sorce
// See LICENSE.txt file for terms

use std::ffi::{c_void, CStr, CString};
use std::path::Path;

use kryoptic_lib::pkcs11;
use libc;

fn dl_error() -> String {
    let cstr = unsafe { libc::dlerror() };
    if cstr.is_null() {
        String::from("<unknown error>")
    } else {
        unsafe {
            String::from_utf8_lossy(CStr::from_ptr(cstr).to_bytes()).to_string()
        }
    }
}

pub struct FuncList {
    fntable: *mut pkcs11::CK_FUNCTION_LIST_3_2,
    _lib_handle: *mut c_void,
}

impl FuncList {
    pub fn load(lib_path: &Path) -> Result<Self, String> {
        let soname = CString::new(lib_path.to_str().unwrap_or("")).unwrap();
        let rtld_flags = libc::RTLD_LOCAL | libc::RTLD_NOW;
        let lib_handle = unsafe { libc::dlopen(soname.as_ptr(), rtld_flags) };
        if lib_handle.is_null() {
            return Err(format!(
                "Failed to load PKCS#11 module '{}': {}",
                lib_path.display(),
                dl_error()
            ));
        }

        let symbol_name = CString::new("C_GetInterface").unwrap();
        let iface_fn: pkcs11::CK_C_GetInterface = unsafe {
            let ptr = libc::dlsym(lib_handle, symbol_name.as_ptr());
            if ptr.is_null() {
                None
            } else {
                Some(std::mem::transmute::<
                    *mut c_void,
                    unsafe extern "C" fn(
                        pkcs11::CK_UTF8CHAR_PTR,
                        pkcs11::CK_VERSION_PTR,
                        pkcs11::CK_INTERFACE_PTR_PTR,
                        pkcs11::CK_FLAGS,
                    ) -> pkcs11::CK_RV,
                >(ptr))
            }
        };

        let mut interface: pkcs11::CK_INTERFACE_PTR = std::ptr::null_mut();
        let mut version = pkcs11::CK_VERSION { major: 3, minor: 2 };
        let rv = match iface_fn {
            None => {
                return Err(format!(
                    "Failed to find symbol C_GetInterface: {}",
                    dl_error()
                ));
            }
            Some(func) => unsafe {
                func(std::ptr::null_mut(), &mut version, &mut interface, 0)
            },
        };

        if rv != pkcs11::CKR_OK || interface.is_null() {
            return Err(format!(
                "Failed to get PKCS#11 interface, CKR code: 0x{:08X}",
                rv
            ));
        }

        let fn_list = unsafe {
            (*interface).pFunctionList as *mut pkcs11::CK_FUNCTION_LIST_3_2
        };
        if fn_list.is_null() {
            return Err("PKCS#11 interface returned null function list".into());
        }

        Ok(FuncList {
            fntable: fn_list,
            _lib_handle: lib_handle,
        })
    }

    pub fn initialize(&self, db_path: &Path) -> Result<(), String> {
        let path_str =
            db_path.to_str().ok_or("Invalid UTF-8 in database path")?;
        let init_arg = CString::new(path_str).map_err(|e| e.to_string())?;

        unsafe {
            match (*self.fntable).C_Initialize {
                None => {
                    return Err(
                        "PKCS#11 module has no C_Initialize function".into()
                    )
                }
                Some(func) => {
                    let mut targs = pkcs11::CK_C_INITIALIZE_ARGS {
                        CreateMutex: None,
                        DestroyMutex: None,
                        LockMutex: None,
                        UnlockMutex: None,
                        flags: pkcs11::CKF_OS_LOCKING_OK,
                        pReserved: init_arg.as_ptr() as pkcs11::CK_VOID_PTR,
                    };
                    let targs_ptr =
                        &mut targs as *mut pkcs11::CK_C_INITIALIZE_ARGS;
                    let rv = func(targs_ptr as *mut c_void);
                    if rv != pkcs11::CKR_OK
                        && rv != pkcs11::CKR_CRYPTOKI_ALREADY_INITIALIZED
                    {
                        return Err(format!(
                            "C_Initialize failed with code 0x{:08X}",
                            rv
                        ));
                    }
                    Ok(())
                }
            }
        }
    }

    pub fn finalize(&self) -> Result<(), String> {
        unsafe {
            match (*self.fntable).C_Finalize {
                None => Err("PKCS#11 module has no C_Finalize function".into()),
                Some(func) => {
                    let rv = func(std::ptr::null_mut());
                    if rv != pkcs11::CKR_OK {
                        Err(format!("C_Finalize failed with code 0x{:08X}", rv))
                    } else {
                        Ok(())
                    }
                }
            }
        }
    }

    pub fn get_slot_list(&self) -> Result<Vec<pkcs11::CK_SLOT_ID>, String> {
        unsafe {
            match (*self.fntable).C_GetSlotList {
                None => {
                    Err("PKCS#11 module has no C_GetSlotList function".into())
                }
                Some(func) => {
                    let mut count: pkcs11::CK_ULONG = 0;
                    let rv = func(
                        pkcs11::CK_FALSE,
                        std::ptr::null_mut(),
                        &mut count,
                    );
                    if rv != pkcs11::CKR_OK {
                        return Err(format!(
                            "C_GetSlotList (count query) failed: 0x{:08X}",
                            rv
                        ));
                    }
                    if count == 0 {
                        return Ok(Vec::new());
                    }
                    let mut slots = vec![0; count as usize];
                    let rv =
                        func(pkcs11::CK_FALSE, slots.as_mut_ptr(), &mut count);
                    if rv != pkcs11::CKR_OK {
                        return Err(format!(
                            "C_GetSlotList failed: 0x{:08X}",
                            rv
                        ));
                    }
                    slots.truncate(count as usize);
                    Ok(slots)
                }
            }
        }
    }

    pub fn get_token_info(
        &self,
        slot: pkcs11::CK_SLOT_ID,
    ) -> Result<pkcs11::CK_TOKEN_INFO, String> {
        unsafe {
            match (*self.fntable).C_GetTokenInfo {
                None => {
                    Err("PKCS#11 module has no C_GetTokenInfo function".into())
                }
                Some(func) => {
                    let mut info: pkcs11::CK_TOKEN_INFO = std::mem::zeroed();
                    let rv = func(slot, &mut info);
                    if rv != pkcs11::CKR_OK {
                        Err(format!(
                            "C_GetTokenInfo failed with code 0x{:08X}",
                            rv
                        ))
                    } else {
                        Ok(info)
                    }
                }
            }
        }
    }

    pub fn init_token(
        &self,
        slot_id: pkcs11::CK_SLOT_ID,
        pin: &str,
        label: &str,
    ) -> Result<(), String> {
        let pin_c = CString::new(pin).map_err(|e| e.to_string())?;
        let mut label_padded = [b' '; 32];
        let label_bytes = label.as_bytes();
        let len = std::cmp::min(label_bytes.len(), 32);
        label_padded[..len].copy_from_slice(&label_bytes[..len]);

        unsafe {
            match (*self.fntable).C_InitToken {
                None => {
                    Err("PKCS#11 module has no C_InitToken function".into())
                }
                Some(func) => {
                    let rv = func(
                        slot_id,
                        pin_c.as_ptr() as *mut u8,
                        pin_c.to_bytes().len() as pkcs11::CK_ULONG,
                        label_padded.as_mut_ptr(),
                    );
                    if rv != pkcs11::CKR_OK {
                        Err(format!(
                            "C_InitToken failed with code 0x{:08X}",
                            rv
                        ))
                    } else {
                        Ok(())
                    }
                }
            }
        }
    }

    pub fn open_rw_session(
        &self,
        slot_id: pkcs11::CK_SLOT_ID,
    ) -> Result<pkcs11::CK_SESSION_HANDLE, String> {
        unsafe {
            match (*self.fntable).C_OpenSession {
                None => {
                    Err("PKCS#11 module has no C_OpenSession function".into())
                }
                Some(func) => {
                    let mut session_handle: pkcs11::CK_SESSION_HANDLE =
                        pkcs11::CK_INVALID_HANDLE;
                    let flags =
                        pkcs11::CKF_SERIAL_SESSION | pkcs11::CKF_RW_SESSION;
                    let rv = func(
                        slot_id,
                        flags,
                        std::ptr::null_mut(),
                        None,
                        &mut session_handle,
                    );
                    if rv != pkcs11::CKR_OK {
                        Err(format!(
                            "C_OpenSession failed with code 0x{:08X}",
                            rv
                        ))
                    } else {
                        Ok(session_handle)
                    }
                }
            }
        }
    }

    pub fn close_session(
        &self,
        session: pkcs11::CK_SESSION_HANDLE,
    ) -> Result<(), String> {
        unsafe {
            match (*self.fntable).C_CloseSession {
                None => {
                    Err("PKCS#11 module has no C_CloseSession function".into())
                }
                Some(func) => {
                    let rv = func(session);
                    if rv != pkcs11::CKR_OK {
                        Err(format!(
                            "C_CloseSession failed with code 0x{:08X}",
                            rv
                        ))
                    } else {
                        Ok(())
                    }
                }
            }
        }
    }

    pub fn try_login(
        &self,
        session: pkcs11::CK_SESSION_HANDLE,
        user_type: pkcs11::CK_USER_TYPE,
        pin: &str,
    ) -> Result<(), pkcs11::CK_RV> {
        let pin_c = match CString::new(pin) {
            Ok(c) => c,
            Err(_) => return Err(pkcs11::CKR_ARGUMENTS_BAD),
        };
        unsafe {
            match (*self.fntable).C_Login {
                None => Err(pkcs11::CKR_FUNCTION_NOT_SUPPORTED),
                Some(func) => {
                    let rv = func(
                        session,
                        user_type,
                        pin_c.as_ptr() as *mut u8,
                        pin_c.to_bytes().len() as pkcs11::CK_ULONG,
                    );
                    if rv == pkcs11::CKR_OK
                        || rv == pkcs11::CKR_USER_ALREADY_LOGGED_IN
                    {
                        Ok(())
                    } else {
                        Err(rv)
                    }
                }
            }
        }
    }

    pub fn login(
        &self,
        session: pkcs11::CK_SESSION_HANDLE,
        user_type: pkcs11::CK_USER_TYPE,
        pin: &str,
    ) -> Result<(), String> {
        self.try_login(session, user_type, pin)
            .map_err(|rv| format!("C_Login failed with code 0x{:08X}", rv))
    }

    pub fn logout(
        &self,
        session: pkcs11::CK_SESSION_HANDLE,
    ) -> Result<(), String> {
        unsafe {
            match (*self.fntable).C_Logout {
                None => Err("PKCS#11 module has no C_Logout function".into()),
                Some(func) => {
                    let rv = func(session);
                    if rv != pkcs11::CKR_OK
                        && rv != pkcs11::CKR_USER_NOT_LOGGED_IN
                    {
                        Err(format!("C_Logout failed with code 0x{:08X}", rv))
                    } else {
                        Ok(())
                    }
                }
            }
        }
    }

    pub fn init_pin(
        &self,
        session: pkcs11::CK_SESSION_HANDLE,
        pin: &str,
    ) -> Result<(), String> {
        let pin_c = CString::new(pin).map_err(|e| e.to_string())?;
        unsafe {
            match (*self.fntable).C_InitPIN {
                None => Err("PKCS#11 module has no C_InitPIN function".into()),
                Some(func) => {
                    let rv = func(
                        session,
                        pin_c.as_ptr() as *mut u8,
                        pin_c.to_bytes().len() as pkcs11::CK_ULONG,
                    );
                    if rv != pkcs11::CKR_OK {
                        Err(format!("C_InitPIN failed with code 0x{:08X}", rv))
                    } else {
                        Ok(())
                    }
                }
            }
        }
    }

    pub fn generate_random(
        &self,
        session: pkcs11::CK_SESSION_HANDLE,
        len: usize,
    ) -> Result<Vec<u8>, String> {
        let mut buf = vec![0u8; len];
        unsafe {
            match (*self.fntable).C_GenerateRandom {
                None => {
                    Err("PKCS#11 module has no C_GenerateRandom function"
                        .into())
                }
                Some(func) => {
                    let rv = func(
                        session,
                        buf.as_mut_ptr(),
                        len as pkcs11::CK_ULONG,
                    );
                    if rv != pkcs11::CKR_OK {
                        Err(format!(
                            "C_GenerateRandom failed with code 0x{:08X}",
                            rv
                        ))
                    } else {
                        Ok(buf)
                    }
                }
            }
        }
    }

    pub fn create_object(
        &self,
        session: pkcs11::CK_SESSION_HANDLE,
        template: &[pkcs11::CK_ATTRIBUTE],
    ) -> Result<pkcs11::CK_OBJECT_HANDLE, String> {
        unsafe {
            match (*self.fntable).C_CreateObject {
                None => {
                    Err("PKCS#11 module has no C_CreateObject function".into())
                }
                Some(func) => {
                    let mut object_handle = pkcs11::CK_INVALID_HANDLE;
                    let rv = func(
                        session,
                        template.as_ptr() as *mut pkcs11::CK_ATTRIBUTE,
                        template.len() as pkcs11::CK_ULONG,
                        &mut object_handle,
                    );
                    if rv != pkcs11::CKR_OK {
                        Err(format!(
                            "C_CreateObject failed with code 0x{:08X}",
                            rv
                        ))
                    } else {
                        Ok(object_handle)
                    }
                }
            }
        }
    }

    pub fn find_objects(
        &self,
        session: pkcs11::CK_SESSION_HANDLE,
        template: &[pkcs11::CK_ATTRIBUTE],
    ) -> Result<Vec<pkcs11::CK_OBJECT_HANDLE>, String> {
        unsafe {
            match (*self.fntable).C_FindObjectsInit {
                None => {
                    return Err(
                        "PKCS#11 module has no C_FindObjectsInit function"
                            .into(),
                    )
                }
                Some(func) => {
                    let rv = func(
                        session,
                        template.as_ptr() as *mut pkcs11::CK_ATTRIBUTE,
                        template.len() as pkcs11::CK_ULONG,
                    );
                    if rv != pkcs11::CKR_OK {
                        return Err(format!(
                            "C_FindObjectsInit failed: 0x{:08X}",
                            rv
                        ));
                    }
                }
            }

            let mut objects = vec![0; 100];
            let mut count: pkcs11::CK_ULONG = 0;
            let rv = match (*self.fntable).C_FindObjects {
                None => {
                    let _ =
                        (*self.fntable).C_FindObjectsFinal.map(|f| f(session));
                    return Err(
                        "PKCS#11 module has no C_FindObjects function".into()
                    );
                }
                Some(func) => {
                    func(session, objects.as_mut_ptr(), 100, &mut count)
                }
            };

            let final_rv = match (*self.fntable).C_FindObjectsFinal {
                None => pkcs11::CKR_OK,
                Some(func) => func(session),
            };

            if rv != pkcs11::CKR_OK {
                return Err(format!("C_FindObjects failed: 0x{:08X}", rv));
            }
            if final_rv != pkcs11::CKR_OK {
                return Err(format!(
                    "C_FindObjectsFinal failed: 0x{:08X}",
                    final_rv
                ));
            }

            objects.truncate(count as usize);
            Ok(objects)
        }
    }

    pub fn get_attribute_bytes(
        &self,
        session: pkcs11::CK_SESSION_HANDLE,
        handle: pkcs11::CK_OBJECT_HANDLE,
        attr_type: pkcs11::CK_ATTRIBUTE_TYPE,
    ) -> Result<Vec<u8>, String> {
        unsafe {
            let func =
                match (*self.fntable).C_GetAttributeValue {
                    None => return Err(
                        "PKCS#11 module has no C_GetAttributeValue function"
                            .into(),
                    ),
                    Some(f) => f,
                };

            // Query length
            let mut attr = pkcs11::CK_ATTRIBUTE {
                type_: attr_type,
                pValue: std::ptr::null_mut(),
                ulValueLen: 0,
            };
            let rv = func(session, handle, &mut attr, 1);
            if rv != pkcs11::CKR_OK {
                return Err(format!(
                    "C_GetAttributeValue (query length) failed: 0x{:08X}",
                    rv
                ));
            }
            if attr.ulValueLen == pkcs11::CK_UNAVAILABLE_INFORMATION
                || (attr.ulValueLen as isize) < 0
            {
                return Err("Attribute value unavailable".into());
            }

            let mut buf = vec![0u8; attr.ulValueLen as usize];
            attr.pValue = buf.as_mut_ptr() as pkcs11::CK_VOID_PTR;
            let rv = func(session, handle, &mut attr, 1);
            if rv != pkcs11::CKR_OK {
                return Err(format!(
                    "C_GetAttributeValue (fetch) failed: 0x{:08X}",
                    rv
                ));
            }
            if attr.ulValueLen == pkcs11::CK_UNAVAILABLE_INFORMATION
                || (attr.ulValueLen as isize) < 0
            {
                return Err("Attribute value unavailable".into());
            }
            buf.truncate(attr.ulValueLen as usize);
            Ok(buf)
        }
    }

    #[allow(dead_code)]
    pub fn get_attribute_ulong(
        &self,
        session: pkcs11::CK_SESSION_HANDLE,
        handle: pkcs11::CK_OBJECT_HANDLE,
        attr_type: pkcs11::CK_ATTRIBUTE_TYPE,
    ) -> Result<pkcs11::CK_ULONG, String> {
        unsafe {
            let func =
                match (*self.fntable).C_GetAttributeValue {
                    None => return Err(
                        "PKCS#11 module has no C_GetAttributeValue function"
                            .into(),
                    ),
                    Some(f) => f,
                };
            let mut val: pkcs11::CK_ULONG = 0;
            let mut attr = pkcs11::CK_ATTRIBUTE {
                type_: attr_type,
                pValue: &mut val as *mut _ as pkcs11::CK_VOID_PTR,
                ulValueLen: std::mem::size_of::<pkcs11::CK_ULONG>()
                    as pkcs11::CK_ULONG,
            };
            let rv = func(session, handle, &mut attr, 1);
            if rv != pkcs11::CKR_OK {
                return Err(format!(
                    "C_GetAttributeValue failed: 0x{:08X}",
                    rv
                ));
            }
            if attr.ulValueLen == pkcs11::CK_UNAVAILABLE_INFORMATION
                || (attr.ulValueLen as isize) < 0
            {
                return Err("Attribute value unavailable".into());
            }
            Ok(val)
        }
    }

    pub fn sign_otp(
        &self,
        session: pkcs11::CK_SESSION_HANDLE,
        key_handle: pkcs11::CK_OBJECT_HANDLE,
        counter: Option<u64>,
    ) -> Result<String, String> {
        unsafe {
            let sign_init_fn = match (*self.fntable).C_SignInit {
                None => {
                    return Err(
                        "PKCS#11 module has no C_SignInit function".into()
                    )
                }
                Some(f) => f,
            };
            let sign_fn = match (*self.fntable).C_Sign {
                None => {
                    return Err("PKCS#11 module has no C_Sign function".into())
                }
                Some(f) => f,
            };

            let mut counter_bytes;
            let mut otp_param;
            let mut otp_params;
            let mut mech;

            if let Some(c) = counter {
                counter_bytes = c.to_be_bytes();
                otp_param = pkcs11::CK_OTP_PARAM {
                    type_: pkcs11::CK_OTP_COUNTER,
                    pValue: counter_bytes.as_mut_ptr() as pkcs11::CK_VOID_PTR,
                    ulValueLen: 8,
                };
                otp_params = pkcs11::CK_OTP_PARAMS {
                    pParams: &mut otp_param,
                    ulCount: 1,
                };
                mech = pkcs11::CK_MECHANISM {
                    mechanism: pkcs11::CKM_HOTP,
                    pParameter: &mut otp_params as *mut _
                        as pkcs11::CK_VOID_PTR,
                    ulParameterLen: std::mem::size_of::<pkcs11::CK_OTP_PARAMS>()
                        as pkcs11::CK_ULONG,
                };
            } else {
                mech = pkcs11::CK_MECHANISM {
                    mechanism: pkcs11::CKM_HOTP,
                    pParameter: std::ptr::null_mut(),
                    ulParameterLen: 0,
                };
            }

            let rv = sign_init_fn(session, &mut mech, key_handle);
            if rv != pkcs11::CKR_OK {
                return Err(format!("C_SignInit failed: 0x{:08X}", rv));
            }

            let dummy = [0u8; 1];
            let mut sig_buf = vec![0u64; 32];
            let mut sig_len = (sig_buf.len() * std::mem::size_of::<u64>())
                as pkcs11::CK_ULONG;

            let rv = sign_fn(
                session,
                dummy.as_ptr() as *mut u8,
                0,
                sig_buf.as_mut_ptr() as *mut u8,
                &mut sig_len,
            );
            if rv != pkcs11::CKR_OK {
                return Err(format!("C_Sign failed: 0x{:08X}", rv));
            }

            if (sig_len as usize)
                < std::mem::size_of::<pkcs11::CK_OTP_SIGNATURE_INFO>()
            {
                return Err(
                    "Invalid OTP signature returned: buffer too small".into()
                );
            }

            let sig_info: pkcs11::CK_OTP_SIGNATURE_INFO =
                std::ptr::read_unaligned(
                    sig_buf.as_ptr() as *const pkcs11::CK_OTP_SIGNATURE_INFO
                );
            if sig_info.ulCount == 0 || sig_info.pParams.is_null() {
                return Err("Invalid OTP signature returned: no params".into());
            }

            let mut otp_param = None;
            for i in 0..sig_info.ulCount {
                let param_ptr = sig_info.pParams.add(i as usize);
                let param: pkcs11::CK_OTP_PARAM =
                    std::ptr::read_unaligned(param_ptr);
                if param.type_ == pkcs11::CK_OTP_VALUE {
                    otp_param = Some(param);
                    break;
                }
            }
            let param = otp_param.ok_or(
                "Invalid OTP signature returned: CK_OTP_VALUE not found",
            )?;
            let p_value = param.pValue as *const u8;
            let ul_value_len = param.ulValueLen as usize;
            if p_value.is_null() || ul_value_len == 0 {
                return Err(
                    "Invalid OTP signature returned: empty value".into()
                );
            }
            let otp_slice = std::slice::from_raw_parts(p_value, ul_value_len);
            let otp_str = std::str::from_utf8(otp_slice)
                .map_err(|e| format!("OTP returned is not valid UTF-8: {}", e))?
                .to_string();

            Ok(otp_str)
        }
    }
}
