// Copyright 2025 Simo Sorce
// See LICENSE.txt file for terms

use super::Error;
use kryoptic_lib::pkcs11;
use libc;
use std::ffi::{c_void, CStr, CString};

pub fn dl_error() -> String {
    let cstr = unsafe { libc::dlerror() };
    if cstr.is_null() {
        String::from("<none>")
    } else {
        unsafe {
            String::from_utf8_lossy(CStr::from_ptr(cstr).to_bytes()).to_string()
        }
    }
}

pub struct FuncList {
    fntable: *mut pkcs11::CK_FUNCTION_LIST,
}

impl FuncList {
    pub fn from_symbol_name(
        handle: *mut c_void,
        name: &str,
    ) -> Result<FuncList, String> {
        let fname = CString::new(name).unwrap();
        let list_fn: pkcs11::CK_C_GetFunctionList = unsafe {
            let ptr = libc::dlsym(handle, fname.as_ptr());
            if ptr.is_null() {
                None
            } else {
                Some(std::mem::transmute::<
                    *mut c_void,
                    unsafe extern "C" fn(
                        *mut *mut pkcs11::CK_FUNCTION_LIST,
                    ) -> pkcs11::CK_RV,
                >(ptr))
            }
        };
        let mut fn_list: *mut pkcs11::CK_FUNCTION_LIST = std::ptr::null_mut();
        let rv = match list_fn {
            None => {
                return Err(dl_error().to_string());
            }
            Some(func) => unsafe { func(&mut fn_list) },
        };
        if rv != pkcs11::CKR_OK {
            return Err(format!("Failed to load pkcs11 function list: {}", rv));
        }
        Ok(FuncList { fntable: fn_list })
    }

    pub fn initialize(&self, initargs: Option<&CStr>) -> Result<(), Error> {
        unsafe {
            match (*self.fntable).C_Initialize {
                None => {
                    return Err(
                        "Broken pkcs11 module, no C_Initialize function".into(),
                    );
                }
                Some(func) => {
                    let p_reserved = if let Some(ia) = initargs {
                        ia.as_ptr() as pkcs11::CK_VOID_PTR
                    } else {
                        std::ptr::null_mut()
                    };

                    let mut targs = pkcs11::CK_C_INITIALIZE_ARGS {
                        CreateMutex: None,
                        DestroyMutex: None,
                        LockMutex: None,
                        UnlockMutex: None,
                        flags: pkcs11::CKF_OS_LOCKING_OK,
                        pReserved: p_reserved,
                    };
                    let targs_ptr =
                        &mut targs as *mut pkcs11::CK_C_INITIALIZE_ARGS;
                    let rv = func(targs_ptr as *mut c_void);
                    if rv != pkcs11::CKR_OK {
                        return Err(format!(
                            "Pkcs11 Token Initialization failed: {}",
                            rv
                        )
                        .into());
                    }
                    Ok(())
                }
            }
        }
    }

    pub fn get_info(&self) -> Result<pkcs11::CK_INFO, Error> {
        unsafe {
            match (*self.fntable).C_GetInfo {
                None => {
                    Err("Broken pkcs11 module, no C_GetInfo function".into())
                }
                Some(func) => {
                    let mut info: pkcs11::CK_INFO = std::mem::zeroed();
                    let rv = func(&mut info);
                    if rv != pkcs11::CKR_OK {
                        Err(format!("C_GetInfo failed: {}", rv).into())
                    } else {
                        Ok(info)
                    }
                }
            }
        }
    }

    pub fn get_slot_list(
        &self,
        token_present: pkcs11::CK_BBOOL,
        slots: Option<&mut [pkcs11::CK_SLOT_ID]>,
    ) -> Result<pkcs11::CK_ULONG, Error> {
        unsafe {
            match (*self.fntable).C_GetSlotList {
                None => {
                    Err("Broken pkcs11 module, no C_GetSlotList function"
                        .into())
                }
                Some(func) => {
                    let (ptr, mut count) = match slots {
                        Some(s) => {
                            (s.as_mut_ptr(), s.len() as pkcs11::CK_ULONG)
                        }
                        None => (std::ptr::null_mut(), 0),
                    };

                    let rv = func(token_present, ptr, &mut count);
                    if rv != pkcs11::CKR_OK {
                        Err(format!("C_GetSlotList (get list) failed: {}", rv)
                            .into())
                    } else {
                        Ok(count)
                    }
                }
            }
        }
    }

    pub fn get_slot_info(
        &self,
        slot_id: pkcs11::CK_SLOT_ID,
    ) -> Result<pkcs11::CK_SLOT_INFO, Error> {
        unsafe {
            match (*self.fntable).C_GetSlotInfo {
                None => {
                    Err("Broken pkcs11 module, no C_GetSlotInfo function"
                        .into())
                }
                Some(func) => {
                    let mut info: pkcs11::CK_SLOT_INFO = std::mem::zeroed();
                    let rv = func(slot_id, &mut info);
                    if rv != pkcs11::CKR_OK {
                        Err(format!("C_GetSlotInfo failed: {}", rv).into())
                    } else {
                        Ok(info)
                    }
                }
            }
        }
    }

    pub fn get_token_info(
        &self,
        slot_id: pkcs11::CK_SLOT_ID,
    ) -> Result<pkcs11::CK_TOKEN_INFO, Error> {
        unsafe {
            match (*self.fntable).C_GetTokenInfo {
                None => {
                    Err("Broken pkcs11 module, no C_GetTokenInfo function"
                        .into())
                }
                Some(func) => {
                    let mut info: pkcs11::CK_TOKEN_INFO = std::mem::zeroed();
                    let rv = func(slot_id, &mut info);
                    if rv != pkcs11::CKR_OK {
                        Err(format!("C_GetTokenInfo failed: {}", rv).into())
                    } else {
                        Ok(info)
                    }
                }
            }
        }
    }

    pub fn get_mechanism_list(
        &self,
        slot_id: pkcs11::CK_SLOT_ID,
        mechanisms: Option<&mut [pkcs11::CK_MECHANISM_TYPE]>,
    ) -> Result<pkcs11::CK_ULONG, Error> {
        unsafe {
            match (*self.fntable).C_GetMechanismList {
                None => {
                    Err("Broken pkcs11 module, no C_GetMechanismList function"
                        .into())
                }
                Some(func) => {
                    let (ptr, mut count) = match mechanisms {
                        Some(m) => {
                            (m.as_mut_ptr(), m.len() as pkcs11::CK_ULONG)
                        }
                        None => (std::ptr::null_mut(), 0),
                    };

                    let rv = func(slot_id, ptr, &mut count);
                    if rv != pkcs11::CKR_OK {
                        Err(format!("C_GetMechanismList failed: {}", rv).into())
                    } else {
                        Ok(count)
                    }
                }
            }
        }
    }

    pub fn get_mechanism_info(
        &self,
        slot_id: pkcs11::CK_SLOT_ID,
        mech_type: pkcs11::CK_MECHANISM_TYPE,
    ) -> Result<pkcs11::CK_MECHANISM_INFO, Error> {
        unsafe {
            match (*self.fntable).C_GetMechanismInfo {
                None => {
                    Err("Broken pkcs11 module, no C_GetMechanismInfo function"
                        .into())
                }
                Some(func) => {
                    let mut info: pkcs11::CK_MECHANISM_INFO =
                        std::mem::zeroed();
                    let rv = func(slot_id, mech_type, &mut info);
                    if rv != pkcs11::CKR_OK {
                        Err(format!("C_GetMechanismInfo failed: {}", rv).into())
                    } else {
                        Ok(info)
                    }
                }
            }
        }
    }

    pub fn open_session(
        &self,
        slot_id: pkcs11::CK_SLOT_ID,
        flags: pkcs11::CK_FLAGS,
    ) -> Result<pkcs11::CK_SESSION_HANDLE, Error> {
        unsafe {
            match (*self.fntable).C_OpenSession {
                None => {
                    Err("Broken pkcs11 module, no C_OpenSession function"
                        .into())
                }
                Some(func) => {
                    let mut session_handle: pkcs11::CK_SESSION_HANDLE =
                        pkcs11::CK_INVALID_HANDLE;
                    let rv = func(
                        slot_id,
                        flags,
                        std::ptr::null_mut(), // pApplication
                        None,                 // Notify
                        &mut session_handle,
                    );
                    if rv != pkcs11::CKR_OK {
                        Err(format!("C_OpenSession failed: {}", rv).into())
                    } else {
                        Ok(session_handle)
                    }
                }
            }
        }
    }

    pub fn find_objects_init(
        &self,
        session: pkcs11::CK_SESSION_HANDLE,
        template: &[pkcs11::CK_ATTRIBUTE],
    ) -> Result<(), Error> {
        unsafe {
            match (*self.fntable).C_FindObjectsInit {
                None => {
                    Err("Broken pkcs11 module, no C_FindObjectsInit function"
                        .into())
                }
                Some(func) => {
                    let rv = func(
                        session,
                        template.as_ptr() as *mut pkcs11::CK_ATTRIBUTE,
                        template.len() as pkcs11::CK_ULONG,
                    );
                    if rv != pkcs11::CKR_OK {
                        Err(format!("C_FindObjectsInit failed: {}", rv).into())
                    } else {
                        Ok(())
                    }
                }
            }
        }
    }

    pub fn find_objects(
        &self,
        session: pkcs11::CK_SESSION_HANDLE,
        max_count: pkcs11::CK_ULONG,
    ) -> Result<Vec<pkcs11::CK_OBJECT_HANDLE>, Error> {
        unsafe {
            match (*self.fntable).C_FindObjects {
                None => {
                    Err("Broken pkcs11 module, no C_FindObjects function"
                        .into())
                }
                Some(func) => {
                    let mut objects = vec![0; max_count as usize];
                    let mut count = 0;
                    let rv = func(
                        session,
                        objects.as_mut_ptr(),
                        max_count,
                        &mut count,
                    );
                    if rv != pkcs11::CKR_OK {
                        Err(format!("C_FindObjects failed: {}", rv).into())
                    } else {
                        objects.truncate(count as usize);
                        Ok(objects)
                    }
                }
            }
        }
    }

    pub fn find_objects_final(
        &self,
        session: pkcs11::CK_SESSION_HANDLE,
    ) -> Result<(), Error> {
        unsafe {
            match (*self.fntable).C_FindObjectsFinal {
                None => {
                    Err("Broken pkcs11 module, no C_FindObjectsFinal function"
                        .into())
                }
                Some(func) => {
                    let rv = func(session);
                    if rv != pkcs11::CKR_OK {
                        Err(format!("C_FindObjectsFinal failed: {}", rv).into())
                    } else {
                        Ok(())
                    }
                }
            }
        }
    }

    pub fn finalize(&self) -> Result<(), Error> {
        unsafe {
            match (*self.fntable).C_Finalize {
                None => {
                    Err("Broken pkcs11 module, no C_Finalize function".into())
                }
                Some(func) => {
                    let rv = func(std::ptr::null_mut());
                    if rv != pkcs11::CKR_OK {
                        Err(format!("C_Finalize failed: {}", rv).into())
                    } else {
                        Ok(())
                    }
                }
            }
        }
    }

    pub fn init_token(
        &self,
        slot_id: pkcs11::CK_SLOT_ID,
        so_pin: &CStr,
        label: &str,
    ) -> Result<(), Error> {
        let mut label_padded = [b' '; 32];
        let label_bytes = label.as_bytes();
        let len = std::cmp::min(label_bytes.len(), 32);
        label_padded[..len].copy_from_slice(&label_bytes[..len]);

        unsafe {
            match (*self.fntable).C_InitToken {
                None => {
                    Err("Broken pkcs11 module, no C_InitToken function".into())
                }
                Some(func) => {
                    let rv = func(
                        slot_id,
                        so_pin.as_ptr() as *mut u8,
                        so_pin.to_bytes().len() as pkcs11::CK_ULONG,
                        label_padded.as_mut_ptr(),
                    );
                    if rv != pkcs11::CKR_OK {
                        Err(format!("C_InitToken failed: {}", rv).into())
                    } else {
                        Ok(())
                    }
                }
            }
        }
    }

    pub fn login(
        &self,
        session: pkcs11::CK_SESSION_HANDLE,
        user_type: pkcs11::CK_USER_TYPE,
        pin: &CStr,
    ) -> Result<(), Error> {
        unsafe {
            match (*self.fntable).C_Login {
                None => Err("Broken pkcs11 module, no C_Login function".into()),
                Some(func) => {
                    let rv = func(
                        session,
                        user_type,
                        pin.as_ptr() as *mut u8,
                        pin.to_bytes().len() as pkcs11::CK_ULONG,
                    );
                    if rv != pkcs11::CKR_OK {
                        Err(format!("C_Login failed: {}", rv).into())
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
        pin: &CStr,
    ) -> Result<(), Error> {
        unsafe {
            match (*self.fntable).C_InitPIN {
                None => {
                    Err("Broken pkcs11 module, no C_InitPIN function".into())
                }
                Some(func) => {
                    let rv = func(
                        session,
                        pin.as_ptr() as *mut u8,
                        pin.to_bytes().len() as pkcs11::CK_ULONG,
                    );
                    if rv != pkcs11::CKR_OK {
                        Err(format!("C_InitPIN failed: {}", rv).into())
                    } else {
                        Ok(())
                    }
                }
            }
        }
    }

    pub fn logout(
        &self,
        session: pkcs11::CK_SESSION_HANDLE,
    ) -> Result<(), Error> {
        unsafe {
            match (*self.fntable).C_Logout {
                None => {
                    Err("Broken pkcs11 module, no C_Logout function".into())
                }
                Some(func) => {
                    let rv = func(session);
                    if rv != pkcs11::CKR_OK {
                        Err(format!("C_Logout failed: {}", rv).into())
                    } else {
                        Ok(())
                    }
                }
            }
        }
    }

    pub fn close_session(
        &self,
        session: pkcs11::CK_SESSION_HANDLE,
    ) -> Result<(), Error> {
        unsafe {
            match (*self.fntable).C_CloseSession {
                None => {
                    Err("Broken pkcs11 module, no C_CloseSession function"
                        .into())
                }
                Some(func) => {
                    let rv = func(session);
                    if rv != pkcs11::CKR_OK {
                        Err(format!("C_CloseSession failed: {}", rv).into())
                    } else {
                        Ok(())
                    }
                }
            }
        }
    }

    pub fn close_all_sessions(
        &self,
        slot_id: pkcs11::CK_SLOT_ID,
    ) -> Result<(), Error> {
        unsafe {
            match (*self.fntable).C_CloseAllSessions {
                None => {
                    Err("Broken pkcs11 module, no C_CloseAllSessions function"
                        .into())
                }
                Some(func) => {
                    let rv = func(slot_id);
                    if rv != pkcs11::CKR_OK {
                        Err(format!("C_CloseAllSessions failed: {}", rv).into())
                    } else {
                        Ok(())
                    }
                }
            }
        }
    }
}
