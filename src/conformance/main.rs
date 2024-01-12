// Copyright 2024 Simo Sorce
// See LICENSE.txt file for terms

use libc;
use std::env;
use std::ffi::{c_void, CStr, CString};
use std::path::PathBuf;

mod interface {
    #![allow(non_upper_case_globals)]
    #![allow(non_camel_case_types)]
    #![allow(non_snake_case)]
    #![allow(dead_code)]
    include!("../pkcs11/interface.rs");
}

use interface::{
    CK_C_GetFunctionList, CKR_OK, CK_C_INITIALIZE_ARGS, CK_FUNCTION_LIST,
};

fn dl_error() -> String {
    let cstr = unsafe { libc::dlerror() };
    if cstr.is_null() {
        String::from("<none>")
    } else {
        unsafe {
            String::from_utf8_lossy(CStr::from_ptr(cstr).to_bytes()).to_string()
        }
    }
}

struct FuncList {
    fntable: *mut CK_FUNCTION_LIST,
}

impl FuncList {
    fn from_symbol_name(
        handle: *mut c_void,
        name: &str,
    ) -> Result<FuncList, String> {
        let fname = CString::new(name).unwrap();
        let list_fn: CK_C_GetFunctionList = unsafe {
            let ptr = libc::dlsym(handle, fname.as_ptr());
            if ptr.is_null() {
                None
            } else {
                Some(std::mem::transmute::<
                    *mut c_void,
                    unsafe extern "C" fn(*mut *mut CK_FUNCTION_LIST) -> u64,
                >(ptr))
            }
        };
        let mut fn_list: *mut CK_FUNCTION_LIST = std::ptr::null_mut();
        let rv = match list_fn {
            None => {
                return Err(dl_error().to_string());
            }
            Some(func) => unsafe { func(&mut fn_list) },
        };
        if rv != CKR_OK {
            return Err(format!("Failed to load pkcs11 function list: {}", rv));
        }
        Ok(FuncList { fntable: fn_list })
    }

    fn initialize(&self) -> Result<(), String> {
        unsafe {
            match (*self.fntable).C_Initialize {
                None => {
                    return Err(format!(
                        "Broken pkcs11 token, non Initialize function in list"
                    ))
                }
                Some(func) => {
                    let mut targs = CK_C_INITIALIZE_ARGS {
                        CreateMutex: None,
                        DestroyMutex: None,
                        LockMutex: None,
                        UnlockMutex: None,
                        flags: 0,
                        pReserved: std::ptr::null_mut(),
                    };
                    let targs_ptr = &mut targs as *mut CK_C_INITIALIZE_ARGS;
                    let rv = func(targs_ptr as *mut c_void);
                    if rv != CKR_OK {
                        return Err(format!(
                            "Pkcs11 Token Initialization failed: {}",
                            rv
                        ));
                    }
                    Ok(())
                }
            }
        }
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() != 2 {
        println!("usage: {} <path/to/pkcs11/module.so>", args[0]);
        std::process::exit(1);
    }

    /* Let's try to load the library */
    let rtld_flags = libc::RTLD_LOCAL | libc::RTLD_NOW;
    let filename = PathBuf::from(&args[1])
        .canonicalize()
        .expect("Couldn't resolve path for pkcs11 module")
        .into_os_string();
    let lib_handle = unsafe {
        libc::dlopen(
            filename.as_encoded_bytes().as_ptr() as *const i8,
            rtld_flags,
        )
    };
    if lib_handle.is_null() {
        println!("Failed to load pkcs11 module: {}", dl_error());
        std::process::exit(1);
    }

    /* Get entrypoint */
    /* FIXME: support using Get_Interface and falling back to 2.40 C_GetFunctionList */
    let function_list =
        match FuncList::from_symbol_name(lib_handle, "C_GetFunctionList") {
            Ok(x) => x,
            Err(e) => {
                println!("{}", e);
                std::process::exit(1);
            }
        };

    /* initialize the token */
    match function_list.initialize() {
        Ok(()) => (),
        Err(e) => {
            println!("{}", e);
            std::process::exit(1);
        }
    }

    /* loaded and initialized, time to start testing */

    test1(&function_list);
}

fn test1(_f: &FuncList) {
    /* TODO */
}
