// Copyright 2025 Simo Sorce
// See LICENSE.txt file for terms

use super::pkcs11_wrapper::{dl_error, FuncList};
use super::Arguments;
use kryoptic_lib::pkcs11;
use libc;
use std::ffi::CString;

pub fn init_token(args: &Arguments) -> Result<(), Box<dyn std::error::Error>> {
    let module_path = args
        .pkcs11_module
        .as_deref()
        .ok_or("--pkcs11-module is required with --init")?;
    let so_pin_str = args
        .so_pin
        .as_deref()
        .ok_or("--so-pin is required with --init")?;
    let pin_str = args
        .pkcs11_pin
        .as_deref()
        .ok_or("--pkcs11-pin is required with --init")?;
    let token_label = args
        .token_label
        .as_deref()
        .ok_or("--token-label is required with --init")?;

    println!("Loading PKCS#11 module: {}", module_path);
    let soname = CString::new(module_path)?;
    let rtld_flags = libc::RTLD_LOCAL | libc::RTLD_NOW;
    let lib_handle =
        unsafe { libc::dlopen(soname.as_c_str().as_ptr(), rtld_flags) };
    if lib_handle.is_null() {
        return Err(
            format!("Failed to load pkcs11 module: {}", dl_error()).into()
        );
    }

    let pkcs11 =
        match FuncList::from_symbol_name(lib_handle, "C_GetFunctionList") {
            Ok(p) => p,
            Err(e) => {
                unsafe {
                    libc::dlclose(lib_handle);
                }
                return Err(
                    format!("Failed to get function list: {}", e).into()
                );
            }
        };

    let res = (|| {
        let initargs_cstring;
        let initargs = if let Some(ia) = args.pkcs11_initargs.as_deref() {
            initargs_cstring = CString::new(ia)?;
            Some(initargs_cstring.as_c_str())
        } else {
            None
        };
        pkcs11.initialize(initargs)?;
        println!("PKCS#11 library initialized.");

        let slot_id = if let Some(sid) = args.pkcs11_slot {
            sid
        } else {
            println!("No slot specified, finding first slot with a token...");
            let num_slots = pkcs11.get_slot_list(pkcs11::CK_TRUE, None)?;
            if num_slots == 0 {
                return Err("No slots with tokens found".into());
            }
            let mut slots = vec![0; num_slots as usize];
            let count =
                pkcs11.get_slot_list(pkcs11::CK_TRUE, Some(&mut slots))?;
            slots.truncate(count as usize);
            if slots.is_empty() {
                return Err("No slots with tokens found".into());
            }
            println!(
                "Found {} slots with tokens. Using first one: {}",
                slots.len(),
                slots[0]
            );
            slots[0]
        };

        println!("Initializing token in slot {}", slot_id);

        let so_pin = CString::new(so_pin_str)?;
        pkcs11.init_token(slot_id, &so_pin, token_label)?;
        println!("Token initialized with label '{}'.", token_label);

        let session = pkcs11.open_session(
            slot_id,
            pkcs11::CKF_RW_SESSION | pkcs11::CKF_SERIAL_SESSION,
        )?;
        println!("R/W session opened on slot {}.", slot_id);

        let session_ops_result: Result<(), Box<dyn std::error::Error>> =
            (|| {
                pkcs11.login(session, pkcs11::CKU_SO, &so_pin)?;
                println!("Logged in as Security Officer (SO).");

                let pin = CString::new(pin_str)?;
                pkcs11.init_pin(session, &pin)?;
                println!("User PIN initialized.");

                println!("Logging out.");
                pkcs11.logout(session)?;
                Ok(())
            })();

        println!("Closing session.");
        let _ = pkcs11.close_session(session);

        session_ops_result?;

        println!("Token initialization successful.");
        Ok(())
    })();

    println!("Finalizing PKCS#11 library.");
    let _ = pkcs11.finalize();

    unsafe {
        libc::dlclose(lib_handle);
    }
    res
}
