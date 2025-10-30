// Copyright 2025 Simo Sorce
// See LICENSE.txt file for terms

use super::pkcs11_wrapper::{dl_error, FuncList};
use super::{Arguments, Profile};
use kryoptic_lib::pkcs11;
use libc;
use std::ffi::CString;

fn generate_key(
    pkcs11: &FuncList,
    session: pkcs11::CK_SESSION_HANDLE,
    key_type: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    match key_type.to_uppercase().as_str() {
        "RSA" => {
            let mut mechanism = pkcs11::CK_MECHANISM {
                mechanism: pkcs11::CKM_RSA_PKCS_KEY_PAIR_GEN,
                pParameter: std::ptr::null_mut(),
                ulParameterLen: 0,
            };

            let ck_true = pkcs11::CK_TRUE;
            let modulus_bits: pkcs11::CK_ULONG = 2048;
            let public_exponent: [u8; 3] = [0x01, 0x00, 0x01]; // 65537
            let pub_label = "testrsa-pub";
            let pri_label = "testrsa-pri";

            let public_key_template = [
                pkcs11::CK_ATTRIBUTE {
                    type_: pkcs11::CKA_ENCRYPT,
                    pValue: &ck_true as *const _ as pkcs11::CK_VOID_PTR,
                    ulValueLen: std::mem::size_of_val(&ck_true)
                        as pkcs11::CK_ULONG,
                },
                pkcs11::CK_ATTRIBUTE {
                    type_: pkcs11::CKA_VERIFY,
                    pValue: &ck_true as *const _ as pkcs11::CK_VOID_PTR,
                    ulValueLen: std::mem::size_of_val(&ck_true)
                        as pkcs11::CK_ULONG,
                },
                pkcs11::CK_ATTRIBUTE {
                    type_: pkcs11::CKA_WRAP,
                    pValue: &ck_true as *const _ as pkcs11::CK_VOID_PTR,
                    ulValueLen: std::mem::size_of_val(&ck_true)
                        as pkcs11::CK_ULONG,
                },
                pkcs11::CK_ATTRIBUTE {
                    type_: pkcs11::CKA_MODULUS_BITS,
                    pValue: &modulus_bits as *const _ as pkcs11::CK_VOID_PTR,
                    ulValueLen: std::mem::size_of_val(&modulus_bits)
                        as pkcs11::CK_ULONG,
                },
                pkcs11::CK_ATTRIBUTE {
                    type_: pkcs11::CKA_PUBLIC_EXPONENT,
                    pValue: public_exponent.as_ptr() as pkcs11::CK_VOID_PTR,
                    ulValueLen: public_exponent.len() as pkcs11::CK_ULONG,
                },
                pkcs11::CK_ATTRIBUTE {
                    type_: pkcs11::CKA_TOKEN,
                    pValue: &ck_true as *const _ as pkcs11::CK_VOID_PTR,
                    ulValueLen: std::mem::size_of_val(&ck_true)
                        as pkcs11::CK_ULONG,
                },
                pkcs11::CK_ATTRIBUTE {
                    type_: pkcs11::CKA_LABEL,
                    pValue: pub_label.as_ptr() as pkcs11::CK_VOID_PTR,
                    ulValueLen: pub_label.len() as pkcs11::CK_ULONG,
                },
            ];

            let private_key_template = [
                pkcs11::CK_ATTRIBUTE {
                    type_: pkcs11::CKA_TOKEN,
                    pValue: &ck_true as *const _ as pkcs11::CK_VOID_PTR,
                    ulValueLen: std::mem::size_of_val(&ck_true)
                        as pkcs11::CK_ULONG,
                },
                pkcs11::CK_ATTRIBUTE {
                    type_: pkcs11::CKA_PRIVATE,
                    pValue: &ck_true as *const _ as pkcs11::CK_VOID_PTR,
                    ulValueLen: std::mem::size_of_val(&ck_true)
                        as pkcs11::CK_ULONG,
                },
                pkcs11::CK_ATTRIBUTE {
                    type_: pkcs11::CKA_SENSITIVE,
                    pValue: &ck_true as *const _ as pkcs11::CK_VOID_PTR,
                    ulValueLen: std::mem::size_of_val(&ck_true)
                        as pkcs11::CK_ULONG,
                },
                pkcs11::CK_ATTRIBUTE {
                    type_: pkcs11::CKA_DECRYPT,
                    pValue: &ck_true as *const _ as pkcs11::CK_VOID_PTR,
                    ulValueLen: std::mem::size_of_val(&ck_true)
                        as pkcs11::CK_ULONG,
                },
                pkcs11::CK_ATTRIBUTE {
                    type_: pkcs11::CKA_SIGN,
                    pValue: &ck_true as *const _ as pkcs11::CK_VOID_PTR,
                    ulValueLen: std::mem::size_of_val(&ck_true)
                        as pkcs11::CK_ULONG,
                },
                pkcs11::CK_ATTRIBUTE {
                    type_: pkcs11::CKA_UNWRAP,
                    pValue: &ck_true as *const _ as pkcs11::CK_VOID_PTR,
                    ulValueLen: std::mem::size_of_val(&ck_true)
                        as pkcs11::CK_ULONG,
                },
                pkcs11::CK_ATTRIBUTE {
                    type_: pkcs11::CKA_LABEL,
                    pValue: pri_label.as_ptr() as pkcs11::CK_VOID_PTR,
                    ulValueLen: pri_label.len() as pkcs11::CK_ULONG,
                },
            ];

            let (pub_key, priv_key) = pkcs11.generate_key_pair(
                session,
                &mut mechanism,
                &public_key_template,
                &private_key_template,
            )?;
            println!(
                "Generated RSA key pair. Public key handle: {}, Private key handle: {}",
                pub_key,
                priv_key
            );
        }
        _ => {
            return Err(format!("Unsupported key type: {}", key_type).into());
        }
    }
    Ok(())
}

pub fn check_profile(
    pkcs11: &FuncList,
    args: &Arguments,
) -> Result<(), Box<dyn std::error::Error>> {
    let profile_to_check = match &args.profile {
        Some(p) => p,
        None => return Ok(()),
    };

    if args.debug {
        eprintln!("Checking for profile: {:?}", profile_to_check);
    }

    let profile_id_val: pkcs11::CK_PROFILE_ID = match profile_to_check {
        Profile::Baseline => pkcs11::CKP_BASELINE_PROVIDER,
        Profile::Extended => pkcs11::CKP_EXTENDED_PROVIDER,
        Profile::Authentication => pkcs11::CKP_AUTHENTICATION_TOKEN,
        Profile::Complete => pkcs11::CKP_COMPLETE_PROVIDER,
        Profile::PublicCerts => pkcs11::CKP_PUBLIC_CERTIFICATES_TOKEN,
        Profile::HkdfTls => pkcs11::CKP_HKDF_TLS_TOKEN,
    };

    let slot_count = pkcs11.get_slot_list(pkcs11::CK_TRUE, None)?;
    if slot_count == 0 {
        return Err(format!(
            "No token present, cannot check for profile '{:?}'",
            profile_to_check
        )
        .into());
    }
    let mut slot_ids = vec![0; slot_count as usize];
    pkcs11.get_slot_list(pkcs11::CK_TRUE, Some(&mut slot_ids))?;

    let slot_id = slot_ids[0];
    if args.debug {
        eprintln!("Using slot {} to check for profile.", slot_id);
    }

    let session = pkcs11.open_session(slot_id, pkcs11::CKF_SERIAL_SESSION)?;

    let cko_profile_class: pkcs11::CK_OBJECT_CLASS = pkcs11::CKO_PROFILE;

    let template = [
        pkcs11::CK_ATTRIBUTE {
            type_: pkcs11::CKA_CLASS,
            pValue: &cko_profile_class as *const _ as pkcs11::CK_VOID_PTR,
            ulValueLen: std::mem::size_of_val(&cko_profile_class)
                as pkcs11::CK_ULONG,
        },
        pkcs11::CK_ATTRIBUTE {
            type_: pkcs11::CKA_PROFILE_ID,
            pValue: &profile_id_val as *const _ as pkcs11::CK_VOID_PTR,
            ulValueLen: std::mem::size_of_val(&profile_id_val)
                as pkcs11::CK_ULONG,
        },
    ];

    pkcs11.find_objects_init(session, &template)?;
    let objects = pkcs11.find_objects(session, 1)?;
    pkcs11.find_objects_final(session)?;
    pkcs11.close_session(session)?;

    if objects.is_empty() {
        return Err(format!(
            "Profile object for '{:?}' not found on token.",
            profile_to_check
        )
        .into());
    }
    if args.debug {
        eprintln!(
            "Info: Found profile object for '{:?}' on token.",
            profile_to_check
        );
    }

    Ok(())
}

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

                if let Some(key_type) = &args.genkey {
                    println!("Logging out as SO.");
                    pkcs11.logout(session)?;

                    println!("Logging in as user for key generation.");
                    pkcs11.login(session, pkcs11::CKU_USER, &pin)?;

                    println!("Generating {} key...", key_type);
                    generate_key(&pkcs11, session, key_type)?;

                    println!("Logging out as user.");
                    pkcs11.logout(session)?;
                } else {
                    println!("Logging out.");
                    pkcs11.logout(session)?;
                }

                Ok(())
            })();

        println!("Closing session.");
        let _ = pkcs11.close_session(session);

        session_ops_result?;

        check_profile(&pkcs11, args)?;

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
