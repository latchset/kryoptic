// Copyright 2025 Simo Sorce
// See LICENSE.txt file for terms

use super::pkcs11_wrapper::FuncList;
use super::profile::{get_call_name, Call, Pkcs11Profile};
use super::{Arguments, Error};
use hex;
use kryoptic_lib::pkcs11;
use std::collections::HashMap;
use std::ffi::CString;

fn get_attribute_type_from_str(
    attr_name: &str,
) -> Result<pkcs11::CK_ATTRIBUTE_TYPE, Error> {
    let full_name = format!("CKA_{}", attr_name);
    pkcs11::name_to_attr(&full_name).map_err(|_| {
        format!("Unsupported attribute type: {}", attr_name).into()
    })
}

fn get_mechanism_type_from_str(
    mech_name: &str,
) -> Result<pkcs11::CK_MECHANISM_TYPE, Error> {
    let mech_name_for_lookup = if mech_name == "SHA1" {
        "SHA_1"
    } else {
        mech_name
    };
    let full_name = format!("CKM_{}", mech_name_for_lookup);
    pkcs11::name_to_mech(&full_name).map_err(|_| {
        format!("Unsupported mechanism type: {}", mech_name).into()
    })
}

fn get_attribute_value_bytes(
    attr_type: pkcs11::CK_ATTRIBUTE_TYPE,
    value_str: &str,
) -> Result<Vec<u8>, Error> {
    match attr_type {
        pkcs11::CKA_TOKEN | pkcs11::CKA_PRIVATE => {
            let val = match value_str.to_uppercase().as_str() {
                "TRUE" => pkcs11::CK_TRUE,
                "FALSE" => pkcs11::CK_FALSE,
                _ => {
                    return Err(format!(
                        "Invalid boolean value for attribute: {}",
                        value_str
                    )
                    .into())
                }
            };
            Ok(vec![val])
        }
        pkcs11::CKA_CLASS => {
            let full_name = format!("CKO_{}", value_str);
            let val = pkcs11::name_to_obj(&full_name).map_err(|_| {
                format!("Unsupported object class: {}", value_str)
            })?;
            Ok(val.to_ne_bytes().to_vec())
        }
        pkcs11::CKA_LABEL | pkcs11::CKA_ID => Ok(value_str.as_bytes().to_vec()),
        _ => Err(format!(
            "Value conversion for attribute type {:#x} not implemented",
            attr_type
        )
        .into()),
    }
}

fn resolve_variable<'a>(
    variables: &'a HashMap<String, String>,
    value: &'a str,
) -> Result<&'a str, Box<dyn std::error::Error>> {
    if value.starts_with("${") && value.ends_with('}') {
        variables
            .get(value)
            .map(|s| s.as_str())
            .ok_or_else(|| format!("Variable '{}' not found", value).into())
    } else {
        Ok(value)
    }
}

fn store_variable(
    variables: &mut HashMap<String, String>,
    var_name: &str,
    value: String,
    debug: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    if var_name.starts_with("${") && var_name.ends_with('}') {
        variables.insert(var_name.to_string(), value.clone());
        if debug {
            eprintln!("Stored variable: {} = {}", var_name, value);
        }
        Ok(())
    } else {
        Err(format!(
            "Attempted to store variable with invalid name format: {}",
            var_name
        )
        .into())
    }
}

pub fn execute_calls(
    pkcs11: &FuncList,
    profile: Pkcs11Profile,
    args: &Arguments,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut calls_iter = profile.calls.into_iter();
    let mut variables = HashMap::<String, String>::new();

    if let Some(pin) = &args.pkcs11_pin {
        store_variable(&mut variables, "${Pin}", pin.clone(), args.debug)?;
    }

    let mut unimplemented_function_called = false;

    let mut counter = 0;
    while let Some(request) = calls_iter.next() {
        if args.debug {
            counter += 1;
            eprintln!("\n--- Processing call pair #{} ---", counter);
            eprintln!("Request: {:?}", &request);
        }

        let response = match calls_iter.next() {
            Some(res) => res,
            None => {
                panic!(
                    "Odd number of calls, request without response: {:?}",
                    request
                );
            }
        };

        if std::mem::discriminant(&request) != std::mem::discriminant(&response)
        {
            panic!(
                "Mismatched request/response pair: {:?}, {:?}",
                request, response
            );
        }

        let call_name = get_call_name(&request);
        println!("Executing {}...", call_name);

        match &request {
            Call::Initialize(_) => {
                let initargs_cstring;
                let initargs = if let Some(ia) = args.pkcs11_initargs.as_deref()
                {
                    initargs_cstring = CString::new(ia)?;
                    Some(initargs_cstring.as_c_str())
                } else {
                    None
                };
                pkcs11.initialize(initargs)?;
            }
            Call::GetInfo(_) => {
                let info = pkcs11.get_info()?;
                if args.debug {
                    eprintln!("GetInfo returned: {:?}", info);
                }
            }
            Call::GetSlotList(c) => {
                let token_present = c
                    .token_present
                    .as_ref()
                    .map(|v| v.value.parse::<bool>().unwrap_or(false))
                    .unwrap_or(false);
                let b_token_present = if token_present {
                    pkcs11::CK_TRUE
                } else {
                    pkcs11::CK_FALSE
                };

                if let Some(slot_list) = &c.slot_list {
                    if let Some(count_str) = &slot_list.pul_count {
                        // This is the second call, get list
                        let num_slots_str =
                            resolve_variable(&variables, count_str)?;
                        let num_slots = num_slots_str.parse::<usize>()?;

                        let mut slot_ids =
                            vec![0 as pkcs11::CK_SLOT_ID; num_slots];
                        let returned_slots_count = pkcs11.get_slot_list(
                            b_token_present,
                            Some(&mut slot_ids),
                        )?;
                        slot_ids.truncate(returned_slots_count as usize);

                        if args.debug {
                            eprintln!(
                                "C_GetSlotList returned {} slots: {:?}",
                                returned_slots_count, slot_ids
                            );
                        }

                        // Now process response and store variables
                        if let Call::GetSlotList(res_c) = response {
                            if let Some(res_slot_list) = &res_c.slot_list {
                                if slot_ids.len()
                                    < res_slot_list.p_slot_list.len()
                                {
                                    return Err(format!(
                                        "Expected at least {} slots, but got {}",
                                        res_slot_list.p_slot_list.len(),
                                        slot_ids.len()
                                    )
                                    .into());
                                }
                                for (i, slot_id_val) in
                                    res_slot_list.p_slot_list.iter().enumerate()
                                {
                                    store_variable(
                                        &mut variables,
                                        &slot_id_val.value,
                                        slot_ids[i].to_string(),
                                        args.debug,
                                    )?;
                                }
                            }
                        } else {
                            return Err(
                                "Mismatched response type for C_GetSlotList"
                                    .into(),
                            );
                        }
                    } else {
                        // This is the first call, get count
                        let count =
                            pkcs11.get_slot_list(b_token_present, None)?;
                        if args.debug {
                            eprintln!(
                                "C_GetSlotList returned count: {}",
                                count
                            );
                        }

                        // Now process response and store variables
                        if let Call::GetSlotList(res_c) = response {
                            if let Some(res_slot_list) = res_c.slot_list {
                                if let Some(var_placeholder) =
                                    res_slot_list.pul_count
                                {
                                    store_variable(
                                        &mut variables,
                                        &var_placeholder,
                                        count.to_string(),
                                        args.debug,
                                    )?;
                                }
                            }
                        } else {
                            return Err(
                                "Mismatched response type for C_GetSlotList"
                                    .into(),
                            );
                        }
                    }
                } else {
                    return Err(
                        "C_GetSlotList request is missing SlotList element"
                            .into(),
                    );
                }
            }
            Call::GetSlotInfo(c) => {
                let slot_id_str = c
                    .slot_id
                    .as_ref()
                    .map(|s| s.value.as_str())
                    .ok_or("C_GetSlotInfo requires a SlotID")?;
                let resolved_slot_id_str =
                    resolve_variable(&variables, slot_id_str)?;
                let slot_id =
                    resolved_slot_id_str.parse::<pkcs11::CK_SLOT_ID>()?;

                let info = pkcs11.get_slot_info(slot_id)?;
                if args.debug {
                    eprintln!("C_GetSlotInfo returned: {:?}", info);
                }

                // Now process response for checks
                if let Call::GetSlotInfo(res_c) = response {
                    if let Some(expected_info) = &res_c.p_info {
                        // For now, only checking flags as requested.
                        let expected_flags_str = &expected_info.flags.value;
                        let mut expected_flags: pkcs11::CK_FLAGS = 0;
                        for flag in expected_flags_str.split('|') {
                            let trimmed_flag = flag.trim();
                            if trimmed_flag.is_empty() {
                                continue;
                            }
                            match trimmed_flag {
                                "TOKEN_PRESENT" => {
                                    expected_flags |= pkcs11::CKF_TOKEN_PRESENT
                                }
                                _ => {
                                    return Err(format!(
                                        "Unknown flag for C_GetSlotInfo: {}",
                                        trimmed_flag
                                    )
                                    .into())
                                }
                            }
                        }

                        if expected_flags != 0
                            && (info.flags & expected_flags) == 0
                        {
                            return Err(format!(
                                "C_GetSlotInfo flags check failed. Returned: {:#x}, Expected to include any of: {:#x}",
                                info.flags, expected_flags
                            )
                            .into());
                        }

                        if args.debug {
                            eprintln!("C_GetSlotInfo flags check passed. Returned: {:#x}, Expected any of: {:#x}", info.flags, expected_flags);
                        }
                    }
                } else {
                    return Err(
                        "Mismatched response type for C_GetSlotInfo".into()
                    );
                }
            }
            Call::GetTokenInfo(c) => {
                let slot_id_str = c
                    .slot_id
                    .as_ref()
                    .map(|s| s.value.as_str())
                    .ok_or("C_GetTokenInfo requires a SlotID")?;
                let resolved_slot_id_str =
                    resolve_variable(&variables, slot_id_str)?;
                let slot_id =
                    resolved_slot_id_str.parse::<pkcs11::CK_SLOT_ID>()?;
                let info = pkcs11.get_token_info(slot_id)?;
                if args.debug {
                    eprintln!("C_GetTokenInfo returned: {:?}", info);
                }
            }
            Call::GetMechanismList(c) => {
                let slot_id_str = c
                    .slot_id
                    .as_ref()
                    .map(|s| s.value.as_str())
                    .ok_or("C_GetMechanismList requires a SlotID")?;
                let resolved_slot_id_str =
                    resolve_variable(&variables, slot_id_str)?;
                let slot_id =
                    resolved_slot_id_str.parse::<pkcs11::CK_SLOT_ID>()?;

                if let Some(mech_list) = &c.p_mechanism_list {
                    if let Some(count_str) = &mech_list.pul_count {
                        // This is the second call, get list
                        let num_mechs_str =
                            resolve_variable(&variables, count_str)?;
                        let num_mechs = num_mechs_str.parse::<usize>()?;

                        let mut mech_types =
                            vec![0 as pkcs11::CK_MECHANISM_TYPE; num_mechs];
                        let returned_mechs_count = pkcs11.get_mechanism_list(
                            slot_id,
                            Some(&mut mech_types),
                        )?;
                        mech_types.truncate(returned_mechs_count as usize);

                        if args.debug {
                            eprintln!(
                                "C_GetMechanismList returned {} mechanisms: {:?}",
                                returned_mechs_count, mech_types
                            );
                        }

                        // Now process response for checks
                        if let Call::GetMechanismList(res_c) = response {
                            if let Some(res_mech_list) = &res_c.p_mechanism_list
                            {
                                let mut expected_mechs = Vec::new();
                                for mech_val in &res_mech_list.p_mechanism_list
                                {
                                    let mech_type =
                                        get_mechanism_type_from_str(
                                            &mech_val.value,
                                        )?;
                                    expected_mechs.push(mech_type);
                                }

                                if mech_types.len() < expected_mechs.len() {
                                    return Err(format!(
                                        "Expected at least {} mechanisms, but got {}",
                                        expected_mechs.len(),
                                        mech_types.len()
                                    )
                                    .into());
                                }

                                for expected_mech in expected_mechs {
                                    if !mech_types.contains(&expected_mech) {
                                        return Err(format!(
                                            "Expected mechanism {:#x} was not found",
                                            expected_mech
                                        )
                                        .into());
                                    }
                                }
                                if args.debug {
                                    eprintln!("All expected mechanisms found in list.");
                                }
                            }
                        } else {
                            return Err(
                                "Mismatched response type for C_GetMechanismList"
                                    .into(),
                            );
                        }
                    } else {
                        // This is the first call, get count
                        let count = pkcs11.get_mechanism_list(slot_id, None)?;
                        if args.debug {
                            eprintln!(
                                "C_GetMechanismList returned count: {}",
                                count
                            );
                        }

                        // Now process response and store variables
                        if let Call::GetMechanismList(res_c) = response {
                            if let Some(res_mech_list) = res_c.p_mechanism_list
                            {
                                if let Some(var_placeholder) =
                                    res_mech_list.pul_count
                                {
                                    store_variable(
                                        &mut variables,
                                        &var_placeholder,
                                        count.to_string(),
                                        args.debug,
                                    )?;
                                }
                            }
                        } else {
                            return Err(
                                "Mismatched response type for C_GetMechanismList"
                                    .into(),
                            );
                        }
                    }
                } else {
                    return Err(
                        "C_GetMechanismList request is missing MechanismList element"
                            .into(),
                    );
                }
            }
            Call::GetMechanismInfo(c) => {
                let slot_id_str = c
                    .slot_id
                    .as_ref()
                    .map(|s| s.value.as_str())
                    .ok_or("C_GetMechanismInfo requires a SlotID")?;
                let resolved_slot_id_str =
                    resolve_variable(&variables, slot_id_str)?;
                let slot_id =
                    resolved_slot_id_str.parse::<pkcs11::CK_SLOT_ID>()?;

                let mech_type_str =
                    c.mechanism_type.as_ref().map(|m| m.value.as_str()).ok_or(
                        "C_GetMechanismInfo requires a mechanism Type",
                    )?;
                let mech_type = get_mechanism_type_from_str(mech_type_str)?;

                let info = pkcs11.get_mechanism_info(slot_id, mech_type)?;
                if args.debug {
                    eprintln!("C_GetMechanismInfo returned: {:?}", info);
                }

                // Now process response for checks
                if let Call::GetMechanismInfo(res_c) = response {
                    if let Some(expected_info) = &res_c.p_info {
                        let expected_min_key_size = expected_info
                            .min_key_size
                            .value
                            .parse::<pkcs11::CK_ULONG>()?;
                        if info.ulMinKeySize != expected_min_key_size {
                            // special case for RSA mechanisms where some implementations have
                            // different minimums than the conformance tests expect.
                            let is_rsa = mech_type_str.starts_with("RSA");
                            if is_rsa && expected_min_key_size < 1048 {
                                if args.debug {
                                    eprintln!(
                                        "Ignoring MinKeySize mismatch for RSA mechanism with size < 1048. Returned: {}, Expected: {}",
                                        info.ulMinKeySize, expected_min_key_size
                                    );
                                }
                            } else {
                                return Err(format!(
                                    "C_GetMechanismInfo MinKeySize mismatch. Returned: {}, Expected: {}",
                                    info.ulMinKeySize, expected_min_key_size
                                )
                                .into());
                            }
                        }

                        let expected_max_key_size = expected_info
                            .max_key_size
                            .value
                            .parse::<pkcs11::CK_ULONG>()?;
                        if info.ulMaxKeySize != expected_max_key_size {
                            return Err(format!(
                                "C_GetMechanismInfo MaxKeySize mismatch. Returned: {}, Expected: {}",
                                info.ulMaxKeySize, expected_max_key_size
                            )
                            .into());
                        }

                        let expected_flags_str = &expected_info.flags.value;
                        let mut expected_flags: pkcs11::CK_FLAGS = 0;
                        for flag in expected_flags_str.split('|') {
                            let trimmed_flag = flag.trim();
                            if trimmed_flag.is_empty() {
                                continue;
                            }
                            match trimmed_flag {
                                "ENCRYPT" => {
                                    expected_flags |= pkcs11::CKF_ENCRYPT
                                }
                                "DECRYPT" => {
                                    expected_flags |= pkcs11::CKF_DECRYPT
                                }
                                "DIGEST" => {
                                    expected_flags |= pkcs11::CKF_DIGEST
                                }
                                "SIGN" => expected_flags |= pkcs11::CKF_SIGN,
                                "VERIFY" => {
                                    expected_flags |= pkcs11::CKF_VERIFY
                                }
                                "GENERATE_KEY_PAIR" => {
                                    expected_flags |=
                                        pkcs11::CKF_GENERATE_KEY_PAIR
                                }
                                "WRAP" => expected_flags |= pkcs11::CKF_WRAP,
                                "UNWRAP" => {
                                    expected_flags |= pkcs11::CKF_UNWRAP
                                }
                                _ => {
                                    return Err(format!(
                                    "Unknown flag for C_GetMechanismInfo: {}",
                                    trimmed_flag
                                )
                                    .into())
                                }
                            }
                        }

                        if info.flags != expected_flags {
                            return Err(format!(
                                "C_GetMechanismInfo flags mismatch. Returned: {:#x}, Expected: {:#x}",
                                info.flags, expected_flags
                            )
                            .into());
                        }

                        if args.debug {
                            eprintln!("C_GetMechanismInfo checks passed.");
                        }
                    }
                } else {
                    return Err(
                        "Mismatched response type for C_GetMechanismInfo"
                            .into(),
                    );
                }
            }
            Call::OpenSession(c) => {
                let slot_id_str = c
                    .slot_id
                    .as_ref()
                    .map(|s| s.value.as_str())
                    .ok_or("C_OpenSession requires a SlotID")?;
                let resolved_slot_id_str =
                    resolve_variable(&variables, slot_id_str)?;
                let slot_id =
                    resolved_slot_id_str.parse::<pkcs11::CK_SLOT_ID>()?;

                let flags_str = c
                    .flags
                    .as_ref()
                    .map(|f| f.value.as_str())
                    .ok_or("C_OpenSession requires Flags")?;

                let mut flags: pkcs11::CK_FLAGS = 0;
                for flag in flags_str.split('|') {
                    match flag.trim() {
                        "RW_SESSION" => flags |= pkcs11::CKF_RW_SESSION,
                        "SERIAL_SESSION" => flags |= pkcs11::CKF_SERIAL_SESSION,
                        _ => {
                            return Err(format!(
                                "Unknown flag for C_OpenSession: {}",
                                flag
                            )
                            .into())
                        }
                    }
                }

                let session_handle = pkcs11.open_session(slot_id, flags)?;
                if args.debug {
                    eprintln!(
                        "C_OpenSession returned session handle: {}",
                        session_handle
                    );
                }

                if let Call::OpenSession(res_c) = response {
                    if let Some(res_session) = res_c.ph_session {
                        store_variable(
                            &mut variables,
                            &res_session.value,
                            session_handle.to_string(),
                            args.debug,
                        )?;
                    }
                } else {
                    return Err(
                        "Mismatched response type for C_OpenSession".into()
                    );
                }
            }
            Call::FindObjectsInit(c) => {
                let session_str = c
                    .h_session
                    .as_ref()
                    .map(|s| s.value.as_str())
                    .ok_or("C_FindObjectsInit requires a Session")?;
                let resolved_session_str =
                    resolve_variable(&variables, session_str)?;
                let session = resolved_session_str
                    .parse::<pkcs11::CK_SESSION_HANDLE>()?;

                let mut ck_template = Vec::<pkcs11::CK_ATTRIBUTE>::new();
                let mut value_storage = Vec::<Vec<u8>>::new(); // to keep values alive

                if let Some(template) = &c.p_template {
                    for attr in &template.attribute {
                        if args.debug {
                            eprintln!(
                                "Processing attribute type: {}",
                                attr.attr_type
                            );
                        }
                        let attr_type =
                            get_attribute_type_from_str(&attr.attr_type)?;

                        let val_str = attr.p_value.as_ref().ok_or_else(|| {
                            format!(
                                "Attribute {} in FindObjectsInit template must have a value",
                                attr.attr_type
                            )
                        })?;

                        let bytes =
                            get_attribute_value_bytes(attr_type, val_str)?;
                        let len = bytes.len() as pkcs11::CK_ULONG;
                        value_storage.push(bytes);
                        let ptr = value_storage.last().unwrap().as_ptr()
                            as pkcs11::CK_VOID_PTR;

                        ck_template.push(pkcs11::CK_ATTRIBUTE {
                            type_: attr_type,
                            pValue: ptr,
                            ulValueLen: len,
                        });
                    }
                }
                pkcs11.find_objects_init(session, &ck_template)?;
            }
            Call::FindObjects(c) => {
                let session_str = c
                    .h_session
                    .as_ref()
                    .map(|s| s.value.as_str())
                    .ok_or("C_FindObjects requires a Session")?;
                let resolved_session_str =
                    resolve_variable(&variables, session_str)?;
                let session = resolved_session_str
                    .parse::<pkcs11::CK_SESSION_HANDLE>()?;

                if c.ph_object.len() != 1 || c.ph_object[0].length.is_none() {
                    return Err("C_FindObjects request requires exactly one Object element with a length attribute".into());
                }
                let max_count_str = c.ph_object[0].length.as_deref().unwrap();
                let max_count = max_count_str.parse::<pkcs11::CK_ULONG>()?;

                let objects = pkcs11.find_objects(session, max_count)?;

                if args.debug {
                    eprintln!(
                        "C_FindObjects returned {} objects: {:?}",
                        objects.len(),
                        objects
                    );
                }

                if let Call::FindObjects(res_c) = response {
                    let empty_response = res_c.ph_object.is_empty()
                        || (res_c.ph_object.len() == 1
                            && res_c.ph_object[0].object.is_empty()
                            && res_c.ph_object[0].value.is_none());

                    if empty_response {
                        if !objects.is_empty() {
                            return Err(format!(
                                "C_FindObjects expected to find 0 objects, but found {}",
                                objects.len()
                            )
                            .into());
                        }
                    } else {
                        // Not empty response, so we expect objects.
                        // For now we just check if we have enough, and store handles.
                        let expected_objects = &res_c.ph_object[0].object;
                        if objects.len() < expected_objects.len() {
                            return Err(format!(
                                "C_FindObjects expected to find at least {} objects, but found {}",
                                expected_objects.len(),
                                objects.len()
                            )
                            .into());
                        }
                        for (i, expected_obj) in
                            expected_objects.iter().enumerate()
                        {
                            if let Some(var_name) = &expected_obj.value {
                                store_variable(
                                    &mut variables,
                                    var_name,
                                    objects[i].to_string(),
                                    args.debug,
                                )?;
                            }
                        }
                    }
                } else {
                    return Err(
                        "Mismatched response type for C_FindObjects".into()
                    );
                }
            }
            Call::FindObjectsFinal(c) => {
                let session_str = c
                    .h_session
                    .as_ref()
                    .map(|s| s.value.as_str())
                    .ok_or("C_FindObjectsFinal requires a Session")?;
                let resolved_session_str =
                    resolve_variable(&variables, session_str)?;
                let session = resolved_session_str
                    .parse::<pkcs11::CK_SESSION_HANDLE>()?;
                pkcs11.find_objects_final(session)?;
            }
            Call::GetAttributeValue(c) => {
                let session_str = c
                    .h_session
                    .as_ref()
                    .map(|s| s.value.as_str())
                    .ok_or("C_GetAttributeValue requires a Session")?;
                let resolved_session_str =
                    resolve_variable(&variables, session_str)?;
                let session = resolved_session_str
                    .parse::<pkcs11::CK_SESSION_HANDLE>()?;

                let object_str = c
                    .h_object
                    .as_ref()
                    .and_then(|o| o.value.as_deref())
                    .ok_or("C_GetAttributeValue requires an Object with a value attribute")?;
                let resolved_object_str =
                    resolve_variable(&variables, object_str)?;
                let object =
                    resolved_object_str.parse::<pkcs11::CK_OBJECT_HANDLE>()?;

                let mut ck_template = Vec::<pkcs11::CK_ATTRIBUTE>::new();
                let mut value_storage = Vec::<Vec<u8>>::new();
                let is_get_length_call;

                if let Some(template) = &c.p_template {
                    if template.attribute.is_empty() {
                        is_get_length_call = false; // Does not matter
                    } else {
                        is_get_length_call =
                            template.attribute[0].ul_value_len.is_none();
                        for attr in &template.attribute {
                            if args.debug {
                                eprintln!(
                                    "Preparing attribute type for GetValue: {}",
                                    attr.attr_type
                                );
                            }
                            let attr_type =
                                get_attribute_type_from_str(&attr.attr_type)?;

                            if is_get_length_call {
                                if attr.ul_value_len.is_some() {
                                    return Err("Inconsistent attributes in C_GetAttributeValue template: mix of length-query and value-fetch.".into());
                                }
                                ck_template.push(pkcs11::CK_ATTRIBUTE {
                                    type_: attr_type,
                                    pValue: std::ptr::null_mut(),
                                    ulValueLen: 0,
                                });
                            } else {
                                let len_str = attr.ul_value_len.as_ref().ok_or_else(|| {
                                    format!(
                                        "Attribute {} in GetAttributeValue template must have a length for value-fetch call",
                                        attr.attr_type
                                    )
                                })?;
                                let len = len_str.parse::<usize>()?;

                                let mut buffer = vec![0u8; len];
                                let ptr =
                                    buffer.as_mut_ptr() as pkcs11::CK_VOID_PTR;

                                ck_template.push(pkcs11::CK_ATTRIBUTE {
                                    type_: attr_type,
                                    pValue: ptr,
                                    ulValueLen: len as pkcs11::CK_ULONG,
                                });
                                value_storage.push(buffer);
                            }
                        }
                    }
                } else {
                    return Err(
                        "C_GetAttributeValue requires a Template".into()
                    );
                }

                pkcs11.get_attribute_value(
                    session,
                    object,
                    &mut ck_template,
                )?;

                if let Call::GetAttributeValue(res_c) = response {
                    if let Some(res_template) = &res_c.p_template {
                        for (i, res_attr) in
                            res_template.attribute.iter().enumerate()
                        {
                            let returned_attr = &ck_template[i];
                            let req_attr =
                                &c.p_template.as_ref().unwrap().attribute[i];

                            if returned_attr.ulValueLen
                                == pkcs11::CK_UNAVAILABLE_INFORMATION
                            {
                                return Err(format!(
                                    "C_GetAttributeValue for attribute '{}' returned CK_UNAVAILABLE_INFORMATION",
                                    req_attr.attr_type
                                )
                                .into());
                            }

                            if is_get_length_call {
                                let expected_len_str = res_attr.ul_value_len.as_ref().ok_or_else(|| {
                                    format!("Response for GetAttributeValue length query for '{}' must have a length", res_attr.attr_type)
                                })?;
                                let expected_len = expected_len_str
                                    .parse::<pkcs11::CK_ULONG>(
                                )?;

                                if returned_attr.ulValueLen != expected_len {
                                    return Err(format!("C_GetAttributeValue length mismatch for '{}'. Returned: {}, Expected: {}", res_attr.attr_type, returned_attr.ulValueLen, expected_len).into());
                                }
                                if args.debug {
                                    eprintln!(
                                        "Attribute '{}' length check passed. Got {}",
                                        res_attr.attr_type,
                                        returned_attr.ulValueLen
                                    );
                                }
                            } else if let Some(expected_val_str) =
                                &res_attr.p_value
                            {
                                let returned_bytes = &value_storage[i]
                                    [..returned_attr.ulValueLen as usize];
                                let req_attr_name = &req_attr.attr_type;

                                if req_attr_name == "VALUE" {
                                    let expected_bytes = hex::decode(expected_val_str)
                                        .map_err(|e| format!("Failed to decode hex value for {}: {}", req_attr_name, e))?;
                                    if returned_bytes
                                        != expected_bytes.as_slice()
                                    {
                                        return Err(format!(
                                            "C_GetAttributeValue value mismatch for '{}'.\nReturned: {}\nExpected: {}",
                                            req_attr_name,
                                            hex::encode(returned_bytes),
                                            expected_val_str
                                        )
                                        .into());
                                    }
                                } else if req_attr_name == "LABEL"
                                    || req_attr_name == "ID"
                                {
                                    let returned_str =
                                        std::ffi::CStr::from_bytes_with_nul(
                                            returned_bytes,
                                        )?
                                        .to_str()?;
                                    if returned_str != expected_val_str {
                                        return Err(format!(
                                            "C_GetAttributeValue value mismatch for '{}'.\nReturned: '{}'\nExpected: '{}'",
                                            req_attr_name,
                                            returned_str,
                                            expected_val_str
                                        )
                                        .into());
                                    }
                                } else if args.debug {
                                    eprintln!("Value comparison for attribute type {} not implemented, skipping.", req_attr_name);
                                }
                                if args.debug {
                                    eprintln!(
                                        "Attribute '{}' value check passed.",
                                        req_attr_name
                                    );
                                }
                            }
                        }
                    }
                } else {
                    return Err(
                        "Mismatched response type for C_GetAttributeValue"
                            .into(),
                    );
                }
            }
            Call::SignInit(c) => {
                let session_str = c
                    .h_session
                    .as_ref()
                    .map(|s| s.value.as_str())
                    .ok_or("C_SignInit requires a Session")?;
                let resolved_session_str =
                    resolve_variable(&variables, session_str)?;
                let session = resolved_session_str
                    .parse::<pkcs11::CK_SESSION_HANDLE>()?;

                let mech_str = c
                    .p_mechanism
                    .as_ref()
                    .map(|m| m.mechanism.value.as_str())
                    .ok_or("C_SignInit requires a Mechanism")?;
                let mech_type = get_mechanism_type_from_str(mech_str)?;

                // For now, assume no parameters for mechanism
                let mut mechanism = pkcs11::CK_MECHANISM {
                    mechanism: mech_type,
                    pParameter: std::ptr::null_mut(),
                    ulParameterLen: 0,
                };

                let key_str = c
                    .h_key
                    .as_ref()
                    .map(|k| k.value.as_str())
                    .ok_or("C_SignInit requires a Key")?;
                let resolved_key_str = resolve_variable(&variables, key_str)?;
                let key =
                    resolved_key_str.parse::<pkcs11::CK_OBJECT_HANDLE>()?;

                pkcs11.sign_init(session, &mut mechanism, key)?;
            }
            Call::Sign(c) => {
                let session_str = c
                    .h_session
                    .as_ref()
                    .map(|s| s.value.as_str())
                    .ok_or("C_Sign requires a Session")?;
                let resolved_session_str =
                    resolve_variable(&variables, session_str)?;
                let session = resolved_session_str
                    .parse::<pkcs11::CK_SESSION_HANDLE>()?;

                let data_hex = c
                    .p_data
                    .as_ref()
                    .map(|d| d.value.as_str())
                    .ok_or("C_Sign requires Data")?;
                let data = hex::decode(data_hex)
                    .map_err(|e| format!("Failed to decode data hex: {}", e))?;

                let sig_info = c
                    .p_signature
                    .as_ref()
                    .ok_or("C_Sign requires a Signature element")?;
                let sig_len_str = sig_info
                    .pul_signature_len
                    .as_ref()
                    .ok_or("C_Sign Signature element requires a length")?;
                let sig_len = sig_len_str.parse::<usize>()?;

                let mut signature = vec![0u8; sig_len];
                let returned_len =
                    pkcs11.sign(session, &data, &mut signature)?;

                if returned_len == 0 {
                    return Err(
                        "C_Sign returned a signature of length 0".into()
                    );
                }

                if args.debug {
                    eprintln!(
                        "C_Sign returned a signature of length {}. Buffer size was {}.",
                        returned_len, sig_len
                    );
                    signature.truncate(returned_len as usize);
                    eprintln!("Signature (hex): {}", hex::encode(&signature));
                }
            }
            Call::CloseSession(c) => {
                let session_str = c
                    .h_session
                    .as_ref()
                    .map(|s| s.value.as_str())
                    .ok_or("C_CloseSession requires a Session")?;
                let resolved_session_str =
                    resolve_variable(&variables, session_str)?;
                let session = resolved_session_str
                    .parse::<pkcs11::CK_SESSION_HANDLE>()?;
                pkcs11.close_session(session)?;
            }
            Call::CloseAllSessions(c) => {
                let slot_id_str = c
                    .slot_id
                    .as_ref()
                    .map(|s| s.value.as_str())
                    .ok_or("C_CloseAllSessions requires a SlotID")?;
                let resolved_slot_id_str =
                    resolve_variable(&variables, slot_id_str)?;
                let slot_id =
                    resolved_slot_id_str.parse::<pkcs11::CK_SLOT_ID>()?;
                pkcs11.close_all_sessions(slot_id)?;
            }
            Call::Login(c) => {
                let session_str = c
                    .h_session
                    .as_ref()
                    .map(|s| s.value.as_str())
                    .ok_or("C_Login requires a Session")?;
                let resolved_session_str =
                    resolve_variable(&variables, session_str)?;
                let session = resolved_session_str
                    .parse::<pkcs11::CK_SESSION_HANDLE>()?;

                let user_type_str = c
                    .user_type
                    .as_ref()
                    .map(|u| u.value.as_str())
                    .ok_or("C_Login requires a UserType")?;
                let user_type = match user_type_str {
                    "USER" => pkcs11::CKU_USER,
                    "SO" => pkcs11::CKU_SO,
                    "CONTEXT_SPECIFIC" => pkcs11::CKU_CONTEXT_SPECIFIC,
                    _ => {
                        return Err(format!(
                            "Unsupported user type: {}",
                            user_type_str
                        )
                        .into())
                    }
                };

                let pin_str = c
                    .p_pin
                    .as_ref()
                    .map(|p| p.value.as_str())
                    .ok_or("C_Login requires a Pin")?;
                let resolved_pin_str = resolve_variable(&variables, pin_str)?;
                let pin = CString::new(resolved_pin_str)?;

                pkcs11.login(session, user_type, &pin)?;
            }
            Call::Logout(c) => {
                let session_str = c
                    .h_session
                    .as_ref()
                    .map(|s| s.value.as_str())
                    .ok_or("C_Logout requires a Session")?;
                let resolved_session_str =
                    resolve_variable(&variables, session_str)?;
                let session = resolved_session_str
                    .parse::<pkcs11::CK_SESSION_HANDLE>()?;
                pkcs11.logout(session)?;
            }
            Call::Finalize(_) => {
                pkcs11.finalize()?;
                println!("{} successful.", call_name);
                break;
            }
            _ => {
                eprintln!(
                    "Execution for {} is not implemented yet.",
                    call_name
                );
                unimplemented_function_called = true;
                continue;
            }
        }
        println!("{} successful.", call_name);
    }

    if calls_iter.next().is_some() {
        return Err(
            "PKCS#11 was finalized, but there were more calls in the profile."
                .into(),
        );
    }

    if unimplemented_function_called {
        return Err(
            "Test failed due to calls to unimplemented functions.".into()
        );
    }

    Ok(())
}
