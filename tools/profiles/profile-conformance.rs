// Copyright 2025 Simo Sorce
// See LICENSE.txt file for terms

use clap::Parser;
use libc;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::ffi::{c_void, CStr, CString};
use std::fmt;
use std::fs;

use kryoptic_lib::pkcs11;

// Root element of the XML profile
#[derive(Debug, Deserialize)]
#[serde(rename = "PKCS11")]
struct Pkcs11Profile {
    #[serde(rename = "$value")]
    calls: Vec<Call>,
}

// Enum representing all possible PKCS#11 function calls in the XML
#[derive(Debug, Deserialize)]
enum Call {
    #[serde(rename = "C_Initialize")]
    Initialize(CInitialize),
    #[serde(rename = "C_GetInfo")]
    GetInfo(CGetInfo),
    #[serde(rename = "C_GetSlotList")]
    GetSlotList(CGetSlotList),
    #[serde(rename = "C_GetSlotInfo")]
    GetSlotInfo(CGetSlotInfo),
    #[serde(rename = "C_GetTokenInfo")]
    GetTokenInfo(CGetTokenInfo),
    #[serde(rename = "C_GetMechanismList")]
    GetMechanismList(CGetMechanismList),
    #[serde(rename = "C_GetMechanismInfo")]
    GetMechanismInfo(CGetMechanismInfo),
    #[serde(rename = "C_OpenSession")]
    OpenSession(COpenSession),
    #[serde(rename = "C_FindObjectsInit")]
    FindObjectsInit(CFindObjectsInit),
    #[serde(rename = "C_FindObjects")]
    FindObjects(CFindObjects),
    #[serde(rename = "C_FindObjectsFinal")]
    FindObjectsFinal(CFindObjectsFinal),
    #[serde(rename = "C_CloseSession")]
    CloseSession(CCloseSession),
    #[serde(rename = "C_CloseAllSessions")]
    CloseAllSessions(CCloseAllSessions),
    #[serde(rename = "C_Finalize")]
    Finalize(CFinalize),
    #[serde(rename = "C_Login")]
    Login(CLogin),
    #[serde(rename = "C_GetAttributeValue")]
    GetAttributeValue(CGetAttributeValue),
    #[serde(rename = "C_SignInit")]
    SignInit(CSignInit),
    #[serde(rename = "C_Sign")]
    Sign(CSign),
    #[serde(rename = "C_Logout")]
    Logout(CLogout),
}

impl Call {
    fn has_rv(&self) -> bool {
        match self {
            Call::Initialize(c) => c.rv.is_some(),
            Call::GetInfo(c) => c.rv.is_some(),
            Call::GetSlotList(c) => c.rv.is_some(),
            Call::GetSlotInfo(c) => c.rv.is_some(),
            Call::GetTokenInfo(c) => c.rv.is_some(),
            Call::GetMechanismList(c) => c.rv.is_some(),
            Call::GetMechanismInfo(c) => c.rv.is_some(),
            Call::OpenSession(c) => c.rv.is_some(),
            Call::FindObjectsInit(c) => c.rv.is_some(),
            Call::FindObjects(c) => c.rv.is_some(),
            Call::FindObjectsFinal(c) => c.rv.is_some(),
            Call::CloseSession(c) => c.rv.is_some(),
            Call::CloseAllSessions(c) => c.rv.is_some(),
            Call::Finalize(c) => c.rv.is_some(),
            Call::Login(c) => c.rv.is_some(),
            Call::GetAttributeValue(c) => c.rv.is_some(),
            Call::SignInit(c) => c.rv.is_some(),
            Call::Sign(c) => c.rv.is_some(),
            Call::Logout(c) => c.rv.is_some(),
        }
    }
}

#[derive(Serialize)]
#[serde(untagged)]
enum CallForSerialize<'a> {
    Initialize(&'a CInitialize),
    GetInfo(&'a CGetInfo),
    GetSlotList(&'a CGetSlotList),
    GetSlotInfo(&'a CGetSlotInfo),
    GetTokenInfo(&'a CGetTokenInfo),
    GetMechanismList(&'a CGetMechanismList),
    GetMechanismInfo(&'a CGetMechanismInfo),
    OpenSession(&'a COpenSession),
    FindObjectsInit(&'a CFindObjectsInit),
    FindObjects(&'a CFindObjects),
    FindObjectsFinal(&'a CFindObjectsFinal),
    CloseSession(&'a CCloseSession),
    CloseAllSessions(&'a CCloseAllSessions),
    Finalize(&'a CFinalize),
    Login(&'a CLogin),
    GetAttributeValue(&'a CGetAttributeValue),
    SignInit(&'a CSignInit),
    Sign(&'a CSign),
    Logout(&'a CLogout),
}

impl<'a> From<&'a Call> for CallForSerialize<'a> {
    fn from(call: &'a Call) -> Self {
        match call {
            Call::Initialize(c) => CallForSerialize::Initialize(c),
            Call::GetInfo(c) => CallForSerialize::GetInfo(c),
            Call::GetSlotList(c) => CallForSerialize::GetSlotList(c),
            Call::GetSlotInfo(c) => CallForSerialize::GetSlotInfo(c),
            Call::GetTokenInfo(c) => CallForSerialize::GetTokenInfo(c),
            Call::GetMechanismList(c) => CallForSerialize::GetMechanismList(c),
            Call::GetMechanismInfo(c) => CallForSerialize::GetMechanismInfo(c),
            Call::OpenSession(c) => CallForSerialize::OpenSession(c),
            Call::FindObjectsInit(c) => CallForSerialize::FindObjectsInit(c),
            Call::FindObjects(c) => CallForSerialize::FindObjects(c),
            Call::FindObjectsFinal(c) => CallForSerialize::FindObjectsFinal(c),
            Call::CloseSession(c) => CallForSerialize::CloseSession(c),
            Call::CloseAllSessions(c) => CallForSerialize::CloseAllSessions(c),
            Call::Finalize(c) => CallForSerialize::Finalize(c),
            Call::Login(c) => CallForSerialize::Login(c),
            Call::GetAttributeValue(c) => {
                CallForSerialize::GetAttributeValue(c)
            }
            Call::SignInit(c) => CallForSerialize::SignInit(c),
            Call::Sign(c) => CallForSerialize::Sign(c),
            Call::Logout(c) => CallForSerialize::Logout(c),
        }
    }
}

fn get_call_name(call: &Call) -> &str {
    match call {
        Call::Initialize(_) => "C_Initialize",
        Call::GetInfo(_) => "C_GetInfo",
        Call::GetSlotList(_) => "C_GetSlotList",
        Call::GetSlotInfo(_) => "C_GetSlotInfo",
        Call::GetTokenInfo(_) => "C_GetTokenInfo",
        Call::GetMechanismList(_) => "C_GetMechanismList",
        Call::GetMechanismInfo(_) => "C_GetMechanismInfo",
        Call::OpenSession(_) => "C_OpenSession",
        Call::FindObjectsInit(_) => "C_FindObjectsInit",
        Call::FindObjects(_) => "C_FindObjects",
        Call::FindObjectsFinal(_) => "C_FindObjectsFinal",
        Call::CloseSession(_) => "C_CloseSession",
        Call::CloseAllSessions(_) => "C_CloseAllSessions",
        Call::Finalize(_) => "C_Finalize",
        Call::Login(_) => "C_Login",
        Call::GetAttributeValue(_) => "C_GetAttributeValue",
        Call::SignInit(_) => "C_SignInit",
        Call::Sign(_) => "C_Sign",
        Call::Logout(_) => "C_Logout",
    }
}

// --- Reusable utility structs ---

#[derive(Debug, Deserialize, Serialize)]
pub struct ValueAttr {
    #[serde(rename(serialize = "value", deserialize = "@value"))]
    pub value: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct MajorMinor {
    #[serde(rename(serialize = "major", deserialize = "@major"))]
    pub major: String,
    #[serde(rename(serialize = "minor", deserialize = "@minor"))]
    pub minor: String,
}

// --- Structs for each PKCS#11 function call ---

#[derive(Debug, Deserialize, Serialize)]
pub struct CInitialize {
    #[serde(
        rename(serialize = "rv", deserialize = "@rv"),
        skip_serializing_if = "Option::is_none"
    )]
    pub rv: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct CGetInfo {
    #[serde(
        rename(serialize = "rv", deserialize = "@rv"),
        skip_serializing_if = "Option::is_none"
    )]
    pub rv: Option<String>,
    #[serde(
        rename(serialize = "pInfo", deserialize = "Info"),
        skip_serializing_if = "Option::is_none"
    )]
    pub p_info: Option<Info>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Info {
    #[serde(rename(
        serialize = "cryptokiVersion",
        deserialize = "CryptokiVersion"
    ))]
    pub cryptoki_version: MajorMinor,
    #[serde(rename(
        serialize = "manufacturerID",
        deserialize = "ManufacturerID"
    ))]
    pub manufacturer_id: ValueAttr,
    #[serde(rename(serialize = "flags", deserialize = "Flags"))]
    pub flags: ValueAttr,
    #[serde(rename(
        serialize = "libraryDescription",
        deserialize = "LibraryDescription"
    ))]
    pub library_description: ValueAttr,
    #[serde(rename(
        serialize = "libraryVersion",
        deserialize = "LibraryVersion"
    ))]
    pub library_version: MajorMinor,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct CGetSlotList {
    #[serde(
        rename(serialize = "rv", deserialize = "@rv"),
        skip_serializing_if = "Option::is_none"
    )]
    pub rv: Option<String>,
    #[serde(
        rename(serialize = "tokenPresent", deserialize = "TokenPresent"),
        skip_serializing_if = "Option::is_none"
    )]
    pub token_present: Option<ValueAttr>,
    #[serde(
        rename(serialize = "slotList", deserialize = "SlotList"),
        skip_serializing_if = "Option::is_none"
    )]
    pub slot_list: Option<SlotList>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct SlotList {
    #[serde(
        rename(serialize = "pulCount", deserialize = "@length"),
        skip_serializing_if = "Option::is_none"
    )]
    pub pul_count: Option<String>,
    #[serde(rename(serialize = "pSlotList", deserialize = "SlotID"), default)]
    pub p_slot_list: Vec<SlotID>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct SlotID {
    #[serde(rename(serialize = "value", deserialize = "@value"))]
    pub value: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct CGetSlotInfo {
    #[serde(
        rename(serialize = "rv", deserialize = "@rv"),
        skip_serializing_if = "Option::is_none"
    )]
    pub rv: Option<String>,
    #[serde(
        rename(serialize = "slotID", deserialize = "SlotID"),
        skip_serializing_if = "Option::is_none"
    )]
    pub slot_id: Option<SlotID>,
    #[serde(
        rename(serialize = "pInfo", deserialize = "SlotInfo"),
        skip_serializing_if = "Option::is_none"
    )]
    pub p_info: Option<SlotInfo>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct SlotInfo {
    #[serde(rename(
        serialize = "slotDescription",
        deserialize = "SlotDescription"
    ))]
    pub slot_description: ValueAttr,
    #[serde(rename(
        serialize = "manufacturerID",
        deserialize = "ManufacturerID"
    ))]
    pub manufacturer_id: ValueAttr,
    #[serde(rename(serialize = "flags", deserialize = "Flags"))]
    pub flags: ValueAttr,
    #[serde(rename(
        serialize = "hardwareVersion",
        deserialize = "HardwareVersion"
    ))]
    pub hardware_version: MajorMinor,
    #[serde(rename(
        serialize = "firmwareVersion",
        deserialize = "FirmwareVersion"
    ))]
    pub firmware_version: MajorMinor,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct CGetTokenInfo {
    #[serde(
        rename(serialize = "rv", deserialize = "@rv"),
        skip_serializing_if = "Option::is_none"
    )]
    pub rv: Option<String>,
    #[serde(
        rename(serialize = "slotID", deserialize = "SlotID"),
        skip_serializing_if = "Option::is_none"
    )]
    pub slot_id: Option<SlotID>,
    #[serde(
        rename(serialize = "pInfo", deserialize = "TokenInfo"),
        skip_serializing_if = "Option::is_none"
    )]
    pub p_info: Option<TokenInfo>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct TokenInfo {
    #[serde(rename(serialize = "label"))]
    pub label: ValueAttr,
    #[serde(rename(
        serialize = "manufacturerID",
        deserialize = "ManufacturerID"
    ))]
    pub manufacturer_id: ValueAttr,
    #[serde(rename(serialize = "model"))]
    pub model: ValueAttr,
    #[serde(rename(serialize = "serialNumber", deserialize = "serialNumber"))]
    pub serial_number: ValueAttr,
    #[serde(rename(serialize = "flags", deserialize = "Flags"))]
    pub flags: ValueAttr,
    #[serde(rename(
        serialize = "ulMaxSessionCount",
        deserialize = "MaxSessionCount"
    ))]
    pub max_session_count: ValueAttr,
    #[serde(rename(
        serialize = "ulSessionCount",
        deserialize = "SessionCount"
    ))]
    pub session_count: ValueAttr,
    #[serde(rename(
        serialize = "ulMaxRwSessionCount",
        deserialize = "MaxRwSessionCount"
    ))]
    pub max_rw_session_count: ValueAttr,
    #[serde(rename(
        serialize = "ulRwSessionCount",
        deserialize = "RwSessionCount"
    ))]
    pub rw_session_count: ValueAttr,
    #[serde(rename(serialize = "ulMaxPinLen", deserialize = "MaxPinLen"))]
    pub max_pin_len: ValueAttr,
    #[serde(rename(serialize = "ulMinPinLen", deserialize = "MinPinLen"))]
    pub min_pin_len: ValueAttr,
    #[serde(rename(
        serialize = "ulTotalPublicMemory",
        deserialize = "TotalPublicMemory"
    ))]
    pub total_public_memory: ValueAttr,
    #[serde(rename(
        serialize = "ulFreePublicMemory",
        deserialize = "FreePublicMemory"
    ))]
    pub free_public_memory: ValueAttr,
    #[serde(rename(
        serialize = "ulTotalPrivateMemory",
        deserialize = "TotalPrivateMemory"
    ))]
    pub total_private_memory: ValueAttr,
    #[serde(rename(
        serialize = "ulFreePrivateMemory",
        deserialize = "FreePrivateMemory"
    ))]
    pub free_private_memory: ValueAttr,
    #[serde(rename(
        serialize = "hardwareVersion",
        deserialize = "HardwareVersion"
    ))]
    pub hardware_version: MajorMinor,
    #[serde(rename(
        serialize = "firmwareVersion",
        deserialize = "FirmwareVersion"
    ))]
    pub firmware_version: MajorMinor,
    #[serde(rename(serialize = "utcTime", deserialize = "utcTime"))]
    pub utc_time: ValueAttr,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct CGetMechanismList {
    #[serde(
        rename(serialize = "rv", deserialize = "@rv"),
        skip_serializing_if = "Option::is_none"
    )]
    pub rv: Option<String>,
    #[serde(
        rename(serialize = "slotID", deserialize = "SlotID"),
        skip_serializing_if = "Option::is_none"
    )]
    pub slot_id: Option<SlotID>,
    #[serde(
        rename(serialize = "pMechanismList", deserialize = "MechanismList"),
        skip_serializing_if = "Option::is_none"
    )]
    pub p_mechanism_list: Option<MechanismList>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct MechanismList {
    #[serde(
        rename(serialize = "pulCount", deserialize = "@length"),
        skip_serializing_if = "Option::is_none"
    )]
    pub pul_count: Option<String>,
    #[serde(
        rename(serialize = "pMechanismList", deserialize = "Type"),
        default
    )]
    pub p_mechanism_list: Vec<ValueAttr>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct CGetMechanismInfo {
    #[serde(
        rename(serialize = "rv", deserialize = "@rv"),
        skip_serializing_if = "Option::is_none"
    )]
    pub rv: Option<String>,
    #[serde(
        rename(serialize = "slotID", deserialize = "SlotID"),
        skip_serializing_if = "Option::is_none"
    )]
    pub slot_id: Option<SlotID>,
    #[serde(
        rename(serialize = "type", deserialize = "Type"),
        skip_serializing_if = "Option::is_none"
    )]
    pub mechanism_type: Option<ValueAttr>,
    #[serde(
        rename(serialize = "pInfo", deserialize = "MechanismInfo"),
        skip_serializing_if = "Option::is_none"
    )]
    pub p_info: Option<MechanismInfo>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct MechanismInfo {
    #[serde(rename(serialize = "ulMinKeySize", deserialize = "MinKeySize"))]
    pub min_key_size: ValueAttr,
    #[serde(rename(serialize = "ulMaxKeySize", deserialize = "MaxKeySize"))]
    pub max_key_size: ValueAttr,
    #[serde(rename(serialize = "flags", deserialize = "Flags"))]
    pub flags: ValueAttr,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct COpenSession {
    #[serde(
        rename(serialize = "rv", deserialize = "@rv"),
        skip_serializing_if = "Option::is_none"
    )]
    pub rv: Option<String>,
    #[serde(
        rename(serialize = "slotID", deserialize = "SlotID"),
        skip_serializing_if = "Option::is_none"
    )]
    pub slot_id: Option<SlotID>,
    #[serde(
        rename(serialize = "flags", deserialize = "Flags"),
        skip_serializing_if = "Option::is_none"
    )]
    pub flags: Option<ValueAttr>,
    #[serde(
        rename(serialize = "phSession", deserialize = "Session"),
        skip_serializing_if = "Option::is_none"
    )]
    pub ph_session: Option<Session>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Session {
    #[serde(rename(serialize = "value", deserialize = "@value"))]
    pub value: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct CFindObjectsInit {
    #[serde(
        rename(serialize = "rv", deserialize = "@rv"),
        skip_serializing_if = "Option::is_none"
    )]
    pub rv: Option<String>,
    #[serde(
        rename(serialize = "hSession", deserialize = "Session"),
        skip_serializing_if = "Option::is_none"
    )]
    pub h_session: Option<Session>,
    #[serde(
        rename(serialize = "pTemplate", deserialize = "Template"),
        skip_serializing_if = "Option::is_none"
    )]
    pub p_template: Option<Template>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Template {
    #[serde(
        rename(serialize = "attribute", deserialize = "Attribute"),
        default
    )]
    pub attribute: Vec<Attribute>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Attribute {
    #[serde(rename(serialize = "type", deserialize = "@type"))]
    pub attr_type: String,
    #[serde(
        rename(serialize = "pValue", deserialize = "@value"),
        skip_serializing_if = "Option::is_none"
    )]
    pub p_value: Option<String>,
    #[serde(
        rename(serialize = "ulValueLen", deserialize = "@length"),
        skip_serializing_if = "Option::is_none"
    )]
    pub ul_value_len: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct CFindObjects {
    #[serde(
        rename(serialize = "rv", deserialize = "@rv"),
        skip_serializing_if = "Option::is_none"
    )]
    pub rv: Option<String>,
    #[serde(
        rename(serialize = "hSession", deserialize = "Session"),
        skip_serializing_if = "Option::is_none"
    )]
    pub h_session: Option<Session>,
    #[serde(rename(serialize = "phObject", deserialize = "Object"), default)]
    pub ph_object: Vec<Object>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Object {
    #[serde(
        rename(serialize = "length", deserialize = "@length"),
        skip_serializing_if = "Option::is_none"
    )]
    pub length: Option<String>,
    #[serde(
        rename(serialize = "value", deserialize = "@value"),
        skip_serializing_if = "Option::is_none"
    )]
    pub value: Option<String>,
    #[serde(
        rename(deserialize = "Object"),
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub object: Vec<Object>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct CFindObjectsFinal {
    #[serde(
        rename(serialize = "rv", deserialize = "@rv"),
        skip_serializing_if = "Option::is_none"
    )]
    pub rv: Option<String>,
    #[serde(
        rename(serialize = "hSession", deserialize = "Session"),
        skip_serializing_if = "Option::is_none"
    )]
    pub h_session: Option<Session>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct CCloseSession {
    #[serde(
        rename(serialize = "rv", deserialize = "@rv"),
        skip_serializing_if = "Option::is_none"
    )]
    pub rv: Option<String>,
    #[serde(
        rename(serialize = "hSession", deserialize = "Session"),
        skip_serializing_if = "Option::is_none"
    )]
    pub h_session: Option<Session>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct CCloseAllSessions {
    #[serde(
        rename(serialize = "rv", deserialize = "@rv"),
        skip_serializing_if = "Option::is_none"
    )]
    pub rv: Option<String>,
    #[serde(
        rename(serialize = "slotID", deserialize = "SlotID"),
        skip_serializing_if = "Option::is_none"
    )]
    pub slot_id: Option<SlotID>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct CFinalize {
    #[serde(
        rename(serialize = "rv", deserialize = "@rv"),
        skip_serializing_if = "Option::is_none"
    )]
    pub rv: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct CLogin {
    #[serde(
        rename(serialize = "rv", deserialize = "@rv"),
        skip_serializing_if = "Option::is_none"
    )]
    pub rv: Option<String>,
    #[serde(
        rename(serialize = "hSession", deserialize = "Session"),
        skip_serializing_if = "Option::is_none"
    )]
    pub h_session: Option<Session>,
    #[serde(
        rename(serialize = "userType", deserialize = "UserType"),
        skip_serializing_if = "Option::is_none"
    )]
    pub user_type: Option<ValueAttr>,
    #[serde(
        rename(serialize = "pPin", deserialize = "Pin"),
        skip_serializing_if = "Option::is_none"
    )]
    pub p_pin: Option<ValueAttr>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct CGetAttributeValue {
    #[serde(
        rename(serialize = "rv", deserialize = "@rv"),
        skip_serializing_if = "Option::is_none"
    )]
    pub rv: Option<String>,
    #[serde(
        rename(serialize = "hSession", deserialize = "Session"),
        skip_serializing_if = "Option::is_none"
    )]
    pub h_session: Option<Session>,
    #[serde(
        rename(serialize = "hObject", deserialize = "Object"),
        skip_serializing_if = "Option::is_none"
    )]
    pub h_object: Option<Object>,
    #[serde(
        rename(serialize = "pTemplate", deserialize = "Template"),
        skip_serializing_if = "Option::is_none"
    )]
    pub p_template: Option<Template>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct CSignInit {
    #[serde(
        rename(serialize = "rv", deserialize = "@rv"),
        skip_serializing_if = "Option::is_none"
    )]
    pub rv: Option<String>,
    #[serde(
        rename(serialize = "hSession", deserialize = "Session"),
        skip_serializing_if = "Option::is_none"
    )]
    pub h_session: Option<Session>,
    #[serde(
        rename(serialize = "pMechanism", deserialize = "Mechanism"),
        skip_serializing_if = "Option::is_none"
    )]
    pub p_mechanism: Option<Mechanism>,
    #[serde(
        rename(serialize = "hKey", deserialize = "Key"),
        skip_serializing_if = "Option::is_none"
    )]
    pub h_key: Option<ValueAttr>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Mechanism {
    #[serde(rename(serialize = "mechanism", deserialize = "Type"))]
    pub mechanism: ValueAttr,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct CSign {
    #[serde(
        rename(serialize = "rv", deserialize = "@rv"),
        skip_serializing_if = "Option::is_none"
    )]
    pub rv: Option<String>,
    #[serde(
        rename(serialize = "hSession", deserialize = "Session"),
        skip_serializing_if = "Option::is_none"
    )]
    pub h_session: Option<Session>,
    #[serde(
        rename(serialize = "pData", deserialize = "Data"),
        skip_serializing_if = "Option::is_none"
    )]
    pub p_data: Option<ValueAttr>,
    #[serde(
        rename(serialize = "pSignature", deserialize = "Signature"),
        skip_serializing_if = "Option::is_none"
    )]
    pub p_signature: Option<Signature>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Signature {
    #[serde(
        rename(serialize = "pulSignatureLen", deserialize = "@length"),
        skip_serializing_if = "Option::is_none"
    )]
    pub pul_signature_len: Option<String>,
    #[serde(
        rename(serialize = "pSignature", deserialize = "@value"),
        skip_serializing_if = "Option::is_none"
    )]
    pub p_signature: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct CLogout {
    #[serde(
        rename(serialize = "rv", deserialize = "@rv"),
        skip_serializing_if = "Option::is_none"
    )]
    pub rv: Option<String>,
    #[serde(
        rename(serialize = "hSession", deserialize = "Session"),
        skip_serializing_if = "Option::is_none"
    )]
    pub h_session: Option<Session>,
}

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Arguments {
    #[arg(short = 'd', long)]
    debug: bool,

    #[arg(short = 'o', long)]
    output: Option<String>,

    #[arg(short = 'm', long)]
    pkcs11_module: Option<String>,

    #[arg(short = 'i', long)]
    pkcs11_initargs: Option<String>,

    #[arg(short = 'p', long)]
    pkcs11_pin: Option<String>,

    #[arg(short = 's', long)]
    pkcs11_slot: Option<u64>,

    xml_profile: String,
}

#[derive(Debug)]
struct Error {
    msg: String,
}

impl From<String> for Error {
    fn from(msg: String) -> Error {
        Error { msg: msg }
    }
}

impl From<&str> for Error {
    fn from(msg: &str) -> Error {
        Error::from(msg.to_string())
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.msg)
    }
}

impl std::error::Error for Error {}

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
    fntable: *mut pkcs11::CK_FUNCTION_LIST,
}

impl FuncList {
    fn from_symbol_name(
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

    fn initialize(&self, initargs: Option<&CStr>) -> Result<(), Error> {
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

    fn get_info(&self) -> Result<pkcs11::CK_INFO, Error> {
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

    fn get_slot_list(
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

    fn open_session(
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

    fn finalize(&self) -> Result<(), Error> {
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

fn execute_calls(
    pkcs11: &FuncList,
    profile: Pkcs11Profile,
    args: &Arguments,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut calls_iter = profile.calls.into_iter();
    let mut variables = HashMap::<String, String>::new();

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
            Call::FindObjectsFinal(_)
            | Call::Logout(_)
            | Call::CloseSession(_) => {
                // These calls only return a return value, but require a session handle
                // that is not available yet as state management is not implemented.
                return Err(format!(
                    "Execution for {} requires state management which is not yet implemented",
                    call_name
                )
                .into());
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

    Ok(())
}

fn generate_json(
    profile: Pkcs11Profile,
    debug: bool,
) -> Result<String, Box<dyn std::error::Error>> {
    let mut paired_calls: Vec<serde_json::Value> = Vec::new();
    let mut calls_iter = profile.calls.into_iter();

    let mut counter = 0;
    while let Some(request) = calls_iter.next() {
        if debug {
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
        if debug {
            eprintln!("Response: {:?}", &response);
        }

        if std::mem::discriminant(&request) != std::mem::discriminant(&response)
        {
            panic!(
                "Mismatched request/response pair: {:?}, {:?}",
                request, response
            );
        }
        if debug {
            eprintln!("-> Request/Response pair type matches.");
        }

        if request.has_rv() {
            panic!("Request node has 'rv' field: {:?}", request);
        }
        if debug {
            eprintln!("-> Validated: Request does not have 'rv' field.");
        }

        if !response.has_rv() {
            panic!("Response node is missing 'rv' field: {:?}", response);
        }
        if debug {
            eprintln!("-> Validated: Response has 'rv' field.");
        }

        let call_name = get_call_name(&request);
        if debug {
            eprintln!("-> Call name: {}", call_name);
        }

        let request_val =
            serde_json::to_value(CallForSerialize::from(&request))?;
        if debug {
            eprintln!("-> Serialized request to JSON value.");
        }
        let response_val =
            serde_json::to_value(CallForSerialize::from(&response))?;
        if debug {
            eprintln!("-> Serialized response to JSON value.");
        }

        let mut call_pair = serde_json::Map::new();
        call_pair.insert("request".to_string(), request_val);
        call_pair.insert("response".to_string(), response_val);

        let mut call_item = serde_json::Map::new();
        call_item.insert(
            call_name.to_string(),
            serde_json::Value::Object(call_pair),
        );

        paired_calls.push(serde_json::Value::Object(call_item));
        if debug {
            eprintln!("-> Added paired call to the list.");
        }
    }

    if debug {
        eprintln!(
            "\n--- Finished processing all call pairs. Total pairs: {} ---",
            paired_calls.len()
        );
    }
    let json_output = serde_json::to_string_pretty(&paired_calls)?;
    if debug {
        eprintln!(
            "Successfully serialized paired calls to pretty JSON string."
        );
    }
    Ok(json_output)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Arguments::parse();

    if args.debug {
        eprintln!("Debug mode enabled.");
        eprintln!("XML file path: {}", args.xml_profile);
    }

    let xml_content = fs::read_to_string(&args.xml_profile)?;
    if args.debug {
        eprintln!(
            "Successfully read XML file content ({} bytes).",
            xml_content.len()
        );
    }

    let pkcs11_profile: Pkcs11Profile = quick_xml::de::from_str(&xml_content)?;
    if args.debug {
        eprintln!("Successfully parsed XML into Pkcs11Profile struct.");
        eprintln!("Found {} calls in the profile.", pkcs11_profile.calls.len());
    }

    if let Some(output_format) = args.output {
        if output_format.to_uppercase() == "JSON" {
            let json_output = generate_json(pkcs11_profile, args.debug)?;
            println!("{}", json_output);
            return Ok(());
        } else {
            eprintln!("Error: unsupported output format '{}'", output_format);
            std::process::exit(1);
        }
    }

    let module_path = match args.pkcs11_module {
        Some(ref path) => path.as_str(),
        None => {
            eprintln!("Error: --pkcs11-module is required when not using --output JSON");
            std::process::exit(1);
        }
    };

    let soname = CString::new(module_path)?;
    let rtld_flags = libc::RTLD_LOCAL | libc::RTLD_NOW;
    let lib_handle =
        unsafe { libc::dlopen(soname.as_c_str().as_ptr(), rtld_flags) };
    if lib_handle.is_null() {
        eprintln!("Failed to load pkcs11 module: {}", dl_error());
        std::process::exit(1);
    }

    let res = {
        let pkcs11 =
            match FuncList::from_symbol_name(lib_handle, "C_GetFunctionList") {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("Failed to get function list: {}", e);
                    unsafe {
                        libc::dlclose(lib_handle);
                    }
                    std::process::exit(1);
                }
            };
        execute_calls(&pkcs11, pkcs11_profile, &args)
    };

    unsafe {
        libc::dlclose(lib_handle);
    }
    res
}
