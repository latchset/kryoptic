// Copyright 2025 Simo Sorce
// See LICENSE.txt file for terms

use serde::{Deserialize, Serialize};

// Root element of the XML profile
#[derive(Debug, Deserialize)]
#[serde(rename = "PKCS11")]
pub struct Pkcs11Profile {
    #[serde(rename = "$value")]
    pub calls: Vec<Call>,
}

// Enum representing all possible PKCS#11 function calls in the XML
#[derive(Debug, Deserialize)]
pub enum Call {
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
    #[serde(rename = "C_VerifyInit")]
    VerifyInit(CVerifyInit),
    #[serde(rename = "C_Verify")]
    Verify(CVerify),
    #[serde(rename = "C_Logout")]
    Logout(CLogout),
}

impl Call {
    pub fn has_rv(&self) -> bool {
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
            Call::VerifyInit(c) => c.rv.is_some(),
            Call::Verify(c) => c.rv.is_some(),
            Call::Logout(c) => c.rv.is_some(),
        }
    }
}

#[derive(Serialize)]
#[serde(untagged)]
pub enum CallForSerialize<'a> {
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
    VerifyInit(&'a CVerifyInit),
    Verify(&'a CVerify),
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
            Call::VerifyInit(c) => CallForSerialize::VerifyInit(c),
            Call::Verify(c) => CallForSerialize::Verify(c),
            Call::Logout(c) => CallForSerialize::Logout(c),
        }
    }
}

pub fn get_call_name(call: &Call) -> &str {
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
        Call::VerifyInit(_) => "C_VerifyInit",
        Call::Verify(_) => "C_Verify",
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
pub struct CVerifyInit {
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
pub struct CVerify {
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

pub fn generate_json(
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
