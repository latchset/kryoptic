// Copyright 2023 Simo Sorce
// See LICENSE.txt file for terms

use serde_json::{Value, Number};
use data_encoding::BASE64;

use super::interface;
use super::error;

use interface::*;
use error::{KResult, KError};
use super::{err_rv, err_not_found};

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum AttrType {
    BoolType,
    NumType,
    StringType,
    BytesType,
    DateType,
    DenyType,
}

#[derive(Debug)]
struct Attrmap<'a> {
    id: CK_ULONG,
    name: &'a str,
    atype: AttrType,
}

static ATTRMAP: [Attrmap<'_>; 126] = [
    Attrmap { id: 0, name: "CKA_CLASS", atype: AttrType::NumType  },
    Attrmap { id: 1, name: "CKA_TOKEN", atype: AttrType::BoolType  },
    Attrmap { id: 2, name: "CKA_PRIVATE", atype: AttrType::BoolType  },
    Attrmap { id: 3, name: "CKA_LABEL", atype: AttrType::StringType  },
    Attrmap { id: 4, name: "CKA_UNIQUE_ID", atype: AttrType::StringType  },
    Attrmap { id: 16, name: "CKA_APPLICATION", atype: AttrType::StringType  },
    Attrmap { id: 17, name: "CKA_VALUE", atype: AttrType::BytesType  },
    Attrmap { id: 18, name: "CKA_OBJECT_ID", atype: AttrType::BytesType  },
    Attrmap { id: 128, name: "CKA_CERTIFICATE_TYPE", atype: AttrType::NumType  },
    Attrmap { id: 129, name: "CKA_ISSUER", atype: AttrType::BytesType  },
    Attrmap { id: 130, name: "CKA_SERIAL_NUMBER", atype: AttrType::BytesType  },
    Attrmap { id: 131, name: "CKA_AC_ISSUER", atype: AttrType::BytesType  },
    Attrmap { id: 132, name: "CKA_OWNER", atype: AttrType::BytesType  },
    Attrmap { id: 133, name: "CKA_ATTR_TYPES", atype: AttrType::BytesType  },
    Attrmap { id: 134, name: "CKA_TRUSTED", atype: AttrType::BoolType  },
    Attrmap { id: 135, name: "CKA_CERTIFICATE_CATEGORY", atype: AttrType::NumType  },
    Attrmap { id: 136, name: "CKA_JAVA_MIDP_SECURITY_DOMAIN", atype: AttrType::NumType  },
    Attrmap { id: 137, name: "CKA_URL", atype: AttrType::StringType  },
    Attrmap { id: 138, name: "CKA_HASH_OF_SUBJECT_PUBLIC_KEY", atype: AttrType::BytesType  },
    Attrmap { id: 139, name: "CKA_HASH_OF_ISSUER_PUBLIC_KEY", atype: AttrType::BytesType  },
    Attrmap { id: 140, name: "CKA_NAME_HASH_ALGORITHM", atype: AttrType::NumType  },
    Attrmap { id: 144, name: "CKA_CHECK_VALUE", atype: AttrType::BytesType  },
    Attrmap { id: 256, name: "CKA_KEY_TYPE", atype: AttrType::NumType  },
    Attrmap { id: 257, name: "CKA_SUBJECT", atype: AttrType::BytesType  },
    Attrmap { id: 258, name: "CKA_ID", atype: AttrType::BytesType  },
    Attrmap { id: 259, name: "CKA_SENSITIVE", atype: AttrType::BoolType  },
    Attrmap { id: 260, name: "CKA_ENCRYPT", atype: AttrType::BoolType  },
    Attrmap { id: 261, name: "CKA_DECRYPT", atype: AttrType::BoolType  },
    Attrmap { id: 262, name: "CKA_WRAP", atype: AttrType::BoolType  },
    Attrmap { id: 263, name: "CKA_UNWRAP", atype: AttrType::BoolType  },
    Attrmap { id: 264, name: "CKA_SIGN", atype: AttrType::BoolType  },
    Attrmap { id: 265, name: "CKA_SIGN_RECOVER", atype: AttrType::BoolType  },
    Attrmap { id: 266, name: "CKA_VERIFY", atype: AttrType::BoolType  },
    Attrmap { id: 267, name: "CKA_VERIFY_RECOVER", atype: AttrType::BoolType  },
    Attrmap { id: 268, name: "CKA_DERIVE", atype: AttrType::BoolType  },
    Attrmap { id: 272, name: "CKA_START_DATE", atype: AttrType::DateType  },
    Attrmap { id: 273, name: "CKA_END_DATE", atype: AttrType::DateType  },
    Attrmap { id: 288, name: "CKA_MODULUS", atype: AttrType::BytesType  },
    Attrmap { id: 289, name: "CKA_MODULUS_BITS", atype: AttrType::NumType  },
    Attrmap { id: 290, name: "CKA_PUBLIC_EXPONENT", atype: AttrType::BytesType  },
    Attrmap { id: 291, name: "CKA_PRIVATE_EXPONENT", atype: AttrType::BytesType  },
    Attrmap { id: 292, name: "CKA_PRIME_1", atype: AttrType::BytesType  },
    Attrmap { id: 293, name: "CKA_PRIME_2", atype: AttrType::BytesType  },
    Attrmap { id: 294, name: "CKA_EXPONENT_1", atype: AttrType::BytesType  },
    Attrmap { id: 295, name: "CKA_EXPONENT_2", atype: AttrType::BytesType  },
    Attrmap { id: 296, name: "CKA_COEFFICIENT", atype: AttrType::BytesType  },
    Attrmap { id: 297, name: "CKA_PUBLIC_KEY_INFO", atype: AttrType::BytesType  },
    Attrmap { id: 304, name: "CKA_PRIME", atype: AttrType::BytesType  },
    Attrmap { id: 305, name: "CKA_SUBPRIME", atype: AttrType::BytesType  },
    Attrmap { id: 306, name: "CKA_BASE", atype: AttrType::BytesType  },
    Attrmap { id: 307, name: "CKA_PRIME_BITS", atype: AttrType::BytesType  },
    Attrmap { id: 308, name: "CKA_SUBPRIME_BITS", atype: AttrType::NumType  },
    /*Attrmap { id: , name: "CKA_SUB_PRIME_BITS", atype: AttrType::NumType  },*/
    Attrmap { id: 352, name: "CKA_VALUE_BITS", atype: AttrType::NumType  },
    Attrmap { id: 353, name: "CKA_VALUE_LEN", atype: AttrType::NumType  },
    Attrmap { id: 354, name: "CKA_EXTRACTABLE", atype: AttrType::BoolType  },
    Attrmap { id: 355, name: "CKA_LOCAL", atype: AttrType::BoolType  },
    Attrmap { id: 356, name: "CKA_NEVER_EXTRACTABLE", atype: AttrType::BoolType  },
    Attrmap { id: 357, name: "CKA_ALWAYS_SENSITIVE", atype: AttrType::BoolType  },
    Attrmap { id: 358, name: "CKA_KEY_GEN_MECHANISM", atype: AttrType::NumType  },
    Attrmap { id: 368, name: "CKA_MODIFIABLE", atype: AttrType::BoolType  },
    Attrmap { id: 369, name: "CKA_COPYABLE", atype: AttrType::BoolType  },
    Attrmap { id: 370, name: "CKA_DESTROYABLE", atype: AttrType::BoolType  },
    /*Attrmap { id: , name: "CKA_ECDSA_PARAMS", atype: AttrType::BytesType  },*/
    Attrmap { id: 384, name: "CKA_EC_PARAMS", atype: AttrType::BytesType  },
    Attrmap { id: 385, name: "CKA_EC_POINT", atype: AttrType::BytesType  },
    Attrmap { id: 512, name: "CKA_SECONDARY_AUTH", atype: AttrType::NumType  },
    Attrmap { id: 513, name: "CKA_AUTH_PIN_FLAGS", atype: AttrType::NumType  },
    Attrmap { id: 514, name: "CKA_ALWAYS_AUTHENTICATE", atype: AttrType::BoolType  },
    Attrmap { id: 528, name: "CKA_WRAP_WITH_TRUSTED", atype: AttrType::BoolType  },
    Attrmap { id: 1073742353, name: "CKA_WRAP_TEMPLATE", atype: AttrType::BytesType  },
    Attrmap { id: 1073742354, name: "CKA_UNWRAP_TEMPLATE", atype: AttrType::BytesType  },
    Attrmap { id: 1073742355, name: "CKA_DERIVE_TEMPLATE", atype: AttrType::BytesType  },
    Attrmap { id: 544, name: "CKA_OTP_FORMAT", atype: AttrType::NumType  },
    Attrmap { id: 545, name: "CKA_OTP_LENGTH", atype: AttrType::NumType  },
    Attrmap { id: 546, name: "CKA_OTP_TIME_INTERVAL", atype: AttrType::NumType  },
    Attrmap { id: 547, name: "CKA_OTP_USER_FRIENDLY_MODE", atype: AttrType::BoolType  },
    Attrmap { id: 548, name: "CKA_OTP_CHALLENGE_REQUIREMENT", atype: AttrType::NumType  },
    Attrmap { id: 549, name: "CKA_OTP_TIME_REQUIREMENT", atype: AttrType::NumType  },
    Attrmap { id: 550, name: "CKA_OTP_COUNTER_REQUIREMENT", atype: AttrType::NumType  },
    Attrmap { id: 551, name: "CKA_OTP_PIN_REQUIREMENT", atype: AttrType::NumType  },
    Attrmap { id: 558, name: "CKA_OTP_COUNTER", atype: AttrType::BytesType  },
    Attrmap { id: 559, name: "CKA_OTP_TIME", atype: AttrType::StringType  },
    Attrmap { id: 554, name: "CKA_OTP_USER_IDENTIFIER", atype: AttrType::StringType  },
    Attrmap { id: 555, name: "CKA_OTP_SERVICE_IDENTIFIER", atype: AttrType::StringType  },
    Attrmap { id: 556, name: "CKA_OTP_SERVICE_LOGO", atype: AttrType::BytesType  },
    Attrmap { id: 557, name: "CKA_OTP_SERVICE_LOGO_TYPE", atype: AttrType::StringType  },
    Attrmap { id: 592, name: "CKA_GOSTR3410_PARAMS", atype: AttrType::BytesType  },
    Attrmap { id: 593, name: "CKA_GOSTR3411_PARAMS", atype: AttrType::BytesType  },
    Attrmap { id: 594, name: "CKA_GOST28147_PARAMS", atype: AttrType::BytesType  },
    Attrmap { id: 768, name: "CKA_HW_FEATURE_TYPE", atype: AttrType::NumType  },
    Attrmap { id: 769, name: "CKA_RESET_ON_INIT", atype: AttrType::BoolType  },
    Attrmap { id: 770, name: "CKA_HAS_RESET", atype: AttrType::BoolType  },
    Attrmap { id: 1024, name: "CKA_PIXEL_X", atype: AttrType::NumType  },
    Attrmap { id: 1025, name: "CKA_PIXEL_Y", atype: AttrType::NumType  },
    Attrmap { id: 1026, name: "CKA_RESOLUTION", atype: AttrType::NumType  },
    Attrmap { id: 1027, name: "CKA_CHAR_ROWS", atype: AttrType::NumType  },
    Attrmap { id: 1028, name: "CKA_CHAR_COLUMNS", atype: AttrType::NumType  },
    Attrmap { id: 1029, name: "CKA_COLOR", atype: AttrType::BoolType  },
    Attrmap { id: 1030, name: "CKA_BITS_PER_PIXEL", atype: AttrType::NumType  },
    Attrmap { id: 1152, name: "CKA_CHAR_SETS", atype: AttrType::StringType  },
    Attrmap { id: 1153, name: "CKA_ENCODING_METHODS", atype: AttrType::StringType  },
    Attrmap { id: 1154, name: "CKA_MIME_TYPES", atype: AttrType::StringType  },
    Attrmap { id: 1280, name: "CKA_MECHANISM_TYPE", atype: AttrType::NumType  },
    Attrmap { id: 1281, name: "CKA_REQUIRED_CMS_ATTRIBUTES", atype: AttrType::BytesType  },
    Attrmap { id: 1282, name: "CKA_DEFAULT_CMS_ATTRIBUTES", atype: AttrType::BytesType  },
    Attrmap { id: 1283, name: "CKA_SUPPORTED_CMS_ATTRIBUTES", atype: AttrType::BytesType  },
    Attrmap { id: 1073743360, name: "CKA_ALLOWED_MECHANISMS", atype: AttrType::BytesType  },
    Attrmap { id: 1537, name: "CKA_PROFILE_ID", atype: AttrType::NumType  },
    Attrmap { id: 1538, name: "CKA_X2RATCHET_BAG", atype: AttrType::BytesType  },
    Attrmap { id: 1539, name: "CKA_X2RATCHET_BAGSIZE", atype: AttrType::NumType  },
    Attrmap { id: 1540, name: "CKA_X2RATCHET_BOBS1STMSG", atype: AttrType::BoolType  },
    Attrmap { id: 1541, name: "CKA_X2RATCHET_CKR", atype: AttrType::BytesType  },
    Attrmap { id: 1542, name: "CKA_X2RATCHET_CKS", atype: AttrType::BytesType  },
    Attrmap { id: 1543, name: "CKA_X2RATCHET_DHP", atype: AttrType::BytesType  },
    Attrmap { id: 1544, name: "CKA_X2RATCHET_DHR", atype: AttrType::BytesType  },
    Attrmap { id: 1545, name: "CKA_X2RATCHET_DHS", atype: AttrType::BytesType  },
    Attrmap { id: 1546, name: "CKA_X2RATCHET_HKR", atype: AttrType::BytesType  },
    Attrmap { id: 1547, name: "CKA_X2RATCHET_HKS", atype: AttrType::BytesType  },
    Attrmap { id: 1548, name: "CKA_X2RATCHET_ISALICE", atype: AttrType::BoolType  },
    Attrmap { id: 1549, name: "CKA_X2RATCHET_NHKR", atype: AttrType::BytesType  },
    Attrmap { id: 1550, name: "CKA_X2RATCHET_NHKS", atype: AttrType::BytesType  },
    Attrmap { id: 1551, name: "CKA_X2RATCHET_NR", atype: AttrType::NumType  },
    Attrmap { id: 1552, name: "CKA_X2RATCHET_NS", atype: AttrType::NumType  },
    Attrmap { id: 1553, name: "CKA_X2RATCHET_PNS", atype: AttrType::NumType  },
    Attrmap { id: 1554, name: "CKA_X2RATCHET_RK", atype: AttrType::BytesType  },
    Attrmap { id: 2147483648, name: "CKA_VENDOR_DEFINED", atype: AttrType::DenyType  },
    Attrmap { id: KRYATTR_MAX_LOGIN_ATTEMPTS, name: "KRYATTR_MAX_LOGIN_ATTEMPTS", atype: AttrType::NumType },
];

#[derive(Debug, Clone)]
pub struct Attribute {
    ck_type: CK_ULONG,
    attrtype: AttrType,
    value: Vec<u8>
}

impl Attribute {
    pub fn get_type(&self) -> CK_ULONG {
        self.ck_type
    }

    pub fn get_attrtype(&self) -> AttrType {
        self.attrtype
    }

    pub fn get_value(&self) -> &Vec<u8> {
        &self.value
    }

    pub fn match_ck_attr(&self, attr: &CK_ATTRIBUTE) -> bool {
        if self.ck_type != attr.type_ {
            return false;
        }
        match attr.to_buf() {
            Ok(buf) => buf == self.value,
            Err(_) => false
        }
    }

    pub fn name(&self) -> String {
        for a in &ATTRMAP {
            if a.id == self.ck_type {
                return a.name.to_string();
            }
        }
        return self.ck_type.to_string()
    }

    pub fn to_bool(&self) -> KResult<bool> {
        if self.value.len() != 1 {
            return err_rv!(CKR_ATTRIBUTE_VALUE_INVALID);
        }
        if self.value[0] == 0 {
            return Ok(false);
        }
        Ok(true)
    }
    fn to_bool_value(&self) -> Value {
        match self.to_bool() {
            Ok(b) => Value::Bool(b),
            Err(_) => Value::Null,
        }
    }

    pub fn to_ulong(&self) -> KResult<CK_ULONG> {
        if self.value.len() != 8 {
            return err_rv!(CKR_ATTRIBUTE_VALUE_INVALID);
        }
        Ok(u64::from_ne_bytes(self.value.as_slice().try_into().unwrap()) as CK_ULONG)
    }

    fn to_ulong_value(&self) -> Value {
        match self.to_ulong() {
            Ok(l) => Value::Number(Number::from(l as u64)),
            Err(_) => Value::Null,
        }
    }

    pub fn to_string(&self) -> KResult<String> {
        match std::str::from_utf8(&self.value) {
            Ok(s) => Ok(s.to_string()),
            Err(_) => err_rv!(CKR_ATTRIBUTE_VALUE_INVALID),
        }
    }

    fn to_string_value(&self) -> Value {
        match self.to_string() {
            Ok(s) => Value::String(s),
            Err(_) => self.to_b64_string_value()
        }
    }

    pub fn to_b64_string(&self) -> KResult<String> {
        Ok(BASE64.encode(&self.value))
    }

    fn to_b64_string_value(&self) -> Value {
        Value::String(BASE64.encode(&self.value))
    }

    pub fn to_date(&self) -> KResult<String> {
        if self.value.len() != 8 {
            return err_rv!(CKR_ATTRIBUTE_VALUE_INVALID);
        }
        let chars: [char; 10] = [
            char::from(self.value[0]),
            char::from(self.value[1]),
            char::from(self.value[2]),
            char::from(self.value[3]),
            '-',
            char::from(self.value[4]),
            char::from(self.value[5]),
            '-',
            char::from(self.value[6]),
            char::from(self.value[7]),
        ];
        Ok(chars.iter().collect())
    }

    fn to_date_value(&self) -> Value {
        match self.to_date() {
            Ok(d) => Value::String(d),
            Err(_) => Value::String(String::new()),
        }
    }

    pub fn json_value(&self) -> serde_json::Value {
        match self.attrtype {
            AttrType::BoolType => self.to_bool_value(),
            AttrType::NumType => self.to_ulong_value(),
            AttrType::StringType => self.to_string_value(),
            AttrType::BytesType => self.to_b64_string_value(),
            AttrType::DateType => self.to_date_value(),
            AttrType::DenyType => Value::Null,
        }
    }
}

fn from_bool(t: CK_ULONG, b: bool) -> Attribute {
    let mut a = Attribute {
        ck_type: t,
        attrtype: AttrType::BoolType,
        value: vec![0],
    };
    if b {
        a.value[0] = 1;
    }
    a
}

pub fn from_type_bool(t: CK_ULONG, b: bool) -> KResult<Attribute> {
    for a in &ATTRMAP {
        if a.id == t {
            if a.atype == AttrType::BoolType {
                return Ok(from_bool(t, b));
            }
            return err_rv!(CKR_ATTRIBUTE_VALUE_INVALID);
        }
    }
    err_not_found!(t.to_string())
}

pub fn from_string_bool(s: String, b: bool) -> KResult<Attribute> {
    for a in &ATTRMAP {
        if a.name == &s {
            if a.atype == AttrType::BoolType {
                return Ok(from_bool(a.id, b));
            }
            return err_rv!(CKR_ATTRIBUTE_VALUE_INVALID);
        }
    }
    err_not_found!(s)
}

fn from_ulong(t: CK_ULONG, u: CK_ULONG) -> Attribute {
    Attribute {
        ck_type: t,
        attrtype: AttrType::NumType,
        value: Vec::from((u as u64).to_ne_bytes()),
    }
}

pub fn from_type_ulong(t: CK_ULONG, u: CK_ULONG) -> KResult<Attribute> {
    for a in &ATTRMAP {
        if a.id == t {
            if a.atype == AttrType::NumType {
                return Ok(from_ulong(t, u));
            }
            return err_rv!(CKR_ATTRIBUTE_VALUE_INVALID);
        }
    }
    err_not_found!(t.to_string())
}

pub fn from_string_ulong(s: String, u: CK_ULONG) -> KResult<Attribute> {
    for a in &ATTRMAP {
        if a.name == &s {
            if a.atype == AttrType::NumType {
                return Ok(from_ulong(a.id, u));
            }
            return err_rv!(CKR_ATTRIBUTE_VALUE_INVALID);
        }
    }
    err_not_found!(s)
}

fn from_string(t: CK_ULONG, s: String) -> Attribute {
    Attribute {
        ck_type: t,
        attrtype: AttrType::StringType,
        value: Vec::from(s.as_bytes()),
    }
}

pub fn from_type_string(t: CK_ULONG, s: String) -> KResult<Attribute> {
    for a in &ATTRMAP {
        if a.id == t {
            if a.atype == AttrType::StringType {
                return Ok(from_string(t, s));
            }
            return err_rv!(CKR_ATTRIBUTE_VALUE_INVALID);
        }
    }
    err_not_found!(t.to_string())
}

pub fn from_string_string(s: String, v: String) -> KResult<Attribute> {
    for a in &ATTRMAP {
        if a.name == &s {
            if a.atype == AttrType::StringType {
                return Ok(from_string(a.id, v));
            }
            return err_rv!(CKR_ATTRIBUTE_VALUE_INVALID);
        }
    }
    err_not_found!(s)
}

fn from_bytes(t: CK_ULONG, v: Vec<u8>) -> Attribute {
    Attribute {
        ck_type: t,
        attrtype: AttrType::BytesType,
        value: v,
    }
}

pub fn from_type_bytes(t: CK_ULONG, v: Vec<u8>) -> KResult<Attribute> {
    for a in &ATTRMAP {
        if a.id == t {
            if a.atype == AttrType::BytesType {
                return Ok(from_bytes(t, v));
            }
            return err_rv!(CKR_ATTRIBUTE_VALUE_INVALID);
        }
    }
    err_not_found!(t.to_string())
}

pub fn from_string_bytes(s: String, v: Vec<u8>) -> KResult<Attribute> {
    for a in &ATTRMAP {
        if a.name == &s {
            if a.atype == AttrType::BytesType {
                return Ok(from_bytes(a.id, v));
            }
            return err_rv!(CKR_ATTRIBUTE_VALUE_INVALID);
        }
    }
    err_not_found!(s)
}

pub fn from_value(s: String, v: &Value) -> KResult<Attribute> {
    /* skips invalid types */
    for a in &ATTRMAP {
        if a.name == &s {
            match a.atype {
                AttrType::BoolType => {
                    match v.as_bool() {
                        Some(b) => return Ok(from_bool(a.id, b)),
                        None => return err_rv!(CKR_ATTRIBUTE_VALUE_INVALID),
                    }
                },
                AttrType::NumType => {
                    match v.as_u64() {
                        Some(n) => return Ok(from_ulong(a.id, n as CK_ULONG)),
                        None => return err_rv!(CKR_ATTRIBUTE_VALUE_INVALID),
                    }

                },
                AttrType::StringType => {
                    match v.as_str() {
                        Some(s) => return Ok(from_string(a.id, s.to_string())),
                        None => return err_rv!(CKR_ATTRIBUTE_VALUE_INVALID),
                    }
                },
                AttrType::BytesType => {
                    match v.as_str() {
                        Some(s) => {
                            let len = match BASE64.decode_len(s.len()) {
                                Ok(l) => l,
                                Err(_) => return err_rv!(CKR_GENERAL_ERROR),
                            };
                            let mut v = vec![0; len];
                            match BASE64.decode_mut(s.as_bytes(), &mut v) {
                                Ok(l) => return Ok(from_bytes(a.id, v[0..l].to_vec())),
                                Err(_) => return err_rv!(CKR_GENERAL_ERROR),
                            }
                        },
                        None => return err_rv!(CKR_ATTRIBUTE_VALUE_INVALID),
                    }
                },
                AttrType::DateType => (),
                AttrType::DenyType => (),
            }
        }
    }
    err_not_found!(s)
}


impl CK_ATTRIBUTE {
    pub fn to_ulong(self) -> KResult<CK_ULONG> {
        if self.ulValueLen != std::mem::size_of::<CK_ULONG>() as CK_ULONG {
            return err_rv!(CKR_ATTRIBUTE_VALUE_INVALID);
        }
        let val: &[CK_ULONG] = unsafe {
            std::slice::from_raw_parts(self.pValue as *const _, 1)
        };
        Ok(val[0])
    }
    pub fn to_bool(self) -> KResult<bool> {
        if self.ulValueLen != std::mem::size_of::<CK_BBOOL>() as CK_ULONG {
            return err_rv!(CKR_ATTRIBUTE_VALUE_INVALID);
        }
        let val: &[CK_BBOOL] = unsafe {
            std::slice::from_raw_parts(self.pValue as *const _, 1)
        };
        if val[0] == 0 {
            Ok(false)
        } else {
            Ok(true)
        }
    }
    pub fn to_string(self) ->KResult<String> {
        let buf: &[u8] = unsafe {
            std::slice::from_raw_parts(self.pValue as *const _, self.ulValueLen as usize)
        };
        match std::str::from_utf8(buf) {
            Ok(s) => Ok(s.to_string()),
            Err(_) => err_rv!(CKR_ATTRIBUTE_VALUE_INVALID),
        }
    }
    pub fn to_buf(self) ->KResult<Vec<u8>> {
        let buf: &[u8] = unsafe {
            std::slice::from_raw_parts(self.pValue as *const _, self.ulValueLen as usize)
        };
        Ok(buf.to_vec())
    }
}
