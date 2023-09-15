// Copyright 2023 Simo Sorce
// See LICENSE.txt file for terms

use data_encoding::BASE64;
use serde_json::{Number, Value};

use super::error;
use super::interface;

use super::{err_not_found, err_rv};
use error::{KError, KResult};
use interface::*;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum AttrType {
    BoolType,
    NumType,
    StringType,
    BytesType,
    DateType,
    DenyType,
    IgnoreType,
}

#[derive(Debug)]
struct Attrmap<'a> {
    id: CK_ULONG,
    name: &'a str,
    atype: AttrType,
}

macro_rules! attrmap_element {
    ($id:expr; as $attrtype:ident) => {
        Attrmap {
            id: $id,
            name: stringify!($id),
            atype: AttrType::$attrtype,
        }
    };
}

static ATTRMAP: [Attrmap<'_>; 126] = [
    attrmap_element!(CKA_CLASS; as NumType),
    attrmap_element!(CKA_TOKEN; as BoolType),
    attrmap_element!(CKA_PRIVATE; as BoolType),
    attrmap_element!(CKA_LABEL; as StringType),
    attrmap_element!(CKA_UNIQUE_ID; as StringType),
    attrmap_element!(CKA_APPLICATION; as StringType),
    attrmap_element!(CKA_VALUE; as BytesType),
    attrmap_element!(CKA_OBJECT_ID; as BytesType),
    attrmap_element!(CKA_CERTIFICATE_TYPE; as NumType),
    attrmap_element!(CKA_ISSUER; as BytesType),
    attrmap_element!(CKA_SERIAL_NUMBER; as BytesType),
    attrmap_element!(CKA_AC_ISSUER; as BytesType),
    attrmap_element!(CKA_OWNER; as BytesType),
    attrmap_element!(CKA_ATTR_TYPES; as BytesType),
    attrmap_element!(CKA_TRUSTED; as BoolType),
    attrmap_element!(CKA_CERTIFICATE_CATEGORY; as NumType),
    attrmap_element!(CKA_JAVA_MIDP_SECURITY_DOMAIN; as NumType),
    attrmap_element!(CKA_URL; as StringType),
    attrmap_element!(CKA_HASH_OF_SUBJECT_PUBLIC_KEY; as BytesType),
    attrmap_element!(CKA_HASH_OF_ISSUER_PUBLIC_KEY; as BytesType),
    attrmap_element!(CKA_NAME_HASH_ALGORITHM; as NumType),
    attrmap_element!(CKA_CHECK_VALUE; as IgnoreType),
    attrmap_element!(CKA_KEY_TYPE; as NumType),
    attrmap_element!(CKA_SUBJECT; as BytesType),
    attrmap_element!(CKA_ID; as BytesType),
    attrmap_element!(CKA_SENSITIVE; as BoolType),
    attrmap_element!(CKA_ENCRYPT; as BoolType),
    attrmap_element!(CKA_DECRYPT; as BoolType),
    attrmap_element!(CKA_WRAP; as BoolType),
    attrmap_element!(CKA_UNWRAP; as BoolType),
    attrmap_element!(CKA_SIGN; as BoolType),
    attrmap_element!(CKA_SIGN_RECOVER; as BoolType),
    attrmap_element!(CKA_VERIFY; as BoolType),
    attrmap_element!(CKA_VERIFY_RECOVER; as BoolType),
    attrmap_element!(CKA_DERIVE; as BoolType),
    attrmap_element!(CKA_START_DATE; as DateType),
    attrmap_element!(CKA_END_DATE; as DateType),
    attrmap_element!(CKA_MODULUS; as BytesType),
    attrmap_element!(CKA_MODULUS_BITS; as NumType),
    attrmap_element!(CKA_PUBLIC_EXPONENT; as BytesType),
    attrmap_element!(CKA_PRIVATE_EXPONENT; as BytesType),
    attrmap_element!(CKA_PRIME_1; as BytesType),
    attrmap_element!(CKA_PRIME_2; as BytesType),
    attrmap_element!(CKA_EXPONENT_1; as BytesType),
    attrmap_element!(CKA_EXPONENT_2; as BytesType),
    attrmap_element!(CKA_COEFFICIENT; as BytesType),
    attrmap_element!(CKA_PUBLIC_KEY_INFO; as BytesType),
    attrmap_element!(CKA_PRIME; as BytesType),
    attrmap_element!(CKA_SUBPRIME; as BytesType),
    attrmap_element!(CKA_BASE; as BytesType),
    attrmap_element!(CKA_PRIME_BITS; as BytesType),
    attrmap_element!(CKA_SUBPRIME_BITS; as NumType),
    /*attrmap_element!(CKA_SUB_PRIME_BITS; as NumType),*/
    attrmap_element!(CKA_VALUE_BITS; as NumType),
    attrmap_element!(CKA_VALUE_LEN; as NumType),
    attrmap_element!(CKA_EXTRACTABLE; as BoolType),
    attrmap_element!(CKA_LOCAL; as BoolType),
    attrmap_element!(CKA_NEVER_EXTRACTABLE; as BoolType),
    attrmap_element!(CKA_ALWAYS_SENSITIVE; as BoolType),
    attrmap_element!(CKA_KEY_GEN_MECHANISM; as NumType),
    attrmap_element!(CKA_MODIFIABLE; as BoolType),
    attrmap_element!(CKA_COPYABLE; as BoolType),
    attrmap_element!(CKA_DESTROYABLE; as BoolType),
    /*attrmap_element!(CKA_ECDSA_PARAMS; as BytesType),*/
    attrmap_element!(CKA_EC_PARAMS; as BytesType),
    attrmap_element!(CKA_EC_POINT; as BytesType),
    attrmap_element!(CKA_SECONDARY_AUTH; as NumType),
    attrmap_element!(CKA_AUTH_PIN_FLAGS; as NumType),
    attrmap_element!(CKA_ALWAYS_AUTHENTICATE; as BoolType),
    attrmap_element!(CKA_WRAP_WITH_TRUSTED; as BoolType),
    attrmap_element!(CKA_WRAP_TEMPLATE; as BytesType),
    attrmap_element!(CKA_UNWRAP_TEMPLATE; as BytesType),
    attrmap_element!(CKA_DERIVE_TEMPLATE; as BytesType),
    attrmap_element!(CKA_OTP_FORMAT; as NumType),
    attrmap_element!(CKA_OTP_LENGTH; as NumType),
    attrmap_element!(CKA_OTP_TIME_INTERVAL; as NumType),
    attrmap_element!(CKA_OTP_USER_FRIENDLY_MODE; as BoolType),
    attrmap_element!(CKA_OTP_CHALLENGE_REQUIREMENT; as NumType),
    attrmap_element!(CKA_OTP_TIME_REQUIREMENT; as NumType),
    attrmap_element!(CKA_OTP_COUNTER_REQUIREMENT; as NumType),
    attrmap_element!(CKA_OTP_PIN_REQUIREMENT; as NumType),
    attrmap_element!(CKA_OTP_COUNTER; as BytesType),
    attrmap_element!(CKA_OTP_TIME; as StringType),
    attrmap_element!(CKA_OTP_USER_IDENTIFIER; as StringType),
    attrmap_element!(CKA_OTP_SERVICE_IDENTIFIER; as StringType),
    attrmap_element!(CKA_OTP_SERVICE_LOGO; as BytesType),
    attrmap_element!(CKA_OTP_SERVICE_LOGO_TYPE; as StringType),
    attrmap_element!(CKA_GOSTR3410_PARAMS; as BytesType),
    attrmap_element!(CKA_GOSTR3411_PARAMS; as BytesType),
    attrmap_element!(CKA_GOST28147_PARAMS; as BytesType),
    attrmap_element!(CKA_HW_FEATURE_TYPE; as NumType),
    attrmap_element!(CKA_RESET_ON_INIT; as BoolType),
    attrmap_element!(CKA_HAS_RESET; as BoolType),
    attrmap_element!(CKA_PIXEL_X; as NumType),
    attrmap_element!(CKA_PIXEL_Y; as NumType),
    attrmap_element!(CKA_RESOLUTION; as NumType),
    attrmap_element!(CKA_CHAR_ROWS; as NumType),
    attrmap_element!(CKA_CHAR_COLUMNS; as NumType),
    attrmap_element!(CKA_COLOR; as BoolType),
    attrmap_element!(CKA_BITS_PER_PIXEL; as NumType),
    attrmap_element!(CKA_CHAR_SETS; as StringType),
    attrmap_element!(CKA_ENCODING_METHODS; as StringType),
    attrmap_element!(CKA_MIME_TYPES; as StringType),
    attrmap_element!(CKA_MECHANISM_TYPE; as NumType),
    attrmap_element!(CKA_REQUIRED_CMS_ATTRIBUTES; as BytesType),
    attrmap_element!(CKA_DEFAULT_CMS_ATTRIBUTES; as BytesType),
    attrmap_element!(CKA_SUPPORTED_CMS_ATTRIBUTES; as BytesType),
    attrmap_element!(CKA_ALLOWED_MECHANISMS; as BytesType),
    attrmap_element!(CKA_PROFILE_ID; as NumType),
    attrmap_element!(CKA_X2RATCHET_BAG; as BytesType),
    attrmap_element!(CKA_X2RATCHET_BAGSIZE; as NumType),
    attrmap_element!(CKA_X2RATCHET_BOBS1STMSG; as BoolType),
    attrmap_element!(CKA_X2RATCHET_CKR; as BytesType),
    attrmap_element!(CKA_X2RATCHET_CKS; as BytesType),
    attrmap_element!(CKA_X2RATCHET_DHP; as BytesType),
    attrmap_element!(CKA_X2RATCHET_DHR; as BytesType),
    attrmap_element!(CKA_X2RATCHET_DHS; as BytesType),
    attrmap_element!(CKA_X2RATCHET_HKR; as BytesType),
    attrmap_element!(CKA_X2RATCHET_HKS; as BytesType),
    attrmap_element!(CKA_X2RATCHET_ISALICE; as BoolType),
    attrmap_element!(CKA_X2RATCHET_NHKR; as BytesType),
    attrmap_element!(CKA_X2RATCHET_NHKS; as BytesType),
    attrmap_element!(CKA_X2RATCHET_NR; as NumType),
    attrmap_element!(CKA_X2RATCHET_NS; as NumType),
    attrmap_element!(CKA_X2RATCHET_PNS; as NumType),
    attrmap_element!(CKA_X2RATCHET_RK; as BytesType),
    attrmap_element!(CKA_VENDOR_DEFINED; as DenyType),
    attrmap_element!(KRYATTR_MAX_LOGIN_ATTEMPTS; as NumType),
];

#[derive(Debug, Clone)]
pub struct Attribute {
    ck_type: CK_ULONG,
    attrtype: AttrType,
    value: Vec<u8>,
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
            Err(_) => false,
        }
    }

    pub fn name(&self) -> String {
        for a in &ATTRMAP {
            if a.id == self.ck_type {
                return a.name.to_string();
            }
        }
        return self.ck_type.to_string();
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
        Ok(
            u64::from_ne_bytes(self.value.as_slice().try_into().unwrap())
                as CK_ULONG,
        )
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
            Err(_) => self.to_b64_string_value(),
        }
    }

    pub fn to_bytes(&self) -> KResult<&Vec<u8>> {
        Ok(&self.value)
    }

    pub fn to_b64_string(&self) -> KResult<String> {
        Ok(BASE64.encode(&self.value))
    }

    fn to_b64_string_value(&self) -> Value {
        Value::String(BASE64.encode(&self.value))
    }

    pub fn to_date_string(&self) -> KResult<String> {
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
        match self.to_date_string() {
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
            AttrType::IgnoreType => Value::Null,
            AttrType::DenyType => Value::Null,
        }
    }
}

macro_rules! conversion_from_type {
    (make $fn1:ident; $fn2:ident; $fn3:ident; from $rtype:ty; as $atype:ident; via $conv:ident) => {
        pub fn $fn1(t: CK_ULONG, val: $rtype) -> Attribute {
            Attribute {
                ck_type: t,
                attrtype: AttrType::$atype,
                value: $conv(val),
            }
        }

        pub fn $fn2(t: CK_ULONG, val: $rtype) -> KResult<Attribute> {
            for a in &ATTRMAP {
                if a.id == t {
                    if a.atype == AttrType::$atype {
                        return Ok($fn1(t, val));
                    }
                    return err_rv!(CKR_ATTRIBUTE_VALUE_INVALID);
                }
            }
            err_not_found!(t.to_string())
        }

        pub fn $fn3(s: String, val: $rtype) -> KResult<Attribute> {
            for a in &ATTRMAP {
                if a.name == &s {
                    if a.atype == AttrType::$atype {
                        return Ok($fn1(a.id, val));
                    }
                    return err_rv!(CKR_ATTRIBUTE_VALUE_INVALID);
                }
            }
            err_not_found!(s)
        }
    };
}

fn bool_to_vec(val: bool) -> Vec<u8> {
    Vec::from(if val { &[1 as u8][..] } else { &[0 as u8][..] })
}
conversion_from_type! {make from_bool; from_type_bool; from_string_bool; from bool; as BoolType; via bool_to_vec}

fn ulong_to_vec(val: CK_ULONG) -> Vec<u8> {
    Vec::from((val as u64).to_ne_bytes())
}
conversion_from_type! {make from_ulong; from_type_ulong; from_string_ulong; from CK_ULONG; as NumType; via ulong_to_vec}

fn string_to_vec(val: String) -> Vec<u8> {
    Vec::from(val.as_bytes())
}
conversion_from_type! {make from_string; from_type_string; from_string_string; from String; as StringType; via string_to_vec}

fn bytes_to_vec(val: Vec<u8>) -> Vec<u8> {
    val
}
conversion_from_type! {make from_bytes; from_type_bytes; from_string_bytes; from Vec<u8>; as BytesType; via bytes_to_vec}

fn date_to_vec(val: CK_DATE) -> Vec<u8> {
    let mut v = Vec::with_capacity(8);
    v[0] = val.year[0];
    v[1] = val.year[1];
    v[2] = val.year[2];
    v[3] = val.year[3];
    v[4] = val.month[0];
    v[5] = val.month[1];
    v[6] = val.day[0];
    v[7] = val.day[1];
    v
}

conversion_from_type! {make from_date; from_type_date; from_string_date; from CK_DATE; as DateType; via date_to_vec}

fn vec_to_date(val: Vec<u8>) -> CK_DATE {
    CK_DATE {
        year: [val[0], val[1], val[2], val[3]],
        month: [val[5], val[6]],
        day: [val[8], val[9]],
    }
}

const ASCII_DASH: u8 = 0x2D;
const MIN_ASCII_DIGIT: u8 = 0x30;
const MAX_ASCII_DIGIT: u8 = 0x39;

fn vec_to_date_validate(val: Vec<u8>) -> KResult<CK_DATE> {
    if val.len() != 8 {
        return err_rv!(CKR_ATTRIBUTE_VALUE_INVALID);
    }
    for n in val.iter() {
        if *n < MIN_ASCII_DIGIT || *n > MAX_ASCII_DIGIT {
            return err_rv!(CKR_ATTRIBUTE_VALUE_INVALID);
        }
    }
    Ok(vec_to_date(val))
}

fn string_to_ck_date(date: &str) -> KResult<CK_DATE> {
    let s = date.as_bytes().to_vec();
    if s.len() != 10 {
        return err_rv!(CKR_ATTRIBUTE_VALUE_INVALID);
    }
    if s[4] != ASCII_DASH || s[7] != ASCII_DASH {
        return err_rv!(CKR_ATTRIBUTE_VALUE_INVALID);
    }
    let mut buf = Vec::with_capacity(8);
    buf[0] = s[0];
    buf[1] = s[1];
    buf[2] = s[2];
    buf[3] = s[3];
    buf[4] = s[5];
    buf[5] = s[6];
    buf[6] = s[8];
    buf[7] = s[9];
    vec_to_date_validate(buf)
}

pub fn from_date_bytes(t: CK_ULONG, val: Vec<u8>) -> Attribute {
    Attribute {
        ck_type: t,
        attrtype: AttrType::DateType,
        value: val,
    }
}

pub fn from_ignore(t: CK_ULONG) -> Attribute {
    Attribute {
        ck_type: t,
        attrtype: AttrType::IgnoreType,
        value: Vec::new(),
    }
}

pub fn from_value(s: String, v: &Value) -> KResult<Attribute> {
    /* skips invalid types */
    for a in &ATTRMAP {
        if a.name == &s {
            match a.atype {
                AttrType::BoolType => match v.as_bool() {
                    Some(b) => return Ok(from_bool(a.id, b)),
                    None => return err_rv!(CKR_ATTRIBUTE_VALUE_INVALID),
                },
                AttrType::NumType => match v.as_u64() {
                    Some(n) => return Ok(from_ulong(a.id, n as CK_ULONG)),
                    None => return err_rv!(CKR_ATTRIBUTE_VALUE_INVALID),
                },
                AttrType::StringType => match v.as_str() {
                    Some(s) => return Ok(from_string(a.id, s.to_string())),
                    None => return err_rv!(CKR_ATTRIBUTE_VALUE_INVALID),
                },
                AttrType::BytesType => match v.as_str() {
                    Some(s) => {
                        let len = match BASE64.decode_len(s.len()) {
                            Ok(l) => l,
                            Err(_) => return err_rv!(CKR_GENERAL_ERROR),
                        };
                        let mut v = vec![0; len];
                        match BASE64.decode_mut(s.as_bytes(), &mut v) {
                            Ok(l) => {
                                return Ok(from_bytes(a.id, v[0..l].to_vec()))
                            }
                            Err(_) => return err_rv!(CKR_GENERAL_ERROR),
                        }
                    }
                    None => return err_rv!(CKR_ATTRIBUTE_VALUE_INVALID),
                },
                AttrType::DateType => match v.as_str() {
                    Some(s) => {
                        if s.len() == 0 {
                            /* special case for default empty value */
                            return Ok(from_date_bytes(a.id, Vec::new()));
                        } else {
                            return Ok(from_date(a.id, string_to_ck_date(&s)?));
                        }
                    }
                    None => return err_rv!(CKR_ATTRIBUTE_VALUE_INVALID),
                },
                AttrType::DenyType => (),
                AttrType::IgnoreType => (),
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
        let val: &[CK_ULONG] =
            unsafe { std::slice::from_raw_parts(self.pValue as *const _, 1) };
        Ok(val[0])
    }
    pub fn to_bool(self) -> KResult<bool> {
        if self.ulValueLen != std::mem::size_of::<CK_BBOOL>() as CK_ULONG {
            return err_rv!(CKR_ATTRIBUTE_VALUE_INVALID);
        }
        let val: &[CK_BBOOL] =
            unsafe { std::slice::from_raw_parts(self.pValue as *const _, 1) };
        if val[0] == 0 {
            Ok(false)
        } else {
            Ok(true)
        }
    }
    pub fn to_string(self) -> KResult<String> {
        let buf: &[u8] = unsafe {
            std::slice::from_raw_parts(
                self.pValue as *const _,
                self.ulValueLen as usize,
            )
        };
        match std::str::from_utf8(buf) {
            Ok(s) => Ok(s.to_string()),
            Err(_) => err_rv!(CKR_ATTRIBUTE_VALUE_INVALID),
        }
    }
    pub fn to_buf(self) -> KResult<Vec<u8>> {
        let buf: &[u8] = unsafe {
            std::slice::from_raw_parts(
                self.pValue as *const _,
                self.ulValueLen as usize,
            )
        };
        Ok(buf.to_vec())
    }
    pub fn to_date(self) -> KResult<CK_DATE> {
        if self.ulValueLen != 8 {
            return err_rv!(CKR_ATTRIBUTE_VALUE_INVALID);
        }
        let buf: &[u8] = unsafe {
            std::slice::from_raw_parts(
                self.pValue as *const _,
                self.ulValueLen as usize,
            )
        };
        vec_to_date_validate(buf.to_vec())
    }

    pub fn to_attribute(self) -> KResult<Attribute> {
        let mut atype = AttrType::DenyType;
        for amap in &ATTRMAP {
            if amap.id == self.type_ {
                atype = amap.atype;
                break;
            }
        }
        match atype {
            AttrType::BoolType => Ok(from_bool(self.type_, self.to_bool()?)),
            AttrType::NumType => Ok(from_ulong(self.type_, self.to_ulong()?)),
            AttrType::StringType => {
                Ok(from_string(self.type_, self.to_string()?))
            }
            AttrType::BytesType => Ok(from_bytes(self.type_, self.to_buf()?)),
            AttrType::DateType => Ok(from_date(self.type_, self.to_date()?)),
            AttrType::DenyType => err_rv!(CKR_ATTRIBUTE_TYPE_INVALID),
            AttrType::IgnoreType => Ok(from_ignore(self.type_)),
        }
    }
}
