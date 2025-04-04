// Copyright 2023 Simo Sorce
// See LICENSE.txt file for terms

use std::borrow::Cow;

use crate::error::{Error, Result};
use crate::interface::*;
use crate::misc::{bytes_to_vec, sizeof, void_ptr, zeromem};

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

#[derive(Clone, Copy, Debug)]
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

const ATTRMAP_SIZE: usize = if cfg!(feature = "pkcs11_3_2") {
    158
} else {
    131
};
static ATTRMAP: [Attrmap<'_>; ATTRMAP_SIZE] = {
    /* PKCS11 3.0 defined attributes */
    let mut amap: [Attrmap<'_>; ATTRMAP_SIZE] =
        [attrmap_element!(0; as IgnoreType); ATTRMAP_SIZE];
    amap[0] = attrmap_element!(CKA_CLASS; as NumType);
    amap[1] = attrmap_element!(CKA_TOKEN; as BoolType);
    amap[2] = attrmap_element!(CKA_PRIVATE; as BoolType);
    amap[3] = attrmap_element!(CKA_LABEL; as StringType);
    amap[4] = attrmap_element!(CKA_UNIQUE_ID; as StringType);
    amap[5] = attrmap_element!(CKA_APPLICATION; as StringType);
    amap[6] = attrmap_element!(CKA_VALUE; as BytesType);
    amap[7] = attrmap_element!(CKA_OBJECT_ID; as BytesType);
    amap[8] = attrmap_element!(CKA_CERTIFICATE_TYPE; as NumType);
    amap[9] = attrmap_element!(CKA_ISSUER; as BytesType);
    amap[10] = attrmap_element!(CKA_SERIAL_NUMBER; as BytesType);
    amap[11] = attrmap_element!(CKA_AC_ISSUER; as BytesType);
    amap[12] = attrmap_element!(CKA_OWNER; as BytesType);
    amap[13] = attrmap_element!(CKA_ATTR_TYPES; as BytesType);
    amap[14] = attrmap_element!(CKA_TRUSTED; as BoolType);
    amap[15] = attrmap_element!(CKA_CERTIFICATE_CATEGORY; as NumType);
    amap[16] = attrmap_element!(CKA_JAVA_MIDP_SECURITY_DOMAIN; as NumType);
    amap[17] = attrmap_element!(CKA_URL; as StringType);
    amap[18] = attrmap_element!(CKA_HASH_OF_SUBJECT_PUBLIC_KEY; as BytesType);
    amap[19] = attrmap_element!(CKA_HASH_OF_ISSUER_PUBLIC_KEY; as BytesType);
    amap[20] = attrmap_element!(CKA_NAME_HASH_ALGORITHM; as NumType);
    amap[21] = attrmap_element!(CKA_CHECK_VALUE; as IgnoreType);
    amap[22] = attrmap_element!(CKA_KEY_TYPE; as NumType);
    amap[23] = attrmap_element!(CKA_SUBJECT; as BytesType);
    amap[24] = attrmap_element!(CKA_ID; as BytesType);
    amap[25] = attrmap_element!(CKA_SENSITIVE; as BoolType);
    amap[26] = attrmap_element!(CKA_ENCRYPT; as BoolType);
    amap[27] = attrmap_element!(CKA_DECRYPT; as BoolType);
    amap[28] = attrmap_element!(CKA_WRAP; as BoolType);
    amap[29] = attrmap_element!(CKA_UNWRAP; as BoolType);
    amap[30] = attrmap_element!(CKA_SIGN; as BoolType);
    amap[31] = attrmap_element!(CKA_SIGN_RECOVER; as BoolType);
    amap[32] = attrmap_element!(CKA_VERIFY; as BoolType);
    amap[33] = attrmap_element!(CKA_VERIFY_RECOVER; as BoolType);
    amap[34] = attrmap_element!(CKA_DERIVE; as BoolType);
    amap[35] = attrmap_element!(CKA_START_DATE; as DateType);
    amap[36] = attrmap_element!(CKA_END_DATE; as DateType);
    amap[37] = attrmap_element!(CKA_MODULUS; as BytesType);
    amap[38] = attrmap_element!(CKA_MODULUS_BITS; as NumType);
    amap[39] = attrmap_element!(CKA_PUBLIC_EXPONENT; as BytesType);
    amap[40] = attrmap_element!(CKA_PRIVATE_EXPONENT; as BytesType);
    amap[41] = attrmap_element!(CKA_PRIME_1; as BytesType);
    amap[42] = attrmap_element!(CKA_PRIME_2; as BytesType);
    amap[43] = attrmap_element!(CKA_EXPONENT_1; as BytesType);
    amap[44] = attrmap_element!(CKA_EXPONENT_2; as BytesType);
    amap[45] = attrmap_element!(CKA_COEFFICIENT; as BytesType);
    amap[46] = attrmap_element!(CKA_PUBLIC_KEY_INFO; as BytesType);
    amap[47] = attrmap_element!(CKA_PRIME; as BytesType);
    amap[48] = attrmap_element!(CKA_SUBPRIME; as BytesType);
    amap[49] = attrmap_element!(CKA_BASE; as BytesType);
    amap[50] = attrmap_element!(CKA_PRIME_BITS; as BytesType);
    amap[51] = attrmap_element!(CKA_SUBPRIME_BITS; as NumType);
    amap[52] = attrmap_element!(CKA_VALUE_BITS; as NumType);
    amap[53] = attrmap_element!(CKA_VALUE_LEN; as NumType);
    amap[54] = attrmap_element!(CKA_EXTRACTABLE; as BoolType);
    amap[55] = attrmap_element!(CKA_LOCAL; as BoolType);
    amap[56] = attrmap_element!(CKA_NEVER_EXTRACTABLE; as BoolType);
    amap[57] = attrmap_element!(CKA_ALWAYS_SENSITIVE; as BoolType);
    amap[58] = attrmap_element!(CKA_KEY_GEN_MECHANISM; as NumType);
    amap[59] = attrmap_element!(CKA_MODIFIABLE; as BoolType);
    amap[60] = attrmap_element!(CKA_COPYABLE; as BoolType);
    amap[61] = attrmap_element!(CKA_DESTROYABLE; as BoolType);
    amap[62] = attrmap_element!(CKA_EC_PARAMS; as BytesType);
    amap[63] = attrmap_element!(CKA_EC_POINT; as BytesType);
    amap[64] = attrmap_element!(CKA_ALWAYS_AUTHENTICATE; as BoolType);
    amap[65] = attrmap_element!(CKA_WRAP_WITH_TRUSTED; as BoolType);
    amap[66] = attrmap_element!(CKA_WRAP_TEMPLATE; as BytesType);
    amap[67] = attrmap_element!(CKA_UNWRAP_TEMPLATE; as BytesType);
    amap[68] = attrmap_element!(CKA_DERIVE_TEMPLATE; as BytesType);
    amap[69] = attrmap_element!(CKA_OTP_FORMAT; as NumType);
    amap[70] = attrmap_element!(CKA_OTP_LENGTH; as NumType);
    amap[71] = attrmap_element!(CKA_OTP_TIME_INTERVAL; as NumType);
    amap[72] = attrmap_element!(CKA_OTP_USER_FRIENDLY_MODE; as BoolType);
    amap[73] = attrmap_element!(CKA_OTP_CHALLENGE_REQUIREMENT; as NumType);
    amap[74] = attrmap_element!(CKA_OTP_TIME_REQUIREMENT; as NumType);
    amap[75] = attrmap_element!(CKA_OTP_COUNTER_REQUIREMENT; as NumType);
    amap[76] = attrmap_element!(CKA_OTP_PIN_REQUIREMENT; as NumType);
    amap[77] = attrmap_element!(CKA_OTP_COUNTER; as BytesType);
    amap[78] = attrmap_element!(CKA_OTP_TIME; as StringType);
    amap[79] = attrmap_element!(CKA_OTP_USER_IDENTIFIER; as StringType);
    amap[80] = attrmap_element!(CKA_OTP_SERVICE_IDENTIFIER; as StringType);
    amap[81] = attrmap_element!(CKA_OTP_SERVICE_LOGO; as BytesType);
    amap[82] = attrmap_element!(CKA_OTP_SERVICE_LOGO_TYPE; as StringType);
    amap[83] = attrmap_element!(CKA_GOSTR3410_PARAMS; as BytesType);
    amap[84] = attrmap_element!(CKA_GOSTR3411_PARAMS; as BytesType);
    amap[85] = attrmap_element!(CKA_GOST28147_PARAMS; as BytesType);
    amap[86] = attrmap_element!(CKA_HW_FEATURE_TYPE; as NumType);
    amap[87] = attrmap_element!(CKA_RESET_ON_INIT; as BoolType);
    amap[88] = attrmap_element!(CKA_HAS_RESET; as BoolType);
    amap[89] = attrmap_element!(CKA_PIXEL_X; as NumType);
    amap[90] = attrmap_element!(CKA_PIXEL_Y; as NumType);
    amap[91] = attrmap_element!(CKA_RESOLUTION; as NumType);
    amap[92] = attrmap_element!(CKA_CHAR_ROWS; as NumType);
    amap[93] = attrmap_element!(CKA_CHAR_COLUMNS; as NumType);
    amap[94] = attrmap_element!(CKA_COLOR; as BoolType);
    amap[95] = attrmap_element!(CKA_BITS_PER_PIXEL; as NumType);
    amap[96] = attrmap_element!(CKA_CHAR_SETS; as StringType);
    amap[97] = attrmap_element!(CKA_ENCODING_METHODS; as StringType);
    amap[98] = attrmap_element!(CKA_MIME_TYPES; as StringType);
    amap[99] = attrmap_element!(CKA_MECHANISM_TYPE; as NumType);
    amap[100] = attrmap_element!(CKA_REQUIRED_CMS_ATTRIBUTES; as BytesType);
    amap[101] = attrmap_element!(CKA_DEFAULT_CMS_ATTRIBUTES; as BytesType);
    amap[102] = attrmap_element!(CKA_SUPPORTED_CMS_ATTRIBUTES; as BytesType);
    amap[103] = attrmap_element!(CKA_ALLOWED_MECHANISMS; as BytesType);
    amap[104] = attrmap_element!(CKA_PROFILE_ID; as NumType);
    amap[105] = attrmap_element!(CKA_X2RATCHET_BAG; as BytesType);
    amap[106] = attrmap_element!(CKA_X2RATCHET_BAGSIZE; as NumType);
    amap[107] = attrmap_element!(CKA_X2RATCHET_BOBS1STMSG; as BoolType);
    amap[108] = attrmap_element!(CKA_X2RATCHET_CKR; as BytesType);
    amap[109] = attrmap_element!(CKA_X2RATCHET_CKS; as BytesType);
    amap[110] = attrmap_element!(CKA_X2RATCHET_DHP; as BytesType);
    amap[111] = attrmap_element!(CKA_X2RATCHET_DHR; as BytesType);
    amap[112] = attrmap_element!(CKA_X2RATCHET_DHS; as BytesType);
    amap[113] = attrmap_element!(CKA_X2RATCHET_HKR; as BytesType);
    amap[114] = attrmap_element!(CKA_X2RATCHET_HKS; as BytesType);
    amap[115] = attrmap_element!(CKA_X2RATCHET_ISALICE; as BoolType);
    amap[116] = attrmap_element!(CKA_X2RATCHET_NHKR; as BytesType);
    amap[117] = attrmap_element!(CKA_X2RATCHET_NHKS; as BytesType);
    amap[118] = attrmap_element!(CKA_X2RATCHET_NR; as NumType);
    amap[119] = attrmap_element!(CKA_X2RATCHET_NS; as NumType);
    amap[120] = attrmap_element!(CKA_X2RATCHET_PNS; as NumType);
    amap[121] = attrmap_element!(CKA_X2RATCHET_RK; as BytesType);
    amap[122] = attrmap_element!(CKA_VENDOR_DEFINED; as DenyType);
    amap[123] = attrmap_element!(CKA_HSS_LEVELS; as NumType);
    amap[124] = attrmap_element!(CKA_HSS_LMS_TYPE; as NumType);
    amap[125] = attrmap_element!(CKA_HSS_LMOTS_TYPE; as NumType);
    amap[126] = attrmap_element!(CKA_HSS_LMS_TYPES; as BytesType);
    amap[127] = attrmap_element!(CKA_HSS_LMOTS_TYPES; as BytesType);
    amap[128] = attrmap_element!(CKA_HSS_KEYS_REMAINING; as NumType);

    #[allow(unused_assignments)]
    let mut last = 129;

    /* PKCS11 3.2 defined additional attributes */
    #[cfg(feature = "pkcs11_3_2")]
    {
        amap[129] = attrmap_element!(CKA_PARAMETER_SET; as NumType);
        amap[130] = attrmap_element!(CKA_VALIDATION_TYPE; as NumType);
        amap[131] = attrmap_element!(CKA_VALIDATION_VERSION; as BytesType);
        amap[132] = attrmap_element!(CKA_VALIDATION_LEVEL; as NumType);
        amap[133] = attrmap_element!(CKA_VALIDATION_MODULE_ID; as StringType);
        amap[134] = attrmap_element!(CKA_VALIDATION_FLAG; as NumType);
        amap[135] = attrmap_element!(CKA_VALIDATION_AUTHORITY_TYPE; as NumType);
        amap[136] = attrmap_element!(CKA_VALIDATION_COUNTRY; as StringType);
        amap[137] = attrmap_element!(CKA_VALIDATION_CERTIFICATE_IDENTIFIER; as StringType);
        amap[138] =
            attrmap_element!(CKA_VALIDATION_CERTIFICATE_URI; as StringType);
        amap[139] = attrmap_element!(CKA_VALIDATION_VENDOR_URI; as StringType);
        amap[140] = attrmap_element!(CKA_VALIDATION_PROFILE; as StringType);
        amap[141] = attrmap_element!(CKA_OBJECT_VALIDATION_FLAGS; as NumType);
        amap[142] = attrmap_element!(CKA_ENCAPSULATE_TEMPLATE; as BytesType);
        amap[143] = attrmap_element!(CKA_DECAPSULATE_TEMPLATE; as BytesType);
        amap[144] = attrmap_element!(CKA_TRUST_SERVER_AUTH; as NumType);
        amap[145] = attrmap_element!(CKA_TRUST_CLIENT_AUTH; as NumType);
        amap[146] = attrmap_element!(CKA_TRUST_CODE_SIGNING; as NumType);
        amap[147] = attrmap_element!(CKA_TRUST_EMAIL_PROTECTION; as NumType);
        amap[148] = attrmap_element!(CKA_TRUST_IPSEC_IKE; as NumType);
        amap[149] = attrmap_element!(CKA_TRUST_TIME_STAMPING; as NumType);
        amap[150] = attrmap_element!(CKA_TRUST_OCSP_SIGNING; as NumType);
        amap[151] = attrmap_element!(CKA_ENCAPSULATE; as BoolType);
        amap[152] = attrmap_element!(CKA_DECAPSULATE; as BoolType);
        amap[153] = attrmap_element!(CKA_HASH_OF_CERTIFICATE; as BytesType);
        amap[154] = attrmap_element!(CKA_PUBLIC_CRC64_VALUE; as BytesType);
        amap[155] = attrmap_element!(CKA_SEED; as BytesType);
        last = 156;
    }

    /* Additional Vendor defined Attributes */
    amap[last] = attrmap_element!(KRA_MAX_LOGIN_ATTEMPTS; as NumType);
    last += 1;
    amap[last] = attrmap_element!(KRA_LOGIN_ATTEMPTS; as NumType);
    amap
};

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

    pub fn to_bool(&self) -> Result<bool> {
        if self.value.len() != 1 {
            return Err(CKR_ATTRIBUTE_VALUE_INVALID)?;
        }
        if self.value[0] == 0 {
            return Ok(false);
        }
        Ok(true)
    }
    pub fn to_ulong(&self) -> Result<CK_ULONG> {
        if self.value.len() != std::mem::size_of::<CK_ULONG>() {
            return Err(CKR_ATTRIBUTE_VALUE_INVALID)?;
        }
        Ok(CK_ULONG::from_ne_bytes(
            self.value.as_slice().try_into().unwrap(),
        ))
    }

    pub fn to_string(&self) -> Result<String> {
        match std::str::from_utf8(&self.value) {
            Ok(s) => Ok(s.to_string()),
            Err(_) => Err(CKR_ATTRIBUTE_VALUE_INVALID)?,
        }
    }

    pub fn to_bytes(&self) -> Result<&Vec<u8>> {
        Ok(&self.value)
    }

    pub fn to_date_string(&self) -> Result<String> {
        if self.value.len() == 0 {
            return Ok(String::new()); /* empty default value */
        }
        if self.value.len() != 8 {
            return Err(CKR_ATTRIBUTE_VALUE_INVALID)?;
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

    pub fn zeroize(&mut self) {
        zeromem(self.value.as_mut_slice());
    }

    pub fn from_date_bytes(t: CK_ULONG, val: Vec<u8>) -> Attribute {
        Attribute {
            ck_type: t,
            attrtype: AttrType::DateType,
            value: val,
        }
    }

    pub fn from_ignore(t: CK_ULONG, _val: Option<()>) -> Attribute {
        Attribute {
            ck_type: t,
            attrtype: AttrType::IgnoreType,
            value: Vec::new(),
        }
    }

    pub fn string_from_sized(t: CK_ULONG, val: &[u8]) -> Attribute {
        let mut value = Vec::from(val);
        let mut len = value.len();
        for i in (0..len).rev() {
            if value[i] != 0x20 {
                break;
            }
            len -= 1;
        }
        value.resize(len, 0);
        /* trailing null byte of a string */
        value.push(0);
        Attribute {
            ck_type: t,
            attrtype: AttrType::StringType,
            value: value,
        }
    }

    pub fn from_attr_slice(
        id: CK_ULONG,
        at: AttrType,
        val: &[u8],
    ) -> Attribute {
        Attribute {
            ck_type: id,
            attrtype: at,
            value: val.to_vec(),
        }
    }
}

macro_rules! conversion_from_type {
    (make $fn1:ident; $fn2:ident; $fn3:ident; from $rtype:ty; as $atype:ident; via $conv:ident) => {
        impl Attribute {
            #[allow(dead_code)]
            pub fn $fn1(t: CK_ULONG, val: $rtype) -> Attribute {
                Attribute {
                    ck_type: t,
                    attrtype: AttrType::$atype,
                    value: $conv(val),
                }
            }

            #[allow(dead_code)]
            pub fn $fn2(t: CK_ULONG, val: $rtype) -> Result<Attribute> {
                for a in &ATTRMAP {
                    if a.id == t {
                        if a.atype == AttrType::$atype {
                            return Ok(Self::$fn1(t, val));
                        }
                        return Err(CKR_ATTRIBUTE_VALUE_INVALID)?;
                    }
                }
                Err(Error::not_found((t.to_string())))
            }

            #[allow(dead_code)]
            pub fn $fn3(s: String, val: $rtype) -> Result<Attribute> {
                for a in &ATTRMAP {
                    if a.name == &s {
                        if a.atype == AttrType::$atype {
                            return Ok(Self::$fn1(a.id, val));
                        }
                        return Err(CKR_ATTRIBUTE_VALUE_INVALID)?;
                    }
                }
                Err(Error::not_found((s)))
            }
        }
    };
}

fn bool_to_vec(val: bool) -> Vec<u8> {
    Vec::from(if val { &[1u8][..] } else { &[0u8][..] })
}
conversion_from_type! {make from_bool; from_type_bool; from_string_bool; from bool; as BoolType; via bool_to_vec}

fn ulong_to_vec(val: CK_ULONG) -> Vec<u8> {
    Vec::from(val.to_ne_bytes())
}
conversion_from_type! {make from_ulong; from_type_ulong; from_string_ulong; from CK_ULONG; as NumType; via ulong_to_vec}

fn u64_to_vec(val: u64) -> Vec<u8> {
    let inval = CK_ULONG::try_from(val).unwrap();
    Vec::from(inval.to_ne_bytes())
}
conversion_from_type! {make from_u64; from_type_u64; from_string_u64; from u64; as NumType; via u64_to_vec}

fn string_to_vec(val: String) -> Vec<u8> {
    Vec::from(val.as_bytes())
}
conversion_from_type! {make from_string; from_type_string; from_string_string; from String; as StringType; via string_to_vec}

fn bytes_to_vec(val: Vec<u8>) -> Vec<u8> {
    val
}
conversion_from_type! {make from_bytes; from_type_bytes; from_string_bytes; from Vec<u8>; as BytesType; via bytes_to_vec}

fn date_to_vec(val: CK_DATE) -> Vec<u8> {
    let mut v = vec![0u8; 8];
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

fn empty_date() -> CK_DATE {
    CK_DATE {
        year: [0x30, 0x30, 0x30, 0x30],
        month: [0x30, 0x30],
        day: [0x30, 0x30],
    }
}

fn vec_to_date_validate(val: Vec<u8>) -> Result<CK_DATE> {
    if val.len() != 8 {
        return Err(CKR_ATTRIBUTE_VALUE_INVALID)?;
    }
    for n in val.iter() {
        if *n < MIN_ASCII_DIGIT || *n > MAX_ASCII_DIGIT {
            return Err(CKR_ATTRIBUTE_VALUE_INVALID)?;
        }
    }
    Ok(vec_to_date(val))
}

pub fn string_to_ck_date(date: &str) -> Result<CK_DATE> {
    let s = date.as_bytes().to_vec();
    if s.len() != 10 {
        return Err(CKR_ATTRIBUTE_VALUE_INVALID)?;
    }
    if s[4] != ASCII_DASH || s[7] != ASCII_DASH {
        return Err(CKR_ATTRIBUTE_VALUE_INVALID)?;
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

impl AttrType {
    pub fn attr_name_to_id_type(s: &String) -> Result<(CK_ULONG, AttrType)> {
        for a in &ATTRMAP {
            if a.name == s {
                return Ok((a.id, a.atype));
            }
        }
        Err(Error::not_found(s.clone()))
    }

    pub fn attr_id_to_attrtype(id: CK_ULONG) -> Result<AttrType> {
        for a in &ATTRMAP {
            if a.id == id {
                return Ok(a.atype);
            }
        }
        return Err(CKR_ATTRIBUTE_TYPE_INVALID)?;
    }
}

impl CK_ATTRIBUTE {
    pub fn to_ulong(&self) -> Result<CK_ULONG> {
        if self.ulValueLen != sizeof!(CK_ULONG) {
            return Err(CKR_ATTRIBUTE_VALUE_INVALID)?;
        }
        Ok(unsafe { *(self.pValue as CK_ULONG_PTR) })
    }
    pub fn to_bool(self) -> Result<bool> {
        if self.ulValueLen != sizeof!(CK_BBOOL) {
            return Err(CKR_ATTRIBUTE_VALUE_INVALID)?;
        }
        let val: CK_BBOOL = unsafe { *(self.pValue as CK_BBOOL_PTR) };
        if val == 0 {
            Ok(false)
        } else {
            Ok(true)
        }
    }
    pub fn to_string(&self) -> Result<String> {
        if self.ulValueLen == 0 {
            return Ok(String::new());
        }
        if self.pValue.is_null() {
            return Err(CKR_ATTRIBUTE_VALUE_INVALID)?;
        }
        let buf: &[u8] = unsafe {
            std::slice::from_raw_parts(
                self.pValue as *const _,
                usize::try_from(self.ulValueLen)?,
            )
        };
        match std::str::from_utf8(buf) {
            Ok(s) => Ok(s.to_string()),
            Err(_) => Err(CKR_ATTRIBUTE_VALUE_INVALID)?,
        }
    }
    pub fn to_slice(&self) -> Result<&[u8]> {
        if self.ulValueLen == 0 {
            return Ok(&[]);
        }
        if self.pValue.is_null() {
            return Err(CKR_ATTRIBUTE_VALUE_INVALID)?;
        }
        Ok(unsafe {
            std::slice::from_raw_parts(
                self.pValue as *const u8,
                usize::try_from(self.ulValueLen)?,
            )
        })
    }
    pub fn to_buf(&self) -> Result<Vec<u8>> {
        Ok(bytes_to_vec!(self.pValue, self.ulValueLen))
    }
    pub fn to_date(&self) -> Result<CK_DATE> {
        if self.ulValueLen == 0 {
            /* set 0000-00-00 */
            return Ok(empty_date());
        }
        if self.pValue.is_null() {
            return Err(CKR_ATTRIBUTE_VALUE_INVALID)?;
        }
        if self.ulValueLen != 8 {
            return Err(CKR_ATTRIBUTE_VALUE_INVALID)?;
        }
        vec_to_date_validate(bytes_to_vec!(self.pValue, self.ulValueLen))
    }

    pub fn to_attribute(&self) -> Result<Attribute> {
        let mut atype = AttrType::DenyType;
        for amap in &ATTRMAP {
            if amap.id == self.type_ {
                atype = amap.atype;
                break;
            }
        }
        match atype {
            AttrType::BoolType => {
                Ok(Attribute::from_bool(self.type_, self.to_bool()?))
            }
            AttrType::NumType => {
                Ok(Attribute::from_ulong(self.type_, self.to_ulong()?))
            }
            AttrType::StringType => {
                Ok(Attribute::from_string(self.type_, self.to_string()?))
            }
            AttrType::BytesType => {
                Ok(Attribute::from_bytes(self.type_, self.to_buf()?))
            }
            AttrType::DateType => {
                Ok(Attribute::from_date(self.type_, self.to_date()?))
            }
            AttrType::DenyType => Err(CKR_ATTRIBUTE_TYPE_INVALID)?,
            AttrType::IgnoreType => {
                Ok(Attribute::from_ignore(self.type_, None))
            }
        }
    }
}

#[derive(Debug)]
pub struct CkAttrs<'a> {
    v: Vec<Vec<u8>>,
    p: Cow<'a, [CK_ATTRIBUTE]>,
    pub zeroize: bool,
}

impl Drop for CkAttrs<'_> {
    fn drop(&mut self) {
        if self.zeroize {
            while let Some(mut elem) = self.v.pop() {
                zeromem(elem.as_mut_slice());
            }
        }
    }
}

#[allow(dead_code)]
impl<'a> CkAttrs<'a> {
    pub fn new() -> CkAttrs<'static> {
        Self::with_capacity(0)
    }

    pub fn with_capacity(capacity: usize) -> CkAttrs<'static> {
        CkAttrs {
            v: Vec::new(),
            p: Cow::Owned(Vec::with_capacity(capacity)),
            zeroize: false,
        }
    }

    pub fn from_ptr(
        a: *mut CK_ATTRIBUTE,
        l: CK_ULONG,
    ) -> Result<CkAttrs<'static>> {
        if a.is_null() {
            return Err(CKR_ARGUMENTS_BAD)?;
        }
        Ok(CkAttrs {
            v: Vec::new(),
            p: Cow::Borrowed(unsafe {
                std::slice::from_raw_parts(a, usize::try_from(l)?)
            }),
            zeroize: false,
        })
    }

    pub fn from(a: &'a [CK_ATTRIBUTE]) -> CkAttrs<'a> {
        CkAttrs {
            v: Vec::new(),
            p: Cow::Borrowed(a),
            zeroize: false,
        }
    }

    fn attr_from_last(&self, typ: CK_ATTRIBUTE_TYPE) -> Result<CK_ATTRIBUTE> {
        if let Some(r) = self.v.last() {
            Ok(CK_ATTRIBUTE {
                type_: typ,
                pValue: void_ptr!(r.as_ptr()),
                ulValueLen: CK_ULONG::try_from(r.len())?,
            })
        } else {
            Err(CKR_GENERAL_ERROR)?
        }
    }

    pub fn add_owned_slice(
        &mut self,
        typ: CK_ATTRIBUTE_TYPE,
        val: &[u8],
    ) -> Result<()> {
        self.v.push(val.to_vec());
        let a = self.attr_from_last(typ)?;
        self.p.to_mut().push(a);
        Ok(())
    }

    pub fn add_owned_ulong(
        &mut self,
        typ: CK_ATTRIBUTE_TYPE,
        val: CK_ULONG,
    ) -> Result<()> {
        self.v.push(val.to_ne_bytes().to_vec());
        let a = self.attr_from_last(typ)?;
        self.p.to_mut().push(a);
        Ok(())
    }

    pub fn add_owned_bool(
        &mut self,
        typ: CK_ATTRIBUTE_TYPE,
        val: CK_BBOOL,
    ) -> Result<()> {
        self.v.push(val.to_ne_bytes().to_vec());
        let a = self.attr_from_last(typ)?;
        self.p.to_mut().push(a);
        Ok(())
    }

    pub fn add_vec(
        &mut self,
        typ: CK_ATTRIBUTE_TYPE,
        val: Vec<u8>,
    ) -> Result<()> {
        self.v.push(val);
        let a = self.attr_from_last(typ)?;
        self.p.to_mut().push(a);
        Ok(())
    }

    pub fn add_slice(
        &mut self,
        typ: CK_ATTRIBUTE_TYPE,
        val: &'a [u8],
    ) -> Result<()> {
        self.p.to_mut().push(CK_ATTRIBUTE {
            type_: typ,
            pValue: val.as_ptr() as *mut std::ffi::c_void,
            ulValueLen: CK_ULONG::try_from(val.len())?,
        });
        Ok(())
    }

    pub fn add_ulong(&mut self, typ: CK_ATTRIBUTE_TYPE, val: &'a CK_ULONG) {
        self.p.to_mut().push(CK_ATTRIBUTE {
            type_: typ,
            pValue: val as *const CK_ULONG as *mut std::ffi::c_void,
            ulValueLen: sizeof!(CK_ULONG),
        });
    }

    pub fn add_bool(&mut self, typ: CK_ATTRIBUTE_TYPE, val: &'a CK_BBOOL) {
        self.p.to_mut().push(CK_ATTRIBUTE {
            type_: typ,
            pValue: val as *const CK_BBOOL as *mut std::ffi::c_void,
            ulValueLen: sizeof!(CK_BBOOL),
        });
    }

    pub fn add_missing_slice(
        &mut self,
        typ: CK_ATTRIBUTE_TYPE,
        val: &'a [u8],
    ) -> Result<()> {
        match self.p.as_ref().iter().find(|a| a.type_ == typ) {
            Some(_) => Ok(()),
            None => self.add_slice(typ, val),
        }
    }

    pub fn add_missing_ulong(
        &mut self,
        typ: CK_ATTRIBUTE_TYPE,
        val: &'a CK_ULONG,
    ) {
        match self.p.as_ref().iter().find(|a| a.type_ == typ) {
            Some(_) => (),
            None => self.add_ulong(typ, val),
        }
    }

    pub fn add_missing_bool(
        &mut self,
        typ: CK_ATTRIBUTE_TYPE,
        val: &'a CK_BBOOL,
    ) {
        match self.p.as_ref().iter().find(|a| a.type_ == typ) {
            Some(_) => (),
            None => self.add_bool(typ, val),
        }
    }

    pub fn remove_ulong(
        &mut self,
        typ: CK_ATTRIBUTE_TYPE,
    ) -> Result<Option<CK_ULONG>> {
        match self.p.as_ref().iter().position(|a| a.type_ == typ) {
            Some(idx) => Ok(Some(self.p.to_mut().swap_remove(idx).to_ulong()?)),
            None => return Ok(None),
        }
    }

    pub fn len(&self) -> usize {
        self.p.as_ref().len()
    }

    pub fn as_ptr(&self) -> *const CK_ATTRIBUTE {
        self.p.as_ref().as_ptr()
    }

    pub fn as_mut_ptr(&mut self) -> *mut CK_ATTRIBUTE {
        self.p.to_mut().as_mut_ptr()
    }

    pub fn as_slice(&'a self) -> &'a [CK_ATTRIBUTE] {
        self.p.as_ref()
    }

    pub fn find_attr(
        &'a self,
        typ: CK_ATTRIBUTE_TYPE,
    ) -> Option<&'a CK_ATTRIBUTE> {
        match self.p.as_ref().iter().find(|a| a.type_ == typ) {
            Some(ref a) => Some(a),
            None => None,
        }
    }

    pub fn insert_unique_vec(
        &mut self,
        typ: CK_ATTRIBUTE_TYPE,
        val: Vec<u8>,
    ) -> Result<()> {
        self.v.push(val);
        let attr = self.attr_from_last(typ)?;
        match self.p.as_ref().iter().position(|a| a.type_ == typ) {
            Some(idx) => self.p.to_mut()[idx] = attr,
            None => self.p.to_mut().push(attr),
        }
        Ok(())
    }
}
