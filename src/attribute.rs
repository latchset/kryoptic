// Copyright 2023 Simo Sorce
// See LICENSE.txt file for terms

//! This module provides helper function to manage PKCS#11 attributes with
//! conversions functions to safe Rust representations ([Attribute], [CkAttrs])
//! and defines mappings between PKCS#11 attribute type values and
//! the data type they represent as described in the [AttrType] enumeration.

use std::borrow::Cow;
use std::cmp::Ordering;

use crate::error::{Error, Result};
use crate::misc::{sizeof, void_ptr, zeromem};
use crate::pkcs11::vendor::{KRA_LOGIN_ATTEMPTS, KRA_MAX_LOGIN_ATTEMPTS};
use crate::pkcs11::*;

use ossl::BorrowedReference;

/// List of attribute types we understand
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum AttrType {
    BoolType,
    NumType,
    StringType,
    BytesType,
    UlongArrayType,
    DateType,
    DenyType,
    IgnoreType,
}

impl AttrType {
    /// Finds and return the attribute id and type from the spec name
    #[allow(dead_code)]
    pub fn attr_name_to_id_type(s: &String) -> Result<(CK_ULONG, AttrType)> {
        match Attrmap::search_by_name(s) {
            Some(a) => Ok((a.id, a.atype)),
            None => Err(Error::not_found(s.clone())),
        }
    }

    /// Finds the attribute type from the attribute id
    pub fn attr_id_to_attrtype(id: CK_ULONG) -> Result<AttrType> {
        match Attrmap::search_by_id(id) {
            Some(a) => Ok(a.atype),
            None => Err(CKR_ATTRIBUTE_TYPE_INVALID)?,
        }
    }
}

/// Struct to map a PKCS#11 attribute to a type and a printable name
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Attrmap<'a> {
    id: CK_ULONG,
    name: &'a str,
    atype: AttrType,
}

impl PartialOrd for Attrmap<'_> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Attrmap<'_> {
    fn cmp(&self, other: &Self) -> Ordering {
        if self.id < other.id {
            return Ordering::Less;
        }
        if self.id > other.id {
            return Ordering::Greater;
        }
        Ordering::Equal
    }
}

impl Attrmap<'_> {
    /// Convenience function to efficiently search for a mapping by id
    pub fn search_by_id(id: CK_ULONG) -> Option<&'static Attrmap<'static>> {
        match &ATTRMAP.binary_search(&Attrmap {
            id: id,
            name: "",
            atype: AttrType::StringType,
        }) {
            Ok(i) => Some(&ATTRMAP[*i]),
            Err(_) => None,
        }
    }

    /// Convenience function to search for a mapping by name
    pub fn search_by_name(s: &String) -> Option<&'static Attrmap<'static>> {
        for a in &ATTRMAP {
            if a.name == s {
                return Some(a);
            }
        }
        None
    }
}

/// Helper macro to populate the static attributes map
macro_rules! attrmap_element {
    ($id:expr; as $attrtype:ident) => {
        Attrmap {
            id: $id,
            name: stringify!($id),
            atype: AttrType::$attrtype,
        }
    };
}

/// The main attributes map, list all known attributes
static ATTRMAP: [Attrmap<'_>; 158] = [
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
    attrmap_element!(CKA_EC_PARAMS; as BytesType),
    attrmap_element!(CKA_EC_POINT; as BytesType),
    attrmap_element!(CKA_ALWAYS_AUTHENTICATE; as BoolType),
    attrmap_element!(CKA_WRAP_WITH_TRUSTED; as BoolType),
    attrmap_element!(CKA_OTP_FORMAT; as NumType),
    attrmap_element!(CKA_OTP_LENGTH; as NumType),
    attrmap_element!(CKA_OTP_TIME_INTERVAL; as NumType),
    attrmap_element!(CKA_OTP_USER_FRIENDLY_MODE; as BoolType),
    attrmap_element!(CKA_OTP_CHALLENGE_REQUIREMENT; as NumType),
    attrmap_element!(CKA_OTP_TIME_REQUIREMENT; as NumType),
    attrmap_element!(CKA_OTP_COUNTER_REQUIREMENT; as NumType),
    attrmap_element!(CKA_OTP_PIN_REQUIREMENT; as NumType),
    attrmap_element!(CKA_OTP_USER_IDENTIFIER; as StringType),
    attrmap_element!(CKA_OTP_SERVICE_IDENTIFIER; as StringType),
    attrmap_element!(CKA_OTP_SERVICE_LOGO; as BytesType),
    attrmap_element!(CKA_OTP_SERVICE_LOGO_TYPE; as StringType),
    attrmap_element!(CKA_OTP_COUNTER; as BytesType),
    attrmap_element!(CKA_OTP_TIME; as StringType),
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
    attrmap_element!(CKA_HSS_LEVELS; as NumType),
    attrmap_element!(CKA_HSS_LMS_TYPE; as NumType),
    attrmap_element!(CKA_HSS_LMOTS_TYPE; as NumType),
    attrmap_element!(CKA_HSS_LMS_TYPES; as BytesType),
    attrmap_element!(CKA_HSS_LMOTS_TYPES; as BytesType),
    attrmap_element!(CKA_HSS_KEYS_REMAINING; as NumType),
    attrmap_element!(CKA_PARAMETER_SET; as NumType),
    attrmap_element!(CKA_OBJECT_VALIDATION_FLAGS; as NumType),
    attrmap_element!(CKA_VALIDATION_TYPE; as NumType),
    attrmap_element!(CKA_VALIDATION_VERSION; as BytesType),
    attrmap_element!(CKA_VALIDATION_LEVEL; as NumType),
    attrmap_element!(CKA_VALIDATION_MODULE_ID; as StringType),
    attrmap_element!(CKA_VALIDATION_FLAG; as NumType),
    attrmap_element!(CKA_VALIDATION_AUTHORITY_TYPE; as NumType),
    attrmap_element!(CKA_VALIDATION_COUNTRY; as StringType),
    attrmap_element!(CKA_VALIDATION_CERTIFICATE_IDENTIFIER; as StringType),
    attrmap_element!(CKA_VALIDATION_CERTIFICATE_URI; as StringType),
    attrmap_element!(CKA_VALIDATION_VENDOR_URI; as StringType),
    attrmap_element!(CKA_VALIDATION_PROFILE; as StringType),
    attrmap_element!(CKA_ENCAPSULATE_TEMPLATE; as DenyType),
    attrmap_element!(CKA_DECAPSULATE_TEMPLATE; as DenyType),
    attrmap_element!(CKA_TRUST_SERVER_AUTH; as NumType),
    attrmap_element!(CKA_TRUST_CLIENT_AUTH; as NumType),
    attrmap_element!(CKA_TRUST_CODE_SIGNING; as NumType),
    attrmap_element!(CKA_TRUST_EMAIL_PROTECTION; as NumType),
    attrmap_element!(CKA_TRUST_IPSEC_IKE; as NumType),
    attrmap_element!(CKA_TRUST_TIME_STAMPING; as NumType),
    attrmap_element!(CKA_TRUST_OCSP_SIGNING; as NumType),
    attrmap_element!(CKA_ENCAPSULATE; as BoolType),
    attrmap_element!(CKA_DECAPSULATE; as BoolType),
    attrmap_element!(CKA_HASH_OF_CERTIFICATE; as BytesType),
    attrmap_element!(CKA_PUBLIC_CRC64_VALUE; as BytesType),
    attrmap_element!(CKA_SEED; as BytesType),
    attrmap_element!(CKA_WRAP_TEMPLATE; as DenyType),
    attrmap_element!(CKA_UNWRAP_TEMPLATE; as DenyType),
    attrmap_element!(CKA_DERIVE_TEMPLATE; as DenyType),
    attrmap_element!(CKA_ALLOWED_MECHANISMS; as UlongArrayType),
    attrmap_element!(CKA_VENDOR_DEFINED; as DenyType),
    /* Additional Vendor defined Attributes */
    attrmap_element!(KRA_MAX_LOGIN_ATTEMPTS; as NumType),
    attrmap_element!(KRA_LOGIN_ATTEMPTS; as NumType),
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_order_of_attrmap() {
        let mut copy = ATTRMAP.clone();
        copy.sort();
        assert_eq!(ATTRMAP, copy);
    }
}

/// A Rust native, typed attribute that holds the attribute value
#[derive(Debug, Clone)]
pub struct Attribute {
    ck_type: CK_ULONG,
    attrtype: AttrType,
    value: Vec<u8>,
}

impl Attribute {
    /// Returns the PKCS#11 attribute 'type' which is the attribute ID
    pub fn get_type(&self) -> CK_ULONG {
        self.ck_type
    }

    /// Returns the internal attribute type
    pub fn get_attrtype(&self) -> AttrType {
        self.attrtype
    }

    /// Returns a reference to the internal value
    pub fn get_value(&self) -> &Vec<u8> {
        &self.value
    }

    /// Checks that the attribute and the passed CK_ATTRIBUTE match.
    /// That is, they have same type and same value stored
    pub fn match_ck_attr(&self, attr: &CK_ATTRIBUTE) -> bool {
        if self.ck_type != attr.type_ {
            return false;
        }
        match attr.to_buf() {
            Ok(buf) => buf == self.value,
            Err(_) => false,
        }
    }

    /// Returns the name of the attribute as an allocated String
    #[allow(dead_code)]
    pub fn name(&self) -> String {
        match Attrmap::search_by_id(self.ck_type) {
            Some(a) => return a.name.to_string(),
            None => return self.ck_type.to_string(),
        }
    }

    /// Returns the internal value as a boolean
    ///
    /// Returns a CKR_ATTRIBUTE_VALUE_INVALID error if the value is
    /// not a boolean
    pub fn to_bool(&self) -> Result<bool> {
        if self.attrtype != AttrType::BoolType {
            return Err(CKR_ATTRIBUTE_TYPE_INVALID)?;
        }
        if self.value.len() != 1 {
            return Err(CKR_ATTRIBUTE_VALUE_INVALID)?;
        }
        if self.value[0] == 0 {
            return Ok(false);
        }
        Ok(true)
    }

    /// Returns the internal value as a CK_ULONG
    ///
    /// Returns a CKR_ATTRIBUTE_VALUE_INVALID error if the value is
    /// not a ulong
    pub fn to_ulong(&self) -> Result<CK_ULONG> {
        if self.attrtype != AttrType::NumType {
            return Err(CKR_ATTRIBUTE_TYPE_INVALID)?;
        }
        if self.value.len() != std::mem::size_of::<CK_ULONG>() {
            return Err(CKR_ATTRIBUTE_VALUE_INVALID)?;
        }
        Ok(CK_ULONG::from_ne_bytes(
            self.value.as_slice().try_into().unwrap(),
        ))
    }

    /// Returns the internal value as a String
    ///
    /// Returns a CKR_ATTRIBUTE_VALUE_INVALID error if the value is
    /// not parseable as a string
    pub fn to_string(&self) -> Result<String> {
        if self.attrtype != AttrType::StringType {
            return Err(CKR_ATTRIBUTE_TYPE_INVALID)?;
        }
        match std::str::from_utf8(&self.value) {
            Ok(s) => Ok(s.to_string()),
            Err(_) => Err(CKR_ATTRIBUTE_VALUE_INVALID)?,
        }
    }

    /// Returns a reference to the internal value wrapped in a Result
    pub fn to_bytes(&self) -> Result<&Vec<u8>> {
        if self.attrtype != AttrType::BytesType {
            return Err(CKR_ATTRIBUTE_TYPE_INVALID)?;
        }
        Ok(&self.value)
    }

    /// Returns the internal value as a vector of CK_ULONG values
    ///
    /// Returns a CKR_ATTRIBUTE_VALUE_INVALID error if the value is
    /// not parseable as an array
    pub fn to_ulong_array(&self) -> Result<Vec<CK_ULONG>> {
        if self.attrtype != AttrType::UlongArrayType {
            return Err(CKR_ATTRIBUTE_TYPE_INVALID)?;
        }
        let ulen = std::mem::size_of::<CK_ULONG>();
        if self.value.len() % ulen != 0 {
            return Err(CKR_ATTRIBUTE_VALUE_INVALID)?;
        }
        let vlen = self.value.len() / ulen;
        let mut v = Vec::<CK_ULONG>::with_capacity(vlen);

        let mut idx = 0;
        while idx < self.value.len() {
            let elem = &self.value[idx..(idx + ulen)];
            idx += ulen;
            let ulongval = CK_ULONG::from_ne_bytes(elem.try_into()?);
            v.push(ulongval);
        }
        Ok(v)
    }

    /// Returns the value as an allocated String containing a date
    ///
    /// Returns a CKR_ATTRIBUTE_VALUE_INVALID error if the value is
    /// not parseable as a CK_DATE type
    pub fn to_date_string(&self) -> Result<String> {
        if self.attrtype != AttrType::DateType {
            return Err(CKR_ATTRIBUTE_TYPE_INVALID)?;
        }
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

    /// Zeroizes the internal value
    pub fn zeroize(&mut self) {
        zeromem(self.value.as_mut_slice());
    }

    /// Constructs an attribute as a date type
    pub fn from_date_bytes(t: CK_ULONG, val: Vec<u8>) -> Attribute {
        Attribute {
            ck_type: t,
            attrtype: AttrType::DateType,
            value: val,
        }
    }

    /// Constructs an attribute as an ignored type
    pub fn from_ignore(t: CK_ULONG, _val: Option<()>) -> Attribute {
        Attribute {
            ck_type: t,
            attrtype: AttrType::IgnoreType,
            value: Vec::new(),
        }
    }

    /// Constructs an attribute passing in the value as a slice
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

    /// Constructs an attribute of type UlongArrayType from a vector of bytes.
    ///
    /// The byte vector is not processed or checked for validity
    pub fn from_ulong_bytevec(id: CK_ULONG, val: Vec<u8>) -> Attribute {
        Attribute {
            ck_type: id,
            attrtype: AttrType::UlongArrayType,
            value: val,
        }
    }

    /// Creates an attribute of type AttrType::BoolType from a bool
    ///
    /// Note: Does not verify that the attribute id type is correct
    pub fn from_bool(t: CK_ULONG, val: bool) -> Attribute {
        Attribute {
            ck_type: t,
            attrtype: AttrType::BoolType,
            value: Vec::from(if val { &[1u8][..] } else { &[0u8][..] }),
        }
    }

    /// Creates an attribute of type AttrType::NumType from a CK_ULONG
    ///
    /// Note: Does not verify that the attribute id type is correct
    pub fn from_ulong(t: CK_ULONG, val: CK_ULONG) -> Attribute {
        Attribute {
            ck_type: t,
            attrtype: AttrType::NumType,
            value: Vec::from(val.to_ne_bytes()),
        }
    }

    /// Creates an attribute of type AttrType::NumType from a u64
    ///
    /// Note: Does not verify that the attribute id type is correct
    #[allow(dead_code)]
    pub fn from_u64(t: CK_ULONG, val: u64) -> Attribute {
        let inval = CK_ULONG::try_from(val).unwrap();
        Self::from_ulong(t, inval)
    }

    /// Creates an attribute of type AttrType::StringType from a String
    ///
    /// Note: Does not verify that the attribute id type is correct
    pub fn from_string(t: CK_ULONG, val: String) -> Attribute {
        Attribute {
            ck_type: t,
            attrtype: AttrType::StringType,
            value: Vec::from(val.as_bytes()),
        }
    }

    /// Creates an attribute of type AttrType::BytesType from a `Vec<u8>`
    ///
    /// Note: Does not verify that the attribute id type is correct
    pub fn from_bytes(t: CK_ULONG, val: Vec<u8>) -> Attribute {
        Attribute {
            ck_type: t,
            attrtype: AttrType::BytesType,
            value: val,
        }
    }

    /// Creates an attribute of type AttrType::UlongArrayType from a Vec<CK_ULONG>
    ///
    /// Note: Does not verify that the attribute id type is correct
    pub fn from_ulong_array(t: CK_ULONG, val: Vec<CK_ULONG>) -> Attribute {
        let ulen = std::mem::size_of::<CK_ULONG>();
        let mut v = Vec::<u8>::with_capacity(val.len() * ulen);
        for e in val.iter() {
            for b in e.to_ne_bytes().iter() {
                v.push(*b);
            }
        }
        Attribute {
            ck_type: t,
            attrtype: AttrType::UlongArrayType,
            value: v,
        }
    }

    /// Creates an attribute of type AttrType::DateType from a CK_DATE
    ///
    /// Note: Does not verify that the attribute id type is correct
    pub fn from_date(t: CK_ULONG, val: CK_DATE) -> Attribute {
        let mut v = vec![0u8; 8];
        v[0] = val.year[0];
        v[1] = val.year[1];
        v[2] = val.year[2];
        v[3] = val.year[3];
        v[4] = val.month[0];
        v[5] = val.month[1];
        v[6] = val.day[0];
        v[7] = val.day[1];
        Attribute {
            ck_type: t,
            attrtype: AttrType::DateType,
            value: v,
        }
    }

    /// Converts a CK_ATTRIBUTE to an Attribute object with a typed
    /// copy of the data
    pub fn from_ck_attr(attr: &CK_ATTRIBUTE) -> Result<Attribute> {
        let atype = match Attrmap::search_by_id(attr.type_) {
            Some(a) => a.atype,
            None => return Err(CKR_ATTRIBUTE_TYPE_INVALID)?,
        };
        match atype {
            AttrType::BoolType => {
                Ok(Attribute::from_bool(attr.type_, attr.to_bool()?))
            }
            AttrType::NumType => {
                Ok(Attribute::from_ulong(attr.type_, attr.to_ulong()?))
            }
            AttrType::StringType => {
                Ok(Attribute::from_string(attr.type_, attr.to_string()?))
            }
            AttrType::BytesType => {
                Ok(Attribute::from_bytes(attr.type_, attr.to_buf()?))
            }
            AttrType::UlongArrayType => {
                Ok(Attribute::from_ulong_bytevec(attr.type_, attr.to_buf()?))
            }
            AttrType::DateType => {
                Ok(Attribute::from_date(attr.type_, attr.to_date()?))
            }
            AttrType::DenyType => Err(CKR_ATTRIBUTE_TYPE_INVALID)?,
            AttrType::IgnoreType => {
                Ok(Attribute::from_ignore(attr.type_, None))
            }
        }
    }
}

/// Helper object to represent managed arrays of CK_ATTRIBUTEs
///
/// This object uses Cow memory to optimize keeping around arrays passed
/// from a FFI caller without the need to copy the memory content.
/// However if something attempts to modify the array, a copy is
/// created on the fly, and the copy is then modified.
#[derive(Debug)]
pub struct CkAttrs<'a> {
    /// Storage for owned byte buffers backing some parameters.
    v: Vec<Vec<u8>>,
    /// The actual `CK_ATTRIBUTE` array, potentially borrowed or owned.
    p: Cow<'a, [CK_ATTRIBUTE]>,
    pub zeroize: bool,
    /// Use an enum to hold references to data we need to keep around as
    /// a pointer to their datais stored in the CK_ATTRIBUTE array
    br: Vec<BorrowedReference<'a>>,
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
    /// Creates a new empty managed array of CK_ATTRIBUTEs
    pub fn new() -> CkAttrs<'static> {
        Self::with_capacity(0)
    }

    /// Creates a new empty managed array of CK_ATTRIBUTEs
    /// with the specified capacity
    pub fn with_capacity(capacity: usize) -> CkAttrs<'static> {
        CkAttrs {
            v: Vec::new(),
            p: Cow::Owned(Vec::with_capacity(capacity)),
            zeroize: false,
            br: Vec::new(),
        }
    }

    /// Creates an array form a raw pointer pointing to a list of
    /// CK_ATTRIBUTE elements in memory and a size "l"
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
            br: Vec::new(),
        })
    }

    /// Creates an array from a slice of CK_ATTRIBUTEs
    pub fn from(a: &'a [CK_ATTRIBUTE]) -> CkAttrs<'a> {
        CkAttrs {
            v: Vec::new(),
            p: Cow::Borrowed(a),
            zeroize: false,
            br: Vec::new(),
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

    /// Add a new attribute to the array, the value is defined as a slice
    ///
    /// This internally copies the slice to an allocated vector
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

    /// Add a new attribute to the array, the value is a CK_ULONG
    ///
    /// This internally copies the ulong to an allocated vector of bytes
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

    /// Add a new attribute to the array, the value is a CK_BBOOL
    ///
    /// This internally copies the bool to an allocated vector of bytes
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

    /// Add a new attribute to the array, the value is a vector of bytes
    ///
    /// The vector ownership is transferred to the array
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

    /// Adds a new attribute to the array, the value is a ref to a slice
    ///
    /// The value is *not* copied internally, instead a reference to the
    /// value is held for the life of this array
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
        self.br.push(BorrowedReference::Slice(val));
        Ok(())
    }

    /// Adds a new attribute to the array, the value is a ref to a CK_ULONG
    ///
    /// The value is *not* copied internally, instead a reference to the
    /// value is held for the life of this array
    pub fn add_ulong(&mut self, typ: CK_ATTRIBUTE_TYPE, val: &'a CK_ULONG) {
        self.p.to_mut().push(CK_ATTRIBUTE {
            type_: typ,
            pValue: val as *const CK_ULONG as *mut std::ffi::c_void,
            ulValueLen: sizeof!(CK_ULONG),
        });
        self.br.push(BorrowedReference::Ulong(val));
    }

    /// Adds a new attribute to the array, the value is a ref to a CK_BBOOL
    ///
    /// The value is *not* copied internally, instead a reference to the
    /// value is held for the life of this array
    pub fn add_bool(&mut self, typ: CK_ATTRIBUTE_TYPE, val: &'a CK_BBOOL) {
        self.p.to_mut().push(CK_ATTRIBUTE {
            type_: typ,
            pValue: val as *const CK_BBOOL as *mut std::ffi::c_void,
            ulValueLen: sizeof!(CK_BBOOL),
        });
        self.br.push(BorrowedReference::CharBool(val));
    }

    /// Adds a new attribute but only if it does not already exist on
    /// the array, the value is a reference to a slice
    ///
    /// The value is *not* copied internally, instead a reference to the
    /// value is held for the life of this array
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

    /// Adds a new attribute but only if it does not already exist on
    /// the array, the value is a reference to a CK_ULONG
    ///
    /// The value is *not* copied internally, instead a reference to the
    /// value is held for the life of this array
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

    /// Adds a new attribute but only if it does not already exist on
    /// the array, the value is a reference to a CK_BBOOL
    ///
    /// The value is *not* copied internally, instead a reference to the
    /// value is held for the life of this array
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

    /// Removes an attribute of type CK_ULONG from the array and returns the
    /// internal value if present
    pub fn remove_ulong(
        &mut self,
        typ: CK_ATTRIBUTE_TYPE,
    ) -> Result<Option<CK_ULONG>> {
        match self.p.as_ref().iter().position(|a| a.type_ == typ) {
            Some(idx) => Ok(Some(self.p.to_mut().swap_remove(idx).to_ulong()?)),
            None => return Ok(None),
        }
    }

    /// Returns the number of elements in the array
    pub fn len(&self) -> usize {
        self.p.as_ref().len()
    }

    /// Returns a pointer to the array of CK_ATTRIBUTEs
    pub fn as_ptr(&self) -> *const CK_ATTRIBUTE {
        self.p.as_ref().as_ptr()
    }

    /// Returns a mutable pointer to the array of CK_ATTRIBUTEs
    pub fn as_mut_ptr(&mut self) -> *mut CK_ATTRIBUTE {
        self.p.to_mut().as_mut_ptr()
    }

    /// Returns a reference to the internal CK_ATTRIBUTEs array
    pub fn as_slice(&'a self) -> &'a [CK_ATTRIBUTE] {
        self.p.as_ref()
    }

    /// Finds an attribute by attribute id and return a reference to it
    /// if present, None if not found
    pub fn find_attr(
        &'a self,
        typ: CK_ATTRIBUTE_TYPE,
    ) -> Option<&'a CK_ATTRIBUTE> {
        match self.p.as_ref().iter().find(|a| a.type_ == typ) {
            Some(ref a) => Some(a),
            None => None,
        }
    }

    /// Adds or Replaces an attribute in the array by attribute id, the value
    /// is passed in as a vector.
    ///
    /// The vector ownership is passed to the array.
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
