// Copyright 2023 Simo Sorce
// See LICENSE.txt file for terms

use super::attribute;
use super::error;
use super::interface;
use super::{err_not_found, err_rv};
use attribute::{
    from_bool, from_bytes, from_date_bytes, from_ignore, from_string,
    from_ulong, AttrType, Attribute,
};
use error::{KError, KResult};
use interface::*;
use std::sync::Once;

use uuid::Uuid;

macro_rules! create_bool_checker {
    (make $name:ident; from $id:expr; def $def:expr) => {
        pub fn $name(&self) -> bool {
            for a in &self.attributes {
                if a.get_type() == $id {
                    return a.to_bool().unwrap_or($def);
                }
            }
            $def
        }
    };
}

macro_rules! attr_as_type {
    (make $name:ident; with $r:ty; $atype:ident; via $conv:ident) => {
        pub fn $name(&self, t: CK_ULONG) -> KResult<$r> {
            for attr in &self.attributes {
                if attr.get_type() == t {
                    if attr.get_attrtype() != AttrType::$atype {
                        return err_rv!(CKR_ATTRIBUTE_TYPE_INVALID);
                    }
                    return attr.$conv();
                }
            }
            err_not_found!(t.to_string())
        }
    };
}

static SENSITIVE_CKK_RSA: [CK_ULONG; 6] = [
    CKA_PRIVATE_EXPONENT,
    CKA_PRIME_1,
    CKA_PRIME_2,
    CKA_EXPONENT_1,
    CKA_EXPONENT_2,
    CKA_COEFFICIENT,
];

static SENSITIVE_CKK_EC: [CK_ULONG; 1] = [CKA_VALUE];

static SENSITIVE_CKK_DH: [CK_ULONG; 2] = [CKA_VALUE, CKA_VALUE_BITS];

static SENSITIVE_CKK_DSA: [CK_ULONG; 1] = [CKA_VALUE];

static SENSITIVE_CKK_GENERIC_SECRET: [CK_ULONG; 2] = [CKA_VALUE, CKA_VALUE_LEN];

static SENSITIVE: [(CK_ULONG, &[CK_ULONG]); 8] = [
    (CKK_RSA, &SENSITIVE_CKK_RSA),
    (CKK_EC, &SENSITIVE_CKK_EC),
    (CKK_EC_EDWARDS, &SENSITIVE_CKK_EC),
    (CKK_EC_MONTGOMERY, &SENSITIVE_CKK_EC),
    (CKK_DH, &SENSITIVE_CKK_DH),
    (CKK_X9_42_DH, &SENSITIVE_CKK_DH),
    (CKK_DSA, &SENSITIVE_CKK_DSA),
    (CKK_GENERIC_SECRET, &SENSITIVE_CKK_GENERIC_SECRET),
];

#[derive(Debug, Clone)]
pub struct Object {
    handle: CK_OBJECT_HANDLE,
    attributes: Vec<Attribute>,
}

impl Object {
    pub fn new(handle: CK_ULONG) -> Object {
        Object {
            handle: handle,
            attributes: Vec::new(),
        }
    }

    pub fn get_handle(&self) -> CK_OBJECT_HANDLE {
        self.handle
    }

    create_bool_checker! {make is_token; from CKA_TOKEN; def false}
    create_bool_checker! {make is_private; from CKA_PRIVATE; def true}
    create_bool_checker! {make is_sensitive; from CKA_SENSITIVE; def true}
    create_bool_checker! {make is_modifiable; from CKA_MODIFIABLE; def true}
    create_bool_checker! {make is_destroyable; from CKA_DESTROYABLE; def false}
    create_bool_checker! {make is_extractable; from CKA_EXTRACTABLE; def false}

    pub fn set_attr(&mut self, a: Attribute) -> KResult<()> {
        let mut idx = self.attributes.len();
        for (i, elem) in self.attributes.iter().enumerate() {
            if a.get_type() == elem.get_type() {
                idx = i;
                break;
            }
        }
        if idx < self.attributes.len() {
            self.attributes[idx] = a;
        } else {
            self.attributes.push(a);
        }
        Ok(())
    }

    pub fn get_attributes(&self) -> &Vec<Attribute> {
        return &self.attributes;
    }

    attr_as_type! {make get_attr_as_bool; with bool; BoolType; via to_bool}
    attr_as_type! {make get_attr_as_ulong; with CK_ULONG; NumType; via to_ulong}
    attr_as_type! {make get_attr_as_string; with String; StringType; via to_string}
    attr_as_type! {make get_attr_as_bytes; with &Vec<u8>; BytesType; via to_bytes}

    pub fn match_template(&self, template: &[CK_ATTRIBUTE]) -> bool {
        for ck_attr in template.iter() {
            let mut found = false;
            for attr in &self.attributes {
                found = attr.match_ck_attr(ck_attr);
                if found {
                    break;
                }
            }
            if !found {
                return false;
            }
        }
        true
    }

    fn private_key_type(&self) -> Option<CK_ULONG> {
        let mut class: CK_ULONG = CK_UNAVAILABLE_INFORMATION;
        let mut key_type: CK_ULONG = CK_UNAVAILABLE_INFORMATION;
        for attr in &self.attributes {
            if attr.get_type() == CKA_CLASS {
                class = attr.to_ulong().unwrap_or(CK_UNAVAILABLE_INFORMATION);
                continue;
            }
            if attr.get_type() == CKA_KEY_TYPE {
                key_type =
                    attr.to_ulong().unwrap_or(CK_UNAVAILABLE_INFORMATION);
            }
        }
        if class == CKO_PRIVATE_KEY || class == CKO_SECRET_KEY {
            return Some(key_type);
        }
        None
    }

    fn needs_sensitivity_check(&self) -> Option<&[CK_ULONG]> {
        let kt = self.private_key_type()?;
        for tuple in SENSITIVE {
            if tuple.0 == kt {
                return Some(tuple.1);
            }
        }
        None
    }

    fn is_sensitive_attr(&self, id: CK_ULONG, sense: &[CK_ULONG]) -> bool {
        if !sense.contains(&id) {
            return false;
        }
        if self.is_sensitive() {
            return true;
        }
        if !self.is_extractable() {
            return true;
        }
        false
    }

    pub fn fill_template(&self, template: &mut [CK_ATTRIBUTE]) -> KResult<()> {
        let sense = self.needs_sensitivity_check();
        let mut rv = CKR_OK;
        for elem in template.iter_mut() {
            if let Some(s) = sense {
                if self.is_sensitive_attr(elem.type_, s) {
                    elem.ulValueLen = CK_UNAVAILABLE_INFORMATION;
                    rv = CKR_ATTRIBUTE_SENSITIVE;
                    continue;
                }
            }
            let mut found = false;
            for attr in &self.attributes {
                if attr.get_type() == elem.type_ {
                    found = true;
                    if elem.pValue.is_null() {
                        elem.ulValueLen = attr.get_value().len() as CK_ULONG;
                        break;
                    }
                    let val = attr.get_value();
                    if (elem.ulValueLen as usize) < val.len() {
                        elem.ulValueLen = CK_UNAVAILABLE_INFORMATION;
                        rv = CKR_BUFFER_TOO_SMALL;
                        break;
                    }
                    unsafe {
                        std::ptr::copy_nonoverlapping(
                            val.as_ptr(),
                            elem.pValue as *mut _,
                            val.len(),
                        );
                    }
                    elem.ulValueLen = val.len() as CK_ULONG;
                    break;
                }
            }
            if !found {
                elem.ulValueLen = CK_UNAVAILABLE_INFORMATION;
                rv = CKR_ATTRIBUTE_TYPE_INVALID;
            }
        }
        if rv == CKR_OK {
            return Ok(());
        }
        err_rv!(rv)
    }
}

#[derive(Debug, Clone)]
struct ObjectAttr {
    attribute: Attribute,
    required: bool,
    present: bool,
    default: bool,
    ignore: bool,
}

macro_rules! attr_element {
    ($id:expr; req $required:expr; def $default:expr; $from_type:expr; val $defval:expr) => {
        ObjectAttr {
            attribute: $from_type($id, $defval),
            required: $required,
            present: false,
            default: $default,
            ignore: false,
        }
    };
}

macro_rules! attr_ignore {
    ($id:expr) => {
        ObjectAttr {
            attribute: from_ignore($id),
            required: false,
            present: false,
            default: false,
            ignore: true,
        }
    };
}

struct ObjectTemplates {
    data_object_template: Option<Vec<ObjectAttr>>,
    x509_pubkey_cert_template: Option<Vec<ObjectAttr>>,
}
fn lazy_init_common_object_attrs(attrs: &mut Vec<ObjectAttr>) {
    attrs
        .push(attr_element!(CKA_CLASS; req true; def false; from_ulong; val 0));
}
fn lazy_init_common_storage_attrs(attrs: &mut Vec<ObjectAttr>) {
    attrs.push(
        attr_element!(CKA_TOKEN; req false; def true; from_bool; val false),
    );
    attrs.push(
        attr_element!(CKA_PRIVATE; req false; def true; from_bool; val false),
    );
    attrs.push(
        attr_element!(CKA_MODIFIABLE; req false; def true; from_bool; val true),
    );
    attrs.push(attr_element!(CKA_LABEL; req false; def false; from_string; val String::new()));
    attrs.push(
        attr_element!(CKA_COPYABLE; req false; def true; from_bool; val true),
    );
    attrs.push(attr_element!(CKA_DESTROYABLE; req false; def true; from_bool; val true));
    attrs.push(attr_element!(CKA_UNIQUE_ID; req true; def false; from_string; val String::new()));
}

/* pkcs11-spec-v3.1 4.5 Data Objects */
fn lazy_init_data_object_attrs(attrs: &mut Vec<ObjectAttr>) {
    attrs.push(attr_element!(CKA_APPLICATION; req true; def false; from_string; val String::new()));
    attrs.push(attr_element!(CKA_OBJECT_ID; req false; def false; from_bytes; val Vec::new()));
    attrs.push(attr_element!(CKA_VALUE; req true; def false; from_bytes; val Vec::new()));
}
fn lazy_init_data_object_template() -> Vec<ObjectAttr> {
    let mut new_template = Vec::<ObjectAttr>::with_capacity(11);
    lazy_init_common_object_attrs(&mut new_template);
    lazy_init_common_storage_attrs(&mut new_template);
    lazy_init_data_object_attrs(&mut new_template);
    new_template
}

/* pkcs11-spec-v3.1 4.6 Certificate objects */
fn lazy_init_common_certificate_attrs(attrs: &mut Vec<ObjectAttr>) {
    attrs.push(attr_element!(CKA_CERTIFICATE_TYPE; req true; def false; from_ulong; val 0));
    attrs.push(
        attr_element!(CKA_TRUSTED; req false; def true; from_bool; val false),
    );
    attrs.push(attr_element!(CKA_CERTIFICATE_CATEGORY; req false; def true; from_ulong; val CK_CERTIFICATE_CATEGORY_UNSPECIFIED));
    attrs.push(attr_ignore!(CKA_CHECK_VALUE));
    attrs.push(attr_element!(CKA_START_DATE; req false; def true; from_date_bytes; val Vec::new()));
    attrs.push(attr_element!(CKA_END_DATE; req false; def true; from_date_bytes; val Vec::new()));
    attrs.push(attr_element!(CKA_PUBLIC_KEY_INFO; req false; def true; from_bytes; val Vec::new()));
}

/* pkcs11-spec-v3.1 4.6.3 X.509 public key certificate objects */
fn lazy_init_x509_pubkey_cert_attrs(attrs: &mut Vec<ObjectAttr>) {
    attrs.push(attr_element!(CKA_SUBJECT; req true; def false; from_bytes; val Vec::new()));
    attrs.push(
        attr_element!(CKA_ID; req false; def true; from_bytes; val Vec::new()),
    );
    attrs.push(attr_element!(CKA_ISSUER; req false; def true; from_bytes; val Vec::new()));
    attrs.push(attr_element!(CKA_SERIAL_NUMBER; req false; def true; from_bytes; val Vec::new()));
    attrs.push(attr_element!(CKA_VALUE; req true; def true; from_bytes; val Vec::new()));
    attrs.push(attr_element!(CKA_URL; req false; def false; from_string; val String::new()));
    attrs.push(attr_element!(CKA_HASH_OF_SUBJECT_PUBLIC_KEY; req false; def true; from_bytes; val Vec::new()));
    attrs.push(attr_element!(CKA_HASH_OF_ISSUER_PUBLIC_KEY; req false; def true; from_bytes; val Vec::new()));
    attrs.push(attr_element!(CKA_JAVA_MIDP_SECURITY_DOMAIN; req false; def true; from_ulong; val CK_SECURITY_DOMAIN_UNSPECIFIED));
    attrs.push(attr_element!(CKA_NAME_HASH_ALGORITHM; req false; def false; from_ulong; val CKM_SHA_1));
}

fn lazy_init_x509_pubkey_cert_template() -> Vec<ObjectAttr> {
    let mut new_template = Vec::<ObjectAttr>::with_capacity(11);
    lazy_init_common_object_attrs(&mut new_template);
    lazy_init_common_storage_attrs(&mut new_template);
    lazy_init_common_certificate_attrs(&mut new_template);
    lazy_init_x509_pubkey_cert_attrs(&mut new_template);
    new_template
}

static mut ATTR_DEFAULTS: ObjectTemplates = ObjectTemplates {
    data_object_template: None,
    x509_pubkey_cert_template: None,
};
static INIT: Once = Once::new();

fn get_object_templates() -> &'static ObjectTemplates {
    unsafe {
        INIT.call_once(|| {
            ATTR_DEFAULTS.data_object_template =
                Some(lazy_init_data_object_template());
            ATTR_DEFAULTS.x509_pubkey_cert_template =
                Some(lazy_init_x509_pubkey_cert_template());
        });
        &ATTR_DEFAULTS
    }
}

fn get_data_object_template() -> Vec<ObjectAttr> {
    get_object_templates()
        .data_object_template
        .as_ref()
        .map(|d| d.clone())
        .unwrap()
}

fn get_x509_pubkey_cert_template() -> Vec<ObjectAttr> {
    get_object_templates()
        .x509_pubkey_cert_template
        .as_ref()
        .map(|d| d.clone())
        .unwrap()
}

fn basic_object_attrs_checks(
    obj: &mut Object,
    cattrs: &mut Vec<ObjectAttr>,
) -> CK_RV {
    let mut remove = Vec::<CK_ULONG>::new();
    for attr in &obj.attributes {
        let typ = attr.get_type();
        let mut valid = false;
        for elem in cattrs.iter_mut() {
            if typ == elem.attribute.get_type() {
                if elem.ignore {
                    valid = true;
                    remove.push(typ);
                    break;
                }
                if elem.present {
                    /* duplicate */
                    return CKR_TEMPLATE_INCONSISTENT;
                }
                valid = true;
                elem.present = true;
                break;
            }
        }
        if !valid {
            return CKR_ATTRIBUTE_VALUE_INVALID;
        }
    }

    if remove.len() > 0 {
        for r in remove {
            obj.attributes.retain(|&ref x| x.get_type() != r)
        }
    }

    for elem in cattrs.iter_mut() {
        if !elem.present && elem.default {
            obj.attributes.push(elem.attribute.clone());
            elem.present = true;
        }
        if elem.required && !elem.present {
            return CKR_TEMPLATE_INCOMPLETE;
        }
    }

    CKR_OK
}

fn create_data_object(mut obj: Object) -> KResult<Object> {
    let mut cattrs = get_data_object_template();

    let ret = basic_object_attrs_checks(&mut obj, &mut cattrs);
    if ret != CKR_OK {
        return err_rv!(ret);
    }
    Ok(obj)
}

fn basic_cert_object_attrs_checks(
    obj: &mut Object,
    cattrs: &mut Vec<ObjectAttr>,
) -> CK_RV {
    let ret = basic_object_attrs_checks(obj, cattrs);
    if ret != CKR_OK {
        return ret;
    }

    match obj.get_attr_as_bool(CKA_TRUSTED) {
        Ok(t) => {
            if t == true {
                /* until we implement checking for SO auth */
                return CKR_ATTRIBUTE_READ_ONLY;
            }
        }
        Err(_) => (),
    }
    match obj.get_attr_as_ulong(CKA_CERTIFICATE_CATEGORY) {
        Ok(c) => match c {
            CK_CERTIFICATE_CATEGORY_UNSPECIFIED => (),
            CK_CERTIFICATE_CATEGORY_TOKEN_USER => (),
            CK_CERTIFICATE_CATEGORY_AUTHORITY => (),
            CK_CERTIFICATE_CATEGORY_OTHER_ENTITY => (),
            _ => return CKR_ATTRIBUTE_VALUE_INVALID,
        },
        Err(_) => (),
    }

    CKR_OK
}

fn create_x509_pubkey_cert_object(mut obj: Object) -> KResult<Object> {
    let mut cattrs = get_x509_pubkey_cert_template();

    let ret = basic_cert_object_attrs_checks(&mut obj, &mut cattrs);
    if ret != CKR_OK {
        return err_rv!(ret);
    }

    let value = match obj.get_attr_as_bytes(CKA_VALUE) {
        Ok(v) => v,
        Err(_) => return err_rv!(CKR_TEMPLATE_INCOMPLETE),
    };
    let url = match obj.get_attr_as_string(CKA_URL) {
        Ok(u) => u,
        Err(_) => String::new(),
    };
    if value.len() == 0 && url.len() == 0 {
        return err_rv!(CKR_ATTRIBUTE_VALUE_INVALID);
    }
    if url.len() > 0 {
        match obj.get_attr_as_bytes(CKA_HASH_OF_SUBJECT_PUBLIC_KEY) {
            Ok(h) => {
                if h.len() == 0 {
                    return err_rv!(CKR_ATTRIBUTE_VALUE_INVALID);
                }
            }
            Err(_) => return err_rv!(CKR_TEMPLATE_INCOMPLETE),
        }
        match obj.get_attr_as_bytes(CKA_HASH_OF_SUBJECT_PUBLIC_KEY) {
            Ok(h) => {
                if h.len() == 0 {
                    return err_rv!(CKR_ATTRIBUTE_VALUE_INVALID);
                }
            }
            Err(_) => return err_rv!(CKR_TEMPLATE_INCOMPLETE),
        }
    }
    match obj.get_attr_as_ulong(CKA_JAVA_MIDP_SECURITY_DOMAIN) {
        Ok(sd) => match sd {
            CK_SECURITY_DOMAIN_UNSPECIFIED => (),
            CK_SECURITY_DOMAIN_MANUFACTURER => (),
            CK_SECURITY_DOMAIN_OPERATOR => (),
            CK_SECURITY_DOMAIN_THIRD_PARTY => (),
            _ => return err_rv!(CKR_ATTRIBUTE_VALUE_INVALID),
        },
        Err(_) => (),
    }
    /* TODO: should we check if CKA_NAME_HASH_ALGORITHM? */

    Ok(obj)
}

fn create_cert_object(obj: Object) -> KResult<Object> {
    let ctype = match obj.get_attr_as_ulong(CKA_CERTIFICATE_TYPE) {
        Ok(c) => c,
        Err(_) => return err_rv!(CKR_TEMPLATE_INCOMPLETE),
    };
    match ctype {
        CKC_X_509 => create_x509_pubkey_cert_object(obj),
        /* not supported yet */
        CKC_X_509_ATTR_CERT => err_rv!(CKR_ATTRIBUTE_VALUE_INVALID),
        /* not supported yet */
        CKC_WTLS => err_rv!(CKR_ATTRIBUTE_VALUE_INVALID),
        _ => err_rv!(CKR_ATTRIBUTE_VALUE_INVALID),
    }
}

pub fn create(handle: CK_ULONG, template: &[CK_ATTRIBUTE]) -> KResult<Object> {
    let mut obj = Object {
        handle: handle,
        attributes: Vec::new(),
    };

    let uuid = Uuid::new_v4().to_string();
    obj.attributes
        .push(attribute::from_string(CKA_UNIQUE_ID, uuid));

    for ck_attr in template.iter() {
        obj.attributes.push(ck_attr.to_attribute()?);
    }

    let class = match obj.get_attr_as_ulong(CKA_CLASS) {
        Ok(c) => c,
        Err(_) => return err_rv!(CKR_TEMPLATE_INCOMPLETE),
    };
    match class {
        CKO_DATA => create_data_object(obj),
        CKO_CERTIFICATE => create_cert_object(obj),
        CKO_PUBLIC_KEY => err_rv!(CKR_ATTRIBUTE_VALUE_INVALID),
        CKO_PRIVATE_KEY => err_rv!(CKR_ATTRIBUTE_VALUE_INVALID),
        CKO_SECRET_KEY => err_rv!(CKR_ATTRIBUTE_VALUE_INVALID),
        CKO_HW_FEATURE => err_rv!(CKR_ATTRIBUTE_VALUE_INVALID),
        CKO_DOMAIN_PARAMETERS => err_rv!(CKR_ATTRIBUTE_VALUE_INVALID),
        CKO_MECHANISM => err_rv!(CKR_ATTRIBUTE_VALUE_INVALID),
        CKO_OTP_KEY => err_rv!(CKR_ATTRIBUTE_VALUE_INVALID),
        CKO_PROFILE => err_rv!(CKR_ATTRIBUTE_VALUE_INVALID),
        CKO_VENDOR_DEFINED => err_rv!(CKR_ATTRIBUTE_VALUE_INVALID),
        _ => err_rv!(CKR_ATTRIBUTE_VALUE_INVALID),
    }
}
