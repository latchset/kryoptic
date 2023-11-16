// Copyright 2023 Simo Sorce
// See LICENSE.txt file for terms

use bitflags::bitflags;
use std::collections::HashMap;

use super::attribute;
use super::error;
use super::interface;
use super::rng;
use super::{err_not_found, err_rv};
use attribute::{
    from_bool, from_bytes, from_date_bytes, from_ignore, from_string,
    from_ulong, AttrType, Attribute,
};
use error::{KError, KResult};
use interface::*;
use rng::RNG;
use std::fmt::Debug;

use uuid::Uuid;

macro_rules! create_bool_checker {
    (make $name:ident; from $id:expr; def $def:expr) => {
        #[allow(dead_code)]
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

#[derive(Debug, Clone)]
pub struct Object {
    handle: CK_OBJECT_HANDLE,
    session: CK_SESSION_HANDLE,
    attributes: Vec<Attribute>,
}

impl Object {
    pub fn new() -> Object {
        Object {
            handle: CK_INVALID_HANDLE,
            session: CK_INVALID_HANDLE,
            attributes: Vec::new(),
        }
    }

    pub fn generate_unique(&mut self) {
        if !self
            .attributes
            .iter()
            .any(|r| r.get_type() == CKA_UNIQUE_ID)
        {
            let uuid = Uuid::new_v4().to_string();
            self.attributes
                .push(attribute::from_string(CKA_UNIQUE_ID, uuid));
        }
    }

    pub fn blind_copy(&self) -> KResult<Object> {
        let mut obj = Object::new();
        obj.generate_unique();
        for attr in &self.attributes {
            if attr.get_type() == CKA_UNIQUE_ID {
                continue;
            }
            obj.attributes.push(attr.clone())
        }
        Ok(obj)
    }

    pub fn set_handle(&mut self, h: CK_OBJECT_HANDLE) {
        self.handle = h
    }

    pub fn get_handle(&self) -> CK_OBJECT_HANDLE {
        self.handle
    }

    pub fn set_session(&mut self, s: CK_SESSION_HANDLE) {
        self.session = s
    }

    pub fn get_session(&self) -> CK_SESSION_HANDLE {
        self.session
    }

    create_bool_checker! {make is_token; from CKA_TOKEN; def false}
    create_bool_checker! {make is_private; from CKA_PRIVATE; def true}
    create_bool_checker! {make is_sensitive; from CKA_SENSITIVE; def true}
    create_bool_checker! {make is_copyable; from CKA_COPYABLE; def true}
    create_bool_checker! {make is_modifiable; from CKA_MODIFIABLE; def true}
    create_bool_checker! {make is_destroyable; from CKA_DESTROYABLE; def false}
    create_bool_checker! {make is_extractable; from CKA_EXTRACTABLE; def false}

    pub fn get_attr(&self, ck_type: CK_ULONG) -> Option<&Attribute> {
        self.attributes.iter().find(|r| r.get_type() == ck_type)
    }

    pub fn set_attr(&mut self, a: Attribute) -> KResult<()> {
        let atype = a.get_type();
        match self.attributes.iter().position(|r| r.get_type() == atype) {
            Some(idx) => self.attributes[idx] = a,
            None => self.attributes.push(a),
        }
        Ok(())
    }

    pub fn del_attr(&mut self, ck_type: CK_ULONG) {
        self.attributes.retain(|a| a.get_type() != ck_type);
    }

    pub fn get_attributes(&self) -> &Vec<Attribute> {
        return &self.attributes;
    }

    attr_as_type! {make get_attr_as_bool; with bool; BoolType; via to_bool}
    attr_as_type! {make get_attr_as_ulong; with CK_ULONG; NumType; via to_ulong}
    attr_as_type! {make get_attr_as_string; with String; StringType; via to_string}
    attr_as_type! {make get_attr_as_bytes; with &Vec<u8>; BytesType; via to_bytes}

    pub fn match_template(&self, template: &[CK_ATTRIBUTE]) -> bool {
        for ck_attr in template {
            match self.attributes.iter().find(|r| r.match_ck_attr(ck_attr)) {
                Some(_) => (),
                None => return false,
            }
        }
        true
    }
}

bitflags! {
    #[derive(Debug, Clone)]
    pub struct OAFlags: u32 {
        const Ignored              = 0b00000000000001;
        const Sensitive            = 0b00000000000010;
        const Defval               = 0b00000000000100;
        const Required             = 0b00000000001000;
        const RequiredOnCreate     = 0b00000000011000;
        const RequiredOnGenerate   = 0b00000000101000;
        const AlwaysRequired       = 0b00000000111000;
        const Unsettable           = 0b00000001000000;
        const UnsettableOnCreate   = 0b00000011000000;
        const UnsettableOnGenerate = 0b00000101000000;
        const UnsettableOnUnwrap   = 0b00001001000000;
        const NeverSettable        = 0b00001111000000;
        const Unchangeable         = 0b00010000000000;
        const ChangeToFalse        = 0b00110000000000;
        const ChangeToTrue         = 0b01010000000000;
        const ChangeOnCopy         = 0b10010000000000;
    }
}

#[derive(Debug, Clone)]
pub struct ObjectAttr {
    attribute: Attribute,
    flags: OAFlags,
}

impl ObjectAttr {
    pub fn new(a: Attribute, f: OAFlags) -> ObjectAttr {
        ObjectAttr {
            attribute: a,
            flags: f,
        }
    }

    pub fn get_type(&self) -> CK_ULONG {
        self.attribute.get_type()
    }

    pub fn clone_attr(&self) -> Attribute {
        self.attribute.clone()
    }

    pub fn is(&self, val: OAFlags) -> bool {
        self.flags.contains(val)
    }

    pub fn has_default(&self) -> bool {
        self.flags.contains(OAFlags::Defval)
    }
}

#[macro_export]
macro_rules! attr_element {
    ($id:expr; $flags:expr; $from_type:expr; val $defval:expr) => {
        ObjectAttr::new($from_type($id, $defval), $flags)
    };
}

#[macro_export]
macro_rules! bytes_attr_not_empty {
    ($obj:expr; $id:expr) => {
        match $obj.get_attr_as_bytes($id) {
            Ok(e) => {
                if e.len() == 0 {
                    return err_rv!(CKR_ATTRIBUTE_VALUE_INVALID);
                }
            }
            Err(e) => match e {
                KError::NotFound(_) => return err_rv!(CKR_TEMPLATE_INCOMPLETE),
                _ => return Err(e),
            },
        }
    };
}

pub trait ObjectTemplate: Debug + Send + Sync {
    fn create(&self, _template: &[CK_ATTRIBUTE]) -> KResult<Object> {
        return err_rv!(CKR_GENERAL_ERROR);
    }

    fn copy(&self, obj: &Object, template: &[CK_ATTRIBUTE]) -> KResult<Object> {
        self.default_copy(obj, template)
    }

    fn genkey(
        &self,
        _rng: &mut RNG,
        _template: &[CK_ATTRIBUTE],
        _ktype: CK_KEY_TYPE,
    ) -> KResult<Object> {
        return err_rv!(CKR_GENERAL_ERROR);
    }

    fn stubpubkeyhalf(
        &self,
        _pubkey_template: &[CK_ATTRIBUTE],
    ) -> KResult<Object> {
        return err_rv!(CKR_GENERAL_ERROR);
    }

    fn genkeypair(
        &self,
        _rng: &mut RNG,
        _pubkey: &mut Object,
        _prikey_template: &[CK_ATTRIBUTE],
    ) -> KResult<Object> {
        return err_rv!(CKR_GENERAL_ERROR);
    }

    fn get_attributes(&self) -> &Vec<ObjectAttr>;

    fn init_common_object_attrs(&self) -> Vec<ObjectAttr> {
        vec![
            attr_element!(CKA_CLASS; OAFlags::RequiredOnCreate; from_ulong; val 0),
        ]
    }
    fn init_common_storage_attrs(&self) -> Vec<ObjectAttr> {
        vec![
            attr_element!(CKA_TOKEN; OAFlags::Defval | OAFlags::ChangeOnCopy; from_bool; val false),
            attr_element!(CKA_PRIVATE; OAFlags::Defval | OAFlags::ChangeOnCopy; from_bool; val false),
            attr_element!(CKA_MODIFIABLE; OAFlags::Defval | OAFlags::ChangeOnCopy; from_bool; val true),
            attr_element!(CKA_LABEL; OAFlags::empty(); from_string; val String::new()),
            attr_element!(CKA_COPYABLE; OAFlags::Defval | OAFlags::ChangeToFalse; from_bool; val true),
            attr_element!(CKA_DESTROYABLE; OAFlags::Defval; from_bool; val true),
            attr_element!(CKA_UNIQUE_ID; OAFlags::NeverSettable | OAFlags::Unchangeable; from_string; val String::new()),
        ]
    }

    fn default_object_create(
        &self,
        template: &[CK_ATTRIBUTE],
    ) -> KResult<Object> {
        let attributes = self.get_attributes();
        let mut obj = Object::new();
        for ck_attr in template {
            match attributes.iter().find(|a| a.get_type() == ck_attr.type_) {
                Some(attr) => {
                    if attr.is(OAFlags::UnsettableOnCreate) {
                        return err_rv!(CKR_ATTRIBUTE_TYPE_INVALID);
                    }
                    /* duplicate? */
                    match obj.get_attr(ck_attr.type_) {
                        Some(_) => return err_rv!(CKR_TEMPLATE_INCONSISTENT),
                        None => (),
                    }
                    if !attr.is(OAFlags::Ignored) {
                        obj.attributes.push(ck_attr.to_attribute()?);
                    }
                }
                None => {
                    return err_rv!(CKR_ATTRIBUTE_VALUE_INVALID);
                }
            }
        }
        for attr in attributes {
            match obj.get_attr(attr.get_type()) {
                Some(_) => (),
                None => {
                    if attr.has_default() {
                        obj.attributes.push(attr.attribute.clone());
                    } else if attr.is(OAFlags::RequiredOnCreate) {
                        return err_rv!(CKR_TEMPLATE_INCOMPLETE);
                    }
                }
            }
        }
        obj.generate_unique();
        Ok(obj)
    }

    fn default_copy(
        &self,
        origin: &Object,
        template: &[CK_ATTRIBUTE],
    ) -> KResult<Object> {
        let attributes = self.get_attributes();
        for ck_attr in template {
            match attributes.iter().find(|a| a.get_type() == ck_attr.type_) {
                Some(attr) => {
                    if attr.is(OAFlags::Unchangeable) {
                        if attr
                            .is(OAFlags::ChangeToFalse | OAFlags::ChangeToTrue)
                        {
                            let val =
                                match origin.get_attr_as_bool(ck_attr.type_) {
                                    Ok(a) => a,
                                    Err(_) => false,
                                };
                            if val && !attr.is(OAFlags::ChangeToFalse) {
                                return err_rv!(CKR_ATTRIBUTE_READ_ONLY);
                            }
                            if !val && !attr.is(OAFlags::ChangeToTrue) {
                                return err_rv!(CKR_ATTRIBUTE_READ_ONLY);
                            }
                        }
                        if !attr.is(OAFlags::ChangeOnCopy) {
                            return err_rv!(CKR_ATTRIBUTE_READ_ONLY);
                        }
                    }
                }
                None => return err_rv!(CKR_TEMPLATE_INCONSISTENT),
            }
        }

        let mut obj = origin.blind_copy()?;
        for ck_attr in template {
            let _ = obj.set_attr(ck_attr.to_attribute()?);
        }

        /* special attrs handling */
        match obj.get_attr_as_bool(CKA_EXTRACTABLE) {
            Ok(e) => {
                let mut val = !e;
                match obj.get_attr_as_bool(CKA_NEVER_EXTRACTABLE) {
                    Ok(ne) => val &= ne,
                    Err(_) => match origin.get_attr_as_bool(CKA_EXTRACTABLE) {
                        Ok(oe) => val &= !oe,
                        Err(_) => val = false,
                    },
                }
                let _ = obj.set_attr(from_bool(CKA_NEVER_EXTRACTABLE, val))?;
            }
            Err(_) => (),
        }
        match obj.get_attr_as_bool(CKA_SENSITIVE) {
            Ok(b) => {
                let mut val = b;
                match origin.get_attr_as_bool(CKA_ALWAYS_SENSITIVE) {
                    Ok(ob) => val &= ob,
                    Err(_) => match origin.get_attr_as_bool(CKA_SENSITIVE) {
                        Ok(os) => val &= os,
                        Err(_) => val = false,
                    },
                }
                let _ = obj.set_attr(from_bool(CKA_ALWAYS_SENSITIVE, val))?;
            }
            Err(_) => (),
        }

        Ok(obj)
    }
}

/* pkcs11-spec-v3.1 4.5 Data Objects */
#[derive(Debug)]
struct DataTemplate {
    attributes: Vec<ObjectAttr>,
}

impl DataTemplate {
    fn new() -> DataTemplate {
        let mut data: DataTemplate = DataTemplate {
            attributes: Vec::new(),
        };
        data.attributes.append(&mut data.init_common_object_attrs());
        data.attributes.append(&mut data.init_common_storage_attrs());
        data.attributes.push(attr_element!(CKA_APPLICATION; OAFlags::Defval; from_string; val String::new()));
        data.attributes.push(attr_element!(CKA_OBJECT_ID; OAFlags::empty(); from_bytes; val Vec::new()));
        data.attributes.push(attr_element!(CKA_VALUE; OAFlags::Defval; from_bytes; val Vec::new()));
        data
    }
}

impl ObjectTemplate for DataTemplate {
    fn create(&self, template: &[CK_ATTRIBUTE]) -> KResult<Object> {
        self.default_object_create(template)
    }

    fn copy(
        &self,
        origin: &Object,
        template: &[CK_ATTRIBUTE],
    ) -> KResult<Object> {
        self.default_copy(origin, template)
    }

    fn get_attributes(&self) -> &Vec<ObjectAttr> {
        &self.attributes
    }
}

/* pkcs11-spec-v3.1 4.6 Certificate objects */
pub trait CertTemplate {
    fn init_common_certificate_attrs(&self) -> Vec<ObjectAttr> {
        vec![
            attr_element!(CKA_CERTIFICATE_TYPE; OAFlags::Required; from_ulong; val 0),
            attr_element!(CKA_TRUSTED; OAFlags::Defval; from_bool; val false),
            attr_element!(CKA_CERTIFICATE_CATEGORY; OAFlags::Defval; from_ulong; val CK_CERTIFICATE_CATEGORY_UNSPECIFIED),
            attr_element!(CKA_CHECK_VALUE; OAFlags::Ignored; from_ignore; val None),
            attr_element!(CKA_START_DATE; OAFlags::Defval; from_date_bytes; val Vec::new()),
            attr_element!(CKA_END_DATE; OAFlags::Defval; from_date_bytes; val Vec::new()),
            attr_element!(CKA_PUBLIC_KEY_INFO; OAFlags::Defval; from_bytes; val Vec::new()),
        ]
    }

    fn basic_cert_object_create_checks(&self, obj: &mut Object) -> CK_RV {
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

    fn get_attributes(&self) -> &Vec<ObjectAttr>;
}

/* pkcs11-spec-v3.1 4.6.3 X.509 public key certificate objects */
#[derive(Debug)]
struct X509Template {
    attributes: Vec<ObjectAttr>,
}

impl X509Template {
    fn new() -> X509Template {
        let mut data: X509Template = X509Template {
            attributes: Vec::new(),
        };
        data.attributes.append(&mut data.init_common_object_attrs());
        data.attributes.append(&mut data.init_common_storage_attrs());
        data.attributes.append(&mut data.init_common_certificate_attrs());
        data.attributes.push(attr_element!(CKA_SUBJECT; OAFlags::Required; from_bytes; val Vec::new()));
        data.attributes.push(
            attr_element!(CKA_ID; OAFlags::Defval; from_bytes; val Vec::new()),
        );
        data.attributes.push(attr_element!(CKA_ISSUER; OAFlags::Defval; from_bytes; val Vec::new()));
        data.attributes.push(attr_element!(CKA_SERIAL_NUMBER; OAFlags::Defval; from_bytes; val Vec::new()));
        data.attributes.push(attr_element!(CKA_VALUE; OAFlags::Required; from_bytes; val Vec::new()));
        data.attributes.push(attr_element!(CKA_URL; OAFlags::empty(); from_string; val String::new()));
        data.attributes.push(attr_element!(CKA_HASH_OF_SUBJECT_PUBLIC_KEY; OAFlags::Defval; from_bytes; val Vec::new()));
        data.attributes.push(attr_element!(CKA_HASH_OF_ISSUER_PUBLIC_KEY; OAFlags::Defval; from_bytes; val Vec::new()));
        data.attributes.push(attr_element!(CKA_JAVA_MIDP_SECURITY_DOMAIN; OAFlags::Defval; from_ulong; val CK_SECURITY_DOMAIN_UNSPECIFIED));
        data.attributes.push(attr_element!(CKA_NAME_HASH_ALGORITHM; OAFlags::empty(); from_ulong; val CKM_SHA_1));
        data
    }
}

impl CertTemplate for X509Template {
    fn get_attributes(&self) -> &Vec<ObjectAttr> {
        &self.attributes
    }
}

impl ObjectTemplate for X509Template {
    fn create(&self, template: &[CK_ATTRIBUTE]) -> KResult<Object> {
        let mut obj = self.default_object_create(template)?;

        let ret = self.basic_cert_object_create_checks(&mut obj);
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

    fn get_attributes(&self) -> &Vec<ObjectAttr> {
        &self.attributes
    }
}

/* pkcs11-spec-v3.1 4.7 Key objects */
pub trait CommonKeyTemplate {
    fn init_common_key_attrs(&self) -> Vec<ObjectAttr> {
        vec![
            attr_element!(CKA_KEY_TYPE; OAFlags::RequiredOnCreate; from_ulong; val CK_UNAVAILABLE_INFORMATION),
            attr_element!(CKA_ID; OAFlags::empty(); from_bytes; val Vec::new()),
            attr_element!(CKA_START_DATE; OAFlags::Defval; from_date_bytes; val Vec::new()),
            attr_element!(CKA_END_DATE; OAFlags::Defval; from_date_bytes; val Vec::new()),
            attr_element!(CKA_DERIVE; OAFlags::Defval; from_bool; val false),
            attr_element!(CKA_LOCAL; OAFlags::Defval | OAFlags::NeverSettable; from_bool; val false),
            attr_element!(CKA_KEY_GEN_MECHANISM; OAFlags::Defval | OAFlags::NeverSettable; from_ulong; val CK_UNAVAILABLE_INFORMATION),
            attr_element!(CKA_ALLOWED_MECHANISMS; OAFlags::empty(); from_bytes; val Vec::new()),
        ]
    }

    fn get_attributes(&self) -> &Vec<ObjectAttr>;
}

/* pkcs11-spec-v3.1 4.8 Public key objects */
pub trait PubKeyTemplate {
    fn init_common_public_key_attrs(&self) -> Vec<ObjectAttr> {
        vec![
            attr_element!(CKA_SUBJECT; OAFlags::Defval; from_bytes; val Vec::new()),
            attr_element!(CKA_ENCRYPT; OAFlags::empty(); from_bool; val false),
            attr_element!(CKA_VERIFY; OAFlags::empty(); from_bool; val false),
            attr_element!(CKA_VERIFY_RECOVER; OAFlags::empty(); from_bool; val false),
            attr_element!(CKA_WRAP; OAFlags::empty(); from_bool; val false),
            attr_element!(CKA_TRUSTED; OAFlags::NeverSettable; from_bool; val false),
            attr_element!(CKA_WRAP_TEMPLATE; OAFlags::empty(); from_bytes; val Vec::new()),
            attr_element!(CKA_PUBLIC_KEY_INFO; OAFlags::empty(); from_bytes; val Vec::new()),
        ]
    }

    fn get_attributes(&self) -> &Vec<ObjectAttr>;
}

/* pkcs11-spec-v3.1 4.9 Private key objects */
pub trait PrivKeyTemplate {
    fn init_common_private_key_attrs(&self) -> Vec<ObjectAttr> {
        vec![
            attr_element!(CKA_SUBJECT; OAFlags::Defval; from_bytes; val Vec::new()),
            attr_element!(CKA_SENSITIVE; OAFlags::Defval | OAFlags::ChangeToTrue; from_bool; val true),
            attr_element!(CKA_DECRYPT; OAFlags::empty(); from_bool; val false),
            attr_element!(CKA_SIGN; OAFlags::empty(); from_bool; val false),
            attr_element!(CKA_SIGN_RECOVER; OAFlags::empty(); from_bool; val false),
            attr_element!(CKA_UNWRAP; OAFlags::empty(); from_bool; val false),
            attr_element!(CKA_EXTRACTABLE; OAFlags::ChangeToFalse; from_bool; val false),
            attr_element!(CKA_ALWAYS_SENSITIVE; OAFlags::NeverSettable; from_bool; val false),
            attr_element!(CKA_NEVER_EXTRACTABLE; OAFlags::NeverSettable; from_bool; val false),
            attr_element!(CKA_WRAP_WITH_TRUSTED; OAFlags::Defval | OAFlags::ChangeToTrue; from_bool; val false),
            attr_element!(CKA_UNWRAP_TEMPLATE; OAFlags::empty(); from_bytes; val Vec::new()),
            attr_element!(CKA_ALWAYS_AUTHENTICATE; OAFlags::Defval; from_bool; val false),
            attr_element!(CKA_PUBLIC_KEY_INFO; OAFlags::empty(); from_bytes; val Vec::new()),
            attr_element!(CKA_DERIVE_TEMPLATE; OAFlags::empty(); from_bytes; val Vec::new()),
        ]
    }

    fn get_attributes(&self) -> &Vec<ObjectAttr>;
}

/* pkcs11-spec-v3.1 4.10 Secre key objects */
pub trait SecretKeyTemplate {
    fn init_common_secret_key_attrs(&self) -> Vec<ObjectAttr> {
        vec![
            attr_element!(CKA_SENSITIVE; OAFlags::Defval | OAFlags::ChangeToTrue; from_bool; val true),
            attr_element!(CKA_ENCRYPT; OAFlags::empty(); from_bool; val false),
            attr_element!(CKA_DECRYPT; OAFlags::empty(); from_bool; val false),
            attr_element!(CKA_SIGN; OAFlags::empty(); from_bool; val false),
            attr_element!(CKA_VERIFY; OAFlags::empty(); from_bool; val false),
            attr_element!(CKA_WRAP; OAFlags::empty(); from_bool; val false),
            attr_element!(CKA_UNWRAP; OAFlags::empty(); from_bool; val false),
            attr_element!(CKA_EXTRACTABLE; OAFlags::ChangeToFalse; from_bool; val false),
            attr_element!(CKA_ALWAYS_SENSITIVE; OAFlags::NeverSettable; from_bool; val false),
            attr_element!(CKA_NEVER_EXTRACTABLE; OAFlags::NeverSettable; from_bool; val false),
            attr_element!(CKA_CHECK_VALUE; OAFlags::Ignored; from_ignore; val None),
            attr_element!(CKA_WRAP_WITH_TRUSTED; OAFlags::Defval | OAFlags::ChangeToTrue; from_bool; val false),
            attr_element!(CKA_TRUSTED; OAFlags::NeverSettable; from_bool; val false),
            attr_element!(CKA_WRAP_TEMPLATE; OAFlags::empty(); from_bytes; val Vec::new()),
            attr_element!(CKA_UNWRAP_TEMPLATE; OAFlags::empty(); from_bytes; val Vec::new()),
            attr_element!(CKA_DERIVE_TEMPLATE; OAFlags::empty(); from_bytes; val Vec::new()),
        ]
    }

    fn get_attributes(&self) -> &Vec<ObjectAttr>;
}

/* pkcs11-spec-v3.1 6.8 Generic secret key */
#[derive(Debug)]
struct GenericSecretKeyTemplate {
    attributes: Vec<ObjectAttr>,
}

impl GenericSecretKeyTemplate {
    fn new() -> GenericSecretKeyTemplate {
        let mut data: GenericSecretKeyTemplate = GenericSecretKeyTemplate {
            attributes: Vec::new(),
        };
        data.attributes.append(&mut data.init_common_object_attrs());
        data.attributes.append(&mut data.init_common_storage_attrs());
        data.attributes.append(&mut data.init_common_key_attrs());
        data.attributes.append(&mut data.init_common_secret_key_attrs());
        data.attributes.push(attr_element!(CKA_VALUE; OAFlags::Defval | OAFlags::Sensitive | OAFlags::RequiredOnCreate | OAFlags::UnsettableOnGenerate | OAFlags::UnsettableOnUnwrap; from_bytes; val Vec::new()));
        data.attributes.push(attr_element!(CKA_VALUE_LEN; OAFlags::RequiredOnGenerate | OAFlags::UnsettableOnCreate; from_bytes; val Vec::new()));

        /* default to private */
        let private = attr_element!(CKA_PRIVATE; OAFlags::Defval | OAFlags::ChangeOnCopy; from_bool; val true);
        match data
            .attributes
            .iter()
            .position(|x| x.get_type() == CKA_PRIVATE)
        {
            Some(idx) => data.attributes[idx] = private,
            None => data.attributes.push(private),
        }

        data
    }

    fn get_attributes(&self) -> &Vec<ObjectAttr> {
        &self.attributes
    }
}

impl ObjectTemplate for GenericSecretKeyTemplate {
    fn create(&self, template: &[CK_ATTRIBUTE]) -> KResult<Object> {
        let obj = self.default_object_create(template)?;

        bytes_attr_not_empty!(obj; CKA_VALUE);

        Ok(obj)
    }

    fn genkey(
        &self,
        rng: &mut RNG,
        template: &[CK_ATTRIBUTE],
        ktype: CK_KEY_TYPE,
    ) -> KResult<Object> {
        let attributes = self.get_attributes();
        let mut obj = Object::new();
        for ck_attr in template {
            match attributes.iter().find(|a| a.get_type() == ck_attr.type_) {
                Some(attr) => {
                    if attr.is(OAFlags::UnsettableOnGenerate) {
                        return err_rv!(CKR_ATTRIBUTE_TYPE_INVALID);
                    }
                    /* duplicate? */
                    match obj.get_attr(ck_attr.type_) {
                        Some(_) => return err_rv!(CKR_TEMPLATE_INCONSISTENT),
                        None => (),
                    }
                    if !attr.is(OAFlags::Ignored) {
                        obj.attributes.push(ck_attr.to_attribute()?);
                    }
                }
                None => {
                    return err_rv!(CKR_ATTRIBUTE_VALUE_INVALID);
                }
            }
        }
        for attr in attributes {
            match obj.get_attr(attr.get_type()) {
                Some(_) => (),
                None => {
                    if attr.has_default() {
                        obj.attributes.push(attr.attribute.clone());
                    } else if attr.is(OAFlags::RequiredOnGenerate) {
                        return err_rv!(CKR_TEMPLATE_INCOMPLETE);
                    }
                }
            }
        }
        let value_len = obj.get_attr_as_ulong(CKA_VALUE_LEN)? as usize;
        let mut value: Vec<u8> = vec![0; value_len];
        rng.generate_random(value.as_mut_slice())?;
        obj.del_attr(CKA_VALUE_LEN);
        obj.set_attr(attribute::from_bytes(CKA_VALUE, value))?;
        obj.set_attr(attribute::from_ulong(CKA_KEY_TYPE, ktype))?;

        obj.generate_unique();
        Ok(obj)
    }

    fn get_attributes(&self) -> &Vec<ObjectAttr> {
        &self.attributes
    }
}

impl CommonKeyTemplate for GenericSecretKeyTemplate {
    fn get_attributes(&self) -> &Vec<ObjectAttr> {
        &self.attributes
    }
}

impl SecretKeyTemplate for GenericSecretKeyTemplate {
    fn get_attributes(&self) -> &Vec<ObjectAttr> {
        &self.attributes
    }
}

#[derive(Debug, Eq, Hash, PartialEq)]
pub enum ObjectType {
    DataObj,
    X509CertObj,
    RSAPubKey,
    RSAPrivKey,
    GenericSecretKey,
}

#[derive(Debug)]
pub struct ObjectTemplates {
    templates: HashMap<ObjectType, Box<dyn ObjectTemplate>>,
}

impl ObjectTemplates {
    pub fn new() -> ObjectTemplates {
        let mut ot: ObjectTemplates = ObjectTemplates {
            templates: HashMap::new(),
        };
        ot.templates
            .insert(ObjectType::DataObj, Box::new(DataTemplate::new()));
        ot.templates
            .insert(ObjectType::X509CertObj, Box::new(X509Template::new()));
        ot.templates.insert(
            ObjectType::GenericSecretKey,
            Box::new(GenericSecretKeyTemplate::new()),
        );
        ot
    }

    pub fn add_template(
        &mut self,
        typ: ObjectType,
        templ: Box<dyn ObjectTemplate>,
    ) {
        self.templates.insert(typ, templ);
    }

    fn get_template(
        &self,
        otype: ObjectType,
    ) -> KResult<&Box<dyn ObjectTemplate>> {
        match self.templates.get(&otype) {
            Some(b) => Ok(b),
            None => err_rv!(CKR_ATTRIBUTE_VALUE_INVALID),
        }
    }

    pub fn create(&self, template: &[CK_ATTRIBUTE]) -> KResult<Object> {
        let class = match template.iter().find(|a| a.type_ == CKA_CLASS) {
            Some(c) => c.to_ulong()?,
            None => return err_rv!(CKR_TEMPLATE_INCOMPLETE),
        };
        match class {
            CKO_DATA => {
                self.get_template(ObjectType::DataObj)?.create(template)
            }
            CKO_CERTIFICATE => {
                let ctype = match template
                    .iter()
                    .find(|a| a.type_ == CKA_CERTIFICATE_TYPE)
                {
                    Some(c) => c.to_ulong()?,
                    None => return err_rv!(CKR_TEMPLATE_INCOMPLETE),
                };
                match ctype {
                    CKC_X_509 => self
                        .get_template(ObjectType::X509CertObj)?
                        .create(template),
                    /* not supported yet */
                    CKC_X_509_ATTR_CERT => err_rv!(CKR_ATTRIBUTE_VALUE_INVALID),
                    /* not supported yet */
                    CKC_WTLS => err_rv!(CKR_ATTRIBUTE_VALUE_INVALID),
                    _ => err_rv!(CKR_ATTRIBUTE_VALUE_INVALID),
                }
            }
            CKO_PUBLIC_KEY => {
                let ktype =
                    match template.iter().find(|a| a.type_ == CKA_KEY_TYPE) {
                        Some(k) => k.to_ulong()?,
                        None => return err_rv!(CKR_TEMPLATE_INCOMPLETE),
                    };
                match ktype {
                    CKK_RSA => self
                        .get_template(ObjectType::RSAPubKey)?
                        .create(template),
                    _ => err_rv!(CKR_ATTRIBUTE_VALUE_INVALID),
                }
            }
            CKO_PRIVATE_KEY => {
                let ktype =
                    match template.iter().find(|a| a.type_ == CKA_KEY_TYPE) {
                        Some(k) => k.to_ulong()?,
                        None => return err_rv!(CKR_TEMPLATE_INCOMPLETE),
                    };
                match ktype {
                    CKK_RSA => self
                        .get_template(ObjectType::RSAPrivKey)?
                        .create(template),
                    _ => err_rv!(CKR_ATTRIBUTE_VALUE_INVALID),
                }
            }
            CKO_SECRET_KEY => {
                let ktype =
                    match template.iter().find(|a| a.type_ == CKA_KEY_TYPE) {
                        Some(k) => k.to_ulong()?,
                        None => return err_rv!(CKR_TEMPLATE_INCOMPLETE),
                    };
                match ktype {
                    CKK_GENERIC_SECRET | CKK_SHA_1_HMAC | CKK_SHA256_HMAC
                    | CKK_SHA384_HMAC | CKK_SHA512_HMAC => self
                        .get_template(ObjectType::GenericSecretKey)?
                        .create(template),
                    _ => err_rv!(CKR_ATTRIBUTE_VALUE_INVALID),
                }
            }
            /* TODO:
             *  CKO_HW_FEATURE, CKO_DOMAIN_PARAMETERS,
             *  CKO_MECHANISM, CKO_OTP_KEY, CKO_PROFILE,
             *  CKO_VENDOR_DEFINED
             */
            _ => err_rv!(CKR_ATTRIBUTE_VALUE_INVALID),
        }
    }

    fn get_object_template(
        &self,
        obj: &Object,
    ) -> KResult<&Box<dyn ObjectTemplate>> {
        match obj.get_attr_as_ulong(CKA_CLASS) {
            Err(_) => err_rv!(CKR_DEVICE_ERROR),
            Ok(class) => match class {
                CKO_DATA => self.get_template(ObjectType::DataObj),
                CKO_CERTIFICATE => match obj
                    .get_attr_as_ulong(CKA_CERTIFICATE_TYPE)
                {
                    Err(_) => err_rv!(CKR_DEVICE_ERROR),
                    Ok(ctype) => match ctype {
                        CKC_X_509 => self.get_template(ObjectType::X509CertObj),
                        /* not supported yet: CKC_X_509_ATTR_CERT, CKC_WTLS */
                        _ => err_rv!(CKR_DEVICE_ERROR),
                    },
                },
                CKO_PUBLIC_KEY => match obj.get_attr_as_ulong(CKA_KEY_TYPE) {
                    Err(_) => err_rv!(CKR_DEVICE_ERROR),
                    Ok(ktype) => match ktype {
                        CKK_RSA => self.get_template(ObjectType::RSAPubKey),
                        _ => err_rv!(CKR_DEVICE_ERROR),
                    },
                },
                CKO_PRIVATE_KEY => match obj.get_attr_as_ulong(CKA_KEY_TYPE) {
                    Err(_) => err_rv!(CKR_DEVICE_ERROR),
                    Ok(ktype) => match ktype {
                        CKK_RSA => self.get_template(ObjectType::RSAPrivKey),
                        _ => err_rv!(CKR_DEVICE_ERROR),
                    },
                },
                CKO_SECRET_KEY => match obj.get_attr_as_ulong(CKA_KEY_TYPE) {
                    Err(_) => err_rv!(CKR_DEVICE_ERROR),
                    Ok(ktype) => match ktype {
                        CKK_GENERIC_SECRET | CKK_SHA_1_HMAC
                        | CKK_SHA256_HMAC | CKK_SHA384_HMAC
                        | CKK_SHA512_HMAC => {
                            self.get_template(ObjectType::GenericSecretKey)
                        }
                        _ => err_rv!(CKR_DEVICE_ERROR),
                    },
                },
                /* TODO:
                 *  CKO_HW_FEATURE, CKO_DOMAIN_PARAMETERS,
                 *  CKO_MECHANISM, CKO_OTP_KEY, CKO_PROFILE,
                 *  CKO_VENDOR_DEFINED
                 */
                _ => err_rv!(CKR_DEVICE_ERROR),
            },
        }
    }

    pub fn check_sensitive(
        &self,
        obj: &Object,
        template: &[CK_ATTRIBUTE],
    ) -> KResult<()> {
        let objtype_attrs = self.get_object_template(obj)?.get_attributes();
        for ck_attr in template {
            match objtype_attrs.iter().find(|a| a.get_type() == ck_attr.type_) {
                None => return err_rv!(CKR_ATTRIBUTE_TYPE_INVALID),
                Some(attr) => {
                    if attr.is(OAFlags::Sensitive) {
                        return err_rv!(CKR_ATTRIBUTE_SENSITIVE);
                    }
                }
            }
        }
        Ok(())
    }

    pub fn get_object_attributes(
        &self,
        obj: &Object,
        template: &mut [CK_ATTRIBUTE],
    ) -> KResult<()> {
        let mut result = CKR_OK;
        let sensitive = obj.is_sensitive() & !obj.is_extractable();
        let obj_attrs = obj.get_attributes();
        let objtype_attrs = self.get_object_template(obj)?.get_attributes();
        for ck_attr in template.iter_mut() {
            if sensitive {
                match objtype_attrs
                    .iter()
                    .find(|a| a.get_type() == ck_attr.type_)
                {
                    None => {
                        ck_attr.ulValueLen = CK_UNAVAILABLE_INFORMATION;
                        result = CKR_ATTRIBUTE_TYPE_INVALID;
                        continue;
                    }
                    Some(attr) => {
                        if attr.is(OAFlags::Sensitive) {
                            ck_attr.ulValueLen = CK_UNAVAILABLE_INFORMATION;
                            result = CKR_ATTRIBUTE_SENSITIVE;
                            continue;
                        }
                    }
                }
            }
            match obj_attrs.iter().find(|a| a.get_type() == ck_attr.type_) {
                None => {
                    ck_attr.ulValueLen = CK_UNAVAILABLE_INFORMATION;
                    result = CKR_ATTRIBUTE_TYPE_INVALID;
                    continue;
                }
                Some(attr) => {
                    let attr_val = attr.get_value();
                    let attr_len = attr_val.len() as CK_ULONG;
                    if ck_attr.pValue.is_null() {
                        ck_attr.ulValueLen = attr_len;
                    } else {
                        if ck_attr.ulValueLen < attr_len {
                            ck_attr.ulValueLen = CK_UNAVAILABLE_INFORMATION;
                            result = CKR_BUFFER_TOO_SMALL;
                        } else {
                            ck_attr.ulValueLen = attr_len;
                            unsafe {
                                std::ptr::copy_nonoverlapping(
                                    attr_val.as_ptr(),
                                    ck_attr.pValue as *mut _,
                                    attr_val.len(),
                                );
                            }
                        }
                    }
                }
            }
        }
        if result == CKR_OK {
            Ok(())
        } else {
            err_rv!(result)
        }
    }

    pub fn set_object_attributes(
        &self,
        obj: &mut Object,
        template: &[CK_ATTRIBUTE],
    ) -> KResult<()> {
        if !obj.is_modifiable() {
            return err_rv!(CKR_ACTION_PROHIBITED);
        }

        /* first check that all attributes can be changed */
        let objtype_attrs = self.get_object_template(obj)?.get_attributes();
        for ck_attr in template {
            match objtype_attrs.iter().find(|a| a.get_type() == ck_attr.type_) {
                None => return err_rv!(CKR_ATTRIBUTE_TYPE_INVALID),
                Some(attr) => {
                    if attr.is(OAFlags::Unchangeable) {
                        if attr.attribute.get_attrtype() == AttrType::BoolType {
                            let val = match obj.get_attr(ck_attr.type_) {
                                Some(a) => a.to_bool()?,
                                None => {
                                    if attr.has_default() {
                                        attr.attribute.to_bool()?
                                    } else {
                                        return err_rv!(
                                            CKR_ATTRIBUTE_READ_ONLY
                                        );
                                    }
                                }
                            };
                            if val {
                                if !attr.is(OAFlags::ChangeToFalse) {
                                    return err_rv!(CKR_ATTRIBUTE_READ_ONLY);
                                }
                            } else {
                                if !attr.is(OAFlags::ChangeToTrue) {
                                    return err_rv!(CKR_ATTRIBUTE_READ_ONLY);
                                }
                            }
                        } else {
                            return err_rv!(CKR_ATTRIBUTE_READ_ONLY);
                        }
                    }
                }
            }
        }

        /* if checks clear out, apply changes */
        for ck_attr in template {
            obj.set_attr(ck_attr.to_attribute()?)?;
        }

        Ok(())
    }

    pub fn copy(
        &self,
        obj: &Object,
        template: &[CK_ATTRIBUTE],
    ) -> KResult<Object> {
        if !obj.is_copyable() {
            return err_rv!(CKR_ACTION_PROHIBITED);
        }
        self.get_object_template(obj)?.copy(obj, template)
    }

    pub fn genkey(
        &self,
        rng: &mut RNG,
        mech: &CK_MECHANISM,
        template: &[CK_ATTRIBUTE],
    ) -> KResult<Object> {
        let class = match template.iter().find(|a| a.type_ == CKA_CLASS) {
            Some(c) => c.to_ulong()?,
            None => return err_rv!(CKR_TEMPLATE_INCOMPLETE),
        };
        match class {
            CKO_SECRET_KEY => {
                let ktype =
                    match template.iter().find(|a| a.type_ == CKA_KEY_TYPE) {
                        Some(k) => k.to_ulong()?,
                        None => CK_UNAVAILABLE_INFORMATION,
                    };
                match mech.mechanism {
                    CKM_GENERIC_SECRET_KEY_GEN => match ktype {
                        CK_UNAVAILABLE_INFORMATION | CKK_GENERIC_SECRET => self
                            .get_template(ObjectType::GenericSecretKey)?
                            .genkey(rng, template, CKK_GENERIC_SECRET),
                        _ => err_rv!(CKR_TEMPLATE_INCONSISTENT),
                    },
                    CKM_SHA_1_KEY_GEN => match ktype {
                        CK_UNAVAILABLE_INFORMATION | CKK_SHA_1_HMAC => self
                            .get_template(ObjectType::GenericSecretKey)?
                            .genkey(rng, template, CKK_SHA_1_HMAC),
                        _ => err_rv!(CKR_TEMPLATE_INCONSISTENT),
                    },
                    CKM_SHA256_KEY_GEN => match ktype {
                        CK_UNAVAILABLE_INFORMATION | CKK_SHA256_HMAC => self
                            .get_template(ObjectType::GenericSecretKey)?
                            .genkey(rng, template, CKK_SHA256_HMAC),
                        _ => err_rv!(CKR_TEMPLATE_INCONSISTENT),
                    },
                    CKM_SHA384_KEY_GEN => match ktype {
                        CK_UNAVAILABLE_INFORMATION | CKK_SHA384_HMAC => self
                            .get_template(ObjectType::GenericSecretKey)?
                            .genkey(rng, template, CKK_SHA384_HMAC),
                        _ => err_rv!(CKR_TEMPLATE_INCONSISTENT),
                    },
                    CKM_SHA512_KEY_GEN => match ktype {
                        CK_UNAVAILABLE_INFORMATION | CKK_SHA512_HMAC => self
                            .get_template(ObjectType::GenericSecretKey)?
                            .genkey(rng, template, CKK_SHA512_HMAC),
                        _ => err_rv!(CKR_TEMPLATE_INCONSISTENT),
                    },
                    _ => err_rv!(CKR_MECHANISM_INVALID),
                }
            }
            /* TODO: CKO_DOMAIN_PARAMETERS */
            _ => err_rv!(CKR_ATTRIBUTE_VALUE_INVALID),
        }
    }

    pub fn genkeypair(
        &self,
        rng: &mut RNG,
        mech: &CK_MECHANISM,
        pubkey_template: &[CK_ATTRIBUTE],
        prikey_template: &[CK_ATTRIBUTE],
    ) -> KResult<(Object, Object)> {
        match mech.mechanism {
            CKM_RSA_PKCS_KEY_PAIR_GEN => {
                let mut pubkey = self
                    .get_template(ObjectType::RSAPubKey)?
                    .stubpubkeyhalf(pubkey_template)?;
                let prikey = self
                    .get_template(ObjectType::RSAPrivKey)?
                    .genkeypair(rng, &mut pubkey, prikey_template)?;
                Ok((pubkey, prikey))
            }
            _ => err_rv!(CKR_MECHANISM_INVALID),
        }
    }
}
