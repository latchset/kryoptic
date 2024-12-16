// Copyright 2023 Simo Sorce
// See LICENSE.txt file for terms

use std::collections::HashMap;
use std::fmt::Debug;

use crate::attribute::{AttrType, Attribute};
use crate::error::{Error, Result};
use crate::interface::*;
use crate::mechanism::{Mechanism, Mechanisms};
use crate::misc::zeromem;
use crate::CSPRNG;

use bitflags::bitflags;
use once_cell::sync::Lazy;
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
        pub fn $name(&self, t: CK_ULONG) -> Result<$r> {
            for attr in &self.attributes {
                if attr.get_type() == t {
                    if attr.get_attrtype() != AttrType::$atype {
                        return Err(CKR_ATTRIBUTE_TYPE_INVALID)?;
                    }
                    return attr.$conv();
                }
            }
            Err(Error::not_found(t.to_string()))
        }
    };
}

fn incomplete(e: Error) -> Error {
    if e.attr_not_found() {
        Error::ck_rv(CKR_TEMPLATE_INCOMPLETE)
    } else {
        e
    }
}

#[derive(Debug, Clone)]
pub struct Object {
    handle: CK_OBJECT_HANDLE,
    session: CK_SESSION_HANDLE,
    attributes: Vec<Attribute>,
    zeroize: bool,
}

impl Drop for Object {
    fn drop(&mut self) {
        if self.zeroize {
            for a in self.attributes.iter_mut() {
                a.zeroize()
            }
        }
    }
}

impl Object {
    pub fn new() -> Object {
        Object {
            handle: CK_INVALID_HANDLE,
            session: CK_INVALID_HANDLE,
            attributes: Vec::new(),
            zeroize: false,
        }
    }

    pub fn set_zeroize(&mut self) {
        self.zeroize = true;
    }

    pub fn generate_unique(&mut self) {
        if !self
            .attributes
            .iter()
            .any(|r| r.get_type() == CKA_UNIQUE_ID)
        {
            let uuid = Uuid::new_v4().to_string();
            self.attributes
                .push(Attribute::from_string(CKA_UNIQUE_ID, uuid));
        }
    }

    pub fn blind_copy(&self) -> Result<Object> {
        let mut obj = Object::new();
        obj.generate_unique();
        for attr in &self.attributes {
            if attr.get_type() == CKA_UNIQUE_ID {
                continue;
            }
            obj.attributes.push(attr.clone());
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
    create_bool_checker! {make always_auth; from CKA_ALWAYS_AUTHENTICATE; def false}

    pub fn get_attr(&self, ck_type: CK_ULONG) -> Option<&Attribute> {
        self.attributes.iter().find(|r| r.get_type() == ck_type)
    }

    pub fn set_attr(&mut self, a: Attribute) -> Result<()> {
        let atype = a.get_type();
        match self.attributes.iter().position(|r| r.get_type() == atype) {
            Some(idx) => self.attributes[idx] = a,
            None => self.attributes.push(a),
        }
        Ok(())
    }

    pub fn check_or_set_attr(&mut self, a: Attribute) -> Result<bool> {
        let atype = a.get_type();
        match self.attributes.iter().find(|r| r.get_type() == atype) {
            Some(attr) => {
                if attr.get_value() != a.get_value() {
                    return Ok(false);
                }
            }
            None => {
                self.attributes.push(a);
            }
        }
        Ok(true)
    }

    #[allow(dead_code)]
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

    pub fn check_key_ops(
        &self,
        class: CK_OBJECT_CLASS,
        ktype: CK_KEY_TYPE,
        op: CK_ATTRIBUTE_TYPE,
    ) -> Result<()> {
        if self.get_attr_as_ulong(CKA_CLASS)? != class {
            return Err(CKR_KEY_TYPE_INCONSISTENT)?;
        }
        if ktype != CK_UNAVAILABLE_INFORMATION {
            let kt = self.get_attr_as_ulong(CKA_KEY_TYPE)?;
            if kt != ktype {
                return Err(CKR_KEY_TYPE_INCONSISTENT)?;
            }
        }
        if self.get_attr_as_bool(op).or::<Error>(Ok(false))? {
            return Ok(());
        }
        return Err(CKR_KEY_FUNCTION_NOT_PERMITTED)?;
    }

    pub fn rough_size(&self) -> Result<usize> {
        let mut size = std::mem::size_of::<Attribute>() * self.attributes.len();
        for val in &self.attributes {
            size += val.get_value().len();
        }
        Ok(size)
    }
}

bitflags! {
    #[derive(Debug, Clone, Copy)]
    pub struct OAFlags: u32 {
        /* the attribute is ignored and not copied from a template */
        const Ignored              = 0b00000000000001;

        /* The attribute is sensitive and will not be returned by a call
         * unless specifically authorized (like a key secret value) */
        const Sensitive            = 0b00000000000010;

        /* The attribute has a default value that can be set when it is
         * required on object creation but not provided by a template */
        const Defval               = 0b00000000000100;

        /* The attribute must be provided in the tempalate on object
         * creation or the operation will fail */
        const RequiredOnCreate     = 0b00000000001000;

        /* The attribute must be provided in the tempalate on key
         * generation or the operation will fail */
        const RequiredOnGenerate   = 0b00000000010000;

        /* The attribute is always required or the operation will fail,
         * however combined with Defval it means it will be generated
         * automatically when absent from the template and will not
         * cause the operation to fail */
        const AlwaysRequired       = 0b00000000100000;

        /* The attribute can only be set in a template for create
         * (import) operations, if set for any other operation (copy,
         * generate, wrap, derive) it will cause a failure */
        const SettableOnlyOnCreate = 0b00000010000000;

        /* This attribute can never be set in a template, if set the
         * operation will fail (they are only ever set by internal
         * functions) */
        const NeverSettable        = 0b00000100000000;

        /* The attribute cannot be changed once set (enforced from
         * changing via C_SetAttibuteValue or via C_CopyObject */
        const Unchangeable         = 0b00010000000000;

        /* The attribute can only be change True -> False */
        const ChangeToFalse        = 0b00110000000000;

        /* The attribute can only be change False -> True */
        const ChangeToTrue         = 0b01010000000000;

        /* The attribute can be changed only during a Copy Operation */
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

    pub fn is(&self, val: OAFlags) -> bool {
        self.flags.contains(val)
    }

    pub fn has_default(&self) -> bool {
        self.flags.contains(OAFlags::Defval)
    }
}

macro_rules! attr_element {
    ($id:expr; $flags:expr; $from_type:expr; val $defval:expr) => {
        ObjectAttr::new($from_type($id, $defval), $flags)
    };
}
pub(crate) use attr_element;

#[allow(unused_macros)]
macro_rules! bytes_attr_not_empty {
    ($obj:expr; $id:expr) => {
        match $obj.get_attr_as_bytes($id) {
            Ok(e) => {
                if e.len() == 0 {
                    return Err(CKR_ATTRIBUTE_VALUE_INVALID)?;
                }
            }
            Err(e) => {
                if e.attr_not_found() {
                    return Err(CKR_TEMPLATE_INCOMPLETE)?;
                } else {
                    return Err(e);
                }
            }
        }
    };
}
#[allow(unused_imports)]
pub(crate) use bytes_attr_not_empty;

pub trait ObjectFactory: Debug + Send + Sync {
    fn create(&self, _template: &[CK_ATTRIBUTE]) -> Result<Object> {
        return Err(CKR_GENERAL_ERROR)?;
    }

    fn copy(&self, obj: &Object, template: &[CK_ATTRIBUTE]) -> Result<Object> {
        self.default_copy(obj, template)
    }

    fn get_attributes(&self) -> &Vec<ObjectAttr>;

    fn init_common_object_attrs(&self) -> Vec<ObjectAttr> {
        vec![attr_element!(
            CKA_CLASS; OAFlags::RequiredOnCreate; Attribute::from_ulong; val 0)]
    }
    fn init_common_storage_attrs(&self) -> Vec<ObjectAttr> {
        vec![
            attr_element!(
                CKA_TOKEN; OAFlags::Defval | OAFlags::ChangeOnCopy;
                Attribute::from_bool; val false),
            attr_element!(
                CKA_PRIVATE; OAFlags::Defval | OAFlags::ChangeOnCopy;
                Attribute::from_bool; val false),
            attr_element!(
                CKA_MODIFIABLE; OAFlags::Defval | OAFlags::ChangeOnCopy;
                Attribute::from_bool; val true),
            attr_element!(
                CKA_LABEL; OAFlags::empty(); Attribute::from_string;
                val String::new()),
            attr_element!(
                CKA_COPYABLE; OAFlags::Defval | OAFlags::ChangeToFalse;
                Attribute::from_bool; val true),
            attr_element!(
                CKA_DESTROYABLE; OAFlags::Defval; Attribute::from_bool;
                val true),
            attr_element!(
                CKA_UNIQUE_ID; OAFlags::NeverSettable | OAFlags::Unchangeable;
                Attribute::from_string; val String::new()),
        ]
    }

    fn default_object_create(
        &self,
        template: &[CK_ATTRIBUTE],
    ) -> Result<Object> {
        self.internal_object_create(
            template,
            OAFlags::NeverSettable,
            OAFlags::RequiredOnCreate,
        )
    }

    fn default_object_generate(
        &self,
        template: &[CK_ATTRIBUTE],
    ) -> Result<Object> {
        let mut key = self.internal_object_create(
            template,
            OAFlags::SettableOnlyOnCreate,
            OAFlags::RequiredOnGenerate,
        )?;
        key.set_zeroize();
        Ok(key)
    }

    fn default_object_unwrap(
        &self,
        template: &[CK_ATTRIBUTE],
    ) -> Result<Object> {
        self.internal_object_create(
            template,
            OAFlags::SettableOnlyOnCreate,
            OAFlags::AlwaysRequired,
        )
    }

    fn default_object_derive(
        &self,
        template: &[CK_ATTRIBUTE],
        origin: &Object,
    ) -> Result<Object> {
        self.internal_object_derive(template, origin)
    }

    fn internal_object_derive(
        &self,
        template: &[CK_ATTRIBUTE],
        origin: &Object,
    ) -> Result<Object> {
        /* FIXME: handle CKA_DERIVE_TEMPLATE */

        let mut obj = self.internal_object_create(
            template,
            OAFlags::SettableOnlyOnCreate,
            OAFlags::AlwaysRequired,
        )?;
        /* overrides */
        obj.set_attr(Attribute::from_bool(CKA_LOCAL, false))?;
        match origin.get_attr_as_bool(CKA_ALWAYS_SENSITIVE) {
            Ok(b) => match b {
                false => obj.set_attr(Attribute::from_bool(
                    CKA_ALWAYS_SENSITIVE,
                    false,
                ))?,
                true => obj.set_attr(Attribute::from_bool(
                    CKA_ALWAYS_SENSITIVE,
                    obj.is_sensitive(),
                ))?,
            },
            Err(_) => {
                obj.set_attr(Attribute::from_bool(CKA_ALWAYS_SENSITIVE, false))?
            }
        };
        match origin.get_attr_as_bool(CKA_NEVER_EXTRACTABLE) {
            Ok(b) => match b {
                false => obj.set_attr(Attribute::from_bool(
                    CKA_NEVER_EXTRACTABLE,
                    false,
                ))?,
                true => obj.set_attr(Attribute::from_bool(
                    CKA_NEVER_EXTRACTABLE,
                    !obj.is_extractable(),
                ))?,
            },
            Err(_) => obj
                .set_attr(Attribute::from_bool(CKA_NEVER_EXTRACTABLE, false))?,
        };
        Ok(obj)
    }

    fn internal_object_create(
        &self,
        template: &[CK_ATTRIBUTE],
        unacceptable_flags: OAFlags,
        required_flags: OAFlags,
    ) -> Result<Object> {
        let attributes = self.get_attributes();
        let mut obj = Object::new();

        for ck_attr in template {
            match attributes.iter().find(|a| a.get_type() == ck_attr.type_) {
                Some(attr) => {
                    if attr.is(unacceptable_flags)
                        || attr.is(OAFlags::NeverSettable)
                    {
                        return Err(CKR_ATTRIBUTE_TYPE_INVALID)?;
                    }
                    /* duplicate? */
                    match obj.get_attr(ck_attr.type_) {
                        Some(_) => return Err(CKR_TEMPLATE_INCONSISTENT)?,
                        None => (),
                    }
                    if !attr.is(OAFlags::Ignored) {
                        obj.attributes.push(ck_attr.to_attribute()?);
                    }
                }
                None => {
                    return Err(CKR_ATTRIBUTE_VALUE_INVALID)?;
                }
            }
        }
        for attr in attributes {
            match obj.get_attr(attr.get_type()) {
                Some(_) => (),
                None => {
                    if attr.has_default() {
                        obj.attributes.push(attr.attribute.clone());
                    } else if attr.is(required_flags)
                        || attr.is(OAFlags::AlwaysRequired)
                    {
                        return Err(CKR_TEMPLATE_INCOMPLETE)?;
                    }
                }
            }
        }
        obj.generate_unique();
        Ok(obj)
    }

    #[allow(dead_code)]
    fn set_attribute_default(
        &self,
        attr: CK_ATTRIBUTE_TYPE,
        obj: &mut Object,
    ) -> Result<()> {
        let attributes = self.get_attributes();
        match attributes.iter().find(|a| a.get_type() == attr) {
            Some(defattr) => {
                if defattr.has_default() {
                    obj.set_attr(defattr.attribute.clone())?;
                }
            }
            None => (),
        }
        Ok(())
    }

    fn default_copy(
        &self,
        origin: &Object,
        template: &[CK_ATTRIBUTE],
    ) -> Result<Object> {
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
                                return Err(CKR_ATTRIBUTE_READ_ONLY)?;
                            }
                            if !val && !attr.is(OAFlags::ChangeToTrue) {
                                return Err(CKR_ATTRIBUTE_READ_ONLY)?;
                            }
                        }
                        if !attr.is(OAFlags::ChangeOnCopy) {
                            return Err(CKR_ATTRIBUTE_READ_ONLY)?;
                        }
                    }
                }
                None => return Err(CKR_TEMPLATE_INCONSISTENT)?,
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
                let _ = obj.set_attr(Attribute::from_bool(
                    CKA_NEVER_EXTRACTABLE,
                    val,
                ))?;
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
                let _ = obj.set_attr(Attribute::from_bool(
                    CKA_ALWAYS_SENSITIVE,
                    val,
                ))?;
            }
            Err(_) => (),
        }

        Ok(obj)
    }

    fn export_for_wrapping(&self, _obj: &Object) -> Result<Vec<u8>> {
        return Err(CKR_GENERAL_ERROR)?;
    }

    fn import_from_wrapped(
        &self,
        mut _data: Vec<u8>,
        _template: &[CK_ATTRIBUTE],
    ) -> Result<Object> {
        return Err(CKR_GENERAL_ERROR)?;
    }

    fn as_secret_key_factory(&self) -> Result<&dyn SecretKeyFactory> {
        Err(CKR_GENERAL_ERROR)?
    }

    fn check_get_attributes(
        &self,
        template: &mut [CK_ATTRIBUTE],
        sensitive: bool,
    ) -> Result<()> {
        let mut result = CKR_OK;
        let attrs = self.get_attributes();
        for ck_attr in template.iter_mut() {
            match attrs.iter().find(|a| a.get_type() == ck_attr.type_) {
                Some(attr) => {
                    if sensitive && attr.is(OAFlags::Sensitive) {
                        ck_attr.ulValueLen = CK_UNAVAILABLE_INFORMATION;
                        if result == CKR_OK {
                            result = CKR_ATTRIBUTE_SENSITIVE;
                        }
                    }
                }
                None => {
                    ck_attr.ulValueLen = CK_UNAVAILABLE_INFORMATION;
                    if result == CKR_OK {
                        result = CKR_ATTRIBUTE_TYPE_INVALID;
                    }
                }
            }
        }
        if result == CKR_OK {
            Ok(())
        } else {
            Err(result)?
        }
    }

    fn check_set_attributes(&self, template: &[CK_ATTRIBUTE]) -> Result<()> {
        let attrs = self.get_attributes();
        for ck_attr in template {
            match attrs.iter().find(|a| a.get_type() == ck_attr.type_) {
                None => return Err(CKR_ATTRIBUTE_TYPE_INVALID)?,
                Some(attr) => {
                    if attr.is(OAFlags::Unchangeable) {
                        if attr.attribute.get_attrtype() == AttrType::BoolType {
                            let val = ck_attr.to_bool()?;
                            if val {
                                if !attr.is(OAFlags::ChangeToTrue) {
                                    return Err(CKR_ATTRIBUTE_READ_ONLY)?;
                                }
                            } else {
                                if !attr.is(OAFlags::ChangeToFalse) {
                                    return Err(CKR_ATTRIBUTE_READ_ONLY)?;
                                }
                            }
                        } else {
                            return Err(CKR_ATTRIBUTE_READ_ONLY)?;
                        }
                    }
                }
            }
        }
        Ok(())
    }

    fn set_object_attributes(
        &self,
        obj: &mut Object,
        template: &[CK_ATTRIBUTE],
    ) -> Result<()> {
        if !obj.is_modifiable() {
            return Err(CKR_ACTION_PROHIBITED)?;
        }

        /* first check that all attributes can be changed */
        self.check_set_attributes(template)?;

        /* if checks clear out, apply changes */
        for ck_attr in template {
            obj.set_attr(ck_attr.to_attribute()?)?;
        }

        Ok(())
    }
}

/* pkcs11-spec-v3.1 4.5 Data Objects */
#[derive(Debug)]
struct DataFactory {
    attributes: Vec<ObjectAttr>,
}

impl DataFactory {
    fn new() -> DataFactory {
        let mut data: DataFactory = DataFactory {
            attributes: Vec::new(),
        };
        data.attributes.append(&mut data.init_common_object_attrs());
        data.attributes
            .append(&mut data.init_common_storage_attrs());
        data.attributes.push(attr_element!(
            CKA_APPLICATION; OAFlags::Defval; Attribute::from_string;
            val String::new()));
        data.attributes.push(attr_element!(
            CKA_OBJECT_ID; OAFlags::empty(); Attribute::from_bytes;
            val Vec::new()));
        data.attributes.push(attr_element!(
            CKA_VALUE; OAFlags::Defval; Attribute::from_bytes;
            val Vec::new()));
        data
    }
}

impl ObjectFactory for DataFactory {
    fn create(&self, template: &[CK_ATTRIBUTE]) -> Result<Object> {
        self.default_object_create(template)
    }

    fn copy(
        &self,
        origin: &Object,
        template: &[CK_ATTRIBUTE],
    ) -> Result<Object> {
        self.default_copy(origin, template)
    }

    fn get_attributes(&self) -> &Vec<ObjectAttr> {
        &self.attributes
    }
}

/* pkcs11-spec-v3.1 4.6 Certificate objects */
pub trait CertFactory {
    fn init_common_certificate_attrs(&self) -> Vec<ObjectAttr> {
        vec![
            attr_element!(
                CKA_CERTIFICATE_TYPE; OAFlags::AlwaysRequired;
                Attribute::from_ulong; val 0),
            attr_element!(
                CKA_TRUSTED; OAFlags::Defval; Attribute::from_bool;
                val false),
            attr_element!(
                CKA_CERTIFICATE_CATEGORY; OAFlags::Defval;
                Attribute::from_ulong;
                val CK_CERTIFICATE_CATEGORY_UNSPECIFIED),
            attr_element!(
                CKA_CHECK_VALUE; OAFlags::Ignored; Attribute::from_ignore;
                val None),
            attr_element!(
                CKA_START_DATE; OAFlags::empty(); Attribute::from_date_bytes;
                val Vec::new()),
            attr_element!(
                CKA_END_DATE; OAFlags::empty(); Attribute::from_date_bytes;
                val Vec::new()),
            attr_element!(
                CKA_PUBLIC_KEY_INFO; OAFlags::empty(); Attribute::from_bytes;
                val Vec::new()),
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
}

/* pkcs11-spec-v3.1 4.6.3 X.509 public key certificate objects */
#[derive(Debug)]
struct X509Factory {
    attributes: Vec<ObjectAttr>,
}

impl X509Factory {
    fn new() -> X509Factory {
        let mut data: X509Factory = X509Factory {
            attributes: Vec::new(),
        };
        data.attributes.append(&mut data.init_common_object_attrs());
        data.attributes
            .append(&mut data.init_common_storage_attrs());
        data.attributes
            .append(&mut data.init_common_certificate_attrs());
        data.attributes.push(attr_element!(
            CKA_SUBJECT; OAFlags::AlwaysRequired; Attribute::from_bytes;
            val Vec::new()));
        data.attributes.push(attr_element!(
            CKA_ID; OAFlags::Defval; Attribute::from_bytes; val Vec::new()));
        data.attributes.push(attr_element!(
            CKA_ISSUER; OAFlags::Defval; Attribute::from_bytes;
            val Vec::new()));
        data.attributes.push(attr_element!(
            CKA_SERIAL_NUMBER; OAFlags::Defval; Attribute::from_bytes;
            val Vec::new()));
        data.attributes.push(attr_element!(
            CKA_VALUE; OAFlags::AlwaysRequired; Attribute::from_bytes;
            val Vec::new()));
        data.attributes.push(attr_element!(
            CKA_URL; OAFlags::empty(); Attribute::from_string;
            val String::new()));
        data.attributes.push(attr_element!(
            CKA_HASH_OF_SUBJECT_PUBLIC_KEY; OAFlags::Defval;
            Attribute::from_bytes; val Vec::new()));
        data.attributes.push(attr_element!(
            CKA_HASH_OF_ISSUER_PUBLIC_KEY; OAFlags::Defval;
            Attribute::from_bytes; val Vec::new()));
        data.attributes.push(attr_element!(
            CKA_JAVA_MIDP_SECURITY_DOMAIN; OAFlags::Defval;
            Attribute::from_ulong; val CK_SECURITY_DOMAIN_UNSPECIFIED));
        data.attributes.push(attr_element!(
            CKA_NAME_HASH_ALGORITHM; OAFlags::empty(); Attribute::from_ulong;
            val CKM_SHA_1));
        data
    }
}

impl ObjectFactory for X509Factory {
    fn create(&self, template: &[CK_ATTRIBUTE]) -> Result<Object> {
        let mut obj = self.default_object_create(template)?;

        let ret = self.basic_cert_object_create_checks(&mut obj);
        if ret != CKR_OK {
            return Err(ret)?;
        }

        let value = match obj.get_attr_as_bytes(CKA_VALUE) {
            Ok(v) => v,
            Err(_) => return Err(CKR_TEMPLATE_INCOMPLETE)?,
        };
        let url = match obj.get_attr_as_string(CKA_URL) {
            Ok(u) => u,
            Err(_) => String::new(),
        };
        if value.len() == 0 && url.len() == 0 {
            return Err(CKR_ATTRIBUTE_VALUE_INVALID)?;
        }
        if url.len() > 0 {
            match obj.get_attr_as_bytes(CKA_HASH_OF_SUBJECT_PUBLIC_KEY) {
                Ok(h) => {
                    if h.len() == 0 {
                        return Err(CKR_ATTRIBUTE_VALUE_INVALID)?;
                    }
                }
                Err(_) => return Err(CKR_TEMPLATE_INCOMPLETE)?,
            }
            match obj.get_attr_as_bytes(CKA_HASH_OF_SUBJECT_PUBLIC_KEY) {
                Ok(h) => {
                    if h.len() == 0 {
                        return Err(CKR_ATTRIBUTE_VALUE_INVALID)?;
                    }
                }
                Err(_) => return Err(CKR_TEMPLATE_INCOMPLETE)?,
            }
        }
        match obj.get_attr_as_ulong(CKA_JAVA_MIDP_SECURITY_DOMAIN) {
            Ok(sd) => match sd {
                CK_SECURITY_DOMAIN_UNSPECIFIED => (),
                CK_SECURITY_DOMAIN_MANUFACTURER => (),
                CK_SECURITY_DOMAIN_OPERATOR => (),
                CK_SECURITY_DOMAIN_THIRD_PARTY => (),
                _ => return Err(CKR_ATTRIBUTE_VALUE_INVALID)?,
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

impl CertFactory for X509Factory {}

/* pkcs11-spec-v3.1 4.7 Key objects */
pub trait CommonKeyFactory {
    fn init_common_key_attrs(&self) -> Vec<ObjectAttr> {
        vec![
            attr_element!(
                CKA_KEY_TYPE; OAFlags::RequiredOnCreate; Attribute::from_ulong;
                val CK_UNAVAILABLE_INFORMATION),
            attr_element!(
                CKA_ID; OAFlags::empty(); Attribute::from_bytes;
                val Vec::new()),
            attr_element!(
                CKA_START_DATE; OAFlags::empty(); Attribute::from_date_bytes;
                val Vec::new()),
            attr_element!(
                CKA_END_DATE; OAFlags::empty(); Attribute::from_date_bytes;
                val Vec::new()),
            attr_element!(
                CKA_DERIVE; OAFlags::Defval; Attribute::from_bool; val false),
            attr_element!(
                CKA_LOCAL; OAFlags::Defval | OAFlags::NeverSettable;
                Attribute::from_bool; val false),
            attr_element!(
                CKA_KEY_GEN_MECHANISM; OAFlags::Defval | OAFlags::NeverSettable;
                Attribute::from_ulong; val CK_UNAVAILABLE_INFORMATION),
            attr_element!(
                CKA_ALLOWED_MECHANISMS; OAFlags::empty(); Attribute::from_bytes;
                val Vec::new()),
            #[cfg(feature = "fips")]
            attr_element!(
                CKA_VALIDATION_FLAGS; OAFlags::NeverSettable;
                Attribute::from_ulong; val 0),
        ]
    }
}

/* pkcs11-spec-v3.1 4.8 Public key objects */
#[allow(dead_code)]
pub trait PubKeyFactory {
    fn init_common_public_key_attrs(&self) -> Vec<ObjectAttr> {
        vec![
            attr_element!(
                CKA_SUBJECT; OAFlags::Defval; Attribute::from_bytes;
                val Vec::new()),
            attr_element!(
                CKA_ENCRYPT; OAFlags::Defval; Attribute::from_bool; val false),
            attr_element!(
                CKA_VERIFY; OAFlags::Defval; Attribute::from_bool; val false),
            attr_element!(
                CKA_VERIFY_RECOVER; OAFlags::Defval; Attribute::from_bool;
                val false),
            attr_element!(
                CKA_WRAP; OAFlags::Defval; Attribute::from_bool; val false),
            attr_element!(
                CKA_TRUSTED; OAFlags::NeverSettable | OAFlags::Defval;
                Attribute::from_bool; val false),
            attr_element!(
                CKA_WRAP_TEMPLATE; OAFlags::empty(); Attribute::from_bytes;
                val Vec::new()),
            attr_element!(
                CKA_PUBLIC_KEY_INFO; OAFlags::empty(); Attribute::from_bytes;
                val Vec::new()),
        ]
    }
}

/* pkcs11-spec-v3.1 4.9 Private key objects */
#[allow(dead_code)]
pub trait PrivKeyFactory {
    fn init_common_private_key_attrs(&self) -> Vec<ObjectAttr> {
        vec![
            attr_element!(
                CKA_SUBJECT; OAFlags::Defval; Attribute::from_bytes;
                val Vec::new()),
            attr_element!(
                CKA_SENSITIVE; OAFlags::Defval | OAFlags::ChangeToTrue;
                Attribute::from_bool; val true),
            attr_element!(
                CKA_DECRYPT; OAFlags::Defval; Attribute::from_bool; val false),
            attr_element!(
                CKA_SIGN; OAFlags::Defval; Attribute::from_bool; val false),
            attr_element!(
                CKA_SIGN_RECOVER; OAFlags::Defval; Attribute::from_bool;
                val false),
            attr_element!(
                CKA_UNWRAP; OAFlags::Defval; Attribute::from_bool; val false),
            attr_element!(
                CKA_EXTRACTABLE; OAFlags::ChangeToFalse | OAFlags::Defval;
                Attribute::from_bool; val false),
            attr_element!(
                CKA_ALWAYS_SENSITIVE; OAFlags::NeverSettable;
                Attribute::from_bool; val false),
            attr_element!(
                CKA_NEVER_EXTRACTABLE; OAFlags::NeverSettable;
                Attribute::from_bool; val false),
            attr_element!(
                CKA_WRAP_WITH_TRUSTED; OAFlags::Defval | OAFlags::ChangeToTrue;
                Attribute::from_bool; val false),
            attr_element!(
                CKA_UNWRAP_TEMPLATE; OAFlags::empty(); Attribute::from_bytes;
                val Vec::new()),
            attr_element!(
                CKA_ALWAYS_AUTHENTICATE; OAFlags::Defval; Attribute::from_bool;
                val false),
            attr_element!(
                CKA_PUBLIC_KEY_INFO; OAFlags::empty(); Attribute::from_bytes;
                val Vec::new()),
            attr_element!(
                CKA_DERIVE_TEMPLATE; OAFlags::empty(); Attribute::from_bytes;
                val Vec::new()),
        ]
    }

    fn export_for_wrapping(&self, _obj: &Object) -> Result<Vec<u8>> {
        return Err(CKR_GENERAL_ERROR)?;
    }

    fn import_from_wrapped(
        &self,
        mut _data: Vec<u8>,
        _template: &[CK_ATTRIBUTE],
    ) -> Result<Object> {
        return Err(CKR_GENERAL_ERROR)?;
    }
}

macro_rules! ok_or_clear {
    ($clear:expr; $exp:expr) => {
        match $exp {
            Ok(x) => x,
            Err(e) => {
                zeromem($clear.as_mut_slice());
                return Err(e);
            }
        }
    };
}

/* pkcs11-spec-v3.1 4.10 Secre key objects */
pub trait SecretKeyFactory {
    fn init_common_secret_key_attrs(&self) -> Vec<ObjectAttr> {
        vec![
            attr_element!(
                CKA_SENSITIVE; OAFlags::Defval | OAFlags::ChangeToTrue;
                Attribute::from_bool; val true),
            attr_element!(
                CKA_ENCRYPT; OAFlags::Defval; Attribute::from_bool; val false),
            attr_element!(
                CKA_DECRYPT; OAFlags::Defval; Attribute::from_bool; val false),
            attr_element!(
                CKA_SIGN; OAFlags::Defval; Attribute::from_bool; val false),
            attr_element!(
                CKA_VERIFY; OAFlags::Defval; Attribute::from_bool; val false),
            attr_element!(
                CKA_WRAP; OAFlags::Defval; Attribute::from_bool; val false),
            attr_element!(
                CKA_UNWRAP; OAFlags::Defval; Attribute::from_bool; val false),
            attr_element!(
                CKA_EXTRACTABLE; OAFlags::ChangeToFalse | OAFlags::Defval;
                Attribute::from_bool; val false),
            attr_element!(
                CKA_ALWAYS_SENSITIVE; OAFlags::NeverSettable;
                Attribute::from_bool; val false),
            attr_element!(
                CKA_NEVER_EXTRACTABLE; OAFlags::NeverSettable;
                Attribute::from_bool; val false),
            attr_element!(
                CKA_CHECK_VALUE; OAFlags::Ignored; Attribute::from_ignore;
                val None),
            attr_element!(
                CKA_WRAP_WITH_TRUSTED; OAFlags::Defval | OAFlags::ChangeToTrue;
                Attribute::from_bool; val false),
            attr_element!(
                CKA_TRUSTED; OAFlags::NeverSettable | OAFlags::Defval;
                Attribute::from_bool; val false),
            attr_element!(
                CKA_WRAP_TEMPLATE; OAFlags::empty(); Attribute::from_bytes;
                val Vec::new()),
            attr_element!(
                CKA_UNWRAP_TEMPLATE; OAFlags::empty(); Attribute::from_bytes;
                val Vec::new()),
            attr_element!(
                CKA_DERIVE_TEMPLATE; OAFlags::empty(); Attribute::from_bytes;
                val Vec::new()),
        ]
    }

    fn export_for_wrapping(&self, obj: &Object) -> Result<Vec<u8>> {
        if !obj.is_extractable() {
            return Err(CKR_KEY_UNEXTRACTABLE)?;
        }
        match obj.get_attr_as_bytes(CKA_VALUE) {
            Ok(v) => Ok(v.clone()),
            Err(_) => return Err(CKR_DEVICE_ERROR)?,
        }
    }

    fn import_from_wrapped(
        &self,
        mut data: Vec<u8>,
        template: &[CK_ATTRIBUTE],
    ) -> Result<Object> {
        let mut obj =
            ok_or_clear!(&mut data; self.default_object_unwrap(template));
        self.set_key(&mut obj, data)?;
        Ok(obj)
    }

    fn default_object_unwrap(
        &self,
        template: &[CK_ATTRIBUTE],
    ) -> Result<Object>;

    fn get_key_buffer_len(&self, obj: &Object) -> Result<usize> {
        Ok(obj
            .get_attr_as_bytes(CKA_VALUE)
            .map_err(|e| incomplete(e))?
            .len())
    }

    fn get_key_len(&self, obj: &Object) -> usize {
        let Ok(len) = obj.get_attr_as_ulong(CKA_VALUE_LEN) else {
            return 0;
        };
        let Ok(len) = usize::try_from(len) else {
            return 0;
        };
        len
    }

    fn set_key_len(&self, obj: &mut Object, len: usize) -> Result<()> {
        match self.get_key_buffer_len(obj) {
            Ok(blen) => {
                if len != blen {
                    return Err(CKR_GENERAL_ERROR)?;
                }
            }
            Err(_) => (),
        }
        if obj
            .check_or_set_attr(Attribute::from_ulong(
                CKA_VALUE_LEN,
                CK_ULONG::try_from(len)?,
            ))
            .is_ok()
        {
            Ok(())
        } else {
            Err(CKR_GENERAL_ERROR)?
        }
    }

    fn set_key(&self, obj: &mut Object, key: Vec<u8>) -> Result<()> {
        let keylen = key.len();
        obj.set_attr(Attribute::from_bytes(CKA_VALUE, key))?;
        self.set_key_len(obj, keylen)?;
        Ok(())
    }

    fn recommend_key_size(&self, _: usize) -> Result<usize> {
        return Err(CKR_GENERAL_ERROR)?;
    }
}

/* pkcs11-spec-v3.1 6.8 Generic secret key */
#[derive(Debug)]
pub struct GenericSecretKeyFactory {
    keysize: usize,
    attributes: Vec<ObjectAttr>,
}

impl GenericSecretKeyFactory {
    pub fn new() -> GenericSecretKeyFactory {
        let mut data: GenericSecretKeyFactory = GenericSecretKeyFactory {
            keysize: 0,
            attributes: Vec::new(),
        };
        data.attributes.append(&mut data.init_common_object_attrs());
        data.attributes
            .append(&mut data.init_common_storage_attrs());
        data.attributes.append(&mut data.init_common_key_attrs());
        data.attributes
            .append(&mut data.init_common_secret_key_attrs());
        data.attributes.push(attr_element!(
            CKA_VALUE; OAFlags::Sensitive | OAFlags::RequiredOnCreate
            | OAFlags::SettableOnlyOnCreate; Attribute::from_bytes;
            val Vec::new()));
        data.attributes.push(attr_element!(
            CKA_VALUE_LEN; OAFlags::RequiredOnGenerate; Attribute::from_bytes;
            val Vec::new()));

        /* default to private */
        let private = attr_element!(
            CKA_PRIVATE; OAFlags::Defval | OAFlags::ChangeOnCopy; Attribute::from_bool; val true);
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

    pub fn with_key_size(size: usize) -> GenericSecretKeyFactory {
        let mut factory = Self::new();
        factory.keysize = size;
        factory
    }
}

impl ObjectFactory for GenericSecretKeyFactory {
    fn create(&self, template: &[CK_ATTRIBUTE]) -> Result<Object> {
        let mut obj = self.default_object_create(template)?;
        let len = self.get_key_buffer_len(&obj)?;
        if len == 0 {
            return Err(CKR_ATTRIBUTE_VALUE_INVALID)?;
        }
        if self.keysize != 0 && len != self.keysize {
            return Err(CKR_ATTRIBUTE_VALUE_INVALID)?;
        }
        let len = CK_ULONG::try_from(len)?;
        if !obj.check_or_set_attr(Attribute::from_ulong(CKA_VALUE_LEN, len))? {
            return Err(CKR_ATTRIBUTE_VALUE_INVALID)?;
        }

        Ok(obj)
    }

    fn get_attributes(&self) -> &Vec<ObjectAttr> {
        &self.attributes
    }

    fn export_for_wrapping(&self, key: &Object) -> Result<Vec<u8>> {
        SecretKeyFactory::export_for_wrapping(self, key)
    }

    fn import_from_wrapped(
        &self,
        data: Vec<u8>,
        template: &[CK_ATTRIBUTE],
    ) -> Result<Object> {
        SecretKeyFactory::import_from_wrapped(self, data, template)
    }

    fn as_secret_key_factory(&self) -> Result<&dyn SecretKeyFactory> {
        Ok(self)
    }
}

impl CommonKeyFactory for GenericSecretKeyFactory {}

impl SecretKeyFactory for GenericSecretKeyFactory {
    fn default_object_unwrap(
        &self,
        template: &[CK_ATTRIBUTE],
    ) -> Result<Object> {
        ObjectFactory::default_object_unwrap(self, template)
    }

    fn recommend_key_size(&self, max: usize) -> Result<usize> {
        if self.keysize != 0 {
            Ok(self.keysize)
        } else {
            Ok(max)
        }
    }
}

#[derive(Debug)]
pub struct GenericSecretKeyMechanism {
    info: CK_MECHANISM_INFO,
    keytype: CK_KEY_TYPE,
}

impl GenericSecretKeyMechanism {
    pub fn new(keytype: CK_KEY_TYPE) -> GenericSecretKeyMechanism {
        GenericSecretKeyMechanism {
            info: CK_MECHANISM_INFO {
                ulMinKeySize: CK_EFFECTIVELY_INFINITE,
                ulMaxKeySize: CK_EFFECTIVELY_INFINITE,
                flags: CKF_GENERATE,
            },
            keytype: keytype,
        }
    }
    fn keytype(&self) -> CK_KEY_TYPE {
        self.keytype
    }
}

pub fn default_secret_key_generate(key: &mut Object) -> Result<()> {
    let value_len = usize::try_from(key.get_attr_as_ulong(CKA_VALUE_LEN)?)?;

    let mut value: Vec<u8> = vec![0; value_len];
    match CSPRNG
        .with(|rng| rng.borrow_mut().generate_random(value.as_mut_slice()))
    {
        Ok(()) => (),
        Err(e) => return Err(e),
    }
    key.set_attr(Attribute::from_bytes(CKA_VALUE, value))?;
    Ok(())
}

pub fn default_key_attributes(
    key: &mut Object,
    mech: CK_MECHANISM_TYPE,
) -> Result<()> {
    key.set_attr(Attribute::from_bool(CKA_LOCAL, true))?;
    key.set_attr(Attribute::from_ulong(CKA_KEY_GEN_MECHANISM, mech))?;

    let extractable = if let Ok(b) = key.get_attr_as_bool(CKA_EXTRACTABLE) {
        b
    } else {
        true
    };
    key.set_attr(Attribute::from_bool(CKA_NEVER_EXTRACTABLE, !extractable))?;
    let sensitive = if let Ok(b) = key.get_attr_as_bool(CKA_SENSITIVE) {
        b
    } else {
        false
    };
    key.set_attr(Attribute::from_bool(CKA_ALWAYS_SENSITIVE, sensitive))?;

    Ok(())
}

impl Mechanism for GenericSecretKeyMechanism {
    fn info(&self) -> &CK_MECHANISM_INFO {
        &self.info
    }

    fn generate_key(
        &self,
        mech: &CK_MECHANISM,
        template: &[CK_ATTRIBUTE],
        _: &Mechanisms,
        _: &ObjectFactories,
    ) -> Result<Object> {
        let mut key =
            GENERIC_SECRET_FACTORY.default_object_generate(template)?;
        if !key.check_or_set_attr(Attribute::from_ulong(
            CKA_CLASS,
            CKO_SECRET_KEY,
        ))? {
            return Err(CKR_TEMPLATE_INCONSISTENT)?;
        }
        if !key.check_or_set_attr(Attribute::from_ulong(
            CKA_KEY_TYPE,
            self.keytype(),
        ))? {
            return Err(CKR_TEMPLATE_INCONSISTENT)?;
        }

        default_secret_key_generate(&mut key)?;
        default_key_attributes(&mut key, mech.mechanism)?;
        Ok(key)
    }
}

#[derive(Debug, Eq, Hash, PartialEq)]
pub struct ObjectType {
    class: CK_ULONG,
    type_: CK_ULONG,
}

impl ObjectType {
    pub fn new(class: CK_ULONG, type_: CK_ULONG) -> ObjectType {
        ObjectType {
            class: class,
            type_: type_,
        }
    }
}

#[derive(Debug)]
pub struct ObjectFactories {
    factories: HashMap<ObjectType, &'static Box<dyn ObjectFactory>>,
}

impl ObjectFactories {
    pub fn new() -> ObjectFactories {
        ObjectFactories {
            factories: HashMap::new(),
        }
    }

    pub fn add_factory(
        &mut self,
        otype: ObjectType,
        templ: &'static Box<dyn ObjectFactory>,
    ) {
        self.factories.insert(otype, templ);
    }

    pub fn get_factory(
        &self,
        otype: ObjectType,
    ) -> Result<&Box<dyn ObjectFactory>> {
        match self.factories.get(&otype) {
            Some(b) => Ok(b),
            None => Err(CKR_ATTRIBUTE_VALUE_INVALID)?,
        }
    }

    pub fn create(&self, template: &[CK_ATTRIBUTE]) -> Result<Object> {
        let class = match template.iter().find(|a| a.type_ == CKA_CLASS) {
            Some(c) => c.to_ulong()?,
            None => return Err(CKR_TEMPLATE_INCOMPLETE)?,
        };
        let type_ = match class {
            CKO_DATA => 0,
            CKO_CERTIFICATE => {
                match template.iter().find(|a| a.type_ == CKA_CERTIFICATE_TYPE)
                {
                    Some(c) => c.to_ulong()?,
                    None => return Err(CKR_TEMPLATE_INCOMPLETE)?,
                }
            }
            CKO_PUBLIC_KEY => {
                match template.iter().find(|a| a.type_ == CKA_KEY_TYPE) {
                    Some(k) => k.to_ulong()?,
                    None => return Err(CKR_TEMPLATE_INCOMPLETE)?,
                }
            }
            CKO_PRIVATE_KEY => {
                match template.iter().find(|a| a.type_ == CKA_KEY_TYPE) {
                    Some(k) => k.to_ulong()?,
                    None => return Err(CKR_TEMPLATE_INCOMPLETE)?,
                }
            }
            CKO_SECRET_KEY => {
                match template.iter().find(|a| a.type_ == CKA_KEY_TYPE) {
                    Some(k) => k.to_ulong()?,
                    None => return Err(CKR_TEMPLATE_INCOMPLETE)?,
                }
            }
            /* TODO:
             *  CKO_HW_FEATURE, CKO_DOMAIN_PARAMETERS,
             *  CKO_MECHANISM, CKO_OTP_KEY, CKO_PROFILE,
             *  CKO_VENDOR_DEFINED
             */
            _ => return Err(CKR_DEVICE_ERROR)?,
        };
        self.get_factory(ObjectType::new(class, type_))?
            .create(template)
    }

    pub fn get_object_factory(
        &self,
        obj: &Object,
    ) -> Result<&Box<dyn ObjectFactory>> {
        let class = obj.get_attr_as_ulong(CKA_CLASS)?;
        let type_ = match class {
            CKO_CERTIFICATE => obj.get_attr_as_ulong(CKA_CERTIFICATE_TYPE)?,
            CKO_PUBLIC_KEY | CKO_PRIVATE_KEY | CKO_SECRET_KEY => {
                obj.get_attr_as_ulong(CKA_KEY_TYPE)?
            }
            _ => 0,
        };
        self.get_factory(ObjectType::new(class, type_))
    }

    pub fn check_sensitive(
        &self,
        obj: &Object,
        template: &[CK_ATTRIBUTE],
    ) -> Result<()> {
        let objtype_attrs = self.get_object_factory(obj)?.get_attributes();
        for ck_attr in template {
            match objtype_attrs.iter().find(|a| a.get_type() == ck_attr.type_) {
                None => return Err(CKR_ATTRIBUTE_TYPE_INVALID)?,
                Some(attr) => {
                    if attr.is(OAFlags::Sensitive) {
                        return Err(CKR_ATTRIBUTE_SENSITIVE)?;
                    }
                }
            }
        }
        Ok(())
    }

    pub fn get_sensitive_attrs(
        &self,
        obj: &Object,
    ) -> Result<Vec<CK_ATTRIBUTE_TYPE>> {
        let mut v = Vec::<CK_ATTRIBUTE_TYPE>::new();
        let objtype_attrs = self.get_object_factory(obj)?.get_attributes();
        for attr in &obj.attributes {
            match objtype_attrs
                .iter()
                .find(|a| a.get_type() == attr.get_type())
            {
                None => (),
                Some(a) => {
                    if a.is(OAFlags::Sensitive) {
                        v.push(a.get_type());
                    }
                }
            }
        }
        Ok(v)
    }

    pub fn get_object_attributes(
        &self,
        obj: &Object,
        template: &mut [CK_ATTRIBUTE],
    ) -> Result<()> {
        let sensitive = obj.is_sensitive() & !obj.is_extractable();
        let mut result = match self
            .get_object_factory(obj)?
            .check_get_attributes(template, sensitive)
        {
            Ok(()) => CKR_OK,
            Err(e) => e.rv(),
        };

        let obj_attrs = obj.get_attributes();
        for ck_attr in template.iter_mut() {
            match obj_attrs.iter().find(|a| a.get_type() == ck_attr.type_) {
                None => {
                    ck_attr.ulValueLen = CK_UNAVAILABLE_INFORMATION;
                    if result == CKR_OK {
                        result = CKR_ATTRIBUTE_TYPE_INVALID;
                    }
                    continue;
                }
                Some(attr) => {
                    let attr_val = attr.get_value();
                    let attr_len = CK_ULONG::try_from(attr_val.len())?;
                    if ck_attr.pValue.is_null() {
                        ck_attr.ulValueLen = attr_len;
                    } else {
                        if ck_attr.ulValueLen < attr_len {
                            ck_attr.ulValueLen = CK_UNAVAILABLE_INFORMATION;
                            if result == CKR_OK {
                                result = CKR_BUFFER_TOO_SMALL;
                            }
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
            Err(result)?
        }
    }

    pub fn copy(
        &self,
        obj: &Object,
        template: &[CK_ATTRIBUTE],
    ) -> Result<Object> {
        if !obj.is_copyable() {
            return Err(CKR_ACTION_PROHIBITED)?;
        }
        self.get_object_factory(obj)?.copy(obj, template)
    }

    pub fn get_obj_factory_from_key_template(
        &self,
        template: &[CK_ATTRIBUTE],
    ) -> Result<&Box<dyn ObjectFactory>> {
        let class = match template.iter().position(|x| x.type_ == CKA_CLASS) {
            Some(idx) => template[idx].to_ulong()?,
            None => return Err(CKR_TEMPLATE_INCONSISTENT)?,
        };
        let key_type =
            match template.iter().position(|x| x.type_ == CKA_KEY_TYPE) {
                Some(idx) => template[idx].to_ulong()?,
                None => return Err(CKR_TEMPLATE_INCONSISTENT)?,
            };
        self.get_factory(ObjectType::new(class, key_type))
    }

    pub fn derive_key_from_template(
        &self,
        key: &Object,
        template: &[CK_ATTRIBUTE],
    ) -> Result<Object> {
        let factory = self.get_obj_factory_from_key_template(template)?;
        factory.default_object_derive(template, key)
    }
}

static DATA_OBJECT_FACTORY: Lazy<Box<dyn ObjectFactory>> =
    Lazy::new(|| Box::new(DataFactory::new()));

static X509_CERT_FACTORY: Lazy<Box<dyn ObjectFactory>> =
    Lazy::new(|| Box::new(X509Factory::new()));

static GENERIC_SECRET_FACTORY: Lazy<Box<dyn ObjectFactory>> =
    Lazy::new(|| Box::new(GenericSecretKeyFactory::new()));

pub fn register(mechs: &mut Mechanisms, ot: &mut ObjectFactories) {
    mechs.add_mechanism(
        CKM_GENERIC_SECRET_KEY_GEN,
        Box::new(GenericSecretKeyMechanism::new(CKK_GENERIC_SECRET)),
    );

    ot.add_factory(ObjectType::new(CKO_DATA, 0), &DATA_OBJECT_FACTORY);
    ot.add_factory(
        ObjectType::new(CKO_CERTIFICATE, CKC_X_509),
        &X509_CERT_FACTORY,
    );
    ot.add_factory(
        ObjectType::new(CKO_SECRET_KEY, CKK_GENERIC_SECRET),
        &GENERIC_SECRET_FACTORY,
    );
}
