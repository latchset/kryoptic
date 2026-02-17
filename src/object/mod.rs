// Copyright 2023-2026 Simo Sorce
// See LICENSE.txt file for terms

//! This module defines the core representation of PKCS#11 objects (`Object`)
//! and the associated factory system (`ObjectFactory` trait, `ObjectFactories`
//! registry) used to manage object creation, attribute validation, and
//! type-specific operations according to PKCS#11 specifications. It includes
//! common traits for different object classes (keys, certificates) and actual
//! factories for base types like Data objects, X.509 Certificates, and Generic
//! Secret Keys.

use std::fmt::Debug;

use crate::attribute::{AttrType, Attribute};
use crate::error::{Error, Result};
use crate::pkcs11::*;

use uuid::Uuid;

pub mod certs;
pub mod factory;
pub mod key;

pub use factory::{
    attr_element, OAFlags, ObjectFactories, ObjectFactory, ObjectFactoryData,
    ObjectType,
};

pub use key::{
    default_key_attributes, default_secret_key_generate,
    GenericSecretKeyFactory, GenericSecretKeyMechanism, KeyFactory,
    PrivKeyFactory, PubKeyFactory, SecretKeyFactory,
};

/// Helper macro that generates methods to check specific boolean

/// attributes on objects
macro_rules! create_bool_checker {
    (make $name:ident; from $id:expr; def $def:expr) => {
        #[doc = concat!("Returns the value of [", stringify!($id), "] as a boolean")]
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

/// Helper macro that generates methods to retrieve attributes
/// values of a specific type from objects
macro_rules! attr_as_type {
    (make $name:ident; with $r:ty; $atype:ident; via $conv:ident) => {
        #[doc = concat!("Returns the value of the attribute as a `", stringify!($r), "`")]
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

/// This is a generic container for all PKCS#11 Objects
/// For Key objects it is possible to set the zeroize feature which
/// will cause zeroization of every attribute when the object is dropped.

#[derive(Debug, Clone)]
pub struct Object {
    /// The object handle value
    ///
    /// Can be CK_INVALID_HANDLE on new objects
    handle: CK_OBJECT_HANDLE,
    /// The session this object is associated to
    ///
    /// Set to CK_INVALID_HANDLE when the object is not tied to
    /// a session or is new
    session: CK_SESSION_HANDLE,
    /// All objects have a class so we keep it here in order to access it
    /// directly in some internal functions
    class: CK_OBJECT_CLASS,
    /// The object attributes as vector of [Attribute] values
    attributes: Vec<Attribute>,
    /// Flag to indicate if the object needs to be zeroized when it is
    /// drop()ed. Generally set to true for objects containing sensitive
    /// values like private or secret keys
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
    /// Creates a new empty Object
    pub fn new(class: CK_OBJECT_CLASS) -> Object {
        Object {
            handle: CK_INVALID_HANDLE,
            session: CK_INVALID_HANDLE,
            class: class,
            attributes: vec![Attribute::from_ulong(CKA_CLASS, class)],
            zeroize: false,
        }
    }

    /// Set zeroization for the whole object, this is done when
    /// the object is dropped via the Drop trait and memory is freed.
    pub fn set_zeroize(&mut self) {
        self.zeroize = true;
    }

    /// Generates the internal per object unique id
    /// This is generally called at object creation or import
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

    /// Generates the internal per object unique id using a stable input
    pub fn generate_stable_unique(&mut self, stable_id: CK_ULONG) {
        if !self
            .attributes
            .iter()
            .any(|r| r.get_type() == CKA_UNIQUE_ID)
        {
            let class = match self.get_attr_as_ulong(CKA_CLASS) {
                Ok(c) => c,
                Err(_) => CK_UNAVAILABLE_INFORMATION,
            };
            let mut buf = [0u8; 16];
            buf[..8].copy_from_slice(b"kryoptic");
            let val = (class & 0xFFFFFFFF) as u32;
            buf[8..12].copy_from_slice(&val.to_be_bytes());
            let val = (stable_id & 0xFFFFFFFF) as u32;
            buf[12..16].copy_from_slice(&val.to_be_bytes());
            let uuid = Uuid::new_v8(buf).to_string();
            self.attributes
                .push(Attribute::from_string(CKA_UNIQUE_ID, uuid));
        }
    }

    /// Allow for a full copy of all attributes but regenerates the
    /// unique id
    pub fn blind_copy(&self) -> Result<Object> {
        let mut obj = Object::new(self.class);
        obj.generate_unique();
        for attr in &self.attributes {
            if attr.get_type() == CKA_UNIQUE_ID {
                continue;
            }
            obj.attributes.push(attr.clone());
        }
        Ok(obj)
    }

    /// Set the current handle being provided to the application, this
    /// is an internal cache that is not stored in the databases.
    pub fn set_handle(&mut self, h: CK_OBJECT_HANDLE) {
        self.handle = h
    }

    /// Gets the object's handle
    pub fn get_handle(&self) -> CK_OBJECT_HANDLE {
        self.handle
    }

    /// Set the session this object is tied to (for session objects).
    pub fn set_session(&mut self, s: CK_SESSION_HANDLE) {
        self.session = s
    }

    /// Gets the object's Session handle
    pub fn get_session(&self) -> CK_SESSION_HANDLE {
        self.session
    }

    /// Gets the object's class
    pub fn get_class(&self) -> CK_OBJECT_CLASS {
        self.class
    }

    create_bool_checker! {make is_token; from CKA_TOKEN; def false}
    create_bool_checker! {make is_private; from CKA_PRIVATE; def true}
    create_bool_checker! {make is_always_sensitive; from CKA_ALWAYS_SENSITIVE; def true}
    create_bool_checker! {make is_copyable; from CKA_COPYABLE; def true}
    create_bool_checker! {make is_modifiable; from CKA_MODIFIABLE; def true}
    create_bool_checker! {make is_destroyable; from CKA_DESTROYABLE; def false}
    create_bool_checker! {make is_never_extractable; from CKA_NEVER_EXTRACTABLE; def false}
    create_bool_checker! {make always_auth; from CKA_ALWAYS_AUTHENTICATE; def false}

    /// Report if the object is sensitive with a sensible default
    pub fn is_sensitive(&self) -> bool {
        match self.class {
            CKO_PRIVATE_KEY | CKO_SECRET_KEY => {
                for a in &self.attributes {
                    if a.get_type() == CKA_SENSITIVE {
                        return a.to_bool().unwrap_or(true);
                    }
                }
                true
            }
            _ => false,
        }
    }

    /// Report is the object is extractable with a sensible default
    pub fn is_extractable(&self) -> bool {
        match self.class {
            CKO_PRIVATE_KEY | CKO_SECRET_KEY => {
                for a in &self.attributes {
                    if a.get_type() == CKA_EXTRACTABLE {
                        return a.to_bool().unwrap_or(false);
                    }
                }
                false
            }
            _ => true,
        }
    }

    /// Get an attribute from the object by attribute id
    pub fn get_attr(&self, ck_type: CK_ULONG) -> Option<&Attribute> {
        self.attributes.iter().find(|r| r.get_type() == ck_type)
    }

    /// Sets or Replaces an attribute on the object
    pub fn set_attr(&mut self, a: Attribute) -> Result<()> {
        let atype = a.get_type();
        if atype == CKA_CLASS {
            self.class = a.to_ulong()?;
        }
        match self.attributes.iter().position(|r| r.get_type() == atype) {
            Some(idx) => self.attributes[idx] = a,
            None => self.attributes.push(a),
        }
        Ok(())
    }

    /// Deletes an attribute from the object by attribute id
    pub fn del_attr(&mut self, ck_type: CK_ULONG) {
        self.attributes.retain(|a| a.get_type() != ck_type);
    }

    /// Gets a reference to the internal vector of object attributes
    pub fn get_attributes(&self) -> &Vec<Attribute> {
        return &self.attributes;
    }

    attr_as_type! {make get_attr_as_bool; with bool; BoolType; via to_bool}
    attr_as_type! {make get_attr_as_ulong; with CK_ULONG; NumType; via to_ulong}
    attr_as_type! {make get_attr_as_string; with String; StringType; via to_string}
    attr_as_type! {make get_attr_as_bytes; with &Vec<u8>; BytesType; via to_bytes}

    /// Checks that the attributes in the template are present on the object
    /// with the specified value if any value is specified in the individual
    /// template attribute.
    pub fn match_template(&self, template: &[CK_ATTRIBUTE]) -> bool {
        for ck_attr in template {
            match self.attributes.iter().find(|r| r.match_ck_attr(ck_attr)) {
                Some(_) => (),
                None => return false,
            }
        }
        true
    }

    /// Checks that the object is an object of the type specified in the class
    /// and ktype arguments and that it supports the operations specified in
    /// the op argument.
    ///
    /// If ktype is not specified (by setting its value to
    /// CK_UNAVAILABLE_INFORMATION) only the class and operations are checked.
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

    /// Returns the rough size of the object in bytes
    pub fn rough_size(&self) -> Result<usize> {
        let mut size = std::mem::size_of::<Attribute>() * self.attributes.len();
        for val in &self.attributes {
            size += val.get_value().len();
        }
        Ok(size)
    }

    /// Ensures that a specific ulong attribute is present on the object with the given value.
    ///
    /// If the attribute already exists, its value is checked against the provided `value`.
    /// If they don't match, `CKR_ATTRIBUTE_VALUE_INVALID` is returned.
    /// If the attribute does not exist, it is added to the object with the given `name` and `value`.
    pub fn ensure_ulong(
        &mut self,
        name: CK_ATTRIBUTE_TYPE,
        value: CK_ULONG,
    ) -> Result<()> {
        match self.attributes.iter().find(|r| r.get_type() == name) {
            Some(attr) => {
                if attr.to_ulong()? != value {
                    return Err(CKR_ATTRIBUTE_VALUE_INVALID)?;
                }
            }
            None => self.attributes.push(Attribute::from_ulong(name, value)),
        }
        Ok(())
    }

    /// Ensures that a specific byte slice attribute is present on the object with the given value.
    ///
    /// If the attribute already exists, its value is checked against the provided `value`.
    /// If they don't match, `CKR_ATTRIBUTE_VALUE_INVALID` is returned.
    /// If the attribute does not exist, it is added to the object with the given `name` and `value`.
    pub fn ensure_slice(
        &mut self,
        name: CK_ATTRIBUTE_TYPE,
        value: &[u8],
    ) -> Result<()> {
        match self.attributes.iter().find(|r| r.get_type() == name) {
            Some(attr) => {
                if attr.get_value() != value {
                    return Err(CKR_ATTRIBUTE_VALUE_INVALID)?;
                }
            }
            None => self
                .attributes
                .push(Attribute::from_bytes(name, value.to_vec())),
        }
        Ok(())
    }

    /// Ensures that a specific byte vector attribute is present on the object with the given value.
    ///
    /// If the attribute already exists, its value is checked against the provided `value`.
    /// If they don't match, `CKR_ATTRIBUTE_VALUE_INVALID` is returned.
    /// If the attribute does not exist, it is added to the object with the given `name` and `value`.
    pub fn ensure_bytes(
        &mut self,
        name: CK_ATTRIBUTE_TYPE,
        value: Vec<u8>,
    ) -> Result<()> {
        match self.attributes.iter().find(|r| r.get_type() == name) {
            Some(attr) => {
                if attr.get_value() != &value {
                    return Err(CKR_ATTRIBUTE_VALUE_INVALID)?;
                }
            }
            None => self.attributes.push(Attribute::from_bytes(name, value)),
        }
        Ok(())
    }
}
