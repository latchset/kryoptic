// Copyright 2023 Simo Sorce
// See LICENSE.txt file for terms

//! This module defines the core representation of PKCS#11 objects (`Object`)
//! and the associated factory system (`ObjectFactory` trait, `ObjectFactories`
//! registry) used to manage object creation, attribute validation, and
//! type-specific operations according to PKCS#11 specifications. It includes
//! common traits for different object classes (keys, certificates) and actual
//! factories for base types like Data objects, X.509 Certificates, and Generic
//! Secret Keys.

use std::collections::HashMap;
use std::fmt::Debug;

use crate::attribute::{AttrType, Attribute};
use crate::error::{Error, Result};
use crate::mechanism::{Mechanism, Mechanisms};
use crate::misc::zeromem;
use crate::CSPRNG;

use bitflags::bitflags;
use once_cell::sync::Lazy;
use pkcs11::*;
use uuid::Uuid;

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

/// Helper to map errors to CKR_TEMPLATE_INCOMPLETE
fn incomplete(e: Error) -> Error {
    if e.attr_not_found() {
        Error::ck_rv(CKR_TEMPLATE_INCOMPLETE)
    } else {
        e
    }
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
    pub fn new() -> Object {
        Object {
            handle: CK_INVALID_HANDLE,
            session: CK_INVALID_HANDLE,
            attributes: Vec::new(),
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

    /// Allow for a full copy of all attributes but regenerates the
    /// unique id
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

    create_bool_checker! {make is_token; from CKA_TOKEN; def false}
    create_bool_checker! {make is_private; from CKA_PRIVATE; def true}
    create_bool_checker! {make is_sensitive; from CKA_SENSITIVE; def true}
    create_bool_checker! {make is_copyable; from CKA_COPYABLE; def true}
    create_bool_checker! {make is_modifiable; from CKA_MODIFIABLE; def true}
    create_bool_checker! {make is_destroyable; from CKA_DESTROYABLE; def false}
    create_bool_checker! {make is_extractable; from CKA_EXTRACTABLE; def false}
    create_bool_checker! {make always_auth; from CKA_ALWAYS_AUTHENTICATE; def false}

    /// Get an attribute from the object by attribute id
    pub fn get_attr(&self, ck_type: CK_ULONG) -> Option<&Attribute> {
        self.attributes.iter().find(|r| r.get_type() == ck_type)
    }

    /// Sets or Replaces an attribute on the object
    pub fn set_attr(&mut self, a: Attribute) -> Result<()> {
        let atype = a.get_type();
        match self.attributes.iter().position(|r| r.get_type() == atype) {
            Some(idx) => self.attributes[idx] = a,
            None => self.attributes.push(a),
        }
        Ok(())
    }

    /// Sets an attribute, but returns failure if a pre-existing value
    /// is present and does not match the value being set.
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

    pub fn rough_size(&self) -> Result<usize> {
        let mut size = std::mem::size_of::<Attribute>() * self.attributes.len();
        for val in &self.attributes {
            size += val.get_value().len();
        }
        Ok(size)
    }
}

bitflags! {
    /// A bitflag set that defines attribute properties and behaviors
    #[derive(Debug, Clone, Copy)]
    pub struct OAFlags: u32 {
        /// the attribute is ignored and not copied from a template
        const Ignored              = 0x00000001;

        /// The attribute is sensitive and will not be returned by a call
        /// unless specifically authorized (like a key secret value)
        const Sensitive            = 0x00000002;

        /// The attribute has a default value that can be set when it is
        /// required on object creation but not provided by a template
        const Defval               = 0x00000004;

        /// The attribute must be provided in the template on object
        /// creation or the operation will fail
        const RequiredOnCreate     = 0x00000008;

        /// The attribute must be provided in the template on key
        /// generation or the operation will fail
        const RequiredOnGenerate   = 0x00000010;

        /// The attribute is always required or the operation will fail,
        /// however combined with Defval it means it will be generated
        /// automatically when absent from the template and will not
        /// cause the operation to fail
        const AlwaysRequired       = 0x00000020;

        /// The attribute can only be set in a template for create
        /// (import) operations, if set for any other operation (copy,
        /// generate, wrap, derive) it will cause a failure
        const SettableOnlyOnCreate = 0x00000080;

        /// This attribute can never be set in a template, if set the
        /// operation will fail (they are only ever set by internal
        /// functions)
        const NeverSettable        = 0x00000100;

        /// The attribute cannot be changed once set (enforced from
        /// changing via C_SetAttibuteValue or via C_CopyObject
        const Unchangeable         = 0x00000400;

        /// The attribute can only be changed from `True` to `False`
        const ChangeToFalse        = 0x00000C00;

        /// The attribute can only be changed from `False` to `True`
        const ChangeToTrue         = 0x00001400;

        /// The attribute can be changed only during a Copy Operation
        const ChangeOnCopy         = 0x00002400;

        /// The attribute is ephemeral and should not be stored on
        /// permanent storage
        const Ephemeral            = 0x00008000;
    }
}

/// This object is used to list the attribute that are allowed for specific
/// object types and also can define what if any their default value is and
/// what operation can be done on this object by applications.

#[derive(Debug, Clone)]
pub struct ObjectAttr {
    /// The reference attribute, may contain a default value
    attribute: Attribute,
    /// The flags that define the attribute properties for the object
    /// class this ObjectAttr is applied to
    flags: OAFlags,
}

impl ObjectAttr {
    /// Creates a new ObjectAttr
    pub fn new(a: Attribute, f: OAFlags) -> ObjectAttr {
        ObjectAttr {
            attribute: a,
            flags: f,
        }
    }

    /// Gets the internal attribute id (type)
    pub fn get_type(&self) -> CK_ULONG {
        self.attribute.get_type()
    }

    /// Check if a specific flag is present on the ObjectAttr
    pub fn is(&self, val: OAFlags) -> bool {
        self.flags.contains(val)
    }

    /// Checks if the ObjectAttr has a default value
    pub fn has_default(&self) -> bool {
        self.flags.contains(OAFlags::Defval)
    }
}

/// Helper to quickly instantiate an ObjectAttr element
macro_rules! attr_element {
    ($id:expr; $flags:expr; $from_type:expr; val $defval:expr) => {
        ObjectAttr::new($from_type($id, $defval), $flags)
    };
}
pub(crate) use attr_element;

/// This trait must be implemented by any mechanisms that defines an
/// object type, like key object of a specific type. The ObjectFactory
/// is responsible for defining what are the allowed attributes for the
/// specific object/key type, and any special behaviors for object
/// creation/import or other manipulation.

#[derive(Debug, Default)]
pub struct ObjectFactoryData {
    /// List of valid attributes and their properties for this factory
    attributes: Vec<ObjectAttr>,
    /// List of attributes considered sensitive
    sensitive: Vec<CK_ATTRIBUTE_TYPE>,
    /// List of attributes that should never be saved in token storage
    ephemeral: Vec<CK_ATTRIBUTE_TYPE>,
    /// Flag that indicates this factory data has been finalized and cannot
    /// be further modified
    finalized: bool,
}

impl ObjectFactoryData {
    /// Returns a reference to factory valid attributes and their properties
    pub fn get_attributes(&self) -> &Vec<ObjectAttr> {
        &self.attributes
    }

    /// Returns a mutable reference to factory valid attributes and
    /// their properties
    ///
    /// This method panics if it is called after the factory data has
    /// been finalized.
    pub fn get_attributes_mut(&mut self) -> &mut Vec<ObjectAttr> {
        if self.finalized {
            panic!("Attempted modification after finalization");
        }
        &mut self.attributes
    }

    /// Get the list of sensitive attributes
    ///
    /// Empty until the factory data is finalized
    pub fn get_sensitive(&self) -> &Vec<CK_ATTRIBUTE_TYPE> {
        &self.sensitive
    }

    /// Get the list of ephemeral attributes
    ///
    /// Empty until the factory data is finalized
    pub fn get_ephemeral(&self) -> &Vec<CK_ATTRIBUTE_TYPE> {
        &self.ephemeral
    }

    /// Finalizes the factory data and populates the sensitive
    /// and ephemeral lists
    pub fn finalize(&mut self) {
        for a in &self.attributes {
            if a.is(OAFlags::Sensitive) {
                self.sensitive.push(a.get_type());
            }
            if a.is(OAFlags::Ephemeral) {
                self.ephemeral.push(a.get_type());
            }
        }
        self.finalized = true;
    }
}

/// This is a common trait to define common methods all objects implement
/// and common attributes all objects posses
///
/// [Common attributes](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203203)
/// and
/// [Storage Objects](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203216)
/// (Version 3.1)

pub trait ObjectFactory: Debug + Send + Sync {
    /// Creates a new object from the template
    ///
    /// Mechanism implementations that can create objects must implement
    /// this function, the default implementation returns a general error.
    fn create(&self, _template: &[CK_ATTRIBUTE]) -> Result<Object> {
        return Err(CKR_GENERAL_ERROR)?;
    }

    /// Creates a copy of the object
    ///
    /// Uses the default_copy() internal method by default.
    fn copy(&self, obj: &Object, template: &[CK_ATTRIBUTE]) -> Result<Object> {
        self.default_copy(obj, template)
    }

    /// Adds the common object attributes defined in spec
    fn add_common_object_attrs(&mut self) {
        let attrs = self.get_data_mut().get_attributes_mut();
        attrs.push(attr_element!(
            CKA_CLASS; OAFlags::RequiredOnCreate;
            Attribute::from_ulong; val 0));
    }

    /// Adds the storage object attributes defined in the spec
    fn add_common_storage_attrs(&mut self, private: bool) {
        self.add_common_object_attrs();
        let attrs = self.get_data_mut().get_attributes_mut();
        attrs.push(attr_element!(
            CKA_TOKEN; OAFlags::Defval | OAFlags::ChangeOnCopy;
            Attribute::from_bool; val false));
        attrs.push(attr_element!(
            CKA_PRIVATE; OAFlags::Defval | OAFlags::ChangeOnCopy;
            Attribute::from_bool; val private));
        attrs.push(attr_element!(
            CKA_MODIFIABLE; OAFlags::Defval | OAFlags::ChangeOnCopy;
            Attribute::from_bool; val true));
        attrs.push(attr_element!(
            CKA_LABEL; OAFlags::empty(); Attribute::from_string;
            val String::new()));
        attrs.push(attr_element!(
            CKA_COPYABLE; OAFlags::Defval | OAFlags::ChangeToFalse;
            Attribute::from_bool; val true));
        attrs.push(attr_element!(
            CKA_DESTROYABLE; OAFlags::Defval; Attribute::from_bool;
            val true));
        attrs.push(attr_element!(
            CKA_UNIQUE_ID; OAFlags::NeverSettable | OAFlags::Unchangeable;
            Attribute::from_string; val String::new()));
    }

    /// Default object creation function
    ///
    /// Uses `internal_object_create()` with appropriate flags.
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

    /// Default key object generation function
    ///
    /// Uses `internal_object_create()` with appropriate flags.
    ///
    /// Marks the object for zeroization.
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

    /// Default key object unwrapping function
    ///
    /// Uses `internal_object_create()` with appropriate flags.
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

    /// Default key object derivation function
    ///
    /// Uses `internal_object_derive()`
    fn default_object_derive(
        &self,
        template: &[CK_ATTRIBUTE],
        origin: &Object,
    ) -> Result<Object> {
        self.internal_object_derive(template, origin)
    }

    /// The internal key object derivation function
    ///
    /// Uses `internal_object_create()` with appropriate flags.
    ///
    /// Sets appropate default values for [CKA_LOCAL],
    /// [CKA_ALWAYS_SENSITIVE], [CKA_NEVER_EXTRACTABLE] as
    /// required by spec.
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

    /// This function implements the creation/import/derivation of any object
    /// type and encodes common rules to interpret the list of ObjectAttr for
    /// the object.
    ///
    /// The unacceptable_flags argument defines what attributes can't be
    /// manipulated by the calling function when their flag matches one of
    /// the flags specified in this argument.
    ///
    /// The required_flags argument defines what attributes must be provided
    /// in the template by the calling function when their flag matches one of
    /// the flags specified in this argument.
    ///
    /// This function should not be overridden by specialized factories.

    fn internal_object_create(
        &self,
        template: &[CK_ATTRIBUTE],
        unacceptable_flags: OAFlags,
        required_flags: OAFlags,
    ) -> Result<Object> {
        let attributes = self.get_data().get_attributes();
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
                        obj.attributes.push(Attribute::from_ck_attr(ck_attr)?);
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

    /// Adds an attribute to an object using the default value defined
    /// for the attribute type in the factory
    #[allow(dead_code)]
    fn set_attribute_default(
        &self,
        attr: CK_ATTRIBUTE_TYPE,
        obj: &mut Object,
    ) -> Result<()> {
        let attributes = self.get_data().get_attributes();
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

    /// Helper to copy objects that respects the semantics and restrictions
    /// defined in the PKCS#11 specification.
    fn default_copy(
        &self,
        origin: &Object,
        template: &[CK_ATTRIBUTE],
    ) -> Result<Object> {
        let attributes = self.get_data().get_attributes();
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
            let _ = obj.set_attr(Attribute::from_ck_attr(ck_attr)?);
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

    /// Helper to allow serialization to export key material.
    /// A key type factory should implement this function only if a
    /// standardized serialization format specified in PKCS#11 exists.
    fn export_for_wrapping(&self, _obj: &Object) -> Result<Vec<u8>> {
        return Err(CKR_GENERAL_ERROR)?;
    }

    /// Helper to allow deserialization of a data packet wrapped by
    /// another mechanism. Useful only for key type factories for which a
    /// standard serialization format is specified.
    fn import_from_wrapped(
        &self,
        mut _data: Vec<u8>,
        _template: &[CK_ATTRIBUTE],
    ) -> Result<Object> {
        return Err(CKR_GENERAL_ERROR)?;
    }

    /// Helper to access traits that are only available for objects of
    /// class CKO_SECRET_KEY. Other key type factories should not
    /// implement this method.
    fn as_secret_key_factory(&self) -> Result<&dyn SecretKeyFactory> {
        Err(CKR_GENERAL_ERROR)?
    }

    /// Helper function to check if the attributes requested in the template
    /// are marked as sensitive or invalid. Only the first error is returned
    /// if multiple issues are found in the template.
    /// However the ulValueLen parameter of each attribute in the template is
    /// appropriately set based on the type of issue encountered as required
    /// by the PKCS#11 specification.
    fn check_get_attributes(
        &self,
        template: &mut [CK_ATTRIBUTE],
        sensitive: bool,
    ) -> Result<()> {
        let mut result = CKR_OK;
        let attrs = self.get_data().get_attributes();
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
                    /* This attribute is not valid for given object type */
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

    /// Helper function to check if the attributes specified in the template
    /// can be modified according to the PKCS#11 rules for the specific object.
    /// If an attribute provided in the template cannot be changed an
    /// appropriate error is returned.
    fn check_set_attributes(&self, template: &[CK_ATTRIBUTE]) -> Result<()> {
        let attrs = self.get_data().get_attributes();
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

    /// Helper function to change the attributes of an existing object.
    /// This helpers performs the necessary checks required to permit
    /// object modification in accordance to the PKCS#11 specification
    /// and returns an error if any check fails before any attribute is
    /// modified.
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
            obj.set_attr(Attribute::from_ck_attr(ck_attr)?)?;
        }

        Ok(())
    }

    /// Helper method to get a reference to the ObjectFactoryData
    fn get_data(&self) -> &ObjectFactoryData;

    /// Helper method to get a mutable reference to the ObjectFactoryData
    fn get_data_mut(&mut self) -> &mut ObjectFactoryData;
}

/// This is a specialized factory for objects of class CKO_DATA
///
/// [Data Objects](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203218)
/// (Version 3.1)

#[derive(Debug, Default)]
struct DataFactory {
    data: ObjectFactoryData,
}

impl DataFactory {
    /// Initializes a new DataFactory object
    fn new() -> DataFactory {
        let mut factory: DataFactory = Default::default();

        factory.add_common_storage_attrs(false);

        let attributes = factory.data.get_attributes_mut();

        attributes.push(attr_element!(
            CKA_APPLICATION; OAFlags::Defval; Attribute::from_string;
            val String::new()));
        attributes.push(attr_element!(
            CKA_OBJECT_ID; OAFlags::empty(); Attribute::from_bytes;
            val Vec::new()));
        attributes.push(attr_element!(
            CKA_VALUE; OAFlags::Defval; Attribute::from_bytes;
            val Vec::new()));

        factory.data.finalize();

        factory
    }
}

impl ObjectFactory for DataFactory {
    /// Creates a new Data Object from the template
    ///
    /// Uses `default_object_create()`
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

    fn get_data(&self) -> &ObjectFactoryData {
        &self.data
    }

    fn get_data_mut(&mut self) -> &mut ObjectFactoryData {
        &mut self.data
    }
}

/// This is a common trait to define factories for objects of class
/// CKO_CERTIFICATE
///
/// [Certificate objects](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203221)
/// (Version 3.1)

pub trait CertFactory: ObjectFactory {
    /// Adds the certificate object attributes defined in the spec
    fn add_common_certificate_attrs(&mut self) {
        self.add_common_storage_attrs(false);
        let attrs = self.get_data_mut().get_attributes_mut();
        attrs.push(attr_element!(
            CKA_CERTIFICATE_TYPE; OAFlags::AlwaysRequired;
            Attribute::from_ulong; val 0));
        attrs.push(attr_element!(
            CKA_TRUSTED; OAFlags::Defval; Attribute::from_bool;
            val false));
        attrs.push(attr_element!(
            CKA_CERTIFICATE_CATEGORY; OAFlags::Defval;
            Attribute::from_ulong;
            val CK_CERTIFICATE_CATEGORY_UNSPECIFIED));
        attrs.push(attr_element!(
            CKA_CHECK_VALUE; OAFlags::Ignored; Attribute::from_ignore;
            val None));
        attrs.push(attr_element!(
            CKA_START_DATE; OAFlags::Defval; Attribute::from_date_bytes;
            val Vec::new()));
        attrs.push(attr_element!(
            CKA_END_DATE; OAFlags::Defval; Attribute::from_date_bytes;
            val Vec::new()));
        attrs.push(attr_element!(
            CKA_PUBLIC_KEY_INFO; OAFlags::empty(); Attribute::from_bytes;
            val Vec::new()));
    }

    /// Validates values of basic certificate attribute conform to
    /// the spec on object creation
    ///
    /// Specifically prevents setting CKA_TRUSTED to true until we
    /// can properly check that the logged in user is the SO.
    ///
    /// Also ensures that CKA_CERTIFICATE_CATEGORY contains only
    /// valid values.
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

/// This is a specialized factory for objects of class CKO_CERTIFICATE
/// and CKA_CERTIFICATE_TYPE of value CKC_X_509
///
/// [X.509 public key certificate objects](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203224)
/// (Version 3.1)

#[derive(Debug, Default)]
struct X509Factory {
    data: ObjectFactoryData,
}

impl X509Factory {
    /// Initializes a new X509Factory object
    fn new() -> X509Factory {
        let mut factory: X509Factory = Default::default();

        factory.add_common_certificate_attrs();

        let attributes = factory.data.get_attributes_mut();

        attributes.push(attr_element!(
            CKA_SUBJECT; OAFlags::AlwaysRequired; Attribute::from_bytes;
            val Vec::new()));
        attributes.push(attr_element!(
            CKA_ID; OAFlags::Defval; Attribute::from_bytes; val Vec::new()));
        attributes.push(attr_element!(
            CKA_ISSUER; OAFlags::Defval; Attribute::from_bytes;
            val Vec::new()));
        attributes.push(attr_element!(
            CKA_SERIAL_NUMBER; OAFlags::Defval; Attribute::from_bytes;
            val Vec::new()));
        attributes.push(attr_element!(
            CKA_VALUE; OAFlags::AlwaysRequired; Attribute::from_bytes;
            val Vec::new()));
        attributes.push(attr_element!(
            CKA_URL; OAFlags::empty(); Attribute::from_string;
            val String::new()));
        attributes.push(attr_element!(
            CKA_HASH_OF_SUBJECT_PUBLIC_KEY; OAFlags::Defval;
            Attribute::from_bytes; val Vec::new()));
        attributes.push(attr_element!(
            CKA_HASH_OF_ISSUER_PUBLIC_KEY; OAFlags::Defval;
            Attribute::from_bytes; val Vec::new()));
        attributes.push(attr_element!(
            CKA_JAVA_MIDP_SECURITY_DOMAIN; OAFlags::Defval;
            Attribute::from_ulong; val CK_SECURITY_DOMAIN_UNSPECIFIED));
        attributes.push(attr_element!(
            CKA_NAME_HASH_ALGORITHM; OAFlags::empty(); Attribute::from_ulong;
            val CKM_SHA_1));

        factory.data.finalize();

        factory
    }
}

impl ObjectFactory for X509Factory {
    /// Creates a new X509 Certificate object
    ///
    /// Validates that the resulting object conforms to the spec
    /// requirements or returns an appropriate error.
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

    fn get_data(&self) -> &ObjectFactoryData {
        &self.data
    }

    fn get_data_mut(&mut self) -> &mut ObjectFactoryData {
        &mut self.data
    }
}

impl CertFactory for X509Factory {}

/// This is a common trait to define factories for objects that
/// are keys, this trait defines attribute common to all key classes.
///
/// [Key objects](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203227)
/// (Version 3.1)

pub trait CommonKeyFactory: ObjectFactory {
    /// Adds the key objects attributes defined for all keys in the spec
    fn add_common_key_attrs(&mut self, private: bool) {
        self.add_common_storage_attrs(private);
        let attrs = self.get_data_mut().get_attributes_mut();
        attrs.push(attr_element!(
            CKA_KEY_TYPE; OAFlags::RequiredOnCreate; Attribute::from_ulong;
            val CK_UNAVAILABLE_INFORMATION));
        attrs.push(attr_element!(
            CKA_ID; OAFlags::empty(); Attribute::from_bytes;
            val Vec::new()));
        attrs.push(attr_element!(
            CKA_START_DATE; OAFlags::Defval; Attribute::from_date_bytes;
            val Vec::new()));
        attrs.push(attr_element!(
            CKA_END_DATE; OAFlags::Defval; Attribute::from_date_bytes;
            val Vec::new()));
        attrs.push(attr_element!(
            CKA_DERIVE; OAFlags::Defval; Attribute::from_bool; val false));
        attrs.push(attr_element!(
            CKA_LOCAL; OAFlags::Defval | OAFlags::NeverSettable;
            Attribute::from_bool; val false));
        attrs.push(attr_element!(
            CKA_KEY_GEN_MECHANISM; OAFlags::Defval | OAFlags::NeverSettable;
            Attribute::from_ulong; val CK_UNAVAILABLE_INFORMATION));
        attrs.push(attr_element!(
            CKA_ALLOWED_MECHANISMS; OAFlags::empty(); Attribute::from_bytes;
            val Vec::new()));
        attrs.push(attr_element!(
            CKA_OBJECT_VALIDATION_FLAGS;
            OAFlags::NeverSettable | OAFlags::Ephemeral;
            Attribute::from_ulong; val 0));
    }
}

/// This is a common trait to define factories for key objects of class
/// CKO_PUBLIC_KEY
///
/// [Public key objects](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203230)
/// (Version 3.1)

#[allow(dead_code)]
pub trait PubKeyFactory: CommonKeyFactory {
    /// Adds the public key attributes defined in the spec
    fn add_common_public_key_attrs(&mut self) {
        self.add_common_key_attrs(false);
        let attrs = self.get_data_mut().get_attributes_mut();
        attrs.push(attr_element!(
            CKA_SUBJECT; OAFlags::Defval; Attribute::from_bytes;
            val Vec::new()));
        attrs.push(attr_element!(
            CKA_ENCRYPT; OAFlags::Defval; Attribute::from_bool; val false));
        attrs.push(attr_element!(
            CKA_VERIFY; OAFlags::Defval; Attribute::from_bool; val false));
        attrs.push(attr_element!(
            CKA_VERIFY_RECOVER; OAFlags::Defval; Attribute::from_bool;
            val false));
        attrs.push(attr_element!(
            CKA_WRAP; OAFlags::Defval; Attribute::from_bool; val false));
        attrs.push(attr_element!(
            CKA_TRUSTED; OAFlags::NeverSettable | OAFlags::Defval;
            Attribute::from_bool; val false));
        attrs.push(attr_element!(
            CKA_WRAP_TEMPLATE; OAFlags::empty(); Attribute::from_bytes;
            val Vec::new()));
        attrs.push(attr_element!(
            CKA_PUBLIC_KEY_INFO; OAFlags::empty(); Attribute::from_bytes;
            val Vec::new()));
        attrs.push(attr_element!(
            CKA_ENCAPSULATE; OAFlags::Defval; Attribute::from_bool;
            val false));
    }
}

/// This is a common trait to define factories for key objects of class
/// CKO_PRIVATE_KEY
///
/// [Private key objects](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203231)
/// (Version 3.1)

#[allow(dead_code)]
pub trait PrivKeyFactory: CommonKeyFactory {
    /// Adds the private key attributes defined in the spec
    fn add_common_private_key_attrs(&mut self) {
        self.add_common_key_attrs(true);
        let attrs = self.get_data_mut().get_attributes_mut();
        attrs.push(attr_element!(
            CKA_SUBJECT; OAFlags::Defval; Attribute::from_bytes;
            val Vec::new()));
        attrs.push(attr_element!(
            CKA_SENSITIVE; OAFlags::Defval | OAFlags::ChangeToTrue;
            Attribute::from_bool; val true));
        attrs.push(attr_element!(
            CKA_DECRYPT; OAFlags::Defval; Attribute::from_bool; val false));
        attrs.push(attr_element!(
            CKA_SIGN; OAFlags::Defval; Attribute::from_bool; val false));
        attrs.push(attr_element!(
            CKA_SIGN_RECOVER; OAFlags::Defval; Attribute::from_bool;
            val false));
        attrs.push(attr_element!(
            CKA_UNWRAP; OAFlags::Defval; Attribute::from_bool; val false));
        attrs.push(attr_element!(
            CKA_EXTRACTABLE; OAFlags::ChangeToFalse | OAFlags::Defval;
            Attribute::from_bool; val false));
        attrs.push(attr_element!(
            CKA_ALWAYS_SENSITIVE; OAFlags::NeverSettable;
            Attribute::from_bool; val false));
        attrs.push(attr_element!(
            CKA_NEVER_EXTRACTABLE; OAFlags::NeverSettable;
            Attribute::from_bool; val false));
        attrs.push(attr_element!(
            CKA_WRAP_WITH_TRUSTED; OAFlags::Defval | OAFlags::ChangeToTrue;
            Attribute::from_bool; val false));
        attrs.push(attr_element!(
            CKA_UNWRAP_TEMPLATE; OAFlags::empty(); Attribute::from_bytes;
            val Vec::new()));
        attrs.push(attr_element!(
            CKA_ALWAYS_AUTHENTICATE; OAFlags::Defval; Attribute::from_bool;
            val false));
        attrs.push(attr_element!(
            CKA_PUBLIC_KEY_INFO; OAFlags::empty(); Attribute::from_bytes;
            val Vec::new()));
        attrs.push(attr_element!(
            CKA_DERIVE_TEMPLATE; OAFlags::empty(); Attribute::from_bytes;
            val Vec::new()));
        attrs.push(attr_element!(
            CKA_DECAPSULATE; OAFlags::Defval; Attribute::from_bool;
            val false));
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

/// Helper to zeroize data if a function call returns an error
///
/// Allows to use ? error propagation on error while transparently
/// handling data cleanup from memory
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

/// This is a common trait to define factories for key objects of class
/// CKO_SECRET_KEY
///
/// [Secret key objects](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203232)
/// (Version 3.1)

pub trait SecretKeyFactory: CommonKeyFactory {
    /// Adds the secret key attributes defined in the spec
    fn add_common_secret_key_attrs(&mut self) {
        self.add_common_key_attrs(true);
        let attrs = self.get_data_mut().get_attributes_mut();
        attrs.push(attr_element!(
            CKA_SENSITIVE; OAFlags::Defval | OAFlags::ChangeToTrue;
            Attribute::from_bool; val true));
        attrs.push(attr_element!(
            CKA_ENCRYPT; OAFlags::Defval; Attribute::from_bool; val false));
        attrs.push(attr_element!(
            CKA_DECRYPT; OAFlags::Defval; Attribute::from_bool; val false));
        attrs.push(attr_element!(
            CKA_SIGN; OAFlags::Defval; Attribute::from_bool; val false));
        attrs.push(attr_element!(
            CKA_VERIFY; OAFlags::Defval; Attribute::from_bool; val false));
        attrs.push(attr_element!(
            CKA_WRAP; OAFlags::Defval; Attribute::from_bool; val false));
        attrs.push(attr_element!(
            CKA_UNWRAP; OAFlags::Defval; Attribute::from_bool; val false));
        attrs.push(attr_element!(
            CKA_EXTRACTABLE; OAFlags::ChangeToFalse | OAFlags::Defval;
            Attribute::from_bool; val false));
        attrs.push(attr_element!(
            CKA_ALWAYS_SENSITIVE; OAFlags::NeverSettable;
            Attribute::from_bool; val false));
        attrs.push(attr_element!(
            CKA_NEVER_EXTRACTABLE; OAFlags::NeverSettable;
            Attribute::from_bool; val false));
        attrs.push(attr_element!(
            CKA_CHECK_VALUE; OAFlags::Ignored; Attribute::from_ignore;
            val None));
        attrs.push(attr_element!(
            CKA_WRAP_WITH_TRUSTED; OAFlags::Defval | OAFlags::ChangeToTrue;
            Attribute::from_bool; val false));
        attrs.push(attr_element!(
            CKA_TRUSTED; OAFlags::NeverSettable | OAFlags::Defval;
            Attribute::from_bool; val false));
        attrs.push(attr_element!(
            CKA_WRAP_TEMPLATE; OAFlags::empty(); Attribute::from_bytes;
            val Vec::new()));
        attrs.push(attr_element!(
            CKA_UNWRAP_TEMPLATE; OAFlags::empty(); Attribute::from_bytes;
            val Vec::new()));
        attrs.push(attr_element!(
            CKA_DERIVE_TEMPLATE; OAFlags::empty(); Attribute::from_bytes;
            val Vec::new()));
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

    /// Returns the actual secret value length in bytes
    fn get_key_buffer_len(&self, obj: &Object) -> Result<usize> {
        Ok(obj
            .get_attr_as_bytes(CKA_VALUE)
            .map_err(|e| incomplete(e))?
            .len())
    }

    /// returns the key length as stored in CKA_VALUE_LEN
    fn get_key_len(&self, obj: &Object) -> usize {
        let Ok(len) = obj.get_attr_as_ulong(CKA_VALUE_LEN) else {
            return 0;
        };
        let Ok(len) = usize::try_from(len) else {
            return 0;
        };
        len
    }

    /// Checks the secret value length and populates the CKA_VALUE_LEN
    /// object attribute from it
    ///
    /// Ensures the secret value len actually matches the expected length
    /// provided in the `len` parameter.
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

    /// Helper to set a key on a key object, individual factories can override
    /// this function to ensure the key is appropriately formed for the type.
    /// For example by checking the buffer length.
    fn set_key(&self, obj: &mut Object, key: Vec<u8>) -> Result<()> {
        let keylen = key.len();
        obj.set_attr(Attribute::from_bytes(CKA_VALUE, key))?;
        self.set_key_len(obj, keylen)?;
        Ok(())
    }

    /// Helper to allow other mechanisms select the correct key length.
    /// Specialized factories are expected to override this function.
    ///
    /// The expected input is the maximum amount of bytes the caller can
    /// generate, the output will be the allowable size closest to this input
    /// that the mechanism should use.
    fn recommend_key_size(&self, _: usize) -> Result<usize> {
        return Err(CKR_GENERAL_ERROR)?;
    }
}

/// This is a specialized factory for objects of class CKO_SECRET_KEY
/// and CKA_KEY_TYPE of value CKK_GENERIC_SECRET
///
/// [Generic secret key](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203468)
/// (Version 3.1)

#[derive(Debug, Default)]
pub struct GenericSecretKeyFactory {
    keysize: usize,
    data: ObjectFactoryData,
}

impl GenericSecretKeyFactory {
    /// Initializes a new GenericSecretKeyFactory object
    pub fn new() -> GenericSecretKeyFactory {
        let mut factory: GenericSecretKeyFactory = Default::default();

        factory.add_common_secret_key_attrs();

        let attributes = factory.data.get_attributes_mut();

        attributes.push(attr_element!(
            CKA_VALUE; OAFlags::Sensitive | OAFlags::RequiredOnCreate
            | OAFlags::SettableOnlyOnCreate; Attribute::from_bytes;
            val Vec::new()));
        attributes.push(attr_element!(
            CKA_VALUE_LEN; OAFlags::RequiredOnGenerate; Attribute::from_bytes;
            val Vec::new()));

        /* default to private */
        let private = attr_element!(
            CKA_PRIVATE; OAFlags::Defval | OAFlags::ChangeOnCopy; Attribute::from_bool; val true);
        match attributes.iter().position(|x| x.get_type() == CKA_PRIVATE) {
            Some(idx) => attributes[idx] = private,
            None => attributes.push(private),
        }

        factory.data.finalize();

        factory
    }

    /// Initializes a new GenericSecretKeyFactory object that enforces
    /// a defined key size
    pub fn with_key_size(size: usize) -> GenericSecretKeyFactory {
        let mut factory = Self::new();
        factory.keysize = size;
        factory
    }
}

impl ObjectFactory for GenericSecretKeyFactory {
    /// Creates a new secret key from the template
    ///
    /// Ensures that the key length matches the defined size if any
    /// and is not 0 otherwise
    ///
    /// Sets the CKA_VALUE_LEN attribute from the key length, if missing.
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

    /// Returns a cast to the SecretKeyFactory trait for this object
    fn as_secret_key_factory(&self) -> Result<&dyn SecretKeyFactory> {
        Ok(self)
    }

    fn get_data(&self) -> &ObjectFactoryData {
        &self.data
    }

    fn get_data_mut(&mut self) -> &mut ObjectFactoryData {
        &mut self.data
    }
}

impl CommonKeyFactory for GenericSecretKeyFactory {}

impl SecretKeyFactory for GenericSecretKeyFactory {
    /// Provides the recommended key size for this object if available,
    /// otherwise reflects back the provided default
    fn recommend_key_size(&self, default: usize) -> Result<usize> {
        if self.keysize != 0 {
            Ok(self.keysize)
        } else {
            Ok(default)
        }
    }
}

/// Generic reusable object to represent mechanisms associated
/// with symmetric key objects
#[derive(Debug)]
pub struct GenericSecretKeyMechanism {
    /// Generic mechanism info
    info: CK_MECHANISM_INFO,
    /// The actual key type for this mechanism
    ///
    /// Must be a key type of class CKO_SECRET_KEY
    keytype: CK_KEY_TYPE,
}

impl GenericSecretKeyMechanism {
    /// Instantiates a mechanism info for a specified symmetric key type
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

    /// Returns the keytype associated with this mechanism
    fn keytype(&self) -> CK_KEY_TYPE {
        self.keytype
    }
}

/// The generic and default implementation of symmetric key generation
///
/// Uses the internal CSPRNG to generate a high entropy random symmetric key.
///
/// The key length must be specified in the CKA_VALUE_LEN attribute of the
/// provided object.
///
/// The object will be modified to store the secret raw key in the CKA_VALUE
/// attribute.
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

/// Helper function to set generic attributes applicable to all keys
/// to their defaults based on the mechanism that generated the key
pub fn default_key_attributes(
    key: &mut Object,
    mech: CK_MECHANISM_TYPE,
) -> Result<()> {
    key.set_attr(Attribute::from_bool(CKA_LOCAL, true))?;
    key.set_attr(Attribute::from_ulong(CKA_KEY_GEN_MECHANISM, mech))?;

    let extractable = match key.get_attr_as_bool(CKA_EXTRACTABLE) {
        Ok(b) => b,
        _ => true,
    };
    key.set_attr(Attribute::from_bool(CKA_NEVER_EXTRACTABLE, !extractable))?;
    let sensitive = match key.get_attr_as_bool(CKA_SENSITIVE) {
        Ok(b) => b,
        _ => false,
    };
    key.set_attr(Attribute::from_bool(CKA_ALWAYS_SENSITIVE, sensitive))?;

    Ok(())
}

impl Mechanism for GenericSecretKeyMechanism {
    fn info(&self) -> &CK_MECHANISM_INFO {
        &self.info
    }

    /// Implements the Generic Secret Key Generation
    ///
    /// [Generic secret key generation](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203471)
    /// (Version 3.1)

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

/// Structure that defines an Object Type
///
/// Holds a Class type and the underlying type.
///
/// For object classes that have no underlying type `type_` is set to 0.
#[derive(Debug, Eq, Hash, PartialEq)]
pub struct ObjectType {
    class: CK_ULONG,
    type_: CK_ULONG,
}

impl ObjectType {
    /// Initializes and returns a new ObjectType
    pub fn new(class: CK_ULONG, type_: CK_ULONG) -> ObjectType {
        ObjectType {
            class: class,
            type_: type_,
        }
    }
}

/// This structure holds all of the registered object factories for
/// the implemented object types.
///
/// It provides accessors to find and retrieve object factories, and
/// to add object factories at token initialization.

#[derive(Debug)]
pub struct ObjectFactories {
    factories: HashMap<ObjectType, &'static Box<dyn ObjectFactory>>,
}

impl ObjectFactories {
    /// Crates a new Object Factory registry
    pub fn new() -> ObjectFactories {
        ObjectFactories {
            factories: HashMap::new(),
        }
    }

    /// Adds a factory to the registry
    pub fn add_factory(
        &mut self,
        otype: ObjectType,
        templ: &'static Box<dyn ObjectFactory>,
    ) {
        self.factories.insert(otype, templ);
    }

    /// Retrieves a factory for the specified object type from the registry
    pub fn get_factory(
        &self,
        otype: ObjectType,
    ) -> Result<&Box<dyn ObjectFactory>> {
        match self.factories.get(&otype) {
            Some(b) => Ok(b),
            None => Err(CKR_ATTRIBUTE_VALUE_INVALID)?,
        }
    }

    /// Crates a new object using the appropriate factory based on the
    /// data in the template.
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

    /// Returns the object factory associated to the specified object
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

    /// Helper to check if the template includes invalid or sensitive
    /// attributes related to the specified object. This is done by
    /// sourcing the object factory related to the provide object and
    /// then using object type specific attribute lists.
    pub fn check_sensitive(
        &self,
        obj: &Object,
        template: &[CK_ATTRIBUTE],
    ) -> Result<()> {
        let objtype_attrs =
            self.get_object_factory(obj)?.get_data().get_attributes();
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

    /// Fills the template with the specified attributes from the provided
    /// object. Ensures the attribute are valid and can be returned. If the
    /// object is not extractable and a sensitive attribute is requested an
    /// appropriate error is returned and the template is not filled, except
    /// for setting the ulValueLen of the forbidden attributes appropriately
    /// as required by the PKCS#11 specification.
    pub fn get_object_attributes(
        &self,
        obj: &Object,
        template: &mut [CK_ATTRIBUTE],
    ) -> Result<()> {
        let sensitive = obj.is_sensitive() || !obj.is_extractable();
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
                    /* This attribute is not available on given object */
                    ck_attr.ulValueLen = CK_UNAVAILABLE_INFORMATION;
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

    /// Uses an object type specific copy operation to return a copy
    /// of the provided object
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

    /// Finds the appropriate object factory to operate on the object
    /// defined by the template
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

    /// Finds the appropriate object factory for the derivation template
    /// provided and attempts a key derivation operation.
    pub fn derive_key_from_template(
        &self,
        key: &Object,
        template: &[CK_ATTRIBUTE],
    ) -> Result<Object> {
        let factory = self.get_obj_factory_from_key_template(template)?;
        factory.default_object_derive(template, key)
    }
}

/// The static Data Object factory
///
/// This is instantiated only once and finalized to make it unchangeable
/// after process startup
static DATA_OBJECT_FACTORY: Lazy<Box<dyn ObjectFactory>> =
    Lazy::new(|| Box::new(DataFactory::new()));

/// The static X509 Certificate factory
///
/// This is instantiated only once and finalized to make it unchangeable
/// after process startup
static X509_CERT_FACTORY: Lazy<Box<dyn ObjectFactory>> =
    Lazy::new(|| Box::new(X509Factory::new()));

/// The static Generic Secret factory
///
/// This is instantiated only once and finalized to make it unchangeable
/// after process startup
static GENERIC_SECRET_FACTORY: Lazy<Box<dyn ObjectFactory>> =
    Lazy::new(|| Box::new(GenericSecretKeyFactory::new()));

/// Registers mechanisms and key factories for Data Objects, X509
/// Certificates and Generic Secret Keys
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
