// Copyright 2023-2026 Simo Sorce
// See LICENSE.txt file for terms

use std::collections::HashMap;
use std::fmt::Debug;
use std::sync::LazyLock;

use crate::attribute::{AttrType, Attribute};
use crate::error::{Error, Result};
use crate::mechanism::{Mechanism, Mechanisms};
use crate::misc::{sizeof, void_ptr};
use crate::pkcs11::*;

#[cfg(feature = "nssdb")]
use crate::pkcs11::vendor::nss::*;

use super::certs::{TrustObject, X509Factory};
use super::key::{
    GenericSecretKeyFactory, GenericSecretKeyMechanism, KeyFactory,
    PubKeyFactory, SecretKeyFactory,
};
use super::Object;

#[cfg(feature = "nssdb")]
use super::certs::NSSTrustObject;

use bitflags::bitflags;

/// Helper to map errors to CKR_TEMPLATE_INCOMPLETE
pub fn incomplete(e: Error) -> Error {
    if e.attr_not_found() {
        Error::ck_rv(CKR_TEMPLATE_INCOMPLETE)
    } else {
        e
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
    pub(crate) attribute: Attribute,
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
        if val.is_empty() {
            return false;
        }
        self.flags.contains(val)
    }

    /// Checks if the ObjectAttr has a default value
    pub fn has_default(&self) -> bool {
        self.flags.contains(OAFlags::Defval)
    }
}

/// Helper to quickly instantiate an ObjectAttr element
#[macro_export]
macro_rules! attr_element {
    ($id:expr; $flags:expr; $from_type:expr; val $defval:expr) => {
        $crate::object::factory::ObjectAttr::new(
            $from_type($id, $defval),
            $flags,
        )
    };
}
pub use attr_element;

/// This trait must be implemented by any mechanisms that defines an
/// object type, like key object of a specific type. The ObjectFactory
/// is responsible for defining what are the allowed attributes for the
/// specific object/key type, and any special behaviors for object
/// creation/import or other manipulation.

#[derive(Debug)]
pub struct ObjectFactoryData {
    /// Class of the object created by the factory
    class: CK_OBJECT_CLASS,
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
    pub fn new(class: CK_OBJECT_CLASS) -> ObjectFactoryData {
        ObjectFactoryData {
            class: class,
            attributes: Vec::new(),
            sensitive: Vec::new(),
            ephemeral: Vec::new(),
            finalized: false,
        }
    }

    /// Return the class of the object created by the factory
    pub fn get_class(&self) -> CK_OBJECT_CLASS {
        self.class
    }

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

    /// Creates a new Built-In object from the template
    ///
    /// Implemented only by mechanism that provide built-in objects
    fn builtin_create(&self, _id: CK_ULONG) -> Result<Object> {
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
        attrs.push(attr_element!(
            CKA_UNIQUE_ID; OAFlags::NeverSettable | OAFlags::Unchangeable;
            Attribute::from_string; val String::new()));
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
        let data = self.get_data();
        let mut obj = Object::new(data.get_class());

        let attributes = data.get_attributes();
        for ck_attr in template {
            match attributes.iter().find(|a| a.get_type() == ck_attr.type_) {
                Some(attr) => {
                    if attr.is(unacceptable_flags) {
                        return Err(CKR_ATTRIBUTE_TYPE_INVALID)?;
                    }
                    /* duplicate? */
                    match obj.get_attr(ck_attr.type_) {
                        Some(oa) => {
                            if oa.get_type() != CKA_CLASS
                                || (oa.get_type() == CKA_CLASS
                                    && ck_attr.to_ulong()? != oa.to_ulong()?)
                            {
                                return Err(CKR_TEMPLATE_INCONSISTENT)?;
                            }
                        }
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
        Ok(obj)
    }

    fn default_object_create(
        &self,
        template: &[CK_ATTRIBUTE],
    ) -> Result<Object> {
        let mut obj = self.internal_object_create(
            template,
            OAFlags::NeverSettable,
            OAFlags::RequiredOnCreate,
        )?;
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
            let _ = obj.set_attr(Attribute::from_ck_attr(ck_attr)?)?;
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
                    if attr.is(OAFlags::NeverSettable) {
                        return Err(CKR_ACTION_PROHIBITED)?;
                    }
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

    /// Helper to access traits that are only available for objects of
    /// type Key, other types of objects should not implement this method.
    fn as_key_factory(&self) -> Result<&dyn KeyFactory> {
        Err(CKR_GENERAL_ERROR)?
    }

    /// Helper to access traits that are only available for objects of
    /// class CKO_PUPBLIC_KEY. Other key type factories should not

    /// implement this method.
    fn as_public_key_factory(&self) -> Result<&dyn PubKeyFactory> {
        Err(CKR_GENERAL_ERROR)?
    }

    /// Helper to access traits that are only available for objects of
    /// class CKO_SECRET_KEY. Other key type factories should not
    /// implement this method.
    fn as_secret_key_factory(&self) -> Result<&dyn SecretKeyFactory> {
        Err(CKR_GENERAL_ERROR)?
    }
}

/// This is a specialized factory for objects of class CKO_DATA
///
/// [Data Objects](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203218)
/// (Version 3.1)

#[derive(Debug)]
struct DataFactory {
    data: ObjectFactoryData,
}

impl DataFactory {
    /// Initializes a new DataFactory object
    fn new() -> DataFactory {
        let mut factory: DataFactory = DataFactory {
            data: ObjectFactoryData::new(CKO_DATA),
        };

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
    /// Uses `key_create()`
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

/// This is a specialized factory for objects of class CKO_PROFILE

#[cfg(feature = "profiles")]
#[derive(Debug)]
pub struct ProfileFactory {
    data: ObjectFactoryData,
}

#[cfg(feature = "profiles")]
impl ProfileFactory {
    /// Initializes a new ProfileFactory object
    fn new() -> ProfileFactory {
        let mut factory: ProfileFactory = ProfileFactory {
            data: ObjectFactoryData::new(CKO_PROFILE),
        };

        factory.add_common_object_attrs();

        let attributes = factory.data.get_attributes_mut();

        attributes.push(attr_element!(
            CKA_PROFILE_ID; OAFlags::RequiredOnCreate; Attribute::from_ulong;
            val CK_UNAVAILABLE_INFORMATION));

        factory.data.finalize();

        factory
    }
}

#[cfg(feature = "profiles")]
impl ObjectFactory for ProfileFactory {
    fn create(&self, _template: &[CK_ATTRIBUTE]) -> Result<Object> {
        Err(CKR_TEMPLATE_INCOMPLETE)?
    }

    fn builtin_create(&self, profile_id: CK_PROFILE_ID) -> Result<Object> {
        let mut pid = profile_id;
        let attr = CK_ATTRIBUTE {
            type_: CKA_PROFILE_ID,
            pValue: void_ptr!(&mut pid),
            ulValueLen: sizeof!(CK_PROFILE_ID),
        };
        let mut obj = self.internal_object_create(
            &[attr],
            OAFlags::empty(),
            OAFlags::RequiredOnCreate,
        )?;
        obj.generate_stable_unique(profile_id);
        Ok(obj)
    }

    fn copy(
        &self,
        _origin: &Object,
        _template: &[CK_ATTRIBUTE],
    ) -> Result<Object> {
        Err(CKR_ACTION_PROHIBITED)?
    }

    fn get_data(&self) -> &ObjectFactoryData {
        &self.data
    }

    fn get_data_mut(&mut self) -> &mut ObjectFactoryData {
        &mut self.data
    }
}

/// This is a specialized factory for objects of class CKO_MECHANISM

#[derive(Debug)]
pub struct MechanismFactory {
    data: ObjectFactoryData,
}

impl MechanismFactory {
    /// Initializes a new MechanismFactory object
    fn new() -> MechanismFactory {
        let mut factory: MechanismFactory = MechanismFactory {
            data: ObjectFactoryData::new(CKO_MECHANISM),
        };

        factory.add_common_object_attrs();

        let attributes = factory.data.get_attributes_mut();

        attributes.push(attr_element!(
            CKA_MECHANISM_TYPE; OAFlags::RequiredOnCreate; Attribute::from_ulong;
            val CK_UNAVAILABLE_INFORMATION));

        factory.data.finalize();

        factory
    }
}

impl ObjectFactory for MechanismFactory {
    fn create(&self, _template: &[CK_ATTRIBUTE]) -> Result<Object> {
        Err(CKR_TEMPLATE_INCOMPLETE)?
    }

    fn builtin_create(
        &self,
        mechanism_type: CK_MECHANISM_TYPE,
    ) -> Result<Object> {
        let mut mt = mechanism_type;
        let attr = CK_ATTRIBUTE {
            type_: CKA_MECHANISM_TYPE,
            pValue: void_ptr!(&mut mt),
            ulValueLen: sizeof!(CK_MECHANISM_TYPE),
        };
        let mut obj = self.internal_object_create(
            &[attr],
            OAFlags::empty(),
            OAFlags::RequiredOnCreate,
        )?;
        obj.generate_stable_unique(mechanism_type);
        Ok(obj)
    }

    fn copy(
        &self,
        _origin: &Object,
        _template: &[CK_ATTRIBUTE],
    ) -> Result<Object> {
        Err(CKR_ACTION_PROHIBITED)?
    }

    fn get_data(&self) -> &ObjectFactoryData {
        &self.data
    }

    fn get_data_mut(&mut self) -> &mut ObjectFactoryData {
        &mut self.data
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
            CKO_DATA | CKO_TRUST | CKO_PROFILE | CKO_MECHANISM => 0,
            #[cfg(feature = "nssdb")]
            CKO_NSS_TRUST => 0,
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
             * CKO_HW_FEATURE, CKO_DOMAIN_PARAMETERS, CKO_OTP_KEY,
             * CKO_VENDOR_DEFINED.
             * Builtin objects cannot be created so they always return
             * this error. Unsupported objects alaso return the same.
             */
            _ => return Err(CKR_TEMPLATE_INCONSISTENT)?,
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
        let mut result = CKR_OK;

        let factory_attrs =
            self.get_object_factory(obj)?.get_data().get_attributes();
        let obj_attrs = obj.get_attributes();

        for ck_attr in template.iter_mut() {
            let valid: bool;

            /* check if this attribute is valid/allowed */
            match factory_attrs.iter().find(|a| a.get_type() == ck_attr.type_) {
                Some(fa) => {
                    if sensitive && fa.is(OAFlags::Sensitive) {
                        ck_attr.ulValueLen = CK_UNAVAILABLE_INFORMATION;
                        if result == CKR_OK {
                            result = CKR_ATTRIBUTE_SENSITIVE;
                        }
                        valid = false;
                    } else {
                        valid = true;
                    }
                }
                None => {
                    /* This attribute is not valid for given object type */
                    ck_attr.ulValueLen = CK_UNAVAILABLE_INFORMATION;
                    if result == CKR_OK {
                        result = CKR_ATTRIBUTE_TYPE_INVALID;
                    }
                    valid = false;
                }
            }

            if !valid {
                /* The attribute value can't be returned, it is either sesntive
                 * or the attribute type is invalid for this object class.
                 * Continue to the next one skipping the code that copies the
                 * values in the template */
                continue;
            }

            match obj_attrs.iter().find(|a| a.get_type() == ck_attr.type_) {
                Some(oa) => {
                    let attr_val = oa.get_value();
                    let attr_len = CK_ULONG::try_from(attr_val.len())?;
                    if ck_attr.pValue.is_null() {
                        ck_attr.ulValueLen = attr_len;
                    } else if ck_attr.ulValueLen == CK_UNAVAILABLE_INFORMATION {
                        if result == CKR_OK {
                            result = CKR_TEMPLATE_INCONSISTENT;
                        }
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
                None => {
                    /* This attribute is not available on given object */
                    ck_attr.ulValueLen = CK_UNAVAILABLE_INFORMATION;
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
        factory.as_key_factory()?.key_derive(template, key)
    }
}

/// The static Data Object factory
static DATA_OBJECT_FACTORY: LazyLock<Box<dyn ObjectFactory>> =
    LazyLock::new(|| Box::new(DataFactory::new()));

/// The static X509 Certificate factory
static X509_CERT_FACTORY: LazyLock<Box<dyn ObjectFactory>> =
    LazyLock::new(|| Box::new(X509Factory::new()));

/// The static Trust Object factory
static TRUST_OBJECT_FACTORY: LazyLock<Box<dyn ObjectFactory>> =
    LazyLock::new(|| Box::new(TrustObject::new()));

/// The static NSS Trust Object factory
#[cfg(feature = "nssdb")]
static NSS_TRUST_OBJECT_FACTORY: LazyLock<Box<dyn ObjectFactory>> =
    LazyLock::new(|| Box::new(NSSTrustObject::new()));

/// The static Profile Object factory
#[cfg(feature = "profiles")]
static PROFILE_FACTORY: LazyLock<Box<dyn ObjectFactory>> =
    LazyLock::new(|| Box::new(ProfileFactory::new()));

/// The static Mechanism Object factory
static MECHANISM_FACTORY: LazyLock<Box<dyn ObjectFactory>> =
    LazyLock::new(|| Box::new(MechanismFactory::new()));

/// Object that holds Mechanisms for Generic Secrets
static GENERIC_SECRET: LazyLock<Box<dyn Mechanism>> = LazyLock::new(|| {
    Box::new(GenericSecretKeyMechanism::new(CKK_GENERIC_SECRET))
});

/// The static Generic Secret factory
pub(crate) static GENERIC_SECRET_FACTORY: LazyLock<Box<dyn ObjectFactory>> =
    LazyLock::new(|| Box::new(GenericSecretKeyFactory::new()));

/// Registers mechanisms and key factories for Data Objects, X509
/// Certificates and Generic Secret Keys
pub fn register(mechs: &mut Mechanisms, ot: &mut ObjectFactories) {
    mechs.add_mechanism(CKM_GENERIC_SECRET_KEY_GEN, &(*GENERIC_SECRET));

    ot.add_factory(ObjectType::new(CKO_DATA, 0), &(*DATA_OBJECT_FACTORY));
    ot.add_factory(
        ObjectType::new(CKO_CERTIFICATE, CKC_X_509),
        &(*X509_CERT_FACTORY),
    );
    ot.add_factory(
        ObjectType::new(CKO_SECRET_KEY, CKK_GENERIC_SECRET),
        &(*GENERIC_SECRET_FACTORY),
    );
    ot.add_factory(ObjectType::new(CKO_TRUST, 0), &(*TRUST_OBJECT_FACTORY));
    #[cfg(feature = "nssdb")]
    ot.add_factory(
        ObjectType::new(CKO_NSS_TRUST, 0),
        &(*NSS_TRUST_OBJECT_FACTORY),
    );
    #[cfg(feature = "profiles")]
    ot.add_factory(ObjectType::new(CKO_PROFILE, 0), &(*PROFILE_FACTORY));
    ot.add_factory(ObjectType::new(CKO_MECHANISM, 0), &(*MECHANISM_FACTORY));
}
