// Copyright 2023-2026 Simo Sorce
// See LICENSE.txt file for terms

use std::fmt::Debug;

use crate::attribute::{Attribute, CkAttrs};
use crate::error::Result;
use crate::mechanism::{Mechanism, Mechanisms};
use crate::misc::zeromem;
use crate::pkcs11::*;
use crate::CSPRNG;

use super::factory::*;
use super::Object;

/// This is a common trait to define factories for objects that
/// are keys, this trait defines attribute common to all key classes.
///
/// [Key objects](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203227)
/// (Version 3.1)

pub trait KeyFactory: ObjectFactory {
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

    fn internal_key_create(
        &self,
        template: &[CK_ATTRIBUTE],
        unacceptable_flags: OAFlags,
        required_flags: OAFlags,
    ) -> Result<Object> {
        let mut obj = self.internal_object_create(
            template,
            unacceptable_flags,
            required_flags,
        )?;
        obj.generate_unique();
        Ok(obj)
    }

    /// Default object creation function
    ///
    /// Uses `internal_key_create()` with appropriate flags.
    fn key_create(&self, template: &[CK_ATTRIBUTE]) -> Result<Object> {
        let mut obj = self.internal_key_create(
            template,
            OAFlags::NeverSettable,
            OAFlags::RequiredOnCreate,
        )?;

        match obj.get_class() {
            CKO_PUBLIC_KEY | CKO_PRIVATE_KEY | CKO_SECRET_KEY => {
                // default key attributes on CreateObject
                obj.set_attr(Attribute::from_bool(CKA_LOCAL, false))?;
            }
            _ => (),
        }

        match obj.get_class() {
            CKO_PRIVATE_KEY | CKO_SECRET_KEY => {
                // default key attributes on CreateObject for PRIVATE/SECRET keys
                obj.set_attr(Attribute::from_bool(
                    CKA_ALWAYS_SENSITIVE,
                    false,
                ))?;
                obj.set_attr(Attribute::from_bool(
                    CKA_NEVER_EXTRACTABLE,
                    false,
                ))?;
            }
            _ => (),
        }
        Ok(obj)
    }

    /// Default key object generation function
    ///
    /// Uses `internal_key_create()` with appropriate flags.
    ///
    /// Marks the object for zeroization.
    fn key_generate(&self, template: &[CK_ATTRIBUTE]) -> Result<Object> {
        let mut key = self.internal_key_create(
            template,
            OAFlags::SettableOnlyOnCreate | OAFlags::NeverSettable,
            OAFlags::RequiredOnGenerate,
        )?;
        key.set_zeroize();
        Ok(key)
    }

    /// Default key object unwrapping function
    ///
    /// Uses `internal_key_create()` with appropriate flags.
    fn key_unwrap(&self, template: &[CK_ATTRIBUTE]) -> Result<Object> {
        self.internal_key_create(
            template,
            OAFlags::SettableOnlyOnCreate | OAFlags::NeverSettable,
            OAFlags::AlwaysRequired,
        )
    }

    /// The internal key object derivation function
    ///
    /// Uses `internal_key_create()` with appropriate flags.
    ///
    /// Sets appropate default values for [CKA_LOCAL],
    /// [CKA_ALWAYS_SENSITIVE], [CKA_NEVER_EXTRACTABLE] as
    /// required by spec.
    fn internal_key_derive(
        &self,
        template: &[CK_ATTRIBUTE],
        origin: &Object,
    ) -> Result<Object> {
        /* FIXME: handle CKA_DERIVE_TEMPLATE */

        let mut obj = self.internal_key_create(
            template,
            OAFlags::SettableOnlyOnCreate | OAFlags::NeverSettable,
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

    /// Default key object derivation function
    ///
    /// Uses `internal_key_derive()`
    fn key_derive(
        &self,
        template: &[CK_ATTRIBUTE],
        origin: &Object,
    ) -> Result<Object> {
        self.internal_key_derive(template, origin)
    }

    /// Helper to allow serialization to export key material.
    /// A key type factory should implement this function only if a
    /// standardized serialization format specified in PKCS#11 exists.
    fn export_for_wrapping(&self, _obj: &Object) -> Result<Vec<u8>> {
        return Err(CKR_FUNCTION_NOT_SUPPORTED)?;
    }

    /// Helper to allow deserialization of a data packet wrapped by
    /// another mechanism. Useful only for key type factories for which a
    /// standard serialization format is specified.
    fn import_from_wrapped(
        &self,
        mut _data: Vec<u8>,
        _template: &[CK_ATTRIBUTE],
    ) -> Result<Object> {
        return Err(CKR_FUNCTION_NOT_SUPPORTED)?;
    }
}

/// This is a common trait to define factories for key objects of class
/// CKO_PUBLIC_KEY
///
/// [Public key objects](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203230)
/// (Version 3.1)

#[allow(dead_code)]
pub trait PubKeyFactory: KeyFactory {
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

    fn pub_from_private(
        &self,
        _obj: &Object,
        _template: CkAttrs,
    ) -> Result<Object> {
        return Err(CKR_GENERAL_ERROR)?;
    }
}

/// This is a common trait to define factories for key objects of class
/// CKO_PRIVATE_KEY
///
/// [Private key objects](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203231)
/// (Version 3.1)

#[allow(dead_code)]
pub trait PrivKeyFactory: KeyFactory {
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
}

/// This is a common trait to define factories for key objects of class
/// CKO_SECRET_KEY
///
/// [Secret key objects](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203232)
/// (Version 3.1)

pub trait SecretKeyFactory: KeyFactory {
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

    fn default_export_for_wrapping(&self, obj: &Object) -> Result<Vec<u8>> {
        if !obj.is_extractable() {
            return Err(CKR_KEY_UNEXTRACTABLE)?;
        }
        match obj.get_attr_as_bytes(CKA_VALUE) {
            Ok(v) => Ok(v.clone()),
            Err(_) => return Err(CKR_DEVICE_ERROR)?,
        }
    }

    fn default_import_from_wrapped(
        &self,
        mut data: Vec<u8>,
        template: &[CK_ATTRIBUTE],
    ) -> Result<Object> {
        let mut obj = match self.key_unwrap(template) {
            Ok(o) => o,
            Err(e) => {
                /* ensure we do not leave around sensitive data on error */
                zeromem(data.as_mut_slice());
                return Err(e);
            }
        };
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
        obj.ensure_ulong(CKA_VALUE_LEN, CK_ULONG::try_from(len)?)
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

/// This is a specialized factory for objects of class CKO_SECRET_KEY
/// and CKA_KEY_TYPE of value CKK_GENERIC_SECRET
///
/// [Generic secret key](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203468)
/// (Version 3.1)

#[derive(Debug)]
pub struct GenericSecretKeyFactory {
    data: ObjectFactoryData,
    keysize: usize,
}

impl GenericSecretKeyFactory {
    /// Initializes a new GenericSecretKeyFactory object
    pub fn new() -> GenericSecretKeyFactory {
        let mut factory: GenericSecretKeyFactory = GenericSecretKeyFactory {
            data: ObjectFactoryData::new(CKO_SECRET_KEY),
            keysize: 0,
        };

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
        let mut obj = self.key_create(template)?;
        let len = self.get_key_buffer_len(&obj)?;
        if len == 0 {
            return Err(CKR_ATTRIBUTE_VALUE_INVALID)?;
        }
        if self.keysize != 0 && len != self.keysize {
            return Err(CKR_ATTRIBUTE_VALUE_INVALID)?;
        }
        obj.ensure_ulong(CKA_VALUE_LEN, CK_ULONG::try_from(len)?)?;

        Ok(obj)
    }

    fn get_data(&self) -> &ObjectFactoryData {
        &self.data
    }
    fn get_data_mut(&mut self) -> &mut ObjectFactoryData {
        &mut self.data
    }

    /// Returns a cast to the KeyFactory trait for this object
    fn as_key_factory(&self) -> Result<&dyn KeyFactory> {
        Ok(self)
    }
    /// Returns a cast to the SecretKeyFactory trait for this object
    fn as_secret_key_factory(&self) -> Result<&dyn SecretKeyFactory> {
        Ok(self)
    }
}

impl KeyFactory for GenericSecretKeyFactory {
    fn export_for_wrapping(&self, key: &Object) -> Result<Vec<u8>> {
        SecretKeyFactory::default_export_for_wrapping(self, key)
    }

    fn import_from_wrapped(
        &self,
        data: Vec<u8>,
        template: &[CK_ATTRIBUTE],
    ) -> Result<Object> {
        SecretKeyFactory::default_import_from_wrapped(self, data, template)
    }
}

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
        let mut key = GENERIC_SECRET_FACTORY
            .as_key_factory()?
            .key_generate(template)?;
        key.ensure_ulong(CKA_CLASS, CKO_SECRET_KEY)
            .map_err(|_| CKR_TEMPLATE_INCONSISTENT)?;
        key.ensure_ulong(CKA_KEY_TYPE, self.keytype())
            .map_err(|_| CKR_TEMPLATE_INCONSISTENT)?;

        default_secret_key_generate(&mut key)?;
        default_key_attributes(&mut key, mech.mechanism)?;
        Ok(key)
    }
}
