// Copyright 2024 Simo Sorce
// See LICENSE.txt file for terms

use super::*;

use attribute::{from_bytes, from_string, from_ulong};
use interface::*;
use object::{OAFlags, Object, ObjectAttr, ObjectFactory};

/* The CKA_VALIDATION_FLAG used to define the validation is always
 * vendor specific and have no fixed value in the spec.
 * Each CKO_VALIDATION object must define a bit flag that should not
 * conflict with other validation objects (in case multiple validations
 * are achieved for the same token); and that flag is what is then used
 * to mark operations. Applications need to get the flag value after
 * token initialization and use that value thereafter to check against
 * objects and session CKA_VALIDATION_FLAGS attributes. */
pub const KRF_FIPS: CK_ULONG = 1;

#[derive(Debug)]
pub struct ValidationFactory {
    attributes: Vec<ObjectAttr>,
}

impl ValidationFactory {
    fn new() -> ValidationFactory {
        let mut data: ValidationFactory = ValidationFactory {
            attributes: Vec::new(),
        };
        data.attributes.append(&mut data.init_common_object_attrs());
        data.attributes
            .append(&mut data.init_common_storage_attrs());
        data.attributes.push(attr_element!(
                CKA_VALIDATION_TYPE;
                OAFlags::AlwaysRequired | OAFlags::NeverSettable
                | OAFlags::Unchangeable; from_ulong; val 0));
        data.attributes.push(attr_element!(
                CKA_VALIDATION_VERSION;
                OAFlags::AlwaysRequired | OAFlags::NeverSettable
                | OAFlags::Unchangeable; from_bytes; val Vec::new()));
        data.attributes.push(attr_element!(
                CKA_VALIDATION_LEVEL;
                OAFlags::AlwaysRequired | OAFlags::NeverSettable
                | OAFlags::Unchangeable; from_ulong; val 0));
        data.attributes.push(attr_element!(
                CKA_VALIDATION_MODULE_ID;
                OAFlags::AlwaysRequired | OAFlags::NeverSettable
                | OAFlags::Unchangeable; from_string; val String::new()));
        data.attributes.push(attr_element!(
                CKA_VALIDATION_FLAG;
                OAFlags::AlwaysRequired | OAFlags::NeverSettable
                | OAFlags::Unchangeable; from_ulong; val 0));
        data.attributes.push(attr_element!(
                CKA_VALIDATION_AUTHORITY_TYPE;
                OAFlags::AlwaysRequired | OAFlags::NeverSettable
                | OAFlags::Unchangeable; from_ulong; val 0));
        data.attributes.push(attr_element!(
                CKA_VALIDATION_COUNTRY;
                OAFlags::AlwaysRequired | OAFlags::NeverSettable
                | OAFlags::Unchangeable; from_string; val String::new()));
        data.attributes.push(attr_element!(
                CKA_VALIDATION_CERTIFICATE_IDENTIFIER;
                OAFlags::AlwaysRequired | OAFlags::NeverSettable
                | OAFlags::Unchangeable; from_string; val String::new()));
        data.attributes.push(attr_element!(
                CKA_VALIDATION_CERTIFICATE_URI;
                OAFlags::AlwaysRequired | OAFlags::NeverSettable
                | OAFlags::Unchangeable; from_string; val String::new()));
        data.attributes.push(attr_element!(
                CKA_VALIDATION_VENDOR_URI;
                OAFlags::AlwaysRequired | OAFlags::NeverSettable
                | OAFlags::Unchangeable; from_string; val String::new()));
        data.attributes.push(attr_element!(
                CKA_VALIDATION_PROFILE;
                OAFlags::AlwaysRequired | OAFlags::NeverSettable
                | OAFlags::Unchangeable; from_string; val String::new()));
        data
    }
}

impl ObjectFactory for ValidationFactory {
    fn get_attributes(&self) -> &Vec<ObjectAttr> {
        &self.attributes
    }
}

pub static VALIDATION_FACTORY: Lazy<Box<dyn ObjectFactory>> =
    Lazy::new(|| Box::new(ValidationFactory::new()));

pub fn insert_fips_validation(token: &mut Token) -> KResult<()> {
    /* Synthesize a FIPS CKO_VALIDATION object */
    let mut obj = Object::new();
    obj.set_attr(attribute::from_bool(CKA_TOKEN, false))?;
    obj.set_attr(attribute::from_bool(CKA_DESTROYABLE, false))?;
    obj.set_attr(attribute::from_bool(CKA_MODIFIABLE, false))?;
    obj.set_attr(attribute::from_bool(CKA_PRIVATE, false))?;
    obj.set_attr(attribute::from_bool(CKA_SENSITIVE, false))?;
    obj.set_attr(attribute::from_ulong(CKA_CLASS, CKO_VALIDATION))?;
    obj.set_attr(attribute::from_ulong(
        CKA_VALIDATION_TYPE,
        CKV_TYPE_SOFTWARE,
    ))?;
    obj.set_attr(attribute::from_bytes(
        CKA_VALIDATION_VERSION,
        vec![3u8, 0u8],
    ))?;
    obj.set_attr(attribute::from_ulong(CKA_VALIDATION_LEVEL, 1))?;
    /* TODO: This should be generated at build time */
    obj.set_attr(attribute::from_string(
        CKA_VALIDATION_MODULE_ID,
        String::from("Kryoptic FIPS Module - v1"),
    ))?;
    obj.set_attr(attribute::from_ulong(CKA_VALIDATION_FLAG, KRF_FIPS))?;
    obj.set_attr(attribute::from_ulong(
        CKA_VALIDATION_AUTHORITY_TYPE,
        CKV_AUTHORITY_TYPE_NIST_CMVP,
    ))?;

    /* TODO: The following attributes should all be determined at build time */
    obj.set_attr(attribute::from_string(
        CKA_VALIDATION_COUNTRY,
        String::from("US"),
    ))?;
    obj.set_attr(attribute::from_string(
        CKA_VALIDATION_CERTIFICATE_IDENTIFIER,
        String::from("Pending"),
    ))?;
    obj.set_attr(attribute::from_string(
        CKA_VALIDATION_CERTIFICATE_URI,
        String::from(""),
    ))?;
    obj.set_attr(attribute::from_string(
        CKA_VALIDATION_VENDOR_URI,
        String::from("https://github.com/latchset/kryoptic"),
    ))?;
    obj.set_attr(attribute::from_string(
        CKA_VALIDATION_PROFILE,
        String::from(""),
    ))?;

    /* generate a unique id */
    obj.generate_unique();

    /* invalid session handle will prevent it from being removed when
     * session objects are cleared on session closings */
    let _ = token.insert_object(CK_INVALID_HANDLE, obj)?;
    Ok(())
}
