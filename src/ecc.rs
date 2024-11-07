// Copyright 2023 - 2024 Simo Sorce, Jakub Jelen
// See LICENSE.txt file for terms

use std::fmt::Debug;

use crate::attribute::Attribute;
use crate::ecc_misc::*;
use crate::error::Result;
use crate::interface::*;
use crate::kasn1::PrivateKeyInfo;
use crate::mechanism::*;
use crate::object::*;
use crate::ossl::ecc::EccOperation;
use crate::{attr_element, bytes_attr_not_empty};

use asn1;
use once_cell::sync::Lazy;

pub const MIN_EC_SIZE_BITS: usize = 256;
pub const MAX_EC_SIZE_BITS: usize = 521;

// ASN.1 encoding of the OID
const OID_SECP256R1: asn1::ObjectIdentifier =
    asn1::oid!(1, 2, 840, 10045, 3, 1, 7);
const OID_SECP384R1: asn1::ObjectIdentifier = asn1::oid!(1, 3, 132, 0, 34);
const OID_SECP521R1: asn1::ObjectIdentifier = asn1::oid!(1, 3, 132, 0, 35);

// ASN.1 encoding of the curve name
const STRING_SECP256R1: &[u8] = &[
    0x13, 0x0a, 0x70, 0x72, 0x69, 0x6d, 0x65, 0x32, 0x35, 0x36, 0x76, 0x31,
];
const STRING_SECP384R1: &[u8] = &[
    0x13, 0x09, 0x73, 0x65, 0x63, 0x70, 0x33, 0x38, 0x34, 0x72, 0x31,
];
const STRING_SECP521R1: &[u8] = &[
    0x13, 0x09, 0x73, 0x65, 0x63, 0x70, 0x35, 0x32, 0x31, 0x72, 0x31,
];

pub const NAME_SECP256R1: &str = "prime256v1";
pub const NAME_SECP384R1: &str = "secp384r1";
pub const NAME_SECP521R1: &str = "secp521r1";

const BITS_SECP256R1: usize = 256;
const BITS_SECP384R1: usize = 384;
const BITS_SECP521R1: usize = 521;

pub fn oid_to_curve_name(oid: asn1::ObjectIdentifier) -> Result<&'static str> {
    match oid {
        OID_SECP256R1 => Ok(NAME_SECP256R1),
        OID_SECP384R1 => Ok(NAME_SECP384R1),
        OID_SECP521R1 => Ok(NAME_SECP521R1),
        _ => Err(CKR_GENERAL_ERROR)?,
    }
}

#[cfg(test)]
pub fn curve_name_to_ec_params(name: &'static str) -> Result<&'static [u8]> {
    match name {
        NAME_SECP256R1 => Ok(STRING_SECP256R1),
        NAME_SECP384R1 => Ok(STRING_SECP384R1),
        NAME_SECP521R1 => Ok(STRING_SECP521R1),
        _ => Err(CKR_GENERAL_ERROR)?,
    }
}

#[cfg(test)]
pub fn name_to_bits(name: &'static str) -> Result<usize> {
    match name {
        NAME_SECP256R1 => Ok(BITS_SECP256R1),
        NAME_SECP384R1 => Ok(BITS_SECP384R1),
        NAME_SECP521R1 => Ok(BITS_SECP521R1),
        _ => Err(CKR_GENERAL_ERROR)?,
    }
}

pub fn oid_to_bits(oid: asn1::ObjectIdentifier) -> Result<usize> {
    match oid {
        OID_SECP256R1 => Ok(BITS_SECP256R1),
        OID_SECP384R1 => Ok(BITS_SECP384R1),
        OID_SECP521R1 => Ok(BITS_SECP521R1),
        _ => Err(CKR_GENERAL_ERROR)?,
    }
}

pub fn curve_name_to_bits(name: asn1::PrintableString) -> Result<usize> {
    let asn1_name = match asn1::write_single(&name) {
        Ok(r) => r,
        Err(_) => return Err(CKR_GENERAL_ERROR)?,
    };
    match asn1_name.as_slice() {
        STRING_SECP256R1 => Ok(BITS_SECP256R1),
        STRING_SECP384R1 => Ok(BITS_SECP384R1),
        STRING_SECP521R1 => Ok(BITS_SECP521R1),
        _ => Err(CKR_GENERAL_ERROR)?,
    }
}

pub fn curve_name_to_oid(
    name: asn1::PrintableString,
) -> Result<asn1::ObjectIdentifier> {
    let asn1_name = match asn1::write_single(&name) {
        Ok(r) => r,
        Err(_) => return Err(CKR_GENERAL_ERROR)?,
    };
    Ok(match asn1_name.as_slice() {
        STRING_SECP256R1 => OID_SECP256R1,
        STRING_SECP384R1 => OID_SECP384R1,
        STRING_SECP521R1 => OID_SECP521R1,
        _ => return Err(CKR_GENERAL_ERROR)?,
    })
}

#[cfg(feature = "fips")]
pub fn ec_key_curve_size(key: &Object) -> Result<usize> {
    let x = match key.get_attr_as_bytes(CKA_EC_PARAMS) {
        Ok(b) => b,
        Err(_) => return Err(CKR_GENERAL_ERROR)?,
    };
    match asn1::parse_single::<ECParameters>(x) {
        Ok(a) => match a {
            ECParameters::OId(o) => oid_to_bits(o),
            ECParameters::CurveName(c) => curve_name_to_bits(c),
            _ => return Err(CKR_GENERAL_ERROR)?,
        },
        Err(_) => return Err(CKR_GENERAL_ERROR)?,
    }
}

#[derive(Debug)]
pub struct ECCPubFactory {
    attributes: Vec<ObjectAttr>,
}

impl ECCPubFactory {
    pub fn new() -> ECCPubFactory {
        let mut data: ECCPubFactory = ECCPubFactory {
            attributes: Vec::new(),
        };
        data.attributes.append(&mut data.init_common_object_attrs());
        data.attributes
            .append(&mut data.init_common_storage_attrs());
        data.attributes.append(&mut data.init_common_key_attrs());
        data.attributes
            .append(&mut data.init_common_public_key_attrs());
        data.attributes.push(attr_element!(CKA_EC_PARAMS; OAFlags::AlwaysRequired | OAFlags::Unchangeable; Attribute::from_bytes; val Vec::new()));
        data.attributes.push(attr_element!(CKA_EC_POINT; OAFlags::RequiredOnCreate | OAFlags::SettableOnlyOnCreate | OAFlags::Unchangeable; Attribute::from_bytes; val Vec::new()));
        data
    }
}

impl ObjectFactory for ECCPubFactory {
    fn create(&self, template: &[CK_ATTRIBUTE]) -> Result<Object> {
        let obj = self.default_object_create(template)?;

        bytes_attr_not_empty!(obj; CKA_EC_PARAMS);
        bytes_attr_not_empty!(obj; CKA_EC_POINT);

        Ok(obj)
    }

    fn get_attributes(&self) -> &Vec<ObjectAttr> {
        &self.attributes
    }
}

impl CommonKeyFactory for ECCPubFactory {}

impl PubKeyFactory for ECCPubFactory {}

#[derive(Debug)]
pub struct ECCPrivFactory {
    attributes: Vec<ObjectAttr>,
}

impl ECCPrivFactory {
    pub fn new() -> ECCPrivFactory {
        let mut data: ECCPrivFactory = ECCPrivFactory {
            attributes: Vec::new(),
        };
        data.attributes.append(&mut data.init_common_object_attrs());
        data.attributes
            .append(&mut data.init_common_storage_attrs());
        data.attributes.append(&mut data.init_common_key_attrs());
        data.attributes
            .append(&mut data.init_common_private_key_attrs());
        data.attributes.push(attr_element!(
            CKA_EC_PARAMS; OAFlags::RequiredOnCreate | OAFlags::Unchangeable;
            Attribute::from_bytes; val Vec::new()));
        data.attributes.push(attr_element!(
            CKA_VALUE; OAFlags::Sensitive | OAFlags::RequiredOnCreate
            | OAFlags::SettableOnlyOnCreate | OAFlags::Unchangeable;
            Attribute::from_bytes; val Vec::new()));

        /* default to private */
        let private = attr_element!(
            CKA_PRIVATE; OAFlags::Defval | OAFlags::ChangeOnCopy;
            Attribute::from_bool; val true);
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
}

impl ObjectFactory for ECCPrivFactory {
    fn create(&self, template: &[CK_ATTRIBUTE]) -> Result<Object> {
        let mut obj = self.default_object_create(template)?;

        ec_key_check_import(&mut obj)?;

        Ok(obj)
    }

    fn get_attributes(&self) -> &Vec<ObjectAttr> {
        &self.attributes
    }

    fn export_for_wrapping(&self, key: &Object) -> Result<Vec<u8>> {
        PrivKeyFactory::export_for_wrapping(self, key)
    }

    fn import_from_wrapped(
        &self,
        data: Vec<u8>,
        template: &[CK_ATTRIBUTE],
    ) -> Result<Object> {
        PrivKeyFactory::import_from_wrapped(self, data, template)
    }
}

fn get_oid_from_obj(key: &Object) -> Result<asn1::ObjectIdentifier> {
    let x = match key.get_attr_as_bytes(CKA_EC_PARAMS) {
        Ok(b) => b,
        Err(_) => return Err(CKR_GENERAL_ERROR)?,
    };
    match asn1::parse_single::<ECParameters>(x) {
        Ok(a) => match a {
            ECParameters::OId(o) => Ok(o),
            ECParameters::CurveName(c) => curve_name_to_oid(c),
            _ => return Err(CKR_GENERAL_ERROR)?,
        },
        Err(_) => return Err(CKR_GENERAL_ERROR)?,
    }
}

impl CommonKeyFactory for ECCPrivFactory {}

impl PrivKeyFactory for ECCPrivFactory {
    fn export_for_wrapping(&self, key: &Object) -> Result<Vec<u8>> {
        key.check_key_ops(CKO_PRIVATE_KEY, CKK_EC, CKA_EXTRACTABLE)?;

        let oid = match get_oid_from_obj(key) {
            Ok(o) => o,
            _ => return Err(CKR_GENERAL_ERROR)?,
        };
        let ecpkey_asn1 = match asn1::write_single(&ECPrivateKey::new_owned(
            key.get_attr_as_bytes(CKA_VALUE)?,
        )?) {
            Ok(p) => p,
            _ => return Err(CKR_GENERAL_ERROR)?,
        };
        let pkeyinfo = PrivateKeyInfo::new(&ecpkey_asn1.as_slice(), oid)?;

        match asn1::write_single(&pkeyinfo) {
            Ok(x) => Ok(x),
            Err(_) => Err(CKR_GENERAL_ERROR)?,
        }
    }

    fn import_from_wrapped(
        &self,
        data: Vec<u8>,
        template: &[CK_ATTRIBUTE],
    ) -> Result<Object> {
        let mut key = self.default_object_unwrap(template)?;

        if !key.check_or_set_attr(Attribute::from_ulong(
            CKA_CLASS,
            CKO_PRIVATE_KEY,
        ))? {
            return Err(CKR_TEMPLATE_INCONSISTENT)?;
        }
        if !key
            .check_or_set_attr(Attribute::from_ulong(CKA_KEY_TYPE, CKK_EC))?
        {
            return Err(CKR_TEMPLATE_INCONSISTENT)?;
        }

        let (tlv, extra) = match asn1::strip_tlv(&data) {
            Ok(x) => x,
            Err(_) => return Err(CKR_WRAPPED_KEY_INVALID)?,
        };
        /* Some Key Wrapping algorithms may 0 pad to match block size */
        if !extra.iter().all(|b| *b == 0) {
            return Err(CKR_WRAPPED_KEY_INVALID)?;
        }
        let pkeyinfo = match tlv.parse::<PrivateKeyInfo>() {
            Ok(k) => k,
            Err(_) => return Err(CKR_WRAPPED_KEY_INVALID)?,
        };
        /* filter out unknown OIDs */
        let oid = match pkeyinfo.get_oid() {
            &OID_SECP521R1 => OID_SECP256R1,
            &OID_SECP384R1 => OID_SECP384R1,
            &OID_SECP256R1 => OID_SECP521R1,
            _ => return Err(CKR_WRAPPED_KEY_INVALID)?,
        };
        let oid_encoded = match asn1::write_single(&oid) {
            Ok(b) => b,
            Err(_) => return Err(CKR_WRAPPED_KEY_INVALID)?,
        };

        if !key.check_or_set_attr(Attribute::from_bytes(
            CKA_EC_PARAMS,
            oid_encoded.to_vec(),
        ))? {
            return Err(CKR_TEMPLATE_INCONSISTENT)?;
        }

        let ecpkey = match asn1::parse_single::<ECPrivateKey>(
            pkeyinfo.get_private_key(),
        ) {
            Ok(k) => k,
            Err(_) => return Err(CKR_WRAPPED_KEY_INVALID)?,
        };

        if !key.check_or_set_attr(Attribute::from_bytes(
            CKA_VALUE,
            ecpkey.private_key.as_bytes().to_vec(),
        ))? {
            return Err(CKR_TEMPLATE_INCONSISTENT)?;
        }

        Ok(key)
    }
}

static PUBLIC_KEY_FACTORY: Lazy<Box<dyn ObjectFactory>> =
    Lazy::new(|| Box::new(ECCPubFactory::new()));

static PRIVATE_KEY_FACTORY: Lazy<Box<dyn ObjectFactory>> =
    Lazy::new(|| Box::new(ECCPrivFactory::new()));

#[derive(Debug)]
pub struct EccMechanism {
    info: CK_MECHANISM_INFO,
}

impl EccMechanism {
    pub fn new(min: CK_ULONG, max: CK_ULONG, flags: CK_FLAGS) -> EccMechanism {
        EccMechanism {
            info: CK_MECHANISM_INFO {
                ulMinKeySize: min,
                ulMaxKeySize: max,
                flags: flags,
            },
        }
    }
}

impl Mechanism for EccMechanism {
    fn info(&self) -> &CK_MECHANISM_INFO {
        &self.info
    }

    fn sign_new(
        &self,
        mech: &CK_MECHANISM,
        key: &Object,
    ) -> Result<Box<dyn Sign>> {
        if self.info.flags & CKF_SIGN != CKF_SIGN {
            return Err(CKR_MECHANISM_INVALID)?;
        }
        match key.check_key_ops(CKO_PRIVATE_KEY, CKK_EC, CKA_SIGN) {
            Ok(_) => (),
            Err(e) => return Err(e),
        }
        Ok(Box::new(EccOperation::sign_new(mech, key, &self.info)?))
    }
    fn verify_new(
        &self,
        mech: &CK_MECHANISM,
        key: &Object,
    ) -> Result<Box<dyn Verify>> {
        if self.info.flags & CKF_VERIFY != CKF_VERIFY {
            return Err(CKR_MECHANISM_INVALID)?;
        }
        match key.check_key_ops(CKO_PUBLIC_KEY, CKK_EC, CKA_VERIFY) {
            Ok(_) => (),
            Err(e) => return Err(e),
        }
        Ok(Box::new(EccOperation::verify_new(mech, key, &self.info)?))
    }

    fn generate_keypair(
        &self,
        mech: &CK_MECHANISM,
        pubkey_template: &[CK_ATTRIBUTE],
        prikey_template: &[CK_ATTRIBUTE],
    ) -> Result<(Object, Object)> {
        let mut pubkey =
            PUBLIC_KEY_FACTORY.default_object_generate(pubkey_template)?;
        if !pubkey.check_or_set_attr(Attribute::from_ulong(
            CKA_CLASS,
            CKO_PUBLIC_KEY,
        ))? {
            return Err(CKR_TEMPLATE_INCONSISTENT)?;
        }
        if !pubkey
            .check_or_set_attr(Attribute::from_ulong(CKA_KEY_TYPE, CKK_EC))?
        {
            return Err(CKR_TEMPLATE_INCONSISTENT)?;
        }

        let mut privkey =
            PRIVATE_KEY_FACTORY.default_object_generate(prikey_template)?;
        if !privkey.check_or_set_attr(Attribute::from_ulong(
            CKA_CLASS,
            CKO_PRIVATE_KEY,
        ))? {
            return Err(CKR_TEMPLATE_INCONSISTENT)?;
        }
        if !privkey
            .check_or_set_attr(Attribute::from_ulong(CKA_KEY_TYPE, CKK_EC))?
        {
            return Err(CKR_TEMPLATE_INCONSISTENT)?;
        }

        let ec_params = match pubkey.get_attr_as_bytes(CKA_EC_PARAMS) {
            Ok(a) => a.clone(),
            Err(_) => {
                return Err(CKR_ATTRIBUTE_VALUE_INVALID)?;
            }
        };
        if !privkey.check_or_set_attr(Attribute::from_bytes(
            CKA_EC_PARAMS,
            ec_params,
        ))? {
            return Err(CKR_TEMPLATE_INCONSISTENT)?;
        }

        EccOperation::generate_keypair(&mut pubkey, &mut privkey)?;
        default_key_attributes(&mut privkey, mech.mechanism)?;
        default_key_attributes(&mut pubkey, mech.mechanism)?;

        Ok((pubkey, privkey))
    }
}

pub fn register(mechs: &mut Mechanisms, ot: &mut ObjectFactories) {
    EccOperation::register_mechanisms(mechs);

    ot.add_factory(
        ObjectType::new(CKO_PUBLIC_KEY, CKK_EC),
        &PUBLIC_KEY_FACTORY,
    );
    ot.add_factory(
        ObjectType::new(CKO_PRIVATE_KEY, CKK_EC),
        &PRIVATE_KEY_FACTORY,
    );
}
