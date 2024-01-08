// Copyright 2023 Simo Sorce
// See LICENSE.txt file for terms

use super::attribute;
use super::error;
use super::interface;
use super::object;
use super::{attr_element, bytes_attr_not_empty, err_rv};

use attribute::{from_bool, from_bytes, from_ulong};
use error::{KError, KResult};
use interface::*;
use object::{
    CommonKeyTemplate, OAFlags, Object, ObjectAttr, ObjectTemplate,
    ObjectTemplates, ObjectType, PrivKeyTemplate, PubKeyTemplate,
};

use once_cell::sync::Lazy;
use std::fmt::Debug;

pub const MIN_RSA_SIZE_BITS: usize = 1024;
pub const MAX_RSA_SIZE_BITS: usize = 16536;
pub const MIN_RSA_SIZE_BYTES: usize = MIN_RSA_SIZE_BITS / 8;

#[derive(Debug)]
pub struct RSAPubTemplate {
    attributes: Vec<ObjectAttr>,
}

impl RSAPubTemplate {
    pub fn new() -> RSAPubTemplate {
        let mut data: RSAPubTemplate = RSAPubTemplate {
            attributes: Vec::new(),
        };
        data.attributes.append(&mut data.init_common_object_attrs());
        data.attributes
            .append(&mut data.init_common_storage_attrs());
        data.attributes.append(&mut data.init_common_key_attrs());
        data.attributes
            .append(&mut data.init_common_public_key_attrs());
        data.attributes.push(attr_element!(CKA_MODULUS; OAFlags::RequiredOnCreate | OAFlags::Unchangeable; from_bytes; val Vec::new()));
        data.attributes.push(attr_element!(CKA_MODULUS_BITS; OAFlags::RequiredOnGenerate | OAFlags::Unchangeable; from_ulong; val 0));
        data.attributes.push(attr_element!(CKA_PUBLIC_EXPONENT; OAFlags::RequiredOnCreate | OAFlags::Unchangeable; from_bytes; val Vec::new()));
        data
    }
}

impl ObjectTemplate for RSAPubTemplate {
    fn create(&self, template: &[CK_ATTRIBUTE]) -> KResult<Object> {
        let obj = self.default_object_create(template, false)?;

        let modulus = match obj.get_attr_as_bytes(CKA_MODULUS) {
            Ok(m) => m,
            Err(_) => return err_rv!(CKR_TEMPLATE_INCOMPLETE),
        };
        match obj.get_attr_as_ulong(CKA_MODULUS_BITS) {
            Ok(_) => return err_rv!(CKR_ATTRIBUTE_VALUE_INVALID),
            Err(e) => match e {
                KError::NotFound(_) => (),
                _ => return Err(e),
            },
        }
        if modulus.len() < MIN_RSA_SIZE_BYTES {
            return err_rv!(CKR_ATTRIBUTE_VALUE_INVALID);
        }
        bytes_attr_not_empty!(obj; CKA_PUBLIC_EXPONENT);

        Ok(obj)
    }

    fn get_attributes(&self) -> &Vec<ObjectAttr> {
        &self.attributes
    }
}

impl CommonKeyTemplate for RSAPubTemplate {
    fn get_attributes(&self) -> &Vec<ObjectAttr> {
        &self.attributes
    }
}

impl PubKeyTemplate for RSAPubTemplate {
    fn get_attributes(&self) -> &Vec<ObjectAttr> {
        &self.attributes
    }
}

#[derive(Debug)]
pub struct RSAPrivTemplate {
    attributes: Vec<ObjectAttr>,
}

impl RSAPrivTemplate {
    pub fn new() -> RSAPrivTemplate {
        let mut data: RSAPrivTemplate = RSAPrivTemplate {
            attributes: Vec::new(),
        };
        data.attributes.append(&mut data.init_common_object_attrs());
        data.attributes
            .append(&mut data.init_common_storage_attrs());
        data.attributes.append(&mut data.init_common_key_attrs());
        data.attributes
            .append(&mut data.init_common_private_key_attrs());
        data.attributes.push(attr_element!(CKA_MODULUS; OAFlags::Required | OAFlags::Unchangeable; from_bytes; val Vec::new()));
        data.attributes.push(attr_element!(CKA_PUBLIC_EXPONENT; OAFlags::Required | OAFlags::Unchangeable; from_bytes; val Vec::new()));
        data.attributes.push(attr_element!(CKA_PRIVATE_EXPONENT; OAFlags::Sensitive | OAFlags::Required | OAFlags::Unchangeable; from_bytes; val Vec::new()));
        data.attributes.push(attr_element!(CKA_PRIME_1; OAFlags::Sensitive | OAFlags::Unchangeable; from_bytes; val Vec::new()));
        data.attributes.push(attr_element!(CKA_PRIME_2; OAFlags::Sensitive | OAFlags::Unchangeable; from_bytes; val Vec::new()));
        data.attributes.push(attr_element!(CKA_EXPONENT_1; OAFlags::Sensitive | OAFlags::Unchangeable; from_bytes; val Vec::new()));
        data.attributes.push(attr_element!(CKA_EXPONENT_2; OAFlags::Sensitive | OAFlags::Unchangeable; from_bytes; val Vec::new()));
        data.attributes.push(attr_element!(CKA_COEFFICIENT; OAFlags::Sensitive | OAFlags::Unchangeable; from_bytes; val Vec::new()));

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
}

impl ObjectTemplate for RSAPrivTemplate {
    fn create(&self, template: &[CK_ATTRIBUTE]) -> KResult<Object> {
        let mut obj = self.default_object_create(template, false)?;

        rsa_import(&mut obj)?;

        Ok(obj)
    }

    fn get_attributes(&self) -> &Vec<ObjectAttr> {
        &self.attributes
    }
}

impl CommonKeyTemplate for RSAPrivTemplate {
    fn get_attributes(&self) -> &Vec<ObjectAttr> {
        &self.attributes
    }
}

impl PrivKeyTemplate for RSAPrivTemplate {
    fn get_attributes(&self) -> &Vec<ObjectAttr> {
        &self.attributes
    }
}

static PUBLIC_KEY_TEMPLATE: Lazy<Box<dyn ObjectTemplate>> =
    Lazy::new(|| Box::new(RSAPubTemplate::new()));

static PRIVATE_KEY_TEMPLATE: Lazy<Box<dyn ObjectTemplate>> =
    Lazy::new(|| Box::new(RSAPrivTemplate::new()));

fn check_key_object(key: &Object, public: bool, op: CK_ULONG) -> KResult<()> {
    match key.get_attr_as_ulong(CKA_CLASS)? {
        CKO_PUBLIC_KEY => {
            if !public {
                return err_rv!(CKR_KEY_TYPE_INCONSISTENT);
            }
        }
        CKO_PRIVATE_KEY => {
            if public {
                return err_rv!(CKR_KEY_TYPE_INCONSISTENT);
            }
        }
        _ => return err_rv!(CKR_KEY_TYPE_INCONSISTENT),
    }
    match key.get_attr_as_ulong(CKA_KEY_TYPE)? {
        CKK_RSA => (),
        _ => return err_rv!(CKR_KEY_TYPE_INCONSISTENT),
    }
    match key.get_attr_as_bool(op) {
        Ok(avail) => {
            if !avail {
                return err_rv!(CKR_KEY_FUNCTION_NOT_PERMITTED);
            }
        }
        Err(_) => return err_rv!(CKR_KEY_FUNCTION_NOT_PERMITTED),
    }
    Ok(())
}

#[derive(Debug)]
struct RsaPKCSMechanism {
    info: CK_MECHANISM_INFO,
}

impl Mechanism for RsaPKCSMechanism {
    fn info(&self) -> &CK_MECHANISM_INFO {
        &self.info
    }

    fn encryption_new(
        &self,
        mech: &CK_MECHANISM,
        key: &Object,
    ) -> KResult<Box<dyn Encryption>> {
        if self.info.flags & CKF_ENCRYPT != CKF_ENCRYPT {
            return err_rv!(CKR_MECHANISM_INVALID);
        }
        match check_key_object(key, true, CKA_ENCRYPT) {
            Ok(_) => (),
            Err(e) => return Err(e),
        }
        Ok(Box::new(RsaPKCSOperation::encrypt_new(
            mech, key, &self.info,
        )?))
    }

    fn decryption_new(
        &self,
        mech: &CK_MECHANISM,
        key: &Object,
    ) -> KResult<Box<dyn Decryption>> {
        if self.info.flags & CKF_DECRYPT != CKF_DECRYPT {
            return err_rv!(CKR_MECHANISM_INVALID);
        }
        match check_key_object(key, false, CKA_DECRYPT) {
            Ok(_) => (),
            Err(e) => return Err(e),
        }
        Ok(Box::new(RsaPKCSOperation::decrypt_new(
            mech, key, &self.info,
        )?))
    }
    fn sign_new(
        &self,
        mech: &CK_MECHANISM,
        key: &Object,
    ) -> KResult<Box<dyn Sign>> {
        if self.info.flags & CKF_SIGN != CKF_SIGN {
            return err_rv!(CKR_MECHANISM_INVALID);
        }
        match check_key_object(key, false, CKA_SIGN) {
            Ok(_) => (),
            Err(e) => return Err(e),
        }
        Ok(Box::new(RsaPKCSOperation::sign_new(mech, key, &self.info)?))
    }
    fn verify_new(
        &self,
        mech: &CK_MECHANISM,
        key: &Object,
    ) -> KResult<Box<dyn Verify>> {
        if self.info.flags & CKF_VERIFY != CKF_VERIFY {
            return err_rv!(CKR_MECHANISM_INVALID);
        }
        match check_key_object(key, true, CKA_VERIFY) {
            Ok(_) => (),
            Err(e) => return Err(e),
        }
        Ok(Box::new(RsaPKCSOperation::verify_new(
            mech, key, &self.info,
        )?))
    }

    fn generate_keypair(
        &self,
        rng: &mut rng::RNG,
        _mech: &CK_MECHANISM,
        pubkey_template: &[CK_ATTRIBUTE],
        prikey_template: &[CK_ATTRIBUTE],
    ) -> KResult<(Object, Object)> {
        let mut pubkey =
            PUBLIC_KEY_TEMPLATE.default_object_create(pubkey_template, true)?;
        if !pubkey.check_or_set_attr(attribute::from_ulong(
            CKA_CLASS,
            CKO_PUBLIC_KEY,
        ))? {
            return err_rv!(CKR_TEMPLATE_INCONSISTENT);
        }
        if !pubkey
            .check_or_set_attr(attribute::from_ulong(CKA_KEY_TYPE, CKK_RSA))?
        {
            return err_rv!(CKR_TEMPLATE_INCONSISTENT);
        }

        let bits = pubkey.get_attr_as_ulong(CKA_MODULUS_BITS)? as usize;
        if bits < MIN_RSA_SIZE_BITS || bits > MAX_RSA_SIZE_BITS {
            return err_rv!(CKR_ATTRIBUTE_VALUE_INVALID);
        }
        let exponent: Vec<u8> = match pubkey.get_attr(CKA_PUBLIC_EXPONENT) {
            Some(a) => a.get_value().clone(),
            None => {
                pubkey.set_attr(attribute::from_bytes(
                    CKA_PUBLIC_EXPONENT,
                    vec![0x01, 0x00, 0x01],
                ))?;
                pubkey.get_attr_as_bytes(CKA_PUBLIC_EXPONENT)?.clone()
            }
        };

        let mut privkey = PRIVATE_KEY_TEMPLATE
            .default_object_create(prikey_template, true)?;
        if !privkey.check_or_set_attr(attribute::from_ulong(
            CKA_CLASS,
            CKO_PUBLIC_KEY,
        ))? {
            return err_rv!(CKR_TEMPLATE_INCONSISTENT);
        }
        if !privkey
            .check_or_set_attr(attribute::from_ulong(CKA_KEY_TYPE, CKK_RSA))?
        {
            return err_rv!(CKR_TEMPLATE_INCONSISTENT);
        }

        RsaPKCSOperation::generate_keypair(
            rng,
            exponent,
            bits,
            &mut pubkey,
            &mut privkey,
        )?;

        Ok((pubkey, privkey))
    }
}

pub fn register(mechs: &mut Mechanisms, ot: &mut ObjectTemplates) {
    mechs.add_mechanism(
        CKM_RSA_PKCS,
        Box::new(RsaPKCSMechanism {
            info: CK_MECHANISM_INFO {
                ulMinKeySize: MIN_RSA_SIZE_BITS as CK_ULONG,
                ulMaxKeySize: MAX_RSA_SIZE_BITS as CK_ULONG,
                flags: CKF_ENCRYPT | CKF_DECRYPT | CKF_SIGN | CKF_VERIFY,
            },
        }),
    );
    mechs.add_mechanism(
        CKM_SHA1_RSA_PKCS,
        Box::new(RsaPKCSMechanism {
            info: CK_MECHANISM_INFO {
                ulMinKeySize: MIN_RSA_SIZE_BITS as CK_ULONG,
                ulMaxKeySize: MAX_RSA_SIZE_BITS as CK_ULONG,
                flags: CKF_SIGN | CKF_VERIFY,
            },
        }),
    );

    mechs.add_mechanism(
        CKM_SHA256_RSA_PKCS,
        Box::new(RsaPKCSMechanism {
            info: CK_MECHANISM_INFO {
                ulMinKeySize: MIN_RSA_SIZE_BITS as CK_ULONG,
                ulMaxKeySize: MAX_RSA_SIZE_BITS as CK_ULONG,
                flags: CKF_SIGN | CKF_VERIFY,
            },
        }),
    );

    mechs.add_mechanism(
        CKM_SHA384_RSA_PKCS,
        Box::new(RsaPKCSMechanism {
            info: CK_MECHANISM_INFO {
                ulMinKeySize: MIN_RSA_SIZE_BITS as CK_ULONG,
                ulMaxKeySize: MAX_RSA_SIZE_BITS as CK_ULONG,
                flags: CKF_SIGN | CKF_VERIFY,
            },
        }),
    );

    mechs.add_mechanism(
        CKM_SHA512_RSA_PKCS,
        Box::new(RsaPKCSMechanism {
            info: CK_MECHANISM_INFO {
                ulMinKeySize: MIN_RSA_SIZE_BITS as CK_ULONG,
                ulMaxKeySize: MAX_RSA_SIZE_BITS as CK_ULONG,
                flags: CKF_SIGN | CKF_VERIFY,
            },
        }),
    );

    mechs.add_mechanism(
        CKM_RSA_PKCS_KEY_PAIR_GEN,
        Box::new(RsaPKCSMechanism {
            info: CK_MECHANISM_INFO {
                ulMinKeySize: MIN_RSA_SIZE_BITS as CK_ULONG,
                ulMaxKeySize: MAX_RSA_SIZE_BITS as CK_ULONG,
                flags: CKF_GENERATE_KEY_PAIR,
            },
        }),
    );

    ot.add_template(ObjectType::RSAPubKey, &PUBLIC_KEY_TEMPLATE);
    ot.add_template(ObjectType::RSAPrivKey, &PRIVATE_KEY_TEMPLATE);
}

#[cfg(feature = "fips")]
include!("fips/rsa.rs");

#[cfg(not(feature = "fips"))]
include!("ossl/rsa.rs");
