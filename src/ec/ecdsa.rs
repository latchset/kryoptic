// Copyright 2023 - 2024 Simo Sorce, Jakub Jelen
// See LICENSE.txt file for terms

use std::fmt::Debug;

use crate::attribute::Attribute;
use crate::ec::*;
use crate::error::{general_error, Error, Result};
use crate::kasn1::{oid, PrivateKeyInfo};
use crate::mechanism::*;
use crate::object::*;
use crate::ossl::ecdsa::EccOperation;

use asn1;
use once_cell::sync::Lazy;

pub const MIN_EC_SIZE_BITS: usize = BITS_SECP256R1;
pub const MAX_EC_SIZE_BITS: usize = BITS_SECP521R1;

#[derive(Debug, Default)]
pub struct ECCPubFactory {
    data: ObjectFactoryData,
}

impl ECCPubFactory {
    pub fn new() -> ECCPubFactory {
        let mut factory: ECCPubFactory = Default::default();

        factory.add_common_public_key_attrs();

        let attributes = factory.data.get_attributes_mut();

        attributes.push(attr_element!(
            CKA_EC_PARAMS; OAFlags::AlwaysRequired | OAFlags::Unchangeable;
            Attribute::from_bytes; val Vec::new()));
        attributes.push(attr_element!(
            CKA_EC_POINT; OAFlags::RequiredOnCreate
            | OAFlags::SettableOnlyOnCreate | OAFlags::Unchangeable;
            Attribute::from_bytes; val Vec::new()));

        factory.data.finalize();

        factory
    }
}

impl ObjectFactory for ECCPubFactory {
    fn create(&self, template: &[CK_ATTRIBUTE]) -> Result<Object> {
        let mut obj = self.default_object_create(template)?;

        /* According to PKCS#11 v3.1 6.3.3:
         * CKA_EC_PARAMS, Byte array,
         * DER-encoding of an ANSI X9.62 Parameters value */
        let oid = get_oid_from_obj(&obj).map_err(|e| {
            if e.attr_not_found() {
                Error::ck_rv_from_error(CKR_TEMPLATE_INCOMPLETE, e)
            } else if e.rv() != CKR_ATTRIBUTE_VALUE_INVALID {
                Error::ck_rv_from_error(CKR_ATTRIBUTE_VALUE_INVALID, e)
            } else {
                general_error(e)
            }
        })?;
        match oid {
            oid::EC_SECP256R1 | oid::EC_SECP384R1 | oid::EC_SECP521R1 => (),
            _ => return Err(CKR_ATTRIBUTE_VALUE_INVALID)?,
        }

        /* According to PKCS#11 v3.1 6.3.3:
         * CKA_EC_POINT, Byte array,
         * DER-encoding of ANSI X9.62 ECPoint value Q */
        check_ec_point_from_obj(&oid, &mut obj).map_err(|e| {
            if e.attr_not_found() {
                Error::ck_rv_from_error(CKR_TEMPLATE_INCOMPLETE, e)
            } else {
                e
            }
        })?;

        Ok(obj)
    }

    fn get_data(&self) -> &ObjectFactoryData {
        &self.data
    }

    fn get_data_mut(&mut self) -> &mut ObjectFactoryData {
        &mut self.data
    }
}

impl CommonKeyFactory for ECCPubFactory {}

impl PubKeyFactory for ECCPubFactory {}

#[derive(Debug, Default)]
pub struct ECCPrivFactory {
    data: ObjectFactoryData,
}

impl ECCPrivFactory {
    pub fn new() -> ECCPrivFactory {
        let mut factory: ECCPrivFactory = Default::default();

        factory.add_common_private_key_attrs();

        let attributes = factory.data.get_attributes_mut();

        attributes.push(attr_element!(
            CKA_EC_PARAMS; OAFlags::RequiredOnCreate | OAFlags::Unchangeable;
            Attribute::from_bytes; val Vec::new()));
        attributes.push(attr_element!(
            CKA_VALUE; OAFlags::Sensitive | OAFlags::RequiredOnCreate
            | OAFlags::SettableOnlyOnCreate | OAFlags::Unchangeable;
            Attribute::from_bytes; val Vec::new()));

        /* default to private */
        let private = attr_element!(
            CKA_PRIVATE; OAFlags::Defval | OAFlags::ChangeOnCopy;
            Attribute::from_bool; val true);
        match attributes.iter().position(|x| x.get_type() == CKA_PRIVATE) {
            Some(idx) => attributes[idx] = private,
            None => attributes.push(private),
        }

        factory.data.finalize();

        factory
    }
}

impl ObjectFactory for ECCPrivFactory {
    fn create(&self, template: &[CK_ATTRIBUTE]) -> Result<Object> {
        let obj = self.default_object_create(template)?;

        /* According to PKCS#11 v3.1 6.3.4:
         * CKA_EC_PARAMS, Byte array,
         * DER-encoding of an ANSI X9.62 Parameters value */
        let oid = get_oid_from_obj(&obj).map_err(|e| {
            if e.attr_not_found() {
                Error::ck_rv_from_error(CKR_TEMPLATE_INCOMPLETE, e)
            } else if e.rv() != CKR_ATTRIBUTE_VALUE_INVALID {
                Error::ck_rv_from_error(CKR_ATTRIBUTE_VALUE_INVALID, e)
            } else {
                general_error(e)
            }
        })?;
        match oid {
            oid::EC_SECP256R1 | oid::EC_SECP384R1 | oid::EC_SECP521R1 => (),
            _ => return Err(CKR_ATTRIBUTE_VALUE_INVALID)?,
        }

        /* According to PKCS#11 v3.1 6.3.4:
         * CKA_VALUE, BigInteger,
         * ANSI X9.62 private value d */
        match obj.get_attr_as_bytes(CKA_VALUE) {
            Ok(v) => {
                if v.len() != ec_key_size(&oid)? {
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

        Ok(obj)
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

    fn get_data(&self) -> &ObjectFactoryData {
        &self.data
    }

    fn get_data_mut(&mut self) -> &mut ObjectFactoryData {
        &mut self.data
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
        let oid = pkeyinfo.get_oid();
        /* filter out unknown OIDs */
        match oid {
            &EC_SECP521R1 | &EC_SECP384R1 | &EC_SECP256R1 => (),
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

    #[cfg(feature = "pkcs11_3_2")]
    fn verify_signature_new(
        &self,
        mech: &CK_MECHANISM,
        key: &Object,
        signature: &[u8],
    ) -> Result<Box<dyn VerifySignature>> {
        if self.info.flags & CKF_VERIFY != CKF_VERIFY {
            return Err(CKR_MECHANISM_INVALID)?;
        }
        match key.check_key_ops(CKO_PUBLIC_KEY, CKK_EC, CKA_VERIFY) {
            Ok(_) => (),
            Err(e) => return Err(e),
        }
        Ok(Box::new(EccOperation::verify_signature_new(
            mech, key, &self.info, signature,
        )?))
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
