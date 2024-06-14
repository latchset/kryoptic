// Copyright 2023 Simo Sorce
// See LICENSE.txt file for terms

use super::attribute;
use super::error;
use super::interface;
use super::kasn1;
use super::object;
use super::{attr_element, bytes_attr_not_empty, err_rv};

use attribute::{from_bool, from_bytes, from_ulong};
use error::{KError, KResult};
use interface::*;
use kasn1::DerEncBigUint;
use object::{
    CommonKeyFactory, OAFlags, Object, ObjectAttr, ObjectFactories,
    ObjectFactory, ObjectType, PrivKeyFactory, PubKeyFactory,
};

use asn1;
use once_cell::sync::Lazy;
use std::fmt::Debug;

pub const OID_RSA_ENCRYPTION: asn1::ObjectIdentifier =
    asn1::oid!(1, 2, 840, 113549, 1, 1, 1);

#[derive(Debug)]
pub struct RSAPubFactory {
    attributes: Vec<ObjectAttr>,
}

impl RSAPubFactory {
    pub fn new() -> RSAPubFactory {
        let mut data: RSAPubFactory = RSAPubFactory {
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

impl ObjectFactory for RSAPubFactory {
    fn create(&self, template: &[CK_ATTRIBUTE]) -> KResult<Object> {
        let mut obj = self.default_object_create(template)?;

        rsa_import(&mut obj)?;

        Ok(obj)
    }

    fn get_attributes(&self) -> &Vec<ObjectAttr> {
        &self.attributes
    }
}

impl CommonKeyFactory for RSAPubFactory {}

impl PubKeyFactory for RSAPubFactory {}

type Version = u64;

#[derive(asn1::Asn1Read, asn1::Asn1Write)]
struct OtherPrimeInfo<'a> {
    prime: DerEncBigUint<'a>,
    exponent: DerEncBigUint<'a>,
    coefficient: DerEncBigUint<'a>,
}

#[derive(asn1::Asn1Read, asn1::Asn1Write)]
struct RSAPrivateKey<'a> {
    version: Version,
    modulus: DerEncBigUint<'a>,
    public_exponent: DerEncBigUint<'a>,
    private_exponent: DerEncBigUint<'a>,
    prime1: DerEncBigUint<'a>,
    prime2: DerEncBigUint<'a>,
    exponent1: DerEncBigUint<'a>,
    exponent2: DerEncBigUint<'a>,
    coefficient: DerEncBigUint<'a>,
    other_prime_infos: Option<asn1::SequenceOf<'a, OtherPrimeInfo<'a>>>,
}

impl RSAPrivateKey<'_> {
    pub fn new_owned<'a>(
        modulus: &'a Vec<u8>,
        public_exponent: &'a Vec<u8>,
        private_exponent: &'a Vec<u8>,
        prime1: &'a Vec<u8>,
        prime2: &'a Vec<u8>,
        exponent1: &'a Vec<u8>,
        exponent2: &'a Vec<u8>,
        coefficient: &'a Vec<u8>,
    ) -> KResult<RSAPrivateKey<'a>> {
        Ok(RSAPrivateKey {
            version: 0,
            modulus: DerEncBigUint::new(modulus.as_slice())?,
            public_exponent: DerEncBigUint::new(public_exponent.as_slice())?,
            private_exponent: DerEncBigUint::new(private_exponent.as_slice())?,
            prime1: DerEncBigUint::new(prime1.as_slice())?,
            prime2: DerEncBigUint::new(prime2.as_slice())?,
            exponent1: DerEncBigUint::new(exponent1.as_slice())?,
            exponent2: DerEncBigUint::new(exponent2.as_slice())?,
            coefficient: DerEncBigUint::new(coefficient.as_slice())?,
            other_prime_infos: None,
        })
    }
}

#[derive(Debug)]
pub struct RSAPrivFactory {
    attributes: Vec<ObjectAttr>,
}

impl RSAPrivFactory {
    pub fn new() -> RSAPrivFactory {
        let mut data: RSAPrivFactory = RSAPrivFactory {
            attributes: Vec::new(),
        };
        data.attributes.append(&mut data.init_common_object_attrs());
        data.attributes
            .append(&mut data.init_common_storage_attrs());
        data.attributes.append(&mut data.init_common_key_attrs());
        data.attributes
            .append(&mut data.init_common_private_key_attrs());
        data.attributes.push(attr_element!(CKA_MODULUS; OAFlags::RequiredOnCreate | OAFlags::Unchangeable; from_bytes; val Vec::new()));
        data.attributes.push(attr_element!(CKA_PUBLIC_EXPONENT; OAFlags::RequiredOnCreate | OAFlags::Unchangeable; from_bytes; val Vec::new()));
        data.attributes.push(attr_element!(CKA_PRIVATE_EXPONENT; OAFlags::Sensitive | OAFlags::RequiredOnCreate | OAFlags::SettableOnlyOnCreate | OAFlags::Unchangeable; from_bytes; val Vec::new()));
        data.attributes.push(attr_element!(CKA_PRIME_1; OAFlags::Sensitive | OAFlags::SettableOnlyOnCreate | OAFlags::Unchangeable; from_bytes; val Vec::new()));
        data.attributes.push(attr_element!(CKA_PRIME_2; OAFlags::Sensitive | OAFlags::SettableOnlyOnCreate | OAFlags::Unchangeable; from_bytes; val Vec::new()));
        data.attributes.push(attr_element!(CKA_EXPONENT_1; OAFlags::Sensitive | OAFlags::SettableOnlyOnCreate | OAFlags::Unchangeable; from_bytes; val Vec::new()));
        data.attributes.push(attr_element!(CKA_EXPONENT_2; OAFlags::Sensitive | OAFlags::SettableOnlyOnCreate | OAFlags::Unchangeable; from_bytes; val Vec::new()));
        data.attributes.push(attr_element!(CKA_COEFFICIENT; OAFlags::Sensitive | OAFlags::SettableOnlyOnCreate | OAFlags::Unchangeable; from_bytes; val Vec::new()));

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

impl ObjectFactory for RSAPrivFactory {
    fn create(&self, template: &[CK_ATTRIBUTE]) -> KResult<Object> {
        let mut obj = self.default_object_create(template)?;

        rsa_import(&mut obj)?;

        Ok(obj)
    }

    fn get_attributes(&self) -> &Vec<ObjectAttr> {
        &self.attributes
    }

    fn export_for_wrapping(&self, key: &Object) -> KResult<Vec<u8>> {
        PrivKeyFactory::export_for_wrapping(self, key)
    }

    fn import_from_wrapped(
        &self,
        data: Vec<u8>,
        template: &[CK_ATTRIBUTE],
    ) -> KResult<Object> {
        PrivKeyFactory::import_from_wrapped(self, data, template)
    }
}

impl CommonKeyFactory for RSAPrivFactory {}

impl PrivKeyFactory for RSAPrivFactory {
    fn export_for_wrapping(&self, key: &Object) -> KResult<Vec<u8>> {
        key.check_key_ops(CKO_PRIVATE_KEY, CKK_RSA, CKA_EXTRACTABLE)?;

        let pkey = match asn1::write_single(&RSAPrivateKey::new_owned(
            key.get_attr_as_bytes(CKA_MODULUS)?,
            key.get_attr_as_bytes(CKA_PUBLIC_EXPONENT)?,
            key.get_attr_as_bytes(CKA_PRIVATE_EXPONENT)?,
            key.get_attr_as_bytes(CKA_PRIME_1)?,
            key.get_attr_as_bytes(CKA_PRIME_2)?,
            key.get_attr_as_bytes(CKA_EXPONENT_1)?,
            key.get_attr_as_bytes(CKA_EXPONENT_2)?,
            key.get_attr_as_bytes(CKA_COEFFICIENT)?,
        )?) {
            Ok(p) => p,
            _ => return err_rv!(CKR_GENERAL_ERROR),
        };
        let pkeyinfo =
            kasn1::PrivateKeyInfo::new(&pkey.as_slice(), OID_RSA_ENCRYPTION)?;

        match asn1::write_single(&pkeyinfo) {
            Ok(x) => Ok(x),
            Err(_) => err_rv!(CKR_GENERAL_ERROR),
        }
    }

    fn import_from_wrapped(
        &self,
        data: Vec<u8>,
        template: &[CK_ATTRIBUTE],
    ) -> KResult<Object> {
        let mut key = self.default_object_unwrap(template)?;

        if !key.check_or_set_attr(attribute::from_ulong(
            CKA_CLASS,
            CKO_PRIVATE_KEY,
        ))? {
            return err_rv!(CKR_TEMPLATE_INCONSISTENT);
        }
        if !key
            .check_or_set_attr(attribute::from_ulong(CKA_KEY_TYPE, CKK_RSA))?
        {
            return err_rv!(CKR_TEMPLATE_INCONSISTENT);
        }

        let (tlv, extra) = match asn1::strip_tlv(&data) {
            Ok(x) => x,
            Err(_) => return err_rv!(CKR_WRAPPED_KEY_INVALID),
        };
        /* Some Key Wrapping algorithms may 0 pad to match block size */
        if !extra.iter().all(|b| *b == 0) {
            return err_rv!(CKR_WRAPPED_KEY_INVALID);
        }
        let pkeyinfo = match tlv.parse::<kasn1::PrivateKeyInfo>() {
            Ok(k) => k,
            Err(_) => return err_rv!(CKR_WRAPPED_KEY_INVALID),
        };
        if pkeyinfo.get_oid() != &OID_RSA_ENCRYPTION {
            return err_rv!(CKR_WRAPPED_KEY_INVALID);
        }
        let rsapkey = match asn1::parse_single::<RSAPrivateKey>(
            pkeyinfo.get_private_key(),
        ) {
            Ok(k) => k,
            Err(_) => return err_rv!(CKR_WRAPPED_KEY_INVALID),
        };

        if !key.check_or_set_attr(attribute::from_bytes(
            CKA_MODULUS,
            rsapkey.modulus.as_nopad_bytes().to_vec(),
        ))? {
            return err_rv!(CKR_TEMPLATE_INCONSISTENT);
        }
        if !key.check_or_set_attr(attribute::from_bytes(
            CKA_PUBLIC_EXPONENT,
            rsapkey.public_exponent.as_nopad_bytes().to_vec(),
        ))? {
            return err_rv!(CKR_TEMPLATE_INCONSISTENT);
        }
        if !key.check_or_set_attr(attribute::from_bytes(
            CKA_PRIVATE_EXPONENT,
            rsapkey.private_exponent.as_nopad_bytes().to_vec(),
        ))? {
            return err_rv!(CKR_TEMPLATE_INCONSISTENT);
        }
        if !key.check_or_set_attr(attribute::from_bytes(
            CKA_PRIME_1,
            rsapkey.prime1.as_nopad_bytes().to_vec(),
        ))? {
            return err_rv!(CKR_TEMPLATE_INCONSISTENT);
        }
        if !key.check_or_set_attr(attribute::from_bytes(
            CKA_PRIME_2,
            rsapkey.prime2.as_nopad_bytes().to_vec(),
        ))? {
            return err_rv!(CKR_TEMPLATE_INCONSISTENT);
        }
        if !key.check_or_set_attr(attribute::from_bytes(
            CKA_EXPONENT_1,
            rsapkey.exponent1.as_nopad_bytes().to_vec(),
        ))? {
            return err_rv!(CKR_TEMPLATE_INCONSISTENT);
        }
        if !key.check_or_set_attr(attribute::from_bytes(
            CKA_EXPONENT_2,
            rsapkey.exponent2.as_nopad_bytes().to_vec(),
        ))? {
            return err_rv!(CKR_TEMPLATE_INCONSISTENT);
        }
        if !key.check_or_set_attr(attribute::from_bytes(
            CKA_COEFFICIENT,
            rsapkey.coefficient.as_nopad_bytes().to_vec(),
        ))? {
            return err_rv!(CKR_TEMPLATE_INCONSISTENT);
        }

        Ok(key)
    }
}

static PUBLIC_KEY_FACTORY: Lazy<Box<dyn ObjectFactory>> =
    Lazy::new(|| Box::new(RSAPubFactory::new()));

static PRIVATE_KEY_FACTORY: Lazy<Box<dyn ObjectFactory>> =
    Lazy::new(|| Box::new(RSAPrivFactory::new()));

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
        match key.check_key_ops(CKO_PUBLIC_KEY, CKK_RSA, CKA_ENCRYPT) {
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
        match key.check_key_ops(CKO_PRIVATE_KEY, CKK_RSA, CKA_DECRYPT) {
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
        match key.check_key_ops(CKO_PRIVATE_KEY, CKK_RSA, CKA_SIGN) {
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
        match key.check_key_ops(CKO_PUBLIC_KEY, CKK_RSA, CKA_VERIFY) {
            Ok(_) => (),
            Err(e) => return Err(e),
        }
        Ok(Box::new(RsaPKCSOperation::verify_new(
            mech, key, &self.info,
        )?))
    }

    fn generate_keypair(
        &self,
        mech: &CK_MECHANISM,
        pubkey_template: &[CK_ATTRIBUTE],
        prikey_template: &[CK_ATTRIBUTE],
    ) -> KResult<(Object, Object)> {
        let mut pubkey =
            PUBLIC_KEY_FACTORY.default_object_generate(pubkey_template)?;
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

        let mut privkey =
            PRIVATE_KEY_FACTORY.default_object_generate(prikey_template)?;
        if !privkey.check_or_set_attr(attribute::from_ulong(
            CKA_CLASS,
            CKO_PRIVATE_KEY,
        ))? {
            return err_rv!(CKR_TEMPLATE_INCONSISTENT);
        }
        if !privkey
            .check_or_set_attr(attribute::from_ulong(CKA_KEY_TYPE, CKK_RSA))?
        {
            return err_rv!(CKR_TEMPLATE_INCONSISTENT);
        }

        RsaPKCSOperation::generate_keypair(
            exponent,
            bits,
            &mut pubkey,
            &mut privkey,
        )?;
        object::default_key_attributes(&mut privkey, mech)?;
        object::default_key_attributes(&mut pubkey, mech)?;

        Ok((pubkey, privkey))
    }

    fn wrap_key(
        &self,
        mech: &CK_MECHANISM,
        wrapping_key: &Object,
        key: &Object,
        data: CK_BYTE_PTR,
        data_len: CK_ULONG_PTR,
        key_template: &Box<dyn ObjectFactory>,
    ) -> KResult<()> {
        if self.info.flags & CKF_WRAP != CKF_WRAP {
            return err_rv!(CKR_MECHANISM_INVALID);
        }

        RsaPKCSOperation::wrap(
            mech,
            wrapping_key,
            key_template.export_for_wrapping(key)?,
            data,
            data_len,
            &self.info,
        )
    }

    fn unwrap_key(
        &self,
        mech: &CK_MECHANISM,
        wrapping_key: &Object,
        data: &[u8],
        template: &[CK_ATTRIBUTE],
        key_template: &Box<dyn ObjectFactory>,
    ) -> KResult<Object> {
        if self.info.flags & CKF_UNWRAP != CKF_UNWRAP {
            return err_rv!(CKR_MECHANISM_INVALID);
        }
        let keydata =
            RsaPKCSOperation::unwrap(mech, wrapping_key, data, &self.info)?;
        key_template.import_from_wrapped(keydata, template)
    }
}

pub fn register(mechs: &mut Mechanisms, ot: &mut ObjectFactories) {
    RsaPKCSOperation::register_mechanisms(mechs);

    ot.add_factory(
        ObjectType::new(CKO_PUBLIC_KEY, CKK_RSA),
        &PUBLIC_KEY_FACTORY,
    );
    ot.add_factory(
        ObjectType::new(CKO_PRIVATE_KEY, CKK_RSA),
        &PRIVATE_KEY_FACTORY,
    );
}

include!("ossl/rsa.rs");
