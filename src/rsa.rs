// Copyright 2023 Simo Sorce
// See LICENSE.txt file for terms

use std::fmt::Debug;

use crate::attribute::Attribute;
use crate::error::Result;
use crate::interface::*;
use crate::kasn1::{oid, DerEncBigUint, PrivateKeyInfo};
use crate::mechanism::*;
use crate::object::*;
use crate::ossl::rsa::*;
use crate::{attr_element, bytes_attr_not_empty};

use asn1;
use once_cell::sync::Lazy;

fn rsa_check_import(obj: &Object) -> Result<()> {
    let modulus = match obj.get_attr_as_bytes(CKA_MODULUS) {
        Ok(m) => m,
        Err(_) => return Err(CKR_TEMPLATE_INCOMPLETE)?,
    };
    match obj.get_attr_as_ulong(CKA_MODULUS_BITS) {
        Ok(b) => {
            let len = usize::try_from((b + 7) / 8)?;
            if modulus.len() != len {
                return Err(CKR_TEMPLATE_INCONSISTENT)?;
            }
        }
        Err(e) => {
            if !e.attr_not_found() {
                return Err(e);
            }
        }
    }
    if modulus.len() < MIN_RSA_SIZE_BYTES {
        return Err(CKR_ATTRIBUTE_VALUE_INVALID)?;
    }
    match obj.get_attr_as_ulong(CKA_CLASS) {
        Ok(c) => match c {
            CKO_PUBLIC_KEY => {
                bytes_attr_not_empty!(obj; CKA_PUBLIC_EXPONENT);
            }
            CKO_PRIVATE_KEY => {
                bytes_attr_not_empty!(obj; CKA_PUBLIC_EXPONENT);
                bytes_attr_not_empty!(obj; CKA_PRIVATE_EXPONENT);
                /* The FIPS module can handle missing p,q,a,b,c */
            }
            _ => return Err(CKR_ATTRIBUTE_VALUE_INVALID)?,
        },
        Err(_) => return Err(CKR_TEMPLATE_INCOMPLETE)?,
    }

    Ok(())
}

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
        data.attributes.push(attr_element!(
            CKA_MODULUS; OAFlags::RequiredOnCreate | OAFlags::Unchangeable;
            Attribute::from_bytes; val Vec::new()));
        data.attributes.push(attr_element!(
            CKA_MODULUS_BITS; OAFlags::RequiredOnGenerate
            | OAFlags::Unchangeable; Attribute::from_ulong; val 0));
        data.attributes.push(attr_element!(
            CKA_PUBLIC_EXPONENT; OAFlags::RequiredOnCreate
            | OAFlags::Unchangeable; Attribute::from_bytes; val Vec::new()));
        data
    }
}

impl ObjectFactory for RSAPubFactory {
    fn create(&self, template: &[CK_ATTRIBUTE]) -> Result<Object> {
        let mut obj = self.default_object_create(template)?;

        rsa_check_import(&mut obj)?;

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
    ) -> Result<RSAPrivateKey<'a>> {
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
        data.attributes.push(attr_element!(
            CKA_MODULUS; OAFlags::RequiredOnCreate | OAFlags::Unchangeable;
            Attribute::from_bytes; val Vec::new()));
        data.attributes.push(attr_element!(
            CKA_PUBLIC_EXPONENT; OAFlags::RequiredOnCreate
            | OAFlags::Unchangeable; Attribute::from_bytes; val Vec::new()));
        data.attributes.push(attr_element!(
            CKA_PRIVATE_EXPONENT; OAFlags::Sensitive
            | OAFlags::RequiredOnCreate | OAFlags::SettableOnlyOnCreate
            | OAFlags::Unchangeable; Attribute::from_bytes; val Vec::new()));
        data.attributes.push(attr_element!(
            CKA_PRIME_1; OAFlags::Sensitive | OAFlags::SettableOnlyOnCreate
            | OAFlags::Unchangeable; Attribute::from_bytes; val Vec::new()));
        data.attributes.push(attr_element!(
            CKA_PRIME_2; OAFlags::Sensitive | OAFlags::SettableOnlyOnCreate
            | OAFlags::Unchangeable; Attribute::from_bytes; val Vec::new()));
        data.attributes.push(attr_element!(
            CKA_EXPONENT_1; OAFlags::Sensitive | OAFlags::SettableOnlyOnCreate
            | OAFlags::Unchangeable; Attribute::from_bytes; val Vec::new()));
        data.attributes.push(attr_element!(
            CKA_EXPONENT_2; OAFlags::Sensitive | OAFlags::SettableOnlyOnCreate
            | OAFlags::Unchangeable; Attribute::from_bytes; val Vec::new()));
        data.attributes.push(attr_element!(
            CKA_COEFFICIENT; OAFlags::Sensitive | OAFlags::SettableOnlyOnCreate
            | OAFlags::Unchangeable; Attribute::from_bytes; val Vec::new()));

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

impl ObjectFactory for RSAPrivFactory {
    fn create(&self, template: &[CK_ATTRIBUTE]) -> Result<Object> {
        let mut obj = self.default_object_create(template)?;

        rsa_check_import(&mut obj)?;

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

impl CommonKeyFactory for RSAPrivFactory {}

impl PrivKeyFactory for RSAPrivFactory {
    fn export_for_wrapping(&self, key: &Object) -> Result<Vec<u8>> {
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
            _ => return Err(CKR_GENERAL_ERROR)?,
        };
        let pkeyinfo = PrivateKeyInfo::new(&pkey.as_slice(), oid::RSA_OID)?;

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
            .check_or_set_attr(Attribute::from_ulong(CKA_KEY_TYPE, CKK_RSA))?
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
        if pkeyinfo.get_oid() != &oid::RSA_OID {
            return Err(CKR_WRAPPED_KEY_INVALID)?;
        }
        let rsapkey = match asn1::parse_single::<RSAPrivateKey>(
            pkeyinfo.get_private_key(),
        ) {
            Ok(k) => k,
            Err(_) => return Err(CKR_WRAPPED_KEY_INVALID)?,
        };

        if !key.check_or_set_attr(Attribute::from_bytes(
            CKA_MODULUS,
            rsapkey.modulus.as_nopad_bytes().to_vec(),
        ))? {
            return Err(CKR_TEMPLATE_INCONSISTENT)?;
        }
        if !key.check_or_set_attr(Attribute::from_bytes(
            CKA_PUBLIC_EXPONENT,
            rsapkey.public_exponent.as_nopad_bytes().to_vec(),
        ))? {
            return Err(CKR_TEMPLATE_INCONSISTENT)?;
        }
        if !key.check_or_set_attr(Attribute::from_bytes(
            CKA_PRIVATE_EXPONENT,
            rsapkey.private_exponent.as_nopad_bytes().to_vec(),
        ))? {
            return Err(CKR_TEMPLATE_INCONSISTENT)?;
        }
        if !key.check_or_set_attr(Attribute::from_bytes(
            CKA_PRIME_1,
            rsapkey.prime1.as_nopad_bytes().to_vec(),
        ))? {
            return Err(CKR_TEMPLATE_INCONSISTENT)?;
        }
        if !key.check_or_set_attr(Attribute::from_bytes(
            CKA_PRIME_2,
            rsapkey.prime2.as_nopad_bytes().to_vec(),
        ))? {
            return Err(CKR_TEMPLATE_INCONSISTENT)?;
        }
        if !key.check_or_set_attr(Attribute::from_bytes(
            CKA_EXPONENT_1,
            rsapkey.exponent1.as_nopad_bytes().to_vec(),
        ))? {
            return Err(CKR_TEMPLATE_INCONSISTENT)?;
        }
        if !key.check_or_set_attr(Attribute::from_bytes(
            CKA_EXPONENT_2,
            rsapkey.exponent2.as_nopad_bytes().to_vec(),
        ))? {
            return Err(CKR_TEMPLATE_INCONSISTENT)?;
        }
        if !key.check_or_set_attr(Attribute::from_bytes(
            CKA_COEFFICIENT,
            rsapkey.coefficient.as_nopad_bytes().to_vec(),
        ))? {
            return Err(CKR_TEMPLATE_INCONSISTENT)?;
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

impl RsaPKCSMechanism {
    fn new_mechanism(flags: CK_FLAGS) -> Box<dyn Mechanism> {
        Box::new(RsaPKCSMechanism {
            info: CK_MECHANISM_INFO {
                ulMinKeySize: CK_ULONG::try_from(MIN_RSA_SIZE_BITS).unwrap(),
                ulMaxKeySize: CK_ULONG::try_from(MAX_RSA_SIZE_BITS).unwrap(),
                flags: flags,
            },
        })
    }

    pub fn register_mechanisms(mechs: &mut Mechanisms) {
        for ckm in &[CKM_RSA_X_509, CKM_RSA_PKCS] {
            mechs.add_mechanism(
                *ckm,
                Self::new_mechanism(
                    CKF_ENCRYPT
                        | CKF_DECRYPT
                        | CKF_SIGN
                        | CKF_VERIFY
                        | CKF_WRAP
                        | CKF_UNWRAP,
                ),
            );
        }
        for ckm in &[
            CKM_SHA1_RSA_PKCS,
            CKM_SHA224_RSA_PKCS,
            CKM_SHA256_RSA_PKCS,
            CKM_SHA384_RSA_PKCS,
            CKM_SHA512_RSA_PKCS,
            CKM_SHA3_224_RSA_PKCS,
            CKM_SHA3_256_RSA_PKCS,
            CKM_SHA3_384_RSA_PKCS,
            CKM_SHA3_512_RSA_PKCS,
            CKM_RSA_PKCS_PSS,
            CKM_SHA1_RSA_PKCS_PSS,
            CKM_SHA224_RSA_PKCS_PSS,
            CKM_SHA256_RSA_PKCS_PSS,
            CKM_SHA384_RSA_PKCS_PSS,
            CKM_SHA512_RSA_PKCS_PSS,
            CKM_SHA3_224_RSA_PKCS_PSS,
            CKM_SHA3_256_RSA_PKCS_PSS,
            CKM_SHA3_384_RSA_PKCS_PSS,
            CKM_SHA3_512_RSA_PKCS_PSS,
        ] {
            mechs.add_mechanism(
                *ckm,
                Self::new_mechanism(CKF_SIGN | CKF_VERIFY),
            );
        }

        mechs.add_mechanism(
            CKM_RSA_PKCS_KEY_PAIR_GEN,
            Self::new_mechanism(CKF_GENERATE_KEY_PAIR),
        );

        mechs.add_mechanism(
            CKM_RSA_PKCS_OAEP,
            Self::new_mechanism(
                CKF_ENCRYPT | CKF_DECRYPT | CKF_WRAP | CKF_UNWRAP,
            ),
        );
    }
}

impl Mechanism for RsaPKCSMechanism {
    fn info(&self) -> &CK_MECHANISM_INFO {
        &self.info
    }

    fn encryption_new(
        &self,
        mech: &CK_MECHANISM,
        key: &Object,
    ) -> Result<Box<dyn Encryption>> {
        if self.info.flags & CKF_ENCRYPT != CKF_ENCRYPT {
            return Err(CKR_MECHANISM_INVALID)?;
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
    ) -> Result<Box<dyn Decryption>> {
        if self.info.flags & CKF_DECRYPT != CKF_DECRYPT {
            return Err(CKR_MECHANISM_INVALID)?;
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
    ) -> Result<Box<dyn Sign>> {
        if self.info.flags & CKF_SIGN != CKF_SIGN {
            return Err(CKR_MECHANISM_INVALID)?;
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
    ) -> Result<Box<dyn Verify>> {
        if self.info.flags & CKF_VERIFY != CKF_VERIFY {
            return Err(CKR_MECHANISM_INVALID)?;
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
            .check_or_set_attr(Attribute::from_ulong(CKA_KEY_TYPE, CKK_RSA))?
        {
            return Err(CKR_TEMPLATE_INCONSISTENT)?;
        }

        let bits =
            usize::try_from(pubkey.get_attr_as_ulong(CKA_MODULUS_BITS)?)?;
        let exponent: Vec<u8> = match pubkey.get_attr(CKA_PUBLIC_EXPONENT) {
            Some(a) => a.get_value().clone(),
            None => {
                pubkey.set_attr(Attribute::from_bytes(
                    CKA_PUBLIC_EXPONENT,
                    vec![0x01, 0x00, 0x01],
                ))?;
                pubkey.get_attr_as_bytes(CKA_PUBLIC_EXPONENT)?.clone()
            }
        };

        let mut privkey =
            PRIVATE_KEY_FACTORY.default_object_generate(prikey_template)?;
        if !privkey.check_or_set_attr(Attribute::from_ulong(
            CKA_CLASS,
            CKO_PRIVATE_KEY,
        ))? {
            return Err(CKR_TEMPLATE_INCONSISTENT)?;
        }
        if !privkey
            .check_or_set_attr(Attribute::from_ulong(CKA_KEY_TYPE, CKK_RSA))?
        {
            return Err(CKR_TEMPLATE_INCONSISTENT)?;
        }

        RsaPKCSOperation::generate_keypair(
            exponent,
            bits,
            &mut pubkey,
            &mut privkey,
        )?;
        default_key_attributes(&mut privkey, mech.mechanism)?;
        default_key_attributes(&mut pubkey, mech.mechanism)?;

        Ok((pubkey, privkey))
    }

    fn wrap_key(
        &self,
        mech: &CK_MECHANISM,
        wrapping_key: &Object,
        key: &Object,
        data: &mut [u8],
        key_template: &Box<dyn ObjectFactory>,
    ) -> Result<usize> {
        if self.info.flags & CKF_WRAP != CKF_WRAP {
            return Err(CKR_MECHANISM_INVALID)?;
        }

        RsaPKCSOperation::wrap(
            mech,
            wrapping_key,
            key_template.export_for_wrapping(key)?,
            data,
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
    ) -> Result<Object> {
        if self.info.flags & CKF_UNWRAP != CKF_UNWRAP {
            return Err(CKR_MECHANISM_INVALID)?;
        }
        let keydata =
            RsaPKCSOperation::unwrap(mech, wrapping_key, data, &self.info)?;
        key_template.import_from_wrapped(keydata, template)
    }
}

pub fn register(mechs: &mut Mechanisms, ot: &mut ObjectFactories) {
    RsaPKCSMechanism::register_mechanisms(mechs);

    ot.add_factory(
        ObjectType::new(CKO_PUBLIC_KEY, CKK_RSA),
        &PUBLIC_KEY_FACTORY,
    );
    ot.add_factory(
        ObjectType::new(CKO_PRIVATE_KEY, CKK_RSA),
        &PRIVATE_KEY_FACTORY,
    );
}
