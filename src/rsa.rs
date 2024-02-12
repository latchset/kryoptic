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
    CommonKeyFactory, OAFlags, Object, ObjectAttr, ObjectFactories,
    ObjectFactory, ObjectType, PrivKeyFactory, PubKeyFactory,
};

use asn1;
use once_cell::sync::Lazy;
use std::borrow::Cow;
use std::fmt::Debug;

pub const MIN_RSA_SIZE_BITS: usize = 1024;
pub const MAX_RSA_SIZE_BITS: usize = 16536;
pub const MIN_RSA_SIZE_BYTES: usize = MIN_RSA_SIZE_BITS / 8;

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
        let obj = self.default_object_create(template)?;

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

impl CommonKeyFactory for RSAPubFactory {}

impl PubKeyFactory for RSAPubFactory {}

type Version = u64;

struct DerEncBigUint<'a> {
    data: Cow<'a, [u8]>,
}

impl<'a> DerEncBigUint<'a> {
    fn new(data: &'a [u8]) -> KResult<Self> {
        let mut de = DerEncBigUint {
            data: Cow::from(data),
        };
        if de.data[0] & 0x80 == 0x80 {
            let mut v = Vec::with_capacity(de.data.len() + 1);
            v.push(0);
            v.extend_from_slice(&de.data);
            de = DerEncBigUint {
                data: Cow::Owned(v),
            };
        }
        /* check it works */
        match asn1::BigUint::new(&de.data) {
            Some(_) => Ok(de),
            None => err_rv!(CKR_GENERAL_ERROR),
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }
}

impl Drop for DerEncBigUint<'_> {
    fn drop(&mut self) {
        match &self.data {
            Cow::Owned(_) => self.data.to_mut().zeroize(),
            _ => (),
        }
    }
}

impl<'a> asn1::SimpleAsn1Readable<'a> for DerEncBigUint<'a> {
    const TAG: asn1::Tag = asn1::BigUint::TAG;
    fn parse_data(data: &'a [u8]) -> asn1::ParseResult<Self> {
        match DerEncBigUint::new(data) {
            Ok(x) => Ok(x),
            Err(_) => {
                Err(asn1::ParseError::new(asn1::ParseErrorKind::InvalidValue))
            }
        }
    }
}
impl<'a> asn1::SimpleAsn1Writable for DerEncBigUint<'a> {
    const TAG: asn1::Tag = asn1::Tag::primitive(0x02);
    fn write_data(&self, dest: &mut asn1::WriteBuf) -> asn1::WriteResult {
        dest.push_slice(self.as_bytes())
    }
}

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
        check_key_object(key, false, CKA_EXTRACTABLE)?;

        let pkey = RSAPrivateKey::new_owned(
            key.get_attr_as_bytes(CKA_MODULUS)?,
            key.get_attr_as_bytes(CKA_PUBLIC_EXPONENT)?,
            key.get_attr_as_bytes(CKA_PRIVATE_EXPONENT)?,
            key.get_attr_as_bytes(CKA_PRIME_1)?,
            key.get_attr_as_bytes(CKA_PRIME_2)?,
            key.get_attr_as_bytes(CKA_EXPONENT_1)?,
            key.get_attr_as_bytes(CKA_EXPONENT_2)?,
            key.get_attr_as_bytes(CKA_COEFFICIENT)?,
        )?;

        match asn1::write_single(&pkey) {
            Ok(x) => Ok(x),
            Err(_) => err_rv!(CKR_GENERAL_ERROR),
        }
    }

    fn import_from_wrapped(
        &self,
        data: Vec<u8>,
        template: &[CK_ATTRIBUTE],
    ) -> KResult<Object> {
        let mut attrs = template.to_vec();
        let class = CKO_PRIVATE_KEY;
        let key_type = CKK_RSA;
        let (tlv, extra) = match asn1::strip_tlv(&data) {
            Ok(x) => x,
            Err(_) => return err_rv!(CKR_WRAPPED_KEY_INVALID),
        };
        /* Some Key Wrapping algorithms may 0 pad to match block size */
        if !extra.iter().all(|b| *b == 0) {
            return err_rv!(CKR_WRAPPED_KEY_INVALID);
        }
        let rsapkey = match tlv.parse::<RSAPrivateKey>() {
            Ok(k) => k,
            Err(_) => return err_rv!(CKR_WRAPPED_KEY_INVALID),
        };
        attrs.push(CK_ATTRIBUTE::from_slice(
            CKA_MODULUS,
            rsapkey.modulus.as_bytes(),
        ));
        attrs.push(CK_ATTRIBUTE::from_slice(
            CKA_PUBLIC_EXPONENT,
            rsapkey.public_exponent.as_bytes(),
        ));
        attrs.push(CK_ATTRIBUTE::from_slice(
            CKA_PRIVATE_EXPONENT,
            rsapkey.private_exponent.as_bytes(),
        ));
        attrs.push(CK_ATTRIBUTE::from_slice(
            CKA_PRIME_1,
            rsapkey.prime1.as_bytes(),
        ));
        attrs.push(CK_ATTRIBUTE::from_slice(
            CKA_PRIME_2,
            rsapkey.prime2.as_bytes(),
        ));
        attrs.push(CK_ATTRIBUTE::from_slice(
            CKA_EXPONENT_1,
            rsapkey.exponent1.as_bytes(),
        ));
        attrs.push(CK_ATTRIBUTE::from_slice(
            CKA_EXPONENT_2,
            rsapkey.exponent2.as_bytes(),
        ));
        attrs.push(CK_ATTRIBUTE::from_slice(
            CKA_COEFFICIENT,
            rsapkey.coefficient.as_bytes(),
        ));

        if match attrs.iter().position(|x| x.type_ == CKA_CLASS) {
            Some(idx) => attrs[idx].to_ulong()?,
            None => CK_UNAVAILABLE_INFORMATION,
        } != class
        {
            return err_rv!(CKR_TEMPLATE_INCONSISTENT);
        }

        if match attrs.iter().position(|x| x.type_ == CKA_KEY_TYPE) {
            Some(idx) => attrs[idx].to_ulong()?,
            None => CK_UNAVAILABLE_INFORMATION,
        } != key_type
        {
            return err_rv!(CKR_TEMPLATE_INCONSISTENT);
        }

        self.default_object_unwrap(&attrs)
    }
}

static PUBLIC_KEY_FACTORY: Lazy<Box<dyn ObjectFactory>> =
    Lazy::new(|| Box::new(RSAPubFactory::new()));

static PRIVATE_KEY_FACTORY: Lazy<Box<dyn ObjectFactory>> =
    Lazy::new(|| Box::new(RSAPrivFactory::new()));

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
        _mech: &CK_MECHANISM,
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

        Ok((pubkey, privkey))
    }
}

pub fn register(mechs: &mut Mechanisms, ot: &mut ObjectFactories) {
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

    ot.add_factory(
        ObjectType::new(CKO_PUBLIC_KEY, CKK_RSA),
        &PUBLIC_KEY_FACTORY,
    );
    ot.add_factory(
        ObjectType::new(CKO_PRIVATE_KEY, CKK_RSA),
        &PRIVATE_KEY_FACTORY,
    );
}

#[cfg(feature = "fips")]
include!("fips/rsa.rs");

#[cfg(not(feature = "fips"))]
include!("ossl/rsa.rs");
