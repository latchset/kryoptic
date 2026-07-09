// Copyright 2023 Simo Sorce
// See LICENSE.txt file for terms

//! This module handles RSA key object factories, ASN.1 structures for key
//! export/import, and registration of RSA-related PKCS#11 mechanisms (PKCS#1
//! v1.5, PSS, OAEP).

use std::fmt::Debug;
use std::sync::LazyLock;

use crate::aes::AES_BLOCK_SIZE;
use crate::attribute::{Attribute, CkAttrs};
use crate::error::{Error, Result};
use crate::kasn1::{pkcs, DerEncBigUint, PrivateKeyInfo};
use crate::mechanism::*;
use crate::misc::{warn_weak_key_wrap, zeromem};
use crate::object::*;
use crate::ossl::aes::AesOperation;
use crate::ossl::rsa::*;
use crate::pkcs11::*;

use asn1;

/// Object that holds Mechanisms for RSA
static RSA_MECHS: LazyLock<[Box<dyn Mechanism>; 4]> = LazyLock::new(|| {
    [
        Box::new(RsaPKCSMechanism {
            info: CK_MECHANISM_INFO {
                ulMinKeySize: CK_ULONG::try_from(MIN_RSA_SIZE_BITS).unwrap(),
                ulMaxKeySize: CK_ULONG::try_from(MAX_RSA_SIZE_BITS).unwrap(),
                flags: CKF_ENCRYPT
                    | CKF_DECRYPT
                    | CKF_SIGN
                    | CKF_VERIFY
                    | CKF_WRAP
                    | CKF_UNWRAP,
            },
        }),
        Box::new(RsaPKCSMechanism {
            info: CK_MECHANISM_INFO {
                ulMinKeySize: CK_ULONG::try_from(MIN_RSA_SIZE_BITS).unwrap(),
                ulMaxKeySize: CK_ULONG::try_from(MAX_RSA_SIZE_BITS).unwrap(),
                flags: CKF_SIGN | CKF_VERIFY,
            },
        }),
        Box::new(RsaPKCSMechanism {
            info: CK_MECHANISM_INFO {
                ulMinKeySize: CK_ULONG::try_from(MIN_RSA_SIZE_BITS).unwrap(),
                ulMaxKeySize: CK_ULONG::try_from(MAX_RSA_SIZE_BITS).unwrap(),
                flags: CKF_GENERATE_KEY_PAIR,
            },
        }),
        Box::new(RsaPKCSMechanism {
            info: CK_MECHANISM_INFO {
                ulMinKeySize: CK_ULONG::try_from(MIN_RSA_SIZE_BITS).unwrap(),
                ulMaxKeySize: CK_ULONG::try_from(MAX_RSA_SIZE_BITS).unwrap(),
                flags: CKF_ENCRYPT | CKF_DECRYPT | CKF_WRAP | CKF_UNWRAP,
            },
        }),
    ]
});

/// Mechanism object implementing the CKM_RSA_AES_KEY_WRAP composite key
/// wrapping mechanism.
static RSA_AES_KW_MECH: LazyLock<Box<dyn Mechanism>> = LazyLock::new(|| {
    Box::new(RsaAesKeyWrapMechanism {
        info: CK_MECHANISM_INFO {
            ulMinKeySize: CK_ULONG::try_from(MIN_RSA_SIZE_BITS).unwrap(),
            ulMaxKeySize: CK_ULONG::try_from(MAX_RSA_SIZE_BITS).unwrap(),
            flags: CKF_WRAP | CKF_UNWRAP,
        },
    })
});

/// The static RSA Public Key factory.
static PUBLIC_KEY_FACTORY: LazyLock<Box<dyn ObjectFactory>> =
    LazyLock::new(|| Box::new(RSAPubFactory::new()));

/// The static RSA Private Key factory.
static PRIVATE_KEY_FACTORY: LazyLock<Box<dyn ObjectFactory>> =
    LazyLock::new(|| Box::new(RSAPrivFactory::new()));

/// Registers all RSA mechanisms and key factories
pub fn register(mechs: &mut Mechanisms, ot: &mut ObjectFactories) {
    for ckm in &[CKM_RSA_X_509, CKM_RSA_PKCS] {
        mechs.add_mechanism(*ckm, &RSA_MECHS[0]);
    }
    for ckm in &[
        #[cfg(not(feature = "no_sha1"))]
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
        #[cfg(not(feature = "no_sha1"))]
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
        mechs.add_mechanism(*ckm, &RSA_MECHS[1]);
    }
    mechs.add_mechanism(CKM_RSA_PKCS_KEY_PAIR_GEN, &RSA_MECHS[2]);
    mechs.add_mechanism(CKM_RSA_PKCS_OAEP, &RSA_MECHS[3]);
    mechs.add_mechanism(CKM_RSA_AES_KEY_WRAP, &RSA_AES_KW_MECH);

    ot.add_factory(
        ObjectType::new(CKO_PUBLIC_KEY, CKK_RSA),
        &PUBLIC_KEY_FACTORY,
    );
    ot.add_factory(
        ObjectType::new(CKO_PRIVATE_KEY, CKK_RSA),
        &PRIVATE_KEY_FACTORY,
    );
}

/// Macro to check that an attribute that contains a vector of bytes
/// exists and contains a vector of length greater than 0
#[allow(unused_macros)]
macro_rules! bytes_attr_not_empty {
    ($obj:expr; $id:expr) => {
        match $obj.get_attr_as_bytes($id) {
            Ok(e) => {
                if e.len() == 0 {
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
    };
}

/// Performs common validation checks for RSA key attributes during object creation.
///
/// Checks for:
/// - Presence and consistency of CKA_MODULUS and CKA_MODULUS_BITS.
/// - Minimum modulus size.
/// - Presence of required attributes based on CKA_CLASS (Public/Private).
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

fn rsa_check_public_key_info(obj: &mut Object) -> Result<()> {
    // Get modulus and public exponent.
    let modulus = obj.get_attr_as_bytes(CKA_MODULUS)?;
    let pubexp = obj.get_attr_as_bytes(CKA_PUBLIC_EXPONENT)?;

    // Create RsaPublicKey.
    // Note: The RsaPublicKey struct is defined in `kasn1/pkcs.rs`.
    let rsa_pub_key = pkcs::RsaPublicKey::new(modulus, pubexp)?.serialize()?;

    // Check if CKA_PUBLIC_KEY_INFO is already there.
    obj.ensure_bytes(
        CKA_PUBLIC_KEY_INFO,
        pkcs::SubjectPublicKeyInfo::new(pkcs::RSA_ALG, &rsa_pub_key)?
            .serialize()?,
    )?;

    Ok(())
}

/// The RSA Public-Key Factory.
#[derive(Debug)]
pub struct RSAPubFactory {
    data: ObjectFactoryData,
}

impl RSAPubFactory {
    /// Initializes a new RSA Public-Key factory.
    ///
    /// Sets up common public key attributes and RSA-specific required attributes
    /// like CKA_MODULUS and CKA_PUBLIC_EXPONENT.
    pub fn new() -> RSAPubFactory {
        let mut factory: RSAPubFactory = RSAPubFactory {
            data: ObjectFactoryData::new(CKO_PUBLIC_KEY),
        };

        factory.add_common_public_key_attrs();

        let attributes = factory.data.get_attributes_mut();

        attributes.push(attr_element!(
            CKA_MODULUS; OAFlags::RequiredOnCreate | OAFlags::Unchangeable;
            Attribute::from_bytes; val Vec::new()));
        attributes.push(attr_element!(
            CKA_MODULUS_BITS; OAFlags::RequiredOnGenerate
            | OAFlags::Unchangeable; Attribute::from_ulong; val 0));
        attributes.push(attr_element!(
            CKA_PUBLIC_EXPONENT; OAFlags::RequiredOnCreate
            | OAFlags::Unchangeable; Attribute::from_bytes; val Vec::new()));

        factory.data.finalize();

        factory
    }
}
impl ObjectFactory for RSAPubFactory {
    /// Creates an RSA Public-Key Object from a template.
    ///
    /// Validates that the provided attributes are consistent with the
    /// factory via [KeyFactory::key_create()] and performs
    /// RSA-specific checks using [rsa_check_import].
    fn create(&self, template: &[CK_ATTRIBUTE]) -> Result<Object> {
        let mut obj = self.key_create(template)?;

        rsa_check_import(&mut obj)?;

        rsa_check_public_key_info(&mut obj)?;

        Ok(obj)
    }

    fn get_data(&self) -> &ObjectFactoryData {
        &self.data
    }
    fn get_data_mut(&mut self) -> &mut ObjectFactoryData {
        &mut self.data
    }

    fn as_key_factory(&self) -> Result<&dyn KeyFactory> {
        Ok(self)
    }

    fn as_public_key_factory(&self) -> Result<&dyn PubKeyFactory> {
        Ok(self)
    }
}

impl KeyFactory for RSAPubFactory {}

impl PubKeyFactory for RSAPubFactory {
    /// For RSA the private key object must carry the public exponent
    /// as well so this is somewhat of a silly op
    fn pub_from_private(
        &self,
        key: &Object,
        template: CkAttrs,
    ) -> Result<Object> {
        let mut template: CkAttrs<'_> = template;
        if let Some(modulus) = key.get_attr(CKA_MODULUS) {
            template.add_slice(CKA_MODULUS, modulus.get_value().as_slice())?;
        } else {
            return Err(CKR_KEY_UNEXTRACTABLE)?;
        }
        if let Some(pubexp) = key.get_attr(CKA_PUBLIC_EXPONENT) {
            template.add_slice(
                CKA_PUBLIC_EXPONENT,
                pubexp.get_value().as_slice(),
            )?;
        } else {
            return Err(CKR_KEY_UNEXTRACTABLE)?;
        }

        self.create(template.as_slice())
    }
}

/// Represents the ASN.1 Version field (integer). Always 0 for standard RSA keys.
type Version = u64;

/// Represents the ASN.1 structure `OtherPrimeInfo` for multi-prime RSA
///
/// Defined in [RFC 8017](https://www.rfc-editor.org/rfc/rfc8017).
#[derive(asn1::Asn1Read, asn1::Asn1Write)]
struct OtherPrimeInfo<'a> {
    prime: DerEncBigUint<'a>,
    exponent: DerEncBigUint<'a>,
    coefficient: DerEncBigUint<'a>,
}

/// Represents the ASN.1 structure `RSAPrivateKey`
///
/// Defined in [RFC 8017](https://www.rfc-editor.org/rfc/rfc8017).
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
    /// Constructs an `RSAPrivateKey` ASN.1 structure from byte slices of its components.
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

/// The RSA Private-Key Factory.
#[derive(Debug)]
pub struct RSAPrivFactory {
    data: ObjectFactoryData,
}

impl RSAPrivFactory {
    /// Initializes a new RSA Private-Key factory.
    ///
    /// Sets up common private key attributes and all RSA private key component
    /// attributes (CKA_MODULUS, CKA_PUBLIC_EXPONENT, CKA_PRIVATE_EXPONENT, CKA_PRIME_1, etc.).
    /// Sets CKA_PRIVATE defaults appropriately.
    pub fn new() -> RSAPrivFactory {
        let mut factory: RSAPrivFactory = RSAPrivFactory {
            data: ObjectFactoryData::new(CKO_PRIVATE_KEY),
        };

        factory.add_common_private_key_attrs();

        let attributes = factory.data.get_attributes_mut();

        attributes.push(attr_element!(
            CKA_MODULUS; OAFlags::RequiredOnCreate | OAFlags::Unchangeable;
            Attribute::from_bytes; val Vec::new()));
        attributes.push(attr_element!(
            CKA_PUBLIC_EXPONENT; OAFlags::RequiredOnCreate
            | OAFlags::Unchangeable; Attribute::from_bytes; val Vec::new()));
        attributes.push(attr_element!(
            CKA_PRIVATE_EXPONENT; OAFlags::Sensitive
            | OAFlags::RequiredOnCreate | OAFlags::SettableOnlyOnCreate
            | OAFlags::Unchangeable; Attribute::from_bytes; val Vec::new()));
        attributes.push(attr_element!(
            CKA_PRIME_1; OAFlags::Sensitive | OAFlags::SettableOnlyOnCreate
            | OAFlags::Unchangeable; Attribute::from_bytes; val Vec::new()));
        attributes.push(attr_element!(
            CKA_PRIME_2; OAFlags::Sensitive | OAFlags::SettableOnlyOnCreate
            | OAFlags::Unchangeable; Attribute::from_bytes; val Vec::new()));
        attributes.push(attr_element!(
            CKA_EXPONENT_1; OAFlags::Sensitive | OAFlags::SettableOnlyOnCreate
            | OAFlags::Unchangeable; Attribute::from_bytes; val Vec::new()));
        attributes.push(attr_element!(
            CKA_EXPONENT_2; OAFlags::Sensitive | OAFlags::SettableOnlyOnCreate
            | OAFlags::Unchangeable; Attribute::from_bytes; val Vec::new()));
        attributes.push(attr_element!(
            CKA_COEFFICIENT; OAFlags::Sensitive | OAFlags::SettableOnlyOnCreate
            | OAFlags::Unchangeable; Attribute::from_bytes; val Vec::new()));

        factory.data.finalize();

        factory
    }
}
impl ObjectFactory for RSAPrivFactory {
    /// Creates an RSA Private-Key Object from a template.
    ///
    /// Validates that the provided attributes are consistent with the
    /// factory via [KeyFactory::key_create()] and performs
    /// RSA-specific checks using [rsa_check_import].
    fn create(&self, template: &[CK_ATTRIBUTE]) -> Result<Object> {
        let mut obj = self.key_create(template)?;

        rsa_check_import(&mut obj)?;

        rsa_check_public_key_info(&mut obj)?;

        Ok(obj)
    }

    fn get_data(&self) -> &ObjectFactoryData {
        &self.data
    }
    fn get_data_mut(&mut self) -> &mut ObjectFactoryData {
        &mut self.data
    }

    fn as_key_factory(&self) -> Result<&dyn KeyFactory> {
        Ok(self)
    }
}

impl KeyFactory for RSAPrivFactory {
    /// Exports the RSA private key material in PKCS#8 format for wrapping.
    ///
    /// Checks if the key is extractable (CKA_EXTRACTABLE=true).
    /// Constructs an ASN.1 `RSAPrivateKey` structure from the key's attributes.
    /// Wraps the `RSAPrivateKey` bytes inside a PKCS#8 `PrivateKeyInfo` structure.
    ///
    /// Returns the DER-encoded `PrivateKeyInfo`.
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
        let pkeyinfo = PrivateKeyInfo::new(&pkey.as_slice(), pkcs::RSA_ALG)?;

        match asn1::write_single(&pkeyinfo) {
            Ok(x) => Ok(x),
            Err(_) => Err(CKR_GENERAL_ERROR)?,
        }
    }

    /// Imports an RSA private key from wrapped data (expected PKCS#8 format).
    ///
    /// Creates a base private key object using the template and factory defaults.
    /// Parses the input data as a DER-encoded PKCS#8 `PrivateKeyInfo`.
    /// Validates the AlgorithmIdentifier OID is for RSA.
    /// Parses the inner `privateKey` OCTET STRING as an `RSAPrivateKey` structure.
    /// Sets the attributes of the new key object based on the parsed ASN.1 components.
    /// Returns the newly created key object.
    fn import_from_wrapped(
        &self,
        data: Vec<u8>,
        template: &[CK_ATTRIBUTE],
    ) -> Result<Object> {
        let mut key = self.key_unwrap(template)?;

        key.ensure_ulong(CKA_CLASS, CKO_PRIVATE_KEY)?;
        key.ensure_ulong(CKA_KEY_TYPE, CKK_RSA)
            .map_err(|_| CKR_TEMPLATE_INCONSISTENT)?;

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
        if pkeyinfo.get_algorithm() != &pkcs::RSA_ALG {
            return Err(CKR_WRAPPED_KEY_INVALID)?;
        }
        let rsapkey = match asn1::parse_single::<RSAPrivateKey>(
            pkeyinfo.get_private_key(),
        ) {
            Ok(k) => k,
            Err(_) => return Err(CKR_WRAPPED_KEY_INVALID)?,
        };

        key.ensure_bytes(
            CKA_MODULUS,
            rsapkey.modulus.as_nopad_bytes().to_vec(),
        )?;
        key.ensure_bytes(
            CKA_PUBLIC_EXPONENT,
            rsapkey.public_exponent.as_nopad_bytes().to_vec(),
        )?;
        key.ensure_bytes(
            CKA_PRIVATE_EXPONENT,
            rsapkey.private_exponent.as_nopad_bytes().to_vec(),
        )?;
        key.ensure_bytes(
            CKA_PRIME_1,
            rsapkey.prime1.as_nopad_bytes().to_vec(),
        )?;
        key.ensure_bytes(
            CKA_PRIME_2,
            rsapkey.prime2.as_nopad_bytes().to_vec(),
        )?;
        key.ensure_bytes(
            CKA_EXPONENT_1,
            rsapkey.exponent1.as_nopad_bytes().to_vec(),
        )?;
        key.ensure_bytes(
            CKA_EXPONENT_2,
            rsapkey.exponent2.as_nopad_bytes().to_vec(),
        )?;
        key.ensure_bytes(
            CKA_COEFFICIENT,
            rsapkey.coefficient.as_nopad_bytes().to_vec(),
        )?;

        rsa_check_public_key_info(&mut key)?;

        Ok(key)
    }
}

impl PrivKeyFactory for RSAPrivFactory {}

/// Object representing various RSA mechanisms (PKCS#1 v1.5, PSS, OAEP).
#[derive(Debug)]
struct RsaPKCSMechanism {
    info: CK_MECHANISM_INFO,
}

impl Mechanism for RsaPKCSMechanism {
    fn info(&self) -> &CK_MECHANISM_INFO {
        &self.info
    }

    /// Initializes an RSA encryption operation.
    ///
    /// Checks mechanism flags and key suitability, then delegates to
    /// [RsaPKCSOperation::encrypt_new].
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

    /// Initializes an RSA decryption operation.
    ///
    /// Checks mechanism flags and key suitability, then delegates to
    /// [RsaPKCSOperation::decrypt_new].
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

    /// Initializes an RSA signing operation.
    ///
    /// Checks mechanism flags and key suitability, then delegates to
    /// [RsaPKCSOperation::sign_new].
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

    /// Initializes an RSA verification operation.
    ///
    /// Checks mechanism flags and key suitability, then delegates to
    /// [RsaPKCSOperation::verify_new].
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

    /// Initializes an RSA verification operation front-loading the
    /// signature to verify.
    ///
    /// Checks mechanism flags and key suitability, then delegates to
    /// [RsaPKCSOperation::verify_signature_new].
    fn verify_signature_new(
        &self,
        mech: &CK_MECHANISM,
        key: &Object,
        signature: &[u8],
    ) -> Result<Box<dyn VerifySignature>> {
        if self.info.flags & CKF_VERIFY != CKF_VERIFY {
            return Err(CKR_MECHANISM_INVALID)?;
        }
        match key.check_key_ops(CKO_PUBLIC_KEY, CKK_RSA, CKA_VERIFY) {
            Ok(_) => (),
            Err(e) => return Err(e),
        }
        Ok(Box::new(RsaPKCSOperation::verify_signature_new(
            mech, key, &self.info, signature,
        )?))
    }

    /// Generates an RSA key pair.
    ///
    /// Creates preliminary public and private key objects based on templates
    /// and factory defaults.
    ///
    /// Extracts modulus bits and public exponent (defaulting to 65537 if not
    /// provided) from the public key template.
    ///
    /// Delegates actual key generation to [RsaPKCSOperation::generate_keypair].
    ///
    /// Sets default attributes (like CKA_LOCAL) on the generated keys.
    fn generate_keypair(
        &self,
        mech: &CK_MECHANISM,
        pubkey_template: &[CK_ATTRIBUTE],
        prikey_template: &[CK_ATTRIBUTE],
    ) -> Result<(Object, Object)> {
        let mut pubkey = PUBLIC_KEY_FACTORY
            .as_key_factory()?
            .key_generate(pubkey_template)?;
        pubkey
            .ensure_ulong(CKA_CLASS, CKO_PUBLIC_KEY)
            .map_err(|_| CKR_TEMPLATE_INCONSISTENT)?;
        pubkey
            .ensure_ulong(CKA_KEY_TYPE, CKK_RSA)
            .map_err(|_| CKR_TEMPLATE_INCONSISTENT)?;

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

        let mut privkey = PRIVATE_KEY_FACTORY
            .as_key_factory()?
            .key_generate(prikey_template)?;
        privkey
            .ensure_ulong(CKA_CLASS, CKO_PRIVATE_KEY)
            .map_err(|_| CKR_TEMPLATE_INCONSISTENT)?;
        privkey
            .ensure_ulong(CKA_KEY_TYPE, CKK_RSA)
            .map_err(|_| CKR_TEMPLATE_INCONSISTENT)?;

        RsaPKCSOperation::generate_keypair(
            exponent,
            bits,
            &mut pubkey,
            &mut privkey,
        )?;
        default_key_attributes(&mut privkey, mech.mechanism)?;
        default_key_attributes(&mut pubkey, mech.mechanism)?;

        rsa_check_public_key_info(&mut pubkey)?;
        /* copy the calculated CKA_PUBLIC_KEY_INFO to the private key */
        privkey.ensure_slice(
            CKA_PUBLIC_KEY_INFO,
            pubkey.get_attr_as_bytes(CKA_PUBLIC_KEY_INFO)?,
        )?;

        Ok((pubkey, privkey))
    }

    /// Wraps a key using RSA.
    ///
    /// Checks mechanism flags and key suitability.
    ///
    /// Exports the key-to-be-wrapped using its factory's
    /// `export_for_wrapping`.
    ///
    /// Delegates the actual wrapping operation to [RsaPKCSOperation::wrap].
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
            key_template.as_key_factory()?.export_for_wrapping(key)?,
            data,
            &self.info,
        )
    }

    /// Unwraps a key using RSA.
    ///
    /// Checks mechanism flags and key suitability.
    ///
    /// Delegates the actual unwrapping operation to
    /// [RsaPKCSOperation::unwrap] to get the raw key bytes.
    ///
    /// Imports the raw key bytes into a new key object using the target
    /// factory's `import_from_wrapped`.
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
        key_template
            .as_key_factory()?
            .import_from_wrapped(keydata, template)
    }
}

/// Returns the NIST SP800-57 security strength (in bits) provided by an RSA
/// key of the given modulus size in bits.
fn rsa_security_bits(modulus_bits: usize) -> usize {
    match modulus_bits {
        b if b >= 15360 => 256,
        b if b >= 7680 => 192,
        b if b >= 3072 => 128,
        b if b >= 2048 => 112,
        b if b >= 1024 => 80,
        _ => 0,
    }
}

#[cfg(test)]
mod weak_wrap_tests {
    use super::rsa_security_bits;
    use crate::misc::is_weak_key_wrap;

    /// Convenience helper mirroring the decision made in `wrap_key`: does
    /// wrapping an `aes_bits` AES key with an RSA key of `rsa_bits` modulus
    /// trigger the weak-wrap warning?
    fn warns(rsa_bits: usize, aes_bits: usize) -> bool {
        is_weak_key_wrap(rsa_security_bits(rsa_bits), aes_bits)
    }

    #[test]
    fn rsa_security_strength_mapping() {
        assert_eq!(rsa_security_bits(2048), 112);
        assert_eq!(rsa_security_bits(3072), 128);
        assert_eq!(rsa_security_bits(4096), 128);
        assert_eq!(rsa_security_bits(7680), 192);
        assert_eq!(rsa_security_bits(15360), 256);
    }

    #[test]
    fn rsa2048_warns_only_above_aes128() {
        /* RSA-2048 (112 bits): AES-128 tolerated, AES-192/256 flagged */
        assert!(!warns(2048, 128));
        assert!(warns(2048, 192));
        assert!(warns(2048, 256));
    }

    #[test]
    fn rsa3072_4096_warn_above_aes128() {
        /* RSA-3072/4096 (128 bits): AES-128 fine, anything above flagged */
        assert!(!warns(3072, 128));
        assert!(warns(3072, 256));
        assert!(!warns(4096, 128));
        assert!(warns(4096, 192));
        assert!(warns(4096, 256));
    }

    #[test]
    fn large_rsa_does_not_warn() {
        /* RSA-7680 (192 bits) and RSA-15360 (256 bits) cover the AES sizes */
        assert!(!warns(7680, 192));
        assert!(warns(7680, 256));
        assert!(!warns(15360, 256));
    }
}

/// Object implementing the CKM_RSA_AES_KEY_WRAP composite mechanism.
///
/// [RSA AES KEY WRAP](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203524)
/// (Version 3.1)
///
/// The mechanism wraps a target key by:
///  1. generating a fresh random temporary AES key,
///  2. wrapping the target key with AES Key Wrap with Padding
///     (`CKM_AES_KEY_WRAP_KWP`, NIST SP800-38F),
///  3. wrapping the temporary AES key with RSA-OAEP.
///
/// The wrapped output is the RSA-OAEP wrapped temporary AES key concatenated
/// with the AES-KWP wrapped target key.
#[derive(Debug)]
struct RsaAesKeyWrapMechanism {
    info: CK_MECHANISM_INFO,
}

impl RsaAesKeyWrapMechanism {
    /// Validates the requested temporary AES key size and returns its length
    /// in bytes.
    fn aes_key_bytes(aes_key_bits: CK_ULONG) -> Result<usize> {
        match aes_key_bits {
            128 => Ok(16),
            192 => Ok(24),
            256 => Ok(32),
            _ => Err(CKR_MECHANISM_PARAM_INVALID)?,
        }
    }

    /// Builds the inner CKM_RSA_PKCS_OAEP mechanism from the parameters of the
    /// CKM_RSA_AES_KEY_WRAP mechanism.
    fn oaep_mechanism(
        params: &CK_RSA_AES_KEY_WRAP_PARAMS,
    ) -> Result<CK_MECHANISM> {
        if params.pOAEPParams.is_null() {
            return Err(CKR_MECHANISM_PARAM_INVALID)?;
        }
        Ok(CK_MECHANISM {
            mechanism: CKM_RSA_PKCS_OAEP,
            pParameter: params.pOAEPParams as CK_VOID_PTR,
            ulParameterLen: CK_ULONG::try_from(std::mem::size_of::<
                CK_RSA_PKCS_OAEP_PARAMS,
            >())?,
        })
    }

    /// The inner AES Key Wrap with Padding mechanism, which takes no
    /// parameters.
    fn kwp_mechanism() -> CK_MECHANISM {
        CK_MECHANISM {
            mechanism: CKM_AES_KEY_WRAP_KWP,
            pParameter: std::ptr::null_mut(),
            ulParameterLen: 0,
        }
    }

    /// Constructs an in-memory, ephemeral AES key object from raw bytes to be
    /// used solely for the internal AES-KWP operation.
    fn ephemeral_aes_key(value: &[u8]) -> Result<Object> {
        let mut key = Object::new(CKO_SECRET_KEY);
        key.set_zeroize();
        key.set_attr(Attribute::from_ulong(CKA_KEY_TYPE, CKK_AES))?;
        key.set_attr(Attribute::from_ulong(
            CKA_VALUE_LEN,
            CK_ULONG::try_from(value.len())?,
        ))?;
        key.set_attr(Attribute::from_bytes(CKA_VALUE, value.to_vec()))?;
        Ok(key)
    }

    /// Generates an in-memory, ephemeral AES key object of `aes_len` bytes.
    ///
    /// This routes through [default_secret_key_generate], the same
    /// CSPRNG-backed helper used to generate all other secret keys in the
    /// token, so the temporary key benefits from the exact same generation
    /// path. The object is kept in memory only, never stored, and is used
    /// solely for the internal AES-KWP operation.
    fn generate_ephemeral_aes_key(aes_len: usize) -> Result<Object> {
        let mut key = Object::new(CKO_SECRET_KEY);
        key.set_zeroize();
        key.set_attr(Attribute::from_ulong(CKA_KEY_TYPE, CKK_AES))?;
        key.set_attr(Attribute::from_ulong(
            CKA_VALUE_LEN,
            CK_ULONG::try_from(aes_len)?,
        ))?;
        default_secret_key_generate(&mut key)?;
        Ok(key)
    }
}

impl Mechanism for RsaAesKeyWrapMechanism {
    fn info(&self) -> &CK_MECHANISM_INFO {
        &self.info
    }

    /// Implements the RSA AES key wrap operation (Wrap)
    ///
    /// [RSA AES KEY WRAP](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203524)
    /// (Version 3.1)
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

        /* the wrapping key must be an RSA public key */
        if wrapping_key.get_attr_as_ulong(CKA_CLASS)? != CKO_PUBLIC_KEY
            || wrapping_key.get_attr_as_ulong(CKA_KEY_TYPE)? != CKK_RSA
        {
            return Err(CKR_WRAPPING_KEY_TYPE_INCONSISTENT)?;
        }

        let params = mech.get_parameters::<CK_RSA_AES_KEY_WRAP_PARAMS>()?;
        let aes_len = Self::aes_key_bytes(params.ulAESKeyBits)?;
        let oaep_mech = Self::oaep_mechanism(&params)?;
        let kwp_mech = Self::kwp_mechanism();

        /* the RSA-OAEP wrapped temporary AES key (C1) has the size of the
         * RSA modulus */
        let modulus_len = wrapping_key.get_attr_as_bytes(CKA_MODULUS)?.len();

        /* warn if the wrapping key is weaker than the wrapped AES key */
        warn_weak_key_wrap(
            rsa_security_bits(modulus_len * 8),
            usize::try_from(params.ulAESKeyBits)?,
        );

        /* export the target key material to be wrapped */
        let mut keydata =
            key_template.as_key_factory()?.export_for_wrapping(key)?;

        /* AES-KWP output length (C2), per NIST SP800-38F: the input padded to
         * an 8-byte boundary plus an 8-byte integrity check block */
        let c2_len = ((keydata.len() + AES_BLOCK_SIZE - 1) / 8) * 8;
        let needed = modulus_len + c2_len;
        if data.is_empty() {
            zeromem(keydata.as_mut_slice());
            return Ok(needed);
        }
        if data.len() < needed {
            zeromem(keydata.as_mut_slice());
            return Err(Error::buf_too_small(needed));
        }

        /* generate the ephemeral AES key using secret key generation */
        let aesobj = match Self::generate_ephemeral_aes_key(aes_len) {
            Ok(o) => o,
            Err(e) => {
                zeromem(keydata.as_mut_slice());
                return Err(e);
            }
        };
        let mut aeskey = match aesobj.get_attr_as_bytes(CKA_VALUE) {
            Ok(v) => v.clone(),
            Err(e) => {
                zeromem(keydata.as_mut_slice());
                return Err(e);
            }
        };

        /* wrap the target key with AES-KWP into the tail of the output
         * (keydata is consumed and zeroized by AesOperation::wrap) */
        let c2_written = match AesOperation::wrap(
            &kwp_mech,
            &aesobj,
            keydata,
            &mut data[modulus_len..needed],
        ) {
            Ok(len) => len,
            Err(e) => {
                zeromem(aeskey.as_mut_slice());
                return Err(e);
            }
        };

        /* wrap the ephemeral AES key with RSA-OAEP into the head of the output
         * (aeskey is consumed and zeroized by RsaPKCSOperation::wrap) */
        let c1_written = match RsaPKCSOperation::wrap(
            &oaep_mech,
            wrapping_key,
            aeskey,
            &mut data[..modulus_len],
            &self.info,
        ) {
            Ok(len) => len,
            Err(e) => {
                /* scrub the AES-KWP output already written */
                zeromem(&mut data[..needed]);
                return Err(e);
            }
        };

        Ok(c1_written + c2_written)
    }

    /// Implements the RSA AES key wrap operation (Unwrap)
    ///
    /// [RSA AES KEY WRAP](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203524)
    /// (Version 3.1)
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

        /* the unwrapping key must be an RSA private key */
        if wrapping_key.get_attr_as_ulong(CKA_CLASS)? != CKO_PRIVATE_KEY
            || wrapping_key.get_attr_as_ulong(CKA_KEY_TYPE)? != CKK_RSA
        {
            return Err(CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT)?;
        }

        let params = mech.get_parameters::<CK_RSA_AES_KEY_WRAP_PARAMS>()?;
        let aes_len = Self::aes_key_bytes(params.ulAESKeyBits)?;
        let oaep_mech = Self::oaep_mechanism(&params)?;
        let kwp_mech = Self::kwp_mechanism();

        /* the RSA-OAEP wrapped temporary AES key (C1) is exactly one RSA
         * block long, the remainder is the AES-KWP wrapped target key (C2) */
        let modulus_len = wrapping_key.get_attr_as_bytes(CKA_MODULUS)?.len();
        if data.len() <= modulus_len {
            return Err(CKR_WRAPPED_KEY_LEN_RANGE)?;
        }
        let (c1, c2) = data.split_at(modulus_len);

        /* recover the temporary AES key with RSA-OAEP */
        let mut aeskey =
            RsaPKCSOperation::unwrap(&oaep_mech, wrapping_key, c1, &self.info)?;
        if aeskey.len() != aes_len {
            zeromem(aeskey.as_mut_slice());
            return Err(CKR_WRAPPED_KEY_INVALID)?;
        }
        let aesobj = match Self::ephemeral_aes_key(&aeskey) {
            Ok(o) => o,
            Err(e) => {
                zeromem(aeskey.as_mut_slice());
                return Err(e);
            }
        };
        zeromem(aeskey.as_mut_slice());

        /* recover the target key material with AES-KWP */
        let keydata = AesOperation::unwrap(&kwp_mech, &aesobj, c2)?;

        key_template
            .as_key_factory()?
            .import_from_wrapped(keydata, template)
    }
}
