// Copyright 2024 Simo Sorce
// See LICENSE.txt file for terms

//! This module implements the PKCS#11 mechanisms for AES as defined in
//! [FIPS 197](https://doi.org/10.6028/NIST.FIPS.197-upd1):
//! _Advanced Encryption Standard (AES)_ and various NIST Special
//! Publications (e.g., [SP 800-38A](https://doi.org/10.6028/NIST.SP.800-38A):
//! _Recommendation for Block Cipher Modes of Operation: Methods and
//! Techniques_, [SP 800-38D](https://doi.org/10.6028/NIST.SP.800-38D):
//! _Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode
//! (GCM) and GMAC_).

use std::fmt::Debug;
use std::sync::LazyLock;

use crate::attribute::Attribute;
use crate::error::Result;
use crate::mechanism::*;
use crate::misc::{cast_params, zeromem};
use crate::object::*;
use crate::ossl::aes::*;
use crate::pkcs11::*;

/// Smallest AES Key Size (128 bits)
pub const MIN_AES_SIZE_BYTES: usize = 16; /* 128 bits */
/// Medium AES Key size (192 bits)
pub const MID_AES_SIZE_BYTES: usize = 24; /* 192 bits */
/// Largest AES Key Size (256 bits)
pub const MAX_AES_SIZE_BYTES: usize = 32; /* 256 bits */

/// Object that holds AES Mechanisms
pub(crate) static AES_MECHS: LazyLock<[Box<dyn Mechanism>; 6]> =
    LazyLock::new(|| {
        [
            Box::new(AesMechanism {
                info: CK_MECHANISM_INFO {
                    ulMinKeySize: CK_ULONG::try_from(MIN_AES_SIZE_BYTES)
                        .unwrap(),
                    ulMaxKeySize: CK_ULONG::try_from(MAX_AES_SIZE_BYTES)
                        .unwrap(),
                    flags: CKF_ENCRYPT | CKF_DECRYPT | CKF_WRAP | CKF_UNWRAP,
                },
            }),
            Box::new(AesMechanism {
                info: CK_MECHANISM_INFO {
                    ulMinKeySize: CK_ULONG::try_from(MIN_AES_SIZE_BYTES)
                        .unwrap(),
                    ulMaxKeySize: CK_ULONG::try_from(MAX_AES_SIZE_BYTES)
                        .unwrap(),
                    flags: CKF_ENCRYPT
                        | CKF_DECRYPT
                        | CKF_WRAP
                        | CKF_UNWRAP
                        | CKF_MESSAGE_ENCRYPT
                        | CKF_MESSAGE_DECRYPT
                        | CKF_MULTI_MESSAGE,
                },
            }),
            Box::new(AesMechanism {
                info: CK_MECHANISM_INFO {
                    ulMinKeySize: CK_ULONG::try_from(MIN_AES_SIZE_BYTES)
                        .unwrap(),
                    ulMaxKeySize: CK_ULONG::try_from(MAX_AES_SIZE_BYTES)
                        .unwrap(),
                    flags: CKF_ENCRYPT | CKF_DECRYPT,
                },
            }),
            Box::new(AesMechanism {
                info: CK_MECHANISM_INFO {
                    ulMinKeySize: CK_ULONG::try_from(MIN_AES_SIZE_BYTES)
                        .unwrap(),
                    ulMaxKeySize: CK_ULONG::try_from(MAX_AES_SIZE_BYTES)
                        .unwrap(),
                    flags: CKF_GENERATE,
                },
            }),
            Box::new(AesMechanism {
                info: CK_MECHANISM_INFO {
                    ulMinKeySize: CK_ULONG::try_from(MIN_AES_SIZE_BYTES)
                        .unwrap(),
                    ulMaxKeySize: CK_ULONG::try_from(MAX_AES_SIZE_BYTES)
                        .unwrap(),
                    flags: CKF_SIGN | CKF_VERIFY,
                },
            }),
            Box::new(AesMechanism {
                info: CK_MECHANISM_INFO {
                    ulMinKeySize: CK_ULONG::try_from(MIN_AES_SIZE_BYTES)
                        .unwrap(),
                    ulMaxKeySize: CK_ULONG::try_from(MAX_AES_SIZE_BYTES)
                        .unwrap(),
                    flags: CKF_DERIVE,
                },
            }),
        ]
    });

/// The AES Key Factory facility.
static AES_KEY_FACTORY: LazyLock<Box<dyn ObjectFactory>> =
    LazyLock::new(|| Box::new(AesKeyFactory::new()));

/// Registers all implemented AES Mechanisms and Factories
pub fn register(mechs: &mut Mechanisms, ot: &mut ObjectFactories) {
    AesOperation::register_mechanisms(mechs);
    AesKDFOperation::register_mechanisms(mechs);
    #[cfg(not(feature = "fips"))]
    AesMacOperation::register_mechanisms(mechs);
    AesCmacOperation::register_mechanisms(mechs);

    ot.add_factory(
        ObjectType::new(CKO_SECRET_KEY, CKK_AES),
        &(*AES_KEY_FACTORY),
    );
}

/// The AES block size is 128 bits (16 bytes) for all currently implemented
/// variants
pub const AES_BLOCK_SIZE: usize = 16;

pub(crate) fn check_key_len(len: usize) -> Result<()> {
    match len {
        16 | 24 | 32 => Ok(()),
        _ => Err(CKR_KEY_SIZE_RANGE)?,
    }
}

/// This is a specialized factory for objects of class CKO_SECRET_KEY
/// and CKA_KEY_TYPE of value CKK_AES
///
/// [AES secret key objects](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203476)
/// (Version 3.1)
///
/// Derives from the generic ObjectFactory, CommonKeyFactory and
/// SecretKeyFactory
///
/// This is used to store the list of attributes allowed for an AES Key object, as well as provide
/// methods for generic manipulation of AES key objects (generation, derivation, wrapping ...)
///

#[derive(Debug, Default)]
pub struct AesKeyFactory {
    data: ObjectFactoryData,
}

impl AesKeyFactory {
    fn new() -> AesKeyFactory {
        let mut factory: AesKeyFactory = Default::default();

        factory.add_common_secret_key_attrs();

        let attributes = factory.data.get_attributes_mut();

        attributes.push(attr_element!(
            CKA_VALUE; OAFlags::Defval | OAFlags::Sensitive
            | OAFlags::RequiredOnCreate | OAFlags::SettableOnlyOnCreate;
            Attribute::from_bytes; val Vec::new()));
        attributes.push(attr_element!(
            CKA_VALUE_LEN; OAFlags::RequiredOnGenerate;
            Attribute::from_bytes; val Vec::new()));

        factory.data.finalize();

        factory
    }
}

impl ObjectFactory for AesKeyFactory {
    /// Creation of AES keys use the default generic secret creation
    /// code and additionally ensures the key size is one of the AES allowed
    /// sizes (currently 128, 192 or 256 bits).
    fn create(&self, template: &[CK_ATTRIBUTE]) -> Result<Object> {
        let mut obj = self.default_object_create(template)?;
        let len = self.get_key_buffer_len(&obj)?;
        check_key_len(len)?;
        obj.ensure_ulong(CKA_VALUE_LEN, CK_ULONG::try_from(len)?)?;

        Ok(obj)
    }

    fn export_for_wrapping(&self, key: &Object) -> Result<Vec<u8>> {
        SecretKeyFactory::export_for_wrapping(self, key)
    }

    fn import_from_wrapped(
        &self,
        mut data: Vec<u8>,
        template: &[CK_ATTRIBUTE],
    ) -> Result<Object> {
        /* AES keys can only be 16, 24, 32 bytes long,
         * ensure we allow only these sizes */
        match template.iter().position(|x| x.type_ == CKA_VALUE_LEN) {
            Some(idx) => {
                let len = usize::try_from(template[idx].to_ulong()?)?;
                if len > data.len() {
                    zeromem(data.as_mut_slice());
                    return Err(CKR_KEY_SIZE_RANGE)?;
                }
                if len < data.len() {
                    unsafe { data.set_len(len) };
                }
            }
            None => (),
        }
        match check_key_len(data.len()) {
            Ok(_) => (),
            Err(e) => {
                zeromem(data.as_mut_slice());
                return Err(e);
            }
        }
        SecretKeyFactory::import_from_wrapped(self, data, template)
    }

    /// The AES derive adds key length checks on top of the generic secret
    /// derive helper
    fn default_object_derive(
        &self,
        template: &[CK_ATTRIBUTE],
        origin: &Object,
    ) -> Result<Object> {
        let obj = self.internal_object_derive(template, origin)?;

        let key_len = self.get_key_len(&obj);
        if key_len != 0 {
            if check_key_len(key_len).is_err() {
                return Err(CKR_TEMPLATE_INCONSISTENT)?;
            }
        }
        Ok(obj)
    }

    fn as_secret_key_factory(&self) -> Result<&dyn SecretKeyFactory> {
        Ok(self)
    }

    fn get_data(&self) -> &ObjectFactoryData {
        &self.data
    }

    fn get_data_mut(&mut self) -> &mut ObjectFactoryData {
        &mut self.data
    }
}

impl CommonKeyFactory for AesKeyFactory {}

impl SecretKeyFactory for AesKeyFactory {
    /// Helper to set key that check the key is correctly formed for an
    /// AES key object
    fn set_key(&self, obj: &mut Object, key: Vec<u8>) -> Result<()> {
        let keylen = key.len();
        check_key_len(keylen)?;
        obj.set_attr(Attribute::from_bytes(CKA_VALUE, key))?;
        self.set_key_len(obj, keylen)?;
        Ok(())
    }

    /// AES recommends very specific size preferring the largest key size
    /// first and going down from there
    fn recommend_key_size(&self, max: usize) -> Result<usize> {
        if max >= MAX_AES_SIZE_BYTES {
            Ok(MAX_AES_SIZE_BYTES)
        } else if max > MID_AES_SIZE_BYTES {
            Ok(MID_AES_SIZE_BYTES)
        } else if max > MIN_AES_SIZE_BYTES {
            Ok(MIN_AES_SIZE_BYTES)
        } else {
            Err(CKR_KEY_SIZE_RANGE)?
        }
    }
}

/// The Generic AES Mechanism object
///
/// Implements access to the Mechanisms functions applicable to the AES
/// cryptosystem.
/// The mechanism function can implement a crypto operation directly or return
/// an allocated [AesOperation] object for operations that need to keep data
/// around until they complete.

#[derive(Debug)]
pub(crate) struct AesMechanism {
    info: CK_MECHANISM_INFO,
}

impl Mechanism for AesMechanism {
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
        match key.check_key_ops(CKO_SECRET_KEY, CKK_AES, CKA_ENCRYPT) {
            Ok(_) => (),
            Err(e) => return Err(e),
        }
        Ok(Box::new(AesOperation::encrypt_new(mech, key)?))
    }

    fn decryption_new(
        &self,
        mech: &CK_MECHANISM,
        key: &Object,
    ) -> Result<Box<dyn Decryption>> {
        if self.info.flags & CKF_DECRYPT != CKF_DECRYPT {
            return Err(CKR_MECHANISM_INVALID)?;
        }
        match key.check_key_ops(CKO_SECRET_KEY, CKK_AES, CKA_DECRYPT) {
            Ok(_) => (),
            Err(e) => return Err(e),
        }
        Ok(Box::new(AesOperation::decrypt_new(mech, key)?))
    }

    /// Implements the AES Key generation mechanism
    ///
    /// [AES key generation](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203477)
    /// (Version 3.1)

    fn generate_key(
        &self,
        mech: &CK_MECHANISM,
        template: &[CK_ATTRIBUTE],
        _: &Mechanisms,
        _: &ObjectFactories,
    ) -> Result<Object> {
        if mech.mechanism != CKM_AES_KEY_GEN {
            return Err(CKR_MECHANISM_INVALID)?;
        }
        let mut key = AES_KEY_FACTORY.default_object_generate(template)?;
        key.ensure_ulong(CKA_CLASS, CKO_SECRET_KEY)
            .map_err(|_| CKR_TEMPLATE_INCONSISTENT)?;
        key.ensure_ulong(CKA_KEY_TYPE, CKK_AES)
            .map_err(|_| CKR_TEMPLATE_INCONSISTENT)?;

        default_secret_key_generate(&mut key)?;
        default_key_attributes(&mut key, mech.mechanism)?;
        Ok(key)
    }

    /// Implements the AES Key wrap operation (Wrap)
    ///
    /// [AES Key Wrap](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203510)
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

        AesOperation::wrap(
            mech,
            wrapping_key,
            key_template.export_for_wrapping(key)?,
            data,
        )
    }

    /// Implements the AES Key wrap operation (Unwrap)
    ///
    /// [AES Key Wrap](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203510)
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
        let keydata = AesOperation::unwrap(mech, wrapping_key, data)?;
        key_template.import_from_wrapped(keydata, template)
    }

    /// Implements the AES derivation operation
    ///
    /// [Key derivation by data encryption – DES & AES](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203514)
    /// (Version 3.1)

    fn derive_operation(&self, mech: &CK_MECHANISM) -> Result<Box<dyn Derive>> {
        if self.info.flags & CKF_DERIVE != CKF_DERIVE {
            return Err(CKR_MECHANISM_INVALID)?;
        }

        let kdf = match mech.mechanism {
            CKM_AES_ECB_ENCRYPT_DATA => {
                let params = cast_params!(mech, CK_KEY_DERIVATION_STRING_DATA);
                AesKDFOperation::aes_ecb_new(params)?
            }
            CKM_AES_CBC_ENCRYPT_DATA => {
                let params = cast_params!(mech, CK_AES_CBC_ENCRYPT_DATA_PARAMS);
                AesKDFOperation::aes_cbc_new(params)?
            }
            _ => return Err(CKR_MECHANISM_INVALID)?,
        };
        Ok(Box::new(kdf))
    }

    /// Internal interface for MAC operations required by other mechanisms
    fn mac_new(
        &self,
        mech: &CK_MECHANISM,
        key: &Object,
        op_type: CK_FLAGS,
    ) -> Result<Box<dyn Mac>> {
        /* the mechanism advertises only SIGN/VERIFY to the callers
         * DERIVE is a mediated operation so it is not advertised
         * and we do not check it against self.info nor the key */
        if op_type != CKF_DERIVE {
            return Err(CKR_MECHANISM_INVALID)?;
        }
        match mech.mechanism {
            CKM_AES_CMAC | CKM_AES_CMAC_GENERAL => {
                Ok(Box::new(AesCmacOperation::init(mech, key, None)?))
            }
            _ => Err(CKR_MECHANISM_INVALID)?,
        }
    }

    /// Implements AES MAC/CMAC operation (Sign)
    ///
    /// [AES MAC](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203484)
    /// [AES CMAC](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203500)
    /// (version 3.1)

    fn sign_new(
        &self,
        mech: &CK_MECHANISM,
        key: &Object,
    ) -> Result<Box<dyn Sign>> {
        if self.info.flags & CKF_SIGN != CKF_SIGN {
            return Err(CKR_MECHANISM_INVALID)?;
        }
        match key.check_key_ops(CKO_SECRET_KEY, CKK_AES, CKA_SIGN) {
            Ok(_) => (),
            Err(e) => return Err(e),
        }
        match mech.mechanism {
            #[cfg(not(feature = "fips"))]
            CKM_AES_MAC | CKM_AES_MAC_GENERAL => {
                Ok(Box::new(AesMacOperation::init(mech, key, None)?))
            }
            CKM_AES_CMAC | CKM_AES_CMAC_GENERAL => {
                Ok(Box::new(AesCmacOperation::init(mech, key, None)?))
            }
            _ => Err(CKR_MECHANISM_INVALID)?,
        }
    }

    /// Implements AES MAC/CMAC operations (Verify)
    ///
    /// [AES MAC](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203484)
    /// [AES CMAC](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203500)
    /// (version 3.1)

    fn verify_new(
        &self,
        mech: &CK_MECHANISM,
        key: &Object,
    ) -> Result<Box<dyn Verify>> {
        if self.info.flags & CKF_VERIFY != CKF_VERIFY {
            return Err(CKR_MECHANISM_INVALID)?;
        }
        match key.check_key_ops(CKO_SECRET_KEY, CKK_AES, CKA_VERIFY) {
            Ok(_) => (),
            Err(e) => return Err(e),
        }
        match mech.mechanism {
            #[cfg(not(feature = "fips"))]
            CKM_AES_MAC | CKM_AES_MAC_GENERAL => {
                Ok(Box::new(AesMacOperation::init(mech, key, None)?))
            }
            CKM_AES_CMAC | CKM_AES_CMAC_GENERAL => {
                Ok(Box::new(AesCmacOperation::init(mech, key, None)?))
            }
            _ => Err(CKR_MECHANISM_INVALID)?,
        }
    }

    fn verify_signature_new(
        &self,
        mech: &CK_MECHANISM,
        key: &Object,
        signature: &[u8],
    ) -> Result<Box<dyn VerifySignature>> {
        if self.info.flags & CKF_VERIFY != CKF_VERIFY {
            return Err(CKR_MECHANISM_INVALID)?;
        }
        match key.check_key_ops(CKO_SECRET_KEY, CKK_AES, CKA_VERIFY) {
            Ok(_) => (),
            Err(e) => return Err(e),
        }
        match mech.mechanism {
            #[cfg(not(feature = "fips"))]
            CKM_AES_MAC | CKM_AES_MAC_GENERAL => {
                Ok(Box::new(AesMacOperation::init(mech, key, Some(signature))?))
            }
            CKM_AES_CMAC | CKM_AES_CMAC_GENERAL => Ok(Box::new(
                AesCmacOperation::init(mech, key, Some(signature))?,
            )),
            _ => Err(CKR_MECHANISM_INVALID)?,
        }
    }

    fn msg_encryption_op(
        &self,
        mech: &CK_MECHANISM,
        key: &Object,
    ) -> Result<Box<dyn MsgEncryption>> {
        if self.info.flags & CKF_MESSAGE_ENCRYPT == 0 {
            return Err(CKR_MECHANISM_INVALID)?;
        }
        match key.check_key_ops(CKO_SECRET_KEY, CKK_AES, CKA_ENCRYPT) {
            Ok(_) => (),
            Err(e) => return Err(e),
        }
        Ok(Box::new(AesOperation::msg_encrypt_init(mech, key)?))
    }

    fn msg_decryption_op(
        &self,
        mech: &CK_MECHANISM,
        key: &Object,
    ) -> Result<Box<dyn MsgDecryption>> {
        if self.info.flags & CKF_MESSAGE_DECRYPT == 0 {
            return Err(CKR_MECHANISM_INVALID)?;
        }
        match key.check_key_ops(CKO_SECRET_KEY, CKK_AES, CKA_DECRYPT) {
            Ok(_) => (),
            Err(e) => return Err(e),
        }
        Ok(Box::new(AesOperation::msg_decrypt_init(mech, key)?))
    }
}

/// AES KDF Operation implementation
///
/// An AES Operation specific for Key Derivation that uses the AES cipher
/// with various modes as the PRF to compute a derived key
/// Implements [Derive]

#[derive(Debug)]
struct AesKDFOperation<'a> {
    mech: CK_MECHANISM_TYPE,
    finalized: bool,
    iv: &'a [u8],
    data: &'a [u8],
    #[cfg(feature = "fips")]
    fips_approved: Option<bool>,
}

impl AesKDFOperation<'_> {
    /// Helper function to register the AES KDF Mechanisms
    fn register_mechanisms(mechs: &mut Mechanisms) {
        if mechs.get(CKM_AES_ECB).is_ok() {
            mechs.add_mechanism(CKM_AES_ECB_ENCRYPT_DATA, &(*AES_MECHS)[5]);
        }
        if mechs.get(CKM_AES_CBC).is_ok() {
            mechs.add_mechanism(CKM_AES_CBC_ENCRYPT_DATA, &(*AES_MECHS)[5]);
        }
    }

    /// Instantiates a new CKM_AES_ECB based KDF operation
    fn aes_ecb_new<'a>(
        params: CK_KEY_DERIVATION_STRING_DATA,
    ) -> Result<AesKDFOperation<'a>> {
        if params.pData == std::ptr::null_mut()
            || params.ulLen == 0
            || params.ulLen % 16 != 0
        {
            return Err(CKR_MECHANISM_PARAM_INVALID)?;
        }
        Ok(AesKDFOperation {
            mech: CKM_AES_ECB,
            finalized: false,
            iv: &[],
            data: unsafe {
                std::slice::from_raw_parts(
                    params.pData,
                    usize::try_from(params.ulLen)?,
                )
            },
            #[cfg(feature = "fips")]
            fips_approved: None,
        })
    }

    /// Instantiates a new CKM_AES_CBC based KDF operation
    fn aes_cbc_new<'a>(
        params: CK_AES_CBC_ENCRYPT_DATA_PARAMS,
    ) -> Result<AesKDFOperation<'a>> {
        if params.pData == std::ptr::null_mut()
            || params.length == 0
            || params.length % 16 != 0
        {
            return Err(CKR_MECHANISM_PARAM_INVALID)?;
        }
        Ok(AesKDFOperation {
            mech: CKM_AES_CBC,
            finalized: false,
            iv: unsafe { std::slice::from_raw_parts(params.iv.as_ptr(), 16) },
            data: unsafe {
                std::slice::from_raw_parts(
                    params.pData,
                    usize::try_from(params.length)?,
                )
            },
            #[cfg(feature = "fips")]
            fips_approved: None,
        })
    }
}

impl MechOperation for AesKDFOperation<'_> {
    fn mechanism(&self) -> Result<CK_MECHANISM_TYPE> {
        Ok(self.mech)
    }

    fn finalized(&self) -> bool {
        self.finalized
    }
}

impl Derive for AesKDFOperation<'_> {
    /// Derives a Key using the parameters set on the AESKDFOperation object
    fn derive(
        &mut self,
        key: &Object,
        template: &[CK_ATTRIBUTE],
        _mechanisms: &Mechanisms,
        objfactories: &ObjectFactories,
    ) -> Result<Vec<Object>> {
        if self.finalized {
            return Err(CKR_OPERATION_NOT_INITIALIZED)?;
        }
        self.finalized = true;

        key.check_key_ops(CKO_SECRET_KEY, CKK_AES, CKA_DERIVE)?;

        let factory =
            objfactories.get_obj_factory_from_key_template(template)?;
        let mut obj = factory.default_object_derive(template, key)?;

        let mechanism = CK_MECHANISM {
            mechanism: self.mech,
            pParameter: if self.iv.len() > 0 {
                self.iv.as_ptr() as CK_VOID_PTR
            } else {
                std::ptr::null_mut()
            },
            ulParameterLen: CK_ULONG::try_from(self.iv.len())?,
        };
        let mut op = AesOperation::encrypt_new(&mechanism, key)?;

        let keysize = op.encryption_len(self.data.len(), false)?;

        let mut dkm = vec![0u8; keysize];
        let outsize = op.encrypt(self.data, &mut dkm)?;
        if outsize != keysize {
            return Err(CKR_GENERAL_ERROR)?;
        }

        factory.as_secret_key_factory()?.set_key(&mut obj, dkm)?;

        #[cfg(feature = "fips")]
        {
            self.fips_approved = op.fips_approved();
        }
        Ok(vec![obj])
    }
}
