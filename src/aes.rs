// Copyright 2024 Simo Sorce
// See LICENSE.txt file for terms

use std::fmt::Debug;

use crate::attribute::Attribute;
use crate::error::Result;
use crate::interface::*;
use crate::mechanism::*;
use crate::object::*;
use crate::ossl::aes::*;
use crate::{attr_element, cast_params};

use once_cell::sync::Lazy;

use zeroize::Zeroize;

pub const MIN_AES_SIZE_BYTES: usize = 16; /* 128 bits */
pub const MID_AES_SIZE_BYTES: usize = 24; /* 192 bits */
pub const MAX_AES_SIZE_BYTES: usize = 32; /* 256 bits */
pub const AES_BLOCK_SIZE: usize = 16;

pub(crate) fn check_key_len(len: usize) -> Result<()> {
    match len {
        16 | 24 | 32 => Ok(()),
        _ => Err(CKR_KEY_SIZE_RANGE)?,
    }
}

#[derive(Debug)]
pub struct AesKeyFactory {
    attributes: Vec<ObjectAttr>,
}

impl AesKeyFactory {
    fn new() -> AesKeyFactory {
        let mut data: AesKeyFactory = AesKeyFactory {
            attributes: Vec::new(),
        };
        data.attributes.append(&mut data.init_common_object_attrs());
        data.attributes
            .append(&mut data.init_common_storage_attrs());
        data.attributes.append(&mut data.init_common_key_attrs());
        data.attributes
            .append(&mut data.init_common_secret_key_attrs());
        data.attributes.push(attr_element!(
            CKA_VALUE; OAFlags::Defval | OAFlags::Sensitive
            | OAFlags::RequiredOnCreate | OAFlags::SettableOnlyOnCreate;
            Attribute::from_bytes; val Vec::new()));
        data.attributes.push(attr_element!(
            CKA_VALUE_LEN; OAFlags::RequiredOnGenerate;
            Attribute::from_bytes; val Vec::new()));

        /* default to private */
        let private = attr_element!(CKA_PRIVATE; OAFlags::Defval | OAFlags::ChangeOnCopy; Attribute::from_bool; val true);
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

impl ObjectFactory for AesKeyFactory {
    fn create(&self, template: &[CK_ATTRIBUTE]) -> Result<Object> {
        let mut obj = self.default_object_create(template)?;
        let len = self.get_key_buffer_len(&obj)?;
        check_key_len(len)?;
        if !obj.check_or_set_attr(Attribute::from_ulong(
            CKA_VALUE_LEN,
            CK_ULONG::try_from(len)?,
        ))? {
            return Err(CKR_ATTRIBUTE_VALUE_INVALID)?;
        }

        Ok(obj)
    }

    fn get_attributes(&self) -> &Vec<ObjectAttr> {
        &self.attributes
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
                    data.zeroize();
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
                data.zeroize();
                return Err(e);
            }
        }
        SecretKeyFactory::import_from_wrapped(self, data, template)
    }

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
}

impl CommonKeyFactory for AesKeyFactory {}

impl SecretKeyFactory for AesKeyFactory {
    fn default_object_unwrap(
        &self,
        template: &[CK_ATTRIBUTE],
    ) -> Result<Object> {
        ObjectFactory::default_object_unwrap(self, template)
    }

    fn set_key(&self, obj: &mut Object, key: Vec<u8>) -> Result<()> {
        let keylen = key.len();
        check_key_len(keylen)?;
        obj.set_attr(Attribute::from_bytes(CKA_VALUE, key))?;
        self.set_key_len(obj, keylen)?;
        Ok(())
    }

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

static AES_KEY_FACTORY: Lazy<Box<dyn ObjectFactory>> =
    Lazy::new(|| Box::new(AesKeyFactory::new()));

#[derive(Debug)]
pub(crate) struct AesMechanism {
    info: CK_MECHANISM_INFO,
}

impl AesMechanism {
    pub fn new(min: CK_ULONG, max: CK_ULONG, flags: CK_FLAGS) -> AesMechanism {
        AesMechanism {
            info: CK_MECHANISM_INFO {
                ulMinKeySize: min,
                ulMaxKeySize: max,
                flags: flags,
            },
        }
    }
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
        if !key.check_or_set_attr(Attribute::from_ulong(
            CKA_CLASS,
            CKO_SECRET_KEY,
        ))? {
            return Err(CKR_TEMPLATE_INCONSISTENT)?;
        }
        if !key
            .check_or_set_attr(Attribute::from_ulong(CKA_KEY_TYPE, CKK_AES))?
        {
            return Err(CKR_TEMPLATE_INCONSISTENT)?;
        }

        default_secret_key_generate(&mut key)?;
        default_key_attributes(&mut key, mech.mechanism)?;
        Ok(key)
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

        AesOperation::wrap(
            mech,
            wrapping_key,
            key_template.export_for_wrapping(key)?,
            data,
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
        let keydata = AesOperation::unwrap(mech, wrapping_key, data)?;
        key_template.import_from_wrapped(keydata, template)
    }

    fn derive_operation(&self, mech: &CK_MECHANISM) -> Result<Operation> {
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
        Ok(Operation::Derive(Box::new(kdf)))
    }

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
                Ok(Box::new(AesCmacOperation::init(mech, key)?))
            }
            _ => Err(CKR_MECHANISM_INVALID)?,
        }
    }

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
                Ok(Box::new(AesMacOperation::init(mech, key)?))
            }
            CKM_AES_CMAC | CKM_AES_CMAC_GENERAL => {
                Ok(Box::new(AesCmacOperation::init(mech, key)?))
            }
            _ => Err(CKR_MECHANISM_INVALID)?,
        }
    }

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
                Ok(Box::new(AesMacOperation::init(mech, key)?))
            }
            CKM_AES_CMAC | CKM_AES_CMAC_GENERAL => {
                Ok(Box::new(AesCmacOperation::init(mech, key)?))
            }
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
    fn register_mechanisms(mechs: &mut Mechanisms) {
        if mechs.get(CKM_AES_ECB).is_ok() {
            mechs.add_mechanism(
                CKM_AES_ECB_ENCRYPT_DATA,
                Box::new(AesMechanism::new(
                    CK_ULONG::try_from(MIN_AES_SIZE_BYTES).unwrap(),
                    CK_ULONG::try_from(MAX_AES_SIZE_BYTES).unwrap(),
                    CKF_DERIVE,
                )),
            );
        }
        if mechs.get(CKM_AES_CBC).is_ok() {
            mechs.add_mechanism(
                CKM_AES_CBC_ENCRYPT_DATA,
                Box::new(AesMechanism::new(
                    CK_ULONG::try_from(MIN_AES_SIZE_BYTES).unwrap(),
                    CK_ULONG::try_from(MAX_AES_SIZE_BYTES).unwrap(),
                    CKF_DERIVE,
                )),
            );
        }
    }

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

pub fn register(mechs: &mut Mechanisms, ot: &mut ObjectFactories) {
    AesOperation::register_mechanisms(mechs);
    AesKDFOperation::register_mechanisms(mechs);
    #[cfg(not(feature = "fips"))]
    AesMacOperation::register_mechanisms(mechs);
    AesCmacOperation::register_mechanisms(mechs);

    ot.add_factory(ObjectType::new(CKO_SECRET_KEY, CKK_AES), &AES_KEY_FACTORY);
}
