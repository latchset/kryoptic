// Copyright 2023-2026 Simo Sorce
// See LICENSE.txt file for terms

use std::fmt::Debug;
use std::sync::LazyLock;

use crate::attribute::{Attribute, CkAttrs};
use crate::error::Result;
use crate::mechanism::{
    Mac, MechOperation, Mechanism, Mechanisms, Sign, Verify,
};
use crate::native::hmac::HMACOperation;
use crate::object::factory::{
    attr_element, OAFlags, ObjectFactories, ObjectFactory, ObjectFactoryData,
};
use crate::object::key::{
    default_key_attributes, default_secret_key_generate, KeyFactory,
    SecretKeyFactory,
};
use crate::object::otp::OTPKeyFactory;
use crate::object::{Object, ObjectType};
use crate::pkcs11::*;

/// Object that holds HOTP Mechanisms
pub(crate) static HOTP_MECHS: LazyLock<[Box<dyn Mechanism>; 2]> =
    LazyLock::new(|| {
        [
            Box::new(HOTPKeyMechanism::new()),
            Box::new(HOTPMechanism::new()),
        ]
    });

/// The HOTP Key Factory facility.
static HOTP_KEY_FACTORY: LazyLock<Box<dyn ObjectFactory>> =
    LazyLock::new(|| Box::new(HOTPKeyFactory::new()));

/// Registers all implemented HOTP Mechanisms and Factories
pub fn register(mechs: &mut Mechanisms, ot: &mut ObjectFactories) {
    mechs.add_mechanism(CKM_HOTP_KEY_GEN, &(*HOTP_MECHS)[0]);
    mechs.add_mechanism(CKM_HOTP, &(*HOTP_MECHS)[1]);

    ot.add_factory(
        ObjectType::new(CKO_OTP_KEY, CKK_HOTP),
        &(*HOTP_KEY_FACTORY),
    );
}

/// This is a specialized factory for objects of class CKO_OTP_KEY
/// and CKA_KEY_TYPE of value CKK_HOTP
///
/// [HOTP secret key objects](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.2/pkcs11-spec-v3.2.html#_Toc195693654)
#[derive(Debug)]
pub struct HOTPKeyFactory {
    data: ObjectFactoryData,
}

impl HOTPKeyFactory {
    /// Initializes a new HOTPKeyFactory object
    pub fn new() -> HOTPKeyFactory {
        let mut factory = HOTPKeyFactory {
            data: ObjectFactoryData::new(CKO_OTP_KEY),
        };

        factory.add_common_otp_key_attrs();

        let attributes = factory.data.get_attributes_mut();

        attributes.push(attr_element!(
            CKA_VALUE; OAFlags::Sensitive | OAFlags::RequiredOnCreate
            | OAFlags::SettableOnlyOnCreate; Attribute::from_bytes;
            val Vec::new()));
        attributes.push(attr_element!(
            CKA_VALUE_LEN; OAFlags::Defval; Attribute::from_ulong;
            val 20));

        /* default to true CKA_PRIVATE, CKA_SIGN, CKA_VERIFY */
        let private = attr_element!(
            CKA_PRIVATE; OAFlags::Defval | OAFlags::ChangeOnCopy; Attribute::from_bool; val true);
        match attributes.iter().position(|x| x.get_type() == CKA_PRIVATE) {
            Some(idx) => attributes[idx] = private,
            None => attributes.push(private),
        }
        let sign = attr_element!(
            CKA_SIGN; OAFlags::Defval; Attribute::from_bool; val true);
        match attributes.iter().position(|x| x.get_type() == CKA_SIGN) {
            Some(idx) => attributes[idx] = sign,
            None => attributes.push(sign),
        }
        let verify = attr_element!(
            CKA_VERIFY; OAFlags::Defval; Attribute::from_bool; val true);
        match attributes.iter().position(|x| x.get_type() == CKA_VERIFY) {
            Some(idx) => attributes[idx] = verify,
            None => attributes.push(verify),
        }

        /* override CKA_OTP_COUNTER to have 8 bytes of 0s as defval */
        let counter = attr_element!(
            CKA_OTP_COUNTER; OAFlags::Defval | OAFlags::SettableOnlyOnCreate; Attribute::from_bytes;
            val vec![0; 8]);
        match attributes
            .iter()
            .position(|x| x.get_type() == CKA_OTP_COUNTER)
        {
            Some(idx) => attributes[idx] = counter,
            None => attributes.push(counter),
        }

        /* override CKA_OTP_FORMAT to be settable only on creation */
        let format = attr_element!(
            CKA_OTP_FORMAT; OAFlags::Defval | OAFlags::SettableOnlyOnCreate; Attribute::from_ulong;
            val CK_OTP_FORMAT_DECIMAL);
        match attributes
            .iter()
            .position(|x| x.get_type() == CKA_OTP_FORMAT)
        {
            Some(idx) => attributes[idx] = format,
            None => attributes.push(format),
        }

        /* override CKA_OTP_USER_FRIENDLY_MODE to be true by default */
        let user_friendly = attr_element!(
            CKA_OTP_USER_FRIENDLY_MODE; OAFlags::Defval; Attribute::from_bool;
            val true);
        match attributes
            .iter()
            .position(|x| x.get_type() == CKA_OTP_USER_FRIENDLY_MODE)
        {
            Some(idx) => attributes[idx] = user_friendly,
            None => attributes.push(user_friendly),
        }

        factory.data.finalize();

        factory
    }

    pub fn validate_object(&self, obj: &mut Object) -> Result<()> {
        obj.ensure_ulong(CKA_CLASS, CKO_OTP_KEY)
            .map_err(|_| CKR_TEMPLATE_INCONSISTENT)?;
        obj.ensure_ulong(CKA_KEY_TYPE, CKK_HOTP)
            .map_err(|_| CKR_TEMPLATE_INCONSISTENT)?;

        for attr in [CKA_ENCRYPT, CKA_DECRYPT, CKA_WRAP, CKA_UNWRAP] {
            if let Ok(true) = obj.get_attr_as_bool(attr) {
                return Err(CKR_ATTRIBUTE_VALUE_INVALID)?;
            }
        }

        let set_mech = match obj.get_attr_as_bytes(CKA_ALLOWED_MECHANISMS) {
            Ok(mechs) => {
                if mechs.is_empty() {
                    true
                } else if mechs != CKM_HOTP.to_ne_bytes().as_slice() {
                    return Err(CKR_ATTRIBUTE_VALUE_INVALID)?;
                } else {
                    false
                }
            }
            Err(_) => true,
        };
        if set_mech {
            obj.set_attr(Attribute::from_bytes(
                CKA_ALLOWED_MECHANISMS,
                CKM_HOTP.to_ne_bytes().to_vec(),
            ))?;
        }

        if let Ok(c) = obj.get_attr_as_bytes(CKA_OTP_COUNTER) {
            if c.len() != 8 {
                return Err(CKR_ATTRIBUTE_VALUE_INVALID)?;
            }
        }

        if let Ok(format) = obj.get_attr_as_ulong(CKA_OTP_FORMAT) {
            if format != CK_OTP_FORMAT_DECIMAL {
                return Err(CKR_ATTRIBUTE_VALUE_INVALID)?;
            }
        }

        if let Ok(len) = obj.get_attr_as_ulong(CKA_VALUE_LEN) {
            if len != 20 && len != 32 && len != 64 {
                return Err(CKR_ATTRIBUTE_VALUE_INVALID)?;
            }
        }

        if let Ok(otp_len) = obj.get_attr_as_ulong(CKA_OTP_LENGTH) {
            if otp_len < 6 || otp_len > 8 {
                return Err(CKR_ATTRIBUTE_VALUE_INVALID)?;
            }
        }

        if let Ok(time) = obj.get_attr_as_string(CKA_OTP_TIME) {
            if !time.is_empty() {
                return Err(CKR_ATTRIBUTE_VALUE_INVALID)?;
            }
        }

        if let Ok(req) = obj.get_attr_as_ulong(CKA_OTP_TIME_REQUIREMENT) {
            if req != CK_OTP_PARAM_IGNORED {
                return Err(CKR_ATTRIBUTE_VALUE_INVALID)?;
            }
        }

        if let Ok(req) = obj.get_attr_as_ulong(CKA_OTP_CHALLENGE_REQUIREMENT) {
            if req != CK_OTP_PARAM_IGNORED {
                return Err(CKR_ATTRIBUTE_VALUE_INVALID)?;
            }
        }

        if let Ok(req) = obj.get_attr_as_ulong(CKA_OTP_PIN_REQUIREMENT) {
            if req != CK_OTP_PARAM_IGNORED {
                return Err(CKR_ATTRIBUTE_VALUE_INVALID)?;
            }
        }

        Ok(())
    }
}

impl ObjectFactory for HOTPKeyFactory {
    fn create(&self, template: &[CK_ATTRIBUTE]) -> Result<Object> {
        let mut obj = self.key_create(template)?;
        let len = self.get_key_buffer_len(&obj)?;
        if len == 0 {
            return Err(CKR_ATTRIBUTE_VALUE_INVALID)?;
        }
        /* By default CKA_VALUE_LEN is set to 20 by the object's factory,
         * ensure we set it to the actual buffer value passed in via
         * template instead */
        obj.set_attr(Attribute::from_ulong(CKA_VALUE_LEN, len as CK_ULONG))?;

        self.validate_object(&mut obj)?;

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
    fn as_secret_key_factory(&self) -> Result<&dyn SecretKeyFactory> {
        Ok(self)
    }
}

impl KeyFactory for HOTPKeyFactory {
    fn export_for_wrapping(&self, key: &Object) -> Result<Vec<u8>> {
        SecretKeyFactory::default_export_for_wrapping(self, key)
    }

    fn import_from_wrapped(
        &self,
        data: Vec<u8>,
        template: &[CK_ATTRIBUTE],
    ) -> Result<Object> {
        SecretKeyFactory::default_import_from_wrapped(self, data, template)
    }
}

impl SecretKeyFactory for HOTPKeyFactory {
    fn recommend_key_size(&self, _default: usize) -> Result<usize> {
        Ok(32)
    }
}

impl OTPKeyFactory for HOTPKeyFactory {}

const HOTP_MIN_KEY_SIZE: CK_ULONG = 20;
const HOTP_MAX_KEY_SIZE: CK_ULONG = 64;

/// Generic reusable object to represent mechanisms associated
/// with HOTP key objects
#[derive(Debug)]
pub struct HOTPKeyMechanism {
    info: CK_MECHANISM_INFO,
}

impl HOTPKeyMechanism {
    /// Instantiates a mechanism info for HOTP key type
    pub fn new() -> HOTPKeyMechanism {
        HOTPKeyMechanism {
            info: CK_MECHANISM_INFO {
                ulMinKeySize: HOTP_MIN_KEY_SIZE,
                ulMaxKeySize: HOTP_MAX_KEY_SIZE,
                flags: CKF_GENERATE,
            },
        }
    }
}

impl Mechanism for HOTPKeyMechanism {
    fn info(&self) -> &CK_MECHANISM_INFO {
        &self.info
    }

    fn generate_key(
        &self,
        mech: &CK_MECHANISM,
        template: &[CK_ATTRIBUTE],
        _: &Mechanisms,
        _: &ObjectFactories,
    ) -> Result<Object> {
        let factory = HOTPKeyFactory::new();
        let mut key = factory.key_generate(template)?;

        factory.validate_object(&mut key)?;

        default_secret_key_generate(&mut key)?;
        default_key_attributes(&mut key, mech.mechanism)?;

        if key.get_attr_as_bytes(CKA_OTP_COUNTER).is_err() {
            key.set_attr(Attribute::from_bytes(CKA_OTP_COUNTER, vec![0; 8]))?;
        }

        Ok(key)
    }
}

/// Generic reusable object to represent HOTP signature and verification mechanism
#[derive(Debug)]
pub struct HOTPMechanism {
    info: CK_MECHANISM_INFO,
}

impl HOTPMechanism {
    /// Instantiates a mechanism info for HOTP mechanism
    pub fn new() -> HOTPMechanism {
        HOTPMechanism {
            info: CK_MECHANISM_INFO {
                ulMinKeySize: HOTP_MIN_KEY_SIZE,
                ulMaxKeySize: HOTP_MAX_KEY_SIZE,
                flags: CKF_SIGN | CKF_VERIFY,
            },
        }
    }
}

impl Mechanism for HOTPMechanism {
    fn info(&self) -> &CK_MECHANISM_INFO {
        &self.info
    }

    fn sign_new(
        &self,
        mech: &CK_MECHANISM,
        key: &Object,
    ) -> Result<Box<dyn Sign>> {
        if key.get_attr_as_ulong(CKA_CLASS)? != CKO_OTP_KEY
            || key.get_attr_as_ulong(CKA_KEY_TYPE)? != CKK_HOTP
        {
            return Err(CKR_KEY_TYPE_INCONSISTENT)?;
        }
        let can_sign = key
            .get_attr_as_bool(CKA_SIGN)
            .map_err(|_| CKR_GENERAL_ERROR)?;
        if !can_sign {
            return Err(CKR_KEY_FUNCTION_NOT_PERMITTED)?;
        }
        Ok(Box::new(HOTPOperation::new(mech, key, true)?))
    }

    fn verify_new(
        &self,
        mech: &CK_MECHANISM,
        key: &Object,
    ) -> Result<Box<dyn Verify>> {
        if key.get_attr_as_ulong(CKA_CLASS)? != CKO_OTP_KEY
            || key.get_attr_as_ulong(CKA_KEY_TYPE)? != CKK_HOTP
        {
            return Err(CKR_KEY_TYPE_INCONSISTENT)?;
        }
        let can_verify = key
            .get_attr_as_bool(CKA_VERIFY)
            .map_err(|_| CKR_GENERAL_ERROR)?;
        if !can_verify {
            return Err(CKR_KEY_FUNCTION_NOT_PERMITTED)?;
        }
        Ok(Box::new(HOTPOperation::new(mech, key, false)?))
    }
}

#[derive(Debug)]
pub struct HOTPOperation {
    mech_type: CK_MECHANISM_TYPE,
    hmac: HMACOperation,
    counter: [u8; 8],
    key_handle: CK_OBJECT_HANDLE,
    length: usize,
    mac_len: usize,
    finalized: bool,
    update: Option<bool>,
}

impl HOTPOperation {
    pub fn new(
        mech: &CK_MECHANISM,
        key: &Object,
        _is_sign: bool,
    ) -> Result<Self> {
        let mut override_counter = None;
        let update: Option<bool>;

        if mech.ulParameterLen != 0 && !mech.pParameter.is_null() {
            if mech.ulParameterLen as usize
                != std::mem::size_of::<CK_OTP_PARAMS>()
            {
                return Err(CKR_MECHANISM_PARAM_INVALID)?;
            }
            let params = mech.get_parameters::<CK_OTP_PARAMS>()?;
            if params.ulCount > 0 && params.pParams.is_null() {
                return Err(CKR_MECHANISM_PARAM_INVALID)?;
            }
            for p in params.to_slice()? {
                match p.type_ {
                    CK_OTP_FLAGS => {
                        let flags = p.to_ulong()?;
                        if (flags & !CKF_USER_FRIENDLY_OTP) != 0 {
                            return Err(CKR_MECHANISM_PARAM_INVALID)?;
                        }
                    }
                    CK_OTP_COUNTER => override_counter = Some(p.to_buf()?),
                    _ => return Err(CKR_MECHANISM_PARAM_INVALID)?,
                }
            }
        }

        let req = key
            .get_attr_as_ulong(CKA_OTP_COUNTER_REQUIREMENT)
            .map_err(|_| CKR_GENERAL_ERROR)?;

        let c_vec = if let Some(oc) = override_counter {
            if req == CK_OTP_PARAM_OPTIONAL || req == CK_OTP_PARAM_MANDATORY {
                update = None;
                oc
            } else {
                update = Some(false);
                key.get_attr_as_bytes(CKA_OTP_COUNTER)
                    .map_err(|_| CKR_GENERAL_ERROR)?
                    .to_vec()
            }
        } else {
            if req == CK_OTP_PARAM_MANDATORY {
                return Err(CKR_MECHANISM_PARAM_INVALID)?;
            }
            update = Some(false);
            key.get_attr_as_bytes(CKA_OTP_COUNTER)
                .map_err(|_| CKR_GENERAL_ERROR)?
                .to_vec()
        };

        if c_vec.len() != 8 {
            return Err(CKR_GENERAL_ERROR)?;
        }
        let mut counter = [0u8; 8];
        counter.copy_from_slice(&c_vec);

        let length = key
            .get_attr_as_ulong(CKA_OTP_LENGTH)
            .map_err(|_| CKR_GENERAL_ERROR)? as usize;

        let key_val = key.get_attr_as_bytes(CKA_VALUE)?.clone();
        let (hmac_mech, mac_len) = match key_val.len() {
            20 => (CKM_SHA_1_HMAC, 20),
            32 => (CKM_SHA256_HMAC, 32),
            64 => (CKM_SHA512_HMAC, 64),
            _ => return Err(CKR_GENERAL_ERROR)?,
        };
        let hmac = HMACOperation::internal(hmac_mech, key_val, mac_len)?;

        Ok(HOTPOperation {
            mech_type: mech.mechanism,
            hmac,
            counter,
            key_handle: key.get_handle(),
            length,
            mac_len,
            finalized: false,
            update: update,
        })
    }

    fn generate_otp(
        &mut self,
        counter: &[u8; 8],
        output: &mut [u8],
    ) -> Result<()> {
        if output.len() != self.length {
            return Err(CKR_GENERAL_ERROR)?;
        }

        let mut mac = [0u8; HOTP_MAX_KEY_SIZE as usize];
        self.hmac.mac(counter, &mut mac[0..self.mac_len])?;

        let offset = (mac[self.mac_len - 1] & 0x0f) as usize;
        mac[offset] &= 0x7f;
        let value = u32::from_be_bytes(mac[offset..(offset + 4)].try_into()?);
        let otp = value
            % match self.length {
                6 => 1000000,
                7 => 10000000,
                8 => 100000000,
                _ => return Err(CKR_GENERAL_ERROR)?,
            };
        let otp_str = format!("{:0width$}", otp, width = self.length);
        output.copy_from_slice(otp_str.as_bytes());
        Ok(())
    }
}

impl MechOperation for HOTPOperation {
    fn mechanism(&self) -> Result<CK_MECHANISM_TYPE> {
        Ok(self.mech_type)
    }

    fn finalized(&self) -> bool {
        self.finalized
    }
}

impl Sign for HOTPOperation {
    fn sign(&mut self, data: &[u8], signature: &mut [u8]) -> Result<()> {
        if data.len() != 0 {
            return Err(CKR_DATA_INVALID)?;
        }
        self.sign_final(signature)
    }

    fn sign_update(&mut self, _data: &[u8]) -> Result<()> {
        Err(CKR_DATA_INVALID)?
    }

    fn sign_final(&mut self, signature: &mut [u8]) -> Result<()> {
        if self.finalized {
            return Err(CKR_OPERATION_NOT_INITIALIZED)?;
        }

        let struct_size = std::mem::size_of::<CK_OTP_SIGNATURE_INFO>();
        let param_size = std::mem::size_of::<CK_OTP_PARAM>();
        let total_size = struct_size + param_size + self.length;

        if signature.len() < total_size {
            return Err(CKR_BUFFER_TOO_SMALL)?;
        }

        self.finalized = true;

        let mut otp = vec![0u8; self.length];
        let counter = self.counter;
        self.generate_otp(&counter, &mut otp)?;

        unsafe {
            let sig_info = signature.as_mut_ptr() as *mut CK_OTP_SIGNATURE_INFO;
            let p_params =
                signature.as_mut_ptr().add(struct_size) as *mut CK_OTP_PARAM;
            let p_value = signature.as_mut_ptr().add(struct_size + param_size);

            std::ptr::write_unaligned(&mut (*sig_info).pParams, p_params);
            std::ptr::write_unaligned(&mut (*sig_info).ulCount, 1);

            std::ptr::write_unaligned(&mut (*p_params).type_, CK_OTP_VALUE);
            std::ptr::write_unaligned(
                &mut (*p_params).pValue,
                p_value as *mut std::ffi::c_void,
            );
            std::ptr::write_unaligned(
                &mut (*p_params).ulValueLen,
                self.length as CK_ULONG,
            );

            std::ptr::copy_nonoverlapping(otp.as_ptr(), p_value, self.length);
        }

        if self.update.is_some() {
            let mut c_val = u64::from_be_bytes(self.counter);
            c_val += 1;
            self.counter = c_val.to_be_bytes();
            self.update = Some(true);
        }

        Ok(())
    }

    fn signature_len(&self) -> Result<usize> {
        let struct_size = std::mem::size_of::<CK_OTP_SIGNATURE_INFO>();
        let param_size = std::mem::size_of::<CK_OTP_PARAM>();
        Ok(struct_size + param_size + self.length)
    }

    fn updates_object(&self) -> Option<(CK_OBJECT_HANDLE, CkAttrs<'_>)> {
        if self.update == Some(true) {
            let mut attrs = CkAttrs::new();
            if attrs
                .add_owned_slice(CKA_OTP_COUNTER, &self.counter)
                .is_ok()
            {
                return Some((self.key_handle, attrs));
            }
        }
        None
    }
}

impl Verify for HOTPOperation {
    fn verify(&mut self, data: &[u8], signature: &[u8]) -> Result<()> {
        if data.len() != 0 {
            return Err(CKR_DATA_INVALID)?;
        }
        self.verify_final(signature)
    }

    fn verify_update(&mut self, _data: &[u8]) -> Result<()> {
        Err(CKR_DATA_INVALID)?
    }

    fn verify_final(&mut self, signature: &[u8]) -> Result<()> {
        if self.finalized {
            return Err(CKR_OPERATION_NOT_INITIALIZED)?;
        }
        self.finalized = true;

        if signature.len() != self.length {
            return Err(CKR_SIGNATURE_LEN_RANGE)?;
        }

        let mut c_val = u64::from_be_bytes(self.counter);
        for i in 0..5 {
            if i > 0 {
                self.hmac.reset()?;
            }
            let current_counter = c_val.to_be_bytes();
            let mut otp = vec![0u8; self.length];
            self.generate_otp(&current_counter, &mut otp)?;
            if signature == otp {
                if self.update.is_some() {
                    self.counter = (c_val + 1).to_be_bytes();
                    self.update = Some(true);
                }
                return Ok(());
            }
            c_val += 1;
        }
        Err(CKR_SIGNATURE_INVALID)?
    }

    fn signature_len(&self) -> Result<usize> {
        Ok(self.length)
    }

    fn updates_object(&self) -> Option<(CK_OBJECT_HANDLE, CkAttrs<'_>)> {
        if self.update == Some(true) {
            let mut attrs = CkAttrs::new();
            if attrs
                .add_owned_slice(CKA_OTP_COUNTER, &self.counter)
                .is_ok()
            {
                return Some((self.key_handle, attrs));
            }
        }
        None
    }
}
