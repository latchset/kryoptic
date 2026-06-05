// Copyright 2023-2026 Simo Sorce
// See LICENSE.txt file for terms

use crate::attribute::Attribute;
use crate::object::factory::{attr_element, OAFlags};
use crate::object::key::SecretKeyFactory;
use crate::pkcs11::*;

/// This is a common trait to define factories for key objects of class
/// CKO_OTP_KEY
///
/// [OTP key objects](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.2/pkcs11-spec-v3.2.html#_Toc195693644)
/// (Version 3.2)
pub trait OTPKeyFactory: SecretKeyFactory {
    /// Adds the OTP key attributes defined in the spec
    fn add_common_otp_key_attrs(&mut self) {
        self.add_common_secret_key_attrs();
        let attrs = self.get_data_mut().get_attributes_mut();
        attrs.push(attr_element!(
            CKA_OTP_FORMAT; OAFlags::Defval | OAFlags::SettableOnlyOnCreate; Attribute::from_ulong; val CK_OTP_FORMAT_DECIMAL));
        attrs.push(attr_element!(
            CKA_OTP_LENGTH; OAFlags::Defval | OAFlags::SettableOnlyOnCreate; Attribute::from_ulong; val 6));
        attrs.push(attr_element!(
            CKA_OTP_USER_FRIENDLY_MODE; OAFlags::Defval; Attribute::from_bool; val false));
        attrs.push(attr_element!(
            CKA_OTP_CHALLENGE_REQUIREMENT; OAFlags::Defval | OAFlags::SettableOnlyOnCreate; Attribute::from_ulong; val CK_OTP_PARAM_IGNORED));
        attrs.push(attr_element!(
            CKA_OTP_TIME_REQUIREMENT; OAFlags::Defval | OAFlags::SettableOnlyOnCreate; Attribute::from_ulong; val CK_OTP_PARAM_IGNORED));
        attrs.push(attr_element!(
            CKA_OTP_COUNTER_REQUIREMENT; OAFlags::Defval | OAFlags::SettableOnlyOnCreate; Attribute::from_ulong; val CK_OTP_PARAM_IGNORED));
        attrs.push(attr_element!(
            CKA_OTP_PIN_REQUIREMENT; OAFlags::Defval | OAFlags::SettableOnlyOnCreate; Attribute::from_ulong; val CK_OTP_PARAM_IGNORED));
        attrs.push(attr_element!(
            CKA_OTP_COUNTER; OAFlags::Defval; Attribute::from_bytes; val vec![0u8; 8]));
        attrs.push(attr_element!(
            CKA_OTP_TIME; OAFlags::Defval; Attribute::from_string; val String::new()));
        attrs.push(attr_element!(
            CKA_OTP_USER_IDENTIFIER; OAFlags::empty(); Attribute::from_string; val String::new()));
        attrs.push(attr_element!(
            CKA_OTP_SERVICE_IDENTIFIER; OAFlags::empty(); Attribute::from_string; val String::new()));
        attrs.push(attr_element!(
            CKA_OTP_SERVICE_LOGO; OAFlags::empty(); Attribute::from_bytes; val Vec::new()));
        attrs.push(attr_element!(
            CKA_OTP_SERVICE_LOGO_TYPE; OAFlags::empty(); Attribute::from_string; val String::new()));
    }
}
