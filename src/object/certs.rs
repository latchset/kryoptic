// Copyright 2023-2026 Simo Sorce
// See LICENSE.txt file for terms

use std::fmt::Debug;

use crate::attribute::Attribute;
use crate::error::Result;
#[cfg(feature = "nssdb")]
use crate::pkcs11::vendor::nss::*;
use crate::pkcs11::*;

use super::factory::*;
use super::Object;

/// This is a common trait to define factories for objects of class
/// CKO_CERTIFICATE
///
/// [Certificate objects](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203221)
/// (Version 3.1)

pub trait CertFactory: ObjectFactory {
    /// Adds the certificate object attributes defined in the spec
    fn add_common_certificate_attrs(&mut self) {
        self.add_common_storage_attrs(false);
        let attrs = self.get_data_mut().get_attributes_mut();
        attrs.push(attr_element!(
            CKA_CERTIFICATE_TYPE; OAFlags::AlwaysRequired;
            Attribute::from_ulong; val 0));
        attrs.push(attr_element!(
            CKA_TRUSTED; OAFlags::Defval; Attribute::from_bool;
            val false));
        attrs.push(attr_element!(
            CKA_CERTIFICATE_CATEGORY; OAFlags::Defval;
            Attribute::from_ulong;
            val CK_CERTIFICATE_CATEGORY_UNSPECIFIED));
        attrs.push(attr_element!(
            CKA_CHECK_VALUE; OAFlags::Ignored; Attribute::from_ignore;
            val None));
        attrs.push(attr_element!(
            CKA_START_DATE; OAFlags::Defval; Attribute::from_date_bytes;
            val Vec::new()));
        attrs.push(attr_element!(
            CKA_END_DATE; OAFlags::Defval; Attribute::from_date_bytes;
            val Vec::new()));
        attrs.push(attr_element!(
            CKA_PUBLIC_KEY_INFO; OAFlags::empty(); Attribute::from_bytes;
            val Vec::new()));
    }

    /// Validates values of basic certificate attribute conform to
    /// the spec on object creation
    ///
    /// Specifically prevents setting CKA_TRUSTED to true until we
    /// can properly check that the logged in user is the SO.
    ///
    /// Also ensures that CKA_CERTIFICATE_CATEGORY contains only
    /// valid values.
    fn basic_cert_object_create_checks(&self, obj: &mut Object) -> CK_RV {
        match obj.get_attr_as_bool(CKA_TRUSTED) {
            Ok(t) => {
                if t == true {
                    /* until we implement checking for SO auth */
                    return CKR_ATTRIBUTE_READ_ONLY;
                }
            }
            Err(_) => (),
        }
        match obj.get_attr_as_ulong(CKA_CERTIFICATE_CATEGORY) {
            Ok(c) => match c {
                CK_CERTIFICATE_CATEGORY_UNSPECIFIED => (),
                CK_CERTIFICATE_CATEGORY_TOKEN_USER => (),
                CK_CERTIFICATE_CATEGORY_AUTHORITY => (),
                CK_CERTIFICATE_CATEGORY_OTHER_ENTITY => (),
                _ => return CKR_ATTRIBUTE_VALUE_INVALID,
            },
            Err(_) => (),
        }

        CKR_OK
    }
}

/// This is a specialized factory for objects of class CKO_CERTIFICATE
/// and CKA_CERTIFICATE_TYPE of value CKC_X_509
///
/// [X.509 public key certificate objects](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203224)
/// (Version 3.1)

#[derive(Debug)]
pub struct X509Factory {
    data: ObjectFactoryData,
}

impl X509Factory {
    /// Initializes a new X509Factory object
    pub fn new() -> X509Factory {
        let mut factory: X509Factory = X509Factory {
            data: ObjectFactoryData::new(CKO_CERTIFICATE),
        };

        factory.add_common_certificate_attrs();

        let attributes = factory.data.get_attributes_mut();

        attributes.push(attr_element!(
            CKA_SUBJECT; OAFlags::AlwaysRequired; Attribute::from_bytes;
            val Vec::new()));
        attributes.push(attr_element!(
            CKA_ID; OAFlags::Defval; Attribute::from_bytes; val Vec::new()));
        attributes.push(attr_element!(
            CKA_ISSUER; OAFlags::Defval; Attribute::from_bytes;
            val Vec::new()));
        attributes.push(attr_element!(
            CKA_SERIAL_NUMBER; OAFlags::Defval; Attribute::from_bytes;
            val Vec::new()));
        attributes.push(attr_element!(
            CKA_VALUE; OAFlags::AlwaysRequired; Attribute::from_bytes;
            val Vec::new()));
        attributes.push(attr_element!(
            CKA_URL; OAFlags::empty(); Attribute::from_string;
            val String::new()));
        attributes.push(attr_element!(
            CKA_HASH_OF_SUBJECT_PUBLIC_KEY; OAFlags::Defval;
            Attribute::from_bytes; val Vec::new()));
        attributes.push(attr_element!(
            CKA_HASH_OF_ISSUER_PUBLIC_KEY; OAFlags::Defval;
            Attribute::from_bytes; val Vec::new()));
        attributes.push(attr_element!(
            CKA_JAVA_MIDP_SECURITY_DOMAIN; OAFlags::Defval;
            Attribute::from_ulong; val CK_SECURITY_DOMAIN_UNSPECIFIED));
        attributes.push(attr_element!(
            CKA_NAME_HASH_ALGORITHM; OAFlags::empty(); Attribute::from_ulong;
            val CKM_SHA_1));

        factory.data.finalize();

        factory
    }
}

impl ObjectFactory for X509Factory {
    /// Creates a new X509 Certificate object
    ///
    /// Validates that the resulting object conforms to the spec
    /// requirements or returns an appropriate error.
    fn create(&self, template: &[CK_ATTRIBUTE]) -> Result<Object> {
        let mut obj = self.default_object_create(template)?;

        let ret = self.basic_cert_object_create_checks(&mut obj);
        if ret != CKR_OK {
            return Err(ret)?;
        }

        let value = match obj.get_attr_as_bytes(CKA_VALUE) {
            Ok(v) => v,
            Err(_) => return Err(CKR_TEMPLATE_INCOMPLETE)?,
        };
        let url = match obj.get_attr_as_string(CKA_URL) {
            Ok(u) => u,
            Err(_) => String::new(),
        };
        if value.len() == 0 && url.len() == 0 {
            return Err(CKR_ATTRIBUTE_VALUE_INVALID)?;
        }
        if url.len() > 0 {
            match obj.get_attr_as_bytes(CKA_HASH_OF_SUBJECT_PUBLIC_KEY) {
                Ok(h) => {
                    if h.len() == 0 {
                        return Err(CKR_ATTRIBUTE_VALUE_INVALID)?;
                    }
                }
                Err(_) => return Err(CKR_TEMPLATE_INCOMPLETE)?,
            }
            match obj.get_attr_as_bytes(CKA_HASH_OF_SUBJECT_PUBLIC_KEY) {
                Ok(h) => {
                    if h.len() == 0 {
                        return Err(CKR_ATTRIBUTE_VALUE_INVALID)?;
                    }
                }
                Err(_) => return Err(CKR_TEMPLATE_INCOMPLETE)?,
            }
        }
        match obj.get_attr_as_ulong(CKA_JAVA_MIDP_SECURITY_DOMAIN) {
            Ok(sd) => match sd {
                CK_SECURITY_DOMAIN_UNSPECIFIED => (),
                CK_SECURITY_DOMAIN_MANUFACTURER => (),
                CK_SECURITY_DOMAIN_OPERATOR => (),
                CK_SECURITY_DOMAIN_THIRD_PARTY => (),
                _ => return Err(CKR_ATTRIBUTE_VALUE_INVALID)?,
            },
            Err(_) => (),
        }
        /* TODO: should we check if CKA_NAME_HASH_ALGORITHM? */

        Ok(obj)
    }

    fn get_data(&self) -> &ObjectFactoryData {
        &self.data
    }

    fn get_data_mut(&mut self) -> &mut ObjectFactoryData {
        &mut self.data
    }
}

impl CertFactory for X509Factory {}

/// This is a factory for objects of class CKO_TRUST
///
/// [Trust objects](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.2/pkcs11-spec-v3.2.html#_Toc195693091)
/// (Version 3.2)
#[derive(Debug)]
pub struct TrustObject {
    data: ObjectFactoryData,
}

impl TrustObject {
    /// Initializes a new TrustObject factory
    pub fn new() -> TrustObject {
        let mut factory: TrustObject = TrustObject {
            data: ObjectFactoryData::new(CKO_TRUST),
        };

        // CKO_TRUST is a storage object.
        // Spec: if CKA_PRIVATE is not set, it defaults to CK_FALSE.
        // Spec: if CKA_MODIFIABLE is not set, it defaults to CK_TRUE.
        // add_common_storage_attrs handles both correctly.
        factory.add_common_storage_attrs(false);
        let attrs = factory.data.get_attributes_mut();

        attrs.push(attr_element!(
            CKA_ISSUER;
            OAFlags::RequiredOnCreate;
            Attribute::from_bytes;
            val Vec::new()
        ));
        attrs.push(attr_element!(
            CKA_SERIAL_NUMBER;
            OAFlags::RequiredOnCreate;
            Attribute::from_bytes;
            val Vec::new()
        ));
        attrs.push(attr_element!(
            CKA_HASH_OF_CERTIFICATE;
            OAFlags::empty();
            Attribute::from_bytes;
            val Vec::new()
        ));
        attrs.push(attr_element!(
            CKA_NAME_HASH_ALGORITHM;
            OAFlags::empty();
            Attribute::from_ulong;
            val CKM_SHA_1
        ));

        let trust_attributes = [
            CKA_TRUST_SERVER_AUTH,
            CKA_TRUST_CLIENT_AUTH,
            CKA_TRUST_CODE_SIGNING,
            CKA_TRUST_EMAIL_PROTECTION,
            CKA_TRUST_IPSEC_IKE,
            CKA_TRUST_TIME_STAMPING,
            CKA_TRUST_OCSP_SIGNING,
        ];

        for attr_type in trust_attributes {
            attrs.push(attr_element!(
                attr_type;
                OAFlags::Defval;
                Attribute::from_ulong;
                val CKT_TRUST_UNKNOWN
            ));
        }

        factory.data.finalize();
        factory
    }
}

impl ObjectFactory for TrustObject {
    fn create(&self, template: &[CK_ATTRIBUTE]) -> Result<Object> {
        let mut obj = self.default_object_create(template)?;

        obj.ensure_ulong(CKA_CLASS, CKO_TRUST)
            .map_err(|_| CKR_TEMPLATE_INCONSISTENT)?;

        let trust_attributes = [
            CKA_TRUST_SERVER_AUTH,
            CKA_TRUST_CLIENT_AUTH,
            CKA_TRUST_CODE_SIGNING,
            CKA_TRUST_EMAIL_PROTECTION,
            CKA_TRUST_IPSEC_IKE,
            CKA_TRUST_TIME_STAMPING,
            CKA_TRUST_OCSP_SIGNING,
        ];

        let mut some_trusted = false;
        for attr_type in trust_attributes {
            let trust_val = obj.get_attr_as_ulong(attr_type)?; // Will be present due to Defval
            if trust_val != CKT_TRUST_UNKNOWN && trust_val != CKT_NOT_TRUSTED {
                some_trusted = true;
                break;
            }
        }

        if some_trusted {
            // CKA_HASH_OF_CERTIFICATE must be specified and not empty
            let hash = obj
                .get_attr_as_bytes(CKA_HASH_OF_CERTIFICATE)
                .map_err(incomplete)?;
            if hash.is_empty() {
                return Err(CKR_ATTRIBUTE_VALUE_INVALID)?;
            }
            // CKA_NAME_HASH_ALGORITHM must also be specified.
            let _ = obj
                .get_attr_as_ulong(CKA_NAME_HASH_ALGORITHM)
                .map_err(incomplete)?;
        } else if obj.get_attr(CKA_NAME_HASH_ALGORITHM).is_none() {
            // "defaults to SHA-1 if not present"
            obj.set_attr(Attribute::from_ulong(
                CKA_NAME_HASH_ALGORITHM,
                CKM_SHA_1,
            ))?;
        }

        Ok(obj)
    }

    fn get_data(&self) -> &ObjectFactoryData {
        &self.data
    }

    fn get_data_mut(&mut self) -> &mut ObjectFactoryData {
        &mut self.data
    }
}

/// This is a factory for objects of class CKO_NSS_TRUST
///
/// NSS Trust objects are vendor defined and are used in NSS DBs
/// to store trust information about certificates.
#[cfg(feature = "nssdb")]
#[derive(Debug)]
pub struct NSSTrustObject {
    data: ObjectFactoryData,
}

#[cfg(feature = "nssdb")]
impl NSSTrustObject {
    /// Initializes a new NSSTrustObject factory
    pub fn new() -> NSSTrustObject {
        let mut factory: NSSTrustObject = NSSTrustObject {
            data: ObjectFactoryData::new(CKO_NSS_TRUST),
        };

        factory.add_common_storage_attrs(false);
        let attrs = factory.data.get_attributes_mut();

        attrs.push(attr_element!(
            CKA_ISSUER;
            OAFlags::RequiredOnCreate;
            Attribute::from_bytes;
            val Vec::new()
        ));
        attrs.push(attr_element!(
            CKA_SERIAL_NUMBER;
            OAFlags::RequiredOnCreate;
            Attribute::from_bytes;
            val Vec::new()
        ));
        attrs.push(attr_element!(
            CKA_NSS_CERT_SHA1_HASH;
            OAFlags::RequiredOnCreate;
            Attribute::from_bytes;
            val Vec::new()
        ));
        attrs.push(attr_element!(
            CKA_NSS_CERT_MD5_HASH;
            OAFlags::RequiredOnCreate;
            Attribute::from_bytes;
            val Vec::new()
        ));

        /* Some attributes are defined in NSS sources
         * but never actually used, so we comment them
         * out but keep here for completeness. We do not
         * want to accidentally create attributes in
         * the NSS database that NSS would never create
         * or use because these attributes would need to
         * be authenticated but are currently not */
        let trust_attributes = [
            //CKA_NSS_TRUST_DIGITAL_SIGNATURE,
            //CKA_NSS_TRUST_NON_REPUDIATION,
            //CKA_NSS_TRUST_KEY_ENCIPHERMENT,
            //CKA_NSS_TRUST_DATA_ENCIPHERMENT,
            //CKA_NSS_TRUST_KEY_AGREEMENT,
            //CKA_NSS_TRUST_KEY_CERT_SIGN,
            //CKA_NSS_TRUST_CRL_SIGN,
            CKA_NSS_TRUST_SERVER_AUTH,
            CKA_NSS_TRUST_CLIENT_AUTH,
            CKA_NSS_TRUST_CODE_SIGNING,
            CKA_NSS_TRUST_EMAIL_PROTECTION,
            //CKA_NSS_TRUST_IPSEC_END_SYSTEM,
            //CKA_NSS_TRUST_IPSEC_TUNNEL,
            //CKA_NSS_TRUST_IPSEC_USER,
            //CKA_NSS_TRUST_TIME_STAMPING,
            CKA_NSS_TRUST_STEP_UP_APPROVED,
        ];

        for attr_type in trust_attributes {
            attrs.push(attr_element!(
                attr_type;
                OAFlags::empty();
                Attribute::from_ulong;
                val 0
            ));
        }

        factory.data.finalize();
        factory
    }
}

#[cfg(feature = "nssdb")]
impl ObjectFactory for NSSTrustObject {
    fn create(&self, template: &[CK_ATTRIBUTE]) -> Result<Object> {
        let mut obj = self.default_object_create(template)?;

        obj.ensure_ulong(CKA_CLASS, CKO_NSS_TRUST)
            .map_err(|_| CKR_TEMPLATE_INCONSISTENT)?;

        /* NSS does not allow private Trust objects */
        match obj.get_attr_as_bool(CKA_PRIVATE) {
            Ok(b) => match b {
                false => (),
                true => return Err(CKR_ATTRIBUTE_VALUE_INVALID)?,
            },
            Err(_) => (),
        };
        Ok(obj)
    }

    fn get_data(&self) -> &ObjectFactoryData {
        &self.data
    }

    fn get_data_mut(&mut self) -> &mut ObjectFactoryData {
        &mut self.data
    }
}
