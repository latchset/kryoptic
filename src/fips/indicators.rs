// Copyright 2024 Simo Sorce
// See LICENSE.txt file for terms

use crate::attr_element;
use crate::attribute::Attribute;
use crate::ecc_misc::*;
use crate::error::Result;
use crate::interface::*;
use crate::object::{OAFlags, Object, ObjectAttr, ObjectFactory};
use crate::Token;

use once_cell::sync::Lazy;

/* The CKA_VALIDATION_FLAG used to define the validation is always
 * vendor specific and have no fixed value in the spec.
 * Each CKO_VALIDATION object must define a bit flag that should not
 * conflict with other validation objects (in case multiple validations
 * are achieved for the same token); and that flag is what is then used
 * to mark operations. Applications need to get the flag value after
 * token initialization and use that value thereafter to check against
 * objects and session CKA_VALIDATION_FLAGS attributes. */
pub const KRF_FIPS: CK_ULONG = 1;

#[derive(Debug)]
pub struct ValidationFactory {
    attributes: Vec<ObjectAttr>,
}

impl ValidationFactory {
    fn new() -> ValidationFactory {
        let mut data: ValidationFactory = ValidationFactory {
            attributes: Vec::new(),
        };
        data.attributes.append(&mut data.init_common_object_attrs());
        data.attributes
            .append(&mut data.init_common_storage_attrs());
        data.attributes.push(attr_element!(
                CKA_VALIDATION_TYPE; OAFlags::AlwaysRequired
                | OAFlags::NeverSettable | OAFlags::Unchangeable;
                Attribute::from_ulong; val 0));
        data.attributes.push(attr_element!(
                CKA_VALIDATION_VERSION; OAFlags::AlwaysRequired
                | OAFlags::NeverSettable | OAFlags::Unchangeable;
                Attribute::from_bytes; val Vec::new()));
        data.attributes.push(attr_element!(
                CKA_VALIDATION_LEVEL; OAFlags::AlwaysRequired
                | OAFlags::NeverSettable | OAFlags::Unchangeable;
                Attribute::from_ulong; val 0));
        data.attributes.push(attr_element!(
                CKA_VALIDATION_MODULE_ID; OAFlags::AlwaysRequired
                | OAFlags::NeverSettable | OAFlags::Unchangeable;
                Attribute::from_string; val String::new()));
        data.attributes.push(attr_element!(
                CKA_VALIDATION_FLAG; OAFlags::AlwaysRequired
                | OAFlags::NeverSettable | OAFlags::Unchangeable;
                Attribute::from_ulong; val 0));
        data.attributes.push(attr_element!(
                CKA_VALIDATION_AUTHORITY_TYPE; OAFlags::AlwaysRequired
                | OAFlags::NeverSettable | OAFlags::Unchangeable;
                Attribute::from_ulong; val 0));
        data.attributes.push(attr_element!(
                CKA_VALIDATION_COUNTRY; OAFlags::AlwaysRequired
                | OAFlags::NeverSettable | OAFlags::Unchangeable;
                Attribute::from_string; val String::new()));
        data.attributes.push(attr_element!(
                CKA_VALIDATION_CERTIFICATE_IDENTIFIER; OAFlags::AlwaysRequired
                | OAFlags::NeverSettable | OAFlags::Unchangeable;
                Attribute::from_string; val String::new()));
        data.attributes.push(attr_element!(
                CKA_VALIDATION_CERTIFICATE_URI; OAFlags::AlwaysRequired
                | OAFlags::NeverSettable | OAFlags::Unchangeable;
                Attribute::from_string; val String::new()));
        data.attributes.push(attr_element!(
                CKA_VALIDATION_VENDOR_URI; OAFlags::AlwaysRequired
                | OAFlags::NeverSettable | OAFlags::Unchangeable;
                Attribute::from_string; val String::new()));
        data.attributes.push(attr_element!(
                CKA_VALIDATION_PROFILE; OAFlags::AlwaysRequired
                | OAFlags::NeverSettable | OAFlags::Unchangeable;
                Attribute::from_string; val String::new()));
        data
    }
}

impl ObjectFactory for ValidationFactory {
    fn get_attributes(&self) -> &Vec<ObjectAttr> {
        &self.attributes
    }
}

pub static VALIDATION_FACTORY: Lazy<Box<dyn ObjectFactory>> =
    Lazy::new(|| Box::new(ValidationFactory::new()));

pub fn insert_fips_validation(token: &mut Token) -> Result<()> {
    /* Synthesize a FIPS CKO_VALIDATION object */
    let mut obj = Object::new();
    obj.set_attr(Attribute::from_bool(CKA_TOKEN, false))?;
    obj.set_attr(Attribute::from_bool(CKA_DESTROYABLE, false))?;
    obj.set_attr(Attribute::from_bool(CKA_MODIFIABLE, false))?;
    obj.set_attr(Attribute::from_bool(CKA_PRIVATE, false))?;
    obj.set_attr(Attribute::from_bool(CKA_SENSITIVE, false))?;
    obj.set_attr(Attribute::from_ulong(CKA_CLASS, CKO_VALIDATION))?;
    obj.set_attr(Attribute::from_ulong(
        CKA_VALIDATION_TYPE,
        CKV_TYPE_SOFTWARE,
    ))?;
    obj.set_attr(Attribute::from_bytes(
        CKA_VALIDATION_VERSION,
        vec![3u8, 0u8],
    ))?;
    obj.set_attr(Attribute::from_ulong(CKA_VALIDATION_LEVEL, 1))?;
    /* TODO: This should be generated at build time */
    obj.set_attr(Attribute::from_string(
        CKA_VALIDATION_MODULE_ID,
        String::from("Kryoptic FIPS Module - v1"),
    ))?;
    obj.set_attr(Attribute::from_ulong(CKA_VALIDATION_FLAG, KRF_FIPS))?;
    obj.set_attr(Attribute::from_ulong(
        CKA_VALIDATION_AUTHORITY_TYPE,
        CKV_AUTHORITY_TYPE_NIST_CMVP,
    ))?;

    /* TODO: The following attributes should all be determined at build time */
    obj.set_attr(Attribute::from_string(
        CKA_VALIDATION_COUNTRY,
        String::from("US"),
    ))?;
    obj.set_attr(Attribute::from_string(
        CKA_VALIDATION_CERTIFICATE_IDENTIFIER,
        String::from("Pending"),
    ))?;
    obj.set_attr(Attribute::from_string(
        CKA_VALIDATION_CERTIFICATE_URI,
        String::from(""),
    ))?;
    obj.set_attr(Attribute::from_string(
        CKA_VALIDATION_VENDOR_URI,
        String::from("https://github.com/latchset/kryoptic"),
    ))?;
    obj.set_attr(Attribute::from_string(
        CKA_VALIDATION_PROFILE,
        String::from(""),
    ))?;

    /* generate a unique id */
    obj.generate_unique();

    /* invalid session handle will prevent it from being removed when
     * session objects are cleared on session closings */
    let _ = token.insert_object(CK_INVALID_HANDLE, obj)?;
    Ok(())
}

/* bits to bytes */
macro_rules! btb {
    ($val:expr) => {
        ($val + 7) / 8
    };
}

macro_rules! step {
    ($s1:expr) => {
        ([btb!($s1), 0, 0, 0], (0, 0))
    };
    ($s1:expr, $s2:expr) => {
        ([btb!($s1), btb!($s2), 0, 0], (0, 0))
    };
    ($s1:expr, $s2:expr, $s3:expr) => {
        ([btb!($s1), btb!($s2), btb!($s3), 0], (0, 0))
    };
    ($s1:expr, $s2:expr, $s3:expr, $s4:expr) => {
        ([btb!($s1), btb!($s2), btb!($s3), btb!($s4)], (0, 0))
    };
}

macro_rules! range {
    ($r1:expr, $r2:expr) => {
        ([0, 0, 0, 0], (btb!($r1), btb!($r2)))
    };
}

macro_rules! step_and_range {
    () => {
        ([0, 0, 0, 0], (0, 0))
    };
    ($s1:expr; $r1:expr, $r2:expr) => {
        ([btb!($s1), 0, 0, 0], (btb!($r1), btb!($r2)))
    };
    ($s1:expr, $s2:expr; $r1:expr, $r2:expr) => {
        ([btb!($s1), btb!($s2), 0, 0], (btb!($r1), btb!($r2)))
    };
    ($s1:expr, $s2:expr, $s3:expr; $r1:expr, $r2:expr) => {
        ([btb!($s1), btb!($s2), btb!($s3), 0], (btb!($r1), btb!($r2)))
    };
    ($s1:expr, $s2:expr, $s3:expr, $s4:expr; $r1:expr, $r2:expr) => {
        (
            [btb!($s1), btb!($s2), btb!($s3), btb!($s4)],
            (btb!($r1), btb!($r2)),
        )
    };
}

macro_rules! restrict {
    () => {
        (KRY_UNSPEC, step_and_range!())
    };
    ($key:expr) => {
        ($key, step_and_range!())
    };
    ($key:expr, $sr:expr) => {
        ($key, $sr)
    };
}

fn flag_to_op(flag: CK_FLAGS) -> Result<CK_ATTRIBUTE_TYPE> {
    Ok(match flag {
        CKF_SIGN => CKA_SIGN,
        CKF_VERIFY => CKA_VERIFY,
        CKF_ENCRYPT => CKA_ENCRYPT,
        CKF_DECRYPT => CKA_DECRYPT,
        CKF_WRAP => CKA_WRAP,
        CKF_UNWRAP => CKA_UNWRAP,
        CKF_DERIVE => CKA_DERIVE,
        _ => return Err(CKR_GENERAL_ERROR)?,
    })
}

struct FipsKeyType {
    keytype: CK_KEY_TYPE,
    operations: CK_FLAGS,
    sizes: ([usize; 4], (usize, usize)),
}

struct FipsMechanism {
    mechanism: CK_MECHANISM_TYPE,
    operations: CK_FLAGS,
    /* Only filled if the mechanism itself has additional
     * restriction wrt accepted key sizes/outputs for one
     * or all key types.
     * Lists of discrete sizes, and/or list of intervals.
     */
    restrictions: [(CK_KEY_TYPE, ([usize; 4], (usize, usize))); 2],
    genflags: CK_FLAGS,
}

struct FipsChecks {
    keys: [FipsKeyType; 15],
    mechs: [FipsMechanism; 67],
}

/* TODO: double check the values, this is just an initial
 * rough table */
const FIPS_CHECKS: FipsChecks = FipsChecks {
    keys: [
        FipsKeyType {
            keytype: CKK_RSA,
            operations: CKF_SIGN
                | CKF_VERIFY
                | CKF_ENCRYPT
                | CKF_DECRYPT
                | CKF_WRAP
                | CKF_UNWRAP,
            sizes: range!(2048, 16384),
        },
        /* Legacy RSA key sizes that allow only a subset of operations */
        FipsKeyType {
            keytype: CKK_RSA,
            operations: CKF_VERIFY | CKF_DECRYPT | CKF_UNWRAP,
            sizes: step!(1024, 1280, 1536, 1792),
        },
        FipsKeyType {
            keytype: CKK_EC,
            operations: CKF_SIGN | CKF_VERIFY | CKF_DERIVE,
            sizes: step!(256, 384, 521),
        },
        FipsKeyType {
            keytype: CKK_AES,
            operations: CKF_SIGN
                | CKF_VERIFY
                | CKF_ENCRYPT
                | CKF_DECRYPT
                | CKF_WRAP
                | CKF_UNWRAP,
            sizes: step!(128, 192, 256),
        },
        FipsKeyType {
            keytype: CKK_GENERIC_SECRET,
            operations: CKF_SIGN | CKF_VERIFY | CKF_DERIVE,
            sizes: range!(112, 255 * 64 * 8),
        },
        FipsKeyType {
            keytype: CKK_SHA224_HMAC,
            operations: CKF_SIGN | CKF_VERIFY | CKF_DERIVE,
            sizes: step!(224),
        },
        FipsKeyType {
            keytype: CKK_SHA256_HMAC,
            operations: CKF_SIGN | CKF_VERIFY | CKF_DERIVE,
            sizes: step!(256),
        },
        FipsKeyType {
            keytype: CKK_SHA384_HMAC,
            operations: CKF_SIGN | CKF_VERIFY | CKF_DERIVE,
            sizes: step!(384),
        },
        FipsKeyType {
            keytype: CKK_SHA512_HMAC,
            operations: CKF_SIGN | CKF_VERIFY | CKF_DERIVE,
            sizes: step!(512),
        },
        FipsKeyType {
            keytype: CKK_SHA3_224_HMAC,
            operations: CKF_SIGN | CKF_VERIFY | CKF_DERIVE,
            sizes: step!(224),
        },
        FipsKeyType {
            keytype: CKK_SHA3_256_HMAC,
            operations: CKF_SIGN | CKF_VERIFY | CKF_DERIVE,
            sizes: step!(256),
        },
        FipsKeyType {
            keytype: CKK_SHA3_384_HMAC,
            operations: CKF_SIGN | CKF_VERIFY | CKF_DERIVE,
            sizes: step!(384),
        },
        FipsKeyType {
            keytype: CKK_SHA3_512_HMAC,
            operations: CKF_SIGN | CKF_VERIFY | CKF_DERIVE,
            sizes: step!(512),
        },
        FipsKeyType {
            keytype: CKK_EC_EDWARDS,
            operations: CKF_SIGN | CKF_VERIFY,
            sizes: step!(255, 448),
        },
        FipsKeyType {
            keytype: CKK_HKDF,
            operations: CKF_DERIVE,
            sizes: range!(112, 512),
        },
    ],
    mechs: [
        /* RSA */
        FipsMechanism {
            mechanism: CKM_RSA_PKCS_KEY_PAIR_GEN,
            operations: CKF_GENERATE_KEY_PAIR,
            restrictions: [
                restrict!(CKK_RSA, range!(2048, 16384)),
                restrict!(),
            ],
            genflags: CKF_SIGN
                | CKF_VERIFY
                | CKF_ENCRYPT
                | CKF_DECRYPT
                | CKF_WRAP
                | CKF_UNWRAP,
        },
        FipsMechanism {
            mechanism: CKM_RSA_PKCS_OAEP,
            operations: CKF_ENCRYPT | CKF_DECRYPT,
            restrictions: [
                restrict!(CKK_RSA, range!(2048, 16384)),
                restrict!(),
            ],
            genflags: 0,
        },
        FipsMechanism {
            mechanism: CKM_SHA1_RSA_PKCS,
            operations: CKF_VERIFY,
            restrictions: [restrict!(CKK_RSA), restrict!()],
            genflags: 0,
        },
        FipsMechanism {
            mechanism: CKM_SHA224_RSA_PKCS,
            operations: CKF_SIGN | CKF_VERIFY,
            restrictions: [restrict!(CKK_RSA), restrict!()],
            genflags: 0,
        },
        FipsMechanism {
            mechanism: CKM_SHA256_RSA_PKCS,
            operations: CKF_SIGN | CKF_VERIFY,
            restrictions: [restrict!(CKK_RSA), restrict!()],
            genflags: 0,
        },
        FipsMechanism {
            mechanism: CKM_SHA384_RSA_PKCS,
            operations: CKF_SIGN | CKF_VERIFY,
            restrictions: [restrict!(CKK_RSA), restrict!()],
            genflags: 0,
        },
        FipsMechanism {
            mechanism: CKM_SHA512_RSA_PKCS,
            operations: CKF_SIGN | CKF_VERIFY,
            restrictions: [restrict!(CKK_RSA), restrict!()],
            genflags: 0,
        },
        FipsMechanism {
            mechanism: CKM_SHA3_224_RSA_PKCS,
            operations: CKF_SIGN | CKF_VERIFY,
            restrictions: [restrict!(CKK_RSA), restrict!()],
            genflags: 0,
        },
        FipsMechanism {
            mechanism: CKM_SHA3_256_RSA_PKCS,
            operations: CKF_SIGN | CKF_VERIFY,
            restrictions: [restrict!(CKK_RSA), restrict!()],
            genflags: 0,
        },
        FipsMechanism {
            mechanism: CKM_SHA3_384_RSA_PKCS,
            operations: CKF_SIGN | CKF_VERIFY,
            restrictions: [restrict!(CKK_RSA), restrict!()],
            genflags: 0,
        },
        FipsMechanism {
            mechanism: CKM_SHA3_512_RSA_PKCS,
            operations: CKF_SIGN | CKF_VERIFY,
            restrictions: [restrict!(CKK_RSA), restrict!()],
            genflags: 0,
        },
        FipsMechanism {
            mechanism: CKM_SHA1_RSA_PKCS_PSS,
            operations: CKF_VERIFY,
            restrictions: [restrict!(CKK_RSA), restrict!()],
            genflags: 0,
        },
        FipsMechanism {
            mechanism: CKM_SHA224_RSA_PKCS_PSS,
            operations: CKF_SIGN | CKF_VERIFY,
            restrictions: [restrict!(CKK_RSA), restrict!()],
            genflags: 0,
        },
        FipsMechanism {
            mechanism: CKM_SHA256_RSA_PKCS_PSS,
            operations: CKF_SIGN | CKF_VERIFY,
            restrictions: [restrict!(CKK_RSA), restrict!()],
            genflags: 0,
        },
        FipsMechanism {
            mechanism: CKM_SHA384_RSA_PKCS_PSS,
            operations: CKF_SIGN | CKF_VERIFY,
            restrictions: [restrict!(CKK_RSA), restrict!()],
            genflags: 0,
        },
        FipsMechanism {
            mechanism: CKM_SHA512_RSA_PKCS_PSS,
            operations: CKF_SIGN | CKF_VERIFY,
            restrictions: [restrict!(CKK_RSA), restrict!()],
            genflags: 0,
        },
        FipsMechanism {
            mechanism: CKM_SHA3_224_RSA_PKCS_PSS,
            operations: CKF_SIGN | CKF_VERIFY,
            restrictions: [restrict!(CKK_RSA), restrict!()],
            genflags: 0,
        },
        FipsMechanism {
            mechanism: CKM_SHA3_256_RSA_PKCS_PSS,
            operations: CKF_SIGN | CKF_VERIFY,
            restrictions: [restrict!(CKK_RSA), restrict!()],
            genflags: 0,
        },
        FipsMechanism {
            mechanism: CKM_SHA3_384_RSA_PKCS_PSS,
            operations: CKF_SIGN | CKF_VERIFY,
            restrictions: [restrict!(CKK_RSA), restrict!()],
            genflags: 0,
        },
        FipsMechanism {
            mechanism: CKM_SHA3_512_RSA_PKCS_PSS,
            operations: CKF_SIGN | CKF_VERIFY,
            restrictions: [restrict!(CKK_RSA), restrict!()],
            genflags: 0,
        },
        /* ECC */
        FipsMechanism {
            mechanism: CKM_EC_KEY_PAIR_GEN,
            operations: CKF_GENERATE_KEY_PAIR,
            restrictions: [restrict!(CKK_EC), restrict!()],
            genflags: CKF_SIGN | CKF_VERIFY | CKF_DERIVE,
        },
        FipsMechanism {
            mechanism: CKM_ECDSA_SHA224,
            operations: CKF_SIGN | CKF_VERIFY,
            restrictions: [restrict!(CKK_RSA), restrict!()],
            genflags: 0,
        },
        FipsMechanism {
            mechanism: CKM_ECDSA_SHA256,
            operations: CKF_SIGN | CKF_VERIFY,
            restrictions: [restrict!(CKK_RSA), restrict!()],
            genflags: 0,
        },
        FipsMechanism {
            mechanism: CKM_ECDSA_SHA384,
            operations: CKF_SIGN | CKF_VERIFY,
            restrictions: [restrict!(CKK_RSA), restrict!()],
            genflags: 0,
        },
        FipsMechanism {
            mechanism: CKM_ECDSA_SHA512,
            operations: CKF_SIGN | CKF_VERIFY,
            restrictions: [restrict!(CKK_RSA), restrict!()],
            genflags: 0,
        },
        /* AES */
        FipsMechanism {
            mechanism: CKM_AES_KEY_GEN,
            operations: CKF_GENERATE,
            restrictions: [restrict!(CKK_AES), restrict!()],
            genflags: CKF_ENCRYPT
                | CKF_DECRYPT
                | CKF_WRAP
                | CKF_UNWRAP
                | CKF_DERIVE,
        },
        FipsMechanism {
            mechanism: CKM_AES_ECB,
            operations: CKF_ENCRYPT | CKF_DECRYPT,
            restrictions: [restrict!(CKK_AES), restrict!()],
            genflags: 0,
        },
        FipsMechanism {
            mechanism: CKM_AES_CBC,
            operations: CKF_ENCRYPT | CKF_DECRYPT,
            restrictions: [restrict!(CKK_AES), restrict!()],
            genflags: 0,
        },
        FipsMechanism {
            mechanism: CKM_AES_CBC_PAD,
            operations: CKF_ENCRYPT | CKF_DECRYPT,
            restrictions: [restrict!(CKK_AES), restrict!()],
            genflags: 0,
        },
        FipsMechanism {
            mechanism: CKM_AES_CTR,
            operations: CKF_ENCRYPT | CKF_DECRYPT,
            restrictions: [restrict!(CKK_AES), restrict!()],
            genflags: 0,
        },
        FipsMechanism {
            mechanism: CKM_AES_GCM,
            operations: CKF_ENCRYPT | CKF_DECRYPT | CKF_WRAP | CKF_UNWRAP,
            restrictions: [restrict!(CKK_AES), restrict!()],
            genflags: 0,
        },
        FipsMechanism {
            mechanism: CKM_AES_CTS,
            operations: CKF_ENCRYPT | CKF_DECRYPT,
            restrictions: [restrict!(CKK_AES), restrict!()],
            genflags: 0,
        },
        FipsMechanism {
            mechanism: CKM_AES_CMAC,
            operations: CKF_SIGN | CKF_VERIFY,
            restrictions: [restrict!(CKK_AES), restrict!()],
            genflags: 0,
        },
        FipsMechanism {
            mechanism: CKM_AES_CMAC_GENERAL,
            operations: CKF_SIGN | CKF_VERIFY,
            restrictions: [restrict!(CKK_AES), restrict!()],
            genflags: 0,
        },
        FipsMechanism {
            mechanism: CKM_AES_KEY_WRAP,
            operations: CKF_ENCRYPT | CKF_DECRYPT | CKF_WRAP | CKF_UNWRAP,
            restrictions: [restrict!(CKK_AES), restrict!()],
            genflags: 0,
        },
        FipsMechanism {
            mechanism: CKM_AES_KEY_WRAP_KWP,
            operations: CKF_ENCRYPT | CKF_DECRYPT | CKF_WRAP | CKF_UNWRAP,
            restrictions: [restrict!(CKK_AES), restrict!()],
            genflags: 0,
        },
        /* SHA */
        FipsMechanism {
            mechanism: CKM_SHA224,
            operations: CKF_DIGEST,
            restrictions: [restrict!(), restrict!()],
            genflags: 0,
        },
        FipsMechanism {
            mechanism: CKM_SHA256,
            operations: CKF_DIGEST,
            restrictions: [restrict!(), restrict!()],
            genflags: 0,
        },
        FipsMechanism {
            mechanism: CKM_SHA384,
            operations: CKF_DIGEST,
            restrictions: [restrict!(), restrict!()],
            genflags: 0,
        },
        FipsMechanism {
            mechanism: CKM_SHA512,
            operations: CKF_DIGEST,
            restrictions: [restrict!(), restrict!()],
            genflags: 0,
        },
        FipsMechanism {
            mechanism: CKM_SHA3_224,
            operations: CKF_DIGEST,
            restrictions: [restrict!(), restrict!()],
            genflags: 0,
        },
        FipsMechanism {
            mechanism: CKM_SHA3_256,
            operations: CKF_DIGEST,
            restrictions: [restrict!(), restrict!()],
            genflags: 0,
        },
        FipsMechanism {
            mechanism: CKM_SHA3_384,
            operations: CKF_DIGEST,
            restrictions: [restrict!(), restrict!()],
            genflags: 0,
        },
        FipsMechanism {
            mechanism: CKM_SHA3_512,
            operations: CKF_DIGEST,
            restrictions: [restrict!(), restrict!()],
            genflags: 0,
        },
        /* HMAC */
        FipsMechanism {
            mechanism: CKM_SHA224_HMAC,
            operations: CKF_SIGN | CKF_VERIFY,
            restrictions: [
                restrict!(CKK_SHA224_HMAC, range!(112, 224)),
                restrict!(CKK_GENERIC_SECRET, range!(112, 224)),
            ],
            genflags: 0,
        },
        FipsMechanism {
            mechanism: CKM_SHA256_HMAC,
            operations: CKF_SIGN | CKF_VERIFY,
            restrictions: [
                restrict!(CKK_SHA256_HMAC, range!(112, 256)),
                restrict!(CKK_GENERIC_SECRET, range!(112, 256)),
            ],
            genflags: 0,
        },
        FipsMechanism {
            mechanism: CKM_SHA384_HMAC,
            operations: CKF_SIGN | CKF_VERIFY,
            restrictions: [
                restrict!(CKK_SHA384_HMAC, range!(112, 384)),
                restrict!(CKK_GENERIC_SECRET, range!(112, 384)),
            ],
            genflags: 0,
        },
        FipsMechanism {
            mechanism: CKM_SHA512_HMAC,
            operations: CKF_SIGN | CKF_VERIFY,
            restrictions: [
                restrict!(CKK_SHA512_HMAC, range!(112, 512)),
                restrict!(CKK_GENERIC_SECRET, range!(112, 512)),
            ],
            genflags: 0,
        },
        FipsMechanism {
            mechanism: CKM_SHA3_224_HMAC,
            operations: CKF_SIGN | CKF_VERIFY,
            restrictions: [
                restrict!(CKK_SHA3_224_HMAC, range!(112, 224)),
                restrict!(CKK_GENERIC_SECRET, range!(112, 224)),
            ],
            genflags: 0,
        },
        FipsMechanism {
            mechanism: CKM_SHA3_256_HMAC,
            operations: CKF_SIGN | CKF_VERIFY,
            restrictions: [
                restrict!(CKK_SHA3_256_HMAC, range!(112, 256)),
                restrict!(CKK_GENERIC_SECRET, range!(112, 256)),
            ],
            genflags: 0,
        },
        FipsMechanism {
            mechanism: CKM_SHA3_384_HMAC,
            operations: CKF_SIGN | CKF_VERIFY,
            restrictions: [
                restrict!(CKK_SHA3_384_HMAC, range!(112, 384)),
                restrict!(CKK_GENERIC_SECRET, range!(112, 384)),
            ],
            genflags: 0,
        },
        FipsMechanism {
            mechanism: CKM_SHA3_512_HMAC,
            operations: CKF_SIGN | CKF_VERIFY,
            restrictions: [
                restrict!(CKK_SHA3_512_HMAC, range!(112, 512)),
                restrict!(CKK_GENERIC_SECRET, range!(112, 512)),
            ],
            genflags: 0,
        },
        FipsMechanism {
            mechanism: CKM_SHA224_HMAC_GENERAL,
            operations: CKF_SIGN | CKF_VERIFY,
            restrictions: [
                restrict!(CKK_SHA224_HMAC, range!(112, 224)),
                restrict!(CKK_GENERIC_SECRET, range!(112, 224)),
            ],
            genflags: 0,
        },
        FipsMechanism {
            mechanism: CKM_SHA256_HMAC_GENERAL,
            operations: CKF_SIGN | CKF_VERIFY,
            restrictions: [
                restrict!(CKK_SHA256_HMAC, range!(112, 256)),
                restrict!(CKK_GENERIC_SECRET, range!(112, 256)),
            ],
            genflags: 0,
        },
        FipsMechanism {
            mechanism: CKM_SHA384_HMAC_GENERAL,
            operations: CKF_SIGN | CKF_VERIFY,
            restrictions: [
                restrict!(CKK_SHA384_HMAC, range!(112, 384)),
                restrict!(CKK_GENERIC_SECRET, range!(112, 384)),
            ],
            genflags: 0,
        },
        FipsMechanism {
            mechanism: CKM_SHA512_HMAC_GENERAL,
            operations: CKF_SIGN | CKF_VERIFY,
            restrictions: [
                restrict!(CKK_SHA512_HMAC, range!(112, 512)),
                restrict!(CKK_GENERIC_SECRET, range!(112, 512)),
            ],
            genflags: 0,
        },
        FipsMechanism {
            mechanism: CKM_SHA3_224_HMAC_GENERAL,
            operations: CKF_SIGN | CKF_VERIFY,
            restrictions: [
                restrict!(CKK_SHA3_224_HMAC, range!(112, 224)),
                restrict!(CKK_GENERIC_SECRET, range!(112, 224)),
            ],
            genflags: 0,
        },
        FipsMechanism {
            mechanism: CKM_SHA3_256_HMAC_GENERAL,
            operations: CKF_SIGN | CKF_VERIFY,
            restrictions: [
                restrict!(CKK_SHA3_256_HMAC, range!(112, 256)),
                restrict!(CKK_GENERIC_SECRET, range!(112, 256)),
            ],
            genflags: 0,
        },
        FipsMechanism {
            mechanism: CKM_SHA3_384_HMAC_GENERAL,
            operations: CKF_SIGN | CKF_VERIFY,
            restrictions: [
                restrict!(CKK_SHA3_384_HMAC, range!(112, 384)),
                restrict!(CKK_GENERIC_SECRET, range!(112, 384)),
            ],
            genflags: 0,
        },
        FipsMechanism {
            mechanism: CKM_SHA3_512_HMAC_GENERAL,
            operations: CKF_SIGN | CKF_VERIFY,
            restrictions: [
                restrict!(CKK_SHA3_512_HMAC, range!(112, 512)),
                restrict!(CKK_GENERIC_SECRET, range!(112, 512)),
            ],
            genflags: 0,
        },
        /* Key gen, gen/derive */
        FipsMechanism {
            mechanism: CKM_PKCS5_PBKD2,
            operations: CKF_GENERATE,
            restrictions: [
                restrict!(KRY_UNSPEC, range!(112, 256)),
                restrict!(),
            ],
            genflags: CKF_DERIVE,
        },
        FipsMechanism {
            mechanism: CKM_GENERIC_SECRET_KEY_GEN,
            operations: CKF_GENERATE,
            restrictions: [
                restrict!(CKK_GENERIC_SECRET, range!(112, 256)),
                restrict!(),
            ],
            genflags: CKF_DERIVE,
        },
        FipsMechanism {
            mechanism: CKM_HKDF_KEY_GEN,
            operations: CKF_GENERATE,
            restrictions: [
                restrict!(CKK_HKDF, step_and_range!(256, 384, 512; 160, 224)),
                restrict!(),
            ],
            genflags: CKF_DERIVE,
        },
        /* KDFs */
        FipsMechanism {
            mechanism: CKM_HKDF_DERIVE,
            operations: CKF_DERIVE,
            restrictions: [
                restrict!(CKK_GENERIC_SECRET, range!(112, 255 * 64 * 8)),
                restrict!(CKK_HKDF, range!(112, 255 * 64 * 8)),
            ],
            genflags: CKF_SIGN
                | CKF_VERIFY
                | CKF_ENCRYPT
                | CKF_DECRYPT
                | CKF_WRAP
                | CKF_UNWRAP
                | CKF_DERIVE,
        },
        FipsMechanism {
            mechanism: CKM_HKDF_DATA,
            operations: CKF_DERIVE,
            restrictions: [
                restrict!(KRY_UNSPEC, range!(112, 255 * 64 * 8)),
                restrict!(),
            ],
            genflags: CKF_SIGN
                | CKF_VERIFY
                | CKF_ENCRYPT
                | CKF_DECRYPT
                | CKF_WRAP
                | CKF_UNWRAP
                | CKF_DERIVE,
        },
        FipsMechanism {
            mechanism: CKM_SP800_108_COUNTER_KDF,
            operations: CKF_DERIVE,
            restrictions: [
                restrict!(CKK_AES),
                restrict!(KRY_UNSPEC, range!(112, 0xffffffff)),
            ],
            genflags: CKF_SIGN
                | CKF_VERIFY
                | CKF_ENCRYPT
                | CKF_DECRYPT
                | CKF_WRAP
                | CKF_UNWRAP
                | CKF_DERIVE,
        },
        FipsMechanism {
            mechanism: CKM_SP800_108_FEEDBACK_KDF,
            operations: CKF_DERIVE,
            restrictions: [
                restrict!(CKK_AES),
                restrict!(KRY_UNSPEC, range!(112, 0xffffffff)),
            ],
            genflags: CKF_SIGN
                | CKF_VERIFY
                | CKF_ENCRYPT
                | CKF_DECRYPT
                | CKF_WRAP
                | CKF_UNWRAP
                | CKF_DERIVE,
        },
    ],
};

fn size_check(len: usize, sizes: ([usize; 4], (usize, usize))) -> Option<bool> {
    let mut size_check: Option<bool> = None;
    for size in sizes.0 {
        if size != 0 && size_check != Some(true) {
            if len == size {
                size_check = Some(true);
            } else {
                size_check = Some(false);
            }
        }
    }
    if size_check.is_none() && sizes.1 != (0, 0) {
        let (min, max) = sizes.1;
        if min != 0 && len < min {
            size_check = Some(false);
        } else if max != 0 && len > max {
            size_check = Some(false);
        } else {
            size_check = Some(true);
        }
    }
    size_check
}

fn check_key(
    obj: &Object,
    op: CK_FLAGS,
    genflags: Option<CK_FLAGS>,
    restrictions: Option<&[(CK_KEY_TYPE, ([usize; 4], (usize, usize))); 2]>,
) -> bool {
    let key_type = match obj.get_attr_as_ulong(CKA_KEY_TYPE) {
        Ok(k) => k,
        Err(_) => return false,
    };

    let keylen = match key_type {
        CKK_RSA => match obj.get_attr_as_bytes(CKA_MODULUS) {
            Ok(m) => m.len(),
            Err(_) => return false,
        },
        CKK_EC | CKK_EC_EDWARDS => match get_ossl_name_from_obj(obj) {
            Ok(s) => match curve_name_to_bits(s) {
                Ok(l) => l,
                Err(_) => return false,
            },
            Err(_) => return false,
        },
        _ => {
            /* assume everything else is a symmetric key */
            match obj.get_attr_as_ulong(CKA_VALUE_LEN) {
                Ok(l) => usize::try_from(l).unwrap(),
                Err(_) => return false,
            }
        }
    };

    if let Some(gf) = genflags {
        for f in [
            CKF_SIGN,
            CKF_VERIFY,
            CKF_ENCRYPT,
            CKF_DECRYPT,
            CKF_WRAP,
            CKF_UNWRAP,
            CKF_DERIVE,
        ] {
            if gf & f == 0 {
                /* op disallowed */
                let attr = match flag_to_op(f) {
                    Ok(a) => a,
                    Err(_) => return false, /* uh? */
                };
                match obj.get_attr_as_bool(attr) {
                    Ok(b) => {
                        if b {
                            /* deny */
                            return false;
                        }
                    }
                    Err(_) => (),
                }
            }
        }
    }

    if let Some(restr) = restrictions {
        let mut key_passes = false;
        for r in restr {
            if r.0 != KRY_UNSPEC && r.0 != key_type {
                /* restriction for another key type */
                continue;
            }
            match size_check(keylen, r.1) {
                Some(b) => {
                    if b {
                        key_passes = true
                    } else {
                        /* size restriction failed */
                        return false;
                    }
                }
                None => key_passes = true,
            }
        }
        if !key_passes {
            /* the object key_type is not allowed by the
             * additional restrictions, therefore we bail */
            return false;
        }
    }

    /* normal restrictions */
    for k in &FIPS_CHECKS.keys {
        if k.keytype != key_type {
            continue;
        }
        if k.operations & op != 0 {
            if match size_check(keylen, k.sizes) {
                None => false,
                Some(v) => v,
            } == true
            {
                /* Each key type may have multiple key check
                 * sets. As long as one of them returns true
                 * it means the operation was approved, but
                 * if we get a false we continue in case a
                 * later check will approve */
                return true;
            }
        }
    }

    false
}

pub fn is_approved(
    mechanism: CK_MECHANISM_TYPE,
    op: CK_FLAGS,
    iobj: Option<&Object>,
    mut oobj: Option<&mut Object>,
) -> bool {
    let checks = match op {
        /* no keys to check */
        CKF_DIGEST => 0,
        /* only input keys */
        CKF_SIGN | CKF_VERIFY | CKF_ENCRYPT | CKF_DECRYPT | CKF_WRAP => 1,
        /* only output keys */
        CKF_GENERATE | CKF_GENERATE_KEY_PAIR => 2,
        /* both input and output */
        CKF_UNWRAP | CKF_DERIVE => 3,
        /* invalid op */
        _ => return false,
    };

    for m in &FIPS_CHECKS.mechs {
        if mechanism != m.mechanism {
            continue;
        }

        if m.operations & op == 0 {
            /* unapproved op for this mech, we can immediately return
             * because any object generated via an unapproved mechanism
             * will also be non valid so no point in checking or
             * setting flags */
            return false;
        }

        if checks == 0 {
            return true;
        }

        if checks & 1 == 1 {
            let mut valid_key = false;
            if let Some(obj) = iobj {
                if let Ok(f) = obj.get_attr_as_ulong(CKA_VALIDATION_FLAG) {
                    if (f & KRF_FIPS) == KRF_FIPS {
                        valid_key = true;
                    } else if let Ok(class) = obj.get_attr_as_ulong(CKA_CLASS) {
                        if class == CKO_PUBLIC_KEY {
                            /* Public keys may be imported, so we check if they
                             * meet the criteria, and that is good enough */
                            valid_key = check_key(obj, op, None, None);
                        }
                    }
                }
            }
            if !valid_key {
                return false;
            }
            if checks == 1 {
                /* we are done */
                return true;
            }
        }

        if checks & 2 == 2 {
            if let Some(ref mut obj) = oobj {
                if check_key(
                    obj,
                    CK_UNAVAILABLE_INFORMATION,
                    Some(m.genflags),
                    Some(&m.restrictions),
                ) {
                    /* add FIPS validation flag */
                    let flag = match obj.get_attr_as_ulong(CKA_VALIDATION_FLAGS)
                    {
                        Ok(f) => f,
                        Err(_) => 0,
                    } | KRF_FIPS;
                    let _ = obj.set_attr(Attribute::from_ulong(
                        CKA_VALIDATION_FLAG,
                        flag,
                    ));
                    return true;
                } else {
                    /* special case for HKDF which can return a DATA object */
                    if mechanism == CKM_HKDF_DATA {
                        if let Ok(val) = obj.get_attr_as_bytes(CKA_VALUE) {
                            let len = val.len();
                            match size_check(len, m.restrictions[0].1) {
                                Some(true) => return true,
                                _ => return false,
                            }
                        }
                    }
                }
            }
        }
    }

    false
}
