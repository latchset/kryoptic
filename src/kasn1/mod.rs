// Copyright 2023 Simo Sorce
// See LICENSE.txt file for terms

use std::borrow::Cow;

use crate::error::Result;
use crate::interface::*;
use crate::misc::zeromem;

use asn1;

/* Helper routines to use with rust/asn1 */

pub struct DerEncBigUint<'a> {
    data: Cow<'a, [u8]>,
}

impl<'a> DerEncBigUint<'a> {
    pub fn new(data: &'a [u8]) -> Result<Self> {
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
        } else {
            // Skip possible leading zeroes that do not affect sign of the resulting integer
            let mut skip = 0;
            while de.data[skip] == 0
                && skip + 1 < de.data.len()
                && de.data[skip + 1] & 0x80 == 0
            {
                skip += 1;
            }
            de = DerEncBigUint {
                data: Cow::from(&data[skip..]),
            };
        }
        /* check it works */
        match asn1::BigUint::new(&de.data) {
            Some(_) => Ok(de),
            None => Err(CKR_GENERAL_ERROR)?,
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    /// Get the BN bytes without possible leading NULL bytes.
    #[allow(dead_code)]
    pub fn as_nopad_bytes(&self) -> &[u8] {
        let mut skip = 0;
        for val in self.data.as_ref() {
            if *val != 0 {
                break;
            }
            skip += 1;
        }
        &self.data[skip..]
    }
}

impl Drop for DerEncBigUint<'_> {
    fn drop(&mut self) {
        match &self.data {
            Cow::Owned(_) => zeromem(self.data.to_mut()),
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
    const TAG: asn1::Tag = asn1::BigUint::TAG;
    fn write_data(&self, dest: &mut asn1::WriteBuf) -> asn1::WriteResult {
        dest.push_slice(self.as_bytes())
    }
}

pub struct DerEncOctetString<'a> {
    data: Cow<'a, [u8]>,
}

impl<'a> DerEncOctetString<'a> {
    pub fn new(data: &'a [u8]) -> Result<Self> {
        Ok(DerEncOctetString {
            data: Cow::from(data),
        })
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }
}

impl Drop for DerEncOctetString<'_> {
    fn drop(&mut self) {
        match &self.data {
            Cow::Owned(_) => zeromem(self.data.to_mut()),
            _ => (),
        }
    }
}

impl<'a> asn1::SimpleAsn1Readable<'a> for DerEncOctetString<'a> {
    const TAG: asn1::Tag = asn1::Tag::primitive(0x04);
    fn parse_data(data: &'a [u8]) -> asn1::ParseResult<Self> {
        match DerEncOctetString::new(data) {
            Ok(x) => Ok(x),
            Err(_) => {
                Err(asn1::ParseError::new(asn1::ParseErrorKind::InvalidValue))
            }
        }
    }
}
impl<'a> asn1::SimpleAsn1Writable for DerEncOctetString<'a> {
    const TAG: asn1::Tag = asn1::Tag::primitive(0x04);
    fn write_data(&self, dest: &mut asn1::WriteBuf) -> asn1::WriteResult {
        dest.push_slice(self.as_bytes())
    }
}

type Version = u64;

#[derive(asn1::Asn1Read, asn1::Asn1Write)]
struct Attribute<'a> {
    attribute_type: asn1::ObjectIdentifier,
    attribute_value: asn1::SetOf<'a, asn1::Tlv<'a>>, // ANY
}

type Attributes<'a> = asn1::SetOf<'a, Attribute<'a>>;

#[derive(asn1::Asn1Read, asn1::Asn1Write)]
pub struct PrivateKeyInfo<'a> {
    version: Version,
    private_key_algorithm: asn1::ObjectIdentifier,
    private_key: DerEncOctetString<'a>,
    #[explicit(1)]
    attributes: Option<Attributes<'a>>,
}

#[allow(dead_code)]
impl PrivateKeyInfo<'_> {
    pub fn new<'a>(
        private_key_asn1: &'a [u8],
        oid: asn1::ObjectIdentifier,
    ) -> Result<PrivateKeyInfo<'a>> {
        Ok(PrivateKeyInfo {
            version: 0,
            private_key_algorithm: oid,
            private_key: DerEncOctetString::new(private_key_asn1)?,
            attributes: None,
        })
    }

    pub fn get_oid(&self) -> &asn1::ObjectIdentifier {
        &self.private_key_algorithm
    }

    pub fn get_private_key(&self) -> &[u8] {
        &self.private_key.as_bytes()
    }
}

/* Following structs are used for storage purposes */
#[derive(
    asn1::Asn1Read, asn1::Asn1Write, PartialEq, Hash, Clone, Eq, Debug,
)]
pub struct KAlgorithmIdentifier<'a> {
    pub oid: asn1::DefinedByMarker<asn1::ObjectIdentifier>,
    #[defined_by(oid)]
    pub params: KAlgorithmParameters<'a>,
}

#[derive(
    asn1::Asn1DefinedByRead,
    asn1::Asn1DefinedByWrite,
    PartialEq,
    Eq,
    Hash,
    Clone,
    Debug,
)]
pub enum KAlgorithmParameters<'a> {
    #[defined_by(oid::KKDF1_OID)]
    Kkdf1(KKDF1Params<'a>),

    #[defined_by(oid::PBKDF2_OID)]
    Pbkdf2(pkcs::PBKDF2Params<'a>),

    #[defined_by(oid::KKBPS1_OID)]
    Kkbps1(KKBPS1Params<'a>),

    #[defined_by(oid::AES_128_GCM_OID)]
    Aes128Gcm(KGCMParams),
    #[defined_by(oid::AES_192_GCM_OID)]
    Aes192Gcm(KGCMParams),
    #[defined_by(oid::AES_256_GCM_OID)]
    Aes256Gcm(KGCMParams),

    #[defined_by(oid::HMAC_WITH_SHA256_OID)]
    HmacWithSha256(Option<asn1::Null>),
    #[defined_by(oid::HMAC_WITH_SHA384_OID)]
    HmacWithSha384(Option<asn1::Null>),
    #[defined_by(oid::HMAC_WITH_SHA512_OID)]
    HmacWithSha512(Option<asn1::Null>),

    #[default]
    Other(asn1::ObjectIdentifier, Option<asn1::Tlv<'a>>),
}

#[derive(
    asn1::Asn1Read, asn1::Asn1Write, PartialEq, Eq, Hash, Clone, Debug,
)]
pub struct KKDF1Params<'a> {
    pub prf: Box<KAlgorithmIdentifier<'a>>,
    pub info: &'a [u8],
    pub key_length: u64,
}

#[derive(
    asn1::Asn1Read, asn1::Asn1Write, PartialEq, Eq, Hash, Clone, Debug,
)]
pub struct KKBPS1Params<'a> {
    pub key_version_number: u64,
    pub key_derivation_func: Box<KAlgorithmIdentifier<'a>>,
    pub encryption_scheme: Box<KAlgorithmIdentifier<'a>>,
}

#[derive(
    asn1::Asn1Read, asn1::Asn1Write, PartialEq, Eq, Hash, Clone, Debug,
)]
pub struct KProtectedData<'a> {
    pub algorithm: Box<KAlgorithmIdentifier<'a>>,
    pub data: &'a [u8],
    pub signature: Option<&'a [u8]>,
}

#[derive(
    asn1::Asn1Read, asn1::Asn1Write, PartialEq, Eq, Hash, Clone, Debug,
)]
pub struct KGCMParams {
    pub aes_iv: [u8; 12],
    pub aes_tag: [u8; 8],
}

#[allow(dead_code)]
pub mod oid;

#[allow(dead_code)]
pub mod pkcs;
