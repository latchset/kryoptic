// Copyright 2023 Simo Sorce
// See LICENSE.txt file for terms

//! This module provides helpers to (de)serialize structures using Abstract
//! Syntax Notation One (ASN.1) abstractions using DER (Distinguished Encoding
//! Rules) encoding
//! Most of the helpers are imported from the Python Cryptographic Authority -
//! [cryptograhy](https://github.com/pyca/cryptography) project.

use std::borrow::Cow;

use crate::error::Result;
use crate::interface::*;
use crate::misc::zeromem;

use asn1;

/* Helper routines to use with rust/asn1 */

/// Wrapper object to properly handle DER Encoded
/// Big Unsigned Integers
pub struct DerEncBigUint<'a> {
    data: Cow<'a, [u8]>,
}

impl<'a> DerEncBigUint<'a> {
    /// Creates a DER Encoded Big Uint from a byte buffer
    ///
    /// This implementation checks that the higher order byte is smaller
    /// than 0x80, otherwise allocates a new copy of the buffer and prepends
    /// a 0 byte to it. This ensures the buffer is interpreted as an unsigned
    /// integer as in ASN.1 the leading bit is considered a sign bit.
    ///
    /// Uses a Cow buffer such that the provided slice can be directly
    /// referenced when the format does not need to be altered, avoiding
    /// unnecessary memory allocation in most cases.
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

    /// Returns a reference to the internal byte buffer
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
    /// Parses a DerEncBigUint from a data stream
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
    /// Writes out a DerEncBigUint
    fn write_data(&self, dest: &mut asn1::WriteBuf) -> asn1::WriteResult {
        dest.push_slice(self.as_bytes())
    }
}

/// Represents a ASN.1 OctetString wrapper
pub struct DerEncOctetString<'a> {
    data: Cow<'a, [u8]>,
}

impl<'a> DerEncOctetString<'a> {
    /// Returns a new DER Encoded OctetString
    ///
    /// Holds a reference to the provided slice
    ///
    /// Uses a Cow buffer such that the provided slice can be directly
    /// referenced, avoiding unnecessary memory allocation.
    pub fn new(data: &'a [u8]) -> Result<Self> {
        Ok(DerEncOctetString {
            data: Cow::from(data),
        })
    }

    /// Returns a reference to the internal byte buffer
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
    /// Parses a DerEncOctetString from a data stream
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
    /// Writes out a DerEncOctetString
    fn write_data(&self, dest: &mut asn1::WriteBuf) -> asn1::WriteResult {
        dest.push_slice(self.as_bytes())
    }
}

/// This type is used in PrivateKeyInfo
type Version = u64;

/// ASN.1 Attribute used in PrivateKeyInfo
#[derive(asn1::Asn1Read, asn1::Asn1Write)]
struct Attribute<'a> {
    /// Object Identifier for the contained attribute
    attribute_type: asn1::ObjectIdentifier,
    /// The value type is determined by the `attribute_type` member
    attribute_value: asn1::SetOf<'a, asn1::Tlv<'a>>, // ANY
}

/// Sequence of [Attribute] objects
type Attributes<'a> = asn1::SetOf<'a, Attribute<'a>>;

/// Defined in [RFC 5958](https://www.rfc-editor.org/rfc/rfc5958)
#[derive(asn1::Asn1Read, asn1::Asn1Write)]
pub struct PrivateKeyInfo<'a> {
    version: Version,
    algorithm: Box<pkcs::AlgorithmIdentifier<'a>>,
    private_key: DerEncOctetString<'a>,
    #[explicit(1)]
    attributes: Option<Attributes<'a>>,
}

#[allow(dead_code)]
impl PrivateKeyInfo<'_> {
    /// Wraps an encoded private key identified by the oid
    pub fn new<'a>(
        private_key_asn1: &'a [u8],
        algorithm: pkcs::AlgorithmIdentifier<'a>,
    ) -> Result<PrivateKeyInfo<'a>> {
        Ok(PrivateKeyInfo {
            version: 0,
            algorithm: Box::new(algorithm),
            private_key: DerEncOctetString::new(private_key_asn1)?,
            attributes: None,
        })
    }

    /// Returns the key type (as an OID)
    pub fn get_algorithm(&self) -> &pkcs::AlgorithmIdentifier {
        &self.algorithm
    }

    /// Returns a reference to the encoded private key
    pub fn get_private_key(&self) -> &[u8] {
        &self.private_key.as_bytes()
    }
}

/* Following structs are used for storage purposes */

/// Identifies an algorithm by OID for storage in ASN.1 encoded structures
#[derive(
    asn1::Asn1Read, asn1::Asn1Write, PartialEq, Hash, Clone, Eq, Debug,
)]
pub struct KAlgorithmIdentifier<'a> {
    pub oid: asn1::DefinedByMarker<asn1::ObjectIdentifier>,
    #[defined_by(oid)]
    pub params: KAlgorithmParameters<'a>,
}

/// Set of known Algorithms identified by OID
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

/// Kryoptic Key Derivation Function v1 parameters
///
/// Defines specific parameters to use with HKDF-Expand
#[derive(
    asn1::Asn1Read, asn1::Asn1Write, PartialEq, Eq, Hash, Clone, Debug,
)]
pub struct KKDF1Params<'a> {
    /// The Hash function to use
    pub prf: Box<KAlgorithmIdentifier<'a>>,
    /// Optional context and application specific information
    pub info: &'a [u8],
    /// Desired key output length
    pub key_length: u64,
}

/// Kryoptic Key Based Protection Scheme v1
#[derive(
    asn1::Asn1Read, asn1::Asn1Write, PartialEq, Eq, Hash, Clone, Debug,
)]
pub struct KKBPS1Params<'a> {
    /// A monotonicaly increasing number that identifies the version of
    /// the key used, allows for rolling key changes
    pub key_version_number: u64,
    /// The key derivation function used to derive the encryption key (KKDF1)
    pub key_derivation_func: Box<KAlgorithmIdentifier<'a>>,
    /// The encryption scheme used to encrypt the data (AES GCM)
    pub encryption_scheme: Box<KAlgorithmIdentifier<'a>>,
}

/// Kryoptic Protected Data Packet
#[derive(
    asn1::Asn1Read, asn1::Asn1Write, PartialEq, Eq, Hash, Clone, Debug,
)]
pub struct KProtectedData<'a> {
    /// The algorithm used to protect the data (ex: KKBPS1)
    pub algorithm: Box<KAlgorithmIdentifier<'a>>,
    /// The (encrypted) data buffer
    pub data: &'a [u8],
    /// Optional signature on the data, for uses where integrity
    /// is desired but encryption is not necessary.
    pub signature: Option<&'a [u8]>,
}

/// Kryoptic GCM Params
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
