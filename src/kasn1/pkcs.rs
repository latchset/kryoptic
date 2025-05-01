// Copyright 2024 Simo Sorce
// See LICENSE.txt file for terms

//! This module provides objects and helpers to handle the [asn1] objects
//! defined by various [PKCS](https://en.wikipedia.org/wiki/PKCS) standards.

use crate::error::Result;
use crate::kasn1::oid;
use crate::kasn1::DerEncOctetString;
use crate::kasn1::Version;

use asn1;

include! {"pyca/pkcs.rs"}

/// Defined in ANSI X9.62
///
/// This structure has been modified to remove the CHOICE of explicit parameters
///
/// An older version is also defined in [RFC 5480](https://www.rfc-editor.org/rfc/rfc5480)
/// but this version does not define the CurveName CHOICE
#[derive(asn1::Asn1Read, asn1::Asn1Write)]
pub enum ECParameters<'a> {
    //EcParameters(EcParameters<'a>),
    /// Aka as namedCurve, is an oid that identifies the curve
    OId(asn1::ObjectIdentifier),

    /// Aka implicitCurve, indicates that the parameters are defined out of band
    ///
    /// Should never be used
    ImplicitlyCA(asn1::Null),

    /// Identifies the curve via its standard printable name
    CurveName(asn1::PrintableString<'a>),
}

/// EC Private Key ASN.1 Object
///
/// Defined in [RFC 5915](https://www.rfc-editor.org/rfc/rfc5915)
#[derive(asn1::Asn1Read, asn1::Asn1Write)]
pub struct ECPrivateKey<'a> {
    /// The ASN.1 key structure version
    ///
    /// Allows to transparently support multiple version of this structure
    ///
    /// The only version available is ecPrivkeyVer1 (1)
    version: Version,

    /// The private point defined as an Octet String, obtained from the
    /// unsigned integer via the Integer-to-Octet-String-Primitive (I2OSP)
    /// defined in [RFC3447](https://www.rfc-editor.org/rfc/rfc3447).
    pub private_key: DerEncOctetString<'a>,

    /// Specifies the elliptic curve domain parameters associated to the
    /// private key.
    #[explicit(0)]
    parameters: Option<ECParameters<'a>>,

    /// Contains the elliptic curve public key associated with
    /// the private key as a BitString
    #[explicit(1)]
    public_key: Option<asn1::BitString<'a>>,
}

impl ECPrivateKey<'_> {
    /// Creates a new Private Key that references (via Cow) the private_key
    pub fn new_owned<'a>(private_key: &'a Vec<u8>) -> Result<ECPrivateKey<'a>> {
        Ok(ECPrivateKey {
            version: 1,
            private_key: DerEncOctetString::new(private_key.as_slice())?,
            parameters: None,
            public_key: None,
        })
    }
}

/// Password-Based Message Authentication Code 1 Parameters
#[derive(
    asn1::Asn1Read, asn1::Asn1Write, PartialEq, Eq, Hash, Clone, Debug,
)]
pub struct PBMAC1Params<'a> {
    /// The KDF algorithm identifier
    pub key_derivation_func: Box<AlgorithmIdentifier<'a>>,
    /// The Authentication scheme algorithm identifier
    pub message_auth_scheme: Box<AlgorithmIdentifier<'a>>,
}

/// The HMAC-SHA256 Algorithm identifier
pub const HMAC_SHA_256_ALG: AlgorithmIdentifier<'_> = AlgorithmIdentifier {
    oid: asn1::DefinedByMarker::marker(),
    params: AlgorithmParameters::HmacWithSha256(Some(())),
};
