// Copyright 2024 Simo Sorce
// See LICENSE.txt file for terms

//! This module provides objects and helpers to handle the [asn1] objects
//! defined by various [PKCS](https://en.wikipedia.org/wiki/PKCS) standards.

use crate::error::Result;
use crate::kasn1::{oid, DerEncBigUint, DerEncOctetString, Version};
use crate::pkcs11;

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

/// RSA Algorithm Identifier, typically used for Identifying a private or
/// public key (for example in PrivateKeyInfo)
pub const RSA_ALG: AlgorithmIdentifier<'_> = AlgorithmIdentifier {
    oid: asn1::DefinedByMarker::marker(),
    params: AlgorithmParameters::Rsa(Some(())),
};

/// P-256 Algorithm Identifier, typically used for Identifying a private or
/// public key (for example in PrivateKeyInfo)
pub const EC_SECP256R1_ALG: AlgorithmIdentifier<'_> = AlgorithmIdentifier {
    oid: asn1::DefinedByMarker::marker(),
    params: AlgorithmParameters::Ec(EcParameters::NamedCurve(
        oid::EC_SECP256R1,
    )),
};

/// P-384 Algorithm Identifier, typically used for Identifying a private or
/// public key (for example in PrivateKeyInfo)
pub const EC_SECP384R1_ALG: AlgorithmIdentifier<'_> = AlgorithmIdentifier {
    oid: asn1::DefinedByMarker::marker(),
    params: AlgorithmParameters::Ec(EcParameters::NamedCurve(
        oid::EC_SECP384R1,
    )),
};

/// P-521 Algorithm Identifier, typically used for Identifying a private or
/// public key (for example in PrivateKeyInfo)
pub const EC_SECP521R1_ALG: AlgorithmIdentifier<'_> = AlgorithmIdentifier {
    oid: asn1::DefinedByMarker::marker(),
    params: AlgorithmParameters::Ec(EcParameters::NamedCurve(
        oid::EC_SECP521R1,
    )),
};

/// Ed25519 Algorithm Identifier, typically used for Identifying a private or
/// public key (for example in PrivateKeyInfo)
pub const ED25519_ALG: AlgorithmIdentifier<'_> = AlgorithmIdentifier {
    oid: asn1::DefinedByMarker::marker(),
    params: AlgorithmParameters::Ed25519,
};

/// Ed448 Algorithm Identifier, typically used for Identifying a private or
/// public key (for example in PrivateKeyInfo)
pub const ED448_ALG: AlgorithmIdentifier<'_> = AlgorithmIdentifier {
    oid: asn1::DefinedByMarker::marker(),
    params: AlgorithmParameters::Ed448,
};

/// X25519 Algorithm Identifier, typically used for Identifying a private or
/// public key (for example in PrivateKeyInfo)
pub const X25519_ALG: AlgorithmIdentifier<'_> = AlgorithmIdentifier {
    oid: asn1::DefinedByMarker::marker(),
    params: AlgorithmParameters::X25519,
};

/// X448  Algorithm Identifier, typically used for Identifying a private or
/// public key (for example in PrivateKeyInfo
pub const X448_ALG: AlgorithmIdentifier<'_> = AlgorithmIdentifier {
    oid: asn1::DefinedByMarker::marker(),
    params: AlgorithmParameters::X448,
};

impl SubjectPublicKeyInfo<'_> {
    pub fn new<'a>(
        alg: AlgorithmIdentifier<'a>,
        pubkey: &'a [u8],
    ) -> Result<SubjectPublicKeyInfo<'a>> {
        Ok(SubjectPublicKeyInfo {
            algorithm: alg,
            subject_public_key: asn1::BitString::new(pubkey, 0)
                .ok_or(pkcs11::CKR_GENERAL_ERROR)?,
        })
    }

    // DER-encode SubjectPublicKeyInfo.
    pub fn serialize(&self) -> Result<Vec<u8>> {
        match asn1::write_single(self) {
            Ok(der) => Ok(der),
            Err(_) => Err(pkcs11::CKR_GENERAL_ERROR)?,
        }
    }
}

#[derive(asn1::Asn1Read, asn1::Asn1Write)]
pub struct RsaPublicKey<'a> {
    modulus: DerEncBigUint<'a>,
    public_exponent: DerEncBigUint<'a>,
}

impl RsaPublicKey<'_> {
    /// Constructs an `RsaPublicKey` ASN.1 structure from byte slices of its components.
    pub fn new<'a>(
        modulus: &'a Vec<u8>,
        public_exponent: &'a Vec<u8>,
    ) -> Result<RsaPublicKey<'a>> {
        Ok(RsaPublicKey {
            modulus: DerEncBigUint::new(modulus.as_slice())?,
            public_exponent: DerEncBigUint::new(public_exponent.as_slice())?,
        })
    }

    // DER-encode SubjectPublicKeyInfo.
    pub fn serialize(&self) -> Result<Vec<u8>> {
        match asn1::write_single(self) {
            Ok(der) => Ok(der),
            Err(_) => Err(pkcs11::CKR_GENERAL_ERROR)?,
        }
    }
}
