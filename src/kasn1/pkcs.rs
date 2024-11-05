// Copyright 2024 Simo Sorce
// See LICENSE.txt file for terms

use crate::error::Result;
use crate::kasn1::oid;
use crate::kasn1::DerEncOctetString;
use crate::kasn1::Version;

use asn1;

include! {"pyca/pkcs.rs"}

#[derive(asn1::Asn1Read, asn1::Asn1Write)]
pub enum ECParameters<'a> {
    //EcParameters(EcParameters<'a>),
    OId(asn1::ObjectIdentifier),
    ImplicitlyCA(asn1::Null),
    CurveName(asn1::PrintableString<'a>),
}

// Defined in SECG SEC 1, C.4
#[derive(asn1::Asn1Read, asn1::Asn1Write)]
pub struct ECPrivateKey<'a> {
    version: Version,
    pub private_key: DerEncOctetString<'a>,
    #[explicit(0)]
    parameters: Option<ECParameters<'a>>,
    #[explicit(1)]
    public_key: Option<asn1::BitString<'a>>,
}

impl ECPrivateKey<'_> {
    pub fn new_owned<'a>(private_key: &'a Vec<u8>) -> Result<ECPrivateKey<'a>> {
        Ok(ECPrivateKey {
            version: 1,
            private_key: DerEncOctetString::new(private_key.as_slice())?,
            parameters: None,
            public_key: None,
        })
    }
}

#[derive(
    asn1::Asn1Read, asn1::Asn1Write, PartialEq, Eq, Hash, Clone, Debug,
)]
pub struct PBMAC1Params<'a> {
    pub key_derivation_func: Box<AlgorithmIdentifier<'a>>,
    pub message_auth_scheme: Box<AlgorithmIdentifier<'a>>,
}
