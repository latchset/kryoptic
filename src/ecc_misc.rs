// Copyright 2023 - 2024 Simo Sorce, Jakub Jelen
// See LICENSE.txt file for terms

use super::error::Result;
use super::kasn1;

type Version = u64;

#[derive(asn1::Asn1Read, asn1::Asn1Write)]
pub enum ECParameters<'a> {
    // ecParametdders   ECParameters,
    OId(asn1::ObjectIdentifier),
    ImplicitlyCA(asn1::Null),
    CurveName(asn1::PrintableString<'a>),
}

/// Defined in SECG SEC 1, C.4
#[derive(asn1::Asn1Read, asn1::Asn1Write)]
pub struct ECPrivateKey<'a> {
    version: Version,
    pub private_key: kasn1::DerEncOctetString<'a>,
    #[explicit(0)]
    parameters: Option<ECParameters<'a>>,
    #[explicit(1)]
    public_key: Option<asn1::BitString<'a>>,
}

impl ECPrivateKey<'_> {
    pub fn new_owned<'a>(private_key: &'a Vec<u8>) -> Result<ECPrivateKey<'a>> {
        Ok(ECPrivateKey {
            version: 1,
            private_key: kasn1::DerEncOctetString::new(private_key.as_slice())?,
            parameters: None,
            public_key: None,
        })
    }
}
