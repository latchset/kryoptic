// Copyright 2023 - 2024 Simo Sorce, Jakub Jelen
// See LICENSE.txt file for terms

use crate::bytes_attr_not_empty;
use crate::error::Result;
use crate::interface::*;
use crate::kasn1::DerEncOctetString;
use crate::object::Object;

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

pub fn ec_key_check_import(obj: &mut Object) -> Result<()> {
    bytes_attr_not_empty!(obj; CKA_EC_PARAMS);
    bytes_attr_not_empty!(obj; CKA_VALUE);
    Ok(())
}
