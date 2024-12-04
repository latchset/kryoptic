// Copyright 2024 Simo Sorce
// See LICENSE.txt file for terms
include! {"pyca/oid.rs"}

pub const PBMAC1_OID: asn1::ObjectIdentifier =
    asn1::oid!(1, 2, 840, 113549, 1, 5, 14);

pub const AES_128_GCM_OID: asn1::ObjectIdentifier =
    asn1::oid!(2, 16, 840, 1, 101, 3, 4, 1, 6);
pub const AES_192_GCM_OID: asn1::ObjectIdentifier =
    asn1::oid!(2, 16, 840, 1, 101, 3, 4, 1, 26);
pub const AES_256_GCM_OID: asn1::ObjectIdentifier =
    asn1::oid!(2, 16, 840, 1, 101, 3, 4, 1, 46);

pub const HMAC_WITH_SHA384_OID: asn1::ObjectIdentifier =
    asn1::oid!(1, 2, 840, 113549, 2, 10);
pub const HMAC_WITH_SHA512_OID: asn1::ObjectIdentifier =
    asn1::oid!(1, 2, 840, 113549, 2, 11);

pub const KKDF1_OID: asn1::ObjectIdentifier =
    asn1::oid!(1, 3, 6, 1, 4, 1, 2312, 20, 1, 1);
pub const KKBPS1_OID: asn1::ObjectIdentifier =
    asn1::oid!(1, 3, 6, 1, 4, 1, 2312, 20, 2, 1);
