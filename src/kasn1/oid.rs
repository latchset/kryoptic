// Copyright 2024 Simo Sorce
// See LICENSE.txt file for terms

//! This module provides the OIDs definitions and objects instantiated
//! as [asn1::ObjectIdentifier]s used in this project.

include! {"pyca/oid.rs"}

/// Password-Based Message Authentication Code 1
pub const PBMAC1_OID: asn1::ObjectIdentifier =
    asn1::oid!(1, 2, 840, 113549, 1, 5, 14);

pub const AES_128_GCM_OID: asn1::ObjectIdentifier =
    asn1::oid!(2, 16, 840, 1, 101, 3, 4, 1, 6);
pub const AES_192_GCM_OID: asn1::ObjectIdentifier =
    asn1::oid!(2, 16, 840, 1, 101, 3, 4, 1, 26);
pub const AES_256_GCM_OID: asn1::ObjectIdentifier =
    asn1::oid!(2, 16, 840, 1, 101, 3, 4, 1, 46);

/// Kryoptic Key Derivation Function v1
pub const KKDF1_OID: asn1::ObjectIdentifier =
    asn1::oid!(1, 3, 6, 1, 4, 1, 2312, 20, 1, 1);
/// Kryoptic Key Based Protection Scheme v1
pub const KKBPS1_OID: asn1::ObjectIdentifier =
    asn1::oid!(1, 3, 6, 1, 4, 1, 2312, 20, 2, 1);

// The SHA3 OIDs are wrong in pyca
// https://github.com/pyca/cryptography/issues/13331
pub const SHA3_224_OID: asn1::ObjectIdentifier =
    asn1::oid!(2, 16, 840, 1, 101, 3, 4, 2, 7);
pub const SHA3_256_OID: asn1::ObjectIdentifier =
    asn1::oid!(2, 16, 840, 1, 101, 3, 4, 2, 8);
pub const SHA3_384_OID: asn1::ObjectIdentifier =
    asn1::oid!(2, 16, 840, 1, 101, 3, 4, 2, 9);
pub const SHA3_512_OID: asn1::ObjectIdentifier =
    asn1::oid!(2, 16, 840, 1, 101, 3, 4, 2, 10);
