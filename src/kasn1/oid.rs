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

// ML-DSA OIDs from https://csrc.nist.gov/projects/computer-security-objects-register/algorithm-registration#DSA
pub const MLDSA44_OID: asn1::ObjectIdentifier =
    asn1::oid!(2, 16, 840, 1, 101, 3, 4, 3, 17);
pub const MLDSA65_OID: asn1::ObjectIdentifier =
    asn1::oid!(2, 16, 840, 1, 101, 3, 4, 3, 18);
pub const MLDSA87_OID: asn1::ObjectIdentifier =
    asn1::oid!(2, 16, 840, 1, 101, 3, 4, 3, 19);

// ML-KEM OIDs from https://csrc.nist.gov/projects/computer-security-objects-register/algorithm-registration#KEM
pub const MLKEM512_OID: asn1::ObjectIdentifier =
    asn1::oid!(2, 16, 840, 1, 101, 3, 4, 4, 1);
pub const MLKEM768_OID: asn1::ObjectIdentifier =
    asn1::oid!(2, 16, 840, 1, 101, 3, 4, 4, 2);
pub const MLKEM1024_OID: asn1::ObjectIdentifier =
    asn1::oid!(2, 16, 840, 1, 101, 3, 4, 4, 3);

// SLH-DSA OIDs from https://csrc.nist.gov/projects/computer-security-objects-register/algorithm-registration#DSA
pub const SLHDSA_SHA2_128S_OID: asn1::ObjectIdentifier =
    asn1::oid!(2, 16, 840, 1, 101, 3, 4, 3, 20);
pub const SLHDSA_SHA2_128F_OID: asn1::ObjectIdentifier =
    asn1::oid!(2, 16, 840, 1, 101, 3, 4, 3, 21);
pub const SLHDSA_SHA2_192S_OID: asn1::ObjectIdentifier =
    asn1::oid!(2, 16, 840, 1, 101, 3, 4, 3, 22);
pub const SLHDSA_SHA2_192F_OID: asn1::ObjectIdentifier =
    asn1::oid!(2, 16, 840, 1, 101, 3, 4, 3, 23);
pub const SLHDSA_SHA2_256S_OID: asn1::ObjectIdentifier =
    asn1::oid!(2, 16, 840, 1, 101, 3, 4, 3, 24);
pub const SLHDSA_SHA2_256F_OID: asn1::ObjectIdentifier =
    asn1::oid!(2, 16, 840, 1, 101, 3, 4, 3, 25);
pub const SLHDSA_SHAKE_128S_OID: asn1::ObjectIdentifier =
    asn1::oid!(2, 16, 840, 1, 101, 3, 4, 3, 26);
pub const SLHDSA_SHAKE_128F_OID: asn1::ObjectIdentifier =
    asn1::oid!(2, 16, 840, 1, 101, 3, 4, 3, 27);
pub const SLHDSA_SHAKE_192S_OID: asn1::ObjectIdentifier =
    asn1::oid!(2, 16, 840, 1, 101, 3, 4, 3, 28);
pub const SLHDSA_SHAKE_192F_OID: asn1::ObjectIdentifier =
    asn1::oid!(2, 16, 840, 1, 101, 3, 4, 3, 29);
pub const SLHDSA_SHAKE_256S_OID: asn1::ObjectIdentifier =
    asn1::oid!(2, 16, 840, 1, 101, 3, 4, 3, 30);
pub const SLHDSA_SHAKE_256F_OID: asn1::ObjectIdentifier =
    asn1::oid!(2, 16, 840, 1, 101, 3, 4, 3, 31);
