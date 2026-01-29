// Copyright 2026 Simo Sorce
// See LICENSE.txt file for terms

use super::set_fips_error_state;
use crate::attribute::Attribute;
use crate::mechanism::Verify;
use crate::hmac::test_get_hmac;
use crate::native::hmac::HMACOperation;
use crate::native::tlskdf::TLSPRF;
use crate::object::Object;
use crate::pkcs11::*;
use std::sync::LazyLock;

/// Holds the result of the FIPS self-test
pub struct FIPSSelftest {
    pub result: CK_RV,
}

impl FIPSSelftest {
    fn fail() -> FIPSSelftest {
        set_fips_error_state();
        FIPSSelftest {
            result: CKR_FIPS_SELF_TEST_FAILED,
        }
    }
    fn pass() -> FIPSSelftest {
        FIPSSelftest { result: CKR_OK }
    }
}

/// Lazy code to run FIPS Known Answer Tests (KATs) on first use
///
/// Uses a test vector from OpenSSL.
///
/// If the calculated output does not match the expected output, it sets the
/// FIPS error state and stores `CKR_FIPS_SELF_TEST_FAILED` in
/// [FIPSSelfTest.result].
pub static HMAC_SELFTEST: LazyLock<FIPSSelftest> = LazyLock::new(|| {
    /* Test vector taken from OpenSSL selftest */
    let plaintext: [u8; 16] = [
        0xDD, 0x0C, 0x30, 0x33, 0x35, 0xF9, 0xE4, 0x2E, 0xC2, 0xEF, 0xCC, 0xBF,
        0x07, 0x95, 0xEE, 0xA2,
    ];
    let secret: Vec<u8> = vec![
        0xF4, 0x55, 0x66, 0x50, 0xAC, 0x31, 0xD3, 0x54, 0x61, 0x61, 0x0B, 0xAC,
        0x4E, 0xD8, 0x1B, 0x1A, 0x18, 0x1B, 0x2D, 0x8A, 0x43, 0xEA, 0x28, 0x54,
        0xCB, 0xAE, 0x22, 0xCA, 0x74, 0x56, 0x08, 0x13,
    ];
    let expect: [u8; 32] = [
        0xF5, 0xF5, 0xE5, 0xF2, 0x66, 0x49, 0xE2, 0x40, 0xFC, 0x9E, 0x85, 0x7F,
        0x2B, 0x9A, 0xBE, 0x28, 0x20, 0x12, 0x00, 0x92, 0x82, 0x21, 0x3E, 0x51,
        0x44, 0x5D, 0xE3, 0x31, 0x04, 0x01, 0x72, 0x6B,
    ];

    let mut hmac = match HMACOperation::internal(CKM_SHA256_HMAC, secret, 32) {
        Ok(h) => h,
        Err(_) => return FIPSSelftest::fail(),
    };
    if Verify::verify(&mut hmac, &plaintext, &expect).is_err() {
        return FIPSSelftest::fail();
    }
    FIPSSelftest::pass()
});

/// Static Lazy variable to run FIPS Known Answer Tests (KATs) for the TLS PRF
/// on first use
///
/// Uses a test vector from OpenSSL.
///
/// If the calculated output does not match the expected output, it sets the
/// FIPS error state and stores `CKR_FIPS_SELF_TEST_FAILED` in
/// [FIPSSelfTest.result].
pub static TLS_PRF_SELFTEST: LazyLock<FIPSSelftest> = LazyLock::new(|| {
    /* Test vector taken from OpenSSL selftest */
    let prf: CK_MECHANISM_TYPE = CKM_SHA256_HMAC;
    let secret = hex::decode(
        "202c88c00f84a17a20027079604787461176455539e705be\
         730890602c289a5001e34eeb3a043e5d52a65e66125188bf",
    )
    .unwrap();
    let label: &[u8] = b"key expansion";
    let randoms = hex::decode(
        "ae6c806f8ad4d80784549dff28a4b58fd837681a51d928c3e30ee5ff14f39868\
         62e1fd91f23f558a605f28478c58cf72637b89784d959df7e946d3f07bd1b616",
    )
    .unwrap();
    let mut seed = Vec::<u8>::with_capacity(label.len() + randoms.len());
    seed.extend_from_slice(&label);
    seed.extend_from_slice(&randoms);

    let expect = hex::decode(
        "d06139889fffac1e3a71865f504aa5d0d2a2e89506c6f2279b670c3e1b74f531\
         016a2530c51a3a0f7e1d6590d0f0566b2f387f8d11fd4f731cdd572d2eae927f\
         6f2f81410b25e6960be68985add6c38445ad9f8c64bf8068bf9a6679485d966f\
         1ad6f68b43495b10a683755ea2b858d70ccac7ec8b053c6bd41ca299d4e51928",
    )
    .unwrap();

    /* mock key */
    let mut key = Object::new();
    key.set_attr(Attribute::from_ulong(CKA_CLASS, CKO_SECRET_KEY))
        .unwrap();
    key.set_attr(Attribute::from_ulong(CKA_KEY_TYPE, CKK_GENERIC_SECRET))
        .unwrap();
    key.set_attr(Attribute::from_bytes(CKA_VALUE, secret.clone()))
        .unwrap();
    key.set_attr(Attribute::from_ulong(
        CKA_VALUE_LEN,
        secret.len() as CK_ULONG,
    ))
    .unwrap();
    key.set_attr(Attribute::from_bool(CKA_DERIVE, true))
        .unwrap();

    let mech = test_get_hmac(prf);

    let mut tlsprf = match TLSPRF::init(&key, &mech, prf) {
        Ok(a) => a,
        Err(_) => return FIPSSelftest::fail(),
    };
    let out = match tlsprf.finish(&seed, expect.len()) {
        Ok(a) => a,
        Err(_) => return FIPSSelftest::fail(),
    };
    if out == expect {
        FIPSSelftest::pass()
    } else {
        FIPSSelftest::fail()
    }
});
