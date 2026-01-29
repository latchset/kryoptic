// Copyright 2026 Simo Sorce
// See LICENSE.txt file for terms

use super::set_fips_error_state;
use crate::mechanism::Verify;
use crate::native::hmac::HMACOperation;
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
