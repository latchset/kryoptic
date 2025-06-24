// Copyright 2024 Simo Sorce
// See LICENSE.txt file for terms

use crate::tests::*;

use serial_test::parallel;

#[test]
#[parallel]
fn test_get_mechs() {
    let mut testtokn = TestToken::initialized("test_get_mechs", None);

    let mut count: CK_ULONG = 0;
    let ret = fn_get_mechanism_list(
        testtokn.get_slot(),
        std::ptr::null_mut(),
        &mut count,
    );
    assert_eq!(ret, CKR_OK);
    let mut mechs: Vec<CK_MECHANISM_TYPE> = vec![0; count as usize];
    let ret = fn_get_mechanism_list(
        testtokn.get_slot(),
        mechs.as_mut_ptr() as CK_MECHANISM_TYPE_PTR,
        &mut count,
    );
    assert_eq!(ret, CKR_OK);
    assert_eq!(true, count > 4);
    #[cfg(feature = "no_sha1")]
    {
        let mut sha1_found = 0;
        let sha1_list = [
            CKM_SHA1_RSA_PKCS,
            CKM_SHA1_RSA_X9_31,
            CKM_SHA1_RSA_PKCS_PSS,
            CKM_DSA_SHA1,
            CKM_SHA_1,
            CKM_SHA_1_HMAC,
            CKM_SHA_1_HMAC_GENERAL,
            CKM_SSL3_SHA1_MAC,
            CKM_SHA1_KEY_DERIVATION,
            CKM_PBE_SHA1_CAST128_CBC,
            CKM_PBE_SHA1_RC4_128,
            CKM_PBE_SHA1_RC4_40,
            CKM_PBE_SHA1_DES3_EDE_CBC,
            CKM_PBE_SHA1_DES2_EDE_CBC,
            CKM_PBE_SHA1_RC2_128_CBC,
            CKM_PBE_SHA1_RC2_40_CBC,
            CKM_PBA_SHA1_WITH_SHA1_HMAC,
            CKM_ECDSA_SHA1,
            CKM_SHA_1_KEY_GEN,
            CKM_PBE_SHA1_CAST128_CBC,
        ];
        for mech in &mechs {
            if sha1_list.contains(mech) {
                sha1_found += 1;
            }
        }
        assert_eq!(sha1_found, 0);
    }
    let mut info: CK_MECHANISM_INFO = Default::default();
    let ret = fn_get_mechanism_info(testtokn.get_slot(), mechs[0], &mut info);
    assert_eq!(ret, CKR_OK);

    testtokn.finalize();
}
