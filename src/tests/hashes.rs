// Copyright 2024 Simo Sorce
// See LICENSE.txt file for terms

use crate::tests::*;

use serial_test::parallel;

#[test]
#[parallel]
fn test_hashes_digest() {
    let mut testtokn = TestToken::initialized("test_hashes", None);
    let session = testtokn.get_session(false);

    /* test data */
    let hash = hex::decode(
        "e32bd03f46f51d4a5c903429fea1c31032d8d7aa689c764141b7cebd74f4e140",
    )
    .expect("failed to decode hash");
    let mut value = hex::decode("48656c6c6f205348413235360a")
        .expect("failed to decode value");

    /* one shot digest */
    let mut mechanism: CK_MECHANISM = CK_MECHANISM {
        mechanism: CKM_SHA256,
        pParameter: std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    let mut ret = fn_digest_init(session, &mut mechanism);
    assert_eq!(ret, CKR_OK);

    let mut digest: [u8; 32] = [0; 32];
    let mut digest_len: CK_ULONG = digest.len() as CK_ULONG;
    ret = fn_digest(
        session,
        value.as_mut_ptr(),
        value.len() as CK_ULONG,
        digest.as_mut_ptr(),
        &mut digest_len,
    );
    assert_eq!(ret, CKR_OK);
    assert_eq!(hash, digest);

    /* update digest */
    ret = fn_digest_init(session, &mut mechanism);
    assert_eq!(ret, CKR_OK);

    ret =
        fn_digest_update(session, value.as_mut_ptr(), value.len() as CK_ULONG);
    assert_eq!(ret, CKR_OK);

    let mut digest2_len: CK_ULONG = 0;
    ret = fn_digest_final(session, std::ptr::null_mut(), &mut digest2_len);
    assert_eq!(ret, CKR_OK);
    assert_eq!(digest_len, digest2_len);

    let mut digest2: [u8; 32] = [0; 32];
    ret = fn_digest_final(session, digest2.as_mut_ptr(), &mut digest2_len);
    assert_eq!(ret, CKR_OK);
    assert_eq!(hash, digest);

    /* ==== SHA 384 ==== */

    /* test data */
    let hash = hex::decode(
        "d20cf10aec4b5294440edb9650bd0e91f2652c7535e42d3565e1710873d15de5\
         d9773637b15bb08c757bea52580d87c5",
    )
    .expect("failed to decode hash");
    let mut value = hex::decode("48656c6c6f205348413338340a")
        .expect("failed to decode value");

    /* one shot digest */
    let mut mechanism: CK_MECHANISM = CK_MECHANISM {
        mechanism: CKM_SHA384,
        pParameter: std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    ret = fn_digest_init(session, &mut mechanism);
    assert_eq!(ret, CKR_OK);

    let mut digest: [u8; 48] = [0; 48];
    let mut digest_len: CK_ULONG = digest.len() as CK_ULONG;
    ret = fn_digest(
        session,
        value.as_mut_ptr(),
        value.len() as CK_ULONG,
        digest.as_mut_ptr(),
        &mut digest_len,
    );
    assert_eq!(ret, CKR_OK);
    assert_eq!(hash, digest);

    /* ==== SHA 512 ==== */

    /* test data */
    let hash = hex::decode(
        "eec46beef24079f2d0f2e1c34f88baa7d8d89014fd453c12ceedc7590999104b\
         d0223646fb10c00068a5c46b7d6bf21ab119af3717f59d6b6f70a503ac515605",
    )
    .expect("failed to decode hash");
    let mut value = hex::decode("48656c6c6f205348413531320a")
        .expect("failed to decode value");

    /* one shot digest */
    let mut mechanism: CK_MECHANISM = CK_MECHANISM {
        mechanism: CKM_SHA512,
        pParameter: std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    ret = fn_digest_init(session, &mut mechanism);
    assert_eq!(ret, CKR_OK);

    let mut digest: [u8; 64] = [0; 64];
    let mut digest_len: CK_ULONG = digest.len() as CK_ULONG;
    ret = fn_digest(
        session,
        value.as_mut_ptr(),
        value.len() as CK_ULONG,
        digest.as_mut_ptr(),
        &mut digest_len,
    );
    assert_eq!(ret, CKR_OK);
    assert_eq!(hash, digest);

    #[cfg(not(feature = "no_sha1"))]
    {
        /* ==== SHA 1 ==== */
        /* test data */
        let hash = hex::decode("31d2378fd917639c7120f58bdff96da84dc5b19f")
            .expect("failed to decode hash");
        let mut value = hex::decode("48656c6c6f20534841310a")
            .expect("failed to decode value");

        /* one shot digest */
        let mut mechanism: CK_MECHANISM = CK_MECHANISM {
            mechanism: CKM_SHA_1,
            pParameter: std::ptr::null_mut(),
            ulParameterLen: 0,
        };
        ret = fn_digest_init(session, &mut mechanism);
        assert_eq!(ret, CKR_OK);

        let mut digest: [u8; 20] = [0; 20];
        let mut digest_len: CK_ULONG = digest.len() as CK_ULONG;
        ret = fn_digest(
            session,
            value.as_mut_ptr(),
            value.len() as CK_ULONG,
            digest.as_mut_ptr(),
            &mut digest_len,
        );
        assert_eq!(ret, CKR_OK);
        assert_eq!(hash, digest);
    }

    testtokn.finalize();
}

#[test]
#[parallel]
fn test_hashes_digest_key() {
    let mut testtokn = TestToken::initialized("test_hashes_key", None);
    let session = testtokn.get_session(true);

    let mut mechanism: CK_MECHANISM = CK_MECHANISM {
        mechanism: CKM_SHA256,
        pParameter: std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    let mut key = [0x55u8; 16];
    let hash = hex::decode(
        "b1bfaa407f70c80c650379dfeafaa40f29b753b076f9ae8fc7f6eddb1941e904",
    )
    .expect("failed to decode hash");

    /* Sanity */
    let mut ret = fn_digest_init(session, &mut mechanism);
    assert_eq!(ret, CKR_OK);

    let mut digest: [u8; 32] = [0; 32];
    let mut digest_len: CK_ULONG = digest.len() as CK_ULONG;
    ret = fn_digest(
        session,
        key.as_mut_ptr(),
        key.len() as CK_ULONG,
        digest.as_mut_ptr(),
        &mut digest_len,
    );
    assert_eq!(ret, CKR_OK);
    assert_eq!(hash, digest);

    /* login */
    testtokn.login();

    /* Import AES key */
    let handle = ret_or_panic!(import_object(
        session,
        CKO_SECRET_KEY,
        &[(CKA_KEY_TYPE, CKK_AES)],
        &[(CKA_VALUE, &key)],
        &[(CKA_EXTRACTABLE, true), (CKA_TOKEN, true)],
    ));

    let ret = fn_digest_init(session, &mut mechanism);
    assert_eq!(ret, CKR_OK);

    let ret = fn_digest_key(session, handle);
    assert_eq!(ret, CKR_OK);

    let mut digest_len: CK_ULONG = 0;
    let ret = fn_digest_final(session, std::ptr::null_mut(), &mut digest_len);
    assert_eq!(ret, CKR_OK);
    assert_eq!(digest_len, 32);

    let mut digest: [u8; 32] = [0; 32];
    let ret = fn_digest_final(session, digest.as_mut_ptr(), &mut digest_len);
    assert_eq!(ret, CKR_OK);
    assert_eq!(hash, digest);

    /* This should not work without login */
    testtokn.logout();

    let ret = fn_digest_init(session, &mut mechanism);
    assert_eq!(ret, CKR_OK);

    let ret = fn_digest_key(session, handle);
    /* The NSSDB returns CKR_USER_NOT_LOGGED_IN, but other backends CKR_GENERAL_ERROR */
    assert_ne!(ret, CKR_OK);

    testtokn.finalize();
}
