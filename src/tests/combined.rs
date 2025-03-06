// Copyright 2025 Simo Sorce
// See LICENSE.txt file for terms

use crate::tests::*;

use serial_test::parallel;

#[test]
#[parallel]
#[cfg(all(feature = "aes", feature = "hash"))]
fn test_combined_operations() {
    let mut testtokn = TestToken::initialized("test_combined_operations", None);
    let session = testtokn.get_session(true);

    /* login */
    testtokn.login();

    /* Generate AES key */
    let handle = ret_or_panic!(generate_key(
        session,
        CKM_AES_KEY_GEN,
        std::ptr::null_mut(),
        0,
        &[(CKA_VALUE_LEN, 16),],
        &[],
        &[(CKA_TOKEN, false), (CKA_ENCRYPT, true), (CKA_DECRYPT, true),],
    ));

    let param = CK_AES_CTR_PARAMS {
        ulCounterBits: 128,
        cb: [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A,
            0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        ],
    };

    /* init encryption */
    let mut mechanism: CK_MECHANISM = CK_MECHANISM {
        mechanism: CKM_AES_CTR,
        pParameter: void_ptr!(&param),
        ulParameterLen: sizeof!(CK_AES_CTR_PARAMS),
    };
    let ret = fn_encrypt_init(session, &mut mechanism, handle);
    assert_eq!(ret, CKR_OK);

    /* init digest */
    let mut mechanism: CK_MECHANISM = CK_MECHANISM {
        mechanism: CKM_SHA256,
        pParameter: std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    let ret = fn_digest_init(session, &mut mechanism);
    assert_eq!(ret, CKR_OK);

    let mut data: [u8; 13] = [0x99; 13];
    let mut enc: [u8; 16] = [0; 16];
    let mut enc_len: CK_ULONG = 16;

    /* combined update */
    let ret = fn_digest_encrypt_update(
        session,
        data.as_mut_ptr(),
        data.len() as CK_ULONG,
        enc.as_mut_ptr(),
        &mut enc_len,
    );
    assert_eq!(ret, CKR_OK);
    assert_eq!(enc_len as usize, data.len());

    /* finalize encryption part */
    let mut no_len: CK_ULONG = 0;
    let ret = fn_encrypt_final(session, enc.as_mut_ptr(), &mut no_len);
    assert_eq!(ret, CKR_OK);
    assert_eq!(no_len, 0);

    /* finalize digest part */
    let mut digest: [u8; 32] = [0u8; 32];
    let mut digest_len: CK_ULONG = 32;
    let ret = fn_digest_final(session, digest.as_mut_ptr(), &mut digest_len);
    assert_eq!(ret, CKR_OK);

    /* <<<< reverse now */

    let param = CK_AES_CTR_PARAMS {
        ulCounterBits: 128,
        cb: [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A,
            0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        ],
    };

    /* init decryption */
    let mut mechanism: CK_MECHANISM = CK_MECHANISM {
        mechanism: CKM_AES_CTR,
        pParameter: void_ptr!(&param),
        ulParameterLen: sizeof!(CK_AES_CTR_PARAMS),
    };
    let ret = fn_decrypt_init(session, &mut mechanism, handle);
    assert_eq!(ret, CKR_OK);

    /* init digest */
    let mut mechanism: CK_MECHANISM = CK_MECHANISM {
        mechanism: CKM_SHA256,
        pParameter: std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    let ret = fn_digest_init(session, &mut mechanism);
    assert_eq!(ret, CKR_OK);

    let mut dec: [u8; 16] = [0; 16];
    let mut dec_len: CK_ULONG = 16;

    /* combined update */
    let ret = fn_decrypt_digest_update(
        session,
        enc.as_mut_ptr(),
        enc_len,
        dec.as_mut_ptr(),
        &mut dec_len,
    );
    assert_eq!(ret, CKR_OK);
    assert_eq!(enc_len, dec_len);

    /* finalize decryption part */
    let ret = fn_decrypt_final(session, dec.as_mut_ptr(), &mut no_len);
    assert_eq!(ret, CKR_OK);
    assert_eq!(no_len, 0);
    assert_eq!(dec[0..(dec_len as usize)], data);

    /* finalize digest part */
    let mut digest2: [u8; 32] = [0; 32];
    let ret = fn_digest_final(session, digest2.as_mut_ptr(), &mut digest_len);
    assert_eq!(ret, CKR_OK);
    assert_eq!(digest, digest2);

    testtokn.finalize();
}
