// Copyright 2024 Simo Sorce
// See LICENSE.txt file for terms

use super::tests;
use tests::*;

#[test]
fn test_aes_operations() {
    let mut testtokn = TestToken::initialized(
        "test_aes_operations.sql",
        Some("testdata/test_aes_operations.json"),
    );
    let session = testtokn.get_session(true);

    /* login */
    testtokn.login();

    /* Generate AES key */
    let mut mechanism: CK_MECHANISM = CK_MECHANISM {
        mechanism: CKM_AES_KEY_GEN,
        pParameter: std::ptr::null_mut(),
        ulParameterLen: 0,
    };

    let mut handle: CK_ULONG = CK_INVALID_HANDLE;

    let mut class = CKO_SECRET_KEY;
    let mut len: CK_ULONG = 16;
    let mut truebool = CK_TRUE;
    let mut falsebool = CK_FALSE;
    let mut template = vec![
        make_attribute!(CKA_CLASS, &mut class as *mut _, CK_ULONG_SIZE),
        make_attribute!(CKA_VALUE_LEN, &mut len as *mut _, CK_ULONG_SIZE),
        make_attribute!(CKA_SENSITIVE, &mut truebool as *mut _, CK_BBOOL_SIZE),
        make_attribute!(CKA_TOKEN, &mut falsebool as *mut _, CK_BBOOL_SIZE),
        make_attribute!(CKA_ENCRYPT, &mut truebool as *mut _, CK_BBOOL_SIZE),
        make_attribute!(CKA_DECRYPT, &mut truebool as *mut _, CK_BBOOL_SIZE),
    ];

    let mut ret = fn_generate_key(
        session,
        &mut mechanism,
        template.as_mut_ptr(),
        template.len() as CK_ULONG,
        &mut handle,
    );
    assert_eq!(ret, CKR_OK);

    {
        /* AES ECB */

        /* encrypt init */
        let mut mechanism: CK_MECHANISM = CK_MECHANISM {
            mechanism: CKM_AES_ECB,
            pParameter: std::ptr::null_mut(),
            ulParameterLen: 0,
        };

        ret = fn_encrypt_init(session, &mut mechanism, handle);
        assert_eq!(ret, CKR_OK);

        /* Data need to be exactly one block in size */
        let data = "0123456789ABCDEF";
        let mut enc_len: CK_ULONG = 0;
        ret = fn_encrypt(
            session,
            CString::new(data).unwrap().into_raw() as *mut u8,
            data.len() as CK_ULONG,
            std::ptr::null_mut(),
            &mut enc_len,
        );
        assert_eq!(ret, CKR_OK);
        assert_eq!(enc_len, 16);

        let enc: [u8; 16] = [0; 16];
        ret = fn_encrypt(
            session,
            CString::new(data).unwrap().into_raw() as *mut u8,
            data.len() as CK_ULONG,
            enc.as_ptr() as *mut _,
            &mut enc_len,
        );
        assert_eq!(ret, CKR_OK);
        assert_eq!(enc_len, 16);

        ret = fn_decrypt_init(session, &mut mechanism, handle);
        assert_eq!(ret, CKR_OK);

        let dec: [u8; 16] = [0; 16];
        let mut dec_len: CK_ULONG = 16;
        ret = fn_decrypt(
            session,
            enc.as_ptr() as *mut _,
            enc_len,
            dec.as_ptr() as *mut _,
            &mut dec_len,
        );
        assert_eq!(ret, CKR_OK);
        assert_eq!(dec_len as usize, data.len());
        assert_eq!(data.as_bytes(), &dec);
    }

    {
        /* AES CBC */

        /* encrypt init */
        let iv = "FEDCBA0987654321";
        let mut mechanism: CK_MECHANISM = CK_MECHANISM {
            mechanism: CKM_AES_CBC,
            pParameter: CString::new(iv).unwrap().into_raw() as CK_VOID_PTR,
            ulParameterLen: iv.len() as CK_ULONG,
        };

        ret = fn_encrypt_init(session, &mut mechanism, handle);
        assert_eq!(ret, CKR_OK);

        /* Data need to be exactly one block in size */
        let data = "0123456789ABCDEF";
        let enc: [u8; 16] = [0; 16];
        let mut enc_len: CK_ULONG = 16;
        ret = fn_encrypt(
            session,
            CString::new(data).unwrap().into_raw() as *mut u8,
            data.len() as CK_ULONG,
            enc.as_ptr() as *mut _,
            &mut enc_len,
        );
        assert_eq!(ret, CKR_OK);
        assert_eq!(enc_len, 16);

        ret = fn_decrypt_init(session, &mut mechanism, handle);
        assert_eq!(ret, CKR_OK);

        let dec: [u8; 16] = [0; 16];
        let mut dec_len: CK_ULONG = 16;
        ret = fn_decrypt(
            session,
            enc.as_ptr() as *mut _,
            enc_len,
            dec.as_ptr() as *mut _,
            &mut dec_len,
        );
        assert_eq!(ret, CKR_OK);
        assert_eq!(dec_len as usize, data.len());
        assert_eq!(data.as_bytes(), &dec);
    }

    {
        /* AES CBC and Padding */

        /* encrypt init */
        let iv = "FEDCBA0987654321";
        let mut mechanism: CK_MECHANISM = CK_MECHANISM {
            mechanism: CKM_AES_CBC_PAD,
            pParameter: CString::new(iv).unwrap().into_raw() as CK_VOID_PTR,
            ulParameterLen: iv.len() as CK_ULONG,
        };

        ret = fn_encrypt_init(session, &mut mechanism, handle);
        assert_eq!(ret, CKR_OK);

        /* Data of exactly one block in size will cause two block output
         * The PKCS#11 specs are wrong here! */
        let data = "0123456789ABCDEF";
        let mut enc_len: CK_ULONG = 0;
        ret = fn_encrypt(
            session,
            CString::new(data).unwrap().into_raw() as *mut u8,
            data.len() as CK_ULONG,
            std::ptr::null_mut(),
            &mut enc_len,
        );
        assert_eq!(ret, CKR_OK);
        assert_eq!(enc_len, 32);

        let enc: [u8; 32] = [0; 32];
        ret = fn_encrypt(
            session,
            CString::new(data).unwrap().into_raw() as *mut u8,
            data.len() as CK_ULONG,
            enc.as_ptr() as *mut _,
            &mut enc_len,
        );
        assert_eq!(ret, CKR_OK);
        assert_eq!(enc_len, 32);

        ret = fn_decrypt_init(session, &mut mechanism, handle);
        assert_eq!(ret, CKR_OK);

        let dec: [u8; 32] = [0; 32];
        let mut dec_len: CK_ULONG = 32;
        ret = fn_decrypt(
            session,
            enc.as_ptr() as *mut _,
            enc_len,
            dec.as_ptr() as *mut _,
            &mut dec_len,
        );
        assert_eq!(ret, CKR_OK);
        assert_eq!(dec_len as usize, data.len());
        assert_eq!(data.as_bytes(), &dec[..dec_len as usize])
    }

    #[cfg(not(feature = "fips"))]
    {
        /* AES OFB */

        /* encrypt init */
        let iv = "FEDCBA0987654321";
        let mut mechanism: CK_MECHANISM = CK_MECHANISM {
            mechanism: CKM_AES_OFB,
            pParameter: CString::new(iv).unwrap().into_raw() as CK_VOID_PTR,
            ulParameterLen: iv.len() as CK_ULONG,
        };

        ret = fn_encrypt_init(session, &mut mechanism, handle);
        assert_eq!(ret, CKR_OK);

        /* Stream mode, so arbitrary data size and matching output */
        let data = "01234567";
        let enc: [u8; 16] = [0; 16];
        let mut enc_len: CK_ULONG = 16;
        ret = fn_encrypt(
            session,
            CString::new(data).unwrap().into_raw() as *mut u8,
            data.len() as CK_ULONG,
            enc.as_ptr() as *mut _,
            &mut enc_len,
        );
        assert_eq!(ret, CKR_OK);
        assert_eq!(enc_len as usize, data.len());

        ret = fn_decrypt_init(session, &mut mechanism, handle);
        assert_eq!(ret, CKR_OK);

        let dec: [u8; 16] = [0; 16];
        let mut dec_len: CK_ULONG = 16;
        ret = fn_decrypt(
            session,
            enc.as_ptr() as *mut _,
            enc_len,
            dec.as_ptr() as *mut _,
            &mut dec_len,
        );
        assert_eq!(ret, CKR_OK);
        assert_eq!(dec_len as usize, data.len());
        assert_eq!(data.as_bytes(), &dec[..dec_len as usize])
    }

    #[cfg(not(feature = "fips"))]
    {
        /* AES CFB */

        /* encrypt init */
        let iv = "FEDCBA0987654321";
        let mut mechanism: CK_MECHANISM = CK_MECHANISM {
            mechanism: CKM_AES_CFB1,
            pParameter: CString::new(iv).unwrap().into_raw() as CK_VOID_PTR,
            ulParameterLen: iv.len() as CK_ULONG,
        };

        ret = fn_encrypt_init(session, &mut mechanism, handle);
        assert_eq!(ret, CKR_OK);

        /* Stream mode, so arbitrary data size and matching output */
        let data = "01234567";
        let enc: [u8; 16] = [0; 16];
        let mut enc_len: CK_ULONG = 16;
        ret = fn_encrypt(
            session,
            CString::new(data).unwrap().into_raw() as *mut u8,
            data.len() as CK_ULONG,
            enc.as_ptr() as *mut _,
            &mut enc_len,
        );
        assert_eq!(ret, CKR_OK);
        assert_eq!(enc_len as usize, data.len());

        ret = fn_decrypt_init(session, &mut mechanism, handle);
        assert_eq!(ret, CKR_OK);

        let dec: [u8; 16] = [0; 16];
        let mut dec_len: CK_ULONG = 16;
        ret = fn_decrypt(
            session,
            enc.as_ptr() as *mut _,
            enc_len,
            dec.as_ptr() as *mut _,
            &mut dec_len,
        );
        assert_eq!(ret, CKR_OK);
        assert_eq!(dec_len as usize, data.len());
        assert_eq!(data.as_bytes(), &dec[..dec_len as usize])
    }

    {
        /* AES CTR */

        /* encrypt init */
        let mut param = CK_AES_CTR_PARAMS {
            ulCounterBits: 128,
            cb: [
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
                0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
            ],
        };

        let mut mechanism: CK_MECHANISM = CK_MECHANISM {
            mechanism: CKM_AES_CTR,
            pParameter: &mut param as *mut CK_AES_CTR_PARAMS as CK_VOID_PTR,
            ulParameterLen: std::mem::size_of::<CK_AES_CTR_PARAMS>()
                as CK_ULONG,
        };

        ret = fn_encrypt_init(session, &mut mechanism, handle);
        assert_eq!(ret, CKR_OK);

        /* Stream mode, so arbitrary data size and matching output */
        let data = "01234567";
        let enc: [u8; 16] = [0; 16];
        let mut enc_len: CK_ULONG = 16;
        ret = fn_encrypt(
            session,
            CString::new(data).unwrap().into_raw() as *mut u8,
            data.len() as CK_ULONG,
            enc.as_ptr() as *mut _,
            &mut enc_len,
        );
        assert_eq!(ret, CKR_OK);
        assert_eq!(enc_len as usize, data.len());

        ret = fn_decrypt_init(session, &mut mechanism, handle);
        assert_eq!(ret, CKR_OK);

        let dec: [u8; 16] = [0; 16];
        let mut dec_len: CK_ULONG = 16;
        ret = fn_decrypt(
            session,
            enc.as_ptr() as *mut _,
            enc_len,
            dec.as_ptr() as *mut _,
            &mut dec_len,
        );
        assert_eq!(ret, CKR_OK);
        assert_eq!(dec_len as usize, data.len());
        assert_eq!(data.as_bytes(), &dec[..dec_len as usize]);

        /* Counterbits edge cases */

        /* 9 bit counter, counter value should allow a single block before
         * wrap around */
        let mut param = CK_AES_CTR_PARAMS {
            ulCounterBits: 9,
            cb: [
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x01, 0xFE,
            ],
        };

        let mut mechanism: CK_MECHANISM = CK_MECHANISM {
            mechanism: CKM_AES_CTR,
            pParameter: &mut param as *mut CK_AES_CTR_PARAMS as CK_VOID_PTR,
            ulParameterLen: std::mem::size_of::<CK_AES_CTR_PARAMS>()
                as CK_ULONG,
        };

        ret = fn_encrypt_init(session, &mut mechanism, handle);
        assert_eq!(ret, CKR_OK);

        /* Stream mode, so arbitrary data size and matching output */
        let mut data: [u8; 16] = [255u8; 16];
        let enc: [u8; 16] = [0; 16];
        let mut enc_len: CK_ULONG = 16;

        /* First block should succeed */
        ret = fn_encrypt_update(
            session,
            data.as_mut_ptr(),
            data.len() as CK_ULONG,
            enc.as_ptr() as *mut _,
            &mut enc_len,
        );
        assert_eq!(ret, CKR_OK);
        assert_eq!(enc_len as usize, data.len());

        /* Second should fail */
        ret = fn_encrypt_update(
            session,
            data.as_mut_ptr(),
            data.len() as CK_ULONG,
            enc.as_ptr() as *mut _,
            &mut enc_len,
        );
        assert_eq!(ret, CKR_DATA_LEN_RANGE);
    }

    {
        /* AES CTS */

        /* encrypt init */
        let iv = "FEDCBA0987654321";
        let mut mechanism: CK_MECHANISM = CK_MECHANISM {
            mechanism: CKM_AES_CTS,
            pParameter: CString::new(iv).unwrap().into_raw() as CK_VOID_PTR,
            ulParameterLen: iv.len() as CK_ULONG,
        };

        ret = fn_encrypt_init(session, &mut mechanism, handle);
        assert_eq!(ret, CKR_OK);

        /* CTS requires at least one block */
        let data = "01234567";
        let enc: [u8; 16] = [0; 16];
        let mut enc_len: CK_ULONG = 16;
        ret = fn_encrypt(
            session,
            CString::new(data).unwrap().into_raw() as *mut u8,
            data.len() as CK_ULONG,
            enc.as_ptr() as *mut _,
            &mut enc_len,
        );
        assert_eq!(ret, CKR_DATA_LEN_RANGE);

        ret = fn_encrypt_init(session, &mut mechanism, handle);
        assert_eq!(ret, CKR_OK);

        /* CTS requires at least one block */
        let data = "0123456789ABCDEF1111";
        let enc: [u8; 32] = [0; 32];
        let mut enc_len: CK_ULONG = 32;
        ret = fn_encrypt(
            session,
            CString::new(data).unwrap().into_raw() as *mut u8,
            data.len() as CK_ULONG,
            enc.as_ptr() as *mut _,
            &mut enc_len,
        );
        assert_eq!(ret, CKR_OK);
        assert_eq!(enc_len as usize, data.len());

        ret = fn_decrypt_init(session, &mut mechanism, handle);
        assert_eq!(ret, CKR_OK);

        let dec: [u8; 32] = [0; 32];
        let mut dec_len: CK_ULONG = 32;
        ret = fn_decrypt(
            session,
            enc.as_ptr() as *mut _,
            enc_len,
            dec.as_ptr() as *mut _,
            &mut dec_len,
        );
        assert_eq!(ret, CKR_OK);
        assert_eq!(dec_len as usize, data.len());
        assert_eq!(data.as_bytes(), &dec[..dec_len as usize])
    }

    {
        /* AES-GCM */

        let tag_len = 4usize;

        /* IV needs to be of size 12 for the test to work in FIPS mode as well */
        let iv = "BA0987654321";
        let aad = "AUTH ME";
        let mut param = CK_GCM_PARAMS {
            pIv: iv.as_ptr() as *mut CK_BYTE,
            ulIvLen: iv.len() as CK_ULONG,
            ulIvBits: (iv.len() * 8) as CK_ULONG,
            pAAD: aad.as_ptr() as *mut CK_BYTE,
            ulAADLen: aad.len() as CK_ULONG,
            ulTagBits: (tag_len * 8) as CK_ULONG,
        };

        let mut mechanism: CK_MECHANISM = CK_MECHANISM {
            mechanism: CKM_AES_GCM,
            pParameter: &mut param as *mut CK_GCM_PARAMS as CK_VOID_PTR,
            ulParameterLen: std::mem::size_of::<CK_GCM_PARAMS>() as CK_ULONG,
        };

        ret = fn_encrypt_init(session, &mut mechanism, handle);
        assert_eq!(ret, CKR_OK);

        /* Stream mode, so arbitrary data size and matching output */
        let data = "01234567";
        /* enc needs enough space for the tag */
        let enc: [u8; 16] = [0; 16];
        let mut enc_len = enc.len() as CK_ULONG;
        ret = fn_encrypt_update(
            session,
            data.as_ptr() as *mut CK_BYTE,
            (data.len() - 1) as CK_ULONG,
            enc.as_ptr() as *mut _,
            &mut enc_len,
        );
        assert_eq!(ret, CKR_OK);
        assert_eq!(enc_len as usize, data.len() - 1);

        let mut offset = enc_len as isize;
        enc_len = enc.len() as CK_ULONG - offset as CK_ULONG;
        ret = fn_encrypt_update(
            session,
            unsafe { data.as_ptr().offset(offset) } as *mut CK_BYTE,
            1 as CK_ULONG,
            unsafe { enc.as_ptr().offset(offset) } as *mut _,
            &mut enc_len,
        );
        assert_eq!(ret, CKR_OK);
        assert_eq!(enc_len, 1);

        offset += enc_len as isize;
        enc_len = enc.len() as CK_ULONG - offset as CK_ULONG;
        ret = fn_encrypt_final(
            session,
            unsafe { enc.as_ptr().offset(offset) } as *mut _,
            &mut enc_len,
        );
        assert_eq!(ret, CKR_OK);
        assert_eq!(enc_len, tag_len as CK_ULONG);

        ret = fn_decrypt_init(session, &mut mechanism, handle);
        assert_eq!(ret, CKR_OK);

        enc_len = offset as CK_ULONG + tag_len as CK_ULONG;

        let dec: [u8; 16] = [0; 16];
        let mut dec_len: CK_ULONG = 16;
        ret = fn_decrypt(
            session,
            enc.as_ptr() as *mut _,
            enc_len,
            dec.as_ptr() as *mut _,
            &mut dec_len,
        );
        assert_eq!(ret, CKR_OK);
        assert_eq!(dec_len as usize, data.len());
        assert_eq!(data.as_bytes(), &dec[..dec_len as usize]);

        /* retry with one-shot encrypt operation */
        ret = fn_encrypt_init(session, &mut mechanism, handle);
        assert_eq!(ret, CKR_OK);

        let data = "01234567";
        /* enc2 needs enough space for encrypted data and tag */
        let enc2: [u8; 12] = [0; 12];
        let mut enc_len = enc2.len() as CK_ULONG;
        ret = fn_encrypt(
            session,
            data.as_ptr() as *mut CK_BYTE,
            data.len() as CK_ULONG,
            std::ptr::null_mut(),
            &mut enc_len,
        );
        assert_eq!(ret, CKR_OK);
        assert_eq!(enc_len, 12);

        ret = fn_encrypt(
            session,
            data.as_ptr() as *mut CK_BYTE,
            data.len() as CK_ULONG,
            enc2.as_ptr() as *mut _,
            &mut enc_len,
        );
        assert_eq!(ret, CKR_OK);
        assert_eq!(enc_len, 12);

        assert_eq!(enc[..12], enc2);
    }

    {
        /* AES-CCM */

        /* Data Len needs to be known in advance for CCM */
        let data = "01234567";
        let tag_len = 4usize;

        let iv = "BA0987654321";
        let aad = "AUTH ME";
        let mut param = CK_CCM_PARAMS {
            ulDataLen: data.len() as CK_ULONG,
            pNonce: iv.as_ptr() as *mut CK_BYTE,
            ulNonceLen: iv.len() as CK_ULONG,
            pAAD: aad.as_ptr() as *mut CK_BYTE,
            ulAADLen: aad.len() as CK_ULONG,
            ulMACLen: tag_len as CK_ULONG,
        };

        let mut mechanism: CK_MECHANISM = CK_MECHANISM {
            mechanism: CKM_AES_CCM,
            pParameter: &mut param as *mut CK_CCM_PARAMS as CK_VOID_PTR,
            ulParameterLen: std::mem::size_of::<CK_CCM_PARAMS>() as CK_ULONG,
        };

        ret = fn_encrypt_init(session, &mut mechanism, handle);
        assert_eq!(ret, CKR_OK);

        /* enc needs enough space for the tag */
        let enc: [u8; 16] = [0; 16];
        let mut enc_len = enc.len() as CK_ULONG;

        let data_len = data.len() - 1;
        ret = fn_encrypt_update(
            session,
            data.as_ptr() as *mut CK_BYTE,
            data_len as CK_ULONG,
            enc.as_ptr() as *mut _,
            &mut enc_len,
        );
        assert_eq!(ret, CKR_OK);
        assert_eq!(enc_len as usize, 0);

        enc_len = enc.len() as CK_ULONG;
        ret = fn_encrypt_update(
            session,
            unsafe { data.as_ptr().offset(data_len as isize) } as *mut CK_BYTE,
            1 as CK_ULONG,
            enc.as_ptr() as *mut _,
            &mut enc_len,
        );
        assert_eq!(ret, CKR_OK);
        assert_eq!(enc_len as usize, data.len());

        enc_len = (enc.len() - data.len()) as CK_ULONG;
        ret = fn_encrypt_final(
            session,
            unsafe { enc.as_ptr().offset(data.len() as isize) } as *mut _,
            &mut enc_len,
        );
        assert_eq!(ret, CKR_OK);
        assert_eq!(enc_len, tag_len as CK_ULONG);

        ret = fn_decrypt_init(session, &mut mechanism, handle);
        assert_eq!(ret, CKR_OK);

        enc_len = (data.len() + tag_len) as CK_ULONG;

        let dec: [u8; 16] = [0; 16];
        let mut dec_len: CK_ULONG = 16;
        ret = fn_decrypt(
            session,
            enc.as_ptr() as *mut _,
            enc_len,
            dec.as_ptr() as *mut _,
            &mut dec_len,
        );
        assert_eq!(ret, CKR_OK);
        assert_eq!(dec_len as usize, data.len());
        assert_eq!(data.as_bytes(), &dec[..dec_len as usize])
    }

    /* Some sample test vectors taken from:
     * https://github.com/pyca/cryptography/blob/main/vectors/cryptography_vectors/ciphers/AES
     */

    {
        /* ECB */
        let testname = "ECBMMT256 DECRYPT 0";
        let key_handle =
            match get_test_key_handle(session, testname, CKO_SECRET_KEY) {
                Ok(k) => k,
                Err(e) => panic!("{}", e),
            };

        let mut ciphertext =
            match get_test_data(session, testname, "ciphertext") {
                Ok(vec) => vec,
                Err(ret) => return assert_eq!(ret, CKR_OK),
            };
        let plaintext = match get_test_data(session, testname, "plaintext") {
            Ok(vec) => vec,
            Err(ret) => return assert_eq!(ret, CKR_OK),
        };

        /* encrypt init */
        let mut mechanism: CK_MECHANISM = CK_MECHANISM {
            mechanism: CKM_AES_ECB,
            pParameter: std::ptr::null_mut(),
            ulParameterLen: 0,
        };

        ret = fn_decrypt_init(session, &mut mechanism, key_handle);
        assert_eq!(ret, CKR_OK);

        let mut dec = vec![0u8; plaintext.len()];
        let mut dec_len = dec.len() as CK_ULONG;
        ret = fn_decrypt(
            session,
            ciphertext.as_mut_ptr(),
            ciphertext.len() as CK_ULONG,
            dec.as_mut_ptr(),
            &mut dec_len,
        );
        assert_eq!(ret, CKR_OK);
        assert_eq!(dec_len, dec.len() as CK_ULONG);
        assert_eq!(&dec, &plaintext);
    }

    {
        /* CBC */

        let testname = "CBCMMT128 ENCRYPT 9";
        let key_handle =
            match get_test_key_handle(session, testname, CKO_SECRET_KEY) {
                Ok(k) => k,
                Err(e) => panic!("{}", e),
            };
        let mut iv = match get_test_data(session, testname, "iv") {
            Ok(vec) => vec,
            Err(ret) => return assert_eq!(ret, CKR_OK),
        };
        let mut plaintext = match get_test_data(session, testname, "plaintext")
        {
            Ok(vec) => vec,
            Err(ret) => return assert_eq!(ret, CKR_OK),
        };
        let ciphertext = match get_test_data(session, testname, "ciphertext") {
            Ok(vec) => vec,
            Err(ret) => return assert_eq!(ret, CKR_OK),
        };

        let mut mechanism: CK_MECHANISM = CK_MECHANISM {
            mechanism: CKM_AES_CBC,
            pParameter: iv.as_mut_ptr() as CK_VOID_PTR,
            ulParameterLen: iv.len() as CK_ULONG,
        };

        ret = fn_encrypt_init(session, &mut mechanism, key_handle);
        assert_eq!(ret, CKR_OK);

        let mut enc = vec![0u8; ciphertext.len()];
        let mut enc_len = enc.len() as CK_ULONG;
        ret = fn_encrypt(
            session,
            plaintext.as_mut_ptr(),
            plaintext.len() as CK_ULONG,
            enc.as_mut_ptr(),
            &mut enc_len,
        );
        assert_eq!(ret, CKR_OK);
        assert_eq!(enc_len, enc.len() as CK_ULONG);
        assert_eq!(&enc, &ciphertext);
    }

    {
        /* GCM */

        let testname = "gcmDecrypt128 96,104,128,128 0";
        let key_handle =
            match get_test_key_handle(session, testname, CKO_SECRET_KEY) {
                Ok(k) => k,
                Err(e) => panic!("{}", e),
            };
        let mut iv = match get_test_data(session, testname, "IV") {
            Ok(vec) => vec,
            Err(ret) => return assert_eq!(ret, CKR_OK),
        };
        let mut aad = match get_test_data(session, testname, "AAD") {
            Ok(vec) => vec,
            Err(ret) => return assert_eq!(ret, CKR_OK),
        };
        let tag = match get_test_data(session, testname, "Tag") {
            Ok(vec) => vec,
            Err(ret) => return assert_eq!(ret, CKR_OK),
        };
        let ct = match get_test_data(session, testname, "CT") {
            Ok(vec) => vec,
            Err(ret) => return assert_eq!(ret, CKR_OK),
        };
        let plaintext = match get_test_data(session, testname, "PT") {
            Ok(vec) => vec,
            Err(ret) => return assert_eq!(ret, CKR_OK),
        };

        let mut param = CK_GCM_PARAMS {
            pIv: iv.as_mut_ptr(),
            ulIvLen: iv.len() as CK_ULONG,
            ulIvBits: (iv.len() * 8) as CK_ULONG,
            pAAD: aad.as_mut_ptr(),
            ulAADLen: aad.len() as CK_ULONG,
            ulTagBits: (tag.len() * 8) as CK_ULONG,
        };

        let mut mechanism: CK_MECHANISM = CK_MECHANISM {
            mechanism: CKM_AES_GCM,
            pParameter: &mut param as *mut CK_GCM_PARAMS as CK_VOID_PTR,
            ulParameterLen: std::mem::size_of::<CK_GCM_PARAMS>() as CK_ULONG,
        };

        ret = fn_decrypt_init(session, &mut mechanism, key_handle);
        assert_eq!(ret, CKR_OK);

        let mut ciphertext = [&ct[..], &tag[..]].concat();

        let mut dec = vec![0u8; plaintext.len()];
        let mut dec_len = dec.len() as CK_ULONG;
        ret = fn_decrypt(
            session,
            ciphertext.as_mut_ptr(),
            ciphertext.len() as CK_ULONG,
            dec.as_mut_ptr(),
            &mut dec_len,
        );
        assert_eq!(ret, CKR_OK);
        assert_eq!(dec_len, dec.len() as CK_ULONG);
        assert_eq!(&dec, &plaintext);
    }

    {
        /* CTR */
        let testname = "aes-192-ctr ENCRYPT 2";
        let key_handle =
            match get_test_key_handle(session, testname, CKO_SECRET_KEY) {
                Ok(k) => k,
                Err(e) => panic!("{}", e),
            };
        let iv = match get_test_data(session, testname, "iv") {
            Ok(vec) => vec,
            Err(ret) => return assert_eq!(ret, CKR_OK),
        };
        let mut plaintext = match get_test_data(session, testname, "plaintext")
        {
            Ok(vec) => vec,
            Err(ret) => return assert_eq!(ret, CKR_OK),
        };
        let ciphertext = match get_test_data(session, testname, "ciphertext") {
            Ok(vec) => vec,
            Err(ret) => return assert_eq!(ret, CKR_OK),
        };

        let mut param = CK_AES_CTR_PARAMS {
            ulCounterBits: 32,
            cb: [0u8; 16],
        };
        param.cb.copy_from_slice(iv.as_slice());

        let mut mechanism: CK_MECHANISM = CK_MECHANISM {
            mechanism: CKM_AES_CTR,
            pParameter: &mut param as *mut CK_AES_CTR_PARAMS as CK_VOID_PTR,
            ulParameterLen: std::mem::size_of::<CK_AES_CTR_PARAMS>()
                as CK_ULONG,
        };

        ret = fn_encrypt_init(session, &mut mechanism, key_handle);
        assert_eq!(ret, CKR_OK);

        let mut enc = vec![0u8; ciphertext.len()];
        let mut enc_len = enc.len() as CK_ULONG;
        ret = fn_encrypt(
            session,
            plaintext.as_mut_ptr(),
            plaintext.len() as CK_ULONG,
            enc.as_mut_ptr(),
            &mut enc_len,
        );
        assert_eq!(ret, CKR_OK);
        assert_eq!(enc_len, enc.len() as CK_ULONG);
        assert_eq!(&enc, &ciphertext);
    }

    testtokn.finalize();
}
