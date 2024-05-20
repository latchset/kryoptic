// Copyright 2024 Simo Sorce
// See LICENSE.txt file for terms

use super::tests;
use tests::*;

const AES_BLOCK_SIZE: usize = 16;

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
    let handle = ret_or_panic!(generate_key(
        session,
        CKM_AES_KEY_GEN,
        &[(CKA_VALUE_LEN, 16),],
        &[],
        &[
            (CKA_SENSITIVE, true),
            (CKA_TOKEN, false),
            (CKA_ENCRYPT, true),
            (CKA_DECRYPT, true),
            (CKA_WRAP, true),
            (CKA_UNWRAP, true),
        ],
    ));

    {
        /* AES ECB */

        /* Data need to be exactly one block in size */
        let data = "0123456789ABCDEF";
        let enc = ret_or_panic!(encrypt(
            session,
            handle,
            data.as_bytes(),
            &CK_MECHANISM {
                mechanism: CKM_AES_ECB,
                pParameter: std::ptr::null_mut(),
                ulParameterLen: 0,
            },
        ));
        assert_eq!(enc.len(), AES_BLOCK_SIZE);

        let dec = ret_or_panic!(decrypt(
            session,
            handle,
            enc.as_slice(),
            &CK_MECHANISM {
                mechanism: CKM_AES_ECB,
                pParameter: std::ptr::null_mut(),
                ulParameterLen: 0,
            },
        ));
        assert_eq!(dec.len(), data.len());
        assert_eq!(data.as_bytes(), dec.as_slice());
    }

    {
        /* AES CBC */

        /* Data need to be exactly one block in size */
        let data = "0123456789ABCDEF";
        let iv = "FEDCBA0987654321";
        let enc = ret_or_panic!(encrypt(
            session,
            handle,
            data.as_bytes(),
            &CK_MECHANISM {
                mechanism: CKM_AES_CBC,
                pParameter: void_ptr!(iv.as_bytes()),
                ulParameterLen: iv.len() as CK_ULONG,
            }
        ));
        assert_eq!(enc.len(), 16);

        let dec = ret_or_panic!(decrypt(
            session,
            handle,
            enc.as_slice(),
            &CK_MECHANISM {
                mechanism: CKM_AES_CBC,
                pParameter: void_ptr!(iv.as_bytes()),
                ulParameterLen: iv.len() as CK_ULONG,
            }
        ));
        assert_eq!(dec.len(), data.len());
        assert_eq!(data.as_bytes(), dec.as_slice());
    }

    {
        /* AES CBC and Padding */

        let data = "0123456789ABCDEF";
        let iv = "FEDCBA0987654321";
        let enc = ret_or_panic!(encrypt(
            session,
            handle,
            data.as_bytes(),
            &CK_MECHANISM {
                mechanism: CKM_AES_CBC_PAD,
                pParameter: void_ptr!(iv.as_bytes()),
                ulParameterLen: iv.len() as CK_ULONG,
            },
        ));

        /* Data of exactly one block in size will cause two block output
         * The PKCS#11 specs are wrong here! */
        assert_eq!(enc.len(), AES_BLOCK_SIZE * 2);

        let dec = ret_or_panic!(decrypt(
            session,
            handle,
            enc.as_slice(),
            &CK_MECHANISM {
                mechanism: CKM_AES_CBC_PAD,
                pParameter: void_ptr!(iv.as_bytes()),
                ulParameterLen: iv.len() as CK_ULONG,
            },
        ));
        assert_eq!(dec.len(), data.len());
        assert_eq!(data.as_bytes(), dec.as_slice());
    }

    #[cfg(not(feature = "fips"))]
    {
        /* AES OFB */

        /* Stream mode, so arbitrary data size and matching output */
        let data = "01234567";
        let iv = "FEDCBA0987654321";

        let enc = ret_or_panic!(encrypt(
            session,
            handle,
            data.as_bytes(),
            &CK_MECHANISM {
                mechanism: CKM_AES_OFB,
                pParameter: void_ptr!(iv.as_bytes()),
                ulParameterLen: iv.len() as CK_ULONG,
            }
        ));
        assert_eq!(enc.len(), data.len());

        let dec = ret_or_panic!(decrypt(
            session,
            handle,
            enc.as_slice(),
            &CK_MECHANISM {
                mechanism: CKM_AES_OFB,
                pParameter: void_ptr!(iv.as_bytes()),
                ulParameterLen: iv.len() as CK_ULONG,
            }
        ));
        assert_eq!(dec.len(), data.len());
        assert_eq!(data.as_bytes(), dec.as_slice());
    }

    #[cfg(not(feature = "fips"))]
    {
        /* AES CFB */

        /* Stream mode, so arbitrary data size and matching output */
        let data = "01234567";
        let iv = "FEDCBA0987654321";

        let enc = ret_or_panic!(encrypt(
            session,
            handle,
            data.as_bytes(),
            &CK_MECHANISM {
                mechanism: CKM_AES_CFB1,
                pParameter: void_ptr!(iv.as_bytes()),
                ulParameterLen: iv.len() as CK_ULONG,
            }
        ));
        assert_eq!(enc.len(), data.len());

        let dec = ret_or_panic!(decrypt(
            session,
            handle,
            enc.as_slice(),
            &CK_MECHANISM {
                mechanism: CKM_AES_CFB1,
                pParameter: void_ptr!(iv.as_bytes()),
                ulParameterLen: iv.len() as CK_ULONG,
            }
        ));
        assert_eq!(dec.len(), data.len());
        assert_eq!(data.as_bytes(), dec.as_slice());
    }

    {
        /* AES CTR */

        let param = CK_AES_CTR_PARAMS {
            ulCounterBits: 128,
            cb: [
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
                0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
            ],
        };
        let mechanism: CK_MECHANISM = CK_MECHANISM {
            mechanism: CKM_AES_CTR,
            pParameter: void_ptr!(&param),
            ulParameterLen: std::mem::size_of::<CK_AES_CTR_PARAMS>()
                as CK_ULONG,
        };

        /* Stream mode, so arbitrary data size and matching output */
        let data = "01234567";

        let enc = ret_or_panic!(encrypt(
            session,
            handle,
            data.as_bytes(),
            &mechanism,
        ));
        assert_eq!(enc.len(), data.len());

        let dec =
            ret_or_panic!(
                decrypt(session, handle, enc.as_slice(), &mechanism,)
            );
        assert_eq!(dec.len(), data.len());
        assert_eq!(data.as_bytes(), dec.as_slice());

        /* Counterbits edge cases */

        /* 9 bit counter, counter value should allow a single block before
         * wrap around */
        let param = CK_AES_CTR_PARAMS {
            ulCounterBits: 9,
            cb: [
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x01, 0xFE,
            ],
        };
        let mut mechanism: CK_MECHANISM = CK_MECHANISM {
            mechanism: CKM_AES_CTR,
            pParameter: void_ptr!(&param),
            ulParameterLen: std::mem::size_of::<CK_AES_CTR_PARAMS>()
                as CK_ULONG,
        };

        let ret = fn_encrypt_init(session, &mut mechanism, handle);
        assert_eq!(ret, CKR_OK);

        /* Stream mode, so arbitrary data size and matching output */
        let mut data: [u8; 16] = [255u8; 16];
        let enc: [u8; 16] = [0; 16];
        let mut enc_len: CK_ULONG = 16;

        /* First block should succeed */
        let ret = fn_encrypt_update(
            session,
            data.as_mut_ptr(),
            data.len() as CK_ULONG,
            enc.as_ptr() as *mut _,
            &mut enc_len,
        );
        assert_eq!(ret, CKR_OK);
        assert_eq!(enc_len as usize, data.len());

        /* Second should fail */
        let ret = fn_encrypt_update(
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

        let iv = "FEDCBA0987654321";
        let mechanism = CK_MECHANISM {
            mechanism: CKM_AES_CTS,
            pParameter: void_ptr!(iv.as_bytes()),
            ulParameterLen: iv.len() as CK_ULONG,
        };

        /* CTS requires at least one block */
        let data = "01234567";

        let _ = err_or_panic!(
            encrypt(session, handle, data.as_bytes(), &mechanism),
            CKR_DATA_LEN_RANGE
        );

        /* CTS requires at least one block */
        let data = "0123456789ABCDEF1111";

        let enc = ret_or_panic!(encrypt(
            session,
            handle,
            data.as_bytes(),
            &mechanism,
        ));
        assert_eq!(enc.len(), data.len());

        let dec = ret_or_panic!(decrypt(
            session,
            handle,
            enc.as_slice(),
            &CK_MECHANISM {
                mechanism: CKM_AES_CTS,
                pParameter: void_ptr!(iv.as_bytes()),
                ulParameterLen: iv.len() as CK_ULONG,
            }
        ));
        assert_eq!(dec.len(), data.len());
        assert_eq!(data.as_bytes(), dec.as_slice());
    }

    {
        /* AES-GCM */

        let tag_len = 4usize;

        /* IV needs to be of size 12 for the test to work in FIPS mode as well */
        let iv = "BA0987654321";
        let aad = "AUTH ME";
        let param = CK_GCM_PARAMS {
            pIv: iv.as_ptr() as *mut CK_BYTE,
            ulIvLen: iv.len() as CK_ULONG,
            ulIvBits: (iv.len() * 8) as CK_ULONG,
            pAAD: aad.as_ptr() as *mut CK_BYTE,
            ulAADLen: aad.len() as CK_ULONG,
            ulTagBits: (tag_len * 8) as CK_ULONG,
        };

        let mut mechanism: CK_MECHANISM = CK_MECHANISM {
            mechanism: CKM_AES_GCM,
            pParameter: void_ptr!(&param),
            ulParameterLen: std::mem::size_of::<CK_GCM_PARAMS>() as CK_ULONG,
        };

        let ret = fn_encrypt_init(session, &mut mechanism, handle);
        assert_eq!(ret, CKR_OK);

        /* Stream mode, so arbitrary data size and matching output */
        let data = "01234567";
        /* enc needs enough space for the tag */
        let enc: [u8; 16] = [0; 16];
        let mut enc_len = enc.len() as CK_ULONG;
        let ret = fn_encrypt_update(
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
        let ret = fn_encrypt_update(
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
        let ret = fn_encrypt_final(
            session,
            unsafe { enc.as_ptr().offset(offset) } as *mut _,
            &mut enc_len,
        );
        assert_eq!(ret, CKR_OK);
        assert_eq!(enc_len, tag_len as CK_ULONG);

        let dec = ret_or_panic!(decrypt(
            session,
            handle,
            &enc[..(offset as usize + tag_len)],
            &mechanism,
        ));
        assert_eq!(dec.len(), data.len());
        assert_eq!(data.as_bytes(), dec.as_slice());

        /* retry with one-shot encrypt operation */
        let enc2 = ret_or_panic!(encrypt(
            session,
            handle,
            data.as_bytes(),
            &mechanism,
        ));
        assert_eq!(enc2.len(), 12);
        assert_eq!(&enc[..12], enc2.as_slice());
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

        let ret = fn_encrypt_init(session, &mut mechanism, handle);
        assert_eq!(ret, CKR_OK);

        /* enc needs enough space for the tag */
        let enc: [u8; 16] = [0; 16];
        let mut enc_len = enc.len() as CK_ULONG;

        let data_len = data.len() - 1;
        let ret = fn_encrypt_update(
            session,
            data.as_ptr() as *mut CK_BYTE,
            data_len as CK_ULONG,
            enc.as_ptr() as *mut _,
            &mut enc_len,
        );
        assert_eq!(ret, CKR_OK);
        assert_eq!(enc_len as usize, 0);

        enc_len = enc.len() as CK_ULONG;
        let ret = fn_encrypt_update(
            session,
            unsafe { data.as_ptr().offset(data_len as isize) } as *mut CK_BYTE,
            1 as CK_ULONG,
            enc.as_ptr() as *mut _,
            &mut enc_len,
        );
        assert_eq!(ret, CKR_OK);
        assert_eq!(enc_len as usize, data.len());

        enc_len = (enc.len() - data.len()) as CK_ULONG;
        let ret = fn_encrypt_final(
            session,
            unsafe { enc.as_ptr().offset(data.len() as isize) } as *mut _,
            &mut enc_len,
        );
        assert_eq!(ret, CKR_OK);
        assert_eq!(enc_len, tag_len as CK_ULONG);

        let dec = ret_or_panic!(decrypt(
            session,
            handle,
            &enc[..(data.len() + tag_len)],
            &mechanism,
        ));
        assert_eq!(dec.len(), data.len());
        assert_eq!(data.as_bytes(), dec.as_slice());
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

        let ciphertext = match get_test_data(session, testname, "ciphertext") {
            Ok(vec) => vec,
            Err(ret) => return assert_eq!(ret, CKR_OK),
        };
        let plaintext = match get_test_data(session, testname, "plaintext") {
            Ok(vec) => vec,
            Err(ret) => return assert_eq!(ret, CKR_OK),
        };

        let dec = ret_or_panic!(decrypt(
            session,
            key_handle,
            ciphertext.as_slice(),
            &CK_MECHANISM {
                mechanism: CKM_AES_ECB,
                pParameter: std::ptr::null_mut(),
                ulParameterLen: 0,
            },
        ));
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
        let iv = match get_test_data(session, testname, "iv") {
            Ok(vec) => vec,
            Err(ret) => return assert_eq!(ret, CKR_OK),
        };
        let plaintext = match get_test_data(session, testname, "plaintext") {
            Ok(vec) => vec,
            Err(ret) => return assert_eq!(ret, CKR_OK),
        };
        let ciphertext = match get_test_data(session, testname, "ciphertext") {
            Ok(vec) => vec,
            Err(ret) => return assert_eq!(ret, CKR_OK),
        };

        let enc = ret_or_panic!(encrypt(
            session,
            key_handle,
            plaintext.as_slice(),
            &CK_MECHANISM {
                mechanism: CKM_AES_CBC,
                pParameter: void_ptr!(iv.as_ptr()),
                ulParameterLen: iv.len() as CK_ULONG,
            }
        ));
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
        let iv = match get_test_data(session, testname, "IV") {
            Ok(vec) => vec,
            Err(ret) => return assert_eq!(ret, CKR_OK),
        };
        let aad = match get_test_data(session, testname, "AAD") {
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

        let param = CK_GCM_PARAMS {
            pIv: byte_ptr!(iv.as_ptr()),
            ulIvLen: iv.len() as CK_ULONG,
            ulIvBits: (iv.len() * 8) as CK_ULONG,
            pAAD: byte_ptr!(aad.as_ptr()),
            ulAADLen: aad.len() as CK_ULONG,
            ulTagBits: (tag.len() * 8) as CK_ULONG,
        };

        let mechanism: CK_MECHANISM = CK_MECHANISM {
            mechanism: CKM_AES_GCM,
            pParameter: void_ptr!(&param),
            ulParameterLen: std::mem::size_of::<CK_GCM_PARAMS>() as CK_ULONG,
        };

        let ciphertext = [&ct[..], &tag[..]].concat();

        let dec = ret_or_panic!(decrypt(
            session,
            key_handle,
            &ciphertext,
            &mechanism,
        ));
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
        let plaintext = match get_test_data(session, testname, "plaintext") {
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

        let mechanism: CK_MECHANISM = CK_MECHANISM {
            mechanism: CKM_AES_CTR,
            pParameter: void_ptr!(&param),
            ulParameterLen: std::mem::size_of::<CK_AES_CTR_PARAMS>()
                as CK_ULONG,
        };

        let enc = ret_or_panic!(encrypt(
            session,
            key_handle,
            plaintext.as_slice(),
            &mechanism,
        ));
        assert_eq!(&enc, &ciphertext);
    }

    for mech in [CKM_AES_KEY_WRAP, CKM_AES_KEY_WRAP_KWP] {
        /* AES KEY WRAP */

        /* encryption and key wrapping operations should give the same
         * result, so we try both and compare */

        let data = [0x55u8; AES_BLOCK_SIZE];
        let iv = [0xCCu8; 8];
        let iv_len = match mech {
            CKM_AES_KEY_WRAP => 8,
            CKM_AES_KEY_WRAP_KWP => 4,
            _ => panic!("uh?"),
        };

        let mut wrapped = [0u8; AES_BLOCK_SIZE * 2];
        let mut wraplen = wrapped.len() as CK_ULONG;
        let mut mechanism = CK_MECHANISM {
            mechanism: mech,
            pParameter: void_ptr!(&iv),
            ulParameterLen: iv_len,
        };

        /* key to be wrapped */
        let wp_handle = ret_or_panic!(import_object(
            session,
            CKO_SECRET_KEY,
            &[(CKA_KEY_TYPE, CKK_AES)],
            &[(CKA_VALUE, &data)],
            &[(CKA_EXTRACTABLE, true)],
        ));
        let ret = fn_wrap_key(
            session,
            &mut mechanism,
            handle,
            wp_handle,
            wrapped.as_mut_ptr(),
            &mut wraplen,
        );
        assert_eq!(ret, CKR_OK);

        let dec = ret_or_panic!(decrypt(
            session,
            handle,
            &wrapped[..(wraplen as usize)],
            &mechanism,
        ));
        assert_eq!(data, dec.as_slice());

        let mut enc =
            ret_or_panic!(encrypt(session, handle, &data, &mechanism,));

        let mut template = make_attr_template(
            &[
                (CKA_CLASS, CKO_SECRET_KEY),
                (CKA_KEY_TYPE, CKK_AES),
                (CKA_VALUE_LEN, 16),
            ],
            &[],
            &[(CKA_EXTRACTABLE, true)],
        );

        let mut wp_handle2 = CK_INVALID_HANDLE;
        let ret = fn_unwrap_key(
            session,
            &mut mechanism,
            handle,
            enc.as_mut_ptr(),
            enc.len() as CK_ULONG,
            template.as_mut_ptr(),
            template.len() as CK_ULONG,
            &mut wp_handle2,
        );
        assert_eq!(ret, CKR_OK);

        let mut value = [0u8; AES_BLOCK_SIZE];
        let mut extract_template = make_ptrs_template(&[(
            CKA_VALUE,
            void_ptr!(value.as_mut_ptr()),
            value.len(),
        )]);

        let ret = fn_get_attribute_value(
            session,
            wp_handle2,
            extract_template.as_mut_ptr(),
            extract_template.len() as CK_ULONG,
        );
        assert_eq!(ret, CKR_OK);
        assert_eq!(value, data);
    }

    testtokn.finalize();
}

#[test]
fn test_aes_macs() {
    let mut testtokn = TestToken::initialized("test_aes_macs.sql", None);
    let session = testtokn.get_session(true);

    /* login */
    testtokn.login();

    /* Generate AES key */
    let handle = ret_or_panic!(generate_key(
        session,
        CKM_AES_KEY_GEN,
        &[(CKA_VALUE_LEN, 16),],
        &[],
        &[(CKA_SIGN, true), (CKA_VERIFY, true),],
    ));

    #[cfg(not(feature = "fips"))]
    {
        /* AES MAC */

        let data = "01234567";

        let mac = ret_or_panic!(sig_gen(
            session,
            handle,
            data.as_bytes(),
            &CK_MECHANISM {
                mechanism: CKM_AES_MAC,
                pParameter: std::ptr::null_mut(),
                ulParameterLen: 0,
            }
        ));
        assert_eq!(mac.len(), AES_BLOCK_SIZE / 2);

        assert_eq!(
            CKR_OK,
            sig_verify(
                session,
                handle,
                data.as_bytes(),
                mac.as_slice(),
                &CK_MECHANISM {
                    mechanism: CKM_AES_MAC,
                    pParameter: std::ptr::null_mut(),
                    ulParameterLen: 0,
                }
            )
        );

        /* too long */
        let size: CK_ULONG = (AES_BLOCK_SIZE + 1) as CK_ULONG;
        err_or_panic!(
            sig_gen(
                session,
                handle,
                data.as_bytes(),
                &CK_MECHANISM {
                    mechanism: CKM_AES_MAC_GENERAL,
                    pParameter: void_ptr!(&size),
                    ulParameterLen: CK_ULONG_SIZE as CK_ULONG,
                }
            ),
            CKR_MECHANISM_PARAM_INVALID
        );

        let size: CK_ULONG = (AES_BLOCK_SIZE - 1) as CK_ULONG;
        let mac = ret_or_panic!(sig_gen(
            session,
            handle,
            data.as_bytes(),
            &CK_MECHANISM {
                mechanism: CKM_AES_MAC_GENERAL,
                pParameter: void_ptr!(&size),
                ulParameterLen: CK_ULONG_SIZE as CK_ULONG,
            }
        ));
        assert_eq!(mac.len(), size as usize);

        assert_eq!(
            CKR_OK,
            sig_verify(
                session,
                handle,
                data.as_bytes(),
                mac.as_slice(),
                &CK_MECHANISM {
                    mechanism: CKM_AES_MAC_GENERAL,
                    pParameter: void_ptr!(&size),
                    ulParameterLen: CK_ULONG_SIZE as CK_ULONG,
                }
            )
        );
    }

    {
        /* AES CMAC */

        let data = "01234567";

        let mac = ret_or_panic!(sig_gen(
            session,
            handle,
            data.as_bytes(),
            &CK_MECHANISM {
                mechanism: CKM_AES_CMAC,
                pParameter: std::ptr::null_mut(),
                ulParameterLen: 0,
            }
        ));
        assert_eq!(mac.len(), AES_BLOCK_SIZE);

        assert_eq!(
            CKR_OK,
            sig_verify(
                session,
                handle,
                data.as_bytes(),
                mac.as_slice(),
                &CK_MECHANISM {
                    mechanism: CKM_AES_CMAC,
                    pParameter: std::ptr::null_mut(),
                    ulParameterLen: 0,
                }
            )
        );

        /* too long */
        let size: CK_ULONG = (AES_BLOCK_SIZE + 1) as CK_ULONG;
        err_or_panic!(
            sig_gen(
                session,
                handle,
                data.as_bytes(),
                &CK_MECHANISM {
                    mechanism: CKM_AES_CMAC_GENERAL,
                    pParameter: void_ptr!(&size),
                    ulParameterLen: CK_ULONG_SIZE as CK_ULONG,
                }
            ),
            CKR_MECHANISM_PARAM_INVALID
        );

        let size: CK_ULONG = (AES_BLOCK_SIZE - 1) as CK_ULONG;

        let mac = ret_or_panic!(sig_gen(
            session,
            handle,
            data.as_bytes(),
            &CK_MECHANISM {
                mechanism: CKM_AES_CMAC_GENERAL,
                pParameter: void_ptr!(&size),
                ulParameterLen: CK_ULONG_SIZE as CK_ULONG,
            }
        ));
        assert_eq!(mac.len(), size as usize);

        assert_eq!(
            CKR_OK,
            sig_verify(
                session,
                handle,
                data.as_bytes(),
                mac.as_slice(),
                &CK_MECHANISM {
                    mechanism: CKM_AES_CMAC_GENERAL,
                    pParameter: void_ptr!(&size),
                    ulParameterLen: CK_ULONG_SIZE as CK_ULONG,
                }
            )
        );
    }

    testtokn.finalize();
}
