// Copyright 2024 Simo Sorce
// See LICENSE.txt file for terms

use crate::tests::*;

use serial_test::parallel;

const AES_BLOCK_SIZE: usize = 16;

fn get_gcm_test_data() -> (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) {
    let iv =
        hex::decode("3d8cf16e262880ddfe0c86eb").expect("failed to decode IV");
    let aad = hex::decode("8560b10c011a1d4190eb46a3692daa17")
        .expect("failed to decode AAD");
    let tag = hex::decode("761cb84a963e1db1a4ab2c5f904c09db")
        .expect("failed to decode tag");
    let ct =
        hex::decode("b1ee05f1415a61d7637e97c5f3").expect("Failed to decode CT");
    let plaintext = hex::decode("2efbaedfec3cfe4ac32f201fa5")
        .expect("Failed to decode plaintext");
    (iv, aad, tag, ct, plaintext)
}

#[test]
#[parallel]
fn test_aes_operations() {
    let mut testtokn = TestToken::initialized(
        "test_aes_operations",
        Some("testdata/test_aes_operations.json"),
    );
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
        &[
            (CKA_SENSITIVE, true),
            (CKA_TOKEN, false),
            (CKA_ENCRYPT, true),
            (CKA_DECRYPT, true),
            (CKA_WRAP, true),
            (CKA_UNWRAP, true),
        ],
    ));
    assert_eq!(check_validation(session, 1), true);
    assert_eq!(check_object_validation(session, handle, 1), true);

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

        /* When the AES buffer is partially full, verify that the
         * check against AES_BLOCK_SIZE (that is, the "entire block"
         * check) is '>=', not '>' */
        let ret = fn_encrypt_init(
            session,
            &mut CK_MECHANISM {
                mechanism: CKM_AES_ECB,
                pParameter: std::ptr::null_mut(),
                ulParameterLen: 0,
            },
            handle,
        );
        assert_eq!(ret, CKR_OK);

        let data = vec![0x01u8; 1];
        let enc = ret_or_panic!(encrypt_update(session, &data));
        assert_eq!(enc.len(), 0);

        let data = vec![0x0Fu8; 15];
        let enc = ret_or_panic!(encrypt_update(session, &data));

        /* Skip enc.len() assert, to demonstrate subsequent
         * CKR_DATA_LEN_RANGE error.  enc_len is 0 in the failure
         * case, 16 when the check is correct */
        /* assert_eq!(enc.len(), 16); */

        let final_enc = ret_or_panic!(encrypt_final(session));
        assert_eq!(final_enc.len(), 0);

        let ret = fn_decrypt_init(
            session,
            &mut CK_MECHANISM {
                mechanism: CKM_AES_ECB,
                pParameter: std::ptr::null_mut(),
                ulParameterLen: 0,
            },
            handle,
        );
        assert_eq!(ret, CKR_OK);

        let data = &enc[0..1];
        let dec = ret_or_panic!(decrypt_update(session, &data));
        assert_eq!(dec.len() as usize, 0);

        let data = &enc[1..=15];
        let dec = ret_or_panic!(decrypt_update(session, &data));

        let final_dec = ret_or_panic!(decrypt_final(session));
        assert_eq!(final_dec.len(), 0);
        assert_eq!(dec[0], 0x01u8);
        assert_eq!(dec[1..], vec![0x0Fu8; 15]);
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

        /* AES CBC negative test */
        let data = "short";
        let iv = "FEDCBA0987654321";
        err_or_panic!(
            encrypt(
                session,
                handle,
                data.as_bytes(),
                &CK_MECHANISM {
                    mechanism: CKM_AES_CBC,
                    pParameter: void_ptr!(iv.as_bytes()),
                    ulParameterLen: iv.len() as CK_ULONG,
                }
            ),
            CKR_DATA_LEN_RANGE
        );
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

        /* verify we can get out the padding only on final, when feeding block
         * sized input/output on C_EncryptUpdate */
        let iv = "FEDCBA0987654321";
        let mut mechanism = CK_MECHANISM {
            mechanism: CKM_AES_CBC_PAD,
            pParameter: void_ptr!(iv.as_bytes()),
            ulParameterLen: iv.len() as CK_ULONG,
        };

        let ret = fn_encrypt_init(session, &mut mechanism, handle);
        assert_eq!(ret, CKR_OK);

        let data = vec![0x0Au8; 64];
        let enc = ret_or_panic!(encrypt_update(session, &data));
        assert_eq!(enc.len(), data.len());

        let enc_final = ret_or_panic!(encrypt_final(session));
        assert_eq!(enc_final.len(), 16);
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
            ulParameterLen: sizeof!(CK_AES_CTR_PARAMS),
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
            ulParameterLen: sizeof!(CK_AES_CTR_PARAMS),
        };

        let ret = fn_encrypt_init(session, &mut mechanism, handle);
        assert_eq!(ret, CKR_OK);

        /* Stream mode, so arbitrary data size and matching output */
        let data: [u8; 16] = [255u8; 16];

        /* First block should succeed */
        let enc = ret_or_panic!(encrypt_update(session, &data,));
        assert_eq!(enc.len(), data.len());

        /* Second should fail */
        let ret = encrypt_update(session, &data).map_err(|err| err.rv());
        assert_eq!(ret, Err(CKR_DATA_LEN_RANGE));
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
            ulParameterLen: sizeof!(CK_GCM_PARAMS),
        };

        let ret = fn_encrypt_init(session, &mut mechanism, handle);
        assert_eq!(ret, CKR_OK);

        /* Stream mode, so arbitrary data size and matching output */
        let data = b"01234567";
        let mut enc =
            ret_or_panic!(encrypt_update(session, &data[..data.len() - 1]));
        assert_eq!(enc.len(), data.len() - 1);

        let mut enc_next =
            ret_or_panic!(encrypt_update(session, &data[data.len() - 1..]));
        assert_eq!(enc_next.len(), 1);
        enc.append(&mut enc_next);

        let mut enc_final = ret_or_panic!(encrypt_final(session));
        assert_eq!(enc_final.len(), tag_len);
        enc.append(&mut enc_final);

        /* test that we can get correct indicators based on inputs */
        assert_eq!(check_validation(session, 1), true);

        let ret = fn_decrypt_init(session, &mut mechanism, handle);
        assert_eq!(ret, CKR_OK);

        /* pass partial tag only */
        let dec = ret_or_panic!(decrypt_update(session, &enc[..enc.len() - 1]));
        assert_eq!(dec.len(), data.len() - 1);
        assert_eq!(&data[..data.len() - 1], dec.as_slice());

        let dec = ret_or_panic!(decrypt_update(session, &enc[enc.len() - 1..]));
        assert_eq!(dec.len(), 1);
        assert_eq!(&data[data.len() - 1..], dec.as_slice());

        let dec_final = ret_or_panic!(decrypt_final(session));
        assert_eq!(dec_final.len(), 0);

        /* retry with one-shot decrypt operation */
        let dec2 = ret_or_panic!(decrypt(session, handle, &enc, &mechanism));
        assert_eq!(dec2.len(), data.len());
        assert_eq!(data, dec2.as_slice());

        /* retry with one-shot encrypt operation */
        let enc2 = ret_or_panic!(encrypt(session, handle, data, &mechanism));
        assert_eq!(enc2.len(), 12);
        assert_eq!(enc, enc2);

        /* test that we can get correct indicators based on inputs */
        assert_eq!(check_validation(session, 1), true);

        /* GCM without TAG should fail */
        let iv = "BA0987654321";
        let param = CK_GCM_PARAMS {
            pIv: iv.as_ptr() as *mut CK_BYTE,
            ulIvLen: iv.len() as CK_ULONG,
            ulIvBits: (iv.len() * 8) as CK_ULONG,
            pAAD: std::ptr::null_mut() as *mut CK_BYTE,
            ulAADLen: 0,
            ulTagBits: 0,
        };

        let mut mechanism: CK_MECHANISM = CK_MECHANISM {
            mechanism: CKM_AES_GCM,
            pParameter: void_ptr!(&param),
            ulParameterLen: sizeof!(CK_GCM_PARAMS),
        };

        let ret = fn_encrypt_init(session, &mut mechanism, handle);
        assert_eq!(ret, CKR_MECHANISM_PARAM_INVALID);

        let ret = fn_decrypt_init(session, &mut mechanism, handle);
        assert_eq!(ret, CKR_MECHANISM_PARAM_INVALID);
    }

    {
        /* AES-CCM */

        /* Data Len needs to be known in advance for CCM */
        let data = b"01234567";
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
            ulParameterLen: sizeof!(CK_CCM_PARAMS),
        };

        let ret = fn_encrypt_init(session, &mut mechanism, handle);
        assert_eq!(ret, CKR_OK);

        let enc =
            ret_or_panic!(encrypt_update(session, &data[..data.len() - 1]));
        assert_eq!(enc.len(), 0);

        let mut enc =
            ret_or_panic!(encrypt_update(session, &data[data.len() - 1..]));
        assert_eq!(enc.len(), data.len());

        let mut enc_final = ret_or_panic!(encrypt_final(session));
        assert_eq!(enc_final.len(), tag_len);
        enc.append(&mut enc_final);

        let dec = ret_or_panic!(decrypt(session, handle, &enc, &mechanism,));
        assert_eq!(dec.len(), data.len());
        assert_eq!(data, dec.as_slice());
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
        assert_eq!(check_object_validation(session, key_handle, 1), true);

        let ciphertext = hex::decode("4154c0be71072945d8156f5f046d198d")
            .expect("Failed to decode ciphertext");
        let plaintext = hex::decode("8b2b1b22f733ac09d1196d6be6a87a72")
            .expect("Failed to decode plaintext");

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
        assert_eq!(check_object_validation(session, key_handle, 1), true);

        let iv = hex::decode("1dbbeb2f19abb448af849796244a19d7")
            .expect("Failed to decode IV");
        let plaintext = hex::decode(
            "40d930f9a05334d9816fe204999c3f82a03f6a0457a8c475c94553d1d116693a\
             dc618049f0a769a2eed6a6cb14c0143ec5cccdbc8dec4ce560cfd20622570932\
             6d4de7948e54d603d01b12d7fed752fb23f1aa4494fbb00130e9ded4e77e37c0\
             79042d828040c325b1a5efd15fc842e44014ca4374bf38f3c3fc3ee327733b0c\
             8aee1abcd055772f18dc04603f7b2c1ea69ff662361f2be0a171bbdcea1e5d3f",
        )
        .expect("Failed to decode plaintext");
        let ciphertext = hex::decode(
            "6be8a12800455a320538853e0cba31bd2d80ea0c85164a4c5c261ae485417d93\
             effe2ebc0d0a0b51d6ea18633d210cf63c0c4ddbc27607f2e81ed9113191ef86\
             d56f3b99be6c415a4150299fb846ce7160b40b63baf1179d19275a2e83698376\
             d28b92548c68e06e6d994e2c1501ed297014e702cdefee2f656447706009614d\
             801de1caaf73f8b7fa56cf1ba94b631933bbe577624380850f117435a0355b2b",
        )
        .expect("Failed to decode ciphertext");

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
        assert_eq!(check_object_validation(session, key_handle, 1), true);

        let (iv, aad, tag, ct, plaintext) = get_gcm_test_data();

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
            ulParameterLen: sizeof!(CK_GCM_PARAMS),
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
        assert_eq!(check_object_validation(session, key_handle, 1), true);

        let iv = hex::decode("0007bdfd5cbd60278dcc091200000001")
            .expect("failed to decode iv");
        let plaintext = hex::decode(
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20212223"
        )
        .expect("failed to decode plaintext");
        let ciphertext = hex::decode(
            "96893fc55e5c722f540b7dd1ddf7e758d288bc95c69165884536c811662f2188abee0935"
        )
        .expect("failed to decode ciphertext");

        let mut param = CK_AES_CTR_PARAMS {
            ulCounterBits: 32,
            cb: [0u8; 16],
        };
        param.cb.copy_from_slice(iv.as_slice());

        let mechanism: CK_MECHANISM = CK_MECHANISM {
            mechanism: CKM_AES_CTR,
            pParameter: void_ptr!(&param),
            ulParameterLen: sizeof!(CK_AES_CTR_PARAMS),
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

        /* get length */
        let mut wraplen = 0;
        let ret = fn_wrap_key(
            session,
            &mut mechanism,
            handle,
            wp_handle,
            std::ptr::null_mut(),
            &mut wraplen,
        );
        assert_eq!(ret, CKR_OK);
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
            &[(CKA_SENSITIVE, false), (CKA_EXTRACTABLE, true)],
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
        assert_eq!(check_object_validation(session, wp_handle2, 1), true);

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

    {
        /* GCM via AEAD MessageEncrypt/MessageDecrypt API */
        let mut mechanism: CK_MECHANISM = CK_MECHANISM {
            mechanism: CKM_AES_GCM,
            pParameter: std::ptr::null_mut(),
            ulParameterLen: 0,
        };

        let ret = fn_message_encrypt_init(session, &mut mechanism, handle);
        assert_eq!(ret, CKR_OK);

        /* IV needs to be of size 12 for the test to work in FIPS mode as well,
         * the tag needs to be 64b to pass FIPS requirement */
        let iv = "BA0987654321";
        let aad = "AUTH ME";
        let mut tag = [0u8; 8];
        let mut param = CK_GCM_MESSAGE_PARAMS {
            pIv: iv.as_ptr() as *mut CK_BYTE,
            ulIvLen: iv.len() as CK_ULONG,
            ulIvFixedBits: 0,
            ivGenerator: CKG_NO_GENERATE,
            pTag: tag.as_mut_ptr(),
            ulTagBits: (tag.len() * 8) as CK_ULONG,
        };

        let ret = fn_encrypt_message_begin(
            session,
            void_ptr!(&mut param),
            sizeof!(CK_GCM_MESSAGE_PARAMS),
            byte_ptr!(aad.as_ptr()),
            aad.len() as CK_ULONG,
        );
        assert_eq!(ret, CKR_OK);

        /* Stream mode, so arbitrary data size and matching output */
        let data = "01234567";
        let enc: [u8; 8] = [0; 8];
        let mut enc_len = enc.len() as CK_ULONG;
        let ret = fn_encrypt_message_next(
            session,
            void_ptr!(&mut param),
            sizeof!(CK_GCM_MESSAGE_PARAMS),
            data.as_ptr() as *mut CK_BYTE,
            (data.len() - 1) as CK_ULONG,
            enc.as_ptr() as *mut _,
            &mut enc_len,
            0,
        );
        assert_eq!(ret, CKR_OK);
        assert_eq!(enc_len as usize, data.len() - 1);

        enc_len = 1 as CK_ULONG;
        let ret = fn_encrypt_message_next(
            session,
            void_ptr!(&mut param),
            sizeof!(CK_GCM_MESSAGE_PARAMS),
            unsafe { data.as_ptr().offset(7) } as *mut CK_BYTE,
            1 as CK_ULONG,
            unsafe { enc.as_ptr().offset(7) } as *mut _,
            &mut enc_len,
            CKF_END_OF_MESSAGE,
        );
        assert_eq!(ret, CKR_OK);
        assert_eq!(enc_len, 1);

        /* test that we can get correct indicators based on inputs */
        assert_eq!(check_validation(session, 0), true);

        let ret = fn_message_encrypt_final(session);
        assert_eq!(ret, CKR_OK);

        let ret = fn_message_decrypt_init(session, &mut mechanism, handle);
        assert_eq!(ret, CKR_OK);

        let mut dec: [u8; 8] = [0; 8];
        let mut dec_len = dec.len() as CK_ULONG;

        let ret = fn_decrypt_message(
            session,
            void_ptr!(&mut param),
            sizeof!(CK_GCM_MESSAGE_PARAMS),
            byte_ptr!(aad.as_ptr()),
            aad.len() as CK_ULONG,
            byte_ptr!(enc.as_ptr()),
            enc.len() as CK_ULONG,
            dec.as_mut_ptr(),
            &mut dec_len,
        );
        assert_eq!(ret, CKR_OK);
        assert_eq!(dec.len(), data.len());
        assert_eq!(data.as_bytes(), dec.as_slice());

        /* test that we can get correct indicators based on inputs */
        assert_eq!(check_validation(session, 1), true);

        let ret = fn_message_decrypt_final(session);
        assert_eq!(ret, CKR_OK);

        let testname = "gcmDecrypt128 96,104,128,128 0";
        let key_handle =
            match get_test_key_handle(session, testname, CKO_SECRET_KEY) {
                Ok(k) => k,
                Err(e) => panic!("{}", e),
            };
        assert_eq!(check_object_validation(session, key_handle, 1), true);
        let (iv, aad, tag, ct, plaintext) = get_gcm_test_data();

        let ret = fn_message_decrypt_init(session, &mut mechanism, key_handle);
        assert_eq!(ret, CKR_OK);

        let mut param = CK_GCM_MESSAGE_PARAMS {
            pIv: byte_ptr!(iv.as_ptr()),
            ulIvLen: iv.len() as CK_ULONG,
            ulIvFixedBits: 0,
            ivGenerator: CKG_NO_GENERATE,
            pTag: byte_ptr!(tag.as_ptr()),
            ulTagBits: (tag.len() * 8) as CK_ULONG,
        };

        let ret = fn_decrypt_message_begin(
            session,
            void_ptr!(&mut param),
            sizeof!(CK_GCM_MESSAGE_PARAMS),
            byte_ptr!(aad.as_ptr()),
            aad.len() as CK_ULONG,
        );
        assert_eq!(ret, CKR_OK);

        let mut dec = vec![0u8; plaintext.len()];
        let mut dec_len = dec.len() as CK_ULONG;

        let ret = fn_decrypt_message_next(
            session,
            void_ptr!(&mut param),
            sizeof!(CK_GCM_MESSAGE_PARAMS),
            byte_ptr!(ct.as_ptr()),
            ct.len() as CK_ULONG,
            dec.as_mut_ptr(),
            &mut dec_len,
            CKF_END_OF_MESSAGE,
        );
        assert_eq!(ret, CKR_OK);
        assert_eq!(dec, plaintext);

        let ret = fn_message_decrypt_final(session);
        assert_eq!(ret, CKR_OK);

        /* once more but FIPS compliant */
        let mut mechanism: CK_MECHANISM = CK_MECHANISM {
            mechanism: CKM_AES_GCM,
            pParameter: std::ptr::null_mut(),
            ulParameterLen: 0,
        };

        let ret = fn_message_encrypt_init(session, &mut mechanism, handle);
        assert_eq!(ret, CKR_OK);

        /* IV needs to be of size 12 for the test to work in FIPS mode as well */
        let mut iv = [0u8; 12];
        let aad = "AUTH ME FIPS";
        let mut tag = [0u8; 16];
        let mut param = CK_GCM_MESSAGE_PARAMS {
            pIv: iv.as_mut_ptr(),
            ulIvLen: iv.len() as CK_ULONG,
            ulIvFixedBits: 0,
            ivGenerator: CKG_GENERATE_RANDOM,
            pTag: tag.as_mut_ptr(),
            ulTagBits: (tag.len() * 8) as CK_ULONG,
        };

        let data = "01234567";
        let enc: [u8; 8] = [0; 8];
        let mut enc_len = enc.len() as CK_ULONG;
        let ret = fn_encrypt_message(
            session,
            void_ptr!(&mut param),
            sizeof!(CK_GCM_MESSAGE_PARAMS),
            byte_ptr!(aad.as_ptr()),
            aad.len() as CK_ULONG,
            data.as_ptr() as *mut CK_BYTE,
            data.len() as CK_ULONG,
            enc.as_ptr() as *mut _,
            &mut enc_len,
        );
        assert_eq!(ret, CKR_OK);
        assert_ne!(iv, [0u8; 12]);
        assert_eq!(enc_len as usize, data.len());

        /* test that we can get correct indicators based on inputs */
        assert_eq!(check_validation(session, 1), true);

        let ret = fn_message_encrypt_final(session);
        assert_eq!(ret, CKR_OK);

        let ret = fn_message_encrypt_init(session, &mut mechanism, handle);
        assert_eq!(ret, CKR_OK);

        /* GCM without TAG should fail */
        let mut param = CK_GCM_MESSAGE_PARAMS {
            pIv: iv.as_ptr() as *mut CK_BYTE,
            ulIvLen: iv.len() as CK_ULONG,
            ulIvFixedBits: 0,
            ivGenerator: CKG_NO_GENERATE,
            pTag: std::ptr::null_mut(),
            ulTagBits: 0,
        };

        let ret = fn_encrypt_message_begin(
            session,
            void_ptr!(&mut param),
            sizeof!(CK_GCM_MESSAGE_PARAMS),
            std::ptr::null_mut(),
            0,
        );
        assert_eq!(ret, CKR_MECHANISM_PARAM_INVALID);

        let ret = fn_message_encrypt_final(session);
        assert_eq!(ret, CKR_OK);
    }

    {
        /* CCM via AEAD MessageEncrypt/MessageDecrypt API */
        let mut mechanism: CK_MECHANISM = CK_MECHANISM {
            mechanism: CKM_AES_CCM,
            pParameter: std::ptr::null_mut(),
            ulParameterLen: 0,
        };

        /* Data Len needs to be known in advance for CCM */
        let data = "01234567";

        let ret = fn_message_encrypt_init(session, &mut mechanism, handle);
        assert_eq!(ret, CKR_OK);

        /* IV needs to be of size 12 for the test to work in FIPS mode as well */
        let iv = "BA0987654321";
        let aad = "AUTH ME";
        let mut tag = [0u8; 4];
        let mut param = CK_CCM_MESSAGE_PARAMS {
            ulDataLen: data.len() as CK_ULONG,
            pNonce: iv.as_ptr() as *mut CK_BYTE,
            ulNonceLen: iv.len() as CK_ULONG,
            ulNonceFixedBits: 0,
            nonceGenerator: CKG_NO_GENERATE,
            pMAC: tag.as_mut_ptr(),
            ulMACLen: tag.len() as CK_ULONG,
        };

        let ret = fn_encrypt_message_begin(
            session,
            void_ptr!(&mut param),
            sizeof!(CK_CCM_MESSAGE_PARAMS),
            byte_ptr!(aad.as_ptr()),
            aad.len() as CK_ULONG,
        );
        assert_eq!(ret, CKR_OK);

        /* Stream mode, so arbitrary data size and matching output */
        let mut enc: [u8; 8] = [0; 8];
        let mut enc_len = enc.len() as CK_ULONG;
        let ret = fn_encrypt_message_next(
            session,
            void_ptr!(&mut param),
            sizeof!(CK_CCM_MESSAGE_PARAMS),
            data.as_ptr() as *mut CK_BYTE,
            (data.len() - 1) as CK_ULONG,
            enc.as_mut_ptr(),
            &mut enc_len,
            0,
        );
        assert_eq!(ret, CKR_OK);
        /* CCM is one shot, and returns nothing until the final */
        assert_eq!(enc_len as usize, 0);

        let mut enc_len = enc.len() as CK_ULONG;
        let ret = fn_encrypt_message_next(
            session,
            void_ptr!(&mut param),
            sizeof!(CK_CCM_MESSAGE_PARAMS),
            unsafe { data.as_ptr().offset(7) } as *mut CK_BYTE,
            1 as CK_ULONG,
            enc.as_mut_ptr(),
            &mut enc_len,
            CKF_END_OF_MESSAGE,
        );
        assert_eq!(ret, CKR_OK);
        assert_eq!(enc_len, enc.len() as CK_ULONG);

        /* test that we can get correct indicators based on inputs */
        assert_eq!(check_validation(session, 0), true);

        let ret = fn_message_encrypt_final(session);
        assert_eq!(ret, CKR_OK);

        let ret = fn_message_decrypt_init(session, &mut mechanism, handle);
        assert_eq!(ret, CKR_OK);

        let mut dec: [u8; 8] = [0; 8];
        let mut dec_len = dec.len() as CK_ULONG;

        let ret = fn_decrypt_message(
            session,
            void_ptr!(&mut param),
            sizeof!(CK_CCM_MESSAGE_PARAMS),
            byte_ptr!(aad.as_ptr()),
            aad.len() as CK_ULONG,
            byte_ptr!(enc.as_ptr()),
            enc.len() as CK_ULONG,
            dec.as_mut_ptr(),
            &mut dec_len,
        );
        assert_eq!(ret, CKR_OK);
        assert_eq!(dec.len(), data.len());
        assert_eq!(data.as_bytes(), dec.as_slice());

        /* test that we can get correct indicators based on inputs */
        assert_eq!(check_validation(session, 0), true);

        let ret = fn_message_decrypt_final(session);
        assert_eq!(ret, CKR_OK);
    }

    testtokn.finalize();
}

#[test]
#[parallel]
fn test_aes_macs() {
    let mut testtokn = TestToken::initialized("test_aes_macs", None);
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
        &[(CKA_SIGN, true), (CKA_VERIFY, true),],
    ));
    assert_eq!(check_object_validation(session, handle, 1), true);

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

        /* Again with SignatureVerify API */
        assert_eq!(
            CKR_OK,
            sig_verifysig(
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

        /* test that we can get correct indicators based on inputs */
        assert_eq!(check_validation(session, 1), true);

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

        /* test that we can get correct indicators based on inputs */
        assert_eq!(check_validation(session, 1), true);

        /* 16b or 2B is too small for FIPS */
        let size: CK_ULONG = 2 as CK_ULONG;

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

        /* test that we can get correct indicators based on inputs */
        assert_eq!(check_validation(session, 0), true);

        /* Again with SignatureVerify API */
        assert_eq!(
            CKR_OK,
            sig_verifysig(
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

#[test]
#[parallel]
fn test_aes_iv_generators() {
    let mut testtokn = TestToken::initialized("test_aes_iv_generators", None);
    let session = testtokn.get_session(true);

    /* login */
    testtokn.login();

    let handle = ret_or_panic!(generate_key(
        session,
        CKM_AES_KEY_GEN,
        std::ptr::null_mut(),
        0,
        &[(CKA_VALUE_LEN, 16),],
        &[],
        &[(CKA_ENCRYPT, true), (CKA_DECRYPT, true),],
    ));

    let src_iv = hex::decode("a1b2c3d4e5f67890abcdef12").unwrap();
    let src_aad = b"associated-data".to_vec();
    let src_plaintext = b"Hello world!".to_vec();

    {
        /* AES GCM IV counter generator */
        let mut mechanism: CK_MECHANISM = CK_MECHANISM {
            mechanism: CKM_AES_GCM,
            pParameter: std::ptr::null_mut(),
            ulParameterLen: 0,
        };

        let ret = fn_message_encrypt_init(session, &mut mechanism, handle);
        assert_eq!(ret, CKR_OK);

        let mut iv1 = [0u8; 12];
        iv1.copy_from_slice(&src_iv);
        let mut tag1 = [0u8; 12];
        let mut param1 = CK_GCM_MESSAGE_PARAMS {
            pIv: iv1.as_mut_ptr(),
            ulIvLen: iv1.len() as CK_ULONG,
            ulIvFixedBits: 64, // 8 bytes fixed, 4 bytes counter
            ivGenerator: CKG_GENERATE_COUNTER,
            pTag: tag1.as_mut_ptr(),
            ulTagBits: (tag1.len() * 8) as CK_ULONG,
        };

        let data = &src_plaintext;
        let mut enc1 = [0u8; 12];
        let mut enc1_len = enc1.len() as CK_ULONG;

        let ret = fn_encrypt_message(
            session,
            void_ptr!(&mut param1),
            sizeof!(CK_GCM_MESSAGE_PARAMS),
            src_aad.as_ptr() as *mut CK_BYTE,
            src_aad.len() as CK_ULONG,
            data.as_ptr() as *mut CK_BYTE,
            data.len() as CK_ULONG,
            enc1.as_mut_ptr(),
            &mut enc1_len,
        );
        assert_eq!(ret, CKR_OK);

        let ret = fn_message_decrypt_init(session, &mut mechanism, handle);
        assert_eq!(ret, CKR_OK);
        let mut dec = vec![0u8; data.len()];
        let mut dec_len = dec.len() as CK_ULONG;
        let ret = fn_decrypt_message(
            session,
            void_ptr!(&mut param1),
            sizeof!(CK_GCM_MESSAGE_PARAMS),
            src_aad.as_ptr() as *mut CK_BYTE,
            src_aad.len() as CK_ULONG,
            enc1.as_ptr() as *mut CK_BYTE,
            enc1_len,
            dec.as_mut_ptr(),
            &mut dec_len,
        );
        assert_eq!(ret, CKR_OK);
        assert_eq!(dec, *data);
        assert_eq!(fn_message_decrypt_final(session), CKR_OK);

        // Verify IV has been updated (first 8 bytes preserved, last 4 cleared to 0)
        assert_eq!(iv1[0..8], src_iv[0..8]);
        assert_eq!(iv1[8..12], [0, 0, 0, 0]);

        // Second call: counter is 1
        let mut iv2 = [0u8; 12];
        iv2.copy_from_slice(&src_iv);
        let mut tag2 = [0u8; 12];
        let mut param2 = CK_GCM_MESSAGE_PARAMS {
            pIv: iv2.as_mut_ptr(),
            ulIvLen: iv2.len() as CK_ULONG,
            ulIvFixedBits: 64,
            ivGenerator: CKG_GENERATE_COUNTER,
            pTag: tag2.as_mut_ptr(),
            ulTagBits: (tag2.len() * 8) as CK_ULONG,
        };

        let mut enc2 = [0u8; 12];
        let mut enc2_len = enc2.len() as CK_ULONG;
        let ret = fn_encrypt_message(
            session,
            void_ptr!(&mut param2),
            sizeof!(CK_GCM_MESSAGE_PARAMS),
            src_aad.as_ptr() as *mut CK_BYTE,
            src_aad.len() as CK_ULONG,
            data.as_ptr() as *mut CK_BYTE,
            data.len() as CK_ULONG,
            enc2.as_mut_ptr(),
            &mut enc2_len,
        );
        assert_eq!(ret, CKR_OK);

        let ret = fn_message_decrypt_init(session, &mut mechanism, handle);
        assert_eq!(ret, CKR_OK);
        let mut dec = vec![0u8; data.len()];
        let mut dec_len = dec.len() as CK_ULONG;
        let ret = fn_decrypt_message(
            session,
            void_ptr!(&mut param2),
            sizeof!(CK_GCM_MESSAGE_PARAMS),
            src_aad.as_ptr() as *mut CK_BYTE,
            src_aad.len() as CK_ULONG,
            enc2.as_ptr() as *mut CK_BYTE,
            enc2_len,
            dec.as_mut_ptr(),
            &mut dec_len,
        );
        assert_eq!(ret, CKR_OK);
        assert_eq!(dec, *data);
        assert_eq!(fn_message_decrypt_final(session), CKR_OK);

        // Verify IV has changed and is different from first one
        assert_eq!(iv2[0..8], src_iv[0..8]);
        assert_eq!(iv2[8..12], [0, 0, 0, 1]);

        let ret = fn_message_encrypt_init(session, std::ptr::null_mut(), 0);
        assert_eq!(ret, CKR_OK);
    }

    {
        /* AES GCM IV XOR counter generator */
        let mut mechanism: CK_MECHANISM = CK_MECHANISM {
            mechanism: CKM_AES_GCM,
            pParameter: std::ptr::null_mut(),
            ulParameterLen: 0,
        };

        let ret = fn_message_encrypt_init(session, &mut mechanism, handle);
        assert_eq!(ret, CKR_OK);

        let mut iv1 = [0u8; 12];
        iv1.copy_from_slice(&src_iv);

        let mut tag1 = [0u8; 16];
        let mut param1 = CK_GCM_MESSAGE_PARAMS {
            pIv: iv1.as_mut_ptr(),
            ulIvLen: iv1.len() as CK_ULONG,
            ulIvFixedBits: 64, // 8 bytes fixed, 4 bytes counter
            ivGenerator: CKG_GENERATE_COUNTER_XOR,
            pTag: tag1.as_mut_ptr(),
            ulTagBits: (tag1.len() * 8) as CK_ULONG,
        };

        let data = &src_plaintext;
        let mut enc1 = [0u8; 12];
        let mut enc1_len = enc1.len() as CK_ULONG;

        let ret = fn_encrypt_message(
            session,
            void_ptr!(&mut param1),
            sizeof!(CK_GCM_MESSAGE_PARAMS),
            src_aad.as_ptr() as *mut CK_BYTE,
            src_aad.len() as CK_ULONG,
            data.as_ptr() as *mut CK_BYTE,
            data.len() as CK_ULONG,
            enc1.as_mut_ptr(),
            &mut enc1_len,
        );
        assert_eq!(ret, CKR_OK);

        let ret = fn_message_decrypt_init(session, &mut mechanism, handle);
        assert_eq!(ret, CKR_OK);
        let mut dec1 = vec![0u8; data.len()];
        let mut dec1_len = dec1.len() as CK_ULONG;
        let ret = fn_decrypt_message(
            session,
            void_ptr!(&mut param1),
            sizeof!(CK_GCM_MESSAGE_PARAMS),
            src_aad.as_ptr() as *mut CK_BYTE,
            src_aad.len() as CK_ULONG,
            enc1.as_ptr() as *mut CK_BYTE,
            enc1_len,
            dec1.as_mut_ptr(),
            &mut dec1_len,
        );
        assert_eq!(ret, CKR_OK);
        assert_eq!(dec1, *data);
        assert_eq!(fn_message_decrypt_final(session), CKR_OK);

        // First call: counter is 0, so XOR should leave IV untouched
        assert_eq!(iv1, src_iv.as_slice());

        // Second call: counter is 1
        let mut iv2 = [0u8; 12];
        iv2.copy_from_slice(&src_iv);
        let mut tag2 = [0u8; 16];
        let mut param2 = CK_GCM_MESSAGE_PARAMS {
            pIv: iv2.as_mut_ptr(),
            ulIvLen: iv2.len() as CK_ULONG,
            ulIvFixedBits: 64,
            ivGenerator: CKG_GENERATE_COUNTER_XOR,
            pTag: tag2.as_mut_ptr(),
            ulTagBits: (tag2.len() * 8) as CK_ULONG,
        };

        let mut enc2 = [0u8; 12];
        let mut enc2_len = enc2.len() as CK_ULONG;
        let ret = fn_encrypt_message(
            session,
            void_ptr!(&mut param2),
            sizeof!(CK_GCM_MESSAGE_PARAMS),
            src_aad.as_ptr() as *mut CK_BYTE,
            src_aad.len() as CK_ULONG,
            data.as_ptr() as *mut CK_BYTE,
            data.len() as CK_ULONG,
            enc2.as_mut_ptr(),
            &mut enc2_len,
        );
        assert_eq!(ret, CKR_OK);

        let ret = fn_message_decrypt_init(session, &mut mechanism, handle);
        assert_eq!(ret, CKR_OK);
        let mut dec2 = vec![0u8; data.len()];
        let mut dec2_len = dec2.len() as CK_ULONG;
        let ret = fn_decrypt_message(
            session,
            void_ptr!(&mut param2),
            sizeof!(CK_GCM_MESSAGE_PARAMS),
            src_aad.as_ptr() as *mut CK_BYTE,
            src_aad.len() as CK_ULONG,
            enc2.as_ptr() as *mut CK_BYTE,
            enc2_len,
            dec2.as_mut_ptr(),
            &mut dec2_len,
        );
        assert_eq!(ret, CKR_OK);
        assert_eq!(dec2, *data);
        assert_eq!(fn_message_decrypt_final(session), CKR_OK);

        // Verify IV has been XORed with 1
        let mut expected_iv = src_iv.clone();
        expected_iv[11] ^= 1;
        assert_eq!(iv2, expected_iv.as_slice());

        let ret = fn_message_encrypt_init(session, std::ptr::null_mut(), 0);
        assert_eq!(ret, CKR_OK);
    }

    {
        /* AES CCM Nonce counter generator */
        let mut mechanism: CK_MECHANISM = CK_MECHANISM {
            mechanism: CKM_AES_CCM,
            pParameter: std::ptr::null_mut(),
            ulParameterLen: 0,
        };

        let ret = fn_message_encrypt_init(session, &mut mechanism, handle);
        assert_eq!(ret, CKR_OK);

        let data = &src_plaintext;
        let mut nonce1 = [0u8; 12];
        nonce1.copy_from_slice(&src_iv);
        let mut tag1 = [0u8; 16];
        let mut param1 = CK_CCM_MESSAGE_PARAMS {
            ulDataLen: data.len() as CK_ULONG,
            pNonce: nonce1.as_mut_ptr(),
            ulNonceLen: nonce1.len() as CK_ULONG,
            ulNonceFixedBits: 64, // 8 bytes fixed, 4 bytes counter
            nonceGenerator: CKG_GENERATE_COUNTER,
            pMAC: tag1.as_mut_ptr(),
            ulMACLen: tag1.len() as CK_ULONG,
        };

        let mut enc1 = [0u8; 12];
        let mut enc1_len = enc1.len() as CK_ULONG;

        let ret = fn_encrypt_message(
            session,
            void_ptr!(&mut param1),
            sizeof!(CK_CCM_MESSAGE_PARAMS),
            src_aad.as_ptr() as *mut CK_BYTE,
            src_aad.len() as CK_ULONG,
            data.as_ptr() as *mut CK_BYTE,
            data.len() as CK_ULONG,
            enc1.as_mut_ptr(),
            &mut enc1_len,
        );
        assert_eq!(ret, CKR_OK);

        let ret = fn_message_decrypt_init(session, &mut mechanism, handle);
        assert_eq!(ret, CKR_OK);
        let mut dec1 = vec![0u8; data.len()];
        let mut dec1_len = dec1.len() as CK_ULONG;
        let ret = fn_decrypt_message(
            session,
            void_ptr!(&mut param1),
            sizeof!(CK_CCM_MESSAGE_PARAMS),
            src_aad.as_ptr() as *mut CK_BYTE,
            src_aad.len() as CK_ULONG,
            enc1.as_ptr() as *mut CK_BYTE,
            enc1_len,
            dec1.as_mut_ptr(),
            &mut dec1_len,
        );
        assert_eq!(ret, CKR_OK);
        assert_eq!(dec1, *data);
        assert_eq!(fn_message_decrypt_final(session), CKR_OK);

        // IV should have the non-fixed bits set to zero
        assert_eq!(nonce1[0..8], src_iv[0..8]);
        assert_eq!(nonce1[8..12], [0, 0, 0, 0]);

        // Second call: counter is 1.
        let mut nonce2 = [0u8; 12];
        nonce2.copy_from_slice(&src_iv);
        let mut tag2 = [0u8; 16];
        let mut param2 = CK_CCM_MESSAGE_PARAMS {
            ulDataLen: data.len() as CK_ULONG,
            pNonce: nonce2.as_mut_ptr(),
            ulNonceLen: nonce2.len() as CK_ULONG,
            ulNonceFixedBits: 64,
            nonceGenerator: CKG_GENERATE_COUNTER,
            pMAC: tag2.as_ptr() as *mut CK_BYTE,
            ulMACLen: tag2.len() as CK_ULONG,
        };

        let mut enc2 = [0u8; 12];
        let mut enc2_len = enc2.len() as CK_ULONG;
        let ret = fn_encrypt_message(
            session,
            void_ptr!(&mut param2),
            sizeof!(CK_CCM_MESSAGE_PARAMS),
            src_aad.as_ptr() as *mut CK_BYTE,
            src_aad.len() as CK_ULONG,
            data.as_ptr() as *mut CK_BYTE,
            data.len() as CK_ULONG,
            enc2.as_mut_ptr(),
            &mut enc2_len,
        );
        assert_eq!(ret, CKR_OK);

        let ret = fn_message_decrypt_init(session, &mut mechanism, handle);
        assert_eq!(ret, CKR_OK);
        let mut dec2 = vec![0u8; data.len()];
        let mut dec2_len = dec2.len() as CK_ULONG;
        let ret = fn_decrypt_message(
            session,
            void_ptr!(&mut param2),
            sizeof!(CK_CCM_MESSAGE_PARAMS),
            src_aad.as_ptr() as *mut CK_BYTE,
            src_aad.len() as CK_ULONG,
            enc2.as_ptr() as *mut CK_BYTE,
            enc2_len,
            dec2.as_mut_ptr(),
            &mut dec2_len,
        );
        assert_eq!(ret, CKR_OK);
        assert_eq!(dec2, *data);
        assert_eq!(fn_message_decrypt_final(session), CKR_OK);

        // Check the increment
        assert_eq!(nonce2[0..8], src_iv[0..8]);
        assert_eq!(nonce2[8..12], [0, 0, 0, 1]);

        let ret = fn_message_encrypt_init(session, std::ptr::null_mut(), 0);
        assert_eq!(ret, CKR_OK);
    }

    {
        /* Unaligned boundary: 67 fixed bits, 29 counter bits (12 bytes IV) */
        let mut mechanism: CK_MECHANISM = CK_MECHANISM {
            mechanism: CKM_AES_GCM,
            pParameter: std::ptr::null_mut(),
            ulParameterLen: 0,
        };

        let ret = fn_message_encrypt_init(session, &mut mechanism, handle);
        assert_eq!(ret, CKR_OK);

        let mut iv1 = [0u8; 12];
        iv1.copy_from_slice(&src_iv);

        // XXX0 0000 (3bits fixed, 5 bits counter)
        let expected_split = iv1[8] & (((1u8 << 3) - 1) << 5);

        let mut tag1 = [0u8; 12];
        let mut param = CK_GCM_MESSAGE_PARAMS {
            pIv: iv1.as_mut_ptr(),
            ulIvLen: iv1.len() as CK_ULONG,
            ulIvFixedBits: 67,
            ivGenerator: CKG_GENERATE_COUNTER,
            pTag: tag1.as_mut_ptr(),
            ulTagBits: (tag1.len() * 8) as CK_ULONG,
        };

        let data = &src_plaintext;
        let mut enc = [0u8; 12];
        let mut enc_len = enc.len() as CK_ULONG;

        let ret = fn_encrypt_message(
            session,
            void_ptr!(&mut param),
            sizeof!(CK_GCM_MESSAGE_PARAMS),
            src_aad.as_ptr() as *mut CK_BYTE,
            src_aad.len() as CK_ULONG,
            data.as_ptr() as *mut CK_BYTE,
            data.len() as CK_ULONG,
            enc.as_mut_ptr(),
            &mut enc_len,
        );
        assert_eq!(ret, CKR_OK);
        assert_eq!(iv1[8], expected_split);
        assert_eq!(iv1[9..12], [0, 0, 0]);

        let ret = fn_message_decrypt_init(session, &mut mechanism, handle);
        assert_eq!(ret, CKR_OK);
        let mut dec = vec![0u8; data.len()];
        let mut dec_len = dec.len() as CK_ULONG;
        let ret = fn_decrypt_message(
            session,
            void_ptr!(&mut param),
            sizeof!(CK_GCM_MESSAGE_PARAMS),
            src_aad.as_ptr() as *mut CK_BYTE,
            src_aad.len() as CK_ULONG,
            enc.as_ptr() as *mut CK_BYTE,
            enc_len,
            dec.as_mut_ptr(),
            &mut dec_len,
        );
        assert_eq!(ret, CKR_OK);
        assert_eq!(dec, *data);
        assert_eq!(fn_message_decrypt_final(session), CKR_OK);

        assert_eq!(iv1[8], expected_split);
        assert_eq!(iv1[9..12], [0, 0, 0]);

        let mut iv2 = [0u8; 12];
        iv2.copy_from_slice(&src_iv);

        // Second call: counter is 1.
        let mut tag2 = [0u8; 16];
        let mut param = CK_GCM_MESSAGE_PARAMS {
            pIv: iv2.as_mut_ptr(),
            ulIvLen: iv2.len() as CK_ULONG,
            ulIvFixedBits: 67,
            ivGenerator: CKG_GENERATE_COUNTER,
            pTag: tag2.as_mut_ptr(),
            ulTagBits: (tag2.len() * 8) as CK_ULONG,
        };

        let ret = fn_encrypt_message(
            session,
            void_ptr!(&mut param),
            sizeof!(CK_GCM_MESSAGE_PARAMS),
            src_aad.as_ptr() as *mut CK_BYTE,
            src_aad.len() as CK_ULONG,
            data.as_ptr() as *mut CK_BYTE,
            data.len() as CK_ULONG,
            enc.as_mut_ptr(),
            &mut enc_len,
        );
        assert_eq!(ret, CKR_OK);
        assert_eq!(iv2[8], expected_split);
        assert_eq!(iv2[9..12], [0, 0, 1]);

        let ret = fn_message_decrypt_init(session, &mut mechanism, handle);
        assert_eq!(ret, CKR_OK);
        let mut dec = vec![0u8; data.len()];
        let mut dec_len = dec.len() as CK_ULONG;
        let ret = fn_decrypt_message(
            session,
            void_ptr!(&mut param),
            sizeof!(CK_GCM_MESSAGE_PARAMS),
            src_aad.as_ptr() as *mut CK_BYTE,
            src_aad.len() as CK_ULONG,
            enc.as_ptr() as *mut CK_BYTE,
            enc_len,
            dec.as_mut_ptr(),
            &mut dec_len,
        );
        assert_eq!(ret, CKR_OK);
        assert_eq!(dec, *data);
        assert_eq!(fn_message_decrypt_final(session), CKR_OK);

        assert_eq!(iv2[8], expected_split);
        assert_eq!(iv2[9..12], [0, 0, 1]);

        let ret = fn_message_encrypt_init(session, std::ptr::null_mut(), 0);
        assert_eq!(ret, CKR_OK);
    }

    {
        /* Aligned boundary: 88 fixed bits, 8 counter bits (12 bytes IV) */
        let mut mechanism: CK_MECHANISM = CK_MECHANISM {
            mechanism: CKM_AES_GCM,
            pParameter: std::ptr::null_mut(),
            ulParameterLen: 0,
        };

        let ret = fn_message_encrypt_init(session, &mut mechanism, handle);
        assert_eq!(ret, CKR_OK);

        let mut iv = [0x55u8; 12];
        let mut tag1 = [0u8; 16];
        let mut param = CK_GCM_MESSAGE_PARAMS {
            pIv: iv.as_mut_ptr(),
            ulIvLen: iv.len() as CK_ULONG,
            ulIvFixedBits: 88,
            ivGenerator: CKG_GENERATE_COUNTER,
            pTag: tag1.as_mut_ptr(),
            ulTagBits: (tag1.len() * 8) as CK_ULONG,
        };

        let data = &src_plaintext;
        let mut enc = [0u8; 12];
        let mut enc_len = enc.len() as CK_ULONG;

        let ret = fn_encrypt_message(
            session,
            void_ptr!(&mut param),
            sizeof!(CK_GCM_MESSAGE_PARAMS),
            src_aad.as_ptr() as *mut CK_BYTE,
            src_aad.len() as CK_ULONG,
            data.as_ptr() as *mut CK_BYTE,
            data.len() as CK_ULONG,
            enc.as_mut_ptr(),
            &mut enc_len,
        );
        assert_eq!(ret, CKR_OK);
        assert_eq!(iv[0..11], [0x55; 11]);
        assert_eq!(iv[11], 0);

        let ret = fn_message_decrypt_init(session, &mut mechanism, handle);
        assert_eq!(ret, CKR_OK);
        let mut dec = vec![0u8; data.len()];
        let mut dec_len = dec.len() as CK_ULONG;
        let ret = fn_decrypt_message(
            session,
            void_ptr!(&mut param),
            sizeof!(CK_GCM_MESSAGE_PARAMS),
            src_aad.as_ptr() as *mut CK_BYTE,
            src_aad.len() as CK_ULONG,
            enc.as_ptr() as *mut CK_BYTE,
            enc_len,
            dec.as_mut_ptr(),
            &mut dec_len,
        );
        assert_eq!(ret, CKR_OK);
        assert_eq!(dec, *data);
        assert_eq!(fn_message_decrypt_final(session), CKR_OK);

        // Byte 11 should be 0 (counter 0). Bytes 0-10 should be 0x55.
        assert_eq!(iv[0..11], [0x55; 11]);
        assert_eq!(iv[11], 0);

        // Second call: counter is 1.
        let ret = fn_encrypt_message(
            session,
            void_ptr!(&mut param),
            sizeof!(CK_GCM_MESSAGE_PARAMS),
            src_aad.as_ptr() as *mut CK_BYTE,
            src_aad.len() as CK_ULONG,
            data.as_ptr() as *mut CK_BYTE,
            data.len() as CK_ULONG,
            enc.as_mut_ptr(),
            &mut enc_len,
        );
        assert_eq!(ret, CKR_OK);

        let ret = fn_message_decrypt_init(session, &mut mechanism, handle);
        assert_eq!(ret, CKR_OK);
        let mut dec = vec![0u8; data.len()];
        let mut dec_len = dec.len() as CK_ULONG;
        let ret = fn_decrypt_message(
            session,
            void_ptr!(&mut param),
            sizeof!(CK_GCM_MESSAGE_PARAMS),
            src_aad.as_ptr() as *mut CK_BYTE,
            src_aad.len() as CK_ULONG,
            enc.as_ptr() as *mut CK_BYTE,
            enc_len,
            dec.as_mut_ptr(),
            &mut dec_len,
        );
        assert_eq!(ret, CKR_OK);
        assert_eq!(dec, *data);
        assert_eq!(fn_message_decrypt_final(session), CKR_OK);

        assert_eq!(iv[0..11], [0x55; 11]);
        assert_eq!(iv[11], 1);

        let ret = fn_message_encrypt_init(session, std::ptr::null_mut(), 0);
        assert_eq!(ret, CKR_OK);
    }

    {
        /* Counter Limit: 3 bits counter (93 fixed bits, 12 bytes IV) */
        let mut mechanism: CK_MECHANISM = CK_MECHANISM {
            mechanism: CKM_AES_GCM,
            pParameter: std::ptr::null_mut(),
            ulParameterLen: 0,
        };

        let ret = fn_message_encrypt_init(session, &mut mechanism, handle);
        assert_eq!(ret, CKR_OK);

        let mut iv = [0u8; 12];
        let mut tag1 = [0u8; 16];
        let mut param = CK_GCM_MESSAGE_PARAMS {
            pIv: iv.as_mut_ptr(),
            ulIvLen: iv.len() as CK_ULONG,
            ulIvFixedBits: 93,
            ivGenerator: CKG_GENERATE_COUNTER,
            pTag: tag1.as_mut_ptr(),
            ulTagBits: (tag1.len() * 8) as CK_ULONG,
        };

        let data = &src_plaintext;
        let mut enc = [0u8; 12];
        let mut enc_len = enc.len() as CK_ULONG;

        // Run 8 times (0 to 7)
        let mut next_iv_tail = iv[11];
        for _ in 0..8 {
            let ret = fn_encrypt_message(
                session,
                void_ptr!(&mut param),
                sizeof!(CK_GCM_MESSAGE_PARAMS),
                src_aad.as_ptr() as *mut CK_BYTE,
                src_aad.len() as CK_ULONG,
                data.as_ptr() as *mut CK_BYTE,
                data.len() as CK_ULONG,
                enc.as_mut_ptr(),
                &mut enc_len,
            );
            assert_eq!(ret, CKR_OK);
            assert_eq!(iv[11], next_iv_tail);

            let ret = fn_message_decrypt_init(session, &mut mechanism, handle);
            assert_eq!(ret, CKR_OK);
            let mut dec = vec![0u8; data.len()];
            let mut dec_len = dec.len() as CK_ULONG;
            let ret = fn_decrypt_message(
                session,
                void_ptr!(&mut param),
                sizeof!(CK_GCM_MESSAGE_PARAMS),
                src_aad.as_ptr() as *mut CK_BYTE,
                src_aad.len() as CK_ULONG,
                enc.as_ptr() as *mut CK_BYTE,
                enc_len,
                dec.as_mut_ptr(),
                &mut dec_len,
            );
            assert_eq!(ret, CKR_OK);
            assert_eq!(dec, *data);
            assert_eq!(fn_message_decrypt_final(session), CKR_OK);

            assert_eq!(iv[11], next_iv_tail);
            next_iv_tail += 1;
        }

        // 9th time should fail with CKR_DATA_LEN_RANGE
        let ret = fn_encrypt_message(
            session,
            void_ptr!(&mut param),
            sizeof!(CK_GCM_MESSAGE_PARAMS),
            src_aad.as_ptr() as *mut CK_BYTE,
            src_aad.len() as CK_ULONG,
            data.as_ptr() as *mut CK_BYTE,
            data.len() as CK_ULONG,
            enc.as_mut_ptr(),
            &mut enc_len,
        );
        assert_eq!(ret, CKR_DATA_LEN_RANGE);

        let ret = fn_message_encrypt_init(session, std::ptr::null_mut(), 0);
        assert_eq!(ret, CKR_OK);
    }

    testtokn.finalize();
}

/// Regression test for the null-buffer length-probe of the one-shot
/// C_EncryptMessage/C_DecryptMessage functions on CKM_AES_CCM: calling
/// either with a NULL output pointer (to learn the required buffer size,
/// per PKCS#11's usual "call once with NULL to get the length" idiom) must
/// report the real length rather than 0. Before the fix, self.params
/// (populated only by msg_encrypt_new/msg_decrypt_new, which the one-shot
/// entry point only reaches on the *second*, real call) hadn't been set
/// yet at probe time, so CCM's msg_encryption_len/msg_decryption_len read
/// a stale/default datalen of 0.
#[test]
#[parallel]
fn test_aes_ccm_message_one_shot_length_probe() {
    let mut testtokn = TestToken::initialized(
        "test_aes_ccm_message_one_shot_length_probe",
        None,
    );
    let session = testtokn.get_session(true);
    testtokn.login();

    let handle = ret_or_panic!(generate_key(
        session,
        CKM_AES_KEY_GEN,
        std::ptr::null_mut(),
        0,
        &[(CKA_VALUE_LEN, 16),],
        &[],
        &[(CKA_ENCRYPT, true), (CKA_DECRYPT, true),],
    ));

    let nonce = b"BA0987654321".to_vec();
    let aad = b"AUTH ME".to_vec();
    let plaintext = b"01234567".to_vec();

    let mut mechanism: CK_MECHANISM = CK_MECHANISM {
        mechanism: CKM_AES_CCM,
        pParameter: std::ptr::null_mut(),
        ulParameterLen: 0,
    };

    /* --- Encrypt: probe, then the real call --- */
    let ret = fn_message_encrypt_init(session, &mut mechanism, handle);
    assert_eq!(ret, CKR_OK);

    let mut nonce_buf = nonce.clone();
    let mut tag = [0u8; 8];
    let mut params = CK_CCM_MESSAGE_PARAMS {
        ulDataLen: plaintext.len() as CK_ULONG,
        pNonce: nonce_buf.as_mut_ptr(),
        ulNonceLen: nonce_buf.len() as CK_ULONG,
        ulNonceFixedBits: 0,
        nonceGenerator: CKG_NO_GENERATE,
        pMAC: tag.as_mut_ptr(),
        ulMACLen: tag.len() as CK_ULONG,
    };

    let mut probed_len: CK_ULONG = 0;
    let ret = fn_encrypt_message(
        session,
        void_ptr!(&mut params),
        sizeof!(CK_CCM_MESSAGE_PARAMS),
        byte_ptr!(aad.as_ptr()),
        aad.len() as CK_ULONG,
        plaintext.as_ptr() as *mut CK_BYTE,
        plaintext.len() as CK_ULONG,
        std::ptr::null_mut(),
        &mut probed_len,
    );
    assert_eq!(ret, CKR_OK);
    assert_eq!(probed_len as usize, plaintext.len());

    let mut enc = vec![0u8; probed_len as usize];
    let mut enc_len = enc.len() as CK_ULONG;
    let ret = fn_encrypt_message(
        session,
        void_ptr!(&mut params),
        sizeof!(CK_CCM_MESSAGE_PARAMS),
        byte_ptr!(aad.as_ptr()),
        aad.len() as CK_ULONG,
        plaintext.as_ptr() as *mut CK_BYTE,
        plaintext.len() as CK_ULONG,
        enc.as_mut_ptr(),
        &mut enc_len,
    );
    assert_eq!(ret, CKR_OK);
    assert_eq!(enc_len as usize, plaintext.len());

    /* --- Decrypt: probe, then the real call, and check the round-trip --- */
    let ret = fn_message_decrypt_init(session, &mut mechanism, handle);
    assert_eq!(ret, CKR_OK);

    let mut probed_len: CK_ULONG = 0;
    let ret = fn_decrypt_message(
        session,
        void_ptr!(&mut params),
        sizeof!(CK_CCM_MESSAGE_PARAMS),
        byte_ptr!(aad.as_ptr()),
        aad.len() as CK_ULONG,
        enc.as_ptr() as *mut CK_BYTE,
        enc_len,
        std::ptr::null_mut(),
        &mut probed_len,
    );
    assert_eq!(ret, CKR_OK);
    assert_eq!(probed_len as usize, plaintext.len());

    let mut dec = vec![0u8; probed_len as usize];
    let mut dec_len = dec.len() as CK_ULONG;
    let ret = fn_decrypt_message(
        session,
        void_ptr!(&mut params),
        sizeof!(CK_CCM_MESSAGE_PARAMS),
        byte_ptr!(aad.as_ptr()),
        aad.len() as CK_ULONG,
        enc.as_ptr() as *mut CK_BYTE,
        enc_len,
        dec.as_mut_ptr(),
        &mut dec_len,
    );
    assert_eq!(ret, CKR_OK);
    assert_eq!(dec_len as usize, plaintext.len());
    assert_eq!(dec, plaintext);

    testtokn.finalize();
}

/// Regression test: CKM_AES_CCM must support a zero-length payload -- authenticating only the
/// associated data, with no plaintext at all (NIST SP 800-38C explicitly permits this). This
/// exercises the classic, non-message-mode CK_CCM_PARAMS path via C_Encrypt/C_Decrypt.
/// AesOperation::encrypt_update's buffering condition (`plain.len() < self.params.datalen`)
/// never fires when datalen == 0, so no OpenSSL update() call ever happened and encrypt_final's
/// tag retrieval failed downstream with a confusing CKR_DEVICE_ERROR ("tag not set").
#[test]
#[parallel]
fn test_aes_ccm_classic_empty_data_authenticates_aad() {
    let mut testtokn = TestToken::initialized(
        "test_aes_ccm_classic_empty_data_authenticates_aad",
        None,
    );
    let session = testtokn.get_session(true);
    testtokn.login();

    let handle = ret_or_panic!(generate_key(
        session,
        CKM_AES_KEY_GEN,
        std::ptr::null_mut(),
        0,
        &[(CKA_VALUE_LEN, 16),],
        &[],
        &[(CKA_ENCRYPT, true), (CKA_DECRYPT, true),],
    ));

    let iv = "BA0987654321";
    let aad = "AAD only, no payload";
    let tag_len = 16usize;
    let mut param = CK_CCM_PARAMS {
        ulDataLen: 0,
        pNonce: iv.as_ptr() as *mut CK_BYTE,
        ulNonceLen: iv.len() as CK_ULONG,
        pAAD: aad.as_ptr() as *mut CK_BYTE,
        ulAADLen: aad.len() as CK_ULONG,
        ulMACLen: tag_len as CK_ULONG,
    };
    let mechanism: CK_MECHANISM = CK_MECHANISM {
        mechanism: CKM_AES_CCM,
        pParameter: &mut param as *mut CK_CCM_PARAMS as CK_VOID_PTR,
        ulParameterLen: sizeof!(CK_CCM_PARAMS),
    };

    let enc = ret_or_panic!(encrypt(session, handle, &[], &mechanism));
    assert_eq!(
        enc.len(),
        tag_len,
        "an AAD-only CCM ciphertext is just the authentication tag"
    );

    let dec = ret_or_panic!(decrypt(session, handle, &enc, &mechanism));
    assert_eq!(dec.len(), 0);

    testtokn.finalize();
}

/// Same as test_aes_ccm_classic_empty_data_authenticates_aad, but for the message-mode
/// CK_CCM_MESSAGE_PARAMS call sites (fns/encryption.rs's fn_encrypt_message/fn_decrypt_message,
/// where `plaintext_len == 0`/`ciphertext_len == 0` were bundled into the same reject-condition
/// as a genuinely null pointer).
#[test]
#[parallel]
fn test_aes_ccm_message_empty_data_authenticates_aad() {
    let mut testtokn = TestToken::initialized(
        "test_aes_ccm_message_empty_data_authenticates_aad",
        None,
    );
    let session = testtokn.get_session(true);
    testtokn.login();

    let handle = ret_or_panic!(generate_key(
        session,
        CKM_AES_KEY_GEN,
        std::ptr::null_mut(),
        0,
        &[(CKA_VALUE_LEN, 16),],
        &[],
        &[(CKA_ENCRYPT, true), (CKA_DECRYPT, true),],
    ));

    let mut nonce = b"BA0987654321".to_vec();
    let aad = b"AAD only, no payload".to_vec();
    let plaintext: Vec<u8> = vec![];

    let mut mechanism: CK_MECHANISM = CK_MECHANISM {
        mechanism: CKM_AES_CCM,
        pParameter: std::ptr::null_mut(),
        ulParameterLen: 0,
    };

    let ret = fn_message_encrypt_init(session, &mut mechanism, handle);
    assert_eq!(ret, CKR_OK);

    let mut tag = [0u8; 16];
    let mut params = CK_CCM_MESSAGE_PARAMS {
        ulDataLen: plaintext.len() as CK_ULONG,
        pNonce: nonce.as_mut_ptr(),
        ulNonceLen: nonce.len() as CK_ULONG,
        ulNonceFixedBits: 0,
        nonceGenerator: CKG_NO_GENERATE,
        pMAC: tag.as_mut_ptr(),
        ulMACLen: tag.len() as CK_ULONG,
    };

    // The wrapper's usual idiom: probe first (NULL ciphertext) with the real, empty,
    // non-null plaintext pointer -- this is exactly the call the fix must not reject.
    let mut probed_len: CK_ULONG = 0;
    let ret = fn_encrypt_message(
        session,
        void_ptr!(&mut params),
        sizeof!(CK_CCM_MESSAGE_PARAMS),
        byte_ptr!(aad.as_ptr()),
        aad.len() as CK_ULONG,
        plaintext.as_ptr() as *mut CK_BYTE,
        plaintext.len() as CK_ULONG,
        std::ptr::null_mut(),
        &mut probed_len,
    );
    assert_eq!(ret, CKR_OK);
    assert_eq!(
        probed_len, 0,
        "an AAD-only CCM message produces no ciphertext bytes"
    );

    let mut enc: Vec<u8> = vec![];
    let mut enc_len: CK_ULONG = 0;
    let ret = fn_encrypt_message(
        session,
        void_ptr!(&mut params),
        sizeof!(CK_CCM_MESSAGE_PARAMS),
        byte_ptr!(aad.as_ptr()),
        aad.len() as CK_ULONG,
        plaintext.as_ptr() as *mut CK_BYTE,
        plaintext.len() as CK_ULONG,
        enc.as_mut_ptr(),
        &mut enc_len,
    );
    assert_eq!(ret, CKR_OK);
    assert_eq!(enc_len, 0);

    let ret = fn_message_decrypt_init(session, &mut mechanism, handle);
    assert_eq!(ret, CKR_OK);

    let mut dec: Vec<u8> = vec![];
    let mut dec_len: CK_ULONG = 0;
    let ret = fn_decrypt_message(
        session,
        void_ptr!(&mut params),
        sizeof!(CK_CCM_MESSAGE_PARAMS),
        byte_ptr!(aad.as_ptr()),
        aad.len() as CK_ULONG,
        enc.as_ptr() as *mut CK_BYTE,
        enc_len,
        dec.as_mut_ptr(),
        &mut dec_len,
    );
    assert_eq!(
        ret, CKR_OK,
        "AAD-only decrypt must verify the tag and succeed"
    );
    assert_eq!(dec_len, 0);

    testtokn.finalize();
}

/// Regression test: CKM_AES_CCM with a 7-byte nonce (the maximum-length nonce, giving the
/// SP800-38C length field L = 15 - 7 = 8) must accept messages longer than 1 byte.
///
/// AesOperation::init_params computed the per-nonce-length data cap as `1 << (8 * l)`. CK_ULONG
/// is 64 bits wide on this (LP64) target, and for l == 8 that shift amount is 64 -- out of range
/// for a u64 shift, which silently wraps to `1 << 0 == 1` in a release build (no panic, since
/// overflow-checks are off). The cap then rejected any data longer than 1 byte for exactly the
/// nonce length meant to be the *least* restrictive one.
#[test]
#[parallel]
fn test_aes_ccm_nonce7_allows_data_longer_than_one_byte() {
    let mut testtokn = TestToken::initialized(
        "test_aes_ccm_nonce7_allows_data_longer_than_one_byte",
        None,
    );
    let session = testtokn.get_session(true);
    testtokn.login();

    let handle = ret_or_panic!(generate_key(
        session,
        CKM_AES_KEY_GEN,
        std::ptr::null_mut(),
        0,
        &[(CKA_VALUE_LEN, 16),],
        &[],
        &[(CKA_ENCRYPT, true), (CKA_DECRYPT, true),],
    ));

    let data = b"this plaintext is well over one byte long".to_vec();
    let tag_len = 16usize;
    let nonce = b"1234567".to_vec();
    assert_eq!(nonce.len(), 7);
    let aad = b"AUTH ME".to_vec();

    let mut param = CK_CCM_PARAMS {
        ulDataLen: data.len() as CK_ULONG,
        pNonce: nonce.as_ptr() as *mut CK_BYTE,
        ulNonceLen: nonce.len() as CK_ULONG,
        pAAD: aad.as_ptr() as *mut CK_BYTE,
        ulAADLen: aad.len() as CK_ULONG,
        ulMACLen: tag_len as CK_ULONG,
    };
    let mut mechanism: CK_MECHANISM = CK_MECHANISM {
        mechanism: CKM_AES_CCM,
        pParameter: &mut param as *mut CK_CCM_PARAMS as CK_VOID_PTR,
        ulParameterLen: sizeof!(CK_CCM_PARAMS),
    };

    let ret = fn_encrypt_init(session, &mut mechanism, handle);
    assert_eq!(ret, CKR_OK);

    let mut enc = ret_or_panic!(encrypt_update(session, &data));
    let mut enc_final = ret_or_panic!(encrypt_final(session));
    enc.append(&mut enc_final);
    assert_eq!(enc.len(), data.len() + tag_len);

    let dec = ret_or_panic!(decrypt(session, handle, &enc, &mechanism));
    assert_eq!(dec, data);

    testtokn.finalize();
}

/// Same as test_aes_ccm_nonce7_allows_data_longer_than_one_byte, but for the message-mode
/// CK_CCM_MESSAGE_PARAMS call site (fns/dualcrypto.rs's fn_encrypt_message/fn_decrypt_message
/// via AesOperation::init_msg_params) -- a distinct place the identical shift-overflow bug was
/// duplicated.
#[test]
#[parallel]
fn test_aes_ccm_message_nonce7_allows_data_longer_than_one_byte() {
    let mut testtokn = TestToken::initialized(
        "test_aes_ccm_message_nonce7_allows_data_longer_than_one_byte",
        None,
    );
    let session = testtokn.get_session(true);
    testtokn.login();

    let handle = ret_or_panic!(generate_key(
        session,
        CKM_AES_KEY_GEN,
        std::ptr::null_mut(),
        0,
        &[(CKA_VALUE_LEN, 16),],
        &[],
        &[(CKA_ENCRYPT, true), (CKA_DECRYPT, true),],
    ));

    let mut nonce = b"1234567".to_vec();
    assert_eq!(nonce.len(), 7);
    let aad = b"AUTH ME".to_vec();
    let plaintext = b"this plaintext is well over one byte long".to_vec();

    let mut mechanism: CK_MECHANISM = CK_MECHANISM {
        mechanism: CKM_AES_CCM,
        pParameter: std::ptr::null_mut(),
        ulParameterLen: 0,
    };

    let ret = fn_message_encrypt_init(session, &mut mechanism, handle);
    assert_eq!(ret, CKR_OK);

    let mut tag = [0u8; 16];
    let mut params = CK_CCM_MESSAGE_PARAMS {
        ulDataLen: plaintext.len() as CK_ULONG,
        pNonce: nonce.as_mut_ptr(),
        ulNonceLen: nonce.len() as CK_ULONG,
        ulNonceFixedBits: 0,
        nonceGenerator: CKG_NO_GENERATE,
        pMAC: tag.as_mut_ptr(),
        ulMACLen: tag.len() as CK_ULONG,
    };

    let mut enc = vec![0u8; plaintext.len()];
    let mut enc_len = enc.len() as CK_ULONG;
    let ret = fn_encrypt_message(
        session,
        void_ptr!(&mut params),
        sizeof!(CK_CCM_MESSAGE_PARAMS),
        byte_ptr!(aad.as_ptr()),
        aad.len() as CK_ULONG,
        plaintext.as_ptr() as *mut CK_BYTE,
        plaintext.len() as CK_ULONG,
        enc.as_mut_ptr(),
        &mut enc_len,
    );
    assert_eq!(ret, CKR_OK);
    assert_eq!(enc_len as usize, plaintext.len());

    let ret = fn_message_decrypt_init(session, &mut mechanism, handle);
    assert_eq!(ret, CKR_OK);

    let mut dec = vec![0u8; plaintext.len()];
    let mut dec_len = dec.len() as CK_ULONG;
    let ret = fn_decrypt_message(
        session,
        void_ptr!(&mut params),
        sizeof!(CK_CCM_MESSAGE_PARAMS),
        byte_ptr!(aad.as_ptr()),
        aad.len() as CK_ULONG,
        enc.as_ptr() as *mut CK_BYTE,
        enc_len,
        dec.as_mut_ptr(),
        &mut dec_len,
    );
    assert_eq!(ret, CKR_OK);
    assert_eq!(dec_len as usize, plaintext.len());
    assert_eq!(dec, plaintext);

    testtokn.finalize();
}

/// Regression test for the streaming C_EncryptUpdate call site (fns/encryption.rs
/// internal_encrypt_update, a distinct place the CKR_BUFFER_TOO_SMALL reqsize fix could have
/// been missed vs. the one-shot C_Encrypt / C_Decrypt call sites).
#[test]
#[parallel]
fn test_aes_encrypt_update_buffer_too_small_reports_required_len() {
    let mut testtokn = TestToken::initialized(
        "test_aes_encrypt_update_buffer_too_small_reports_required_len",
        None,
    );
    let session = testtokn.get_session(true);
    testtokn.login();

    let handle = ret_or_panic!(generate_key(
        session,
        CKM_AES_KEY_GEN,
        std::ptr::null_mut(),
        0,
        &[(CKA_VALUE_LEN, 32),],
        &[],
        &[(CKA_ENCRYPT, true), (CKA_DECRYPT, true),],
    ));

    let iv = "FEDCBA0987654321";
    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_AES_CBC,
        pParameter: void_ptr!(iv.as_bytes()),
        ulParameterLen: iv.len() as CK_ULONG,
    };
    let ret = fn_encrypt_init(session, &mut mechanism, handle);
    assert_eq!(ret, CKR_OK);

    /* Exactly one block: CBC (no padding) always emits AES_BLOCK_SIZE bytes for it. */
    let data = "0123456789ABCDEF";
    let mut enc: [u8; 4] = [0; 4];
    let mut enc_len: CK_ULONG = enc.len() as CK_ULONG;
    let ret = fn_encrypt_update(
        session,
        data.as_ptr() as *mut u8,
        data.len() as CK_ULONG,
        enc.as_mut_ptr(),
        &mut enc_len,
    );
    assert_eq!(ret, CKR_BUFFER_TOO_SMALL);
    assert_eq!(
        enc_len, AES_BLOCK_SIZE as CK_ULONG,
        "CKR_BUFFER_TOO_SMALL must report the real required length ({} \
         bytes), not leave *pulEncryptedPartLen at whatever the caller \
         originally passed in (4)",
        AES_BLOCK_SIZE
    );

    let mut enc2 = vec![0u8; enc_len as usize];
    let mut enc2_len = enc2.len() as CK_ULONG;
    let ret = fn_encrypt_update(
        session,
        data.as_ptr() as *mut u8,
        data.len() as CK_ULONG,
        enc2.as_mut_ptr(),
        &mut enc2_len,
    );
    assert_eq!(ret, CKR_OK);
    assert_eq!(enc2_len, AES_BLOCK_SIZE as CK_ULONG);

    testtokn.finalize();
}

/// Regression test for the streaming C_EncryptFinal call site (fns/encryption.rs
/// encrypt_final), distinct from C_EncryptUpdate above -- CBC_PAD's finalize path has its own
/// buf_too_small(AES_BLOCK_SIZE) check for the padding block.
#[test]
#[parallel]
fn test_aes_encrypt_final_buffer_too_small_reports_required_len() {
    let mut testtokn = TestToken::initialized(
        "test_aes_encrypt_final_buffer_too_small_reports_required_len",
        None,
    );
    let session = testtokn.get_session(true);
    testtokn.login();

    let handle = ret_or_panic!(generate_key(
        session,
        CKM_AES_KEY_GEN,
        std::ptr::null_mut(),
        0,
        &[(CKA_VALUE_LEN, 32),],
        &[],
        &[(CKA_ENCRYPT, true), (CKA_DECRYPT, true),],
    ));

    let iv = "FEDCBA0987654321";
    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_AES_CBC_PAD,
        pParameter: void_ptr!(iv.as_bytes()),
        ulParameterLen: iv.len() as CK_ULONG,
    };
    let ret = fn_encrypt_init(session, &mut mechanism, handle);
    assert_eq!(ret, CKR_OK);

    /* One full block via the safe null-probe helper (unaffected by the bug); CBC_PAD always
     * adds a full dummy padding block on Final for block-aligned input. */
    let data = vec![0x0Au8; AES_BLOCK_SIZE];
    let enc = ret_or_panic!(encrypt_update(session, &data));
    assert_eq!(enc.len(), AES_BLOCK_SIZE);

    let mut fin: [u8; 4] = [0; 4];
    let mut fin_len: CK_ULONG = fin.len() as CK_ULONG;
    let ret = fn_encrypt_final(session, fin.as_mut_ptr(), &mut fin_len);
    assert_eq!(ret, CKR_BUFFER_TOO_SMALL);
    assert_eq!(
        fin_len, AES_BLOCK_SIZE as CK_ULONG,
        "CKR_BUFFER_TOO_SMALL must report the real required length ({} \
         bytes), not leave *pulLastEncryptedPartLen at whatever the \
         caller originally passed in (4)",
        AES_BLOCK_SIZE
    );

    let mut fin2 = vec![0u8; fin_len as usize];
    let mut fin2_len = fin2.len() as CK_ULONG;
    let ret = fn_encrypt_final(session, fin2.as_mut_ptr(), &mut fin2_len);
    assert_eq!(ret, CKR_OK);
    assert_eq!(fin2_len, AES_BLOCK_SIZE as CK_ULONG);

    testtokn.finalize();
}

/// Regression test: unlike CCM (see test_aes_ccm_message_empty_data_authenticates_aad), GCM's
/// message-mode msg_encrypt_next/msg_decrypt_next already guarded their ctx.update() calls
/// behind `plain.len() > 0` / `cipher.len() > 0` before the fns/encryption.rs-level zero-length
/// fix -- so removing that fix's now-shared, mechanism-agnostic `_len == 0` argument check could
/// not have newly exposed a GCM-specific bug the way it needed a CCM-specific one (see the other
/// commit in this fix). This confirms a zero-length, AAD-only message round-trips correctly for
/// CKM_AES_GCM's message-mode API too.
#[test]
#[parallel]
fn test_aes_gcm_message_empty_data_authenticates_aad() {
    let mut testtokn = TestToken::initialized(
        "test_aes_gcm_message_empty_data_authenticates_aad",
        None,
    );
    let session = testtokn.get_session(true);
    testtokn.login();

    let handle = ret_or_panic!(generate_key(
        session,
        CKM_AES_KEY_GEN,
        std::ptr::null_mut(),
        0,
        &[(CKA_VALUE_LEN, 32),],
        &[],
        &[(CKA_ENCRYPT, true), (CKA_DECRYPT, true),],
    ));

    let aad = b"AAD only, no payload".to_vec();
    let plaintext: Vec<u8> = vec![];

    let mut mechanism: CK_MECHANISM = CK_MECHANISM {
        mechanism: CKM_AES_GCM,
        pParameter: std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    let ret = fn_message_encrypt_init(session, &mut mechanism, handle);
    assert_eq!(ret, CKR_OK);

    let mut iv = [0u8; 12];
    let mut tag = [0u8; 16];
    let mut params = CK_GCM_MESSAGE_PARAMS {
        pIv: iv.as_mut_ptr(),
        ulIvLen: iv.len() as CK_ULONG,
        ulIvFixedBits: 0,
        ivGenerator: CKG_NO_GENERATE,
        pTag: tag.as_mut_ptr(),
        ulTagBits: (tag.len() * 8) as CK_ULONG,
    };

    let mut enc: Vec<u8> = vec![];
    let mut enc_len: CK_ULONG = 0;
    let ret = fn_encrypt_message(
        session,
        void_ptr!(&mut params),
        sizeof!(CK_GCM_MESSAGE_PARAMS),
        byte_ptr!(aad.as_ptr()),
        aad.len() as CK_ULONG,
        plaintext.as_ptr() as *mut CK_BYTE,
        plaintext.len() as CK_ULONG,
        enc.as_mut_ptr(),
        &mut enc_len,
    );
    assert_eq!(ret, CKR_OK, "GCM AAD-only encrypt");
    assert_eq!(enc_len, 0);

    let ret = fn_message_decrypt_init(session, &mut mechanism, handle);
    assert_eq!(ret, CKR_OK);

    let mut dec: Vec<u8> = vec![];
    let mut dec_len: CK_ULONG = 0;
    let ret = fn_decrypt_message(
        session,
        void_ptr!(&mut params),
        sizeof!(CK_GCM_MESSAGE_PARAMS),
        byte_ptr!(aad.as_ptr()),
        aad.len() as CK_ULONG,
        enc.as_ptr() as *mut CK_BYTE,
        enc_len,
        dec.as_mut_ptr(),
        &mut dec_len,
    );
    assert_eq!(
        ret, CKR_OK,
        "GCM AAD-only decrypt must verify the tag and succeed"
    );
    assert_eq!(dec_len, 0);

    testtokn.finalize();
}

/// Regression test for the one-shot C_EncryptMessage call site (fns/encryption.rs
/// encrypt_message -> operation.msg_encrypt, which for CKM_AES_GCM delegates internally to
/// msg_encrypt_next's own buf_too_small(plain.len()) check).
#[test]
#[parallel]
fn test_aes_gcm_encrypt_message_buffer_too_small_reports_required_len() {
    let mut testtokn = TestToken::initialized(
        "test_aes_gcm_encrypt_message_buffer_too_small_reports_required_len",
        None,
    );
    let session = testtokn.get_session(true);
    testtokn.login();

    let handle = ret_or_panic!(generate_key(
        session,
        CKM_AES_KEY_GEN,
        std::ptr::null_mut(),
        0,
        &[(CKA_VALUE_LEN, 32),],
        &[],
        &[(CKA_ENCRYPT, true), (CKA_DECRYPT, true),],
    ));

    let mut mechanism: CK_MECHANISM = CK_MECHANISM {
        mechanism: CKM_AES_GCM,
        pParameter: std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    let ret = fn_message_encrypt_init(session, &mut mechanism, handle);
    assert_eq!(ret, CKR_OK);

    let mut iv = [0u8; 12];
    let mut tag = [0u8; 16];
    let mut params = CK_GCM_MESSAGE_PARAMS {
        pIv: iv.as_mut_ptr(),
        ulIvLen: iv.len() as CK_ULONG,
        ulIvFixedBits: 0,
        ivGenerator: CKG_NO_GENERATE,
        pTag: tag.as_mut_ptr(),
        ulTagBits: (tag.len() * 8) as CK_ULONG,
    };
    let plaintext = b"Hello world!";
    let mut enc: [u8; 4] = [0; 4];
    let mut enc_len: CK_ULONG = enc.len() as CK_ULONG;
    let ret = fn_encrypt_message(
        session,
        void_ptr!(&mut params),
        sizeof!(CK_GCM_MESSAGE_PARAMS),
        std::ptr::null_mut(),
        0,
        plaintext.as_ptr() as *mut CK_BYTE,
        plaintext.len() as CK_ULONG,
        enc.as_mut_ptr(),
        &mut enc_len,
    );
    assert_eq!(ret, CKR_BUFFER_TOO_SMALL);
    assert_eq!(
        enc_len,
        plaintext.len() as CK_ULONG,
        "CKR_BUFFER_TOO_SMALL must report the real required length ({} \
         bytes), not leave *pulCiphertextLen at whatever the caller \
         originally passed in (4)",
        plaintext.len()
    );

    testtokn.finalize();
}

/// Regression test for the streaming C_EncryptMessageNext call site (fns/encryption.rs
/// encrypt_message_next -> operation.msg_encrypt_next), distinct from the one-shot
/// C_EncryptMessage above -- reached only through the explicit Begin/Next API, never through
/// the one-shot entry point.
#[test]
#[parallel]
fn test_aes_gcm_encrypt_message_next_buffer_too_small_reports_required_len() {
    let mut testtokn = TestToken::initialized(
        "test_aes_gcm_encrypt_message_next_buffer_too_small_reports_required_len",
        None,
    );
    let session = testtokn.get_session(true);
    testtokn.login();

    let handle = ret_or_panic!(generate_key(
        session,
        CKM_AES_KEY_GEN,
        std::ptr::null_mut(),
        0,
        &[(CKA_VALUE_LEN, 32),],
        &[],
        &[(CKA_ENCRYPT, true), (CKA_DECRYPT, true),],
    ));

    let mut mechanism: CK_MECHANISM = CK_MECHANISM {
        mechanism: CKM_AES_GCM,
        pParameter: std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    let ret = fn_message_encrypt_init(session, &mut mechanism, handle);
    assert_eq!(ret, CKR_OK);

    let mut iv = [0u8; 12];
    let mut tag = [0u8; 16];
    let mut params = CK_GCM_MESSAGE_PARAMS {
        pIv: iv.as_mut_ptr(),
        ulIvLen: iv.len() as CK_ULONG,
        ulIvFixedBits: 0,
        ivGenerator: CKG_NO_GENERATE,
        pTag: tag.as_mut_ptr(),
        ulTagBits: (tag.len() * 8) as CK_ULONG,
    };

    let ret = fn_encrypt_message_begin(
        session,
        void_ptr!(&mut params),
        sizeof!(CK_GCM_MESSAGE_PARAMS),
        std::ptr::null_mut(),
        0,
    );
    assert_eq!(ret, CKR_OK);

    let plaintext = b"Hello world!";
    let mut enc: [u8; 4] = [0; 4];
    let mut enc_len: CK_ULONG = enc.len() as CK_ULONG;
    let ret = fn_encrypt_message_next(
        session,
        void_ptr!(&mut params),
        sizeof!(CK_GCM_MESSAGE_PARAMS),
        plaintext.as_ptr() as *mut CK_BYTE,
        plaintext.len() as CK_ULONG,
        enc.as_mut_ptr(),
        &mut enc_len,
        0, /* not CKF_END_OF_MESSAGE */
    );
    assert_eq!(ret, CKR_BUFFER_TOO_SMALL);
    assert_eq!(
        enc_len,
        plaintext.len() as CK_ULONG,
        "CKR_BUFFER_TOO_SMALL must report the real required length ({} \
         bytes), not leave *pulCiphertextPartLen at whatever the caller \
         originally passed in (4)",
        plaintext.len()
    );

    testtokn.finalize();
}

/// Regression test for the C_WrapKey call site (fns/keymgmt.rs wrap_key), the only affected
/// site outside fns/encryption.rs -- it converts its Result via a bare
/// `Err(e) => return Err(e)?` (not even `Err(e) => e.rv()`, but the same effect: the
/// output-length pointer is never written to on this path either).
#[test]
#[parallel]
fn test_aes_wrap_key_buffer_too_small_reports_required_len() {
    let mut testtokn = TestToken::initialized(
        "test_aes_wrap_key_buffer_too_small_reports_required_len",
        None,
    );
    let session = testtokn.get_session(true);
    testtokn.login();

    let wrapping_handle = ret_or_panic!(generate_key(
        session,
        CKM_AES_KEY_GEN,
        std::ptr::null_mut(),
        0,
        &[(CKA_VALUE_LEN, 32),],
        &[],
        &[(CKA_WRAP, true), (CKA_UNWRAP, true),],
    ));
    let target_handle = ret_or_panic!(generate_key(
        session,
        CKM_AES_KEY_GEN,
        std::ptr::null_mut(),
        0,
        &[(CKA_VALUE_LEN, 32),],
        &[],
        &[(CKA_EXTRACTABLE, true),],
    ));

    let mut mechanism: CK_MECHANISM = CK_MECHANISM {
        mechanism: CKM_AES_KEY_WRAP_KWP,
        pParameter: std::ptr::null_mut(),
        ulParameterLen: 0,
    };

    let mut wrapped: [u8; 4] = [0; 4];
    let mut wrapped_len: CK_ULONG = wrapped.len() as CK_ULONG;
    let ret = fn_wrap_key(
        session,
        &mut mechanism,
        wrapping_handle,
        target_handle,
        wrapped.as_mut_ptr(),
        &mut wrapped_len,
    );
    assert_eq!(ret, CKR_BUFFER_TOO_SMALL);
    /* AES-KWP wraps a 32-byte key into 40 bytes (two 8-byte overhead blocks). */
    assert_eq!(
        wrapped_len, 40,
        "CKR_BUFFER_TOO_SMALL must report the real required length (40 \
         bytes), not leave *pulWrappedKeyLen at whatever the caller \
         originally passed in (4)"
    );

    let mut wrapped2 = vec![0u8; wrapped_len as usize];
    let mut wrapped2_len = wrapped2.len() as CK_ULONG;
    let ret = fn_wrap_key(
        session,
        &mut mechanism,
        wrapping_handle,
        target_handle,
        wrapped2.as_mut_ptr(),
        &mut wrapped2_len,
    );
    assert_eq!(ret, CKR_OK);
    assert_eq!(wrapped2_len, 40);

    testtokn.finalize();
}
