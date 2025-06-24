// Copyright 2024 Simo Sorce
// See LICENSE.txt file for terms

use crate::tests::*;

use serial_test::parallel;

const AES_BLOCK_SIZE: usize = 16;

#[test]
#[parallel]
fn test_rsa_operations() {
    let mut testtokn = TestToken::initialized(
        "test_rsa_operations",
        Some("testdata/test_rsa_operations.json"),
    );
    let session = testtokn.get_session(true);

    /* login */
    testtokn.login();

    /* public key data */
    let mut handle: CK_ULONG = CK_INVALID_HANDLE;
    let template = make_attr_template(
        &[(CKA_CLASS, CKO_PUBLIC_KEY)],
        &[(CKA_ID, "\x01".as_bytes())],
        &[],
    );
    let mut ret = fn_find_objects_init(session, template.as_ptr() as *mut _, 2);
    assert_eq!(ret, CKR_OK);
    let mut count: CK_ULONG = 0;
    ret = fn_find_objects(session, &mut handle, 1, &mut count);
    assert_eq!(ret, CKR_OK);
    assert_eq!(count, 1);
    assert_ne!(handle, CK_INVALID_HANDLE);
    ret = fn_find_objects_final(session);
    assert_eq!(ret, CKR_OK);

    #[cfg(not(feature = "fips"))]
    {
        /* encrypt init */
        let mut mechanism: CK_MECHANISM = CK_MECHANISM {
            mechanism: CKM_RSA_PKCS,
            pParameter: std::ptr::null_mut(),
            ulParameterLen: 0,
        };
        ret = fn_encrypt_init(session, &mut mechanism, handle);
        assert_eq!(ret, CKR_OK);

        /* a second invocation should return an error */
        ret = fn_encrypt_init(session, &mut mechanism, handle);
        assert_eq!(ret, CKR_OPERATION_ACTIVE);

        let data = "plaintext";
        let enc: [u8; 512] = [0; 512];
        let mut enc_len: CK_ULONG = 512;
        ret = fn_encrypt(
            session,
            CString::new(data).unwrap().into_raw() as *mut u8,
            data.len() as CK_ULONG,
            enc.as_ptr() as *mut _,
            &mut enc_len,
        );
        assert_eq!(ret, CKR_OK);
        assert_eq!(enc_len, 256);

        /* a second invocation should return an error */
        ret = fn_encrypt(
            session,
            CString::new(data).unwrap().into_raw() as *mut u8,
            data.len() as CK_ULONG,
            enc.as_ptr() as *mut _,
            &mut enc_len,
        );
        assert_eq!(ret, CKR_OPERATION_NOT_INITIALIZED);

        /* test that decryption returns the same data back */
        let template = make_attr_template(
            &[(CKA_CLASS, CKO_PRIVATE_KEY)],
            &[(CKA_ID, "\x01".as_bytes())],
            &[],
        );
        let mut ret =
            fn_find_objects_init(session, template.as_ptr() as *mut _, 2);
        assert_eq!(ret, CKR_OK);
        let mut count: CK_ULONG = 0;
        ret = fn_find_objects(session, &mut handle, 1, &mut count);
        assert_eq!(ret, CKR_OK);
        assert_eq!(count, 1);
        assert_ne!(handle, CK_INVALID_HANDLE);
        ret = fn_find_objects_final(session);
        assert_eq!(ret, CKR_OK);

        ret = fn_decrypt_init(session, &mut mechanism, handle);
        assert_eq!(ret, CKR_OK);

        let dec: [u8; 512] = [0; 512];
        let mut dec_len: CK_ULONG = 512;
        ret = fn_decrypt(
            session,
            enc.as_ptr() as *mut u8,
            enc_len,
            dec.as_ptr() as *mut u8,
            &mut dec_len,
        );
        assert_eq!(ret, CKR_OK);
        assert_eq!(data.as_bytes(), &dec[..dec_len as usize]);
    }

    /* RSA PKCS Sig */
    let pri_key_handle = match get_test_key_handle(
        session,
        "SigVer15_186-3.rsp [mod = 2048]",
        CKO_PRIVATE_KEY,
    ) {
        Ok(k) => k,
        Err(e) => panic!("{}", e),
    };
    let pub_key_handle = match get_test_key_handle(
        session,
        "SigVer15_186-3.rsp [mod = 2048]",
        CKO_PUBLIC_KEY,
    ) {
        Ok(k) => k,
        Err(e) => panic!("{}", e),
    };
    let mut msg = hex::decode(
        "6918d6328ca0a8b64bbe81d91cdea519911b59fc2dbd53af76006fec4b18a320\
         787135ce883b2b2edb26041bf86aa52c230b9620335b6e7f9ec08c7ed6b70823\
         d819e9ab019e9929249f966fdb2069311a0ddc680ac468f514d4ed873b04a6be\
         b0985b91a0cfd8ed51b09f9e6d06da739eaa939d5a00275901c4f8cf25076339",
    )
    .expect("Failed to decode msg");
    let mut sig = hex::decode(
        "794d0a45bc9fc6febb586e319dfa6924c888594802b9deb9668963fdb309bf02\
         817960a7457106fc474f91601436e8954cbb6815350b2c51b53c968d2c48cc17\
         99550d5d03b41f6e5a8c3c264d2e2fe0b5b8ff53fdcb9dd111c985cb488d7086\
         e6548b4077ec00721c9cb500fe07a031c2030e8ad1dd0112c34ffd9091d77a18\
         7aac8661b298eee39eb615f9715c4c48a6762ede55a466ec7f3cdb6a937cfc80\
         188a85d8f8d3a2a80b199ce5e6375af8f02f06d706a34d9cf38318903965db54\
         aaa7d3fa7a7ee58034cd58c8435739c8906366e2ddba293f2fb2c15f07fa4951\
         014471e7f677d3bdacffc4c68a906e08d68b39f9010746cbacd22980cee73e8d",
    )
    .expect("Failed to decode sig");

    let mut mechanism: CK_MECHANISM = CK_MECHANISM {
        mechanism: CKM_SHA256_RSA_PKCS,
        pParameter: std::ptr::null_mut(),
        ulParameterLen: 0,
    };

    let ret =
        sig_verify(session, pub_key_handle, &mut msg, &mut sig, &mut mechanism);
    assert_eq!(ret, CKR_OK);

    let result = ret_or_panic!(sig_gen(
        session,
        pri_key_handle,
        &mut msg,
        &mut mechanism
    ));
    assert_eq!(sig, result);

    /* RSA PKCS PSS Sig */
    let pri_key_handle = ret_or_panic!(get_test_key_handle(
        session,
        "SigVerPSS_186-3.rsp [mod = 3072]",
        CKO_PRIVATE_KEY,
    ));
    let pub_key_handle = ret_or_panic!(get_test_key_handle(
        session,
        "SigVerPSS_186-3.rsp [mod = 3072]",
        CKO_PUBLIC_KEY,
    ));
    let _testname = "SigVerPSS_186-3.rsp SHAAlg = SHA384 2514";
    let msg = hex::decode(
        "489e98a8b44dfc6dcb0fd8acd3ebae3176aca8c95d2bd0a601cc8304be4b230d\
         2ab90dfaa4c1cb7c30308a5a82b5ce5b58e464660d8199e86bfca976c2387ab4\
         36908a755d1c26230a30de62632635f03a5e9dcf9a82a2a79f0f65668b114c29\
         172ef85f07e5772b0118bb0b9fc84bb8c321394d2bb654aa450d9e1b445e0135",
    )
    .expect("Failed to decode msg");
    let sig = hex::decode(
        "4f1469770207406b544635afcc58fe656cfb418f3b7d5e8f4be9c4053887c44c\
         86c4a0a39defde8935c9167e51eb732abc2d80072460ad274599ad3d7cee0043\
         6bc680ea31f791997e45d122909459b2b58a1c12d7a342d260410fb364cee94c\
         cdbd6fcdf94653ee30de307ee08d0e5c75fd29612ff7b6c07282af005e8587c6\
         df3c858457d5a494ea61698a91b8605d3091ede031d69f3e446aae70142701f4\
         c9c676681e04de0020b30981d5e965c51afb9fd0d5d6a78df2019dd2cfafc270\
         e6784774130848eac4391c4c45b926fa281a343b651ee043fb9da4613dc0e3ca\
         bc0e68dea8d972fe6988faf055f97bee44b6de9007ce201982a0192e249f8b53\
         3b54f76824932c72b8cadda60108cd9bdeede8a68e159a06a299f19c80e59ad5\
         dd49a39cb06c416e382808e3d4959591d8de4180b65d7a28a17663f7b6da496c\
         e8a2cf08f1ce0ac360158eb2d7d956d8b1dd2493557501b33848281d9d3fa759\
         0ab92290d16d8b7d824adc2c7488199722bbed2354e4d201f9aaefdd2f5f8595",
    )
    .expect("Failed to decode sig");
    let salt =
        hex::decode("11223344555432167890").expect("Failed to decode salt");

    let params = CK_RSA_PKCS_PSS_PARAMS {
        hashAlg: CKM_SHA384,
        mgf: CKG_MGF1_SHA384,
        sLen: salt.len() as CK_ULONG,
    };

    /* this is the only allowed mechanism */
    let mechanism: CK_MECHANISM = CK_MECHANISM {
        mechanism: CKM_SHA384_RSA_PKCS_PSS,
        pParameter: &params as *const _ as CK_VOID_PTR,
        ulParameterLen: sizeof!(CK_RSA_PKCS_PSS_PARAMS),
    };

    let ret = sig_verify(session, pub_key_handle, &msg, &sig, &mechanism);
    assert_eq!(ret, CKR_OK);

    /* Re-Verify using the SignatureVerification APIs */
    let ret = sig_verifysig(session, pub_key_handle, &msg, &sig, &mechanism);
    assert_eq!(ret, CKR_OK);

    let signed =
        ret_or_panic!(sig_gen(session, pri_key_handle, &msg, &mechanism));
    /* PSS is non deterministic because saltlen > 0,
     * so we can't compare the result
     * assert_eq!(sig, result); */
    assert_eq!(sig.len(), signed.len());
    /* but we can verify again to ensure signing produced
     * something usable */
    let ret = sig_verify(session, pub_key_handle, &msg, &signed, &mechanism);
    assert_eq!(ret, CKR_OK);

    if testtokn.dbtype != "nssdb" {
        /* this is not allowed mechanism per CKA_ALLOWED_MECHANISMS */
        let params = CK_RSA_PKCS_PSS_PARAMS {
            hashAlg: CKM_SHA512,
            mgf: CKG_MGF1_SHA512,
            sLen: salt.len() as CK_ULONG,
        };
        let mechanism: CK_MECHANISM = CK_MECHANISM {
            mechanism: CKM_SHA512_RSA_PKCS_PSS,
            pParameter: &params as *const _ as CK_VOID_PTR,
            ulParameterLen: sizeof!(CK_RSA_PKCS_PSS_PARAMS),
        };

        match sig_gen(session, pri_key_handle, &msg, &mechanism) {
            Ok(_) => panic!(
                "The operation using non-allowed mechanisms should have failed"
            ),
            Err(e) => assert_eq!(e.rv(), CKR_MECHANISM_INVALID),
        }
    }

    #[cfg(not(feature = "fips"))]
    {
        /* RSA PKCS Enc */
        let pri_key_handle = ret_or_panic!(get_test_key_handle(
            session,
            "pkcs1v15crypt-vectors.txt - Example 15: A 2048-bit RSA key pair",
            CKO_PRIVATE_KEY,
        ));
        let pub_key_handle = ret_or_panic!(get_test_key_handle(
            session,
            "pkcs1v15crypt-vectors.txt - Example 15: A 2048-bit RSA key pair",
            CKO_PUBLIC_KEY,
        ));
        let _testname =
            "pkcs1v15crypt-vectors.txt - PKCS#1 v1.5 Encryption Example 15.20";
        let msg = hex::decode("69b7644855f91d1c61c8498e4ba1ba4d845ba882b173")
            .expect("Failed to decode msg");
        let enc = hex::decode(
            "ab4267972c7796839388d4ad87ded74bb653e9a7050e282e82192875689f70ee\
             1da18a1f7322092cd29fd00119922a6de12601980aa9fa6e619e2775e87adae3\
             1695c1304e77f52cce016665f2267c20762643c6003c016d8480443c701df6c1\
             d8d655549600ee455b70e473319b0d4445e0b7552a1f808e88f3264842735ae6\
             1df0325ed03690d6d5d693ad1fed22668450379db5323dc01c89affae369b9c3\
             01c319c37ddf51edf46e09b21e5de91483e8e3cb21eeb7057bc2ebdc3aaa3d65\
             00c92f99b17b3180bba047d76073776336b15d054d79a440cc5e985ea543fcaa\
             25db1dd892b71bb74a5cf68263d8fd58f1a48e6c2fcb8c0b71a251cfc1a20157",
        )
        .expect("Failed to decode enc");

        let mechanism: CK_MECHANISM = CK_MECHANISM {
            mechanism: CKM_RSA_PKCS,
            pParameter: std::ptr::null_mut(),
            ulParameterLen: 0,
        };

        let result =
            ret_or_panic!(decrypt(session, pri_key_handle, &enc, &mechanism));
        assert_eq!(msg, result);

        let encrypted =
            ret_or_panic!(encrypt(session, pub_key_handle, &msg, &mechanism));
        /* can't really compare the data because padding contains random
         * octets so each encryption produces a different output */
        assert_eq!(enc.len(), encrypted.len());
        /* but we can decrypt again to ensure encryption produced
         * something usable */
        let result = ret_or_panic!(decrypt(
            session,
            pri_key_handle,
            &encrypted,
            &mechanism
        ));
        assert_eq!(msg, result);
    }

    /* RSA PKCS OAEP Enc */
    let pri_key_handle = ret_or_panic!(get_test_key_handle(
        session,
        "oaep-sha512-sha512.txt - First Key Example",
        CKO_PRIVATE_KEY,
    ));
    let pub_key_handle = ret_or_panic!(get_test_key_handle(
        session,
        "oaep-sha512-sha512.txt - First Key Example",
        CKO_PUBLIC_KEY,
    ));
    let _testname =
        "oaep-sha512-sha512.txt - First Key Example - OAEP Example 1 alg=sha512 mgf1=sha512";
    let msg =
        hex::decode("6628194e12073db03ba94cda9ef9532397d50dba79b987004afefe34")
            .expect("Failed to decode msg");
    let enc = hex::decode(
        "7b7dccee97b43d4b6e214efb90c22d6679b8c144891d47f0674f6cdc94b8c4a8\
         7c1fab9ddd6a1d77d4c9d0487a071e2a0323acf7f04554b43952cfd49d1c6428\
         77a78c04dc8922240eee6afc5eb94896b83c3fc4c7e21c59f8fe1bcf03aa7511\
         0c86655e25d55b75476153e39e3a80017fa61c640838b5b27d03d5830746926b\
         ddd6434acacd0fcc03615c5ba850b591c673bc8e882d51465795cc9eaff1f4a6\
         5e70f9c92777f0877c69c26c1e5cb8bf0ae87ab61ecef24d4349eb57a1c1a270\
         04703038f2c56d9d4f408dedfb9e5263249be9edefd704c7aa9f6b3f6db0b61f\
         3848dd894e70a3f448ea6583f5d74b82ec2850ae1d0e335c22087cc468e5af64",
    )
    .expect("Failed to decode enc");

    let params = CK_RSA_PKCS_OAEP_PARAMS {
        hashAlg: CKM_SHA512,
        mgf: CKG_MGF1_SHA512,
        source: CKZ_DATA_SPECIFIED,
        pSourceData: std::ptr::null_mut(),
        ulSourceDataLen: 0,
    };

    let mechanism: CK_MECHANISM = CK_MECHANISM {
        mechanism: CKM_RSA_PKCS_OAEP,
        pParameter: &params as *const _ as CK_VOID_PTR,
        ulParameterLen: sizeof!(CK_RSA_PKCS_OAEP_PARAMS),
    };

    let result =
        ret_or_panic!(decrypt(session, pri_key_handle, &enc, &mechanism));
    assert_eq!(msg, result);

    let encrypted =
        ret_or_panic!(encrypt(session, pub_key_handle, &msg, &mechanism));
    /* can't really compare the data because padding contains random
     * octets so each encryption produces a different output */
    assert_eq!(enc.len(), encrypted.len());
    /* but we can decrypt again to ensure encryption produced
     * something usable */
    let result =
        ret_or_panic!(decrypt(session, pri_key_handle, &encrypted, &mechanism));
    assert_eq!(msg, result);

    /* RSA PKCS Wrap */
    /* RSA PKCS OAEP Wrap */

    /* generate key pair and store it */
    /* RSA key pair */
    let (hpub, hpri) = ret_or_panic!(generate_key_pair(
        session,
        CKM_RSA_PKCS_KEY_PAIR_GEN,
        &[(CKA_MODULUS_BITS, 2048)],
        &[],
        &[
            (CKA_TOKEN, true),
            (CKA_ENCRYPT, true),
            (CKA_VERIFY, true),
            (CKA_WRAP, true),
        ],
        &[(CKA_CLASS, CKO_PRIVATE_KEY), (CKA_KEY_TYPE, CKK_RSA),],
        &[],
        &[
            (CKA_TOKEN, true),
            (CKA_PRIVATE, true),
            (CKA_SENSITIVE, true),
            (CKA_DECRYPT, true),
            (CKA_SIGN, true),
            (CKA_UNWRAP, true),
            (CKA_EXTRACTABLE, true),
        ],
    ));

    assert_eq!(check_validation(session, 1), true);

    let label = "Public Key test 1";
    let mut template = make_ptrs_template(&[(
        CKA_LABEL,
        void_ptr!(label.as_ptr()),
        label.as_bytes().len(),
    )]);
    let ret = fn_set_attribute_value(
        session,
        hpub,
        template.as_mut_ptr(),
        template.len() as CK_ULONG,
    );
    assert_eq!(ret, CKR_OK);

    let label = "Private Key test 1";
    let mut template = make_ptrs_template(&[(
        CKA_LABEL,
        void_ptr!(label.as_ptr()),
        label.as_bytes().len(),
    )]);
    let ret = fn_set_attribute_value(
        session,
        hpri,
        template.as_mut_ptr(),
        template.len() as CK_ULONG,
    );
    assert_eq!(ret, CKR_OK);

    /* Raw sig is disabled in the openssl submodule */

    #[cfg(feature = "dynamic")]
    {
        /* RSA PKCS Sig */
        let pri_key_handle = match get_test_key_handle(
            session,
            "SigVer15_186-3.rsp [mod = 2048]",
            CKO_PRIVATE_KEY,
        ) {
            Ok(k) => k,
            Err(e) => panic!("{}", e),
        };
        let pub_key_handle = match get_test_key_handle(
            session,
            "SigVer15_186-3.rsp [mod = 2048]",
            CKO_PUBLIC_KEY,
        ) {
            Ok(k) => k,
            Err(e) => panic!("{}", e),
        };

        /* Test Raw Signature */
        let mut mechanism: CK_MECHANISM = CK_MECHANISM {
            mechanism: CKM_RSA_X_509,
            pParameter: std::ptr::null_mut(),
            ulParameterLen: 0,
        };

        let ret = fn_sign_init(session, &mut mechanism, pri_key_handle);
        assert_eq!(ret, CKR_OK);

        let mut sig_len: CK_ULONG = 0;
        let data = "0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345";
        let ret = fn_sign(
            session,
            byte_ptr!(data.as_ptr()),
            data.len() as CK_ULONG,
            std::ptr::null_mut(),
            &mut sig_len,
        );
        assert_eq!(ret, CKR_OK);

        let mut signature = vec![0; sig_len as usize];
        let ret = fn_sign(
            session,
            byte_ptr!(data.as_ptr()),
            data.len() as CK_ULONG,
            signature.as_mut_ptr(),
            &mut sig_len,
        );
        assert_eq!(ret, CKR_OK);

        let ret = fn_verify_init(session, &mut mechanism, pub_key_handle);
        assert_eq!(ret, CKR_OK);

        let ret = fn_verify(
            session,
            byte_ptr!(data.as_ptr()),
            data.len() as CK_ULONG,
            byte_ptr!(signature.as_ptr()),
            signature.len() as CK_ULONG,
        );
        assert_eq!(ret, CKR_OK);
    }

    /* Key Wrap/Unwrap operation of AES key using RSA key */

    /* key to be wrapped */
    let data = [0x55u8; AES_BLOCK_SIZE];
    let wp_handle = ret_or_panic!(import_object(
        session,
        CKO_SECRET_KEY,
        &[(CKA_KEY_TYPE, CKK_AES)],
        &[(CKA_VALUE, &data)],
        &[(CKA_EXTRACTABLE, true)],
    ));

    let params = CK_RSA_PKCS_OAEP_PARAMS {
        hashAlg: CKM_SHA512,
        mgf: CKG_MGF1_SHA512,
        source: CKZ_DATA_SPECIFIED,
        pSourceData: std::ptr::null_mut(),
        ulSourceDataLen: 0,
    };

    let mut mechanism: CK_MECHANISM = CK_MECHANISM {
        mechanism: CKM_RSA_PKCS_OAEP,
        pParameter: &params as *const _ as CK_VOID_PTR,
        ulParameterLen: sizeof!(CK_RSA_PKCS_OAEP_PARAMS),
    };

    /* get length */
    let mut wraplen = 0;
    let ret = fn_wrap_key(
        session,
        &mut mechanism,
        pub_key_handle,
        wp_handle,
        std::ptr::null_mut(),
        &mut wraplen,
    );
    assert_eq!(ret, CKR_OK);
    let mut wrapped = vec![0; wraplen as usize];
    let ret = fn_wrap_key(
        session,
        &mut mechanism,
        pub_key_handle,
        wp_handle,
        wrapped.as_mut_ptr(),
        &mut wraplen,
    );
    assert_eq!(ret, CKR_OK);

    /* Do the decryption trick */
    let dec = ret_or_panic!(decrypt(
        session,
        pri_key_handle,
        &wrapped[..(wraplen as usize)],
        &mechanism,
    ));
    assert_eq!(data, dec.as_slice());

    testtokn.finalize();
}
