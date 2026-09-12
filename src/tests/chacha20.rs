// Copyright 2026 Alexandre Laroche
// See LICENSE.txt file for terms

use crate::tests::*;

use serial_test::parallel;

/// RFC 8439 §2.4.2 test vector: all-zero 256-bit key, all-zero 96-bit
/// nonce, block counter 0 -- the first block of the ChaCha20 keystream,
/// observed as ciphertext when XORed with an all-zero plaintext. Reused
/// from ossl/src/tests/chacha20.rs, which already vets it against the raw
/// OpenSSL cipher this mechanism is built on.
#[test]
#[parallel]
fn test_chacha20_kat() {
    let mut testtokn = TestToken::initialized("test_chacha20_kat", None);
    let session = testtokn.get_session(true);
    testtokn.login();

    let key = vec![0u8; 32];
    let block_counter = vec![0u8; 4];
    let nonce = vec![0u8; 12];
    let plaintext = vec![0u8; 32];
    let expected_ciphertext = hex::decode(
        "76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7",
    )
    .unwrap();

    let handle = ret_or_panic!(import_object(
        session,
        CKO_SECRET_KEY,
        &[(CKA_KEY_TYPE, CKK_CHACHA20)],
        &[(CKA_VALUE, key.as_slice())],
        &[(CKA_ENCRYPT, true), (CKA_DECRYPT, true)],
    ));

    let params = CK_CHACHA20_PARAMS {
        pBlockCounter: block_counter.as_ptr() as *mut CK_BYTE,
        blockCounterBits: 32,
        pNonce: nonce.as_ptr() as *mut CK_BYTE,
        ulNonceBits: 96,
    };
    let mechanism = CK_MECHANISM {
        mechanism: CKM_CHACHA20,
        pParameter: void_ptr!(&params),
        ulParameterLen: sizeof!(CK_CHACHA20_PARAMS),
    };

    let ciphertext =
        ret_or_panic!(encrypt(session, handle, &plaintext, &mechanism));
    assert_eq!(ciphertext, expected_ciphertext);

    let recovered =
        ret_or_panic!(decrypt(session, handle, &ciphertext, &mechanism));
    assert_eq!(recovered, plaintext);

    testtokn.finalize();
}

/// Exercises `C_EncryptUpdate`/`C_EncryptFinal` with arbitrary chunk sizes
/// against the same known-answer vector as [test_chacha20_kat], since
/// ChaCha20 is a true stream cipher: any split must reassemble to the same
/// output as a single-shot call.
#[test]
#[parallel]
fn test_chacha20_multipart() {
    let mut testtokn = TestToken::initialized("test_chacha20_multipart", None);
    let session = testtokn.get_session(true);
    testtokn.login();

    let key = vec![0u8; 32];
    let block_counter = vec![0u8; 4];
    let nonce = vec![0u8; 12];
    let plaintext = vec![0u8; 32];
    let expected_ciphertext = hex::decode(
        "76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7",
    )
    .unwrap();

    let handle = ret_or_panic!(import_object(
        session,
        CKO_SECRET_KEY,
        &[(CKA_KEY_TYPE, CKK_CHACHA20)],
        &[(CKA_VALUE, key.as_slice())],
        &[(CKA_ENCRYPT, true)],
    ));

    let params = CK_CHACHA20_PARAMS {
        pBlockCounter: block_counter.as_ptr() as *mut CK_BYTE,
        blockCounterBits: 32,
        pNonce: nonce.as_ptr() as *mut CK_BYTE,
        ulNonceBits: 96,
    };
    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_CHACHA20,
        pParameter: void_ptr!(&params),
        ulParameterLen: sizeof!(CK_CHACHA20_PARAMS),
    };

    let ret = fn_encrypt_init(session, &mut mechanism, handle);
    assert_eq!(ret, CKR_OK);

    let mut ciphertext =
        ret_or_panic!(encrypt_update(session, &plaintext[..1]));
    ciphertext.append(&mut ret_or_panic!(encrypt_update(
        session,
        &plaintext[1..17]
    )));
    ciphertext.append(&mut ret_or_panic!(encrypt_update(
        session,
        &plaintext[17..]
    )));
    ciphertext.append(&mut ret_or_panic!(encrypt_final(session)));

    assert_eq!(ciphertext, expected_ciphertext);

    testtokn.finalize();
}

/// RFC 8439 §2.8.2 test vector's key/nonce/AAD, reused from
/// ossl/src/tests/chacha20.rs (test_chacha20_poly1305), which already vets
/// the mechanism's full known-answer ciphertext/tag against the raw
/// OpenSSL cipher this mechanism is built on. This test only checks the
/// AEAD round-trip and tamper-rejection properties, so a plain ASCII
/// plaintext is enough -- it does not need to match the RFC's own message
/// byte-for-byte.
#[test]
#[parallel]
fn test_chacha20_poly1305_kat() {
    let mut testtokn =
        TestToken::initialized("test_chacha20_poly1305_kat", None);
    let session = testtokn.get_session(true);
    testtokn.login();

    let key = hex::decode(
        "1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0",
    )
    .unwrap();
    let nonce = hex::decode("000000000102030405060708").unwrap();
    let aad = hex::decode("f33388860000000000004e91").unwrap();
    let plaintext = b"ChaCha20-Poly1305 AEAD round trip".to_vec();

    let handle = ret_or_panic!(import_object(
        session,
        CKO_SECRET_KEY,
        &[(CKA_KEY_TYPE, CKK_CHACHA20)],
        &[(CKA_VALUE, key.as_slice())],
        &[(CKA_ENCRYPT, true), (CKA_DECRYPT, true)],
    ));

    let params = CK_SALSA20_CHACHA20_POLY1305_PARAMS {
        pNonce: nonce.as_ptr() as *mut CK_BYTE,
        ulNonceLen: nonce.len() as CK_ULONG,
        pAAD: aad.as_ptr() as *mut CK_BYTE,
        ulAADLen: aad.len() as CK_ULONG,
    };
    let mechanism = CK_MECHANISM {
        mechanism: CKM_CHACHA20_POLY1305,
        pParameter: void_ptr!(&params),
        ulParameterLen: sizeof!(CK_SALSA20_CHACHA20_POLY1305_PARAMS),
    };

    let ciphertext =
        ret_or_panic!(encrypt(session, handle, &plaintext, &mechanism));
    assert_eq!(ciphertext.len(), plaintext.len() + 16);

    let recovered =
        ret_or_panic!(decrypt(session, handle, &ciphertext, &mechanism));
    assert_eq!(recovered, plaintext);

    /* A tampered tag must be rejected */
    let mut tampered = ciphertext.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 0xff;
    assert!(decrypt(session, handle, &tampered, &mechanism).is_err());

    testtokn.finalize();
}

/// Exercises `C_EncryptUpdate`/`C_EncryptFinal` and
/// `C_DecryptUpdate`/`C_DecryptFinal` for ChaCha20-Poly1305, specifically
/// to cover the tag-tail buffering: the Poly1305 tag is appended to the
/// end of the ciphertext, so a multi-part decrypt must hold back the last
/// 16 bytes seen so far until `C_DecryptFinal` proves no more data follows.
#[test]
#[parallel]
fn test_chacha20_poly1305_multipart() {
    let mut testtokn =
        TestToken::initialized("test_chacha20_poly1305_multipart", None);
    let session = testtokn.get_session(true);
    testtokn.login();

    let key = vec![0x42u8; 32];
    let nonce = vec![0x24u8; 12];
    let aad = b"header".to_vec();
    let plaintext = b"ChaCha20-Poly1305 multi-part round trip test data, \
                       spanning more than one Poly1305/ChaCha20 block."
        .to_vec();

    let handle = ret_or_panic!(import_object(
        session,
        CKO_SECRET_KEY,
        &[(CKA_KEY_TYPE, CKK_CHACHA20)],
        &[(CKA_VALUE, key.as_slice())],
        &[(CKA_ENCRYPT, true), (CKA_DECRYPT, true)],
    ));

    let params = CK_SALSA20_CHACHA20_POLY1305_PARAMS {
        pNonce: nonce.as_ptr() as *mut CK_BYTE,
        ulNonceLen: nonce.len() as CK_ULONG,
        pAAD: aad.as_ptr() as *mut CK_BYTE,
        ulAADLen: aad.len() as CK_ULONG,
    };
    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_CHACHA20_POLY1305,
        pParameter: void_ptr!(&params),
        ulParameterLen: sizeof!(CK_SALSA20_CHACHA20_POLY1305_PARAMS),
    };

    /* One-shot encrypt to get the reference ciphertext||tag */
    let expected =
        ret_or_panic!(encrypt(session, handle, &plaintext, &mechanism));

    /* Multi-part encrypt in small, uneven chunks must match it */
    let ret = fn_encrypt_init(session, &mut mechanism, handle);
    assert_eq!(ret, CKR_OK);
    let mut ciphertext = Vec::new();
    for chunk in plaintext.chunks(7) {
        ciphertext.append(&mut ret_or_panic!(encrypt_update(session, chunk)));
    }
    ciphertext.append(&mut ret_or_panic!(encrypt_final(session)));
    assert_eq!(ciphertext, expected);

    /* Multi-part decrypt in small, uneven chunks (including chunks smaller
     * than the 16-byte tag) must recover the plaintext */
    let ret = fn_decrypt_init(session, &mut mechanism, handle);
    assert_eq!(ret, CKR_OK);
    let mut recovered = Vec::new();
    for chunk in ciphertext.chunks(5) {
        recovered.append(&mut ret_or_panic!(decrypt_update(session, chunk)));
    }
    recovered.append(&mut ret_or_panic!(decrypt_final(session)));
    assert_eq!(recovered, plaintext);

    testtokn.finalize();
}

/// `CKM_CHACHA20_KEY_GEN` must always produce a 256-bit key.
#[test]
#[parallel]
fn test_chacha20_key_gen() {
    let mut testtokn = TestToken::initialized("test_chacha20_key_gen", None);
    let session = testtokn.get_session(true);
    testtokn.login();

    let handle = ret_or_panic!(generate_key(
        session,
        CKM_CHACHA20_KEY_GEN,
        std::ptr::null_mut(),
        0,
        &[(CKA_VALUE_LEN, 32)],
        &[],
        &[(CKA_TOKEN, false), (CKA_ENCRYPT, true), (CKA_DECRYPT, true)],
    ));

    /* A generated key must be usable, which -- since object_to_raw_key
     * rejects anything but exactly 32 bytes -- proves it was sized
     * correctly, without needing to read CKA_VALUE_LEN back directly. */
    let block_counter = vec![0u8; 4];
    let nonce = vec![0u8; 12];
    let params = CK_CHACHA20_PARAMS {
        pBlockCounter: block_counter.as_ptr() as *mut CK_BYTE,
        blockCounterBits: 32,
        pNonce: nonce.as_ptr() as *mut CK_BYTE,
        ulNonceBits: 96,
    };
    let mechanism = CK_MECHANISM {
        mechanism: CKM_CHACHA20,
        pParameter: void_ptr!(&params),
        ulParameterLen: sizeof!(CK_CHACHA20_PARAMS),
    };
    let plaintext = b"generated key round trip".to_vec();
    let ciphertext =
        ret_or_panic!(encrypt(session, handle, &plaintext, &mechanism));
    let recovered =
        ret_or_panic!(decrypt(session, handle, &ciphertext, &mechanism));
    assert_eq!(recovered, plaintext);

    testtokn.finalize();
}

/// The alternative, original (64-bit-nonce/64-bit-counter) `CK_CHACHA20_PARAMS`
/// layout is not implemented (only the IETF/RFC 8439 layout is), and a
/// wrong-size key must be rejected.
#[test]
#[parallel]
fn test_chacha20_param_validation() {
    let mut testtokn =
        TestToken::initialized("test_chacha20_param_validation", None);
    let session = testtokn.get_session(true);
    testtokn.login();

    let key = vec![0u8; 32];
    let handle = ret_or_panic!(import_object(
        session,
        CKO_SECRET_KEY,
        &[(CKA_KEY_TYPE, CKK_CHACHA20)],
        &[(CKA_VALUE, key.as_slice())],
        &[(CKA_ENCRYPT, true)],
    ));

    /* 64-bit counter / 64-bit nonce (the non-IETF layout) is rejected */
    let block_counter = vec![0u8; 8];
    let nonce = vec![0u8; 8];
    let params = CK_CHACHA20_PARAMS {
        pBlockCounter: block_counter.as_ptr() as *mut CK_BYTE,
        blockCounterBits: 64,
        pNonce: nonce.as_ptr() as *mut CK_BYTE,
        ulNonceBits: 64,
    };
    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_CHACHA20,
        pParameter: void_ptr!(&params),
        ulParameterLen: sizeof!(CK_CHACHA20_PARAMS),
    };
    let ret = fn_encrypt_init(session, &mut mechanism, handle);
    assert_eq!(ret, CKR_MECHANISM_PARAM_INVALID);

    /* A wrong-size key is rejected at import time */
    let short_key = vec![0u8; 16];
    let ret = import_object(
        session,
        CKO_SECRET_KEY,
        &[(CKA_KEY_TYPE, CKK_CHACHA20)],
        &[(CKA_VALUE, short_key.as_slice())],
        &[(CKA_ENCRYPT, true)],
    );
    assert!(ret.is_err());

    testtokn.finalize();
}

/// Message-mode (`C_MessageEncryptInit`/`C_EncryptMessage`/
/// `C_MessageEncryptFinal` and decrypt counterparts) one-shot round trip,
/// including the defining feature of message mode: reusing one
/// initialized session across several independently-nonced messages. Also
/// checks that the Poly1305 tag lands in the separate `pTag` output, not
/// appended to the ciphertext (unlike the classic, non-message path).
#[test]
#[parallel]
fn test_chacha20_poly1305_message_mode() {
    let mut testtokn =
        TestToken::initialized("test_chacha20_poly1305_message_mode", None);
    let session = testtokn.get_session(true);
    testtokn.login();

    let key = vec![0x11u8; 32];
    let handle = ret_or_panic!(import_object(
        session,
        CKO_SECRET_KEY,
        &[(CKA_KEY_TYPE, CKK_CHACHA20)],
        &[(CKA_VALUE, key.as_slice())],
        &[(CKA_ENCRYPT, true), (CKA_DECRYPT, true)],
    ));

    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_CHACHA20_POLY1305,
        pParameter: std::ptr::null_mut(),
        ulParameterLen: 0,
    };

    let ret = fn_message_encrypt_init(session, &mut mechanism, handle);
    assert_eq!(ret, CKR_OK);

    // Encrypt two independent messages under the same initialized
    // session, each with its own nonce/AAD -- exactly what message mode
    // exists to make efficient.
    let messages: [(&[u8], &[u8], &[u8]); 2] = [
        (
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01",
            b"aad-one",
            b"first message",
        ),
        (
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02",
            b"aad-two",
            b"second, different message",
        ),
    ];

    let mut ciphertexts = Vec::new();
    for (nonce, aad, plaintext) in &messages {
        let mut tag = [0u8; 16];
        let mut param = CK_SALSA20_CHACHA20_POLY1305_MSG_PARAMS {
            pNonce: nonce.as_ptr() as *mut CK_BYTE,
            ulNonceLen: nonce.len() as CK_ULONG,
            pTag: tag.as_mut_ptr(),
        };
        let mut ciphertext = vec![0u8; plaintext.len()];
        let mut ciphertext_len = ciphertext.len() as CK_ULONG;

        let ret = fn_encrypt_message(
            session,
            void_ptr!(&mut param),
            sizeof!(CK_SALSA20_CHACHA20_POLY1305_MSG_PARAMS),
            aad.as_ptr() as CK_BYTE_PTR,
            aad.len() as CK_ULONG,
            plaintext.as_ptr() as *mut CK_BYTE,
            plaintext.len() as CK_ULONG,
            ciphertext.as_mut_ptr(),
            &mut ciphertext_len,
        );
        assert_eq!(ret, CKR_OK);
        assert_eq!(ciphertext_len as usize, plaintext.len());
        ciphertexts.push((ciphertext, tag));
    }

    let ret = fn_message_encrypt_final(session);
    assert_eq!(ret, CKR_OK);

    // Decrypt both back, again reusing one initialized session.
    let ret = fn_message_decrypt_init(session, &mut mechanism, handle);
    assert_eq!(ret, CKR_OK);

    for (i, (nonce, aad, plaintext)) in messages.iter().enumerate() {
        let (ciphertext, mut tag) = ciphertexts[i].clone();
        let mut param = CK_SALSA20_CHACHA20_POLY1305_MSG_PARAMS {
            pNonce: nonce.as_ptr() as *mut CK_BYTE,
            ulNonceLen: nonce.len() as CK_ULONG,
            pTag: tag.as_mut_ptr(),
        };
        let mut recovered = vec![0u8; ciphertext.len()];
        let mut recovered_len = recovered.len() as CK_ULONG;

        let ret = fn_decrypt_message(
            session,
            void_ptr!(&mut param),
            sizeof!(CK_SALSA20_CHACHA20_POLY1305_MSG_PARAMS),
            aad.as_ptr() as CK_BYTE_PTR,
            aad.len() as CK_ULONG,
            ciphertext.as_ptr() as *mut CK_BYTE,
            ciphertext.len() as CK_ULONG,
            recovered.as_mut_ptr(),
            &mut recovered_len,
        );
        assert_eq!(ret, CKR_OK);
        assert_eq!(&recovered[..], *plaintext);
    }

    let ret = fn_message_decrypt_final(session);
    assert_eq!(ret, CKR_OK);

    testtokn.finalize();
}

/// Exercises `C_EncryptMessageBegin`/`C_EncryptMessageNext` and their
/// decrypt counterparts for a single message split into several chunks.
#[test]
#[parallel]
fn test_chacha20_poly1305_message_mode_multipart() {
    let mut testtokn = TestToken::initialized(
        "test_chacha20_poly1305_message_mode_multipart",
        None,
    );
    let session = testtokn.get_session(true);
    testtokn.login();

    let key = vec![0x22u8; 32];
    let nonce = vec![0x33u8; 12];
    let aad = b"multipart-aad".to_vec();
    let plaintext = b"this message is split across several \
                       C_EncryptMessageNext/C_DecryptMessageNext calls"
        .to_vec();

    let handle = ret_or_panic!(import_object(
        session,
        CKO_SECRET_KEY,
        &[(CKA_KEY_TYPE, CKK_CHACHA20)],
        &[(CKA_VALUE, key.as_slice())],
        &[(CKA_ENCRYPT, true), (CKA_DECRYPT, true)],
    ));

    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_CHACHA20_POLY1305,
        pParameter: std::ptr::null_mut(),
        ulParameterLen: 0,
    };

    let ret = fn_message_encrypt_init(session, &mut mechanism, handle);
    assert_eq!(ret, CKR_OK);

    let mut tag = [0u8; 16];
    let mut param = CK_SALSA20_CHACHA20_POLY1305_MSG_PARAMS {
        pNonce: nonce.as_ptr() as *mut CK_BYTE,
        ulNonceLen: nonce.len() as CK_ULONG,
        pTag: tag.as_mut_ptr(),
    };

    let ret = fn_encrypt_message_begin(
        session,
        void_ptr!(&mut param),
        sizeof!(CK_SALSA20_CHACHA20_POLY1305_MSG_PARAMS),
        aad.as_ptr() as CK_BYTE_PTR,
        aad.len() as CK_ULONG,
    );
    assert_eq!(ret, CKR_OK);

    let mut ciphertext = Vec::new();
    for chunk in plaintext.chunks(9) {
        let mut out = vec![0u8; chunk.len()];
        let mut out_len = out.len() as CK_ULONG;
        let ret = fn_encrypt_message_next(
            session,
            void_ptr!(&mut param),
            sizeof!(CK_SALSA20_CHACHA20_POLY1305_MSG_PARAMS),
            chunk.as_ptr() as *mut CK_BYTE,
            chunk.len() as CK_ULONG,
            out.as_mut_ptr(),
            &mut out_len,
            0,
        );
        assert_eq!(ret, CKR_OK);
        ciphertext.extend_from_slice(&out[..out_len as usize]);
    }
    // Final, zero-length chunk with CKF_END_OF_MESSAGE finalizes and
    // writes the tag into param.pTag. `fixed`-over-empty-span in the C#
    // wrapper aside, this library itself still requires a real, non-null
    // pointer even for zero-length data -- only a real pointer with
    // pul_ciphertext_part_len set to 0 is a genuine, real call (a null
    // ciphertext_part is instead treated as a length probe).
    let mut empty_in: [u8; 0] = [];
    let mut empty_out: [u8; 0] = [];
    let mut out_len: CK_ULONG = 0;
    let ret = fn_encrypt_message_next(
        session,
        void_ptr!(&mut param),
        sizeof!(CK_SALSA20_CHACHA20_POLY1305_MSG_PARAMS),
        empty_in.as_mut_ptr(),
        0,
        empty_out.as_mut_ptr(),
        &mut out_len,
        CKF_END_OF_MESSAGE,
    );
    assert_eq!(ret, CKR_OK);

    let ret = fn_message_encrypt_final(session);
    assert_eq!(ret, CKR_OK);
    assert_eq!(ciphertext.len(), plaintext.len());

    // Decrypt back, split into different-sized chunks.
    let ret = fn_message_decrypt_init(session, &mut mechanism, handle);
    assert_eq!(ret, CKR_OK);

    let mut param = CK_SALSA20_CHACHA20_POLY1305_MSG_PARAMS {
        pNonce: nonce.as_ptr() as *mut CK_BYTE,
        ulNonceLen: nonce.len() as CK_ULONG,
        pTag: tag.as_mut_ptr(),
    };
    let ret = fn_decrypt_message_begin(
        session,
        void_ptr!(&mut param),
        sizeof!(CK_SALSA20_CHACHA20_POLY1305_MSG_PARAMS),
        aad.as_ptr() as CK_BYTE_PTR,
        aad.len() as CK_ULONG,
    );
    assert_eq!(ret, CKR_OK);

    let mut recovered = Vec::new();
    for chunk in ciphertext.chunks(13) {
        let mut out = vec![0u8; chunk.len()];
        let mut out_len = out.len() as CK_ULONG;
        let ret = fn_decrypt_message_next(
            session,
            void_ptr!(&mut param),
            sizeof!(CK_SALSA20_CHACHA20_POLY1305_MSG_PARAMS),
            chunk.as_ptr() as *mut CK_BYTE,
            chunk.len() as CK_ULONG,
            out.as_mut_ptr(),
            &mut out_len,
            0,
        );
        assert_eq!(ret, CKR_OK);
        recovered.extend_from_slice(&out[..out_len as usize]);
    }
    let mut empty_in: [u8; 0] = [];
    let mut empty_out: [u8; 0] = [];
    let mut out_len: CK_ULONG = 0;
    let ret = fn_decrypt_message_next(
        session,
        void_ptr!(&mut param),
        sizeof!(CK_SALSA20_CHACHA20_POLY1305_MSG_PARAMS),
        empty_in.as_mut_ptr(),
        0,
        empty_out.as_mut_ptr(),
        &mut out_len,
        CKF_END_OF_MESSAGE,
    );
    assert_eq!(ret, CKR_OK);

    let ret = fn_message_decrypt_final(session);
    assert_eq!(ret, CKR_OK);

    assert_eq!(recovered, plaintext);

    testtokn.finalize();
}
