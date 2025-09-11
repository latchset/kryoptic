// Copyright 2025 Jakub Jelen
// See LICENSE.txt file for terms

use hex;
use serial_test::parallel;

use crate::cipher::{EncAlg, OsslCipher};
use crate::tests::test_ossl_context;
use crate::OsslSecret;

// Test vectors taken from
// https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/block-ciphers (MMT)

fn do_3des_test(
    cipher_type: EncAlg,
    key_hex: &str,
    iv_hex: Option<&str>,
    plaintext_hex: &str,
    exp_ciphertext_hex: &str,
) {
    // 1st test from tdesmmt/TCFB64MMT3.rsp
    let key = hex::decode(key_hex).unwrap();
    let iv = match iv_hex {
        Some(v) => Some(hex::decode(v).unwrap()),
        None => None,
    };
    let plaintext = hex::decode(plaintext_hex).unwrap();
    let exp_ciphertext = hex::decode(exp_ciphertext_hex).unwrap();

    // encryption context
    let mut ctx = OsslCipher::new(
        test_ossl_context(),
        cipher_type,
        true, // encryption mode
        OsslSecret::from_slice(&key),
        iv.clone(),
        None,
    )
    .unwrap();
    ctx.set_padding(false).unwrap();

    // encrypt
    let mut ciphertext = vec![0u8; plaintext.len()];
    let outlen = ctx.update(&plaintext, &mut ciphertext).unwrap();
    assert_eq!(outlen, exp_ciphertext.len());
    // Finalize not needed as we got all the output we needed
    // ctx.finalize(&mut ciphertext[outlen..]).unwrap();
    assert_eq!(ciphertext, exp_ciphertext);

    // decrypt to the plaintext
    let mut ctx = OsslCipher::new(
        test_ossl_context(),
        cipher_type,
        false, // decryption mode
        OsslSecret::from_slice(&key),
        iv,
        None,
    )
    .unwrap();
    ctx.set_padding(false).unwrap();

    let mut rt_plaintext = vec![0u8; plaintext.len()];
    let outlen = ctx.update(&ciphertext, &mut rt_plaintext).unwrap();
    assert_eq!(outlen, plaintext.len());
    // Finalize not needed as we got all the output we needed
    // ctx.finalize(&mut rt_plaintext[outlen..]).unwrap();
    assert_eq!(plaintext, rt_plaintext);
}

#[test]
#[parallel]
fn test_3des_cfb() {
    // 1st test from tdesmmt/TCFB64MMT3.rsp
    do_3des_test(
        EncAlg::TripleDesCfb,
        "e0d525e9eca226d5\
         584a702fdcd3df23\
         8058ad4c1570348f",
        Some("8bf6febfde90bd17"),
        "2685a38657e8dbfe",
        "e9fbc028105354ed",
    );
}

#[test]
#[parallel]
fn test_3des_cbc() {
    // 2nd test from tdesmmt/TCBCMMT3.rsp
    do_3des_test(
        EncAlg::TripleDesCbc,
        "6d0d67da68ab166d\
         1f43c7204c4c2aa4\
         c81a528515f1dff2",
        Some("68e63a07b22e33eb"),
        "4346c4e81380626fa0b2776d30a4fc05",
        "5274be183f5dfb6b018f22b322f0392d",
    );
}

#[test]
#[parallel]
fn test_3des_ecb() {
    // 4th test from tdesmmt/TECBMMT3.rsp
    do_3des_test(
        EncAlg::TripleDesEcb,
        "2c29202c10797985\
         efc252b3da378a89\
         e9a7f88c98c73b1c",
        None,
        "4058771b9c808e6935650f97db27e9e69641fcc5e7bc7fa551a29f0918b669dc",
        "9438d7b8b2057a624a4071de46c986a3393da868a29647041418cb946a51d368",
    );
}
