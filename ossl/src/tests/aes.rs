// Copyright 2026 Simo Sorce
// See LICENSE.txt file for terms

use hex;
use serial_test::parallel;

use crate::cipher::{AeadParams, AesSize, EncAlg, OsslCipher};
use crate::tests::test_ossl_context;
use crate::OsslSecret;

fn do_aead_test(
    cipher_type: EncAlg,
    key_hex: &str,
    nonce_hex: &str,
    aad_hex: &str,
    plaintext_hex: &str,
    exp_ciphertext_hex: &str,
    exp_tag_hex: &str,
) {
    let context = test_ossl_context();
    if !OsslCipher::is_supported(context, cipher_type) {
        print!(
            "The cipher {:?} is not supported in current build: \
             Skipping test ...",
            cipher_type
        );
        return;
    }
    let key = hex::decode(key_hex).unwrap();
    let nonce = hex::decode(nonce_hex).unwrap();
    let aad = hex::decode(aad_hex).unwrap();
    let plaintext = hex::decode(plaintext_hex).unwrap();
    let exp_ciphertext = hex::decode(exp_ciphertext_hex).unwrap();
    let exp_tag = hex::decode(exp_tag_hex).unwrap();
    let tag_len = exp_tag.len();

    let ccm_data_len = match cipher_type {
        EncAlg::AesCcm(_) => plaintext.len(),
        _ => 0,
    };

    // Encryption
    let aead = AeadParams::new(
        if aad.is_empty() {
            None
        } else {
            Some(aad.clone())
        },
        tag_len,
        ccm_data_len,
    );
    let mut ctx = OsslCipher::new(
        context,
        cipher_type,
        true,
        OsslSecret::from_slice(&key),
        Some(nonce.clone()),
        Some(aead),
    )
    .unwrap();

    let mut ciphertext = vec![0u8; plaintext.len()];
    let mut ct_len = ctx.update(&plaintext, &mut ciphertext).unwrap();
    ct_len += ctx.finalize(&mut ciphertext[ct_len..]).unwrap();
    assert_eq!(ct_len, plaintext.len());
    let mut tag = vec![0u8; tag_len];
    ctx.get_tag(&mut tag).unwrap();
    assert_eq!(ciphertext, exp_ciphertext);
    assert_eq!(tag, exp_tag);

    // Decryption
    let aead = AeadParams::new(
        if aad.is_empty() {
            None
        } else {
            Some(aad.clone())
        },
        tag_len,
        ccm_data_len,
    );
    let mut ctx = OsslCipher::new(
        context,
        cipher_type,
        false,
        OsslSecret::from_slice(&key),
        Some(nonce.clone()),
        Some(aead),
    )
    .unwrap();

    ctx.set_tag(&tag).unwrap();
    let mut decrypted = vec![0u8; plaintext.len()];
    let mut pt_len = ctx.update(&ciphertext, &mut decrypted).unwrap();
    pt_len += ctx.finalize(&mut decrypted[pt_len..]).unwrap();
    assert_eq!(pt_len, plaintext.len());
    assert_eq!(decrypted, plaintext);
}

#[test]
#[parallel]
fn test_aes_128_ccm() {
    /*  test vectors from https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38c.pdf */
    do_aead_test(
        EncAlg::AesCcm(AesSize::Aes128),
        "404142434445464748494a4b4c4d4e4f",
        "10111213141516",
        "0001020304050607",
        "20212223",
        "7162015b",
        "4dac255d",
    );
}

#[test]
#[parallel]
fn test_aes_128_gcm() {
    /*  test vectors from https://csrc.nist.rip/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-revised-spec.pdf */
    do_aead_test(
        EncAlg::AesGcm(AesSize::Aes128),
        "feffe9928665731c6d6a8f9467308308",
        "cafebabefacedbaddecaf888",
        "feedfacedeadbeeffeedfacedeadbeef\
         abaddad2",
        "d9313225f88406e5a55909c5aff5269a\
         86a7a9531534f7da2e4c303d8a318a72\
         1c3c0c95956809532fcf0e2449a6b525\
         b16aedf5aa0de657ba637b39",
        "42831ec2217774244b7221b784d0d49c\
         e3aa212f2c02a4e035c17e2329aca12e\
         21d514b25466931c7d8f6a5aac84aa05\
         1ba30b396a0aac973d58e091",
        "5bc94fbc3221a5db94fae95ae7121a47",
    );
}

#[test]
#[parallel]
fn test_aes_192_gcm() {
    /*  test vectors from https://csrc.nist.rip/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-revised-spec.pdf */
    do_aead_test(
        EncAlg::AesGcm(AesSize::Aes192),
        "feffe9928665731c6d6a8f9467308308\
         feffe9928665731c",
        "cafebabefacedbaddecaf888",
        "feedfacedeadbeeffeedfacedeadbeef\
         abaddad2",
        "d9313225f88406e5a55909c5aff5269a\
         86a7a9531534f7da2e4c303d8a318a72\
         1c3c0c95956809532fcf0e2449a6b525\
         b16aedf5aa0de657ba637b39",
        "3980ca0b3c00e841eb06fac4872a2757\
         859e1ceaa6efd984628593b40ca1e19c\
         7d773d00c144c525ac619d18c84a3f47\
         18e2448b2fe324d9ccda2710",
        "2519498e80f1478f37ba55bd6d27618c",
    );
}

#[test]
#[parallel]
fn test_aes_256_gcm() {
    /*  test vectors from https://csrc.nist.rip/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-revised-spec.pdf */
    do_aead_test(
        EncAlg::AesGcm(AesSize::Aes256),
        "feffe9928665731c6d6a8f9467308308\
         feffe9928665731c6d6a8f9467308308",
        "cafebabefacedbaddecaf888",
        "feedfacedeadbeeffeedfacedeadbeef\
         abaddad2",
        "d9313225f88406e5a55909c5aff5269a\
         86a7a9531534f7da2e4c303d8a318a72\
         1c3c0c95956809532fcf0e2449a6b525\
         b16aedf5aa0de657ba637b39",
        "522dc1f099567d07f47f37a32a84427d\
         643a8cdcbfe5c0c97598a2bd2555d1aa\
         8cb08e48590dbb3da7b08b1056828838\
         c5f61e6393ba7a0abcc9f662",
        "76fc6ece0f4e1768cddf8853bb2d551b",
    );
}

#[test]
#[parallel]
fn test_aes_128_ocb() {
    /*  test vectors from https://www.rfc-editor.org/rfc/rfc7253#appendix-A */
    do_aead_test(
        EncAlg::AesOcb(AesSize::Aes128),
        "000102030405060708090A0B0C0D0E0F",
        "BBAA99887766554433221101",
        "0001020304050607",
        "0001020304050607",
        "6820B3657B6F615A",
        "5725BDA0D3B4EB3A257C9AF1F8F03009",
    );
}
