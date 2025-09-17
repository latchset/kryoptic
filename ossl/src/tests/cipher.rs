// Copyright 2025 Jakub Jelen
// See LICENSE.txt file for terms

use hex;
use serial_test::parallel;

use crate::cipher::{CamelliaSize, EncAlg, OsslCipher};
use crate::tests::{test_ossl_context, test_ossl_legacy_context};
use crate::{OsslContext, OsslSecret};

fn do_cipher_test(
    cipher_type: EncAlg,
    key_hex: &str,
    iv_hex: Option<&str>,
    plaintext_hex: &str,
    exp_ciphertext_hex: &str,
) {
    do_cipher_test_context(
        cipher_type,
        key_hex,
        iv_hex,
        plaintext_hex,
        exp_ciphertext_hex,
        test_ossl_context(),
    )
}

fn do_cipher_test_legacy(
    cipher_type: EncAlg,
    key_hex: &str,
    iv_hex: Option<&str>,
    plaintext_hex: &str,
    exp_ciphertext_hex: &str,
) {
    do_cipher_test_context(
        cipher_type,
        key_hex,
        iv_hex,
        plaintext_hex,
        exp_ciphertext_hex,
        test_ossl_legacy_context(),
    )
}

fn do_cipher_test_context(
    cipher_type: EncAlg,
    key_hex: &str,
    iv_hex: Option<&str>,
    plaintext_hex: &str,
    exp_ciphertext_hex: &str,
    context: &OsslContext,
) {
    if !OsslCipher::is_supported(context, cipher_type) {
        print!("The cipher {:?} is not supported in current build: Skipping test ...", cipher_type);
        return;
    }
    let key = hex::decode(key_hex).unwrap();
    let iv = match iv_hex {
        Some(v) => Some(hex::decode(v).unwrap()),
        None => None,
    };
    let plaintext = hex::decode(plaintext_hex).unwrap();
    let exp_ciphertext = hex::decode(exp_ciphertext_hex).unwrap();

    // encryption context
    let mut ctx = OsslCipher::new(
        context,
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
        context,
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

// 3DES Test vectors taken from
// https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/block-ciphers (MMT)

#[test]
#[parallel]
fn test_3des_cfb() {
    // 1st test from tdesmmt/TCFB64MMT3.rsp
    do_cipher_test(
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
    do_cipher_test(
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
    do_cipher_test(
        EncAlg::TripleDesEcb,
        "2c29202c10797985\
         efc252b3da378a89\
         e9a7f88c98c73b1c",
        None,
        "4058771b9c808e6935650f97db27e9e69641fcc5e7bc7fa551a29f0918b669dc",
        "9438d7b8b2057a624a4071de46c986a3393da868a29647041418cb946a51d368",
    );
}

// Test vectors taken from
// https://info.isl.ntt.co.jp/crypt/eng/camellia/technology/

#[test]
#[parallel]
fn test_camellia128_ecb() {
    // K No.001, P No.001 from t_camellia.txt
    do_cipher_test(
        EncAlg::CamelliaEcb(CamelliaSize::Camellia128),
        "00000000000000000000000000000000",
        None,
        "80000000000000000000000000000000",
        "07923A39EB0A817D1C4D87BDB82D1F1C",
    );
}

#[test]
#[parallel]
fn test_camellia192_ecb() {
    // K No.004, P No.002 from t_camellia.txt
    do_cipher_test(
        EncAlg::CamelliaEcb(CamelliaSize::Camellia192),
        "F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0",
        None,
        "40000000000000000000000000000000",
        "7D7A57CD0BCD6C872C8076A58C7C2159",
    );
}

#[test]
#[parallel]
fn test_camellia256_ecb() {
    // K No.010, P No.128 from t_camellia.txt
    do_cipher_test(
        EncAlg::CamelliaEcb(CamelliaSize::Camellia256),
        "EFCDAB89674523011032547698BADCFE1032547698BADCFEEFCDAB8967452301",
        None,
        "00000000000000000000000000000001",
        "44AE0AADA74995BE0FD47EC5DA6F862D",
    );
}

// Test vectors taken from OpenSSL
// https://github.com/openssl/openssl/blob/aff636a4893e24bdc686a00a13ae6199dd38d6aa/test/recipes/30-test_evp_data/evpciph_camellia.txt

#[test]
#[parallel]
fn test_camellia128_cbc() {
    // line 123
    do_cipher_test(
        EncAlg::CamelliaCbc(CamelliaSize::Camellia128),
        "2B7E151628AED2A6ABF7158809CF4F3C",
        Some("000102030405060708090A0B0C0D0E0F"),
        "6BC1BEE22E409F96E93D7E117393172A",
        "1607CF494B36BBF00DAEB0B503C831AB",
    );
}

#[test]
#[parallel]
fn test_camellia192_cbc() {
    // line 174
    do_cipher_test(
        EncAlg::CamelliaCbc(CamelliaSize::Camellia192),
        "8E73B0F7DA0E6452C810F32B809079E562F8EAD2522C6B7B",
        Some("37D359C3349836D884E310ADDF68C449"),
        "F69F2445DF4F9B17AD2B417BE66C3710",
        "01FAAA930B4AB9916E9668E1428C6B08",
    );
}

#[test]
#[parallel]
fn test_camellia256_cbc() {
    // line 192
    do_cipher_test(
        EncAlg::CamelliaCbc(CamelliaSize::Camellia256),
        "603DEB1015CA71BE2B73AEF0857D77811F352C073B6108D72D9810A30914DFF4",
        Some("36CBEB73BD504B4070B1B7DE2B21EB50"),
        "30C81C46A35CE411E5FBC1191A0A52EF",
        "E31A6055297D96CA3330CDF1B1860A83",
    );
}

#[test]
#[parallel]
fn test_camellia128_cfb() {
    // line 239
    do_cipher_test(
        EncAlg::CamelliaCfb(CamelliaSize::Camellia128),
        "2B7E151628AED2A6ABF7158809CF4F3C",
        Some("9C2157A664626D1DEF9EA420FDE69B96"),
        "F69F2445DF4F9B17AD2B417BE66C3710",
        "742A25F0542340C7BAEF24CA8482BB09",
    );
}

#[test]
#[parallel]
fn test_camellia192_cfb() {
    // line 291
    do_cipher_test(
        EncAlg::CamelliaCfb(CamelliaSize::Camellia192),
        "8E73B0F7DA0E6452C810F32B809079E562F8EAD2522C6B7B",
        Some("C832BB9780677DAA82D9B6860DCD565E"),
        "AE2D8A571E03AC9C9EB76FAC45AF8E51",
        "86F8491627906D780C7A6D46EA331F98",
    );
}

#[test]
#[parallel]
fn test_camellia256_cfb() {
    // line 375
    do_cipher_test(
        EncAlg::CamelliaCfb(CamelliaSize::Camellia256),
        "603DEB1015CA71BE2B73AEF0857D77811F352C073B6108D72D9810A30914DFF4",
        Some("555FC3F34BDD2D54C62D9E3BF338C1C4"),
        "F69F2445DF4F9B17AD2B417BE66C3710",
        "5953ADCE14DB8C7F39F1BD39F359BFFA",
    );
}

// Blowfish tests from
// https://www.schneier.com/wp-content/uploads/2015/12/vectors-2.txt
// chaining mode test data at the end

#[test]
#[parallel]
fn test_blowfish_cbc() {
    // added padding manually -- should work same with the set_padding(true)
    do_cipher_test_legacy(
        EncAlg::BlowfishCbc,
        "0123456789ABCDEFF0E1D2C3B4A59687",
        Some("FEDCBA9876543210"),
        "37363534333231204E6F77206973207468652074696D6520666F722000000000",
        "6B77B4D63006DEE605B156E27403979358DEB9E7154616D959F1652BD5FF92CC",
    );
}

#[test]
#[parallel]
fn test_blowfish_cfb() {
    do_cipher_test_legacy(
        EncAlg::BlowfishCfb,
        "0123456789ABCDEFF0E1D2C3B4A59687",
        Some("FEDCBA9876543210"),
        "37363534333231204E6F77206973207468652074696D6520666F722000",
        "E73214A2822139CAF26ECF6D2EB9E76E3DA3DE04D1517200519D57A6C3",
    );
}

#[test]
#[parallel]
fn test_blowfish_ecb() {
    // from OpenSSL again as the short keys from the above do not work
    // https://github.com/openssl/openssl/blob/aff636a4893e24bdc686a00a13ae6199dd38d6aa/test/recipes/30-test_evp_data/evpciph_bf.txt#L12
    do_cipher_test_legacy(
        EncAlg::BlowfishEcb,
        "000102030405060708090a0b0c0d0e0f",
        None,
        "0f0e0c0d0b0a09080706050403020100",
        "079590e0010626685653b9b6c2a406e0",
    );
}

#[test]
#[parallel]
fn test_cast5_ecb() {
    // from RFC 2144
    // https://www.rfc-editor.org/rfc/rfc2144#page-15
    do_cipher_test_legacy(
        EncAlg::Cast5Ecb,
        "0123456712345678234567893456789A",
        None,
        "0123456789ABCDEF",
        "238B4FE5847E44B2",
    );
}

// The chaining ones from OpenSSL:
// https://github.com/openssl/openssl/blob/3a43b30ebb2bea7d3a45767751dd695bb9903630/test/recipes/30-test_evp_data/evpciph_cast5.txt

#[test]
#[parallel]
fn test_cast5_cbc() {
    do_cipher_test_legacy(
        EncAlg::Cast5Cbc,
        "3348aa51e9a45c2dbe33ccc47f96e8de",
        Some("19153c673160df2b"),
        "9b7cee827a26575afdbb7c7a329f887238052e3601a7917456ba61251c214763d5e1847a6ad5d54127a399ab07ee3599",
        "3c033e10fad0c4ce1e62e2a91488090947c5e0ac0dd5f55c1b15b0b02fa7cfd20f61b02d67ea9f326c5475447dee69bf",
    );
}

#[test]
#[parallel]
fn test_cast5_cfb() {
    do_cipher_test_legacy(
        EncAlg::Cast5Cfb,
        "0a8e8876c96cddf3223069002002c99f",
        Some("b125a20ecd79e8b5"),
        "4fd0ecac65bfd321c88ebca0daea35d2b061205d696aab08bea68320db65451a6d6c3679fdf633f37cf8ebcf1fa94b91",
        "8feace1e2d6aedf53e779ee3d62e3635a2d1234802665bc34c8be46f397e04aecaea6045f3d0194ea9002dfa358ed390",
    );
}

// IDEA tests from OpenSSL
// https://github.com/openssl/openssl/blob/3a43b30ebb2bea7d3a45767751dd695bb9903630/test/recipes/30-test_evp_data/evpciph_idea.txt
// no other better test vector found

#[test]
#[parallel]
fn test_idea_cfb() {
    do_cipher_test_legacy(
        EncAlg::IdeaCfb,
        "701ccc4c0e36e512ce077f5af6ccb957",
        Some("5337ddeaf89a00dd"),
        "cc1172f2f80866d0768b25f70fcf6361aab7c627c8488f97525d7d88949beeea",
        "4ec6f34be3335024cbfbbf80f3e7501b8c9f7a6cbd630cf8debba4a4c3f1daa4",
    );
}

#[test]
#[parallel]
fn test_idea_cbc() {
    do_cipher_test_legacy(
        EncAlg::IdeaCbc,
        "3348aa51e9a45c2dbe33ccc47f96e8de",
        Some("19153c673160df2b"),
        "9b7cee827a26575afdbb7c7a329f887238052e3601a7917456ba61251c214763d5e1847a6ad5d54127a399ab07ee3599",
        "09738cbc8c7764dd63206892eca29fbc3a67f7fe44ded6b128a0350426776ea71d0c9a1b6d627e1e3d014837dd82f11a",
    );
}

#[test]
#[parallel]
fn test_idea_ecb() {
    do_cipher_test_legacy(
        EncAlg::IdeaEcb,
        "80000000000000000000000000000000",
        None,
        "0000000000000000",
        "B1F5F7F87901370F",
    );
}
