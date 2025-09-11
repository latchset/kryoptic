// Copyright 2025 Simo Sorce
// See LICENSE.txt file for terms

use hex;
use serial_test::parallel;

use crate::derive::EcdhDerive;
use crate::pkey::{EccData, EvpPkey, EvpPkeyType, PkeyData};
use crate::tests::test_ossl_context;
use crate::OsslSecret;

fn do_ecdh_test(
    pkey_type: EvpPkeyType,
    da_hex: &str,
    xa_hex: &str,
    ya_hex: &str,
    db_hex: &str,
    xb_hex: &str,
    yb_hex: &str,
    z_hex: &str,
) {
    let da = hex::decode(da_hex).unwrap();
    let xa = hex::decode(xa_hex).unwrap();
    let ya = hex::decode(ya_hex).unwrap();
    let db = hex::decode(db_hex).unwrap();
    let xb = hex::decode(xb_hex).unwrap();
    let yb = hex::decode(yb_hex).unwrap();
    let expected_z = hex::decode(z_hex).unwrap();

    let mut pub_a_uncompressed = vec![0x04];
    pub_a_uncompressed.extend_from_slice(&xa);
    pub_a_uncompressed.extend_from_slice(&ya);

    let mut pub_b_uncompressed = vec![0x04];
    pub_b_uncompressed.extend_from_slice(&xb);
    pub_b_uncompressed.extend_from_slice(&yb);

    // --- A derives from B's public key ---
    let mut key_a = EvpPkey::import(
        test_ossl_context(),
        pkey_type.clone(),
        PkeyData::Ecc(EccData {
            pubkey: None,
            prikey: Some(OsslSecret::from_slice(&da)),
        }),
    )
    .unwrap();

    let mut peer_b = key_a
        .make_peer(test_ossl_context(), &pub_b_uncompressed)
        .unwrap();
    let mut ecdh_a = EcdhDerive::new(test_ossl_context(), &mut key_a).unwrap();
    let mut shared_secret_a = vec![0u8; expected_z.len()];
    let len_a = ecdh_a.derive(&mut peer_b, &mut shared_secret_a).unwrap();

    assert_eq!(len_a, expected_z.len());
    assert_eq!(shared_secret_a, expected_z);

    // --- B derives from A's public key (symmetry check) ---
    let mut key_b = EvpPkey::import(
        test_ossl_context(),
        pkey_type.clone(),
        PkeyData::Ecc(EccData {
            pubkey: None,
            prikey: Some(OsslSecret::from_slice(&db)),
        }),
    )
    .unwrap();

    let mut peer_a = key_b
        .make_peer(test_ossl_context(), &pub_a_uncompressed)
        .unwrap();
    let mut ecdh_b = EcdhDerive::new(test_ossl_context(), &mut key_b).unwrap();
    let mut shared_secret_b = vec![0u8; expected_z.len()];
    let len_b = ecdh_b.derive(&mut peer_a, &mut shared_secret_b).unwrap();

    assert_eq!(len_b, expected_z.len());
    assert_eq!(shared_secret_b, expected_z);
    assert_eq!(shared_secret_a, shared_secret_b);
}

#[test]
#[parallel]
fn test_ecdh_brainpool_p256r1() {
    /* test vectors from https://www.rfc-editor.org/rfc/rfc8734#appendix-A.1 */
    let da_hex =
        "81DB1EE100150FF2EA338D708271BE38300CB54241D79950F77B063039804F1D";
    let xa_hex =
        "44106E913F92BC02A1705D9953A8414DB95E1AAA49E81D9E85F929A8E3100BE5";
    let ya_hex =
        "8AB4846F11CACCB73CE49CBDD120F5A900A69FD32C272223F789EF10EB089BDC";
    let db_hex =
        "55E40BC41E37E3E2AD25C3C6654511FFA8474A91A0032087593852D3E7D76BD3";
    let xb_hex =
        "8D2D688C6CF93E1160AD04CC4429117DC2C41825E1E9FCA0ADDD34E6F1B39F7B";
    let yb_hex =
        "990C57520812BE512641E47034832106BC7D3E8DD0E4C7F1136D7006547CEC6A";
    let z_hex =
        "89AFC39D41D3B327814B80940B042590F96556EC91E6AE7939BCE31F3A18BF2B";

    do_ecdh_test(
        EvpPkeyType::BrainpoolP256r1,
        da_hex,
        xa_hex,
        ya_hex,
        db_hex,
        xb_hex,
        yb_hex,
        z_hex,
    );
}

#[test]
#[parallel]
fn test_ecdh_brainpool_p384r1() {
    /* test vectors from https://www.rfc-editor.org/rfc/rfc8734#appendix-A.2 */
    let da_hex =
        "1E20F5E048A5886F1F157C74E91BDE2B98C8B52D58E5003D57053FC4B0BD65D6\
         F15EB5D1EE1610DF870795143627D042";
    let xa_hex =
        "68B665DD91C195800650CDD363C625F4E742E8134667B767B1B476793588F885\
         AB698C852D4A6E77A252D6380FCAF068";
    let ya_hex =
        "55BC91A39C9EC01DEE36017B7D673A931236D2F1F5C83942D049E3FA20607493\
         E0D038FF2FD30C2AB67D15C85F7FAA59";
    let db_hex =
        "032640BC6003C59260F7250C3DB58CE647F98E1260ACCE4ACDA3DD869F74E01F\
         8BA5E0324309DB6A9831497ABAC96670";
    let xb_hex =
        "4D44326F269A597A5B58BBA565DA5556ED7FD9A8A9EB76C25F46DB69D19DC8CE\
         6AD18E404B15738B2086DF37E71D1EB4";
    let yb_hex =
        "62D692136DE56CBE93BF5FA3188EF58BC8A3A0EC6C1E151A21038A42E9185329\
         B5B275903D192F8D4E1F32FE9CC78C48";
    let z_hex =
        "0BD9D3A7EA0B3D519D09D8E48D0785FB744A6B355E6304BC51C229FBBCE239BB\
         ADF6403715C35D4FB2A5444F575D4F42";

    do_ecdh_test(
        EvpPkeyType::BrainpoolP384r1,
        da_hex,
        xa_hex,
        ya_hex,
        db_hex,
        xb_hex,
        yb_hex,
        z_hex,
    );
}

#[test]
#[parallel]
fn test_ecdh_brainpool_p512r1() {
    /* test vectors from https://www.rfc-editor.org/rfc/rfc8734#appendix-A.3 */
    let da_hex =
        "16302FF0DBBB5A8D733DAB7141C1B45ACBC8715939677F6A56850A38BD87BD59\
         B09E80279609FF333EB9D4C061231FB26F92EEB04982A5F1D1764CAD57665422";
    let xa_hex =
        "0A420517E406AAC0ACDCE90FCD71487718D3B953EFD7FBEC5F7F27E28C614999\
         9397E91E029E06457DB2D3E640668B392C2A7E737A7F0BF04436D11640FD09FD";
    let ya_hex =
        "72E6882E8DB28AAD36237CD25D580DB23783961C8DC52DFA2EC138AD472A0FCE\
         F3887CF62B623B2A87DE5C588301EA3E5FC269B373B60724F5E82A6AD147FDE7";
    let db_hex =
        "230E18E1BCC88A362FA54E4EA3902009292F7F8033624FD471B5D8ACE49D12CF\
         ABBC19963DAB8E2F1EBA00BFFB29E4D72D13F2224562F405CB80503666B25429";
    let xb_hex =
        "9D45F66DE5D67E2E6DB6E93A59CE0BB48106097FF78A081DE781CDB31FCE8CCB\
         AAEA8DD4320C4119F1E9CD437A2EAB3731FA9668AB268D871DEDA55A5473199F";
    let yb_hex =
        "2FDC313095BCDD5FB3A91636F07A959C8E86B5636A1E930E8396049CB481961D\
         365CC11453A06C719835475B12CB52FC3C383BCE35E27EF194512B71876285FA";
    let z_hex =
        "A7927098655F1F9976FA50A9D566865DC530331846381C87256BAF3226244B76\
         D36403C024D7BBF0AA0803EAFF405D3D24F11A9B5C0BEF679FE1454B21C4CD1F";

    do_ecdh_test(
        EvpPkeyType::BrainpoolP512r1,
        da_hex,
        xa_hex,
        ya_hex,
        db_hex,
        xb_hex,
        yb_hex,
        z_hex,
    );
}

use crate::signature::{OsslSignature, SigAlg, SigOp};

#[test]
#[parallel]
fn test_brainpool_p256r1_signature() {
    // Generate a key pair
    let mut key =
        EvpPkey::generate(test_ossl_context(), EvpPkeyType::BrainpoolP256r1)
            .unwrap();

    // Sample data to sign. Use ECDSA without a pre-computed digest.
    let data = b"some sample data to sign";

    // --- Sign ---
    let mut signer = OsslSignature::new(
        test_ossl_context(),
        SigOp::Sign,
        SigAlg::Ecdsa,
        &mut key,
        None,
    )
    .unwrap();
    let mut signature = vec![0u8; signer.sign(data, None).unwrap()];
    let sig_len = signer.sign(data, Some(&mut signature)).unwrap();
    signature.truncate(sig_len);

    // --- Verify ---
    let mut verifier = OsslSignature::new(
        test_ossl_context(),
        SigOp::Verify,
        SigAlg::Ecdsa,
        &mut key,
        None,
    )
    .unwrap();
    verifier.verify(data, Some(&signature)).unwrap();

    // --- Verify with wrong data should fail ---
    let wrong_data = b"some other data";
    let mut verifier_fail_data = OsslSignature::new(
        test_ossl_context(),
        SigOp::Verify,
        SigAlg::Ecdsa,
        &mut key,
        None,
    )
    .unwrap();
    assert!(verifier_fail_data
        .verify(wrong_data, Some(&signature))
        .is_err());

    // --- Verify with wrong signature should fail ---
    let mut wrong_signature = signature.clone();
    wrong_signature[0] = wrong_signature[0].wrapping_add(1);
    let mut verifier_fail_sig = OsslSignature::new(
        test_ossl_context(),
        SigOp::Verify,
        SigAlg::Ecdsa,
        &mut key,
        None,
    )
    .unwrap();
    assert!(verifier_fail_sig
        .verify(data, Some(&wrong_signature))
        .is_err());
}
