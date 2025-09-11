// Copyright 2025 Jakub Jelen
// See LICENSE.txt file for terms

use hex;
use serial_test::parallel;

use crate::digest::{DigestAlg, OsslDigest};
use crate::pkey::{DsaData, EvpPkey, EvpPkeyType, PkeyData};
use crate::signature::{OsslSignature, SigAlg, SigOp};
use crate::tests::test_ossl_context;
use crate::OsslSecret;

fn do_dsa_test(
    pkey_type: EvpPkeyType,
    p_hex: &str,
    q_hex: &str,
    g_hex: &str,
    x_hex: &str,
    y_hex: &str,
    hash: DigestAlg,
    r_hex: &str,
    s_hex: &str,
) {
    let p = hex::decode(p_hex).unwrap();
    let q = hex::decode(q_hex).unwrap();
    let g = hex::decode(g_hex).unwrap();
    let x = hex::decode(x_hex).unwrap();
    let y = hex::decode(y_hex).unwrap();

    let r = hex::decode(r_hex).unwrap();
    let s = hex::decode(s_hex).unwrap();

    // --- Import private key ---
    let mut privkey = EvpPkey::import(
        test_ossl_context(),
        pkey_type.clone(),
        PkeyData::Dsa(DsaData {
            p: p.clone(),
            q: q.clone(),
            g: g.clone(),
            priv_key: Some(OsslSecret::from_slice(&x)),
            pub_key: y.clone(),
        }),
    )
    .unwrap();

    // --- Import public key ---
    let mut pubkey = EvpPkey::import(
        test_ossl_context(),
        pkey_type.clone(),
        PkeyData::Dsa(DsaData {
            p: p,
            q: q,
            g: g,
            priv_key: None,
            pub_key: y,
        }),
    )
    .unwrap();

    // --- Digest the input message of a test vector ---
    let mut digest = [0; 64];
    let mut dctx = OsslDigest::new(test_ossl_context(), hash, None).unwrap();
    dctx.update(b"sample").unwrap();
    dctx.finalize(&mut digest).unwrap();

    // --- Sign the digest ---
    let mut signer = OsslSignature::new(
        test_ossl_context(),
        SigOp::Sign,
        SigAlg::Dsa,
        &mut privkey,
        None,
    )
    .unwrap();
    let sig_len = signer.sign(&digest, None).unwrap();
    let mut signature = vec![0u8; sig_len];
    let sig_len = signer.sign(&digest, Some(&mut signature)).unwrap();
    signature.truncate(sig_len);

    // --- Verify the produced signature with public key ---
    let mut verifier = OsslSignature::new(
        test_ossl_context(),
        SigOp::Verify,
        SigAlg::Dsa,
        &mut pubkey,
        None,
    )
    .unwrap();
    verifier.verify(&digest, Some(&signature)).unwrap();

    // --- Verify the signature from test vector ---
    // The Signature needs to be ASN.1 encoded in the sequence as defined in
    // https://datatracker.ietf.org/doc/html/rfc3279#section-2.2.2
    let mut signature: Vec<u8> = Vec::with_capacity(128);
    let taglen = 2 + r.len() + 2 + s.len();
    signature.extend_from_slice(&[0x30, taglen as u8]);
    signature.extend_from_slice(&[0x02, r.len() as u8]);
    signature.extend_from_slice(&r);
    signature.extend_from_slice(&[0x02, s.len() as u8]);
    signature.extend_from_slice(&s);
    let mut verifier = OsslSignature::new(
        test_ossl_context(),
        SigOp::Verify,
        SigAlg::Dsa,
        &mut pubkey,
        None,
    )
    .unwrap();
    verifier.verify(&digest, Some(&signature)).unwrap();
}

#[test]
#[parallel]
fn test_dsa_2k() {
    /* test vectors from https://www.ietf.org/rfc/rfc6979.txt */
    let p_hex =
        "9DB6FB5951B66BB6FE1E140F1D2CE5502374161FD6538DF1648218642F0B5C48\
         C8F7A41AADFA187324B87674FA1822B00F1ECF8136943D7C55757264E5A1A44F\
         FE012E9936E00C1D3E9310B01C7D179805D3058B2A9F4BB6F9716BFE6117C6B5\
         B3CC4D9BE341104AD4A80AD6C94E005F4B993E14F091EB51743BF33050C38DE2\
         35567E1B34C3D6A5C0CEAA1A0F368213C3D19843D0B4B09DCB9FC72D39C8DE41\
         F1BF14D4BB4563CA28371621CAD3324B6A2D392145BEBFAC748805236F5CA2FE\
         92B871CD8F9C36D3292B5509CA8CAA77A2ADFC7BFD77DDA6F71125A7456FEA15\
         3E433256A2261C6A06ED3693797E7995FAD5AABBCFBE3EDA2741E375404AE25B";
    let q_hex =
        "F2C3119374CE76C9356990B465374A17F23F9ED35089BD969F61C6DDE9998C1F";
    let g_hex =
        "5C7FF6B06F8F143FE8288433493E4769C4D988ACE5BE25A0E24809670716C613\
         D7B0CEE6932F8FAA7C44D2CB24523DA53FBE4F6EC3595892D1AA58C4328A06C4\
         6A15662E7EAA703A1DECF8BBB2D05DBE2EB956C142A338661D10461C0D135472\
         085057F3494309FFA73C611F78B32ADBB5740C361C9F35BE90997DB2014E2EF5\
         AA61782F52ABEB8BD6432C4DD097BC5423B285DAFB60DC364E8161F4A2A35ACA\
         3A10B1C4D203CC76A470A33AFDCBDD92959859ABD8B56E1725252D78EAC66E71\
         BA9AE3F1DD2487199874393CD4D832186800654760E1E34C09E4D155179F9EC0\
         DC4473F996BDCE6EED1CABED8B6F116F7AD9CF505DF0F998E34AB27514B0FFE7";
    let x_hex =
        "69C7548C21D0DFEA6B9A51C9EAD4E27C33D3B3F180316E5BCAB92C933F0E4DBC";
    let y_hex =
        "667098C654426C78D7F8201EAC6C203EF030D43605032C2F1FA937E5237DBD94\
         9F34A0A2564FE126DC8B715C5141802CE0979C8246463C40E6B6BDAA2513FA61\
         1728716C2E4FD53BC95B89E69949D96512E873B9C8F8DFD499CC312882561ADE\
         CB31F658E934C0C197F2C4D96B05CBAD67381E7B768891E4DA3843D24D94CDFB\
         5126E9B8BF21E8358EE0E0A30EF13FD6A664C0DCE3731F7FB49A4845A4FD8254\
         687972A2D382599C9BAC4E0ED7998193078913032558134976410B89D2C171D1\
         23AC35FD977219597AA7D15C1A9A428E59194F75C721EBCBCFAE44696A499AFA\
         74E04299F132026601638CB87AB79190D4A0986315DA8EEC6561C938996BEADF";

    let hash = DigestAlg::Sha2_512;
    let r_hex =
        "2016ED092DC5FB669B8EFB3D1F31A91EECB199879BE0CF78F02BA062CB4C942E";
    // adjusted with leading 0x00 byte to make sure it is not interpretted as negative number
    let s_hex =
        "00D0C76F84B5F091E141572A639A4FB8C230807EEA7D55C8A154A224400AFF2351";

    do_dsa_test(
        EvpPkeyType::Dsa(2048),
        p_hex,
        q_hex,
        g_hex,
        x_hex,
        y_hex,
        hash,
        r_hex,
        s_hex,
    );
}

#[test]
#[parallel]
fn test_dsa_1k() {
    /* test vectors from https://www.ietf.org/rfc/rfc6979.txt */
    let p_hex =
        "86F5CA03DCFEB225063FF830A0C769B9DD9D6153AD91D7CE27F787C43278B447\
         E6533B86B18BED6E8A48B784A14C252C5BE0DBF60B86D6385BD2F12FB763ED88\
         73ABFD3F5BA2E0A8C0A59082EAC056935E529DAF7C610467899C77ADEDFC846C\
         881870B7B19B2B58F9BE0521A17002E3BDD6B86685EE90B3D9A1B02B782B1779";
    let q_hex = "996F967F6C8E388D9E28D01E205FBA957A5698B1";
    let g_hex =
        "07B0F92546150B62514BB771E2A0C0CE387F03BDA6C56B505209FF25FD3C133D\
         89BBCD97E904E09114D9A7DEFDEADFC9078EA544D2E401AEECC40BB9FBBF78FD\
         87995A10A1C27CB7789B594BA7EFB5C4326A9FE59A070E136DB77175464ADCA4\
         17BE5DCE2F40D10A46A3A3943F26AB7FD9C0398FF8C76EE0A56826A8A88F1DBD";
    let x_hex = "411602CB19A6CCC34494D79D98EF1E7ED5AF25F7";
    let y_hex =
        "5DF5E01DED31D0297E274E1691C192FE5868FEF9E19A84776454B100CF16F653\
         92195A38B90523E2542EE61871C0440CB87C322FC4B4D2EC5E1E7EC766E1BE8D\
         4CE935437DC11C3C8FD426338933EBFE739CB3465F4D3668C5E473508253B1E6\
         82F65CBDC4FAE93C2EA212390E54905A86E2223170B44EAA7DA5DD9FFCFB7F3B";

    let hash = DigestAlg::Sha2_256;
    // adjusted with leading 0x00 byte to make sure it is not interpretted as negative number
    let r_hex = "0081F2F5850BE5BC123C43F71A3033E9384611C545";
    let s_hex = "4CDD914B65EB6C66A8AAAD27299BEE6B035F5E89";

    do_dsa_test(
        EvpPkeyType::Dsa(1024),
        p_hex,
        q_hex,
        g_hex,
        x_hex,
        y_hex,
        hash,
        r_hex,
        s_hex,
    );
}

#[test]
#[parallel]
fn test_dsa_generate() {
    // Generate a key pair
    let mut key =
        EvpPkey::generate(test_ossl_context(), EvpPkeyType::Dsa(3072)).unwrap();

    // Sample data to sign.
    let data = b"some sample data to sign";

    // --- Digest the input message of a test vector ---
    let mut digest = [0; 64];
    let mut dctx =
        OsslDigest::new(test_ossl_context(), DigestAlg::Sha2_384, None)
            .unwrap();
    dctx.update(data).unwrap();
    dctx.finalize(&mut digest).unwrap();

    // --- Sign ---
    let mut signer = OsslSignature::new(
        test_ossl_context(),
        SigOp::Sign,
        SigAlg::Dsa,
        &mut key,
        None,
    )
    .unwrap();
    let mut signature = vec![0u8; signer.sign(&digest, None).unwrap()];
    let sig_len = signer.sign(&digest, Some(&mut signature)).unwrap();
    signature.truncate(sig_len);

    // --- Verify ---
    let mut verifier = OsslSignature::new(
        test_ossl_context(),
        SigOp::Verify,
        SigAlg::Dsa,
        &mut key,
        None,
    )
    .unwrap();
    verifier.verify(&digest, Some(&signature)).unwrap();

    // --- Verify with wrong data should fail ---
    let wrong_data = b"some other data";
    let mut verifier_fail_data = OsslSignature::new(
        test_ossl_context(),
        SigOp::Verify,
        SigAlg::Dsa,
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
        SigAlg::Dsa,
        &mut key,
        None,
    )
    .unwrap();
    assert!(verifier_fail_sig
        .verify(data, Some(&wrong_signature))
        .is_err());
}
