// Copyright 2025 Simo sorce
// See LICENSE.txt file for terms

use crate::ffdh_groups::*;
use crate::kasn1::{pkcs, DerEncBigUint};
use crate::tests::*;
use asn1;

use serial_test::parallel;

#[test]
#[parallel]
fn test_ffdh_generate() {
    let mut testtokn = TestToken::initialized("test_ffdh_generate", None);

    let session = testtokn.get_session(true);

    /* login */
    testtokn.login();

    let (pubkey1, privkey1) = ret_or_panic!(generate_key_pair(
        session,
        CKM_DH_PKCS_KEY_PAIR_GEN,
        &[(CKA_CLASS, CKO_PUBLIC_KEY), (CKA_KEY_TYPE, CKK_DH),],
        &[(CKA_PRIME, &FFDHE2048_P), (CKA_BASE, &GENERATOR2),],
        &[(CKA_DERIVE, true)],
        &[(CKA_CLASS, CKO_PRIVATE_KEY), (CKA_KEY_TYPE, CKK_DH),],
        &[],
        &[(CKA_DERIVE, true)],
    ));

    let (pubkey2, privkey2) = ret_or_panic!(generate_key_pair(
        session,
        CKM_DH_PKCS_KEY_PAIR_GEN,
        &[(CKA_CLASS, CKO_PUBLIC_KEY), (CKA_KEY_TYPE, CKK_DH),],
        &[(CKA_PRIME, &FFDHE2048_P), (CKA_BASE, &GENERATOR2),],
        &[(CKA_DERIVE, true)],
        &[(CKA_CLASS, CKO_PRIVATE_KEY), (CKA_KEY_TYPE, CKK_DH),],
        &[],
        &[(CKA_DERIVE, true)],
    ));

    let derive_template = make_attr_template(
        &[
            (CKA_CLASS, CKO_SECRET_KEY),
            (CKA_KEY_TYPE, CKK_GENERIC_SECRET),
        ],
        &[],
        &[
            (CKA_ENCRYPT, true),
            (CKA_DECRYPT, true),
            (CKA_SENSITIVE, false),
            (CKA_EXTRACTABLE, true),
        ],
    );

    /* Derive Side 1 */
    let mut peerpub = vec![0u8; FFDHE2048_P.len()];
    let mut extract_template = make_ptrs_template(&[(
        CKA_VALUE,
        void_ptr!(peerpub.as_mut_ptr()),
        peerpub.len(),
    )]);

    let ret = fn_get_attribute_value(
        session,
        pubkey2,
        extract_template.as_mut_ptr(),
        extract_template.len() as CK_ULONG,
    );
    assert_eq!(ret, CKR_OK);
    peerpub.resize(extract_template[0].ulValueLen as usize, 0);

    let mut mechanism: CK_MECHANISM = CK_MECHANISM {
        mechanism: CKM_DH_PKCS_DERIVE,
        pParameter: void_ptr!(peerpub.as_ptr()),
        ulParameterLen: peerpub.len() as CK_ULONG,
    };

    let mut secret1 = CK_INVALID_HANDLE;
    let ret = fn_derive_key(
        session,
        &mut mechanism,
        privkey1,
        derive_template.as_ptr() as *mut _,
        derive_template.len() as CK_ULONG,
        &mut secret1,
    );
    assert_eq!(ret, CKR_OK);

    /* Derive Side 2 */
    let mut peerpub = vec![0u8; FFDHE2048_P.len()];
    let mut extract_template = make_ptrs_template(&[(
        CKA_VALUE,
        void_ptr!(peerpub.as_mut_ptr()),
        peerpub.len(),
    )]);

    let ret = fn_get_attribute_value(
        session,
        pubkey1,
        extract_template.as_mut_ptr(),
        extract_template.len() as CK_ULONG,
    );
    assert_eq!(ret, CKR_OK);
    peerpub.resize(extract_template[0].ulValueLen as usize, 0);

    let mut mechanism: CK_MECHANISM = CK_MECHANISM {
        mechanism: CKM_DH_PKCS_DERIVE,
        pParameter: void_ptr!(peerpub.as_ptr()),
        ulParameterLen: peerpub.len() as CK_ULONG,
    };

    let mut secret2 = CK_INVALID_HANDLE;
    let ret = fn_derive_key(
        session,
        &mut mechanism,
        privkey2,
        derive_template.as_ptr() as *mut _,
        derive_template.len() as CK_ULONG,
        &mut secret2,
    );
    assert_eq!(ret, CKR_OK);

    /* Compare results */
    let mut value1 = vec![0u8; FFDHE2048_P.len()];
    let mut extract_template = make_ptrs_template(&[(
        CKA_VALUE,
        void_ptr!(value1.as_mut_ptr()),
        value1.len(),
    )]);

    let ret = fn_get_attribute_value(
        session,
        secret1,
        extract_template.as_mut_ptr(),
        extract_template.len() as CK_ULONG,
    );
    assert_eq!(ret, CKR_OK);
    value1.resize(extract_template[0].ulValueLen as usize, 0);

    let mut value2 = vec![0u8; FFDHE2048_P.len()];
    let mut extract_template = make_ptrs_template(&[(
        CKA_VALUE,
        void_ptr!(value2.as_mut_ptr()),
        value2.len(),
    )]);

    let ret = fn_get_attribute_value(
        session,
        secret2,
        extract_template.as_mut_ptr(),
        extract_template.len() as CK_ULONG,
    );
    assert_eq!(ret, CKR_OK);
    value2.resize(extract_template[0].ulValueLen as usize, 0);

    assert_eq!(value1, value2);
}

#[test]
#[parallel]
fn test_ffdh_derive() {
    let mut testtokn = TestToken::initialized("test_ffdh_derive", None);

    let session = testtokn.get_session(true);

    /* login */
    testtokn.login();

    /* First test from:
     * https://github.com/usnistgov/ACVP-Server/blob/master/gen-val/json-files/KAS-FFC-SSC-Sp800-56Ar3/prompt.json
     */
    let privkey = hex::decode(
        "78502F2AF8969B51D50D2756BAA5EF936FA735B2B2F8423E00D347FF6FB078F1\
         4BFA8B2A01A4CBF700C4861A7C65C7EFA026B6AAA7A60B944B09364D29AC3A9C\
         10F6066AA0BB0115BA15E3934A6C9E981B5732E03A32FC23B3B320089F4EA6CF\
         B31C6C7107E99C3063751238D21352BE40B602F94131D9C2D26E3444437D58ED\
         0793D48ACC50749235F26B66837923750E5801F91ED3584A585A0FB213142312\
         A438BE35A309D87009C30F40D49D2ED554F9D6BCBE84F54AB6382E7425FCADAE\
         D9D11909FA4624647B963605BC68896A34DA5C7F20447AD19C3381F87F40DC63\
         969855A50E92D4448E432189697F7CAB4191D2B1756BB01FF62D4CA1661F6A33",
    )
    .expect("Failed to decode Private FFDHE2048 Key value");

    let priv_handle = ret_or_panic!(import_object(
        session,
        CKO_PRIVATE_KEY,
        &[(CKA_KEY_TYPE, CKK_DH),],
        &[
            (CKA_PRIME, &FFDHE2048_P),
            (CKA_BASE, &GENERATOR2),
            (CKA_VALUE, &privkey),
            (CKA_LABEL, format!("FFDHE2048 private key").as_bytes()),
        ],
        &[(CKA_DERIVE, true)],
    ));

    let peerpub = hex::decode(
        "5FA0CB4D5A976B11442FFDA4569FFF10058E41988C78D0AB6E39B2E226EEFB7C\
         13B9FD65720940118134762CD1ADE1EA83AF64548D8C8BFFA564C8747860FF81\
         6AE9C6F137979FA7C2A4D3E12A3DE68986B43F14CC808E61FAEBAF702FF52379\
         5459CFCD19F83563F25EFC0E57277512FAA8FA23CEF3C8F1D517ABED113FECEE\
         21D926D96BA52A716B5FCDF187D1ACD999A9CFA951311A042C55C693B20B0DDD\
         98C2F2BBEF67E77FD9E18F0D52045E0B424ED3ECBBD2F34E008FD5C7B482B99C\
         ED2A7963DFCA54C5EF9E1FB56F4450B7312CF389D66A696479A6BFEE031D2ECE\
         D27969A4061E73331C63B6F21BD7D6E8358FF052F871DE595DFD57752016D1CA",
    )
    .expect("Failed to decode Peer Public FFDHE2048 Key value");

    let shared_secret = hex::decode(
        "024E9786943F8AA48E0FC7B2862D620A6DDA720F7CEFB53A38D8DEDC8D8E2973\
         7BA62A2E4D04B7E64B2B23396497FBDE5FE803437199C1703C6DA3ED9867FCB3\
         58EFD5B98B8B077E608F39DFBF574A89AA5521F78856E04D05E02B525928C437\
         DF2E2AD5D45B0E6E3C5D656CE2434D4D8BB4DCD11496C30615EB1970CA3DE407\
         23518D79E8ED1A07BE59C486134E5075367A74CF1F9DCBFB85BA36E643D4915C\
         481B3129BD6988CB2E7BE441DA257C924C34B431CE048F8F7BC21B601F51D1EA\
         009C77D3E10F3A59196ED40EE2D80699970F76EEC65142617CF427F1386566FD\
         CE92FBA5FE734071B504EED601797589BF7C7F9EAD508A7B5B4915DD477009E1",
    )
    .expect("Failed to decode Shared Secret value");

    let derive_template = make_attr_template(
        &[
            (CKA_CLASS, CKO_SECRET_KEY),
            (CKA_KEY_TYPE, CKK_GENERIC_SECRET),
        ],
        &[],
        &[
            (CKA_ENCRYPT, true),
            (CKA_DECRYPT, true),
            (CKA_SENSITIVE, false),
            (CKA_EXTRACTABLE, true),
        ],
    );

    let mut mechanism: CK_MECHANISM = CK_MECHANISM {
        mechanism: CKM_DH_PKCS_DERIVE,
        pParameter: void_ptr!(peerpub.as_ptr()),
        ulParameterLen: peerpub.len() as CK_ULONG,
    };

    let mut s_handle = CK_INVALID_HANDLE;
    let ret = fn_derive_key(
        session,
        &mut mechanism,
        priv_handle,
        derive_template.as_ptr() as *mut _,
        derive_template.len() as CK_ULONG,
        &mut s_handle,
    );
    assert_eq!(ret, CKR_OK);

    let mut value = vec![0u8; shared_secret.len()];
    let mut extract_template = make_ptrs_template(&[(
        CKA_VALUE,
        void_ptr!(value.as_mut_ptr()),
        value.len(),
    )]);

    let ret = fn_get_attribute_value(
        session,
        s_handle,
        extract_template.as_mut_ptr(),
        extract_template.len() as CK_ULONG,
    );
    assert_eq!(ret, CKR_OK);
    assert_eq!(value, shared_secret);
}

#[test]
#[parallel]
fn test_ffdh_public_key_info() {
    let mut testtokn =
        TestToken::initialized("test_ffdh_public_key_info", None);
    let session = testtokn.get_session(true);

    /* login */
    testtokn.login();

    /* generate key pair and store it */
    let (hpub, hpri) = ret_or_panic!(generate_key_pair(
        session,
        CKM_DH_PKCS_KEY_PAIR_GEN,
        &[(CKA_CLASS, CKO_PUBLIC_KEY), (CKA_KEY_TYPE, CKK_DH),],
        &[(CKA_PRIME, &FFDHE2048_P), (CKA_BASE, &GENERATOR2),],
        &[(CKA_TOKEN, false)],
        &[(CKA_CLASS, CKO_PRIVATE_KEY), (CKA_KEY_TYPE, CKK_DH),],
        &[],
        &[
            (CKA_TOKEN, false),
            (CKA_PRIVATE, true),
            (CKA_SENSITIVE, false), // Not sensitive to allow extracting components
            (CKA_EXTRACTABLE, true),
        ],
    ));

    // Check generated keys
    let pub_key_info =
        ret_or_panic!(extract_value(session, hpub, CKA_PUBLIC_KEY_INFO));
    assert!(!pub_key_info.is_empty());

    let pri_key_info =
        ret_or_panic!(extract_value(session, hpri, CKA_PUBLIC_KEY_INFO));
    assert!(!pri_key_info.is_empty());
    assert_eq!(pub_key_info, pri_key_info);

    // Verify content of CKA_PUBLIC_KEY_INFO
    let y = ret_or_panic!(extract_value(session, hpub, CKA_VALUE));

    let (p, g, q) =
        ffdh_groups::group_values(ffdh_groups::DHGroupName::FFDHE2048).unwrap();

    let p_der = DerEncBigUint::new(p).unwrap();
    let g_der = DerEncBigUint::new(g).unwrap();
    let q_der = DerEncBigUint::new(q).unwrap();

    let dhx_params = pkcs::DHXParams {
        p: asn1::BigUint::new(p_der.as_bytes()).unwrap(),
        g: asn1::BigUint::new(g_der.as_bytes()).unwrap(),
        q: asn1::BigUint::new(q_der.as_bytes()).unwrap(),
        j: None,
        validation_params: None,
    };

    let alg = pkcs::AlgorithmIdentifier {
        oid: asn1::DefinedByMarker::marker(),
        params: pkcs::AlgorithmParameters::Dh(dhx_params),
    };

    let y_der = asn1::write_single(&DerEncBigUint::new(&y).unwrap()).unwrap();

    let spki = pkcs::SubjectPublicKeyInfo {
        algorithm: alg,
        subject_public_key: asn1::BitString::new(&y_der, 0).unwrap(),
    };
    let spki_der = asn1::write_single(&spki).unwrap();
    assert_eq!(pub_key_info, spki_der);

    // Check imported public key
    let imported_hpub = ret_or_panic!(import_object(
        session,
        CKO_PUBLIC_KEY,
        &[(CKA_KEY_TYPE, CKK_DH)],
        &[
            (CKA_PRIME, &FFDHE2048_P),
            (CKA_BASE, &GENERATOR2),
            (CKA_VALUE, &y),
        ],
        &[],
    ));
    let imported_pub_key_info = ret_or_panic!(extract_value(
        session,
        imported_hpub,
        CKA_PUBLIC_KEY_INFO
    ));
    assert_eq!(imported_pub_key_info, spki_der);

    testtokn.finalize();
}
