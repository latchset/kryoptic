// Copyright 2024 Simo Sorce, Jakub Jelen
// See LICENSE.txt file for terms

use std::io;
use std::io::BufRead;

use crate::tests::*;

use serial_test::{parallel, serial};

/* TODO enable for FIPS when our OpenSSL will include EdDSA in FIPS module */

#[test]
#[parallel]
fn test_create_eddsa_objects() {
    let mut testtokn =
        TestToken::initialized("test_create_eddsa_objects", None);
    let session = testtokn.get_session(true);

    /* login */
    testtokn.login();

    /* Test Vectors for Ed25519ctx */
    let point = hex::decode(
        "dfc9425e4f968f7f0c29f0259cf5f9aed6851c2bb4ad8bfb860cfee0ab248292",
    )
    .expect("Failed to decode hex point");
    let params = hex::decode("130c656477617264733235353139")
        .expect("Failed to decode hex params");
    let public_handle = ret_or_panic!(import_object(
        session,
        CKO_PUBLIC_KEY,
        &[(CKA_KEY_TYPE, CKK_EC_EDWARDS)],
        &[
            (CKA_LABEL, "Ed25519 Public Signature Key".as_bytes()),
            (CKA_EC_POINT, point.as_slice()),
            (CKA_EC_PARAMS, params.as_slice()),
        ],
        &[(CKA_VERIFY, true)]
    ));

    /* Private EC key */
    let value = hex::decode(
        "0305334e381af78f141cb666f6199f57bc3495335a256a95bd2a55bf546663f6",
    )
    .expect("Failed to decode value");
    let private_handle = ret_or_panic!(import_object(
        session,
        CKO_PRIVATE_KEY,
        &[(CKA_KEY_TYPE, CKK_EC_EDWARDS)],
        &[
            (CKA_LABEL, "Ed25519 Private Signature Key".as_bytes()),
            (CKA_VALUE, value.as_slice()),
            (CKA_EC_PARAMS, params.as_slice()),
        ],
        &[(CKA_SIGN, true)]
    ));

    let ctx = hex::decode("666f6f").expect("Failed to decode context");

    let params: CK_EDDSA_PARAMS = CK_EDDSA_PARAMS {
        phFlag: CK_FALSE,
        pContextData: ctx.as_ptr() as *mut CK_BYTE,
        ulContextDataLen: ctx.len() as CK_ULONG,
    };
    let mut mechanism: CK_MECHANISM = CK_MECHANISM {
        mechanism: CKM_EDDSA,
        pParameter: void_ptr!(&params),
        ulParameterLen: sizeof!(CK_EDDSA_PARAMS),
    };
    let ret = fn_sign_init(session, &mut mechanism, private_handle);
    assert_eq!(ret, CKR_OK);

    let data = hex::decode("f726936d19c800494e3fdaff20b276a8")
        .expect("Failed to decode data");
    let sign: [u8; 64] = [0; 64];
    let mut sign_len: CK_ULONG = 64;
    let ret = fn_sign(
        session,
        data.as_ptr() as *mut u8,
        data.len() as CK_ULONG,
        sign.as_ptr() as *mut _,
        &mut sign_len,
    );
    assert_eq!(ret, CKR_OK);
    assert_eq!(sign_len, 64);
    let signature = hex::decode(
        "55a4cc2f70a54e04288c5f4cd1e45a7bb520b36292911876cada7323198dd87a\
         8b36950b95130022907a7fb7c4e9b2d5f6cca685a587b4b21f4b888e4e7edb0d",
    )
    .expect("failed to decode expected signature");
    assert_eq!(signature, sign);

    let ret = fn_verify_init(session, &mut mechanism, public_handle);
    assert_eq!(ret, CKR_OK);

    let ret = fn_verify(
        session,
        data.as_ptr() as *mut u8,
        data.len() as CK_ULONG,
        sign.as_ptr() as *mut u8,
        sign_len,
    );
    assert_eq!(ret, CKR_OK);

    testtokn.finalize();
}

#[test]
#[parallel]
fn test_eddsa_operations() {
    let mut testtokn = TestToken::initialized(
        "test_eddsa_operations",
        Some("testdata/test_eddsa_operations.json"),
    );
    let session = testtokn.get_session(true);

    /* login */
    testtokn.login();

    /* Ed25519 private key */
    let mut handle: CK_ULONG = CK_INVALID_HANDLE;
    let template = make_attr_template(
        &[(CKA_CLASS, CKO_PRIVATE_KEY)],
        &[(CKA_ID, "\x02".as_bytes())],
        &[],
    );
    let ret = fn_find_objects_init(session, template.as_ptr() as *mut _, 2);
    assert_eq!(ret, CKR_OK);
    let mut count: CK_ULONG = 0;
    let ret = fn_find_objects(session, &mut handle, 1, &mut count);
    assert_eq!(ret, CKR_OK);
    assert_eq!(count, 1);
    assert_ne!(handle, CK_INVALID_HANDLE);
    let ret = fn_find_objects_final(session);
    assert_eq!(ret, CKR_OK);

    /* sign init without parameters*/
    let mut mechanism: CK_MECHANISM = CK_MECHANISM {
        mechanism: CKM_EDDSA,
        pParameter: std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    let ret = fn_sign_init(session, &mut mechanism, handle);
    assert_eq!(ret, CKR_OK);

    /* a second invocation should return an error */
    let ret = fn_sign_init(session, &mut mechanism, handle);
    assert_eq!(ret, CKR_OPERATION_ACTIVE);

    /* 2 st Test vector from rfc8032 */
    let data = "\x72";
    let sign: [u8; 64] = [0; 64];
    let mut sign_len: CK_ULONG = 64;
    let ret = fn_sign(
        session,
        CString::new(data).unwrap().into_raw() as *mut u8,
        data.len() as CK_ULONG,
        sign.as_ptr() as *mut _,
        &mut sign_len,
    );
    assert_eq!(ret, CKR_OK);
    assert_eq!(sign_len, 64);

    let signature = hex::decode(
        "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da\
        085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
    )
    .expect("failed to decode expected signature");
    assert_eq!(signature, sign);

    /* a second invocation should return an error */
    let ret = fn_sign(
        session,
        CString::new(data).unwrap().into_raw() as *mut u8,
        data.len() as CK_ULONG,
        sign.as_ptr() as *mut _,
        &mut sign_len,
    );
    assert_eq!(ret, CKR_OPERATION_NOT_INITIALIZED);

    /* test that signature verification works */
    let template = make_attr_template(
        &[(CKA_CLASS, CKO_PUBLIC_KEY)],
        &[(CKA_ID, "\x02".as_bytes())],
        &[],
    );
    let ret = fn_find_objects_init(session, template.as_ptr() as *mut _, 2);
    assert_eq!(ret, CKR_OK);
    let mut count: CK_ULONG = 0;
    let ret = fn_find_objects(session, &mut handle, 1, &mut count);
    assert_eq!(ret, CKR_OK);
    assert_eq!(count, 1);
    assert_ne!(handle, CK_INVALID_HANDLE);
    let ret = fn_find_objects_final(session);
    assert_eq!(ret, CKR_OK);

    let ret = fn_verify_init(session, &mut mechanism, handle);
    assert_eq!(ret, CKR_OK);

    let ret = fn_verify(
        session,
        data.as_ptr() as *mut u8,
        data.len() as CK_ULONG,
        sign.as_ptr() as *mut u8,
        sign_len,
    );
    assert_eq!(ret, CKR_OK);

    /* Ed448 */
    let mut handle: CK_ULONG = CK_INVALID_HANDLE;
    let template = make_attr_template(
        &[(CKA_CLASS, CKO_PRIVATE_KEY)],
        &[(CKA_ID, "\x03".as_bytes())],
        &[],
    );
    let ret = fn_find_objects_init(session, template.as_ptr() as *mut _, 2);
    assert_eq!(ret, CKR_OK);
    let mut count: CK_ULONG = 0;
    let ret = fn_find_objects(session, &mut handle, 1, &mut count);
    assert_eq!(ret, CKR_OK);
    assert_eq!(count, 1);
    assert_ne!(handle, CK_INVALID_HANDLE);
    let ret = fn_find_objects_final(session);
    assert_eq!(ret, CKR_OK);

    /* sign init without parameters fails */
    let mut mechanism: CK_MECHANISM = CK_MECHANISM {
        mechanism: CKM_EDDSA,
        pParameter: std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    let ret = fn_sign_init(session, &mut mechanism, handle);
    assert_eq!(ret, CKR_MECHANISM_PARAM_INVALID);

    /* the ed448 requires params */
    let params: CK_EDDSA_PARAMS = CK_EDDSA_PARAMS {
        phFlag: CK_FALSE,
        pContextData: std::ptr::null_mut(),
        ulContextDataLen: 0,
    };
    let mut mechanism: CK_MECHANISM = CK_MECHANISM {
        mechanism: CKM_EDDSA,
        pParameter: &params as *const _ as CK_VOID_PTR,
        ulParameterLen: sizeof!(CK_EDDSA_PARAMS),
    };
    let ret = fn_sign_init(session, &mut mechanism, handle);
    assert_eq!(ret, CKR_OK);

    /* a second invocation should return an error */
    let ret = fn_sign_init(session, &mut mechanism, handle);
    assert_eq!(ret, CKR_OPERATION_ACTIVE);

    /* 2nd Test vector from rfc8032 for Ed448 */
    let data = "\x03";
    let sign: [u8; 114] = [0; 114];
    let mut sign_len: CK_ULONG = 114;
    let ret = fn_sign(
        session,
        CString::new(data).unwrap().into_raw() as *mut u8,
        data.len() as CK_ULONG,
        sign.as_ptr() as *mut _,
        &mut sign_len,
    );
    assert_eq!(ret, CKR_OK);
    assert_eq!(sign_len, 114);
    let signature = hex::decode(
        "26b8f91727bd62897af15e41eb43c377efb9c610d48f2335cb0bd0087810f435\
         2541b143c4b981b7e18f62de8ccdf633fc1bf037ab7cd779805e0dbcc0aae1cb\
         cee1afb2e027df36bc04dcecbf154336c19f0af7e0a6472905e799f1953d2a0f\
         f3348ab21aa4adafd1d234441cf807c03a00",
    )
    .expect("failed to decode expected signature");
    assert_eq!(signature, sign);

    /* a second invocation should return an error */
    let ret = fn_sign(
        session,
        CString::new(data).unwrap().into_raw() as *mut u8,
        data.len() as CK_ULONG,
        sign.as_ptr() as *mut _,
        &mut sign_len,
    );
    assert_eq!(ret, CKR_OPERATION_NOT_INITIALIZED);

    /* test that signature verification works */
    let template = make_attr_template(
        &[(CKA_CLASS, CKO_PUBLIC_KEY)],
        &[(CKA_ID, "\x03".as_bytes())],
        &[],
    );
    let ret = fn_find_objects_init(session, template.as_ptr() as *mut _, 2);
    assert_eq!(ret, CKR_OK);
    let mut count: CK_ULONG = 0;
    let ret = fn_find_objects(session, &mut handle, 1, &mut count);
    assert_eq!(ret, CKR_OK);
    assert_eq!(count, 1);
    assert_ne!(handle, CK_INVALID_HANDLE);
    let ret = fn_find_objects_final(session);
    assert_eq!(ret, CKR_OK);

    let ret = fn_verify_init(session, &mut mechanism, handle);
    assert_eq!(ret, CKR_OK);

    let ret = fn_verify(
        session,
        data.as_ptr() as *mut u8,
        data.len() as CK_ULONG,
        sign.as_ptr() as *mut u8,
        sign_len,
    );
    assert_eq!(ret, CKR_OK);

    #[cfg(feature = "pkcs11_3_2")]
    {
        /* Re-Verify using the SignatureVerification APIs */
        let ret =
            sig_verifysig(session, handle, data.as_bytes(), &sign, &mechanism);
        assert_eq!(ret, CKR_OK);
    }
}

#[derive(Debug)]
struct EddsaTestUnit {
    line: usize,
    label: String,
    algo: String,
    secret: Vec<u8>,
    public: Vec<u8>,
    message: Vec<u8>,
    context: Vec<u8>,
    signature: Vec<u8>,
}

enum EddsaParserState {
    StateNone,
    StateAlgorithm,
    StateSecret,
    StatePublic,
    StateMessage,
    StateContext,
    StateSignature,
}

fn parse_eddsa_vector(filename: &str) -> Vec<EddsaTestUnit> {
    let file = ret_or_panic!(std::fs::File::open(filename));

    let mut data = Vec::<EddsaTestUnit>::new();
    let mut label = None;

    let mut state = EddsaParserState::StateNone;
    for (l, line) in io::BufReader::new(file).lines().flatten().enumerate() {
        let ln = l + 1;

        if line.len() == 0 {
            continue;
        }
        /* skip these comment lines */
        if line.starts_with("-----") {
            label = Some(line.clone());
            continue;
        }

        match state {
            EddsaParserState::StateNone => {
                if line.starts_with("ALGORITHM:") {
                    state = EddsaParserState::StateAlgorithm;
                }
            }
            EddsaParserState::StateAlgorithm => {
                if line.starts_with("SECRET KEY:") {
                    state = EddsaParserState::StateSecret;
                    continue;
                }

                let unit = EddsaTestUnit {
                    line: ln - 1,
                    label: match label {
                        Some(ref v) => v.clone(),
                        _ => panic!("Missing label on line {})", ln),
                    },
                    algo: line.clone(),
                    secret: Vec::new(),
                    public: Vec::new(),
                    message: Vec::new(),
                    context: Vec::new(),
                    signature: Vec::new(),
                };
                println!("  : Testcase: {:?}", label);
                data.push(unit);
            }
            _ => (),
        }
        let unit = match data.last_mut() {
            Some(u) => u,
            None => continue,
        };
        match state {
            EddsaParserState::StateSecret => {
                if line.starts_with("PUBLIC KEY:") {
                    state = EddsaParserState::StatePublic;
                    continue;
                }

                let sec = parse_or_panic!(hex::decode(&line); line; ln);
                unit.secret.extend(sec);
            }
            EddsaParserState::StatePublic => {
                if line.starts_with("MESSAGE ") {
                    state = EddsaParserState::StateMessage;
                    continue;
                }

                let public = parse_or_panic!(hex::decode(&line); line; ln);
                unit.public.extend(public);
            }
            EddsaParserState::StateMessage => {
                if line.starts_with("CONTEXT:") {
                    state = EddsaParserState::StateContext;
                    continue;
                } else if line.starts_with("SIGNATURE:") {
                    state = EddsaParserState::StateSignature;
                    continue;
                }

                let msg = parse_or_panic!(hex::decode(&line); line; ln);
                unit.message.extend(msg);
            }
            EddsaParserState::StateContext => {
                if line.starts_with("SIGNATURE:") {
                    state = EddsaParserState::StateSignature;
                    continue;
                }

                let context = parse_or_panic!(hex::decode(&line); line; ln);
                unit.context.extend(context);
            }
            EddsaParserState::StateSignature => {
                if line.starts_with("ALGORITHM:") {
                    state = EddsaParserState::StateAlgorithm;
                    continue;
                }

                let sig = parse_or_panic!(hex::decode(&line); line; ln);
                unit.signature.extend(sig);
            }
            _ => (),
        }
    }
    data
}

fn algo_to_ec_params(algo: &String) -> Vec<u8> {
    if algo.starts_with("Ed25519") {
        return hex::decode("130c656477617264733235353139")
            .expect("Failed to decode ec param");
    } else if algo.starts_with("Ed448") {
        return hex::decode("130a65647761726473343438")
            .expect("Failed to decode ec param");
    } else {
        panic!("Unknown algorithm {}", algo);
    }
}

fn test_eddsa_units(session: CK_SESSION_HANDLE, test_data: Vec<EddsaTestUnit>) {
    for unit in test_data {
        println!("Executing test at line {}", unit.line);

        let ec_params = algo_to_ec_params(&unit.algo);
        let priv_handle = ret_or_panic!(import_object(
            session,
            CKO_PRIVATE_KEY,
            &[(CKA_KEY_TYPE, CKK_EC_EDWARDS)],
            &[
                (CKA_VALUE, &unit.secret),
                (CKA_EC_PARAMS, &ec_params),
                (
                    CKA_LABEL,
                    format!(
                        "{} private key, label={}, line {}",
                        unit.algo, unit.label, unit.line
                    )
                    .as_bytes()
                )
            ],
            &[(CKA_SIGN, true)],
        ));

        let pub_handle = ret_or_panic!(import_object(
            session,
            CKO_PUBLIC_KEY,
            &[(CKA_KEY_TYPE, CKK_EC_EDWARDS)],
            &[
                (CKA_EC_POINT, &unit.public),
                (CKA_EC_PARAMS, &ec_params),
                (
                    CKA_LABEL,
                    format!(
                        "{} public key, label={}, line {}",
                        unit.algo, unit.label, unit.line
                    )
                    .as_bytes()
                )
            ],
            &[(CKA_VERIFY, true)],
        ));

        let mut ph_flag = CK_FALSE;
        if unit.algo.ends_with("ph") {
            ph_flag = CK_TRUE;
        }
        let mut mechanism: CK_MECHANISM = CK_MECHANISM {
            mechanism: CKM_EDDSA,
            pParameter: std::ptr::null_mut(),
            ulParameterLen: 0,
        };
        let mut params = CK_EDDSA_PARAMS {
            phFlag: ph_flag,
            pContextData: std::ptr::null_mut(),
            ulContextDataLen: 0 as CK_ULONG,
        };
        if ph_flag == CK_TRUE
            || unit.context.len() > 0
            || unit.algo.starts_with("Ed448")
        {
            if unit.context.len() > 0 {
                params.pContextData = unit.context.as_ptr() as *mut CK_BYTE;
                params.ulContextDataLen = unit.context.len() as CK_ULONG;
            }
            mechanism.pParameter = &mut params as *mut _ as CK_VOID_PTR;
            mechanism.ulParameterLen = sizeof!(CK_EDDSA_PARAMS);
        }

        let ret = fn_sign_init(session, &mut mechanism, priv_handle);
        if ret != CKR_OK {
            panic!("Failed ({}) unit test at line {}", ret, unit.line);
        }

        let sign: [u8; 120] = [0; 120]; /* large enough */
        let mut sign_len: CK_ULONG = unit.signature.len() as CK_ULONG;
        let ret = fn_sign(
            session,
            unit.message.as_ptr() as *mut u8,
            unit.message.len() as CK_ULONG,
            sign.as_ptr() as *mut _,
            &mut sign_len,
        );
        assert_eq!(ret, CKR_OK);
        assert_eq!(sign_len, unit.signature.len() as CK_ULONG);
        assert_eq!(&sign[..sign_len as usize], unit.signature.as_slice());

        let ret = fn_verify_init(session, &mut mechanism, pub_handle);
        assert_eq!(ret, CKR_OK);

        let ret = fn_verify(
            session,
            unit.message.as_ptr() as *mut u8,
            unit.message.len() as CK_ULONG,
            sign.as_ptr() as *mut u8,
            sign_len,
        );
        assert_eq!(ret, CKR_OK);
    }
}

#[test]
#[parallel]
fn test_eddsa_vector() {
    /* Taken from RFC, filtered out the headers */
    let test_data = parse_eddsa_vector("testdata/rfc8032.txt");

    let mut testtokn = TestToken::initialized("test_eddsa_vector", None);
    let session = testtokn.get_session(false);

    /* login */
    testtokn.login();

    test_eddsa_units(session, test_data);

    testtokn.finalize();
}

/* Test needs to be run serially as it changes global config */
#[test]
#[serial]
fn test_create_eddsa_compat() {
    let mut testtokn =
        TestToken::initialized("test_create_eddsa_compat.sql", None);
    let session = testtokn.get_session(true);

    /* login */
    testtokn.login();

    /* Test Vectors for Ed25519ctx */
    let point = hex::decode(
        "dfc9425e4f968f7f0c29f0259cf5f9aed6851c2bb4ad8bfb860cfee0ab248292",
    )
    .expect("Failed to decode hex point");
    let params = hex::decode("130c656477617264733235353139")
        .expect("Failed to decode hex params");
    let public_handle = ret_or_panic!(import_object(
        session,
        CKO_PUBLIC_KEY,
        &[(CKA_KEY_TYPE, CKK_EC_EDWARDS)],
        &[
            (CKA_LABEL, "Ed25519 with ByteArray EC Point".as_bytes()),
            (CKA_EC_POINT, point.as_slice()),
            (CKA_EC_PARAMS, params.as_slice()),
        ],
        &[(CKA_VERIFY, true)]
    ));

    /* Test Vectors for Ed25519ctx with public point in DER format*/
    let point_der = hex::decode(
        "0420dfc9425e4f968f7f0c29f0259cf5f9aed6851c2bb4ad8bfb860cfee0ab248292",
    )
    .expect("Failed to decode hex point");
    let der_handle = ret_or_panic!(import_object(
        session,
        CKO_PUBLIC_KEY,
        &[(CKA_KEY_TYPE, CKK_EC_EDWARDS)],
        &[
            (CKA_LABEL, "Ed25519 with DER EC Point".as_bytes()),
            (CKA_EC_POINT, point_der.as_slice()),
            (CKA_EC_PARAMS, params.as_slice()),
        ],
        &[(CKA_VERIFY, true)]
    ));

    let mut value = vec![0u8; point.len()];
    let mut extract_template = make_ptrs_template(&[(
        CKA_EC_POINT,
        void_ptr!(value.as_mut_ptr()),
        value.len(),
    )]);

    /* test both public_handle, and public30_handle, they should both
     * return the same byte array point in standard mode */
    let ret = fn_get_attribute_value(
        session,
        public_handle,
        extract_template.as_mut_ptr(),
        extract_template.len() as CK_ULONG,
    );
    assert_eq!(ret, CKR_OK);
    assert_eq!(value, point);

    value[0] = !value[0]; /* clobber */
    let ret = fn_get_attribute_value(
        session,
        der_handle,
        extract_template.as_mut_ptr(),
        extract_template.len() as CK_ULONG,
    );
    assert_eq!(ret, CKR_OK);
    assert_eq!(value, point);

    /* test both public_handle, and publicDer_handle, they should both
     * return the same DER encoded point in compatibility mode */
    let mut saved = config::EcPointEncoding::default();
    assert_eq!(get_ec_point_encoding(&mut saved), CKR_OK);
    assert_eq!(set_ec_point_encoding(config::EcPointEncoding::Der), CKR_OK);

    let mut value = vec![0u8; point_der.len()];
    let mut extract_template = make_ptrs_template(&[(
        CKA_EC_POINT,
        void_ptr!(value.as_mut_ptr()),
        value.len(),
    )]);

    let ret = fn_get_attribute_value(
        session,
        public_handle,
        extract_template.as_mut_ptr(),
        extract_template.len() as CK_ULONG,
    );
    assert_eq!(ret, CKR_OK);
    assert_eq!(value, point_der);

    value[0] = !value[0]; /* clobber */
    let ret = fn_get_attribute_value(
        session,
        der_handle,
        extract_template.as_mut_ptr(),
        extract_template.len() as CK_ULONG,
    );
    assert_eq!(ret, CKR_OK);
    assert_eq!(value, point_der);

    assert_eq!(set_ec_point_encoding(saved), CKR_OK);

    testtokn.finalize();
}
