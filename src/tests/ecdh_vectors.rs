// Copyright 2024 Jakub Jelen
// See LICENSE.txt file for terms

use super::tests;
use crate::ecc;
use tests::*;

use serial_test::parallel;
use std::io;
use std::io::BufRead;

#[derive(Debug)]
struct EccKey {
    d: Vec<u8>,
    x: Vec<u8>,
    y: Vec<u8>,
}

#[derive(Debug)]
struct EcdhTestUnit {
    line: usize,
    count: usize,
    curve_name: &'static str,
    ec_params: &'static [u8],
    cavs: EccKey,
    iut: EccKey,
    z: Vec<u8>,
    fail: bool,
    errno: u8,
}

// defined here for completing parsing -- not used as this curve is not supported
const NAME_SECP224R1: &str = "prime224v1";

fn map_curve(curve: &str) -> Option<&'static str> {
    match curve {
        "P-224" => Some(NAME_SECP224R1),
        "P-256" => Some(ecc::NAME_SECP256R1),
        "P-384" => Some(ecc::NAME_SECP384R1),
        "P-521" => Some(ecc::NAME_SECP521R1),
        _ => None,
    }
}

enum EcdhParserState {
    StateParams,
    StateCurves,
    StateData,
}

fn parse_ecdh_vector(filename: &str) -> Vec<EcdhTestUnit> {
    let file = ret_or_panic!(std::fs::File::open(filename));

    let mut data = Vec::<EcdhTestUnit>::new();
    let mut tags = Vec::<String>::new();
    let mut sets = HashMap::<String, &str>::new();
    let mut tag = None;
    let mut curve = None;
    let mut tagg = String::new();

    let mut state = EcdhParserState::StateParams;
    for (l, line) in io::BufReader::new(file).lines().flatten().enumerate() {
        let ln = l + 1;

        if line.len() == 0 {
            continue;
        }

        match state {
            EcdhParserState::StateParams => {
                let kw = "#  Parameter set(s) supported: ";
                if line.starts_with(kw) {
                    let names: Vec<&str> =
                        line[kw.len()..].split(' ').collect();
                    for n in names {
                        tags.push(format!("[{}]", n));
                        println!("  : [{}]", n);
                    }
                    state = EcdhParserState::StateCurves;
                    continue;
                }
            }
            EcdhParserState::StateCurves => {
                let kw = "[Curve selected:  ";
                if tags.contains(&line) {
                    println!("  : {} Matched", line);
                    tag = Some(line.clone());
                    curve = None;
                } else if line.starts_with(kw) {
                    curve = map_curve(&line[kw.len()..line.len() - 1]);
                    if curve != None {
                        println!("  : {} Matched", curve.unwrap());
                    }
                }

                match tag {
                    Some(ref t) => match curve {
                        Some(c) => {
                            sets.insert(t.clone(), c);
                            println!("  : {} -> {} Mapped", t, c);
                            tag = None;
                        }
                        _ => (),
                    },
                    _ => (),
                }
                if sets.len() == tags.len() {
                    state = EcdhParserState::StateData;
                    continue;
                }
            }
            EcdhParserState::StateData => {
                if line.starts_with("[") {
                    tagg = format!("[{}]", &line[1..3]);
                } else if line.starts_with("COUNT = ") {
                    let curve_name =
                        sets.get(&tagg).expect("Failed to parse tag to string");
                    println!("  : curve_name = {}", curve_name);
                    let ec_params =
                        match ecc::curve_name_to_ec_params(curve_name) {
                            Ok(p) => p,
                            Err(_) => continue, /* skip unsupported */
                        };
                    let unit = EcdhTestUnit {
                        line: ln,
                        count: (&line[8..]).parse().unwrap(),
                        curve_name: curve_name,
                        ec_params: ec_params,
                        cavs: EccKey {
                            d: Vec::new(),
                            x: Vec::new(),
                            y: Vec::new(),
                        },
                        iut: EccKey {
                            d: Vec::new(),
                            x: Vec::new(),
                            y: Vec::new(),
                        },
                        fail: false,
                        errno: 0,
                        z: Vec::new(),
                    };
                    println!("  : Testcase = {}", unit.count);
                    data.push(unit);
                    continue;
                }

                let unit = match data.last_mut() {
                    Some(u) => u,
                    None => continue,
                };

                if line.starts_with("dsCAVS = ") {
                    unit.cavs.d =
                        parse_or_panic!(hex::decode(&line[9..]); line; ln);
                } else if line.starts_with("QsCAVSx = ") {
                    unit.cavs.x =
                        parse_or_panic!(hex::decode(&line[10..]); line; ln);
                } else if line.starts_with("QsCAVSy = ") {
                    unit.cavs.y =
                        parse_or_panic!(hex::decode(&line[10..]); line; ln);
                } else if line.starts_with("dsIUT = ") {
                    unit.iut.d =
                        parse_or_panic!(hex::decode(&line[8..]); line; ln);
                } else if line.starts_with("QsIUTx = ") {
                    unit.iut.x =
                        parse_or_panic!(hex::decode(&line[9..]); line; ln);
                } else if line.starts_with("QsIUTy = ") {
                    unit.iut.y =
                        parse_or_panic!(hex::decode(&line[9..]); line; ln);
                } else if line.starts_with("Z = ") {
                    unit.z = parse_or_panic!(hex::decode(&line[4..]); line; ln);
                } else if line.starts_with("Result = ") {
                    if &line[9..10] == "F" {
                        unit.fail = true;
                    } else {
                        unit.fail = false;
                    }
                    unit.errno = parse_or_panic!((&line[12..14]).trim().parse(); line; ln);
                    println!(
                        "  : Fail = {}, errno = {} ({})",
                        unit.fail,
                        unit.errno,
                        &line[9..10]
                    );
                }
            }
        }
    }
    data
}

fn test_to_ecc_point(key: &EccKey, curve_name: &'static str) -> Vec<u8> {
    let mut ec_point = Vec::<u8>::with_capacity(key.x.len() + key.y.len() + 1);
    ec_point.push(0x04);
    /* The P-521 curve points are heavily zero padded so we need to make sure they are well
     * formatted for OpenSSL -- to the field length boundary */
    let field_len = match ecc::name_to_bits(curve_name) {
        Ok(l) => l,
        Err(_) => panic!("Unknown curve given"),
    };
    let bytes = (field_len + 7) / 8;
    assert!(key.x.len() >= bytes);
    assert!(key.y.len() >= bytes);
    ec_point.extend_from_slice(&key.x[(key.x.len() - bytes)..]);
    ec_point.extend_from_slice(&key.y[(key.y.len() - bytes)..]);
    ec_point
}

fn test_ecdh_units(session: CK_SESSION_HANDLE, test_data: Vec<EcdhTestUnit>) {
    for unit in test_data {
        println!("Executing test at line {}", unit.line);

        let priv_handle = ret_or_panic!(import_object(
            session,
            CKO_PRIVATE_KEY,
            &[(CKA_KEY_TYPE, CKK_EC)],
            &[
                (CKA_VALUE, &unit.iut.d),
                (CKA_EC_PARAMS, unit.ec_params),
                (
                    CKA_LABEL,
                    format!(
                        "{} private key, COUNT={}, line {}",
                        unit.curve_name, unit.count, unit.line
                    )
                    .as_bytes()
                )
            ],
            &[(CKA_DERIVE, true)],
        ));

        /* import also public counterpart -- not used for anything now */
        let _ec_point = test_to_ecc_point(&unit.iut, unit.curve_name);
        let _pub_handle = ret_or_panic!(import_object(
            session,
            CKO_PUBLIC_KEY,
            &[(CKA_KEY_TYPE, CKK_EC)],
            &[
                (CKA_EC_POINT, &unit.iut.d),
                (CKA_EC_PARAMS, unit.ec_params),
                (
                    CKA_LABEL,
                    format!(
                        "{} public key, COUNT={}, line {}",
                        unit.curve_name, unit.count, unit.line
                    )
                    .as_bytes()
                )
            ],
            &[(CKA_DERIVE, true)],
        ));

        let derive_template = make_attr_template(
            &[
                (CKA_CLASS, CKO_SECRET_KEY),
                (CKA_KEY_TYPE, CKK_GENERIC_SECRET),
                (CKA_VALUE_LEN, unit.z.len() as CK_ULONG),
            ],
            &[],
            &[(CKA_EXTRACTABLE, true)],
        );

        let mut dk_handle = CK_INVALID_HANDLE;

        let mut peer_point = test_to_ecc_point(&unit.cavs, unit.curve_name);

        let mut params = CK_ECDH1_DERIVE_PARAMS {
            kdf: CKD_NULL,
            ulSharedDataLen: 0,
            pSharedData: std::ptr::null_mut(),
            ulPublicDataLen: peer_point.len() as CK_ULONG,
            pPublicData: peer_point.as_mut_ptr(),
        };
        let mut mechanism: CK_MECHANISM = CK_MECHANISM {
            mechanism: CKM_ECDH1_DERIVE,
            pParameter: &mut params as *mut _ as CK_VOID_PTR,
            ulParameterLen: std::mem::size_of::<CK_ECDH1_DERIVE_PARAMS>()
                as CK_ULONG,
        };

        let ret = fn_derive_key(
            session,
            &mut mechanism,
            priv_handle,
            derive_template.as_ptr() as *mut _,
            derive_template.len() as CK_ULONG,
            &mut dk_handle,
        );
        if ret != CKR_OK {
            if unit.fail {
                continue;
            }
            panic!("Failed ({}) unit test at line {}", ret, unit.line);
        }

        let mut value = vec![0u8; unit.z.len()];
        let mut extract_template = make_ptrs_template(&[(
            CKA_VALUE,
            void_ptr!(value.as_mut_ptr()),
            value.len(),
        )]);

        let ret = fn_get_attribute_value(
            session,
            dk_handle,
            extract_template.as_mut_ptr(),
            extract_template.len() as CK_ULONG,
        );
        assert_eq!(ret, CKR_OK);

        if unit.fail {
            if value == unit.z {
                // TODO This should be an error, but with 9, 10, 11, 12 (oi/tag/mac/dkm changed), the Z still
                // matches and it fails here
                if unit.errno < 9 {
                    panic!("The unit test at line {} worked while it was expected to fail - values same [{}]", unit.line, hex::encode(value));
                }
            }
        } else {
            if value != unit.z {
                panic!("Failed ({}) unit test at line {} - values differ [{} != {}]", ret, unit.line, hex::encode(value), hex::encode(unit.z));
            }
        }
    }
}

#[test]
#[parallel]
fn test_ecdh_vector() {
    let test_data = parse_ecdh_vector(
        "testdata/KASValidityTest_ECCStaticUnified_KDFConcat_NOKC_resp.fax",
    );

    let mut testtokn = TestToken::initialized("test_ecdh_vector.sql", None);
    let session = testtokn.get_session(false);

    /* login */
    testtokn.login();

    test_ecdh_units(session, test_data);

    testtokn.finalize();
}
