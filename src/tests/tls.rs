// Copyright 2024 Simo Sorce
// See LICENSE.txt file for terms

use super::attribute;
use super::hmac;
use super::object;
use super::tests;
use super::tlskdf;
use tests::*;

use serial_test::parallel;
use std::io;
use std::io::BufRead;

#[test]
#[parallel]
fn test_tlsprf_vectors() {
    /* tests from https://mailarchive.ietf.org/arch/msg/tls/fzVCzk-z3FShgGJ6DOXqM1ydxms/2/ */

    let vector = [
        (
            /* secret */
            hex::decode("e18828740352b530d69b34c6597dea2e").unwrap(),
            /* label+seed */
            hex::decode("74657374206c6162656cf5a3fe6d34e2e28560fdcaf6823f9091")
                .unwrap(),
            /* output */
            hex::decode(
                "224d8af3c0453393a9779789d21cf7da5ee62ae6b617873d4894\
                 28efc8dd58d1566e7029e2ca3a5ecd355dc64d4d927e2fbd78c4\
                 233e8604b14749a77a92a70fddf614bc0df623d798604e4ca551\
                 2794d802a258e82f86cf",
            )
            .unwrap(),
            /* prf mechtype */
            CKM_SHA224_HMAC,
            /* name */
            "TLS1.2PRF-SHA224",
        ),
        (
            hex::decode("9bbe436ba940f017b17652849a71db35").unwrap(),
            hex::decode("74657374206c6162656ca0ba9f936cda311827a6f796ffd5198c")
                .unwrap(),
            hex::decode(
                "e3f229ba727be17b8d122620557cd453c2aab21d07c3d495329b\
                 52d4e61edb5a6b301791e90d35c9c9a46b4e14baf9af0fa022f7\
                 077def17abfd3797c0564bab4fbc91666e9def9b97fce34f7967\
                 89baa48082d122ee42c5a72e5a5110fff70187347b66",
            )
            .unwrap(),
            CKM_SHA256_HMAC,
            "TLS1.2PRF-SHA256",
        ),
        (
            hex::decode("b0323523c1853599584d88568bbb05eb").unwrap(),
            hex::decode("74657374206c6162656cd4640e12e4bcdbfb437f03e6ae418ee5")
                .unwrap(),
            hex::decode(
                "1261f588c798c5c201ff036e7a9cb5edcd7fe3f94c669a122a46\
                 38d7d508b283042df6789875c7147e906d868bc75c45e20eb40c\
                 1cf4a1713b27371f68432592f7dc8ea8ef223e12ea8507841311\
                 bf68653d0cfc4056d811f025c45ddfa6e6fec702f054b409d6f2\
                 8dd0a3233e498da41a3e75c5630eedbe22fe254e33a1b0e9f6b9\
                 826675bec7d01a845658dc9c397545401d40b9f46c7a400ee1b8\
                 f81ca0a60d1a397a1028bff5d2ef5066126842fb8da4197632bd\
                 b54ff6633f86bbc836e640d4d898",
            )
            .unwrap(),
            CKM_SHA512_HMAC,
            "TLS1.2PRF-SHA512",
        ),
        (
            hex::decode("b80b733d6ceefcdc71566ea48e5567df").unwrap(),
            hex::decode("74657374206c6162656ccd665cf6a8447dd6ff8b27555edb7465")
                .unwrap(),
            hex::decode(
                "7b0c18e9ced410ed1804f2cfa34a336a1c14dffb4900bb5fd794\
                 2107e81c83cde9ca0faa60be9fe34f82b1233c9146a0e534cb40\
                 0fed2700884f9dc236f80edd8bfa961144c9e8d792eca722a7b3\
                 2fc3d416d473ebc2c5fd4abfdad05d9184259b5bf8cd4d90fa0d\
                 31e2dec479e4f1a26066f2eea9a69236a3e52655c9e9aee691c8\
                 f3a26854308d5eaa3be85e0990703d73e56f",
            )
            .unwrap(),
            CKM_SHA384_HMAC,
            "TLS1.2PRF-SHA384",
        ),
    ];

    for v in vector {
        let secret = &v.0;
        let seed = &v.1;
        let output = &v.2;
        let mechtype = v.3;
        let name = v.4;

        /* mock key */
        let mut key = object::Object::new();
        key.set_attr(attribute::from_ulong(CKA_CLASS, CKO_SECRET_KEY))
            .unwrap();
        key.set_attr(attribute::from_ulong(CKA_KEY_TYPE, CKK_GENERIC_SECRET))
            .unwrap();
        key.set_attr(attribute::from_bytes(CKA_VALUE, secret.clone()))
            .unwrap();
        key.set_attr(attribute::from_ulong(
            CKA_VALUE_LEN,
            secret.len() as CK_ULONG,
        ))
        .unwrap();
        key.set_attr(attribute::from_bool(CKA_DERIVE, true))
            .unwrap();

        let mech = hmac::test_get_hmac(mechtype);

        let out =
            tlskdf::test_tlsprf(&key, &mech, mechtype, seed, output.len())
                .unwrap();
        if &out != output {
            panic!("Failed tls prf vector named {}", name);
        }
    }
}

#[derive(Debug)]
struct TlsKdfTestUnit {
    line: usize,
    count: usize,
    pms: Vec<u8>,
    srv_hlo_rnd: Vec<u8>,
    cli_hlo_rnd: Vec<u8>,
    srv_rnd: Vec<u8>,
    cli_rnd: Vec<u8>,
    ms: Vec<u8>,
    kb: Vec<u8>,
}

#[derive(Debug)]
struct TlsKdfTestSection {
    kdf: CK_MECHANISM_TYPE,
    prf: CK_MECHANISM_TYPE,
    units: Vec<TlsKdfTestUnit>,
}

fn parse_kdf_vector(filename: &str) -> Vec<TlsKdfTestSection> {
    let file = ret_or_panic!(std::fs::File::open(filename));

    let mut kdf: CK_MECHANISM_TYPE;
    let mut data = Vec::<TlsKdfTestSection>::new();
    let mut pms_len = 0usize;
    let mut kb_len = 0usize;

    for (l, line) in io::BufReader::new(file).lines().flatten().enumerate() {
        let ln = l + 1;
        if line.starts_with("#") {
            continue;
        }

        if line.len() == 0 {
            continue;
        }

        if line.starts_with("[TLS ") {
            /* we ignore tests for algorithms we do not care to support like Triple DES,
             * for those we still need to parse the section, but we'll mark it as
             * unknown and skip all units */
            let mut prf = CKM_SHA_1;
            match &line[5..] {
                "1.0/1.1]" => kdf = CKM_TLS_MASTER_KEY_DERIVE,
                "1.2, SHA-256]" => {
                    prf = CKM_SHA256;
                    kdf = CKM_TLS12_MASTER_KEY_DERIVE;
                }
                _ => kdf = CK_UNAVAILABLE_INFORMATION,
            }

            let section = TlsKdfTestSection {
                kdf: kdf,
                prf: prf,
                units: Vec::with_capacity(100),
            };
            data.push(section);
            continue;
        }
        let section = match data.last_mut() {
            Some(s) => s,
            None => continue,
        };
        if section.prf == CK_UNAVAILABLE_INFORMATION {
            continue;
        }
        if line.starts_with("[pre-master secret length = ") {
            pms_len =
                (&line[28..(line.len() - 1)]).parse::<usize>().unwrap() / 8;
            continue;
        }
        if line.starts_with("[key block length = ") {
            kb_len =
                (&line[20..(line.len() - 1)]).parse::<usize>().unwrap() / 8;
            continue;
        }

        /* units */
        if line.starts_with("COUNT = ") {
            let unit = TlsKdfTestUnit {
                line: ln,
                count: (&line[8..]).parse().unwrap(),
                pms: vec![0u8; pms_len],
                srv_hlo_rnd: vec![0u8; 32],
                cli_hlo_rnd: vec![0u8; 32],
                srv_rnd: vec![0u8; 32],
                cli_rnd: vec![0u8; 32],
                ms: vec![0u8; pms_len],
                kb: vec![0u8; kb_len],
            };
            section.units.push(unit);
            continue;
        }

        let unit = match section.units.last_mut() {
            Some(u) => u,
            None => panic!("No unit defined in section (line {})", ln),
        };

        if line.starts_with("pre_master_secret = ") {
            parse_or_panic!(hex::decode_to_slice(&line[20..], unit.pms.as_mut_slice()); line; ln);
            continue;
        }
        if line.starts_with("serverHello_random = ") {
            parse_or_panic!(hex::decode_to_slice(&line[21..], unit.srv_hlo_rnd.as_mut_slice()); line; ln);
            continue;
        }
        if line.starts_with("clientHello_random = ") {
            parse_or_panic!(hex::decode_to_slice(&line[21..], unit.cli_hlo_rnd.as_mut_slice()); line; ln);
            continue;
        }
        if line.starts_with("server_random = ") {
            parse_or_panic!(hex::decode_to_slice(&line[16..], unit.srv_rnd.as_mut_slice()); line; ln);
            continue;
        }
        if line.starts_with("client_random = ") {
            parse_or_panic!(hex::decode_to_slice(&line[16..], unit.cli_rnd.as_mut_slice()); line; ln);
            continue;
        }
        if line.starts_with("master_secret = ") {
            parse_or_panic!(hex::decode_to_slice(&line[16..], unit.ms.as_mut_slice()); line; ln);
            continue;
        }
        if line.starts_with("key_block = ") {
            parse_or_panic!(hex::decode_to_slice(&line[12..], unit.kb.as_mut_slice()); line; ln);
            continue;
        }
    }

    data
}

fn test_tlskdf_units(
    session: CK_SESSION_HANDLE,
    test_data: Vec<TlsKdfTestSection>,
) {
    for section in test_data {
        /* until we support all the KDFs */
        if section.kdf != CKM_TLS12_MASTER_KEY_DERIVE {
            continue;
        }

        for unit in section.units {
            println!("Executing test at line {}", unit.line);
            /* create key */
            let key_handle = ret_or_panic!(import_object(
                session,
                CKO_SECRET_KEY,
                &[(CKA_KEY_TYPE, CKK_GENERIC_SECRET)],
                &[
                    (CKA_VALUE, unit.pms.as_slice()),
                    (
                        CKA_LABEL,
                        format!(
                            "Key for mech {}, COUNT={}, line {}",
                            section.kdf, unit.count, unit.line
                        )
                        .as_bytes()
                    )
                ],
                &[(CKA_DERIVE, true)],
            ));

            /* Master key Derivation */

            let derive_template = make_attr_template(
                &[
                    (CKA_CLASS, CKO_SECRET_KEY),
                    (CKA_KEY_TYPE, CKK_GENERIC_SECRET),
                    (CKA_VALUE_LEN, unit.ms.len() as CK_ULONG),
                ],
                &[],
                &[(CKA_EXTRACTABLE, true)],
            );

            let (params, paramslen) = match section.kdf {
                CKM_TLS12_MASTER_KEY_DERIVE => (
                    CK_TLS12_MASTER_KEY_DERIVE_PARAMS {
                        RandomInfo: CK_SSL3_RANDOM_DATA {
                            pClientRandom: byte_ptr!(unit.cli_hlo_rnd.as_ptr()),
                            ulClientRandomLen: unit.cli_hlo_rnd.len()
                                as CK_ULONG,
                            pServerRandom: byte_ptr!(unit.srv_hlo_rnd.as_ptr()),
                            ulServerRandomLen: unit.srv_hlo_rnd.len()
                                as CK_ULONG,
                        },
                        pVersion: std::ptr::null_mut(),
                        prfHashMechanism: section.prf,
                    },
                    sizeof!(CK_TLS12_MASTER_KEY_DERIVE_PARAMS),
                ),
                _ => panic!("Invalid mechanism"),
            };
            let derive_mech = CK_MECHANISM {
                mechanism: section.kdf,
                pParameter: void_ptr!(&params),
                ulParameterLen: paramslen,
            };

            let mut dk_handle = CK_INVALID_HANDLE;
            let ret = fn_derive_key(
                session,
                &derive_mech as *const _ as CK_MECHANISM_PTR,
                key_handle,
                derive_template.as_ptr() as *mut _,
                derive_template.len() as CK_ULONG,
                &mut dk_handle,
            );
            if ret != CKR_OK {
                panic!("Failed ({}) unit test at line {}", ret, unit.line);
            }

            let value = ret_or_panic!(extract_key_value(
                session,
                dk_handle,
                unit.ms.len()
            ));
            if value != unit.ms {
                panic!("Failed ({}) unit test {} at line {} - values differ [{} != {}]",
                       ret, unit.count, unit.line, hex::encode(value), hex::encode(unit.ms));
            }

            /* Key Expansion */

            /* mac keys can't be extracted, so assume keys of 48 bytes and
             * put the rest as ivs which are returned */

            let half = unit.kb.len() / 2;
            let keylen = if half < 48 { half } else { 48 };
            let ivlen = half - keylen;

            let derive_template = make_attr_template(
                &[
                    (CKA_CLASS, CKO_SECRET_KEY),
                    (CKA_KEY_TYPE, CKK_GENERIC_SECRET),
                    (CKA_VALUE_LEN, keylen as CK_ULONG),
                ],
                &[],
                &[(CKA_EXTRACTABLE, true)],
            );

            let mut cliiv = vec![0u8; ivlen];
            let mut srviv = vec![0u8; ivlen];
            let mut mat_out = CK_SSL3_KEY_MAT_OUT {
                hClientMacSecret: CK_INVALID_HANDLE,
                hServerMacSecret: CK_INVALID_HANDLE,
                hClientKey: CK_INVALID_HANDLE,
                hServerKey: CK_INVALID_HANDLE,
                pIVClient: cliiv.as_mut_ptr(),
                pIVServer: srviv.as_mut_ptr(),
            };

            let (kdf, params, paramslen) = match section.kdf {
                CKM_TLS12_MASTER_KEY_DERIVE => (
                    CKM_TLS12_KEY_AND_MAC_DERIVE,
                    CK_TLS12_KEY_MAT_PARAMS {
                        ulMacSizeInBits: 0,
                        ulKeySizeInBits: (keylen as CK_ULONG) * 8,
                        ulIVSizeInBits: (ivlen as CK_ULONG) * 8,
                        bIsExport: CK_FALSE,
                        RandomInfo: CK_SSL3_RANDOM_DATA {
                            pClientRandom: byte_ptr!(unit.cli_rnd.as_ptr()),
                            ulClientRandomLen: unit.cli_rnd.len() as CK_ULONG,
                            pServerRandom: byte_ptr!(unit.srv_rnd.as_ptr()),
                            ulServerRandomLen: unit.srv_rnd.len() as CK_ULONG,
                        },
                        pReturnedKeyMaterial: &mut mat_out,
                        prfHashMechanism: section.prf,
                    },
                    sizeof!(CK_TLS12_KEY_MAT_PARAMS),
                ),
                _ => panic!("Invalid mechanism"),
            };
            let derive_mech = CK_MECHANISM {
                mechanism: kdf,
                pParameter: void_ptr!(&params),
                ulParameterLen: paramslen,
            };

            let ret = fn_derive_key(
                session,
                &derive_mech as *const _ as CK_MECHANISM_PTR,
                dk_handle,
                derive_template.as_ptr() as *mut _,
                derive_template.len() as CK_ULONG,
                std::ptr::null_mut(),
            );
            if ret != CKR_OK {
                panic!("Failed ({}) unit test at line {}", ret, unit.line);
            }

            let clikeyval = ret_or_panic!(extract_key_value(
                session,
                mat_out.hClientKey,
                keylen
            ));
            let srvkeyval = ret_or_panic!(extract_key_value(
                session,
                mat_out.hServerKey,
                keylen
            ));

            let mut value = Vec::<u8>::with_capacity(unit.kb.len());
            value.extend_from_slice(clikeyval.as_slice());
            value.extend_from_slice(srvkeyval.as_slice());
            value.extend_from_slice(cliiv.as_slice());
            value.extend_from_slice(srviv.as_slice());

            if value != unit.kb {
                panic!("Failed ({}) unit test {} at line {} - values differ [{} != {}]",
                       ret, unit.count, unit.line, hex::encode(value), hex::encode(unit.kb));
            }
        }
    }
}

#[test]
#[parallel]
fn test_tls_master_secret_vectors() {
    let test_data = parse_kdf_vector("testdata/tlsprf_vectors.txt");

    let mut testtokn =
        TestToken::initialized("tls_master_secret_vectors.sql", None);
    let session = testtokn.get_session(false);

    /* login */
    testtokn.login();

    test_tlskdf_units(session, test_data);

    testtokn.finalize();
}

#[test]
#[parallel]
fn test_tls_mechanisms() {
    let mut testtokn = TestToken::initialized("tls_mechanisms.sql", None);
    let session = testtokn.get_session(false);

    /* login */
    testtokn.login();

    /* test CKM_TLS_MAC */
    let handle = ret_or_panic!(generate_key(
        session,
        CKM_GENERIC_SECRET_KEY_GEN,
        std::ptr::null_mut(),
        0,
        &[(CKA_VALUE_LEN, 48),],
        &[],
        &[
            (CKA_SENSITIVE, true),
            (CKA_TOKEN, false),
            (CKA_SIGN, true),
            (CKA_VERIFY, true),
            (CKA_DERIVE, true),
        ],
    ));

    let params = CK_TLS_MAC_PARAMS {
        prfHashMechanism: CKM_SHA256,
        ulMacLength: 64,
        ulServerOrClient: 1,
    };

    let data = "Very Fake Hash Result";

    let mac = ret_or_panic!(sig_gen(
        session,
        handle,
        data.as_bytes(),
        &CK_MECHANISM {
            mechanism: CKM_TLS_MAC,
            pParameter: void_ptr!(&params),
            ulParameterLen: sizeof!(CK_TLS_MAC_PARAMS),
        }
    ));
    assert_eq!(mac.len(), 64);
    assert_eq!(
        CKR_OK,
        sig_verify(
            session,
            handle,
            data.as_bytes(),
            mac.as_slice(),
            &CK_MECHANISM {
                mechanism: CKM_TLS_MAC,
                pParameter: void_ptr!(&params),
                ulParameterLen: sizeof!(CK_TLS_MAC_PARAMS),
            }
        )
    );

    /* Test CKM_TLS12_KEY_SAFE_DERIVE */
    let derive_template = make_attr_template(
        &[
            (CKA_CLASS, CKO_SECRET_KEY),
            (CKA_KEY_TYPE, CKK_GENERIC_SECRET),
            (CKA_VALUE_LEN, 48),
        ],
        &[],
        &[(CKA_EXTRACTABLE, false)],
    );

    let clirnd = [0u8; 32];
    let srvrnd = [0u8; 32];
    let mut cliiv = [0u8; 10];
    let mut srviv = [0u8; 10];
    let mut mat_out = CK_SSL3_KEY_MAT_OUT {
        hClientMacSecret: CK_INVALID_HANDLE,
        hServerMacSecret: CK_INVALID_HANDLE,
        hClientKey: CK_INVALID_HANDLE,
        hServerKey: CK_INVALID_HANDLE,
        pIVClient: cliiv.as_mut_ptr(),
        pIVServer: srviv.as_mut_ptr(),
    };

    let params = CK_TLS12_KEY_MAT_PARAMS {
        ulMacSizeInBits: 0,
        ulKeySizeInBits: 48 * 8,
        ulIVSizeInBits: 10 * 8,
        bIsExport: CK_FALSE,
        RandomInfo: CK_SSL3_RANDOM_DATA {
            pClientRandom: byte_ptr!(clirnd.as_ptr()),
            ulClientRandomLen: clirnd.len() as CK_ULONG,
            pServerRandom: byte_ptr!(srvrnd.as_ptr()),
            ulServerRandomLen: srvrnd.len() as CK_ULONG,
        },
        pReturnedKeyMaterial: &mut mat_out,
        prfHashMechanism: CKM_SHA256,
    };
    let paramslen = sizeof!(CK_TLS12_KEY_MAT_PARAMS);
    let derive_mech = CK_MECHANISM {
        mechanism: CKM_TLS12_KEY_SAFE_DERIVE,
        pParameter: void_ptr!(&params),
        ulParameterLen: paramslen,
    };

    let ret = fn_derive_key(
        session,
        &derive_mech as *const _ as CK_MECHANISM_PTR,
        handle,
        derive_template.as_ptr() as *mut _,
        derive_template.len() as CK_ULONG,
        std::ptr::null_mut(),
    );
    assert_eq!(ret, CKR_OK);

    /* ensure IVs were ignored */
    assert_eq!(cliiv.as_slice(), &[0u8; 10]);
    assert_eq!(srviv.as_slice(), &[0u8; 10]);

    /* Smoke test CKM_TLS12_KDF */
    let clirnd = [0u8; 32];
    let srvrnd = [0u8; 32];
    let label = "EXPERIMENTAL tls derive";
    let context = "This is a context";
    let params = CK_TLS_KDF_PARAMS {
        prfMechanism: CKM_SHA256,
        pLabel: byte_ptr!(label),
        ulLabelLength: label.len() as CK_ULONG,
        RandomInfo: CK_SSL3_RANDOM_DATA {
            pClientRandom: byte_ptr!(clirnd.as_ptr()),
            ulClientRandomLen: clirnd.len() as CK_ULONG,
            pServerRandom: byte_ptr!(srvrnd.as_ptr()),
            ulServerRandomLen: srvrnd.len() as CK_ULONG,
        },
        pContextData: byte_ptr!(context),
        ulContextDataLength: context.len() as CK_ULONG,
    };
    let paramslen = sizeof!(CK_TLS_KDF_PARAMS);
    let derive_mech = CK_MECHANISM {
        mechanism: CKM_TLS12_KDF,
        pParameter: void_ptr!(&params),
        ulParameterLen: paramslen,
    };

    let mut dk_handle = CK_INVALID_HANDLE;
    let ret = fn_derive_key(
        session,
        &derive_mech as *const _ as CK_MECHANISM_PTR,
        handle,
        derive_template.as_ptr() as *mut _,
        derive_template.len() as CK_ULONG,
        &mut dk_handle,
    );
    assert_eq!(ret, CKR_OK);

    /* The End */
    testtokn.finalize();
}
