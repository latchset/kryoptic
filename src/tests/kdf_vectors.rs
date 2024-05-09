// Copyright 2024 Simo Sorce
// See LICENSE.txt file for terms

use super::tests;
use tests::*;

use std::io;
use std::io::BufRead;

#[derive(Debug, PartialEq)]
enum KdfCtrlLoc {
    Undefined,
    AfterFixed,
    AfterIter,
    BeforeFixed,
    BeforeIter,
    MiddleFixed,
}

#[derive(Debug)]
struct KdfTestUnit {
    line: usize,
    count: usize,
    l: usize,
    ki: Vec<u8>,
    iv_len: usize,
    iv: Vec<u8>,
    data_len: usize,
    data: Vec<u8>,
    data_before_len: usize,
    data_before: Vec<u8>,
    ko: Vec<u8>,
}

#[derive(Debug)]
struct KdfTestSection {
    kdf: CK_MECHANISM_TYPE,
    prf: CK_MECHANISM_TYPE,
    ctr_location: KdfCtrlLoc,
    rlen: usize,
    units: Vec<KdfTestUnit>,
}

macro_rules! parse_or_panic {
    ($e:expr; $line:expr; $ln:expr) => {
        match $e {
            Ok(r) => r,
            Err(_) => panic!("Malformed line '{}' (line {})", $line, $ln),
        }
    };
}

fn parse_kdf_vector(filename: &str) -> Vec<KdfTestSection> {
    let file = ret_or_panic!(std::fs::File::open(filename));

    let mut kdf: CK_MECHANISM_TYPE = CK_UNAVAILABLE_INFORMATION;
    let mut data = Vec::<KdfTestSection>::new();

    for (l, line) in io::BufReader::new(file).lines().flatten().enumerate() {
        let ln = l + 1;
        if line.starts_with("#") {
            match line.as_str() {
                "# KDF Mode Supported: Counter Mode" => {
                    kdf = CKM_SP800_108_COUNTER_KDF
                }
                "# KDF Mode Supported: Feedback Mode" => {
                    kdf = CKM_SP800_108_FEEDBACK_KDF
                }
                _ => (),
            }
            continue;
        }

        if line.len() == 0 {
            continue;
        }

        if line.starts_with("[PRF=") {
            /* we ignore tests for algorithms we do not care to support like Triple DES,
             * for those we still need to parse the section, but we'll mark it as
             * unknown and skip all units */
            let section = KdfTestSection {
                kdf: kdf,
                prf: match &line[5..] {
                    "CMAC_AES128]" => CKM_AES_CMAC,
                    "CMAC_AES192]" => CKM_AES_CMAC,
                    "CMAC_AES256]" => CKM_AES_CMAC,
                    "HMAC_SHA1]" => CKM_SHA_1_HMAC,
                    "HMAC_SHA224]" => CKM_SHA224_HMAC,
                    "HMAC_SHA256]" => CKM_SHA256_HMAC,
                    "HMAC_SHA384]" => CKM_SHA384_HMAC,
                    "HMAC_SHA512]" => CKM_SHA512_HMAC,
                    _ => CK_UNAVAILABLE_INFORMATION,
                },
                ctr_location: KdfCtrlLoc::Undefined,
                rlen: 0,
                units: Vec::with_capacity(39),
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
        if line.starts_with("[CTRLOCATION=") {
            if section.ctr_location != KdfCtrlLoc::Undefined {
                panic!(
                    "Repeat CTRLOCATION? Malformed test file? (line {})",
                    ln
                );
            }
            match &line[13..] {
                "AFTER_FIXED]" => section.ctr_location = KdfCtrlLoc::AfterFixed,
                "AFTER_ITER]" => section.ctr_location = KdfCtrlLoc::AfterIter,
                "BEFORE_FIXED]" => {
                    section.ctr_location = KdfCtrlLoc::BeforeFixed
                }
                "BEFORE_ITER]" => section.ctr_location = KdfCtrlLoc::BeforeIter,
                "MIDDLE_FIXED]" => {
                    section.ctr_location = KdfCtrlLoc::MiddleFixed
                }
                _ => panic!("Unrecognized input: {} (line {})", line, ln),
            }
            continue;
        }
        if line.starts_with("[RLEN=") {
            if section.rlen != 0 {
                panic!("Repeat RLEN? Malformed test file?");
            }
            match &line[6..] {
                "8_BITS]" => section.rlen = 8,
                "16_BITS]" => section.rlen = 16,
                "24_BITS]" => section.rlen = 24,
                "32_BITS]" => section.rlen = 32,
                _ => panic!("Unrecognized input: {} (line {})", line, ln),
            }
            continue;
        }

        /* units */
        if line.starts_with("COUNT=") {
            let unit = KdfTestUnit {
                line: ln,
                count: (&line[6..]).parse().unwrap(),
                l: 0,
                ki: Vec::new(),
                iv_len: 0,
                iv: Vec::new(),
                data_len: 0,
                data: Vec::new(),
                data_before: Vec::new(),
                data_before_len: 0,
                ko: Vec::new(),
            };
            section.units.push(unit);
            continue;
        }

        let unit = match section.units.last_mut() {
            Some(u) => u,
            None => panic!("No unit defined in section (line {})", ln),
        };

        if line.starts_with("L = ") {
            unit.l = parse_or_panic!((&line[4..]).parse(); line; ln);
            continue;
        }

        if line.starts_with("KI = ") {
            unit.ki = parse_or_panic!(hex::decode(&line[5..]); line; ln);
            continue;
        }

        if line.starts_with("IVlen = ") {
            unit.iv_len = parse_or_panic!((&line[8..]).parse(); line; ln);
            continue;
        }

        if line.starts_with("IV = ") {
            unit.iv = parse_or_panic!(hex::decode(&line[5..]); line; ln);
            if unit.iv.len() != unit.iv_len / 8 {
                panic!("Length of iv ({} bytes) does not match length of data ({} bits) (line {})", unit.iv.len(), unit.iv_len, ln);
            }
            continue;
        }

        match &section.ctr_location {
            KdfCtrlLoc::AfterFixed | KdfCtrlLoc::AfterIter => {
                if line.starts_with("FixedInputDataByteLen = ") {
                    unit.data_len =
                        parse_or_panic!((&line[24..]).parse(); line; ln);
                    continue;
                }

                if line.starts_with("FixedInputData = ") {
                    unit.data =
                        parse_or_panic!(hex::decode(&line[17..]); line; ln);
                    if unit.data.len() != unit.data_len {
                        panic!("Length of data ({}) does not match data ({}) (line {})", unit.data_before.len(), unit.data_before_len, ln);
                    }
                    continue;
                }
            }
            KdfCtrlLoc::BeforeFixed | KdfCtrlLoc::BeforeIter => {
                if line.starts_with("FixedInputDataByteLen = ") {
                    unit.data_len =
                        parse_or_panic!((&line[24..]).parse(); line; ln);
                    continue;
                }

                if line.starts_with("FixedInputData = ") {
                    unit.data =
                        parse_or_panic!(hex::decode(&line[17..]); line; ln);
                    if unit.data.len() != unit.data_len {
                        panic!("Length of data ({}) does not match data ({}) (line {})", unit.data.len(), unit.data_len, ln);
                    }
                    continue;
                }
            }
            KdfCtrlLoc::MiddleFixed => {
                if line.starts_with("DataBeforeCtrLen = ") {
                    unit.data_before_len =
                        parse_or_panic!((&line[19..]).parse(); line; ln);
                    continue;
                }

                if line.starts_with("DataBeforeCtrData = ") {
                    unit.data_before =
                        parse_or_panic!(hex::decode(&line[20..]); line; ln);
                    if unit.data_before.len() != unit.data_before_len {
                        panic!("Length of data ({}) does not match data ({}) (line {})", unit.data_before.len(), unit.data_before_len, ln);
                    }
                    continue;
                }
                if line.starts_with("DataAfterCtrLen = ") {
                    unit.data_len =
                        parse_or_panic!((&line[18..]).parse(); line; ln);
                    continue;
                }

                if line.starts_with("DataAfterCtrData = ") {
                    unit.data =
                        parse_or_panic!(hex::decode(&line[19..]); line; ln);
                    if unit.data.len() != unit.data_len {
                        panic!("Length of data ({}) does not match data ({}) (line {})", unit.data.len(), unit.data_len, ln);
                    }
                    continue;
                }
            }
            _ => panic!("Unextpected Counter Location type (line {})", ln),
        }

        if line.starts_with("\t") {
            /* ignore */
            continue;
        }

        if line.starts_with("KO = ") {
            unit.ko = parse_or_panic!(hex::decode(&line[5..]); line; ln);
            if unit.ko.len() * 8 != unit.l {
                panic!(
                    "Length of KO ({}) does not match L ({}) (line {})",
                    unit.ko.len(),
                    unit.l,
                    ln
                );
            }
            continue;
        }
    }

    data
}

fn create_secret_key(
    session: CK_ULONG,
    label: &String,
    key_type: CK_KEY_TYPE,
    key: &Vec<u8>,
) -> CK_OBJECT_HANDLE {
    let class = CKO_SECRET_KEY;
    let lb = label.as_bytes();
    let truebool = CK_TRUE;
    let template = vec![
        make_attribute!(CKA_CLASS, &class as *const _, CK_ULONG_SIZE),
        make_attribute!(CKA_KEY_TYPE, &key_type as *const _, CK_ULONG_SIZE),
        make_attribute!(
            CKA_LABEL,
            lb.as_ptr() as CK_VOID_PTR,
            lb.len() as CK_ULONG
        ),
        make_attribute!(
            CKA_VALUE,
            key.as_ptr() as CK_VOID_PTR,
            key.len() as CK_ULONG
        ),
        make_attribute!(CKA_DERIVE, &truebool as *const _, CK_BBOOL_SIZE),
    ];

    let mut handle: CK_OBJECT_HANDLE = CK_INVALID_HANDLE;
    let _ = fn_create_object(
        session,
        template.as_ptr() as CK_ATTRIBUTE_PTR,
        template.len() as CK_ULONG,
        &mut handle,
    );

    handle
}

macro_rules! make_prf_data_param {
    ($type:expr, $value:expr, $a:ty) => {
        CK_PRF_DATA_PARAM {
            type_: $type,
            pValue: $value as *const _ as CK_VOID_PTR,
            ulValueLen: std::mem::size_of::<$a>() as CK_ULONG,
        }
    };
    ($type:expr, $value:expr, $a:expr) => {
        CK_PRF_DATA_PARAM {
            type_: $type,
            pValue: $value as *const _ as CK_VOID_PTR,
            ulValueLen: $a as CK_ULONG,
        }
    };
}

fn test_kdf_units(session: CK_SESSION_HANDLE, test_data: Vec<KdfTestSection>) {
    let iter = make_prf_data_param!(
        CK_SP800_108_ITERATION_VARIABLE,
        std::ptr::null::<std::ffi::c_void>(),
        0
    );

    for section in test_data {
        if section.prf == CKM_AES_CMAC {
            /* unsupported currently */
            continue;
        }

        /* Currently we use the OpenSSL KBKDF backend for FIPS mode and
         * it supports only if the counter is before any fixed data and
         * (in feedback) after the IV */
        #[cfg(feature = "fips")]
        if section.kdf == CKM_SP800_108_COUNTER_KDF
            && section.ctr_location != KdfCtrlLoc::BeforeFixed
        {
            continue;
        }
        #[cfg(feature = "fips")]
        if section.kdf == CKM_SP800_108_FEEDBACK_KDF
            || section.ctr_location != KdfCtrlLoc::AfterIter
        {
            continue;
        }

        for unit in section.units {
            println!("Executing test at line {}", unit.line);
            /* create key */
            let key_handle = create_secret_key(
                session,
                &format!(
                    "Key for mech {}, COUNT={}, line {}",
                    section.prf, unit.count, unit.line
                ),
                CKK_GENERIC_SECRET,
                &unit.ki,
            );

            let class = CKO_SECRET_KEY;
            let ktype = CKK_GENERIC_SECRET;
            let klen = unit.ko.len() as CK_ULONG;
            let truebool = CK_TRUE;
            let derive_template = [
                make_attribute!(CKA_CLASS, &class as *const _, CK_ULONG_SIZE),
                make_attribute!(
                    CKA_KEY_TYPE,
                    &ktype as *const _,
                    CK_ULONG_SIZE
                ),
                make_attribute!(
                    CKA_VALUE_LEN,
                    &klen as *const _,
                    CK_ULONG_SIZE
                ),
                make_attribute!(
                    CKA_EXTRACTABLE,
                    &truebool as *const _,
                    CK_BBOOL_SIZE
                ),
            ];

            let mut dk_handle = CK_INVALID_HANDLE;

            match section.kdf {
                CKM_SP800_108_COUNTER_KDF => {
                    let mut data_params = Vec::<CK_PRF_DATA_PARAM>::new();

                    let counter_format = CK_SP800_108_COUNTER_FORMAT {
                        bLittleEndian: 0,
                        ulWidthInBits: section.rlen as CK_ULONG,
                    };
                    let counter = make_prf_data_param!(
                        CK_SP800_108_ITERATION_VARIABLE,
                        &counter_format,
                        CK_SP800_108_COUNTER_FORMAT
                    );

                    match &section.ctr_location {
                        KdfCtrlLoc::AfterFixed => {
                            let data = make_prf_data_param!(
                                CK_SP800_108_BYTE_ARRAY,
                                unit.data.as_ptr(),
                                unit.data.len()
                            );
                            data_params.push(data);
                            data_params.push(counter);
                        }
                        KdfCtrlLoc::BeforeFixed => {
                            let data = make_prf_data_param!(
                                CK_SP800_108_BYTE_ARRAY,
                                unit.data.as_ptr(),
                                unit.data.len()
                            );
                            data_params.push(counter);
                            data_params.push(data);
                        }
                        KdfCtrlLoc::MiddleFixed => {
                            let data_after = make_prf_data_param!(
                                CK_SP800_108_BYTE_ARRAY,
                                unit.data.as_ptr(),
                                unit.data.len()
                            );
                            let data_before = make_prf_data_param!(
                                CK_SP800_108_BYTE_ARRAY,
                                unit.data_before.as_ptr(),
                                unit.data_before.len()
                            );
                            data_params.push(data_before);
                            data_params.push(counter);
                            data_params.push(data_after);
                        }
                        _ => panic!("Unextpected Counter Location type"),
                    };

                    let mut params = CK_SP800_108_KDF_PARAMS {
                        prfType: section.prf,
                        ulNumberOfDataParams: data_params.len() as CK_ULONG,
                        pDataParams: data_params.as_ptr() as *mut _,
                        ulAdditionalDerivedKeys: 0,
                        pAdditionalDerivedKeys: std::ptr::null_mut(),
                    };

                    let derive_mech = CK_MECHANISM {
                        mechanism: CKM_SP800_108_COUNTER_KDF,
                        pParameter: &mut params as *mut _ as CK_VOID_PTR,
                        ulParameterLen: std::mem::size_of::<
                            CK_SP800_108_KDF_PARAMS,
                        >() as CK_ULONG,
                    };

                    let ret = fn_derive_key(
                        session,
                        &derive_mech as *const _ as CK_MECHANISM_PTR,
                        key_handle,
                        derive_template.as_ptr() as *mut _,
                        derive_template.len() as CK_ULONG,
                        &mut dk_handle,
                    );
                    if ret != CKR_OK {
                        panic!(
                            "Failed ({}) unit test at line {}",
                            ret, unit.line
                        );
                    }
                }
                CKM_SP800_108_FEEDBACK_KDF => {
                    let mut data_params = Vec::<CK_PRF_DATA_PARAM>::new();

                    let counter_format = CK_SP800_108_COUNTER_FORMAT {
                        bLittleEndian: 0,
                        ulWidthInBits: section.rlen as CK_ULONG,
                    };

                    let counter = make_prf_data_param!(
                        CK_SP800_108_COUNTER,
                        &counter_format,
                        CK_SP800_108_COUNTER_FORMAT
                    );

                    match &section.ctr_location {
                        KdfCtrlLoc::AfterFixed => {
                            let data = make_prf_data_param!(
                                CK_SP800_108_BYTE_ARRAY,
                                unit.data.as_ptr(),
                                unit.data.len()
                            );
                            data_params.push(iter);
                            data_params.push(data);
                            data_params.push(counter);
                        }
                        KdfCtrlLoc::AfterIter => {
                            let data = make_prf_data_param!(
                                CK_SP800_108_BYTE_ARRAY,
                                unit.data.as_ptr(),
                                unit.data.len()
                            );
                            data_params.push(iter);
                            data_params.push(counter);
                            data_params.push(data);
                        }
                        KdfCtrlLoc::BeforeIter => {
                            let data = make_prf_data_param!(
                                CK_SP800_108_BYTE_ARRAY,
                                unit.data.as_ptr(),
                                unit.data.len()
                            );
                            data_params.push(counter);
                            data_params.push(iter);
                            data_params.push(data);
                        }
                        _ => panic!("Unextpected Counter Location type"),
                    };

                    let mut params = CK_SP800_108_FEEDBACK_KDF_PARAMS {
                        prfType: section.prf,
                        ulNumberOfDataParams: data_params.len() as CK_ULONG,
                        pDataParams: data_params.as_ptr() as *mut _,
                        ulIVLen: unit.iv.len() as CK_ULONG,
                        pIV: if unit.iv.len() > 0 {
                            unit.iv.as_ptr() as *mut _
                        } else {
                            std::ptr::null_mut()
                        },
                        ulAdditionalDerivedKeys: 0,
                        pAdditionalDerivedKeys: std::ptr::null_mut(),
                    };

                    let derive_mech = CK_MECHANISM {
                        mechanism: CKM_SP800_108_FEEDBACK_KDF,
                        pParameter: &mut params as *mut _ as CK_VOID_PTR,
                        ulParameterLen: std::mem::size_of::<
                            CK_SP800_108_FEEDBACK_KDF_PARAMS,
                        >() as CK_ULONG,
                    };

                    let ret = fn_derive_key(
                        session,
                        &derive_mech as *const _ as CK_MECHANISM_PTR,
                        key_handle,
                        derive_template.as_ptr() as *mut _,
                        derive_template.len() as CK_ULONG,
                        &mut dk_handle,
                    );
                    if ret != CKR_OK {
                        panic!(
                            "Failed ({}) unit test at line {}",
                            ret, unit.line
                        );
                    }
                }
                _ => panic!("Invalid KDF mechanism {}", section.kdf),
            };

            let mut value = vec![0u8; unit.ko.len()];
            let mut extract_template =
                [make_attribute!(CKA_VALUE, value.as_mut_ptr(), value.len())];

            let ret = fn_get_attribute_value(
                session,
                dk_handle,
                extract_template.as_mut_ptr(),
                extract_template.len() as CK_ULONG,
            );
            assert_eq!(ret, CKR_OK);

            if value != unit.ko {
                panic!("Failed ({}) unit test at line {} - values differ [{} != {}]", ret, unit.line, hex::encode(value), hex::encode(unit.ko));
            }
        }
    }
}

#[test]
fn test_kdf_ctr_vector() {
    let test_data = parse_kdf_vector("testdata/KDFCTR_gen.txt");

    let mut testtokn = TestToken::initialized("test_kdf_ctr_vector.sql", None);
    let session = testtokn.get_session(false);

    /* login */
    testtokn.login();

    test_kdf_units(session, test_data);

    testtokn.finalize();
}

#[test]
fn test_kdf_feedback_vector() {
    let test_data = parse_kdf_vector("testdata/KDFFeedback_gen.txt");

    let mut testtokn =
        TestToken::initialized("test_kdf_feedback_vector.sql", None);
    let session = testtokn.get_session(false);

    /* login */
    testtokn.login();
    test_kdf_units(session, test_data);

    testtokn.finalize();
}
