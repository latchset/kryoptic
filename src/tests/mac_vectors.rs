// Copyright 2024 Simo Sorce
// See LICENSE.txt file for terms

use std::io;
use std::io::BufRead;

use crate::tests::*;

use serial_test::parallel;

#[derive(Debug)]
struct TestUnit {
    mech: CK_MECHANISM_TYPE,
    line: usize,
    count: usize,
    klen: isize,
    mlen: isize,
    tlen: isize,
    key: Vec<u8>,
    msg: Vec<u8>,
    mac: Vec<u8>,
}

fn parse_number<T: std::str::FromStr>(
    s: &String,
    ln: usize,
    p: &str,
) -> Option<T> {
    let prefix = p.len() + 3;
    if !s.starts_with(p) || !(&s[(prefix - 3)..prefix]).starts_with(" = ") {
        return None;
    }

    /* some vectors have trailing spaces that break parse() */
    let line = s.as_bytes();
    let mut end = line.len();
    if !line[end - 1].is_ascii_digit() {
        while end > prefix {
            end -= 1;
            if line[end - 1].is_ascii_digit() {
                break;
            }
        }
    }
    Some(parse_or_panic!((&s[prefix..end]).parse::<T>(); s; ln))
}

fn parse_buffer(s: &String, ln: usize, p: &str, len: isize) -> Option<Vec<u8>> {
    let prefix = p.len() + 3;
    if !s.starts_with(p) || !(&s[(prefix - 3)..prefix]).starts_with(" = ") {
        return None;
    }

    let v = parse_or_panic!(hex::decode(&s[prefix..]); s; ln);
    if len != -1 && v.len() != len as usize {
        panic!(
            "Length of {} ({}) does not match specified length: {} (line {})",
            p,
            v.len(),
            len,
            ln
        );
    }
    Some(v)
}

fn parse_mac_vector(filename: &str) -> Vec<TestUnit> {
    let file = ret_or_panic!(std::fs::File::open(filename));

    /* 0 undetermined, 1 CMAC, 2 HMAC */
    let mut mac_type = 0;
    let mut mech = CK_UNAVAILABLE_INFORMATION;
    let mut data = Vec::<TestUnit>::new();

    for (l, line) in io::BufReader::new(file).lines().flatten().enumerate() {
        let ln = l + 1;
        if line.starts_with("#") {
            if mac_type == 0 {
                if line.contains("CMAC") {
                    mac_type = 1;
                } else if line.contains("HMAC") {
                    mac_type = 2;
                }
            } else if mac_type == 1 {
                if line.contains("Alg = AES") {
                    mech = CKM_AES_CMAC_GENERAL;
                }
            }
            continue;
        }

        if line.len() == 0 {
            continue;
        }

        if line.starts_with("[L=") {
            if line.contains("[L=20]") {
                mech = CKM_SHA_1_HMAC_GENERAL;
            } else if line.contains("[L=28]") {
                mech = CKM_SHA224_HMAC_GENERAL;
            } else if line.contains("[L=32]") {
                mech = CKM_SHA256_HMAC_GENERAL;
            } else if line.contains("[L=48]") {
                mech = CKM_SHA384_HMAC_GENERAL;
            } else if line.contains("[L=64]") {
                mech = CKM_SHA512_HMAC_GENERAL;
            } else {
                panic!("Unknown HMAC Length: {} (line {})", line, ln);
            }
            continue;
        }

        if line.starts_with("Count = ") {
            let unit = TestUnit {
                mech: mech,
                line: ln,
                count: (&line[8..]).parse().unwrap(),
                klen: 0,
                /* in HMAC vectors there is no Mlen ... */
                mlen: if mac_type == 2 { -1 } else { 0 },
                tlen: 0,
                key: Vec::new(),
                msg: Vec::new(),
                mac: Vec::new(),
            };
            data.push(unit);
            continue;
        }

        let unit = match data.last_mut() {
            Some(u) => u,
            None => panic!("No unit defined (line {})", ln),
        };

        if let Some(v) = parse_number(&line, ln, "Klen") {
            unit.klen = v;
            continue;
        }

        if let Some(v) = parse_number(&line, ln, "Mlen") {
            unit.mlen = v;
            continue;
        }

        if let Some(v) = parse_number(&line, ln, "Tlen") {
            unit.tlen = v;
            continue;
        }

        if let Some(v) = parse_buffer(&line, ln, "Key", unit.klen) {
            unit.key = v;
            continue;
        }

        if unit.mlen != 0 {
            if let Some(v) = parse_buffer(&line, ln, "Msg", unit.mlen) {
                unit.msg = v;
                continue;
            }
        }

        if let Some(v) = parse_buffer(&line, ln, "Mac", unit.tlen) {
            unit.mac = v;
            continue;
        }
    }

    data
}

fn test_units(session: CK_SESSION_HANDLE, test_data: Vec<TestUnit>) {
    for unit in test_data {
        println!("Executing test at line {}", unit.line);

        let key_type = if unit.mech == CKM_AES_CMAC_GENERAL {
            CKK_AES
        } else {
            CKK_GENERIC_SECRET
        };

        /* create key */
        let key_handle = ret_or_panic!(import_object(
            session,
            CKO_SECRET_KEY,
            &[(CKA_KEY_TYPE, key_type)],
            &[(CKA_VALUE, unit.key.as_slice())],
            &[(CKA_SIGN, true), (CKA_VERIFY, true)],
        ));

        let size: CK_ULONG = unit.tlen as CK_ULONG;
        let mac = ret_or_panic!(sig_gen(
            session,
            key_handle,
            unit.msg.as_slice(),
            &CK_MECHANISM {
                mechanism: unit.mech,
                pParameter: void_ptr!(&size),
                ulParameterLen: CK_ULONG_SIZE as CK_ULONG,
            }
        ));
        if mac != unit.mac {
            panic!(
                "Failed unit test {} at line {} - values differ  [{} != {}]",
                unit.count,
                unit.line,
                hex::encode(mac),
                hex::encode(unit.mac)
            );
        }
    }
}

#[test]
#[parallel]
fn test_cmac_aes_128_vector() {
    let test_data = parse_mac_vector("testdata/CMACGenAES128.rsp");

    let mut testtokn =
        TestToken::initialized("test_cmac_aes_128_vector.sql", None);
    let session = testtokn.get_session(false);

    /* login */
    testtokn.login();

    test_units(session, test_data);

    testtokn.finalize();
}

#[test]
#[parallel]
fn test_cmac_aes_192_vector() {
    let test_data = parse_mac_vector("testdata/CMACGenAES192.rsp");

    let mut testtokn =
        TestToken::initialized("test_cmac_aes_192_vector.sql", None);
    let session = testtokn.get_session(false);

    /* login */
    testtokn.login();

    test_units(session, test_data);

    testtokn.finalize();
}

#[test]
#[parallel]
fn test_cmac_aes_256_vector() {
    let test_data = parse_mac_vector("testdata/CMACGenAES256.rsp");

    let mut testtokn =
        TestToken::initialized("test_cmac_aes_256_vector.sql", None);
    let session = testtokn.get_session(false);

    /* login */
    testtokn.login();

    test_units(session, test_data);

    testtokn.finalize();
}

#[test]
#[parallel]
fn test_hmac_vector() {
    let test_data = parse_mac_vector("testdata/HMAC.rsp");
    let mut testtokn = TestToken::initialized("test_hmac_vector.sql", None);
    let session = testtokn.get_session(false);

    /* login */
    testtokn.login();

    test_units(session, test_data);

    testtokn.finalize();
}
