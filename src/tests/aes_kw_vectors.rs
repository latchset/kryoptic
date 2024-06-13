// Copyright 2024 Simo Sorce
// See LICENSE.txt file for terms

use super::tests;
use tests::*;

use serial_test::parallel;
use std::io;
use std::io::BufRead;

#[derive(Debug)]
struct TestUnit {
    line: usize,
    count: usize,
    mech: CK_MECHANISM_TYPE,
    enc: bool,
    key: Vec<u8>,
    msg: Vec<u8>,
    wp: Vec<u8>,
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

fn parse_kw_vector(filename: &str) -> Vec<TestUnit> {
    let file = ret_or_panic!(std::fs::File::open(filename));

    let mut mech = CK_UNAVAILABLE_INFORMATION;
    let mut enc = 0; /* 1 encrypt, 2 decrypt */
    let mut keylen: isize = 1;
    let mut plen: isize = 0;

    let mut data = Vec::<TestUnit>::new();

    for (l, line) in io::BufReader::new(file).lines().flatten().enumerate() {
        let ln = l + 1;
        if line.starts_with("#") {
            if line.contains("KW-AE") {
                mech = CKM_AES_KEY_WRAP;
                enc = 1;
            } else if line.contains("KW-AD") {
                mech = CKM_AES_KEY_WRAP;
                enc = 2;
            } else if line.contains("KWP-AE") {
                mech = CKM_AES_KEY_WRAP_KWP;
                enc = 1;
            } else if line.contains("KWP-AD") {
                mech = CKM_AES_KEY_WRAP_KWP;
                enc = 2;
            }
            if line.contains("AES-128") {
                keylen = 16;
            } else if line.contains("AES-192") {
                keylen = 24;
            } else if line.contains("AES-256") {
                keylen = 32;
            }
            continue;
        }

        if line.len() == 0 {
            continue;
        }

        if line.starts_with("[PLAINTEXT LENGTH = ") {
            plen = (&line[20..(line.len() - 1)]).parse::<isize>().unwrap() / 8;
            continue;
        }

        if line.starts_with("COUNT = ") {
            let unit = TestUnit {
                line: ln,
                count: (&line[8..]).parse().unwrap(),
                mech: mech,
                enc: match enc {
                    1 => true,
                    2 => false,
                    _ => panic!("Undetermined E vs D operation"),
                },
                key: Vec::new(),
                msg: Vec::new(),
                wp: Vec::new(),
            };
            data.push(unit);
            continue;
        }

        let unit = match data.last_mut() {
            Some(u) => u,
            None => panic!("No unit defined (line {})", ln),
        };

        if let Some(v) = parse_buffer(&line, ln, "C", -1) {
            unit.wp = v;
            continue;
        }

        if let Some(v) = parse_buffer(&line, ln, "K", keylen) {
            unit.key = v;
            continue;
        }

        if let Some(v) = parse_buffer(&line, ln, "P", plen) {
            unit.msg = v;
            continue;
        }

        if line.starts_with("FAIL") {
            /* Happens only in Decryption vectors */
            unit.msg.clear();
        }
    }

    data
}

fn test_units(session: CK_SESSION_HANDLE, test_data: Vec<TestUnit>) {
    for unit in test_data {
        println!("Executing test at line {}", unit.line);

        /* create key */
        let key_handle = ret_or_panic!(import_object(
            session,
            CKO_SECRET_KEY,
            &[(CKA_KEY_TYPE, CKK_AES)],
            &[(CKA_VALUE, unit.key.as_slice())],
            &[(CKA_ENCRYPT, true), (CKA_DECRYPT, true)],
        ));

        if unit.enc {
            let enc = ret_or_panic!(encrypt(
                session,
                key_handle,
                unit.msg.as_slice(),
                &CK_MECHANISM {
                    mechanism: unit.mech,
                    pParameter: std::ptr::null_mut(),
                    ulParameterLen: 0,
                }
            ));

            if enc != unit.wp {
                panic!(
                    "Failed unit test at line {} - values differ  [{} != {}]",
                    unit.line,
                    hex::encode(enc),
                    hex::encode(unit.wp)
                );
            }
        } else {
            let ret = decrypt(
                session,
                key_handle,
                unit.wp.as_slice(),
                &CK_MECHANISM {
                    mechanism: unit.mech,
                    pParameter: std::ptr::null_mut(),
                    ulParameterLen: 0,
                },
            );
            match ret {
                Err(e) => {
                    if unit.msg.len() == 0 {
                        /* expected fail */
                        continue;
                    }
                    panic!("Error {} in unit test at line {}", e, unit.line);
                }
                Ok(dec) => {
                    if dec != unit.msg {
                        panic!(
                        "Failed unit test at line {} - values differ  [{} != {}]",
                        unit.line,
                        hex::encode(dec),
                        hex::encode(unit.msg)
                    );
                    }
                }
            }
        }
    }
}

fn test_kw_vector(mech: &str, op: &str, size: &str) {
    let name = format!("{}_{}_{}", mech, op, size);
    let test_data =
        parse_kw_vector(&format!("testdata/kwtestvectors/{}.txt", name));

    let sql_name = format!("test_{}_vector.sql", name);
    let mut testtokn = TestToken::initialized(&sql_name, None);
    let session = testtokn.get_session(false);

    /* login */
    testtokn.login();

    test_units(session, test_data);

    testtokn.finalize();
}

#[test]
#[parallel]
fn test_kw_ae_128_vector() {
    test_kw_vector("KW", "AE", "128")
}

#[test]
#[parallel]
fn test_kw_ae_192_vector() {
    test_kw_vector("KW", "AE", "192")
}

#[test]
#[parallel]
fn test_kw_ae_256_vector() {
    test_kw_vector("KW", "AE", "256")
}

#[test]
#[parallel]
fn test_kw_ad_128_vector() {
    test_kw_vector("KW", "AD", "128")
}

#[test]
#[parallel]
fn test_kw_ad_192_vector() {
    test_kw_vector("KW", "AD", "192")
}

#[test]
#[parallel]
fn test_kw_ad_256_vector() {
    test_kw_vector("KW", "AD", "256")
}

#[test]
#[parallel]
fn test_kwp_ae_128_vector() {
    test_kw_vector("KWP", "AE", "128")
}

#[test]
#[parallel]
fn test_kwp_ae_192_vector() {
    test_kw_vector("KWP", "AE", "192")
}

#[test]
#[parallel]
fn test_kwp_ae_256_vector() {
    test_kw_vector("KWP", "AE", "256")
}

#[test]
#[parallel]
fn test_kwp_ad_128_vector() {
    test_kw_vector("KWP", "AD", "128")
}

#[test]
#[parallel]
fn test_kwp_ad_192_vector() {
    test_kw_vector("KWP", "AD", "192")
}

#[test]
#[parallel]
fn test_kwp_ad_256_vector() {
    test_kw_vector("KWP", "AD", "256")
}
