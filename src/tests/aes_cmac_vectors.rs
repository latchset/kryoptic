// Copyright 2024 Simo Sorce
// See LICENSE.txt file for terms

use super::tests;
use tests::*;

use std::io;
use std::io::BufRead;

#[derive(Debug)]
struct TestUnit {
    line: usize,
    count: usize,
    klen: usize,
    mlen: usize,
    tlen: usize,
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

fn parse_buffer(s: &String, ln: usize, p: &str, len: usize) -> Option<Vec<u8>> {
    let prefix = p.len() + 3;
    if !s.starts_with(p) || !(&s[(prefix - 3)..prefix]).starts_with(" = ") {
        return None;
    }

    let v = parse_or_panic!(hex::decode(&s[prefix..]); s; ln);
    if v.len() != len {
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

fn parse_cmac_vector(filename: &str) -> Vec<TestUnit> {
    let file = ret_or_panic!(std::fs::File::open(filename));

    let mut data = Vec::<TestUnit>::new();

    for (l, line) in io::BufReader::new(file).lines().flatten().enumerate() {
        let ln = l + 1;
        if line.starts_with("#") {
            continue;
        }

        if line.len() == 0 {
            continue;
        }

        if line.starts_with("Count = ") {
            let unit = TestUnit {
                line: ln,
                count: (&line[8..]).parse().unwrap(),
                klen: 0,
                mlen: 0,
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

        if unit.mlen > 0 {
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

        /* create key */
        let key_handle = ret_or_panic!(import_object(
            session,
            CKO_SECRET_KEY,
            &[(CKA_KEY_TYPE, CKK_AES)],
            &[
                (CKA_VALUE, unit.key.as_slice()),
                (
                    CKA_LABEL,
                    format!(
                        "Key for AES CMAC, COUNT={}, line {}",
                        unit.count, unit.line
                    )
                    .as_bytes()
                )
            ],
            &[(CKA_SIGN, true), (CKA_VERIFY, true)],
        ));

        let size: CK_ULONG = unit.tlen as CK_ULONG;
        let mac = ret_or_panic!(sig_gen(
            session,
            key_handle,
            unit.msg.as_slice(),
            &CK_MECHANISM {
                mechanism: CKM_AES_CMAC_GENERAL,
                pParameter: void_ptr!(&size),
                ulParameterLen: CK_ULONG_SIZE as CK_ULONG,
            }
        ));
        if mac != unit.mac {
            panic!(
                "Failed unit test at line {} - values differ  [{} != {}]",
                unit.line,
                hex::encode(mac),
                hex::encode(unit.mac)
            );
        }
    }
}

#[test]
fn test_cmac_aes_128_vector() {
    let test_data = parse_cmac_vector("testdata/CMACGenAES128.rsp");

    let mut testtokn =
        TestToken::initialized("test_cmac_aes_128_vector.sql", None);
    let session = testtokn.get_session(false);

    /* login */
    testtokn.login();

    test_units(session, test_data);

    testtokn.finalize();
}

#[test]
fn test_cmac_aes_192_vector() {
    let test_data = parse_cmac_vector("testdata/CMACGenAES192.rsp");

    let mut testtokn =
        TestToken::initialized("test_cmac_aes_192_vector.sql", None);
    let session = testtokn.get_session(false);

    /* login */
    testtokn.login();

    test_units(session, test_data);

    testtokn.finalize();
}

#[test]
fn test_cmac_aes_256_vector() {
    let test_data = parse_cmac_vector("testdata/CMACGenAES256.rsp");

    let mut testtokn =
        TestToken::initialized("test_cmac_aes_256_vector.sql", None);
    let session = testtokn.get_session(false);

    /* login */
    testtokn.login();

    test_units(session, test_data);

    testtokn.finalize();
}
