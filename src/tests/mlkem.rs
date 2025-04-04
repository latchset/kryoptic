// Copyright 2025 Simo Sorce
// See LICENSE.txt file for terms

use crate::tests::*;
use serde_json::{from_reader, Value};

use serial_test::parallel;

#[test]
#[parallel]
fn test_mlkem_operations() {
    let mut testtokn = TestToken::initialized("test_mlkem_operations", None);

    let session = testtokn.get_session(true);

    /* login */
    testtokn.login();

    /* key from
     * https://github.com/usnistgov/ACVP-Server/blob/master/gen-val/json-files/ML-KEM-encapDecap-FIPS203/internalProjection.json
     */

    /* public key data */
    let ek = hex::decode(
        "A5F799D57B310740345CF77783B5013D540F557143443A5402B1255A5B043772\
         7113E26B516C2BB899BF1178BE7531636E810B84938DF0B95197540A39289DC3\
         C91CA3E8201A37101221922D5A2E59719F97375D30339196F10F7E986FDD4BC2\
         7E192FEE7654F85CAB2B01AF2E52AA5420295D6429CF5B93981AACEF634DD3B0\
         55F479B72FA45B012433A16939438641245C7113951E42A78399DB1B3451AC31\
         7552440322B93577D1C0A03BC02875F0B3E93A9A24E503DED4BF9B095F002386\
         7122BFFB16785E25BAB9D19670797A5EA812CE22B7E1DB2BFED18F513625DA43\
         4E4D1A07827277386448EEAB09A7395C0CB780EA152989D429C1AC4187C21B90\
         1CB535298AE1753BC42C33BC009839E254C1D61C1CFB5ED4C34446CBCFAC3393\
         5FAC22019498E1F8610BE012BFD637D4D330EA688D384A2AAEBC58B6E389B1B8\
         263DC773A3D989D4A768EFEB74A3643B523947881CABFF7A7A22839572CC4584\
         1147F4C25AD590B834C3B65A9B8F4F35988E36551FD7C9ABF9C0AAE225760744\
         BF937B4DC7B701E86C99D0B87F024B03F9651A58A075C321840B51ADEA90502C\
         9757272FF45C8EA9302013A0BF23864ADB55762332C59C73023D8699FD15CBD8\
         1185292996B67155ADFA5A6FB51904B626320417239317CFCA687F585F9CFABC\
         78BC08C7128405486D3AA88181C7116B114FDD3004E337B5D25B6AF2B69D0AE1\
         BDA696A688B7C5189CC7E5F941C397474CA09D8178B99E1BB2CA590A11E08BAD\
         F18F31A14E7E24CEDA79BB94D7062FB95555283E4C4232C0E5B9E1A970DBA176\
         F9206F1BBBCB082ABB9D6457FEB87B9E977BA1FCC846B0317F084CC0890C7B3B\
         B1A70541BEC77183D62440139EECCC9F543218A2757006133E0C27877BA06A5D\
         691485010938A96E29B249D19C164EE07CDF67129A1136A82C9E8DD05CB80693\
         00DBC78DD5192C385C2A005ED4D5CE22928A6DB6A68044511F4193A45796E04C\
         C03E832EFD8AB15C4C5F16CB84BA848A72E09D88777F3B969972D21FD4F60E12\
         71579D32AB9A1012C9DB0D3204AAF0347925AC89B256B6AA5073CDE02584E602\
         6ADED3696366D43E5543362749864CDB22E69A18B0124A609BE9D1A0F93C3603",
    )
    .expect("failed to decode ML-KEM public key");
    let pub_handle = ret_or_panic!(import_object(
        session,
        CKO_PUBLIC_KEY,
        &[
            (CKA_KEY_TYPE, CKK_ML_KEM),
            (CKA_PARAMETER_SET, CKP_ML_KEM_512),
        ],
        &[
            (CKA_VALUE, &ek),
            (CKA_LABEL, format!("ML-KEM public key").as_bytes()),
        ],
        &[(CKA_ENCAPSULATE, true)],
    ));

    /* private key data */
    let pk = hex::decode(
        "3DFA5F5E21AA779467BB294C5A06A47249A2D6FB1A1B489F75985430B64729F9\
         1AD5C085F762734F98A3CA26CB0594AB31129B67AB76FE302C72C99F806644B2\
         334AD2E7CC72F0A429D34906A35088C1372202706875466E4AA9061612E2E17A\
         5C1C3CB696B0F486383EE4BE680BA7618AB48F78AE93E6834FC4BE2E67749641\
         9772B53842083AC3C6923531B46242189A5CA099564E16E3584BF42AA3418C4C\
         779D81B34B5EDAC3E6560E58FA34C008843FE50D8932B1F662C6103A150C1C2D\
         89B40DA0DA049D9AA21EC0548BD74ACC5599D4D36F29D6B5AB90C37663A2E920\
         0D9D2A06A8E43166E614F697670A9B0958F9C0FEC7ABDE267F8D723DE9193A6A\
         B1083D9279810C46DE251FFC7185DF843FAD708844036B10B74604EBBD182869\
         50906288AB444950C7B7D9766F01B46049A55777A5A1A2BC47D15FC61B8E6A98\
         4167120187D6CA2CF3134A5971A8D8B78927687AE6B7B9A28CA73127A8495AFA\
         4044AFFC147E97BDB435335914113E903FFED18DFF5A64B7D47D04F9566F1C10\
         4D02552B0A346FEC2A65FBA45EC1B32EF4BFEB78485393597CE799802309DD2C\
         85C890968D08A043F56A6B9636394A117B50287E266D65F06E0055BD87F5482B\
         5739DDA6494ADAA8B32AA6FE440DC116969CF1A0DC53C25441313A0B0BB55139\
         6B374BA5C3AD1C7A4323E0C2B009810E0338D102AA010C9E53278BE7C955C840\
         A9C7D5CAB1782E05DC4F114C1AACBA8BB0B0A144C557828A783428538396263D\
         E90D2BC218CF16ACDB33C012888A68B70BF1AC0FFA81AB20716F800805CED967\
         90520ECBC22D127A5246064D24924B715C072D61A5537C5CD8D04FDE175A87C4\
         657DB2CEF283B69805397F601FCDAC5FBF14AFE65493C152A3411138FA3259F4\
         BC4954C9234442C3A37C486E374174A841CB400B40CB514074B17B75B297ABA4\
         F2F415937630C4B7ADD5389C6FC29331F46B35771BB8349C33CB3428C46406F9\
         1F244926D0B51F66E105E3B74467C108F6A21A5A302F0D48217FF587D2B61597\
         3A6A2F66A44EE53427C583D351C8AC93356695CCD075398AF34DA3AB931FDA18\
         A5F799D57B310740345CF77783B5013D540F557143443A5402B1255A5B043772\
         7113E26B516C2BB899BF1178BE7531636E810B84938DF0B95197540A39289DC3\
         C91CA3E8201A37101221922D5A2E59719F97375D30339196F10F7E986FDD4BC2\
         7E192FEE7654F85CAB2B01AF2E52AA5420295D6429CF5B93981AACEF634DD3B0\
         55F479B72FA45B012433A16939438641245C7113951E42A78399DB1B3451AC31\
         7552440322B93577D1C0A03BC02875F0B3E93A9A24E503DED4BF9B095F002386\
         7122BFFB16785E25BAB9D19670797A5EA812CE22B7E1DB2BFED18F513625DA43\
         4E4D1A07827277386448EEAB09A7395C0CB780EA152989D429C1AC4187C21B90\
         1CB535298AE1753BC42C33BC009839E254C1D61C1CFB5ED4C34446CBCFAC3393\
         5FAC22019498E1F8610BE012BFD637D4D330EA688D384A2AAEBC58B6E389B1B8\
         263DC773A3D989D4A768EFEB74A3643B523947881CABFF7A7A22839572CC4584\
         1147F4C25AD590B834C3B65A9B8F4F35988E36551FD7C9ABF9C0AAE225760744\
         BF937B4DC7B701E86C99D0B87F024B03F9651A58A075C321840B51ADEA90502C\
         9757272FF45C8EA9302013A0BF23864ADB55762332C59C73023D8699FD15CBD8\
         1185292996B67155ADFA5A6FB51904B626320417239317CFCA687F585F9CFABC\
         78BC08C7128405486D3AA88181C7116B114FDD3004E337B5D25B6AF2B69D0AE1\
         BDA696A688B7C5189CC7E5F941C397474CA09D8178B99E1BB2CA590A11E08BAD\
         F18F31A14E7E24CEDA79BB94D7062FB95555283E4C4232C0E5B9E1A970DBA176\
         F9206F1BBBCB082ABB9D6457FEB87B9E977BA1FCC846B0317F084CC0890C7B3B\
         B1A70541BEC77183D62440139EECCC9F543218A2757006133E0C27877BA06A5D\
         691485010938A96E29B249D19C164EE07CDF67129A1136A82C9E8DD05CB80693\
         00DBC78DD5192C385C2A005ED4D5CE22928A6DB6A68044511F4193A45796E04C\
         C03E832EFD8AB15C4C5F16CB84BA848A72E09D88777F3B969972D21FD4F60E12\
         71579D32AB9A1012C9DB0D3204AAF0347925AC89B256B6AA5073CDE02584E602\
         6ADED3696366D43E5543362749864CDB22E69A18B0124A609BE9D1A0F93C3603\
         CD5EAB26522E637FD086CE652D0ED7EA525DBC304FC9A5ED64809AAC797964D5\
         C15FFEF9931AAEE0388863CFBD3310B501930CC545C9891CF103509F88A9300E",
    )
    .expect("failed to decode ML-KEM private key");
    let priv_handle = ret_or_panic!(import_object(
        session,
        CKO_PRIVATE_KEY,
        &[
            (CKA_KEY_TYPE, CKK_ML_KEM),
            (CKA_PARAMETER_SET, CKP_ML_KEM_512),
        ],
        &[
            (CKA_VALUE, &pk),
            (CKA_LABEL, format!("ML-KEM private key").as_bytes()),
        ],
        &[(CKA_DECAPSULATE, true)],
    ));

    let key_template = make_attr_template(
        &[
            (CKA_CLASS, CKO_SECRET_KEY),
            (CKA_KEY_TYPE, CKK_AES),
            (CKA_VALUE_LEN, 16),
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
        mechanism: CKM_ML_KEM,
        pParameter: std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    let mut ciphertext = [0u8; 800];
    let mut outlen: CK_ULONG = 800;
    let mut handle_enc = CK_INVALID_HANDLE;
    let ret = fn_encapsulate_key(
        session,
        &mut mechanism,
        pub_handle,
        key_template.as_ptr() as *mut _,
        key_template.len() as CK_ULONG,
        ciphertext.as_mut_ptr(),
        &mut outlen,
        &mut handle_enc,
    );
    assert_eq!(ret, CKR_OK);

    let mut handle_dec = CK_INVALID_HANDLE;
    let ret = fn_decapsulate_key(
        session,
        &mut mechanism,
        priv_handle,
        key_template.as_ptr() as *mut _,
        key_template.len() as CK_ULONG,
        ciphertext.as_mut_ptr(),
        outlen,
        &mut handle_dec,
    );
    assert_eq!(ret, CKR_OK);

    let mut value_enc = vec![0u8; 16];
    let mut extract_template_enc = make_ptrs_template(&[(
        CKA_VALUE,
        void_ptr!(value_enc.as_mut_ptr()),
        value_enc.len(),
    )]);

    let ret = fn_get_attribute_value(
        session,
        handle_enc,
        extract_template_enc.as_mut_ptr(),
        extract_template_enc.len() as CK_ULONG,
    );
    assert_eq!(ret, CKR_OK);

    let mut value_dec = vec![0u8; 16];
    let mut extract_template_dec = make_ptrs_template(&[(
        CKA_VALUE,
        void_ptr!(value_dec.as_mut_ptr()),
        value_dec.len(),
    )]);

    let ret = fn_get_attribute_value(
        session,
        handle_dec,
        extract_template_dec.as_mut_ptr(),
        extract_template_dec.len() as CK_ULONG,
    );
    assert_eq!(ret, CKR_OK);

    assert_eq!(value_enc, value_dec);

    /* try operation with wrong key */
    let ret = fn_encapsulate_key(
        session,
        &mut mechanism,
        priv_handle,
        key_template.as_ptr() as *mut _,
        key_template.len() as CK_ULONG,
        ciphertext.as_mut_ptr(),
        &mut outlen,
        &mut handle_enc,
    );
    assert_eq!(ret, CKR_KEY_TYPE_INCONSISTENT);

    /* try again with key generation first */
    let (pub_handle, priv_handle) = ret_or_panic!(generate_key_pair(
        session,
        CKM_ML_KEM_KEY_PAIR_GEN,
        &[
            (CKA_CLASS, CKO_PUBLIC_KEY),
            (CKA_KEY_TYPE, CKK_ML_KEM),
            (CKA_PARAMETER_SET, CKP_ML_KEM_512)
        ],
        &[],
        &[(CKA_ENCAPSULATE, true)],
        &[
            (CKA_CLASS, CKO_PRIVATE_KEY),
            (CKA_KEY_TYPE, CKK_ML_KEM),
            (CKA_PARAMETER_SET, CKP_ML_KEM_512)
        ],
        &[],
        &[(CKA_DECAPSULATE, true),],
    ));

    let ret = fn_encapsulate_key(
        session,
        &mut mechanism,
        pub_handle,
        key_template.as_ptr() as *mut _,
        key_template.len() as CK_ULONG,
        ciphertext.as_mut_ptr(),
        &mut outlen,
        &mut handle_enc,
    );
    assert_eq!(ret, CKR_OK);

    let ret = fn_decapsulate_key(
        session,
        &mut mechanism,
        priv_handle,
        key_template.as_ptr() as *mut _,
        key_template.len() as CK_ULONG,
        ciphertext.as_mut_ptr(),
        outlen,
        &mut handle_dec,
    );
    assert_eq!(ret, CKR_OK);

    let ret = fn_get_attribute_value(
        session,
        handle_enc,
        extract_template_enc.as_mut_ptr(),
        extract_template_enc.len() as CK_ULONG,
    );
    assert_eq!(ret, CKR_OK);

    let ret = fn_get_attribute_value(
        session,
        handle_dec,
        extract_template_dec.as_mut_ptr(),
        extract_template_dec.len() as CK_ULONG,
    );
    assert_eq!(ret, CKR_OK);

    assert_eq!(value_enc, value_dec);

    /* try operation with wrong ciphertext */
    let mut ciphertext = [42u8; 800];
    let ret = fn_decapsulate_key(
        session,
        &mut mechanism,
        priv_handle,
        key_template.as_ptr() as *mut _,
        key_template.len() as CK_ULONG,
        ciphertext.as_mut_ptr(),
        outlen,
        &mut handle_dec,
    );
    assert_eq!(ret, CKR_OK);

    let ret = fn_get_attribute_value(
        session,
        handle_dec,
        extract_template_dec.as_mut_ptr(),
        extract_template_dec.len() as CK_ULONG,
    );
    assert_eq!(ret, CKR_OK);

    assert_ne!(value_enc, value_dec);
}

fn test_groups(session: CK_SESSION_HANDLE, data: Value) {
    let mut mechanism: CK_MECHANISM = CK_MECHANISM {
        mechanism: CKM_ML_KEM,
        pParameter: std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    let key_template = make_attr_template(
        &[
            (CKA_CLASS, CKO_SECRET_KEY),
            (CKA_KEY_TYPE, CKK_GENERIC_SECRET),
        ],
        &[],
        &[(CKA_SENSITIVE, false), (CKA_EXTRACTABLE, true)],
    );

    let test_groups: &Vec<Value> = match data["testGroups"].as_array() {
        Some(g) => g,
        None => panic!("No testGroups value"),
    };
    for group in test_groups {
        let gnum = match group["tgId"].as_u64() {
            Some(n) => n,
            None => panic!("No tgId value"),
        };
        match group["testType"].as_str() {
            Some(s) => {
                if s != "AFT" {
                    continue;
                }
            }
            None => panic!("No testType value"),
        }
        let parameter_set = match group["parameterSet"].as_str() {
            Some(p) => p,
            None => panic!("No parameterSet value"),
        };
        println!("Executing Test group: {}, paramset:{}", gnum, parameter_set);
        let ckp = if parameter_set == "ML-KEM-512" {
            CKP_ML_KEM_512
        } else if parameter_set == "ML-KEM-768" {
            CKP_ML_KEM_768
        } else if parameter_set == "ML-KEM-1024" {
            CKP_ML_KEM_1024
        } else {
            println!("Unknown set, skipping!");
            continue;
        };

        let tests = match group["tests"].as_array() {
            Some(t) => t,
            None => panic!("No tests value"),
        };
        for test in tests {
            let tnum = match test["tcId"].as_u64() {
                Some(n) => n,
                None => panic!("No tcId value"),
            };
            println!("Executing Test: {}", tnum);

            /* only positive test for now */
            match test["reason"].as_str() {
                Some(r) => {
                    if r != "valid decapsulation" {
                        println!("Skipping fail test with reason: {}", r);
                        continue;
                    }
                }
                None => panic!("No reason value"),
            }

            /* we check only decapsulation here, sop no need for the public key */
            let dk = if let Some(dk_str) = test["dk"].as_str() {
                hex::decode(dk_str)
                    .expect("failed to decode ML-KEM private key")
            } else {
                panic!("no dk value");
            };
            let ciphertext = if let Some(ct_str) = test["c"].as_str() {
                hex::decode(ct_str).expect("failed to decode ciphertext")
            } else {
                panic!("no c value");
            };
            let keyval = if let Some(k_str) = test["k"].as_str() {
                hex::decode(k_str).expect("failed to decode key value")
            } else {
                panic!("no k value");
            };

            let priv_handle = ret_or_panic!(import_object(
                session,
                CKO_PRIVATE_KEY,
                &[(CKA_KEY_TYPE, CKK_ML_KEM), (CKA_PARAMETER_SET, ckp),],
                &[(CKA_VALUE, &dk)],
                &[(CKA_DECAPSULATE, true)],
            ));

            let mut handle_dec = CK_INVALID_HANDLE;
            let ret = fn_decapsulate_key(
                session,
                &mut mechanism,
                priv_handle,
                key_template.as_ptr() as *mut _,
                key_template.len() as CK_ULONG,
                ciphertext.as_ptr() as *mut _,
                ciphertext.len() as CK_ULONG,
                &mut handle_dec,
            );
            assert_eq!(ret, CKR_OK);

            let mut value_dec = vec![0u8; keyval.len()];
            let mut extract_template_dec = make_ptrs_template(&[(
                CKA_VALUE,
                void_ptr!(value_dec.as_mut_ptr()),
                value_dec.len(),
            )]);

            let ret = fn_get_attribute_value(
                session,
                handle_dec,
                extract_template_dec.as_mut_ptr(),
                extract_template_dec.len() as CK_ULONG,
            );
            assert_eq!(ret, CKR_OK);

            assert_eq!(keyval, value_dec);
        }
    }
}

#[test]
#[parallel]
fn test_mlkem_decap_vector() {
    let file = std::fs::File::open("testdata/acvp-ml-kem-decap.json").unwrap();
    let data = from_reader(file).unwrap();

    let mut testtokn = TestToken::initialized("test_mlkem_decap_vector", None);
    let session = testtokn.get_session(false);

    /* login */
    testtokn.login();

    test_groups(session, data);

    testtokn.finalize();
}
