// Copyright 2024 Simo Sorce
// See LICENSE.txt file for terms

use super::tests;
use tests::*;

#[test]
fn test_copy_objects() {
    let mut testtokn = TestToken::initialized("test_copy_objects.sql", None);
    let session = testtokn.get_session(false);

    /* login */
    testtokn.login();

    /* public key data */
    let mut handle: CK_ULONG = CK_INVALID_HANDLE;
    let mut template = vec![make_attribute!(
        CKA_UNIQUE_ID,
        CString::new("2").unwrap().into_raw(),
        1
    )];
    let ret = fn_find_objects_init(session, template.as_mut_ptr(), 1);
    assert_eq!(ret, CKR_OK);
    let mut count: CK_ULONG = 0;
    let ret = fn_find_objects(session, &mut handle, 1, &mut count);
    assert_eq!(ret, CKR_OK);
    assert_eq!(count, 1);
    assert_ne!(handle, CK_INVALID_HANDLE);
    let ret = fn_find_objects_final(session);
    assert_eq!(ret, CKR_OK);

    /* copy token object to session object */
    let mut intoken: CK_BBOOL = CK_FALSE;
    let mut private: CK_BBOOL = CK_TRUE;
    let mut template = vec![
        make_attribute!(CKA_TOKEN, &mut intoken as *mut _, CK_BBOOL_SIZE),
        make_attribute!(CKA_PRIVATE, &mut private as *mut _, CK_BBOOL_SIZE),
    ];
    let mut handle2: CK_ULONG = CK_INVALID_HANDLE;
    let ret = fn_copy_object(
        session,
        handle,
        template.as_mut_ptr(),
        template.len() as CK_ULONG,
        &mut handle2,
    );
    assert_eq!(ret, CKR_OK);

    /* make not copyable object */
    let mut class = CKO_DATA;
    let mut copyable: CK_BBOOL = CK_FALSE;
    let application = "nocopy";
    let data = "data";
    let mut template = vec![
        make_attribute!(CKA_CLASS, &mut class as *mut _, CK_ULONG_SIZE),
        make_attribute!(CKA_COPYABLE, &mut copyable as *mut _, CK_BBOOL_SIZE),
        make_attribute!(
            CKA_APPLICATION,
            CString::new(application).unwrap().into_raw(),
            application.len()
        ),
        make_attribute!(
            CKA_VALUE,
            CString::new(data).unwrap().into_raw(),
            data.len()
        ),
    ];
    let mut handle: CK_ULONG = CK_INVALID_HANDLE;
    let ret = fn_create_object(
        session,
        template.as_mut_ptr(),
        template.len() as CK_ULONG,
        &mut handle,
    );
    assert_eq!(ret, CKR_OK);

    /* copy token object to session object */
    let mut intoken: CK_BBOOL = CK_FALSE;
    let mut template = vec![make_attribute!(
        CKA_TOKEN,
        &mut intoken as *mut _,
        CK_BBOOL_SIZE
    )];
    let mut handle2: CK_ULONG = CK_INVALID_HANDLE;
    let ret = fn_copy_object(
        session,
        handle,
        template.as_mut_ptr(),
        template.len() as CK_ULONG,
        &mut handle2,
    );
    assert_eq!(ret, CKR_ACTION_PROHIBITED);

    testtokn.finalize();
}

#[test]
fn test_create_objects() {
    let mut testtokn = TestToken::initialized("test_create_objects.sql", None);
    let session = testtokn.get_session(false);

    let mut class = CKO_DATA;
    let application = "test";
    let data = "payload";
    let mut template = vec![
        make_attribute!(CKA_CLASS, &mut class as *mut _, CK_ULONG_SIZE),
        make_attribute!(
            CKA_APPLICATION,
            CString::new(application).unwrap().into_raw(),
            application.len()
        ),
        make_attribute!(
            CKA_VALUE,
            CString::new(data).unwrap().into_raw(),
            data.len()
        ),
    ];

    let mut handle: CK_ULONG = CK_INVALID_HANDLE;
    let ret = fn_create_object(
        session,
        template.as_mut_ptr(),
        template.len() as CK_ULONG,
        &mut handle,
    );
    assert_eq!(ret, CKR_USER_NOT_LOGGED_IN);

    /* login */
    testtokn.login();

    let ret = fn_create_object(
        session,
        template.as_mut_ptr(),
        template.len() as CK_ULONG,
        &mut handle,
    );
    assert_eq!(ret, CKR_OK);

    let mut intoken: CK_BBOOL = CK_TRUE;
    template.push(make_attribute!(
        CKA_TOKEN,
        &mut intoken as *mut _,
        CK_BBOOL_SIZE
    ));

    let ret = fn_create_object(
        session,
        template.as_mut_ptr(),
        template.len() as CK_ULONG,
        &mut handle,
    );
    assert_eq!(ret, CKR_SESSION_READ_ONLY);

    let session = testtokn.get_session(true);

    let ret = fn_create_object(
        session,
        template.as_mut_ptr(),
        template.len() as CK_ULONG,
        &mut handle,
    );
    assert_eq!(ret, CKR_OK);

    class = CKO_CERTIFICATE;
    let mut ctype = CKC_X_509;
    let mut trusted: CK_BBOOL = CK_FALSE;
    let ignored = "ignored";
    let bogus = "bogus";
    template = vec![
        make_attribute!(CKA_CLASS, &mut class as *mut _, CK_ULONG_SIZE),
        make_attribute!(CKA_TOKEN, &mut intoken as *mut _, CK_BBOOL_SIZE),
        make_attribute!(
            CKA_CERTIFICATE_TYPE,
            &mut ctype as *mut _,
            CK_ULONG_SIZE
        ),
        make_attribute!(CKA_TRUSTED, &mut trusted as *mut _, CK_BBOOL_SIZE),
        make_attribute!(CKA_CHECK_VALUE, ignored.as_ptr(), 42),
        make_attribute!(CKA_SUBJECT, bogus.as_ptr(), bogus.len()),
        make_attribute!(CKA_VALUE, bogus.as_ptr(), bogus.len()),
    ];

    let ret = fn_create_object(
        session,
        template.as_mut_ptr(),
        template.len() as CK_ULONG,
        &mut handle,
    );
    assert_eq!(ret, CKR_OK);

    class = CKO_PUBLIC_KEY;
    let mut ktype = CKK_RSA;
    let mut encrypt: CK_BBOOL = CK_TRUE;
    let label = "RSA Public Encryption Key";
    let modulus_hex = "9D2E7820CE719B9194CDFE0FD751214193C4E9BE9BFA24D0E91B0FC3541C85885CB3CA95F8FDA4E129558EE41F653481E66A04ECB75808D57BD76ED9069767A2AFC9C3188F2BD42F045D0575765ADE27AD033B338DD5C2C1AAA899B89201A34BBB6ED9CCD0511325ADCF1C69718BD27196447D567F17E35A5865A3BC1FB35B3A605C25294D2A02E5F53D170C57814D8246F50CAE32321D8A5C44508238AC50519BD12221C740620198B762C2D1670A4B94655C783EAAD0E9A1244F8AE86D3B4A3DF26AC532B6A4EAA4FB4A35DF5C3A1B755DC5C17E451643D2DB722113C1E3E2CA59CFA592C80FB9B2D7056E19F5C84198371465CE7DFBA7390C3CE19D878121";
    let modulus =
        hex::decode(modulus_hex).expect("Failed to decode hex modulus");
    let exponent = hex::decode("010001").expect("Failed to decode exponent");
    template = vec![
        make_attribute!(CKA_CLASS, &mut class as *mut _, CK_ULONG_SIZE),
        make_attribute!(CKA_KEY_TYPE, &mut ktype as *mut _, CK_ULONG_SIZE),
        make_attribute!(CKA_ENCRYPT, &mut encrypt as *mut _, CK_BBOOL_SIZE),
        make_attribute!(
            CKA_LABEL,
            label.as_ptr() as *mut std::ffi::c_void,
            label.len()
        ),
        make_attribute!(
            CKA_MODULUS,
            modulus.as_ptr() as *mut std::ffi::c_void,
            modulus.len()
        ),
        make_attribute!(
            CKA_PUBLIC_EXPONENT,
            exponent.as_ptr() as *mut std::ffi::c_void,
            exponent.len()
        ),
    ];

    let ret = fn_create_object(
        session,
        template.as_mut_ptr(),
        template.len() as CK_ULONG,
        &mut handle,
    );
    assert_eq!(ret, CKR_OK);

    /* Private RSA Key with missing Q,A,B parameters */
    class = CKO_PRIVATE_KEY;
    let mut ktype = CKK_RSA;
    let mut encrypt: CK_BBOOL = CK_TRUE;
    let label = "RSA Private Key";
    let modulus = hex::decode("9d2e7820ce719b9194cdfe0fd751214193c4e9be9bfa24d0e91b0fc3541c85885cb3ca95f8fda4e129558ee41f653481e66a04ecb75808d57bd76ed9069767a2afc9c3188f2bd42f045d0575765ade27ad033b338dd5c2c1aaa899b89201a34bbb6ed9ccd0511325adcf1c69718bd27196447d567f17e35a5865a3bc1fb35b3a605c25294d2a02e5f53d170c57814d8246f50cae32321d8a5c44508238ac50519bd12221c740620198b762c2d1670a4b94655c783eaad0e9a1244f8ae86d3b4a3df26ac532b6a4eaa4fb4a35df5c3a1b755dc5c17e451643d2db722113c1e3e2ca59cfa592c80fb9b2d7056e19f5c84198371465ce7dfba7390c3ce19d878121").expect("Failed to decode modulus");
    let pub_exponent =
        hex::decode("010001").expect("Failed to decode public exponent");
    let pri_exponent = hex::decode("14537d0f690302062a8314f6c17669618c956b50cde4e43bebd92709b067dbd0cd84268f8c5a68a7016c62051816435b050bf2c515d49997d9e2fb1faf9d86b6601b2c5291b92e404245313e8666abd1dfaaca4e196a6a3c1730a4685ce13f57bcce51f60d7e5e8681da85a7111aeec4e794c5cc98b4e31ebccdb005d4e7a1c54fcb81eb28a16d649489dfb2374bd3fbcf8e7e68197c08ed48601daa3512367961f4e8ba9a0ecae868365034ac1bba9accdfd0db0407142da7ea1a2b2e4c70e57707ac0db0b9b93f92b9839e5ce0dc61b4a804b60043f9f07675eb6e91eb029767c495682a9261344f9c825d22c148a9d2205d0fa5c521fadf8abbfae75fe591").expect("Failed to decode private exponent");
    let prime_1 = hex::decode("00d76285da69d58f6bca20e85cd645ea5fca42d872e92f190b7cc76cf50d2903ba213a8599db5429dd429a938376b64085bd9e8dd56360470d0d06684a3c18536c4929b3ba7b5f4848ec49327c2094afdd22e66eadf4f6e1af6456e49b4b0f0155c007003d4da785296f49ae013b509c918cc76b48f197a13a67e5eb11f883f585").expect("Failed to decode prime 1");
    let coefficient = hex::decode("26ee312416332f9b8e7c0ab1d0dcc3d7edaea735ffc43295efa876d1948991fd49f2f2a1a54e99ee13ea79903acc48520f0c4b5129687cf5efae60982f1848d54c490a452550d90bb68205d9f350f7134651c84ac9869047c455d1f0f31d6a3a6761ecab2e326190cedd65f775147dae147f1ec7d679cd198fc2a62422fb6178").expect("Failed to decode prime 1");
    template = vec![
        make_attribute!(CKA_CLASS, &mut class as *mut _, CK_ULONG_SIZE),
        make_attribute!(CKA_KEY_TYPE, &mut ktype as *mut _, CK_ULONG_SIZE),
        make_attribute!(CKA_SIGN, &mut encrypt as *mut _, CK_BBOOL_SIZE),
        make_attribute!(
            CKA_LABEL,
            label.as_ptr() as *mut std::ffi::c_void,
            label.len()
        ),
        make_attribute!(
            CKA_MODULUS,
            modulus.as_ptr() as *mut std::ffi::c_void,
            modulus.len()
        ),
        make_attribute!(
            CKA_PUBLIC_EXPONENT,
            pub_exponent.as_ptr() as *mut std::ffi::c_void,
            pub_exponent.len()
        ),
        make_attribute!(
            CKA_PRIVATE_EXPONENT,
            pri_exponent.as_ptr() as *mut std::ffi::c_void,
            pri_exponent.len()
        ),
        make_attribute!(
            CKA_PRIME_1,
            prime_1.as_ptr() as *mut std::ffi::c_void,
            prime_1.len()
        ),
        make_attribute!(
            CKA_COEFFICIENT,
            coefficient.as_ptr() as *mut std::ffi::c_void,
            coefficient.len()
        ),
    ];

    let ret = fn_create_object(
        session,
        template.as_mut_ptr(),
        template.len() as CK_ULONG,
        &mut handle,
    );
    assert_eq!(ret, CKR_OK);

    /* Test create secret key object */
    class = CKO_SECRET_KEY;
    ktype = CKK_GENERIC_SECRET;
    let label = "Test Generic Secret";
    let value = "Anything";
    template = vec![
        make_attribute!(CKA_CLASS, &mut class as *mut _, CK_ULONG_SIZE),
        make_attribute!(CKA_KEY_TYPE, &mut ktype as *mut _, CK_ULONG_SIZE),
        make_attribute!(
            CKA_LABEL,
            label.as_ptr() as *mut std::ffi::c_void,
            label.len()
        ),
        make_attribute!(
            CKA_VALUE,
            value.as_ptr() as *mut std::ffi::c_void,
            value.len()
        ),
    ];

    let ret = fn_create_object(
        session,
        template.as_mut_ptr(),
        template.len() as CK_ULONG,
        &mut handle,
    );
    assert_eq!(ret, CKR_OK);

    let mut size: CK_ULONG = 0;
    let ret = fn_get_object_size(session, handle, &mut size);
    assert_eq!(ret, CKR_OK);
    assert_ne!(size, 0);

    let ret = fn_destroy_object(session, handle);
    assert_eq!(ret, CKR_OK);

    testtokn.finalize();
}
