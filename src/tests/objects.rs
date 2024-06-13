// Copyright 2024 Simo Sorce
// See LICENSE.txt file for terms

use super::tests;
use tests::*;

use serial_test::parallel;

#[test]
#[parallel]
fn test_copy_objects() {
    let mut testtokn = TestToken::initialized("test_copy_objects.sql", None);
    let session = testtokn.get_session(false);

    /* login */
    testtokn.login();

    /* public key data */
    let mut handle: CK_ULONG = CK_INVALID_HANDLE;
    let template =
        make_attr_template(&[], &[(CKA_UNIQUE_ID, "10".as_bytes())], &[]);
    let ret = fn_find_objects_init(session, template.as_ptr() as *mut _, 1);
    assert_eq!(ret, CKR_OK);
    let mut count: CK_ULONG = 0;
    let ret = fn_find_objects(session, &mut handle, 1, &mut count);
    assert_eq!(ret, CKR_OK);
    assert_eq!(count, 1);
    assert_ne!(handle, CK_INVALID_HANDLE);
    let ret = fn_find_objects_final(session);
    assert_eq!(ret, CKR_OK);

    /* copy token object to session object */
    let template = make_attr_template(
        &[],
        &[],
        &[(CKA_TOKEN, false), (CKA_PRIVATE, true)],
    );
    let mut handle2: CK_ULONG = CK_INVALID_HANDLE;
    let ret = fn_copy_object(
        session,
        handle,
        template.as_ptr() as *mut _,
        template.len() as CK_ULONG,
        &mut handle2,
    );
    assert_eq!(ret, CKR_OK);

    /* make not copyable object */
    let handle = ret_or_panic!(import_object(
        session,
        CKO_DATA,
        &[],
        &[
            (CKA_APPLICATION, "nocopy".as_bytes()),
            (CKA_VALUE, "data".as_bytes())
        ],
        &[(CKA_COPYABLE, false)],
    ));

    /* copy token object to session object */
    let template = make_attr_template(&[], &[], &[(CKA_TOKEN, false)]);
    let mut handle2: CK_ULONG = CK_INVALID_HANDLE;
    let ret = fn_copy_object(
        session,
        handle,
        template.as_ptr() as *mut _,
        template.len() as CK_ULONG,
        &mut handle2,
    );
    assert_eq!(ret, CKR_ACTION_PROHIBITED);

    testtokn.finalize();
}

#[test]
#[parallel]
fn test_create_objects() {
    let mut testtokn = TestToken::initialized("test_create_objects.sql", None);
    let session = testtokn.get_session(false);

    let byte_values = [
        (CKA_APPLICATION, "test".as_bytes()),
        (CKA_VALUE, "payload".as_bytes()),
    ];

    err_or_panic!(
        import_object(session, CKO_DATA, &[], &byte_values, &[],),
        CKR_USER_NOT_LOGGED_IN
    );

    /* login */
    testtokn.login();

    let _ =
        ret_or_panic!(
            import_object(session, CKO_DATA, &[], &byte_values, &[],)
        );

    err_or_panic!(
        import_object(
            session,
            CKO_DATA,
            &[],
            &byte_values,
            &[(CKA_TOKEN, true)],
        ),
        CKR_SESSION_READ_ONLY
    );

    let session = testtokn.get_session(true);

    let _ = ret_or_panic!(import_object(
        session,
        CKO_DATA,
        &[],
        &byte_values,
        &[(CKA_TOKEN, true)],
    ));

    let _ = ret_or_panic!(import_object(
        session,
        CKO_CERTIFICATE,
        &[(CKA_CERTIFICATE_TYPE, CKC_X_509)],
        &[
            (CKA_CHECK_VALUE, "ignored".as_bytes()),
            (CKA_SUBJECT, "subject".as_bytes()),
            (CKA_VALUE, "value".as_bytes())
        ],
        &[(CKA_TOKEN, true), (CKA_TRUSTED, false)],
    ));

    let modulus = hex::decode(
        "9D2E7820CE719B9194CDFE0FD751214193C4E9BE9BFA24D0E91B0FC3541C85\
         885CB3CA95F8FDA4E129558EE41F653481E66A04ECB75808D57BD76ED90697\
         67A2AFC9C3188F2BD42F045D0575765ADE27AD033B338DD5C2C1AAA899B892\
         01A34BBB6ED9CCD0511325ADCF1C69718BD27196447D567F17E35A5865A3BC\
         1FB35B3A605C25294D2A02E5F53D170C57814D8246F50CAE32321D8A5C4450\
         8238AC50519BD12221C740620198B762C2D1670A4B94655C783EAAD0E9A124\
         4F8AE86D3B4A3DF26AC532B6A4EAA4FB4A35DF5C3A1B755DC5C17E451643D2\
         DB722113C1E3E2CA59CFA592C80FB9B2D7056E19F5C84198371465CE7DFBA7\
         390C3CE19D878121",
    )
    .expect("Failed to decode hex modulus");
    let exponent = hex::decode("010001").expect("Failed to decode exponent");
    let _ = ret_or_panic!(import_object(
        session,
        CKO_PUBLIC_KEY,
        &[(CKA_KEY_TYPE, CKK_RSA)],
        &[
            (CKA_LABEL, "RSA Public Encryption Key".as_bytes()),
            (CKA_MODULUS, modulus.as_slice()),
            (CKA_PUBLIC_EXPONENT, exponent.as_slice())
        ],
        &[(CKA_ENCRYPT, true)]
    ));

    /* Private RSA Key with missing Q,A,B parameters */

    let private_exponent = hex::decode(
        "14537D0F690302062A8314F6C17669618C956B50CDE4E43BEBD92709B067DB\
         D0CD84268F8C5A68A7016C62051816435B050BF2C515D49997D9E2FB1FAF9D\
         86B6601B2C5291B92E404245313E8666ABD1DFAACA4E196A6A3C1730A4685C\
         E13F57BCCE51F60D7E5E8681DA85A7111AEEC4E794C5CC98B4E31EBCCDB005\
         D4E7A1C54FCB81EB28A16D649489DFB2374BD3FBCF8E7E68197C08ED48601D\
         AA3512367961F4E8BA9A0ECAE868365034AC1BBA9ACCDFD0DB0407142DA7EA\
         1A2B2E4C70E57707AC0DB0B9B93F92B9839E5CE0DC61B4A804B60043F9F076\
         75EB6E91EB029767C495682A9261344F9C825D22C148A9D2205D0FA5C521FA\
         DF8ABBFAE75FE591",
    )
    .expect("Failed to decode private exponent");
    let prime_1 = hex::decode(
        "00D76285DA69D58F6BCA20E85CD645EA5FCA42D872E92F190B7CC76CF50D29\
         03BA213A8599DB5429DD429A938376B64085BD9E8DD56360470D0D06684A3C\
         18536C4929B3BA7B5F4848EC49327C2094AFDD22E66EADF4F6E1AF6456E49B\
         4B0F0155C007003D4DA785296F49AE013B509C918CC76B48F197A13A67E5EB\
         11F883F585",
    )
    .expect("Failed to decode prime 1");
    let coefficient = hex::decode(
        "26ee312416332f9b8e7c0ab1d0dcc3d7edaea735ffc43295efa876d1948991\
         fd49f2f2a1a54e99ee13ea79903acc48520f0c4b5129687cf5efae60982f18\
         48d54c490a452550d90bb68205d9f350f7134651c84ac9869047c455d1f0f3\
         1d6a3a6761ecab2e326190cedd65f775147dae147f1ec7d679cd198fc2a624\
         22fb6178",
    )
    .expect("Failed to decode prime 1");
    let _ = ret_or_panic!(import_object(
        session,
        CKO_PRIVATE_KEY,
        &[(CKA_KEY_TYPE, CKK_RSA)],
        &[
            (CKA_LABEL, "RSA Private Key".as_bytes()),
            (CKA_MODULUS, modulus.as_slice()),
            (CKA_PUBLIC_EXPONENT, exponent.as_slice()),
            (CKA_PRIVATE_EXPONENT, private_exponent.as_slice()),
            (CKA_PRIME_1, prime_1.as_slice()),
            (CKA_COEFFICIENT, coefficient.as_slice()),
        ],
        &[(CKA_SIGN, true)]
    ));

    /* Test create secret key object */
    let secret_key = ret_or_panic!(import_object(
        session,
        CKO_SECRET_KEY,
        &[(CKA_KEY_TYPE, CKK_GENERIC_SECRET)],
        &[
            (CKA_VALUE, "Anything".as_bytes()),
            (CKA_LABEL, "Test Generic Secret".as_bytes())
        ],
        &[],
    ));

    let mut size: CK_ULONG = 0;
    let ret = fn_get_object_size(session, secret_key, &mut size);
    assert_eq!(ret, CKR_OK);
    assert_ne!(size, 0);

    let ret = fn_destroy_object(session, secret_key);
    assert_eq!(ret, CKR_OK);

    testtokn.finalize();
}
