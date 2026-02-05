// Copyright 2026 Simo Sorce
// See LICENSE.txt file for terms

mod rc_common;

use cryptoki::object::{Attribute, AttributeType, KeyType, ObjectClass};
use cryptoki::session::UserType;
use cryptoki::types::AuthPin;

#[test]
#[cfg(feature = "integration_tests")]
fn rc_eddsa_compat() -> Result<(), Box<dyn std::error::Error>> {
    // Setup with default configuration
    let (pkcs11, slot) = rc_common::setup_token("rc_eddsa_compat", &[]);

    // Test Vectors for Ed25519ctx from C_CreateObject
    let point: Vec<u8> = vec![
        0xdf, 0xc9, 0x42, 0x5e, 0x4f, 0x96, 0x8f, 0x7f, 0x0c, 0x29, 0xf0, 0x25,
        0x9c, 0xf5, 0xf9, 0xae, 0xd6, 0x85, 0x1c, 0x2b, 0xb4, 0xad, 0x8b, 0xfb,
        0x86, 0x0c, 0xfe, 0xe0, 0xab, 0x24, 0x82, 0x92,
    ];
    let params: Vec<u8> = vec![
        0x13, 0x0c, 0x65, 0x64, 0x77, 0x61, 0x72, 0x64, 0x73, 0x32, 0x35, 0x35,
        0x31, 0x39,
    ];
    let point_der: Vec<u8> = vec![
        0x04, 0x20, 0xdf, 0xc9, 0x42, 0x5e, 0x4f, 0x96, 0x8f, 0x7f, 0x0c, 0x29,
        0xf0, 0x25, 0x9c, 0xf5, 0xf9, 0xae, 0xd6, 0x85, 0x1c, 0x2b, 0xb4, 0xad,
        0x8b, 0xfb, 0x86, 0x0c, 0xfe, 0xe0, 0xab, 0x24, 0x82, 0x92,
    ];

    // --- Part 1: Default encoding (Bytes) ---
    let session = pkcs11.open_rw_session(slot)?;
    let user_pin = AuthPin::new("12345678".into());
    session.login(UserType::User, Some(&user_pin))?;

    let pub_template = |p: &[u8], label: &str| {
        vec![
            Attribute::Class(ObjectClass::PUBLIC_KEY),
            Attribute::KeyType(KeyType::EC_EDWARDS),
            Attribute::Token(true),
            Attribute::Label(label.as_bytes().to_vec()),
            Attribute::EcPoint(p.to_vec()),
            Attribute::EcParams(params.clone()),
            Attribute::Verify(true),
        ]
    };

    // Create one key with a raw point, one with a DER-encoded point
    let raw_handle = session.create_object(&pub_template(
        &point,
        "Ed25519 with ByteArray EC Point",
    ))?;
    let der_handle = session.create_object(&pub_template(
        &point_der,
        "Ed25519 with DER EC Point",
    ))?;

    // test both handles, they should both return the same byte array point in standard mode
    let attrs =
        session.get_attributes(raw_handle, &[AttributeType::EcPoint])?;
    if let Some(Attribute::EcPoint(val)) = attrs.get(0) {
        assert_eq!(*val, point);
    } else {
        panic!("Expected CKA_EC_POINT attribute");
    }

    let attrs =
        session.get_attributes(der_handle, &[AttributeType::EcPoint])?;
    if let Some(Attribute::EcPoint(val)) = attrs.get(0) {
        assert_eq!(*val, point);
    } else {
        panic!("Expected CKA_EC_POINT attribute");
    }
    session.logout()?;

    // --- Part 2: Compatibility encoding (DER) ---
    // Modify setup with ecPointEncoding = "Der"
    let (pkcs11, slot) = rc_common::modify_setup(
        "rc_eddsa_compat",
        &["[ec_point_encoding]", r#"encoding = "Der""#],
        (pkcs11, slot),
    );
    let session = pkcs11.open_rw_session(slot)?;
    session.login(UserType::User, Some(&user_pin))?;

    // Find the previously created keys
    let find_template = |label: &str| {
        vec![
            Attribute::Class(ObjectClass::PUBLIC_KEY),
            Attribute::Label(label.as_bytes().to_vec()),
        ]
    };

    let objects = session
        .find_objects(&find_template("Ed25519 with ByteArray EC Point"))?;
    assert_eq!(objects.len(), 1);
    let raw_handle = objects[0];
    let objects =
        session.find_objects(&find_template("Ed25519 with DER EC Point"))?;
    assert_eq!(objects.len(), 1);
    let der_handle = objects[0];

    // test both handles, they should both return the same DER encoded point in compatibility mode
    let attrs =
        session.get_attributes(raw_handle, &[AttributeType::EcPoint])?;
    if let Some(Attribute::EcPoint(val)) = attrs.get(0) {
        assert_eq!(*val, point_der);
    } else {
        panic!("Expected CKA_EC_POINT attribute");
    }

    let attrs =
        session.get_attributes(der_handle, &[AttributeType::EcPoint])?;
    if let Some(Attribute::EcPoint(val)) = attrs.get(0) {
        assert_eq!(*val, point_der);
    } else {
        panic!("Expected CKA_EC_POINT attribute");
    }
    session.logout()?;

    Ok(())
}
