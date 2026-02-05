// Copyright 2026 Simo Sorce
// See LICENSE.txt file for terms

mod rc_common;

#[test]
#[cfg(feature = "integration_tests")]
fn ecdh_reimport_loop_test() -> Result<(), Box<dyn std::error::Error>> {
    use cryptoki::mechanism::{elliptic_curve, Mechanism};
    use cryptoki::object::{Attribute, AttributeType, KeyType, ObjectClass};
    use cryptoki::session::UserType;
    use cryptoki::types::AuthPin;
    use std::env;

    let (pkcs11, slot) = rc_common::setup_token("ecdh_reimport_loop_test", &[]);

    let user_pin = AuthPin::new("12345678".into());
    let session = pkcs11.open_rw_session(slot)?;
    session.login(UserType::User, Some(&user_pin))?;

    // Curve params: x25519
    const X25519_OID: &[u8] = &[0x06, 0x03, 0x2b, 0x65, 0x6e];

    // Generate the initial key pair to be re-imported
    let pub_template = vec![
        Attribute::Token(true),
        Attribute::EcParams(X25519_OID.to_vec()),
    ];
    let priv_template = vec![
        Attribute::Token(true),
        Attribute::Private(true),
        Attribute::Sensitive(false), // Needs to be false to read CKA_VALUE
        Attribute::Extractable(true),
        Attribute::Derive(true),
    ];
    let (mut pub_key_handle, mut priv_key_handle) = session.generate_key_pair(
        &Mechanism::EccMontgomeryKeyPairGen,
        &pub_template,
        &priv_template,
    )?;

    // Template for peer keys that are not stored on the token (session objects)
    let peer_pub_template = vec![
        Attribute::Token(false),
        Attribute::EcParams(X25519_OID.to_vec()),
    ];
    let peer_priv_template = vec![
        Attribute::Token(false),
        Attribute::Private(true),
        Attribute::Sensitive(true), // Does not need to be extractable
        Attribute::Derive(true),
    ];

    // Generate a static peer key pair for ECDH
    let (peer_pub_key_handle, _peer_priv_key_handle) = session
        .generate_key_pair(
            &Mechanism::EccMontgomeryKeyPairGen,
            &peer_pub_template,
            &peer_priv_template,
        )?;

    // Extract the peer's public point for ECDH derivation
    let attributes = session
        .get_attributes(peer_pub_key_handle, &[AttributeType::EcPoint])?;
    let peer_public_point = if let [Attribute::EcPoint(val)] = &attributes[..] {
        val.clone()
    } else {
        panic!("Expected EC Point attribute on peer key");
    };

    // Shared Data for ECDH exchange
    let shared_data: [u8; 4] = [0, 1, 2, 3];

    // Loop configuration
    let loop_count = env::var("REIMPORT_LOOP_COUNT")
        .unwrap_or_else(|_| "10".to_string())
        .parse::<usize>()?;
    let mut first_derived_key: Option<Vec<u8>> = None;

    eprintln!("Starting re-import loop for {} iterations", loop_count);

    for i in 0..loop_count {
        // 1. Extract attributes of the key from the current iteration's source
        let attributes = session
            .get_attributes(priv_key_handle, &[AttributeType::EcParams])?;
        let ec_params = if let [Attribute::EcParams(val)] = &attributes[..] {
            val.clone()
        } else {
            panic!("Failed to get EcParams on loop {}", i);
        };

        let attributes =
            session.get_attributes(priv_key_handle, &[AttributeType::Value])?;
        let private_value = if let [Attribute::Value(val)] = &attributes[..] {
            val.clone()
        } else {
            panic!("Failed to get Value on loop {}", i);
        };

        let attributes = session
            .get_attributes(pub_key_handle, &[AttributeType::EcPoint])?;
        let public_ec_point_der =
            if let [Attribute::EcPoint(val)] = &attributes[..] {
                val.clone()
            } else {
                panic!("Failed to get EcPoint on loop {}", i);
            };

        // 2. Re-import the key with a new, unique CKA_ID
        let new_id = (i as u64).to_be_bytes().to_vec();

        let new_priv_template = vec![
            Attribute::Class(ObjectClass::PRIVATE_KEY),
            Attribute::KeyType(KeyType::EC_MONTGOMERY),
            Attribute::Token(false),
            Attribute::Private(true),
            Attribute::Sensitive(false),
            Attribute::Extractable(true),
            Attribute::Derive(true),
            Attribute::Id(new_id.clone()),
            Attribute::EcParams(ec_params.clone()),
            Attribute::Value(private_value),
        ];
        let new_priv_handle = session.create_object(&new_priv_template)?;

        let new_pub_template = vec![
            Attribute::Class(ObjectClass::PUBLIC_KEY),
            Attribute::KeyType(KeyType::EC_MONTGOMERY),
            Attribute::Token(true),
            Attribute::Id(new_id),
            Attribute::EcParams(ec_params),
            Attribute::EcPoint(public_ec_point_der),
        ];
        let new_pub_handle = session.create_object(&new_pub_template)?;

        // 3. Use the newly imported key to perform ECDH with the static peer key
        let ecdh_params_static =
            Mechanism::Ecdh1Derive(elliptic_curve::Ecdh1DeriveParams::new(
                elliptic_curve::EcKdf::sha256(&shared_data),
                &peer_public_point,
            ));

        let derived_key_template = vec![
            Attribute::Class(ObjectClass::SECRET_KEY),
            Attribute::KeyType(KeyType::GENERIC_SECRET),
            Attribute::Token(false), // session object
            Attribute::Sensitive(false),
            Attribute::Extractable(true),
            Attribute::ValueLen(32.into()),
        ];

        let derived_key_handle_static = session.derive_key(
            &ecdh_params_static,
            new_priv_handle,
            &derived_key_template,
        )?;

        // 4. Extract the derived key's value and verify it's consistent
        let attributes = session.get_attributes(
            derived_key_handle_static,
            &[AttributeType::Value],
        )?;
        let derived_key_value_static =
            if let [Attribute::Value(val)] = &attributes[..] {
                val.clone()
            } else {
                panic!("Failed to get value from derived key on loop {}", i)
            };

        session.destroy_object(derived_key_handle_static)?;

        if let Some(ref first_key) = first_derived_key {
            assert_eq!(
                first_key, &derived_key_value_static,
                "Derived key mismatch on loop {}",
                i
            );
        } else {
            first_derived_key = Some(derived_key_value_static.clone());
        }

        // 5. Perform a second ECDH operation with a newly generated peer key for each loop
        let (dynamic_peer_pub_handle, dynamic_peer_priv_handle) = session
            .generate_key_pair(
                &Mechanism::EccMontgomeryKeyPairGen,
                &peer_pub_template,
                &peer_priv_template,
            )?;

        // Extract the dynamic peer's public point for ECDH derivation
        let attributes = session.get_attributes(
            dynamic_peer_pub_handle,
            &[AttributeType::EcPoint],
        )?;
        let dynamic_peer_public_point =
            if let [Attribute::EcPoint(val)] = &attributes[..] {
                val.clone()
            } else {
                panic!(
                "Expected EC Point attribute on dynamic peer key on loop {}",
                i
            );
            };

        let ecdh_params_dynamic =
            Mechanism::Ecdh1Derive(elliptic_curve::Ecdh1DeriveParams::new(
                elliptic_curve::EcKdf::sha256(&shared_data),
                &dynamic_peer_public_point,
            ));

        let derived_key_handle_dynamic = session.derive_key(
            &ecdh_params_dynamic,
            new_priv_handle,
            &derived_key_template,
        )?;

        // Extract the dynamic derived key's value
        let attributes = session.get_attributes(
            derived_key_handle_dynamic,
            &[AttributeType::Value],
        )?;
        let derived_key_value_dynamic = if let [Attribute::Value(val)] =
            &attributes[..]
        {
            val.clone()
        } else {
            panic!("Failed to get value from dynamic derived key on loop {}", i)
        };

        // 6. Ensure the derived shared secret is not the same as the one generated with the static peer key
        assert_ne!(
            derived_key_value_static,
            derived_key_value_dynamic,
            "Derived key from static and dynamic peer should not be the same on loop {}",
            i
        );

        // Clean up dynamic keys
        session.destroy_object(derived_key_handle_dynamic)?;
        session.destroy_object(dynamic_peer_pub_handle)?;
        session.destroy_object(dynamic_peer_priv_handle)?;

        // 7. The newly created key becomes the source for the next iteration
        priv_key_handle = new_priv_handle;
        pub_key_handle = new_pub_handle;
    }

    Ok(())
}
