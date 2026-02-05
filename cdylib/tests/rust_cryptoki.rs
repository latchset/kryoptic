// Copyright 2026 Simo Sorce
// See LICENSE.txt file for terms

mod rc_common;

#[test]
#[cfg(feature = "integration_tests")]
fn basic_example() -> Result<(), Box<dyn std::error::Error>> {
    use cryptoki::mechanism::Mechanism;
    use cryptoki::object::Attribute;
    use cryptoki::session::UserType;
    use cryptoki::types::AuthPin;

    let (pkcs11, slot) = rc_common::setup_token("basic_example", &[]);

    let user_pin = AuthPin::new("12345678".into());

    // Login as user
    let session = pkcs11.open_rw_session(slot)?;
    session.login(UserType::User, Some(&user_pin))?;

    // template of the public key
    let pub_key_template =
        vec![Attribute::Token(true), Attribute::ModulusBits(2048.into())];

    let priv_key_template = vec![Attribute::Token(true)];

    // generate RSA key
    let (_public, _private) = session.generate_key_pair(
        &Mechanism::RsaPkcsKeyPairGen,
        &pub_key_template,
        &priv_key_template,
    )?;

    Ok(())
}
