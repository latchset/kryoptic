#[test]
fn basic_example() -> Result<(), Box<dyn std::error::Error>> {
    use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
    use cryptoki::mechanism::Mechanism;
    use cryptoki::object::Attribute;
    use cryptoki::session::UserType;
    use cryptoki::types::AuthPin;
    use std::env;

    let legacy_confname = format!("token.sql");
    unsafe {
        env::set_var("KRYOPTIC_CONF", legacy_confname);
    }

    let module = env::var("TEST_PKCS11_MODULE").unwrap_or_else(|_| {
        "../target/debug/libkryoptic_pkcs11.so".to_string()
    });
    eprintln!("Using module {}", module);

    // initialize a new Pkcs11 object using the module from the env variable
    let pkcs11 = Pkcs11::new(module)?;

    pkcs11.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))?;

    let slot = pkcs11.get_slots_with_token()?[0];

    // initialize the token
    let so_pin = AuthPin::new("87654321".into());
    pkcs11.init_token(slot, &so_pin, "Test Kryoptic Token")?;

    let user_pin = AuthPin::new("12345678".into());

    // Initialize user's pin
    let session = pkcs11.open_rw_session(slot)?;
    session.login(UserType::So, Some(&so_pin))?;
    session.init_pin(&user_pin)?;

    // Switch from SO to User
    session.logout()?;
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
