use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
use cryptoki::session::UserType;
use cryptoki::slot::Slot;
use cryptoki::types::AuthPin;
use std::env;
use std::fs;
use std::path::Path;

fn setup_token(name: &str) -> (Pkcs11, Slot) {
    let confname = format!("{}.sql", name);
    if Path::new(&confname).exists() {
        fs::remove_file(&confname).unwrap();
    }
    // Set KRYOPTIC_CONF for the C library. Using `std::env::set_var` is not thread-safe.
    // The `serial` macro should serialize test execution, making this safe.
    unsafe {
        env::set_var("KRYOPTIC_CONF", &confname);
    }

    let module = env::var("TEST_PKCS11_MODULE").unwrap_or_else(|_| {
        "../target/debug/libkryoptic_pkcs11.so".to_string()
    });

    let pkcs11 = Pkcs11::new(&module).expect("Failed to load PKCS#11 module");
    pkcs11
        .initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))
        .expect("Failed to initialize PKCS#11");
    let slots = pkcs11.get_slots_with_token().expect("Failed to get slots");
    let slot = slots.first().expect("No slots with tokens found").clone();

    // initialize the token
    let so_pin = AuthPin::new("87654321".into());
    pkcs11
        .init_token(slot, &so_pin, "Test Kryoptic Token")
        .expect("Failed to init token");
    let user_pin = AuthPin::new("12345678".into());

    // Initialize user's pin
    let session = pkcs11
        .open_rw_session(slot)
        .expect("Failed to open RW session");
    session
        .login(UserType::So, Some(&so_pin))
        .expect("SO login failed");
    session.init_pin(&user_pin).expect("init_pin failed");
    session.logout().expect("SO logout failed");

    (pkcs11, slot)
}

#[test]
#[cfg(feature = "integration_tests")]
fn test_login() -> Result<(), Box<dyn std::error::Error>> {
    use cryptoki::context::Function;
    use cryptoki::error::{Error, RvError};
    use cryptoki::session::SessionState;

    let (pkcs11, slot) = setup_token("test_login");

    let ro_session = pkcs11.open_ro_session(slot)?;
    let info = ro_session.get_session_info()?;
    assert_eq!(info.session_state(), SessionState::RoPublic);

    let rw_session = pkcs11.open_rw_session(slot)?;
    let info = rw_session.get_session_info()?;
    assert_eq!(info.session_state(), SessionState::RwPublic);

    /* check pin flags */
    let token_info = pkcs11.get_token_info(slot)?;
    assert_eq!(token_info.so_pin_to_be_changed(), false);
    assert_eq!(token_info.so_pin_locked(), false);
    assert_eq!(token_info.so_pin_final_try(), false);
    assert_eq!(token_info.so_pin_count_low(), false);
    assert_eq!(token_info.user_pin_to_be_changed(), false);
    assert_eq!(token_info.user_pin_locked(), false);
    assert_eq!(token_info.user_pin_final_try(), false);
    assert_eq!(token_info.user_pin_count_low(), false);

    /* fail login first */
    let pin = AuthPin::new("87654321".into());
    let ret = ro_session.login(UserType::User, Some(&pin));
    assert!(matches!(
        ret.unwrap_err(),
        Error::Pkcs11(RvError::PinIncorrect, Function::Login)
    ));

    /* check pin flags */
    let token_info = pkcs11.get_token_info(slot)?;
    assert_eq!(token_info.so_pin_to_be_changed(), false);
    assert_eq!(token_info.so_pin_locked(), false);
    assert_eq!(token_info.so_pin_final_try(), false);
    assert_eq!(token_info.so_pin_count_low(), false);
    assert_eq!(token_info.user_pin_to_be_changed(), false);
    assert_eq!(token_info.user_pin_locked(), false);
    assert_eq!(token_info.user_pin_final_try(), false);
    assert_eq!(token_info.user_pin_count_low(), false);

    /* fail a few more times to bring the count to low */
    for _ in 1..7 {
        let pin = AuthPin::new("87654321".into());
        let ret = ro_session.login(UserType::User, Some(&pin));
        assert!(matches!(
            ret.unwrap_err(),
            Error::Pkcs11(RvError::PinIncorrect, Function::Login)
        ));
    }

    /* check pin flags */
    let token_info = pkcs11.get_token_info(slot)?;
    assert_eq!(token_info.user_pin_count_low(), true);

    /* login */
    let pin = AuthPin::new("12345678".into());
    ro_session.login(UserType::User, Some(&pin))?;

    /* check pin flags */
    let token_info = pkcs11.get_token_info(slot)?;
    assert_eq!(token_info.so_pin_to_be_changed(), false);
    assert_eq!(token_info.so_pin_locked(), false);
    assert_eq!(token_info.so_pin_final_try(), false);
    assert_eq!(token_info.so_pin_count_low(), false);
    assert_eq!(token_info.user_pin_to_be_changed(), false);
    assert_eq!(token_info.user_pin_locked(), false);
    assert_eq!(token_info.user_pin_final_try(), false);
    assert_eq!(token_info.user_pin_count_low(), false);

    let info = ro_session.get_session_info()?;
    assert_eq!(info.session_state(), SessionState::RoUser);

    let info = rw_session.get_session_info()?;
    assert_eq!(info.session_state(), SessionState::RwUser);

    let ret = ro_session.login(UserType::User, Some(&pin));
    assert!(matches!(
        ret.unwrap_err(),
        Error::Pkcs11(RvError::UserAlreadyLoggedIn, Function::Login)
    ));

    rw_session.logout()?;

    let info = ro_session.get_session_info()?;
    assert_eq!(info.session_state(), SessionState::RoPublic);

    let info = rw_session.get_session_info()?;
    assert_eq!(info.session_state(), SessionState::RwPublic);

    let ret = ro_session.logout();
    assert!(matches!(
        ret.unwrap_err(),
        Error::Pkcs11(RvError::UserNotLoggedIn, Function::Logout)
    ));

    Ok(())
}
