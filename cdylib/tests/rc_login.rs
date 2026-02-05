// Copyright 2026 Simo Sorce
// See LICENSE.txt file for terms

mod rc_common;

use cryptoki::session::UserType;
use cryptoki::types::AuthPin;

#[test]
#[cfg(feature = "integration_tests")]
fn test_login() -> Result<(), Box<dyn std::error::Error>> {
    use cryptoki::context::Function;
    use cryptoki::error::{Error, RvError};
    use cryptoki::session::SessionState;

    let (pkcs11, slot) = rc_common::setup_token("test_login", &[]);

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
