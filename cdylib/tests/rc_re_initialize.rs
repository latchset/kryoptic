// Copyright 2026 Simo Sorce
// See LICENSE.txt file for terms

mod rc_common;

use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
use cryptoki::session::UserType;
use cryptoki::types::AuthPin;
use std::env;

fn test_re_initialize_common(
    dbtype: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let test_name = format!("test_re_initialize_{}", dbtype);
    let config_dbtype = format!("dbtype={}", dbtype);
    let (pkcs11, slot) = rc_common::setup_token(&test_name, &[&config_dbtype]);

    // Check the token info and get label
    let token_info = pkcs11.get_token_info(slot)?;
    let expected_label = token_info.label();

    // Now finalize the token
    pkcs11.finalize()?;

    // Re-initialize and check that we can still access data
    let module = env::var("TEST_PKCS11_MODULE").unwrap_or_else(|_| {
        "../target/debug/libkryoptic_pkcs11.so".to_string()
    });
    let pkcs11 = Pkcs11::new(&module).expect("Failed to load PKCS#11 module");
    pkcs11
        .initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))
        .expect("Failed to re-initialize PKCS#11");

    // Check the token info to see if state was preserved.
    let token_info = pkcs11.get_token_info(slot)?;
    assert_eq!(token_info.label(), expected_label);

    // We should be able to log in.
    let session = pkcs11.open_rw_session(slot)?;
    let user_pin = AuthPin::new("12345678".into());
    session.login(UserType::User, Some(&user_pin))?;
    session.logout()?;

    Ok(())
}

#[test]
fn test_re_initialize() -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(all(feature = "integration_tests", feature = "default"))]
    test_re_initialize_common("sqlite")?;

    #[cfg(all(feature = "integration_tests", feature = "nssdb"))]
    test_re_initialize_common("nssdb")?;

    Ok(())
}
