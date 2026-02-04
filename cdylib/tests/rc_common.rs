// Copyright 2026 Simo Sorce
// See LICENSE.txt file for terms

use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
use cryptoki::session::UserType;
use cryptoki::slot::Slot;
use cryptoki::types::AuthPin;
use std::env;
use std::fs;
use std::path::Path;

#[allow(dead_code)]
pub fn setup_token(name: &str) -> (Pkcs11, Slot) {
    let confname = format!("{}.sql", name);
    if Path::new(&confname).exists() {
        fs::remove_file(&confname).unwrap();
    }
    // Set KRYOPTIC_CONF for the C library. Using `std::env::set_var` is not thread-safe.
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
