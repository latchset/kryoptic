// Copyright 2026 Simo Sorce
// See LICENSE.txt file for terms

use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
use cryptoki::session::UserType;
use cryptoki::slot::Slot;
use cryptoki::types::AuthPin;
use std::env;
use std::fs;
use std::path::PathBuf;

fn _setup_common() -> (Pkcs11, Slot) {
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

fn _reload_common((pkcs11, _slot): (Pkcs11, Slot)) -> (Pkcs11, Slot) {
    pkcs11
        .finalize()
        .expect("Failed to finalize previous Pkcs11 context");
    let module = env::var("TEST_PKCS11_MODULE").unwrap_or_else(|_| {
        "../target/debug/libkryoptic_pkcs11.so".to_string()
    });

    let pkcs11 = Pkcs11::new(&module).expect("Failed to load PKCS#11 module");
    pkcs11
        .initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))
        .expect("Failed to initialize PKCS#11");
    let slots = pkcs11.get_slots_with_token().expect("Failed to get slots");
    let slot = slots.first().expect("No slots with tokens found").clone();

    (pkcs11, slot)
}

fn setup_test_dir(name: &str) -> PathBuf {
    let tmpdir = PathBuf::from(
        env::var("CARGO_TARGET_TMPDIR")
            .unwrap_or_else(|_| "target/tmp".to_string()),
    );
    let testdir = tmpdir.join(name);
    if testdir.exists() {
        fs::remove_dir_all(&testdir).unwrap();
    }
    fs::create_dir_all(&testdir).unwrap();
    testdir
}

pub fn setup_token(name: &str, common_config_lines: &[&str]) -> (Pkcs11, Slot) {
    let testdir = setup_test_dir(name);
    let confname = testdir.join(format!("{}.conf", name));

    let mut config_content = String::new();
    let mut dbtype = "sqlite".to_string();

    let mut final_config_lines = Vec::new();
    for line in common_config_lines {
        let line_str = *line;
        if line_str.starts_with("dbtype=") {
            dbtype = line_str.splitn(2, '=').nth(1).unwrap().trim().to_string();
        } else {
            final_config_lines.push(line_str);
        }
    }

    match dbtype.as_str() {
        "sqlite" | "nssdb" | "memory" => {}
        _ => panic!("Unsupported dbtype: {}", dbtype),
    }

    // Add common section lines
    for line in final_config_lines {
        config_content.push_str(line);
        config_content.push('\n');
    }

    // Add slot configuration
    let dbargs = match dbtype.as_str() {
        "sqlite" => {
            let sql_path = testdir.join(format!("{}.sql", name));
            sql_path.to_str().unwrap().replace('\\', "\\\\")
        }
        "nssdb" => format!(
            "configDir={}",
            testdir.to_str().unwrap().replace('\\', "\\\\")
        ),
        "memory" => "flags=encrypt".to_string(),
        _ => unreachable!(),
    };

    let slot_config = format!(
        r#"
[[slots]]
  slot = 0
  dbtype = "{}"
  dbargs = "{}"
"#,
        dbtype,
        dbargs.replace('\\', "\\\\")
    );
    config_content.push_str(&slot_config);

    fs::write(&confname, config_content)
        .expect("Failed to write kryoptic.conf");

    // Set KRYOPTIC_CONF for the C library. Using `std::env::set_var` is not thread-safe.
    unsafe {
        env::set_var("KRYOPTIC_CONF", confname);
    }
    _setup_common()
}

#[allow(dead_code)]
pub fn modify_setup(
    name: &str,
    common_config_lines: &[&str],
    prev: (Pkcs11, Slot),
) -> (Pkcs11, Slot) {
    let testdir = PathBuf::from(
        env::var("CARGO_TARGET_TMPDIR")
            .unwrap_or_else(|_| "target/tmp".to_string()),
    )
    .join(name);
    let confname = testdir.join(format!("{}.conf", name));

    let mut config_content = String::new();
    let mut dbtype = "sqlite".to_string();

    let mut final_config_lines = Vec::new();
    for line in common_config_lines {
        let line_str = *line;
        if line_str.starts_with("dbtype=") {
            dbtype = line_str.splitn(2, '=').nth(1).unwrap().trim().to_string();
        } else {
            final_config_lines.push(line_str);
        }
    }

    match dbtype.as_str() {
        "sqlite" | "nssdb" | "memory" => {}
        _ => panic!("Unsupported dbtype: {}", dbtype),
    }

    // Add common section lines
    for line in final_config_lines {
        config_content.push_str(line);
        config_content.push('\n');
    }

    // Add slot configuration
    let dbargs = match dbtype.as_str() {
        "sqlite" => {
            let sql_path = testdir.join(format!("{}.sql", name));
            sql_path.to_str().unwrap().replace('\\', "\\\\")
        }
        "nssdb" => format!(
            "configDir={}",
            testdir.to_str().unwrap().replace('\\', "\\\\")
        ),
        "memory" => "flags=encrypt".to_string(),
        _ => unreachable!(),
    };

    let slot_config = format!(
        r#"
[[slots]]
  slot = 0
  dbtype = "{}"
  dbargs = "{}"
"#,
        dbtype, dbargs
    );
    config_content.push_str(&slot_config);

    fs::write(&confname, config_content)
        .expect("Failed to write kryoptic.conf");

    // Set KRYOPTIC_CONF for the C library. Using `std::env::set_var` is not thread-safe.
    unsafe {
        env::set_var("KRYOPTIC_CONF", confname);
    }
    _reload_common(prev)
}
