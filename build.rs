// Copyright 2023 Simo Sorce
// See LICENSE.txt file for terms

use std::env;
use std::panic::set_hook;
use std::path::{Path, PathBuf};

#[derive(Debug)]
pub struct Pkcs11Callbacks;

struct Features {
    fips: bool,
    dynamic: bool,
    pkcs11_3_2: bool,
}

impl Features {
    fn to_bools() -> Features {
        #[cfg(all(feature = "dynamic", feature = "fips"))]
        compile_error!("features `dynamic` and `fips` are mutually exclusive");

        #[cfg(all(
            feature = "ecdh",
            not(any(feature = "ecdsa", feature = "ec_montgomery"))
        ))]
        compile_error!(
            "Feature 'ecdh' requires either 'ecdsa' or 'ec_montgomery'"
        );

        Features {
            #[cfg(feature = "fips")]
            fips: true,
            #[cfg(not(feature = "fips"))]
            fips: false,
            #[cfg(feature = "dynamic")]
            dynamic: true,
            #[cfg(not(feature = "dynamic"))]
            dynamic: false,
            #[cfg(feature = "pkcs11_3_2")]
            pkcs11_3_2: true,
            #[cfg(not(feature = "pkcs11_3_2"))]
            pkcs11_3_2: false,
        }
    }
}

impl bindgen::callbacks::ParseCallbacks for Pkcs11Callbacks {
    fn int_macro(
        &self,
        name: &str,
        _: i64,
    ) -> Option<bindgen::callbacks::IntKind> {
        if name == "CK_TRUE" || name == "CK_FALSE" {
            Some(bindgen::callbacks::IntKind::Custom {
                name: "CK_BBOOL",
                is_signed: false,
            })
        } else if name.starts_with("CRYPTOKI_VERSION") {
            Some(bindgen::callbacks::IntKind::Custom {
                name: "CK_BYTE",
                is_signed: false,
            })
        } else if name.starts_with("CK") {
            Some(bindgen::callbacks::IntKind::Custom {
                name: "CK_ULONG",
                is_signed: false,
            })
        } else {
            None
        }
    }
}

#[derive(Debug)]
pub struct OsslCallbacks;
const OPENSSL_3_0_7: i64 = 0x30000070;
const OPENSSL_3_2_0: i64 = 0x30200000;
const OPENSSL_3_5_0: i64 = 0x30500000;

impl bindgen::callbacks::ParseCallbacks for OsslCallbacks {
    fn int_macro(
        &self,
        name: &str,
        value: i64,
    ) -> Option<bindgen::callbacks::IntKind> {
        if name == "OPENSSL_VERSION_NUMBER" {
            if value < OPENSSL_3_5_0 {
                #[cfg(any(
                    feature = "mlkem",
                    feature = "mldsa",
                    feature = "fips"
                ))]
                panic!("OpenSSL 3.5.0 or later is required for mlkem, mldsa or fips");
            }
            if value < OPENSSL_3_2_0 {
                #[cfg(feature = "eddsa")]
                panic!("OpenSSL 3.2.0 or later is required for eddsa");
            }
            if value < OPENSSL_3_0_7 {
                panic!(
                    "OpenSSL 3.0.7 is the minimum viable version. Found {:x}",
                    value
                );
            }
        }
        None
    }
}

fn ossl_bindings(args: &[&str], out_file: &Path) {
    bindgen::Builder::default()
        .header("ossl.h")
        .clang_args(args)
        .derive_default(true)
        .formatter(bindgen::Formatter::Prettyplease)
        .allowlist_item("ossl_.*")
        .allowlist_item("OSSL_.*")
        .allowlist_item("openssl_.*")
        .allowlist_item("OPENSSL_.*")
        .allowlist_item("CRYPTO_.*")
        .allowlist_item("c_.*")
        .allowlist_item("EVP_.*")
        .allowlist_item("evp_.*")
        .allowlist_item("BN_.*")
        .allowlist_item("LN_aes.*")
        .allowlist_item("ERR.*")
        .allowlist_item("BIO.*")
        .parse_callbacks(Box::new(OsslCallbacks))
        .generate()
        .expect("Unable to generate bindings")
        .write_to_file(out_file)
        .expect("Couldn't write bindings!");
}

fn build_ossl(features: &Features, out_file: &Path) {
    let sources = std::env::var("KRYOPTIC_OPENSSL_SOURCES")
        .expect("Env var KRYOPTIC_OPENSSL_SOURCES is not defined");
    let openssl_path = std::path::PathBuf::from(sources)
        .canonicalize()
        .expect("cannot canonicalize OpenSSL path");

    let mut buildargs = vec![
        "no-deprecated",
        "no-aria",
        "no-argon2",
        "no-atexit",
        "no-des",
        "no-dsa",
        "no-cast",
        "no-mdc2",
        "no-ec2m",
        "no-rc2",
        "no-rc4",
        "no-rc5",
        "no-rmd160",
        "no-seed",
        "no-sm2",
        "no-sm3",
        "no-sm4",
        "enable-ec_nistp_64_gcc_128",
    ];

    if env::var("PROFILE").unwrap().as_str() == "debug" {
        buildargs.push("--debug");
    }

    let mut defines = "-DDEVRANDOM=\\\"/dev/urandom\\\"".to_string();

    let ar_path: std::path::PathBuf;
    let ar_name: &str;

    if features.fips {
        buildargs.push("enable-fips");

        defines.push_str(" -DOPENSSL_PEDANTIC_ZEROIZATION");

        let fips_name = match std::env::var("KRYOPTIC_FIPS_VENDOR") {
            Ok(name) => name,
            Err(_) => env!("CARGO_PKG_NAME").to_string(),
        };
        defines.push_str(&format!(
            " -DKRYOPTIC_FIPS_VENDOR=\\\"{}\\\"",
            fips_name,
        ));

        let fips_ver = match std::env::var("KRYOPTIC_FIPS_VERSION") {
            Ok(ver) => ver,
            Err(_) => env!("CARGO_PKG_VERSION").to_string(),
        };
        defines.push_str(&format!(
            " -DKRYOPTIC_FIPS_VERSION=\\\"{}\\\"",
            fips_ver,
        ));

        let fips_build = match std::env::var("KRYOPTIC_FIPS_BUILD") {
            Ok(bd) => bd,
            Err(_) => "test".to_string(),
        };
        defines.push_str(&format!(
            " -DKRYOPTIC_FIPS_BUILD=\\\"{}\\\"",
            fips_build,
        ));

        ar_name = "fips";
        ar_path = openssl_path
            .join("providers")
            .canonicalize()
            .expect("OpenSSL providers path unavailable");
    } else {
        ar_path = openssl_path.clone();
        ar_name = "crypto";
    }

    buildargs.push(&defines);

    let libpath = format!("{}/lib{}.a", ar_path.to_string_lossy(), ar_name);

    println!("cargo:rustc-link-search={}", ar_path.to_string_lossy());
    println!("cargo:rustc-link-lib=static={}", ar_name);
    println!("cargo:rerun-if-changed={}", libpath);

    match std::path::Path::new(&libpath).try_exists() {
        Ok(true) => (),
        _ => {
            /* openssl: ./Configure --debug enable-fips */
            if !std::process::Command::new("./Configure")
                .current_dir(&openssl_path)
                .args(buildargs)
                .stdout(std::process::Stdio::inherit())
                .stderr(std::process::Stdio::inherit())
                .output()
                .expect("could not run openssl `Configure`")
                .status
                .success()
            {
                // Panic if the command was not successful.
                panic!("could not configure OpenSSL");
            }

            if !std::process::Command::new("make")
                .current_dir(&openssl_path)
                .stdout(std::process::Stdio::inherit())
                .stderr(std::process::Stdio::inherit())
                .output()
                .expect("could not run openssl `make`")
                .status
                .success()
            {
                // Panic if the command was not successful.
                panic!("could not build OpenSSL");
            }
        }
    }

    let include_path = format!(
        "-I{}",
        openssl_path
            .join("include")
            .canonicalize()
            .expect("OpenSSL include path unavailable")
            .to_str()
            .unwrap()
    );

    let mut args = vec![&include_path, "-std=c90"];
    if features.fips {
        args.push("-D_KRYOPTIC_FIPS_");
    }

    ossl_bindings(&args, out_file);
}

fn use_system_ossl(out_file: &Path) {
    println!("cargo:rustc-link-lib=crypto");
    ossl_bindings(&["-std=c90"], out_file);
}

fn set_pretty_panic() {
    set_hook(Box::new(|panic_info| {
        if let Some(s) = panic_info.payload().downcast_ref::<&str>() {
            if s != &"panic in a function that cannot unwind" {
                println!("Compile Error: {s:?}");
            }
        } else if let Some(s) = panic_info.payload().downcast_ref::<String>() {
            if s != "panic in a function that cannot unwind" {
                println!("Compile Error: {s:?}");
            }
        } else {
            if let Some(location) = panic_info.location() {
                println!(
                    "Unrecognized compile error in file '{}' at line {}",
                    location.file(),
                    location.line(),
                );
            } else {
                println!("Unknown panic with no location information...");
            }
        }
    }));
}

fn main() {
    set_pretty_panic();

    let features = Features::to_bools();

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    let pkcs11_bindings = out_path.join("pkcs11_bindings.rs");
    let ossl_bindings = out_path.join("ossl_bindings.rs");

    /* PKCS11 Headers */
    let pkcs11_header = if features.pkcs11_3_2 {
        "pkcs11_headers/3.2-prerelease/pkcs11.h"
    } else {
        "pkcs11_headers/3.1/pkcs11.h"
    };
    println!("cargo:rerun-if-changed={}", pkcs11_header);
    bindgen::Builder::default()
        .header(pkcs11_header)
        .derive_default(true)
        .formatter(bindgen::Formatter::Prettyplease)
        .blocklist_type("CK_FUNCTION_LIST_PTR")
        .blocklist_type("CK_FUNCTION_LIST_3_0_PTR")
        .blocklist_type("CK_FUNCTION_LIST_3_2_PTR")
        .blocklist_type("CK_INTERFACE")
        .blocklist_var("CK_UNAVAILABLE_INFORMATION")
        .parse_callbacks(Box::new(Pkcs11Callbacks))
        .generate()
        .expect("Unable to generate bindings")
        .write_to_file(&pkcs11_bindings)
        .expect("Couldn't write bindings!");

    /* OpenSSL Cryptography */
    if features.dynamic {
        use_system_ossl(&ossl_bindings);
    } else {
        build_ossl(&features, &ossl_bindings);
    }

    println!("cargo:rerun-if-changed=build.rs");
}
