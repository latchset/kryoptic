// Copyright 2025 Simo Sorce
// See LICENSE.txt file for terms

use std::env;
use std::panic::set_hook;
use std::path::{Path, PathBuf};

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
                #[cfg(feature = "ossl350")]
                panic!("OpenSSL 3.5.0 or later is required");
            }
            if value < OPENSSL_3_2_0 {
                #[cfg(feature = "ossl320")]
                panic!("OpenSSL 3.2.0 or later is required");
            }
            if value < OPENSSL_3_0_7 {
                panic!(
                    "OpenSSL 3.0.7 is the minimum viable version. Found {:x}",
                    value
                );
            }
            /* Emit versions we found, versions stack, so code
             * just need to build conditionalized just to the older version
             * that introduced the desired feature */
            println!("cargo::rustc-cfg=ossl_v307");
            if value >= OPENSSL_3_2_0 {
                println!("cargo::rustc-cfg=ossl_v320");
            }
            if value >= OPENSSL_3_5_0 {
                println!("cargo::rustc-cfg=ossl_v350");
            }
        }

        None
    }

    fn str_macro(&self, name: &str, _value: &[u8]) {
        if name == "OSSL_PKEY_PARAM_SLH_DSA_SEED" {
            println!("cargo::rustc-cfg=ossl_slhdsa")
        }
        if name == "OSSL_PKEY_PARAM_ML_DSA_SEED" {
            println!("cargo::rustc-cfg=ossl_mldsa")
        }
        if name == "OSSL_PKEY_PARAM_ML_KEM_SEED" {
            println!("cargo::rustc-cfg=ossl_mlkem")
        }
    }

    fn func_macro(&self, name: &str, _value: &[&[u8]]) {
        if name == "OSSL_PARAM_clear_free" {
            println!("cargo::rustc-cfg=param_clear_free")
        }
    }
}

fn ossl_bindings<T: AsRef<str>>(args: &[T], out_file: &Path) {
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

fn build_ossl(out_file: &Path) {
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
    ];

    match std::env::var("CARGO_CFG_TARGET_ARCH") {
        Ok(arch) => match arch.as_str() {
            "x86" => {
                buildargs.insert(0, "linux-elf");
                buildargs.push("-m32");
                buildargs.push("-latomic");
            }
            "x86_64" => buildargs.push("enable-ec_nistp_64_gcc_128"),
            "aarch64" => buildargs.push("enable-ec_nistp_64_gcc_128"),
            "powerpc64" => buildargs.push("enable-ec_nistp_64_gcc_128"),
            "s390x" => buildargs.push("no-ec_nistp_64_gcc_128"),
            _ => (),
        },
        _ => panic!("No arch available in CARGO_CFG_TARGET_ARCH"),
    }

    if env::var("PROFILE").unwrap().as_str() == "debug" {
        buildargs.push("--debug");
    }

    let mut defines = "-DDEVRANDOM=\\\"/dev/urandom\\\"".to_string();

    let ar_path: std::path::PathBuf;
    let ar_name: &str;

    if cfg!(feature = "fips") {
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

    /* must declare this after the static one or builds will fail */
    match std::env::var("CARGO_CFG_TARGET_ARCH") {
        Ok(arch) => match arch.as_str() {
            "x86" => {
                println!("cargo::rustc-link-lib=atomic");
            }
            _ => (),
        },
        _ => panic!("No arch available in CARGO_CFG_TARGET_ARCH"),
    }

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

    let mut args = vec![include_path.as_str()];
    if cfg!(feature = "fips") {
        args.push("-D_KRYOPTIC_FIPS_");
    }

    ossl_bindings(&args, out_file);
}

fn use_system_ossl(out_file: &Path) {
    let library = pkg_config::Config::new()
        .atleast_version("3.0.7")
        .probe("openssl")
        .unwrap();

    let mut args: Vec<String> = Vec::new();
    for include_path in library.include_paths {
        args.push(["-I", include_path.to_str().unwrap()].concat());
    }

    ossl_bindings(&args, out_file);
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

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    let ossl_bindings = out_path.join("ossl_bindings.rs");

    /* Always emit known configs */
    println!("cargo::rustc-check-cfg=cfg(ossl_v307,ossl_v320,ossl_v350,ossl_mldsa,ossl_mlkem,ossl_slhdsa,param_clear_free)");

    /* OpenSSL Cryptography */
    if cfg!(feature = "dynamic") {
        use_system_ossl(&ossl_bindings);
    } else {
        build_ossl(&ossl_bindings);
    }

    println!("cargo:rerun-if-changed=build.rs");
}
