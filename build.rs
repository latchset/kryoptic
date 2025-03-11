// Copyright 2023 Simo Sorce
// See LICENSE.txt file for terms

use std::env;
use std::path::{Path, PathBuf};

#[derive(Debug)]
pub struct Pkcs11Callbacks;

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

fn ossl_bindings(header: &str, args: &[&str], out_file: &Path) {
    bindgen::Builder::default()
        .header(header)
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
        .generate()
        .expect("Unable to generate bindings")
        .write_to_file(out_file)
        .expect("Couldn't write bindings!");
}

#[cfg(not(feature = "dynamic"))]
fn build_ossl(out_file: &Path) {
    let openssl_path = std::path::PathBuf::from("openssl")
        .canonicalize()
        .expect("cannot canonicalize path");

    #[cfg(feature = "fips")]
    let (libpath, bldargs, header) = {
        let providers_path = openssl_path
            .join("providers")
            .canonicalize()
            .expect("OpenSSL providers path unavailable");

        let libfips = format!("{}/libfips.a", providers_path.to_string_lossy());
        let buildargs = [
            "--debug",
            "enable-fips",
            "no-mdc2",
            "no-ec2m",
            "no-sm2",
            "no-sm4",
            "no-des",
            "no-dsa",
            "no-atexit",
            "-DDEVRANDOM=\\\"/dev/urandom\\\" -DOPENSSL_PEDANTIC_ZEROIZATION -DFIPS_VENDOR=\\\"Kryoptic\\\" -DKRYOPTIC_FIPS_VERSION=\\\"1.0.0-test\\\"",
        ];

        println!(
            "cargo:rustc-link-search={}",
            providers_path.to_string_lossy()
        );
        println!("cargo:rustc-link-lib=static=fips");
        println!("cargo:rerun-if-changed={}", libfips);

        (libfips, buildargs, "fips.h")
    };

    #[cfg(not(feature = "fips"))]
    let (libpath, bldargs, header) = {
        let libcrypto =
            format!("{}/libcrypto.a", openssl_path.to_string_lossy());
        let buildargs = [
            "--debug",
            "no-mdc2",
            "no-ec2m",
            "no-sm2",
            "no-sm4",
            "no-des",
            "-DDEVRANDOM=\\\"/dev/urandom\\\"",
        ];

        println!("cargo:rustc-link-search={}", openssl_path.to_str().unwrap());
        println!("cargo:rustc-link-lib=static=crypto");
        println!("cargo:rerun-if-changed={}", libcrypto);

        (libcrypto, buildargs, "ossl.h")
    };

    match std::path::Path::new(&libpath).try_exists() {
        Ok(true) => (),
        _ => {
            /* openssl: ./Configure --debug enable-fips */
            if !std::process::Command::new("./Configure")
                .current_dir(&openssl_path)
                .args(bldargs)
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

    let include_path = openssl_path
        .join("include")
        .canonicalize()
        .expect("OpenSSL include path unavailable");

    let args = [&format!("-I{}", include_path.to_str().unwrap()), "-std=c90"];

    ossl_bindings(header, &args, out_file);
}

#[cfg(feature = "dynamic")]
fn use_system_ossl(out_file: &Path) {
    println!("cargo:rustc-link-lib=crypto");
    ossl_bindings("ossl.h", &["-std=c90"], out_file);
}

fn main() {
    #[cfg(all(feature = "dynamic", feature = "fips"))]
    compile_error!("features `dynamic` and `fips` are mutually exclusive");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    let pkcs11_bindings = out_path.join("pkcs11_bindings.rs");
    let ossl_bindings = out_path.join("ossl_bindings.rs");

    /* PKCS11 Headers */
    let pkcs11_header = "pkcs11_headers/3.1/pkcs11.h";
    println!("cargo:rerun-if-changed={}", pkcs11_header);
    bindgen::Builder::default()
        .header(pkcs11_header)
        .derive_default(true)
        .formatter(bindgen::Formatter::Prettyplease)
        .blocklist_type("CK_FUNCTION_LIST_PTR")
        .blocklist_type("CK_FUNCTION_LIST_3_0_PTR")
        .blocklist_type("CK_INTERFACE")
        .blocklist_var("CK_UNAVAILABLE_INFORMATION")
        .parse_callbacks(Box::new(Pkcs11Callbacks))
        .generate()
        .expect("Unable to generate bindings")
        .write_to_file(&pkcs11_bindings)
        .expect("Couldn't write bindings!");

    /* OpenSSL Cryptography */
    #[cfg(feature = "dynamic")]
    use_system_ossl(&ossl_bindings);

    #[cfg(not(feature = "dynamic"))]
    println!("cargo:rerun-if-changed={}", ".git/modules/openssl/HEAD");

    #[cfg(not(feature = "dynamic"))]
    build_ossl(&ossl_bindings);

    println!("cargo:rerun-if-changed=build.rs");
}
