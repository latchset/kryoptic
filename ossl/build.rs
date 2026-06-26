// Copyright 2025 Simo Sorce
// See LICENSE.txt file for terms

use std::env;
use std::panic::set_hook;

const OPENSSL_3_0_7: i64 = 0x30000070;
const OPENSSL_3_2_0: i64 = 0x30200000;
const OPENSSL_3_5_0: i64 = 0x30500000;
const OPENSSL_4_0_0: i64 = 0x40000000;

fn check_ossl_version(v: String) {
    // Proxy the version for the api_level() API
    println!("cargo:rustc-env=OPENSSL_VERSION_NUMBER={}", v);

    let version = i64::from_str_radix(&v, 16).unwrap();
    if version < OPENSSL_4_0_0 {
        #[cfg(feature = "ossl400")]
        panic!("OpenSSL 4.0.0 or later is required");
    }
    if version < OPENSSL_3_5_0 {
        #[cfg(feature = "ossl350")]
        panic!("OpenSSL 3.5.0 or later is required");
    }
    if version < OPENSSL_3_2_0 {
        #[cfg(feature = "ossl320")]
        panic!("OpenSSL 3.2.0 or later is required");
    }
    if version < OPENSSL_3_0_7 {
        panic!(
            "OpenSSL 3.0.7 is the minimum viable version. Found {:x}",
            version
        );
    }
    /* Emit versions we found, versions stack, so code
     * just need to build conditionalized just to the older version
     * that introduced the desired feature */
    println!("cargo::rustc-cfg=ossl_v307");
    if version >= OPENSSL_3_2_0 {
        println!("cargo::rustc-cfg=ossl_v320");
    }
    if version >= OPENSSL_3_5_0 {
        println!("cargo::rustc-cfg=ossl_v350");
    }
    if version >= OPENSSL_4_0_0 {
        println!("cargo::rustc-cfg=ossl_v400");
    }

    // backward compatible OPENSSL_FULL_VERSION_STR
    let major = (version >> 28) & 0xF;
    let minor = (version >> 20) & 0xFF;
    let patch = (version >> 4) & 0xFF;
    let version_string = format!("{}.{}.{}", major, minor, patch);
    println!(
        "cargo:rustc-env=OPENSSL_FULL_VERSION_STR={}",
        version_string
    );
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

    if cfg!(all(feature = "openssl-sys", feature = "ossl-sys")) {
        panic!("You can't combine openssl-sys and ossl-sys.")
    }

    /* Always emit known configs */
    println!(
        "cargo::rustc-check-cfg=cfg(ossl_v307,ossl_v320,ossl_v350,ossl_v400)"
    );

    /* OpenSSL Cryptography */
    if let Ok(v) = env::var("DEP_OPENSSL_VERSION_NUMBER") {
        check_ossl_version(v);
    } else if let Ok(v) = env::var("DEP_OPENSSL4_VERSION_NUMBER") {
        check_ossl_version(v);
    } else {
        panic!(
            "No OpenSSL version detected. Neither openssl-sys nor ossl-sys \
            provided VERSION_NUMBER"
        );
    }

    println!("cargo:rerun-if-changed=build.rs");
}
