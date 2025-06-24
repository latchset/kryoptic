// Copyright 2025 Simo Sorce
// See LICENSE.txt file for terms

use std::env;
use std::path::PathBuf;

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

fn main() {
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    let pkcs11_bindings = out_path.join("pkcs11_bindings.rs");

    /* PKCS11 Headers */
    let pkcs11_header = "headers/3.2/pkcs11.h";

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

    println!("cargo:rerun-if-changed=build.rs");
}
