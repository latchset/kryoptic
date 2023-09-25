// Copyright 2023 Simo Sorce
// See LICENSE.txt file for terms

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

    fn include_file(&self, filename: &str) {
        println!("cargo:rerun-if-changed={filename}");
    }
}

fn main() {
    println!("cargo:rerun-if-changed=pkcs11.h");

    let bindings = bindgen::Builder::default()
        .header("pkcs11.h")
        .derive_default(true)
        .formatter(bindgen::Formatter::Prettyplease)
        .blocklist_type("CK_FUNCTION_LIST_PTR")
        .blocklist_type("CK_FUNCTION_LIST_3_0_PTR")
        .blocklist_type("CK_INTERFACE")
        .parse_callbacks(Box::new(Pkcs11Callbacks))
        .generate()
        .expect("Unable to generate bindings");

    bindings
        .write_to_file("src/pkcs11_bindings.rs")
        .expect("Couldn't write bindings!");

    println!("cargo:rerun-if-changed=nettle.h");
    println!("cargo:rustc-link-lib=nettle");
    println!("cargo:rustc-link-lib=hogweed");
    println!("cargo:rustc-link-lib=gmp");
    let nettle_bindings = bindgen::Builder::default()
        .header("nettle.h")
        .derive_default(true)
        .formatter(bindgen::Formatter::Prettyplease)
        .blocklist_type("_.*_t")
        .blocklist_type("__u_.*")
        .blocklist_type(".*int_.*_t")
        .blocklist_type(".*intmax_t")
        .blocklist_type("gmp_.*")
        .blocklist_item(".*_MIN")
        .blocklist_item(".*_MAX")
        .blocklist_item("NR_OPEN")
        .blocklist_item("MAX_.*")
        .blocklist_item("PIPE_BUF")
        .blocklist_item("PTHREAD_.*")
        .blocklist_item("_.*_H")
        .blocklist_item("_.*_T")
        .blocklist_item("__GNU_.*")
        .blocklist_item("__HAVE_.*")
        .blocklist_item("__USE_.*")
        .blocklist_item("_POSIX_.*")
        .blocklist_item("_.*LIBC_.*")
        .blocklist_item(".*GMP_.*")
        .blocklist_item("__STDC_.*")
        .blocklist_item("__.*TIME.*")
        .blocklist_item("_.*SOURCE.*")
        .blocklist_item("_.*WORDSIZE.*")
        .blocklist_item("__glibc.*")
        .blocklist_item("__LDOUBLE.*")
        .blocklist_item("__STATFS.*")
        .blocklist_item("__FD.*")
        .blocklist_item("max_align_t")
        .blocklist_item("__gmp.*rand.*")
        .generate()
        .expect("Unable to generate nettle bindings");

    nettle_bindings
        .write_to_file("src/nettle_bindings.rs")
        .expect("Couldn't write bindings!");
}
