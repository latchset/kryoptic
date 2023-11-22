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

#[derive(Debug)]
pub struct HaclCallbacks;

impl bindgen::callbacks::ParseCallbacks for HaclCallbacks {
    fn int_macro(
        &self,
        name: &str,
        _: i64,
    ) -> Option<bindgen::callbacks::IntKind> {
        if name.starts_with("Spec_") {
            Some(bindgen::callbacks::IntKind::Custom {
                name: "u8",
                is_signed: false,
            })
        } else if name.starts_with("Hacl_Streaming_Types_") {
            Some(bindgen::callbacks::IntKind::Custom {
                name: "u8",
                is_signed: false,
            })
        } else if name.starts_with("EverCrypt_Error_") {
            Some(bindgen::callbacks::IntKind::Custom {
                name: "u8",
                is_signed: false,
            })
        } else if name.ends_with("_HASH_LEN") {
            Some(bindgen::callbacks::IntKind::Custom {
                name: "usize",
                is_signed: false,
            })
        } else {
            None
        }
    }
}

fn build_hacl() {
    let hacl_path = std::path::PathBuf::from("hacl/gcc-compatible")
        .canonicalize()
        .expect("cannot canonicalize path");

    let hacl_conf = hacl_path.join("config.h");
    let hacl_krml_include = hacl_path
        .join("../karamel/include")
        .canonicalize()
        .expect("cannot canonicalize path");
    let hacl_krml_dist = hacl_path
        .join("../karamel/krmllib/dist/minimal")
        .canonicalize()
        .expect("cannot canonicalize path");
    let hacl_h = hacl_path.join("hacl.h");

    if !std::process::Command::new("./configure")
        .current_dir(&hacl_path)
        .output()
        .expect("could not run hacl `configure`")
        .status
        .success()
    {
        // Panic if the command was not successful.
        panic!("could not configure HACL");
    }

    if !std::process::Command::new("make")
        .current_dir(&hacl_path)
        .output()
        .expect("could not run hacl `make`")
        .status
        .success()
    {
        // Panic if the command was not successful.
        panic!("could not build HACL library");
    }

    println!("cargo:rustc-link-search={}", hacl_path.to_str().unwrap());
    println!("cargo:rustc-link-lib=evercrypt");
    println!("cargo:rerun-if-changed={}", hacl_conf.to_str().unwrap());

    bindgen::Builder::default()
        .header(hacl_h.to_str().unwrap())
        .clang_arg(format!("-I{}", hacl_krml_include.display()))
        .clang_arg(format!("-I{}", hacl_krml_dist.display()))
        /* https://github.com/rust-lang/rust-bindgen/issues/2500 */
        .clang_arg("-D__AVX512VLFP16INTRIN_H") /* workaround */
        .clang_arg("-D__AVX512FP16INTRIN_H") /* workaround */
        .derive_default(true)
        .formatter(bindgen::Formatter::Prettyplease)
        .allowlist_item("EverCrypt_.*")
        .allowlist_item("Hacl_Hash_Definitions.*")
        .allowlist_item("Hacl_HMAC_DRBG.*")
        .allowlist_item("Spec_.*")
        .allowlist_item("SHA.*_HASH_LEN")
        .parse_callbacks(Box::new(HaclCallbacks))
        .generate()
        .expect("Unable to generate bindings")
        .write_to_file("src/hacl_bindings.rs")
        .expect("Couldn't write bindings!");
}

fn build_gmp() {
    let gmp_path = std::path::PathBuf::from("gmp")
        .canonicalize()
        .expect("cannot canonicalize gmp_path");

    let gmp_h = gmp_path
        .join("gmp-h.in")
        .canonicalize()
        .expect("cannot canonicalize gmp_h path");

    if !std::process::Command::new("./.bootstrap")
        .current_dir(&gmp_path)
        .output()
        .expect("could not run gmp `.bootstrap`")
        .status
        .success()
    {
        // Panic if the command was not successful.
        panic!("could not configure GMP");
    }

    if !std::process::Command::new("./configure")
        .current_dir(&gmp_path)
        .env("CFLAGS", "-fPIC -ggdb3")
        .arg("--disable-shared")
        .output()
        .expect("could not run gmp `configure`")
        .status
        .success()
    {
        // Panic if the command was not successful.
        panic!("could not configure GMP");
    }

    if !std::process::Command::new("make")
        .current_dir(&gmp_path)
        .output()
        .expect("could not run gmp `make`")
        .status
        .success()
    {
        // Panic if the command was not successful.
        panic!("could not build GMP library");
    }

    let gmp_lib = gmp_path
        .join(".libs")
        .canonicalize()
        .expect("cannot canonicalize gmp_lib path");

    println!("cargo:rustc-link-search={}", gmp_lib.to_str().unwrap());
    println!("cargo:rustc-link-lib=gmp");
    println!("cargo:rerun-if-changed={}", gmp_h.to_str().unwrap());
}

fn main() {
    println!("cargo:rerun-if-changed=pkcs11_headers/3.1/pkcs11.h");

    /* PKCS11 Headers */
    bindgen::Builder::default()
        .header("pkcs11_headers/3.1/pkcs11.h")
        .derive_default(true)
        .formatter(bindgen::Formatter::Prettyplease)
        .blocklist_type("CK_FUNCTION_LIST_PTR")
        .blocklist_type("CK_FUNCTION_LIST_3_0_PTR")
        .blocklist_type("CK_INTERFACE")
        .parse_callbacks(Box::new(Pkcs11Callbacks))
        .generate()
        .expect("Unable to generate bindings")
        .write_to_file("src/pkcs11_bindings.rs")
        .expect("Couldn't write bindings!");

    /* HACL Code */
    build_hacl();

    /* GMP for Nettle */
    build_gmp();

    /* Nettle for RSA */
    println!("cargo:rerun-if-changed=nettle.h");
    println!("cargo:rustc-link-lib=nettle");
    println!("cargo:rustc-link-lib=hogweed");
    bindgen::Builder::default()
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
        .expect("Unable to generate nettle bindings")
        .write_to_file("src/nettle_bindings.rs")
        .expect("Couldn't write bindings!");
}
