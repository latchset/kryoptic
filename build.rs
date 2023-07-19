// Copyright 2023 Simo Sorce
// See License file for terms

fn main() {
    println!("cargo:rerun-if-changed=pkcs11.h");

    let bindings = bindgen::Builder::default()
        .header("pkcs11.h")
        .derive_default(true)
        .formatter(bindgen::Formatter::Prettyplease)
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        .generate()
        .expect("Unable to generate bindings");

    bindings
        .write_to_file("src/pkcs11_bindings.rs")
        .expect("Couldn't write bindings!");
}

