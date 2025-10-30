// Copyright 2025 Simo Sorce
// See LICENSE.txt file for terms

mod conformance_lib;

use clap::Parser;
use conformance_lib::{
    executor, pkcs11_wrapper, profile, token_init, Arguments,
};
use libc;
use std::ffi::CString;
use std::fs;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Arguments::parse();

    if args.init {
        return token_init::init_token(&args);
    }

    if args.profile.is_some() {
        eprintln!("Error: --profile can only be used with --init");
        std::process::exit(1);
    }

    if args.debug {
        eprintln!("Debug mode enabled.");
    }

    let xml_profile_path = match args.xml_profile {
        Some(ref path) => path,
        None => {
            eprintln!("Error: xml_profile is required when not using --init");
            std::process::exit(1);
        }
    };
    if args.debug {
        eprintln!("XML file path: {}", xml_profile_path);
    }

    let xml_content = fs::read_to_string(&xml_profile_path)?;
    if args.debug {
        eprintln!(
            "Successfully read XML file content ({} bytes).",
            xml_content.len()
        );
    }

    let pkcs11_profile: profile::Pkcs11Profile =
        quick_xml::de::from_str(&xml_content)?;
    if args.debug {
        eprintln!("Successfully parsed XML into Pkcs11Profile struct.");
        eprintln!("Found {} calls in the profile.", pkcs11_profile.calls.len());
    }

    if let Some(output_format) = args.output {
        if output_format.to_uppercase() == "JSON" {
            let json_output =
                profile::generate_json(pkcs11_profile, args.debug)?;
            println!("{}", json_output);
            return Ok(());
        } else {
            eprintln!("Error: unsupported output format '{}'", output_format);
            std::process::exit(1);
        }
    }

    let module_path = match args.pkcs11_module {
        Some(ref path) => path.as_str(),
        None => {
            eprintln!("Error: --pkcs11-module is required when not using --output JSON");
            std::process::exit(1);
        }
    };

    let soname = CString::new(module_path)?;
    let rtld_flags = libc::RTLD_LOCAL | libc::RTLD_NOW;
    let lib_handle =
        unsafe { libc::dlopen(soname.as_c_str().as_ptr(), rtld_flags) };
    if lib_handle.is_null() {
        eprintln!(
            "Failed to load pkcs11 module: {}",
            pkcs11_wrapper::dl_error()
        );
        std::process::exit(1);
    }

    let res = {
        let pkcs11 = match pkcs11_wrapper::FuncList::from_symbol_name(
            lib_handle,
            "C_GetFunctionList",
        ) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("Failed to get function list: {}", e);
                unsafe {
                    libc::dlclose(lib_handle);
                }
                std::process::exit(1);
            }
        };
        executor::execute_calls(&pkcs11, pkcs11_profile, &args)
    };

    unsafe {
        libc::dlclose(lib_handle);
    }
    res
}
