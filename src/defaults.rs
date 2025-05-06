// Copyright 2024 Simo Sorce
// See LICENSE.txt file for terms

//! This module contains constants and functions to populate information
//! fields returned by PKCS#11 APIs

use std::env;

use crate::interface;

/// Returns the hardware version reported by Slots and Tokens
///
/// It is hard coded to report 0.0 as there is no hardware involved here.
pub fn hardware_version() -> interface::CK_VERSION {
    interface::CK_VERSION { major: 0, minor: 0 }
}

/// Returns the firmware version reported by Slots and Tokens
///
/// It sources the major and minor version at build time from the release
/// version number set in Cargo.toml, there is no space in the CK_VERSION
/// structure to return a patch level, so only the X and Y of X.Y.Z version
/// number are returned here.
pub fn firmware_version() -> interface::CK_VERSION {
    let maj_str = env!("CARGO_PKG_VERSION_MAJOR");
    let maj = match maj_str.parse::<u8>() {
        Ok(v) => v,
        Err(e) => panic!("Couldn't parse package major version: {e}"),
    };

    let min_str = env!("CARGO_PKG_VERSION_MINOR");
    let min = match min_str.parse::<u8>() {
        Ok(v) => v,
        Err(e) => panic!("Couldn't parse package minor version: {e}"),
    };

    interface::CK_VERSION {
        major: maj,
        minor: min,
    }
}
