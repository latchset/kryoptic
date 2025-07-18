// Copyright 2024 Simo Sorce
// See LICENSE.txt file for terms

//! This module contains constants and functions to populate information
//! fields returned by PKCS#11 APIs

use std::env;

use crate::pkcs11::CK_VERSION;

/// Default slot description.
pub const SLOT_DESCRIPTION: &str = "Kryoptic Slot";
/// Default manufacturer ID string.
pub const MANUFACTURER_ID: &str = "Kryoptic Project";
/// Default token label (differs slightly if FIPS feature is enabled).
#[cfg(feature = "fips")]
pub const TOKEN_LABEL: &str = "Kryoptic FIPS Token";
/// Default token label.
#[cfg(not(feature = "fips"))]
pub const TOKEN_LABEL: &str = "Kryoptic Soft Token";
/// Default token model string (differs slightly if FIPS feature is enabled).
#[cfg(feature = "fips")]
pub const TOKEN_MODEL: &str = "FIPS-140-3 v1";
/// Default token model string.
#[cfg(not(feature = "fips"))]
pub const TOKEN_MODEL: &str = "v1";

/// Returns the hardware version reported by Slots and Tokens
///
/// It is hard coded to report 0.0 as there is no hardware involved here.
pub fn hardware_version() -> CK_VERSION {
    CK_VERSION { major: 0, minor: 0 }
}

/// Returns the firmware version reported by Slots and Tokens
///
/// It sources the major and minor version at build time from the release
/// version number set in Cargo.toml, there is no space in the CK_VERSION
/// structure to return a patch level, so only the X and Y of X.Y.Z version
/// number are returned here.
pub fn firmware_version() -> CK_VERSION {
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

    CK_VERSION {
        major: maj,
        minor: min,
    }
}
