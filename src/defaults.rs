// Copyright 2024 Simo Sorce
// See LICENSE.txt file for terms

//! This module contains constants and functions to populate information
//! fields returned by PKCS#11 APIs

use std::env;

use crate::pkcs11::CK_VERSION;

const fn parse_manufacturer_id(val: Option<&'static str>) -> &'static str {
    match val {
        Some(m) if !m.is_empty() => {
            if m.len() > 32 {
                panic!("The maximum manufacturer id length is 32");
            }
            m
        }
        _ => "Kryoptic Project",
    }
}

const fn parse_token_label(val: Option<&'static str>) -> &'static str {
    match val {
        Some(l) if !l.is_empty() => {
            if l.len() > 32 {
                panic!("The maximum token label length is 32");
            }
            l
        }
        _ => {
            #[cfg(feature = "fips")]
            {
                "Kryoptic FIPS Token"
            }
            #[cfg(not(feature = "fips"))]
            {
                "Kryoptic Soft Token"
            }
        }
    }
}

#[allow(dead_code)]
const fn check_token_model(m: &'static str) -> &'static str {
    if m.len() > 16 {
        panic!("The maximum token model length is 16");
    }
    m
}

#[cfg(any(test, feature = "fips"))]
fn truncate_token_model(mut s: String) -> String {
    if s.len() > 16 {
        #[cfg(feature = "log")]
        log::warn!(
            "FIPS provider version string exceeds 16 bytes, truncating: {s}"
        );
        let mut idx = 16;
        while !s.is_char_boundary(idx) {
            idx -= 1;
        }
        s.truncate(idx);
    }
    s
}

/// Default slot description.
pub const SLOT_DESCRIPTION: &str = "Kryoptic Slot";
/// Default manufacturer ID string.
pub const MANUFACTURER_ID: &str =
    parse_manufacturer_id(option_env!("KRYOPTIC_MANUFACTURER_ID"));
/// Default token label (differs slightly if FIPS feature is enabled).
pub const TOKEN_LABEL: &str =
    parse_token_label(option_env!("KRYOPTIC_TOKEN_LABEL"));
/// Default token model string (differs slightly if FIPS feature is enabled).
#[cfg(feature = "fips")]
static TOKEN_MODEL: std::sync::LazyLock<String> =
    std::sync::LazyLock::new(|| {
        let version = match crate::fips::provider::get_fips_provider_info() {
            Ok(info) => info
                .version
                .unwrap_or_else(|| "retrieval error".to_string()),
            Err(_) => "retrieval error".to_string(),
        };
        truncate_token_model(version)
    });
/// Default token model string.
#[cfg(not(feature = "fips"))]
const TOKEN_MODEL: &str = check_token_model(env!("CARGO_PKG_VERSION"));

/// Returns the default token model string.
pub fn token_model() -> &'static str {
    #[cfg(feature = "fips")]
    {
        TOKEN_MODEL.as_str()
    }
    #[cfg(not(feature = "fips"))]
    {
        TOKEN_MODEL
    }
}

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_token_model() {
        assert!(!token_model().is_empty());
        assert!(token_model().len() <= 16);
        #[cfg(feature = "fips")]
        {
            assert_ne!(token_model(), "retrieval error");
            let info = crate::fips::provider::get_fips_provider_info().unwrap();
            assert_eq!(
                token_model(),
                truncate_token_model(info.version.unwrap())
            );
        }
        #[cfg(not(feature = "fips"))]
        {
            assert_eq!(token_model(), env!("CARGO_PKG_VERSION"));
        }
    }

    #[test]
    fn test_manufacturer_id_and_token_label() {
        assert!(MANUFACTURER_ID.len() <= 32);
        assert!(TOKEN_LABEL.len() <= 32);
        assert_eq!(parse_manufacturer_id(None), "Kryoptic Project");
        assert_eq!(parse_manufacturer_id(Some("")), "Kryoptic Project");
        assert_eq!(
            parse_manufacturer_id(Some("Custom Manufacturer")),
            "Custom Manufacturer"
        );
        assert_eq!(
            parse_manufacturer_id(Some("12345678901234567890123456789012")),
            "12345678901234567890123456789012"
        );
        #[cfg(feature = "fips")]
        assert_eq!(parse_token_label(None), "Kryoptic FIPS Token");
        #[cfg(not(feature = "fips"))]
        assert_eq!(parse_token_label(None), "Kryoptic Soft Token");
        #[cfg(feature = "fips")]
        assert_eq!(parse_token_label(Some("")), "Kryoptic FIPS Token");
        #[cfg(not(feature = "fips"))]
        assert_eq!(parse_token_label(Some("")), "Kryoptic Soft Token");
        assert_eq!(parse_token_label(Some("Custom Label")), "Custom Label");
        assert_eq!(
            parse_token_label(Some("12345678901234567890123456789012")),
            "12345678901234567890123456789012"
        );
    }

    #[test]
    #[should_panic(expected = "The maximum manufacturer id length is 32")]
    fn test_manufacturer_id_too_long() {
        let _ =
            parse_manufacturer_id(Some("123456789012345678901234567890123"));
    }

    #[test]
    #[should_panic(expected = "The maximum token label length is 32")]
    fn test_token_label_too_long() {
        let _ = parse_token_label(Some("123456789012345678901234567890123"));
    }

    #[test]
    fn test_check_token_model() {
        assert_eq!(check_token_model("1.2.3"), "1.2.3");
        assert_eq!(check_token_model("1234567890123456"), "1234567890123456");
    }

    #[test]
    #[should_panic(expected = "The maximum token model length is 16")]
    fn test_token_model_too_long() {
        let _ = check_token_model("12345678901234567");
    }

    #[test]
    fn test_truncate_token_model() {
        assert_eq!(truncate_token_model("1.2.3".to_string()), "1.2.3");
        assert_eq!(
            truncate_token_model("1234567890123456".to_string()),
            "1234567890123456"
        );
        assert_eq!(
            truncate_token_model("12345678901234567890".to_string()),
            "1234567890123456"
        );
        assert_eq!(
            truncate_token_model("123456789012345€".to_string()),
            "123456789012345"
        );
    }
}
