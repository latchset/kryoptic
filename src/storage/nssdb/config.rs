// Copyright 2024 Simo Sorce
// See LICENSE.txt file for terms

//! This module defines the `NSSConfig` struct and associated functions for
//! parsing the configuration string used to initialize the NSSDB storage
//! backend, mimicking the behavior of NSS's own module specification parsing.

use crate::defaults;
use crate::error::Result;

use crate::pkcs11::*;

/// Holds configuration parameters for the NSSDB storage backend.
///
/// These parameters are typically parsed from a string provided during
/// `C_Initialize` or via environment variables, similar to how NSS modules
/// are configured.
///
/// Mostly documented at:
/// <https://nss-crypto.org/reference/security/nss/legacy/pkcs11/module_specs/index.html>
#[derive(Debug)]
pub struct NSSConfig {
    /// Path to the NSS database directory (e.g., `~/.pki/nssdb`).
    pub configdir: Option<String>,
    /// Directory for update files (NSS specific, unused).
    pub updatedir: Option<String>,
    /// ID for update mechanism (NSS specific, unused).
    pub updateid: Option<String>,
    /// Name of the security module database file (usually `secmod.db`).
    pub secmod: String,
    /// Manufacturer ID override for the token.
    pub manufacturer: Option<String>,
    /// Library description override.
    pub library_description: Option<String>,
    /// Prefix for certificate database filenames (e.g., "cert").
    pub cert_prefix: String,
    /// Prefix for key database filenames (e.g., "key").
    pub key_prefix: String,
    /// Description override for the PKCS#11 token ("Crypto Token").
    pub token_crypto_description: Option<String>,
    /// Description override for the PKCS#11 token ("DB Token").
    pub token_db_description: Option<String>,
    /// Description override for the PKCS#11 token ("FIPS Token").
    pub token_fips_description: Option<String>,
    /// Description override for the PKCS#11 slot ("Crypto Slot").
    pub slot_crypto_description: Option<String>,
    /// Description override for the PKCS#11 slot ("DB Slot").
    pub slot_db_description: Option<String>,
    /// Description override for the PKCS#11 slot ("FIPS Slot").
    pub slot_fips_description: Option<String>,
    /// Description override for the update token (likely unused).
    pub update_description: Option<String>,
    /// Minimum PIN length requirement (parsed from `minPwLen`).
    pub min_pin_len: usize,
    /// Flag indicating the database should be opened read-only.
    pub read_only: bool,
    /// Flag to skip loading/using `secmod.db` (NSS specific).
    pub no_mod_db: bool,
    /// Flag to prevent opening/using the certificate database (`certN.db`).
    pub no_cert_db: bool,
    /// Flag to prevent opening/using the key database (`keyN.db`).
    pub no_key_db: bool,
    /// Flag to force opening databases even if initialization seems incomplete.
    pub force_open: bool,
    /// Flag indicating a password/PIN is required to access the token.
    pub password_required: bool,
    /// Flag suggesting the backend should optimize for space (NSS specific).
    pub optimize_space: bool,
    /* tokens: currently unsupported */
}

/// Default values for `NSSConfig`.
impl Default for NSSConfig {
    fn default() -> Self {
        NSSConfig {
            configdir: None,
            updatedir: None,
            updateid: None,
            secmod: String::from("secmod.db"),
            manufacturer: None,
            library_description: None,
            cert_prefix: String::from(""),
            key_prefix: String::from(""),
            token_crypto_description: None,
            token_db_description: None,
            token_fips_description: None,
            slot_crypto_description: None,
            slot_db_description: None,
            slot_fips_description: None,
            update_description: None,
            min_pin_len: 0,
            read_only: false,
            no_mod_db: false,
            no_cert_db: false,
            no_key_db: false,
            force_open: false,
            password_required: false,
            optimize_space: false,
        }
    }
}

/// Character used to detect the end of a parameter value if no quotes/braces
/// are used.
const END_VALUE: u8 = b' ';

impl NSSConfig {
    /// Parses comma-separated flags from the `flags=` parameter value.
    /// Updates boolean fields like `read_only`, `no_cert_db`, etc.
    fn parse_flags(&mut self, args: &[u8]) -> Result<()> {
        let mut idx = 0;
        while idx < args.len() {
            let next = match args[idx..].iter().position(|&x| x == ',' as u8) {
                Some(n) => n,
                None => args.len(),
            };
            let flag = String::from_utf8_lossy(&args[idx..next]).to_lowercase();
            match flag.as_str() {
                "readonly" => self.read_only = true,
                "nomoddb" => self.no_mod_db = true,
                "nocertdb" => self.no_cert_db = true,
                "nokeydb" => self.no_key_db = true,
                "forceopen" => self.force_open = true,
                "passwordrequired" => self.password_required = true,
                "optimizespace" => self.optimize_space = true,
                _ => return Err(CKR_ARGUMENTS_BAD)?,
            }
            idx = next + 1;
        }
        Ok(())
    }

    /// Parses a single key-value parameter from the configuration string.
    ///
    /// Handles different value delimiters ('"', '\'', '(', '{', '[', '<', or
    /// space) and potential backslash escapes within quoted/bracketed values.
    /// Updates the corresponding field in `self`. Returns the number of bytes
    /// consumed from the input slice.
    fn parse_parameter(&mut self, args: &[u8]) -> Result<usize> {
        let name: String;
        let value: String;

        /* find param name */
        let mut idx = match args.iter().position(|&x| x == '=' as u8) {
            Some(x) => x,
            None => Err(CKR_ARGUMENTS_BAD)?,
        };

        if args.len() <= idx + 2 {
            return Err(CKR_ARGUMENTS_BAD)?;
        }

        name = String::from_utf8_lossy(&args[0..idx]).to_lowercase();

        let find = match char::from(args[idx + 1]) {
            '\'' => b'\'',
            '\"' => b'\"',
            '(' => b')',
            '{' => b'}',
            '[' => b']',
            '<' => b'>',
            _ => END_VALUE,
        };
        let valx = if find != END_VALUE { idx + 2 } else { idx + 1 };
        idx = valx;

        while idx < args.len() {
            if let Some(pos) = args[idx..].iter().position(|&x| x == find) {
                idx += pos;

                /* backtrack check for escapes */
                let mut esc = 0;
                while esc < pos {
                    if args[pos - 1 - esc] == '\\' as u8 {
                        esc += 1;
                    } else {
                        break;
                    }
                }
                if esc % 2 == 1 {
                    idx += 1;
                    /* escaped */
                    continue;
                }
                break;
            } else {
                idx = args.len();
            }
        }
        if idx >= args.len() {
            /* This may be the last parameter, in which case it is ok
             * if not trailing space is present otherwise error out */
            if idx == args.len() && find != END_VALUE as u8 {
                return Err(CKR_ARGUMENTS_BAD)?;
            }
        }

        value = String::from_utf8_lossy(&args[valx..idx]).to_string();

        if idx < args.len() {
            /* accounting for the space separator */
            idx += 1;
            if find != END_VALUE {
                /* accounting for the closing brace/quote/symbol */
                idx += 1;
            }
        }

        match name.as_str() {
            "configdir" => self.configdir = Some(value),
            "updatedir" => self.updatedir = Some(value),
            "updateid" => self.updateid = Some(value),
            "secmod" => self.secmod = value,
            "manufacturerid" => self.manufacturer = Some(value),
            "librarydescription" => self.library_description = Some(value),
            "certprefix" => self.cert_prefix = value,
            "keyprefix" => self.key_prefix = value,
            "cryptotokendescription" => {
                self.token_crypto_description = Some(value)
            }
            "dbtokendescription" => self.token_db_description = Some(value),
            "fipstokendescription" => self.token_fips_description = Some(value),
            "cryptoslotdescription" => {
                self.slot_crypto_description = Some(value)
            }
            "dbslotdescription" => self.slot_db_description = Some(value),
            "fipsslotdescription" => self.slot_fips_description = Some(value),
            "updatetokendescription" => self.update_description = Some(value),
            "minpwlen" => self.min_pin_len = value.parse::<usize>()?,
            "flags" => self.parse_flags(value.as_bytes())?,
            _ => return Err(CKR_ARGUMENTS_BAD)?,
        }

        Ok(idx)
    }

    /// Parses a complete NSS configuration string (e.g., from `C_Initialize` args)
    /// into an `NSSConfig` structure.
    pub fn from_args(args: &str) -> Result<NSSConfig> {
        let mut config: NSSConfig = Default::default();

        let bargs = args.as_bytes();
        let mut idx = 0usize;

        while idx < bargs.len() {
            idx += config.parse_parameter(&bargs[idx..])?;
        }
        Ok(config)
    }

    /// Returns the appropriate token label as bytes based on the configuration
    /// overrides (`token_fips_description` or `token_db_description`) and
    /// whether the FIPS feature is enabled. Falls back to default labels.
    pub fn get_token_label_as_bytes(&self) -> &[u8] {
        #[cfg(feature = "fips")]
        let label = &self.token_fips_description;
        #[cfg(not(feature = "fips"))]
        let label = &self.token_db_description;
        match label {
            Some(ref s) => s.as_bytes(),
            None => defaults::TOKEN_LABEL.as_bytes(),
        }
    }
}
