// Copyright 2024 Simo Sorce
// See LICENSE.txt file for terms

//! This module provides parsing and management functions to read the
//! configuration file.

use std::env;
use std::fs;
use std::path::Path;

use crate::error::{Error, Result};
use crate::pkcs11::*;
use crate::storage;
use crate::storage::StorageDBInfo;

use serde::de;
use serde::{Deserialize, Serialize};
use toml;

macro_rules! trace_config {
    ($err:expr, $val:expr) => {
        #[cfg(feature = "log")]
        {
            use log::error;
            error!("{}:{}: {} {}", file!(), line!(), $err, $val,);
        }
    };
}

#[cfg(test)]
use crate::pkcs11::vendor::KRR_SLOT_CONFIG;

/// The directory where to search the default configuration,
/// can be changed with the CONFDIR environment variable at
/// build time
#[cfg(not(test))]
const DEFAULT_CONF_DIR: &str = {
    match option_env!("CONFDIR") {
        Some(p) => p,
        None => "/usr/local/etc",
    }
};
#[cfg(test)]
const DEFAULT_CONF_DIR: &str = "test";

/// The default token name (token.conf)
pub const DEFAULT_CONF_NAME: &str = "token.conf";

/// Configuration for a slot
///
/// The basic facility of a PKCS#11 is the slot. The slot represents an
/// idealized hardware slot where a token can be inserted at any time to
/// execute operations.
///
/// In Kryoptic we use slots to allow to provide multiple independent
/// tokens with their own storage separate from any other slot. Slots
/// can't share the same storage.
///
/// Each slot is identified by a slot number (a u32 quantity) and can
/// optionally have a customized description and manufacturer string.
/// If no description or manufacturer strings are provided then default
/// ones are set and returned to PKCS#11 applications.
///
/// Finally the storage is defined by a pair of arguments: dbtype and dbargs
///
/// This structure is generally sourced from a toml configuration file that
/// defines all the slots to be exposed to the application.
///
/// Example:
///
/// \[\[slots\]\]
///  slot = 1
///  dbtype = "sqlite"
///  dbargs = "/var/lib/kryoptic/token.sql"

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Slot {
    /// Slot number
    pub slot: u32,
    /// Slot's description
    pub description: Option<String>,
    /// Slot's manufacturer
    pub manufacturer: Option<String>,
    /// The token type (storage implementation)
    pub dbtype: Option<String>,
    /// Storage specific configuration options
    pub dbargs: Option<String>,
    /// List of allowed mechanisms, if set changes the list
    /// of mechanism this token claims are implemented.
    /// NOTE: this can be an allow list like ["CKM_SHA256", ...] where
    /// only the explicitly mentioned mechanism are available or it can
    /// be a deny list where the first element must be the string "DENY",
    /// followed by the mechanism to remove as in ["DENY", "CKM_SHA256"]
    /// Using "DENY" in any position but the first is not supported and
    /// will cause an error.
    pub mechanisms: Option<Vec<String>>,
    /// The FIPS Behavior for the token
    #[cfg(feature = "fips")]
    #[serde(default)]
    pub fips_behavior: FipsBehavior,
}

impl Slot {
    /// Creates a new empty slot with the slot number set to the special
    /// indicator of u32::MAX, which will fault if encountered by the
    /// configuration processing functions
    pub fn new() -> Slot {
        Slot {
            slot: u32::MAX,
            description: None,
            manufacturer: None,
            dbtype: None,
            dbargs: None,
            mechanisms: None,
            #[cfg(feature = "fips")]
            fips_behavior: FipsBehavior::default(),
        }
    }

    /// Creates a new slot with a specific dbtype and db arguments set
    /// The slot number is set to u32::MAX which indicates this slot still
    /// needs to be assigned a specific number (tests will do that)
    #[cfg(test)]
    pub fn with_db(dbtype: &str, dbargs: Option<String>) -> Slot {
        Slot {
            slot: u32::MAX,
            description: None,
            manufacturer: None,
            dbtype: Some(dbtype.to_string()),
            dbargs: dbargs,
            mechanisms: None,
            #[cfg(feature = "fips")]
            fips_behavior: FipsBehavior {
                keys_always_sensitive: if dbtype == "nssdb" {
                    true
                } else {
                    false
                },
            },
        }
    }

    /// Parses the configurations option listing mechanisms and produces
    /// either an allow list or a deny list or none at all.
    /// Returns an error if the list cannot be parsed successfully.
    /// The returned boolean indicates if the vector is a deny list.
    pub fn mech_list(&self) -> Result<(Option<Vec<CK_ULONG>>, bool)> {
        let list = match &self.mechanisms {
            Some(l) => l,
            None => return Ok((None, false)),
        };

        let mut vec = Vec::<CK_ULONG>::with_capacity(list.len());
        let mut deny = false;
        let mut idx = 0;
        while idx < list.len() {
            if idx == 0 {
                if list[0] == "DENY" {
                    trace_config!("mechanism list type is", "deny");
                    deny = true;
                    idx += 1;
                    continue;
                } else {
                    trace_config!("mechanism list type is", "allow");
                }
            }

            let mech = match name_to_mech(&list[idx]) {
                Ok(m) => m,
                Err(e) => {
                    trace_config!("invalid mechanism name:", &list[idx]);
                    return Err(e);
                }
            };
            vec.push(mech);
            idx += 1;
        }

        Ok((Some(vec), deny))
    }
}

/// For compatibility with applications that expect DER encoded EC Points
///
/// Allows to set a global default encoding for CKA_EC_POINT attributes.
///
/// Example:
///
/// \[ec_point_encoding\]
/// encoding = "Bytes"

#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "encoding")]
pub enum EcPointEncoding {
    Bytes,
    Der,
}

impl Default for EcPointEncoding {
    fn default() -> Self {
        EcPointEncoding::Bytes
    }
}

/// Add tweaks for behavior in FIPS mode.
#[cfg(feature = "fips")]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FipsBehavior {
    /// Changes behavior of token in slot to always enforce keys to be private
    pub keys_always_sensitive: bool,
}

#[cfg(feature = "fips")]
impl Default for FipsBehavior {
    fn default() -> Self {
        FipsBehavior {
            keys_always_sensitive: false,
        }
    }
}

/// Main configuration structure
///
/// The main config structure is comprised of two elements, a general
/// EC Point Encoding indicator and a list of slots

#[derive(Debug, Serialize, Deserialize)]
pub struct Config {
    /// Type of encoding for EC Public Points
    #[serde(default)]
    pub ec_point_encoding: EcPointEncoding,
    /// List of configured slots
    pub slots: Vec<Slot>,
}

/// Maps some config errors to CKR_TOKEN_NOT_RECOGNIZED
fn config_error<E: de::Error + 'static>(error: E) -> Error {
    Error::ck_rv_from_error(CKR_TOKEN_NOT_RECOGNIZED, error)
}

impl Config {
    /// Creates a new, empty, config structure, with the EC POINT Encoding
    /// set to the default.
    pub fn new() -> Config {
        Config {
            ec_point_encoding: EcPointEncoding::default(),
            slots: Vec::new(),
        }
    }

    /// Allows to add a preconfigured slot structure.
    /// Available only for tests. Ensures the slot number is set and that
    /// there are no duplicates
    #[cfg(test)]
    pub fn add_slot(&mut self, slot: Slot) -> Result<()> {
        for s in &self.slots {
            if slot.slot == u32::MAX || slot.slot == s.slot {
                return Err(KRR_SLOT_CONFIG)?;
            }
        }
        self.slots.push(slot);
        Ok(())
    }

    /// Find the applicable configuration for Kryoptic.
    /// Kryoptic searches for a configuration file in multiple places
    /// falling back from one to the next and stops once configuration file
    /// is found. There is no config file merging/include support currently
    ///
    /// The first place where configuration is looked for is in the file
    /// indicated by the `KRYOPTIC_CONF` environment variable. If this
    /// variable is not set, then the code checks if the standard
    /// `XDG_CONFIG_HOME` environment variable is available.
    /// If this variable exists kryoptic assumes the config file is named:
    ///  `${XDG_CONFIG_HOME}/kryoptic/token.conf`
    ///
    /// Otherwise if the environment variable HOME is set the code assumes
    /// the configuration file is named:
    ///  `${HOME}/.config/kryoptic/token.conf`
    ///
    /// Finally if nothing matches the code tries the relative path:
    ///  `test/kryoptic/token.conf`
    ///
    ///  It is srongly advised to set the `KRYOPTIC_CONF` variable for most
    ///  use cases.
    fn find_conf() -> Result<String> {
        /* First check for our own env var,
         * this has the highest precedence */
        match env::var("KRYOPTIC_CONF") {
            Ok(var) => return Ok(var),
            Err(_) => (),
        }
        /* Freedesktop specification for data dirs first
         * then fallback to use $HOME/.local/share, if that is also not
         * available see if we have access to a system store */
        let datafile = match env::var("XDG_CONFIG_HOME") {
            Ok(xdg) => format!("{}/kryoptic/{}", xdg, DEFAULT_CONF_NAME),
            Err(_) => match env::var("HOME") {
                Ok(home) => {
                    format!("{}/.config/kryoptic/{}", home, DEFAULT_CONF_NAME)
                }
                Err(_) => format!(
                    "{}/kryoptic/{}",
                    DEFAULT_CONF_DIR, DEFAULT_CONF_NAME
                ),
            },
        };
        if Path::new(&datafile).is_file() {
            Ok(datafile)
        } else {
            Err(CKR_ARGUMENTS_BAD)?
        }
    }

    /// Generates a configuration structure from the named file which must
    /// be a properly formatted configuration file in toml format.
    fn from_file(filename: &str) -> Result<Config> {
        let config_str = fs::read_to_string(filename)?;
        let conf: Config = toml::from_str(&config_str).map_err(config_error)?;
        Ok(conf)
    }

    /// Generates a configuration structure from a legacy argument as passed
    /// into the reserved argument of the `C_Initialize()` function.
    ///
    /// A valid argument is the path of a file for the sqlite storage driver
    /// which must end with a .sql suffix
    fn from_legacy_conf_string(name: &str) -> Result<Config> {
        let mut conf = Self::new();

        /* backwards compatibility where we used to only specify
         * a file, this does not support all older options, just
         * the more common one of specifying a .sql file with no
         * slot specification. */
        #[cfg(feature = "sqlitedb")]
        if name.ends_with(".sql") {
            let mut slot = Slot::new();
            slot.dbtype = Some(storage::sqlite::DBINFO.dbtype().to_string());
            slot.dbargs = Some(name.to_string());
            /* if this fails there will be no slots defined */
            let _ = conf.slots.push(slot);
        }
        Ok(conf)
    }

    /// Ensure all slot numbers are consistent, and allocates new slot
    /// numbers for slots that have the special invalid slow number of
    /// u32::MAX
    fn fix_slot_numbers(&mut self) {
        let mut slotnum: u32 = 0;
        /* if there are any slot missing a valid slot number
         * we are going to allocate slots numbers after the highest
         * properly configured one. Note that the config file format
         * requires slot numbers, so this generally happens for legacy
         * or init args configurations only, ie a single slot */
        let mut missing = false;
        for slot in &self.slots {
            if slot.slot != u32::MAX {
                if slotnum <= slot.slot {
                    slotnum = slot.slot + 1;
                }
            } else {
                missing = true;
            }
        }
        if missing {
            for slot in &mut self.slots {
                if slot.slot == u32::MAX {
                    slot.slot = slotnum;
                    slotnum += 1;
                }
            }
        }
    }

    /// Generates the default configuration structure by searching the default
    /// configuration file
    pub fn default_config() -> Result<Config> {
        let filename = Self::find_conf()?;

        match Self::from_file(&filename) {
            Ok(conf) => Ok(conf),
            Err(e) => {
                /* attempt fallback, return original error on fail */
                match Self::from_legacy_conf_string(&filename) {
                    Ok(mut conf) => {
                        conf.fix_slot_numbers();
                        Ok(conf)
                    }
                    Err(_) => return Err(e),
                }
            }
        }
    }

    /// Load environment variables overrides for configurations items.
    ///
    /// The only variable currently defined is `KRYOPTIC_EC_POINT_ENCODING`
    /// Which can be used to override the encoding specified in the
    /// configuration file. This is useful when multiple applications use
    /// the same configuration file but expect different behavior from the
    /// configure default:
    ///
    /// Example:
    /// `export KRYOPTIC_EC_POINT_ENCODING="BYTES"`
    pub fn load_env_vars_overrides(&mut self) {
        match env::var("KRYOPTIC_EC_POINT_ENCODING") {
            Ok(var) => {
                self.ec_point_encoding = match var.as_str() {
                    "DER" => EcPointEncoding::Der,
                    "BYTES" => EcPointEncoding::Bytes,
                    _ =>
                    /* ignore */
                    {
                        self.ec_point_encoding
                    }
                }
            }
            Err(_) => (),
        }
    }

    /// Loads the NSS DB Storage configuration which is generally provided
    /// as a complex formatted string as a reserved argument when calling
    /// the `C_Intialize()` function.
    #[cfg(feature = "nssdb")]
    fn from_nss_init_args(args: &str) -> Result<Config> {
        let mut conf = Self::new();
        let mut slot = Slot::new();

        slot.dbtype = Some(storage::nssdb::DBINFO.dbtype().to_string());
        slot.dbargs = Some(args.to_string());
        #[cfg(feature = "fips")]
        {
            /* NSS generally marks all keys as sensitive and forbids
             * creation or extraction of secret keys in FIPS mode.
             * So for NSS, keys are sensitive by default. */
            slot.fips_behavior = FipsBehavior {
                keys_always_sensitive: true,
            };
        }
        conf.slots.push(slot);
        Ok(conf)
    }

    /// Calls the correct configuration parser based on the detected
    /// database configuration string
    fn conf_from_args(&self, args: &str) -> Result<Config> {
        if args.starts_with("kryoptic_conf=") {
            let comps: Vec<&str> = args.splitn(2, '=').collect();
            return Self::from_file(comps[1]);
        }

        #[cfg(feature = "nssdb")]
        /* heuristics for NSS compatibility */
        if args.contains("configDir=") {
            return Self::from_nss_init_args(args);
        }

        /* Finally try with legacy */
        Self::from_legacy_conf_string(args)
    }

    /// Allows to specify the configuration file as a string provided as the
    /// reserved argument of the `C_Initialize()` function.
    pub fn from_init_args(&mut self, args: &str) -> Result<()> {
        let conf = self.conf_from_args(args)?;

        /* check and add slots */
        for mut slot in conf.slots {
            let mut found = false;
            /* check if it has already been loaded */
            for s in &self.slots {
                if slot.slot == u32::MAX {
                    if s.dbtype.as_deref() == slot.dbtype.as_deref()
                        && s.dbargs.as_deref() == slot.dbargs.as_deref()
                    {
                        /* already loaded so we just match the slot number */
                        found = true;
                        slot.slot = s.slot;
                    }
                } else {
                    if slot.slot != s.slot {
                        if s.dbtype.as_deref() == slot.dbtype.as_deref()
                            && s.dbargs.as_deref() == slot.dbargs.as_deref()
                        {
                            /* already loaded in a different slot, fail! */
                            return Err(CKR_ARGUMENTS_BAD)?;
                        }
                    } else {
                        if s.dbtype.as_deref() != slot.dbtype.as_deref() {
                            return Err(CKR_ARGUMENTS_BAD)?;
                        }
                        if s.dbargs.as_deref() != slot.dbargs.as_deref() {
                            return Err(CKR_ARGUMENTS_BAD)?;
                        }
                        /* already present skip adding */
                        found = true;
                    }
                }
            }
            if !found {
                self.slots.push(slot);
            }
        }
        self.fix_slot_numbers();
        Ok(())
    }
}
