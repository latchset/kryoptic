// Copyright 2024 Simo Sorce
// See LICENSE.txt file for terms

use std::env;
use std::fs;
use std::path::Path;

use crate::error::{Error, Result};
use crate::interface;
use crate::storage;
#[cfg(feature = "nssdb")]
use crate::storage::StorageDBInfo;

use serde::de;
use serde::{Deserialize, Serialize};
use toml;

#[cfg(not(test))]
const DEFAULT_CONF_DIR: &str = {
    match option_env!("CONFDIR") {
        Some(p) => p,
        None => "/usr/local/etc",
    }
};
#[cfg(test)]
const DEFAULT_CONF_DIR: &str = "test";

pub const DEFAULT_CONF_NAME: &str = "token.conf";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Slot {
    pub slot: u32,
    pub description: Option<String>,
    pub manufacturer: Option<String>,
    pub dbtype: Option<String>,
    pub dbpath: Option<String>,
}

impl Slot {
    pub fn new() -> Slot {
        Slot {
            slot: u32::MAX,
            description: None,
            manufacturer: None,
            dbtype: None,
            dbpath: None,
        }
    }

    #[cfg(test)]
    pub fn with_db(dbtype: &str, dbpath: Option<String>) -> Slot {
        Slot {
            slot: u32::MAX,
            description: None,
            manufacturer: None,
            dbtype: Some(dbtype.to_string()),
            dbpath: dbpath,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Config {
    pub slots: Vec<Slot>,
}

fn config_error<E: de::Error + 'static>(error: E) -> Error {
    Error::ck_rv_from_error(interface::CKR_TOKEN_NOT_RECOGNIZED, error)
}

impl Config {
    pub fn new() -> Config {
        Config { slots: Vec::new() }
    }

    #[cfg(test)]
    pub fn add_slot(&mut self, slot: Slot) -> Result<()> {
        for s in &self.slots {
            if slot.slot == u32::MAX || slot.slot == s.slot {
                return Err(interface::KRR_SLOT_CONFIG)?;
            }
        }
        self.slots.push(slot);
        Ok(())
    }

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
            Err(interface::CKR_ARGUMENTS_BAD)?
        }
    }

    fn from_file(filename: &str) -> Result<Config> {
        let config_str = fs::read_to_string(filename)?;
        let conf: Config = toml::from_str(&config_str).map_err(config_error)?;
        Ok(conf)
    }

    fn from_legacy_conf_string(name: &str) -> Result<Config> {
        let mut conf = Config { slots: Vec::new() };
        /* backwards compatibility where we used to only specify
         * a file, this does not support all older options, just
         * the more common one of specifying a .sql file with no
         * slot specification. */
        if name.ends_with(".sql") {
            match storage::suffix_to_type(name) {
                Ok(typ_) => {
                    let mut slot = Slot::new();
                    slot.dbtype = Some(typ_.to_string());
                    slot.dbpath = Some(name.to_string());
                    /* if this fails there will be no slots defined */
                    let _ = conf.slots.push(slot);
                }
                Err(_) => (),
            }
        }
        Ok(conf)
    }

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

    pub fn default_config() -> Result<Config> {
        let filename = Self::find_conf()?;

        match Self::from_file(&filename) {
            Ok(conf) => return Ok(conf),
            Err(e) => {
                /* attempt fallback, return original error on fail */
                match Self::from_legacy_conf_string(&filename) {
                    Ok(mut conf) => {
                        conf.fix_slot_numbers();
                        return Ok(conf);
                    }
                    Err(_) => return Err(e),
                }
            }
        }
    }

    #[cfg(feature = "nssdb")]
    fn from_nss_init_args(args: &str) -> Result<Config> {
        let mut conf = Config {
            ec_point_encoding: EcPointEncoding::default(),
            slots: Vec::new(),
        };
        let mut slot = Slot::new();

        slot.dbtype = Some(storage::nssdb::DBINFO.dbtype().to_string());
        slot.dbpath = Some(args.to_string());
        conf.slots.push(slot);
        Ok(conf)
    }

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

    pub fn from_init_args(&mut self, args: &str) -> Result<()> {
        let conf = self.conf_from_args(args)?;

        /* check and add slots */
        for mut slot in conf.slots {
            let mut found = false;
            /* check if it has already been loaded */
            for s in &self.slots {
                if slot.slot == u32::MAX {
                    if s.dbtype.as_deref() == slot.dbtype.as_deref()
                        && s.dbpath.as_deref() == slot.dbpath.as_deref()
                    {
                        /* already loaded so we just match the slot number */
                        found = true;
                        slot.slot = s.slot;
                    }
                } else {
                    if slot.slot != s.slot {
                        if s.dbtype.as_deref() == slot.dbtype.as_deref()
                            && s.dbpath.as_deref() == slot.dbpath.as_deref()
                        {
                            /* already loaded in a different slot, fail! */
                            return Err(interface::CKR_ARGUMENTS_BAD)?;
                        }
                    } else {
                        if s.dbtype.as_deref() != slot.dbtype.as_deref() {
                            return Err(interface::CKR_ARGUMENTS_BAD)?;
                        }
                        if s.dbpath.as_deref() != slot.dbpath.as_deref() {
                            return Err(interface::CKR_ARGUMENTS_BAD)?;
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
