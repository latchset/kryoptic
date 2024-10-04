// Copyright 2024 Simo Sorce
// See LICENSE.txt file for terms

use std::env;
use std::fs;
use std::path::Path;

use crate::error::{Error, Result};
use crate::interface;
use crate::storage;

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
            slot: 0,
            description: None,
            manufacturer: None,
            dbtype: None,
            dbpath: None,
        }
    }

    #[cfg(test)]
    pub fn with_db(dbtype: &str, dbpath: Option<String>) -> Slot {
        Slot {
            slot: 0,
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

    pub fn add_slot(&mut self, slot: Slot) -> Result<()> {
        for s in &self.slots {
            if slot.slot == s.slot {
                return Err(interface::KRR_SLOT_CONFIG)?;
            }
        }
        self.slots.push(slot);
        Ok(())
    }

    pub fn find_conf() -> Result<String> {
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

    pub fn from_file(filename: &str) -> Result<Config> {
        let config_str = fs::read_to_string(filename)?;
        let conf: Config = toml::from_str(&config_str).map_err(config_error)?;
        Ok(conf)
    }

    pub fn from_legacy_conf_string(name: &str) -> Result<Config> {
        let mut conf = Config { slots: Vec::new() };
        /* backwards compatibility where we used to only specify
         * a file, this does not support all older options, just
         * the more common one of specifying a .sql file with no
         * slot specification. */
        if name.ends_with(".sql") {
            match storage::name_to_type(name) {
                Ok(typ_) => {
                    let mut slot = Slot::new();
                    slot.dbtype = Some(typ_.to_string());
                    slot.dbpath = Some(name.to_string());
                    /* if this fails there will be no slots defined */
                    let _ = conf.add_slot(slot);
                }
                Err(_) => (),
            }
        }
        return Ok(conf);
    }

    pub fn from_init_args(&mut self, args: &str) -> Result<()> {
        let assign_slot: bool;
        let mut conf = if args.starts_with("kryoptic_conf=") {
            assign_slot = false;
            let comps: Vec<&str> = args.splitn(2, '=').collect();
            Self::from_file(comps[1])?
        } else {
            assign_slot = true;
            Self::from_legacy_conf_string(args)?
        };

        if assign_slot {
            /* check if it has already been loaded */
            for s in &self.slots {
                if s.dbtype.as_deref() == conf.slots[0].dbtype.as_deref()
                    && s.dbpath.as_deref() == conf.slots[0].dbpath.as_deref()
                {
                    conf.slots[0].slot = s.slot;
                }
            }
        }

        /* check and add slots */
        for mut slot in conf.slots {
            let mut slotnum: u32 = 0;
            let mut found = false;
            for s in &self.slots {
                if assign_slot {
                    if slotnum <= s.slot {
                        slotnum += s.slot + 1;
                    }
                } else if s.slot == slot.slot {
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
            if assign_slot {
                slot.slot = slotnum;
            }
            if !found {
                self.add_slot(slot)?;
            }
        }
        Ok(())
    }
}
