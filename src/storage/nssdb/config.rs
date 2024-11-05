// Copyright 2024 Simo Sorce
// See LICENSE.txt file for terms

use crate::error::Result;
use crate::interface::*;
use crate::storage;

/* Mostly documented at:
 * https://nss-crypto.org/reference/security/nss/legacy/pkcs11/module_specs/index.html
 */
#[derive(Debug)]
pub struct NSSConfig {
    pub configdir: Option<String>,
    pub updatedir: Option<String>,
    pub updateid: Option<String>,
    pub secmod: String,
    pub manufacturer: Option<String>,
    pub library_description: Option<String>,
    pub cert_prefix: String,
    pub key_prefix: String,
    pub token_crypto_description: Option<String>,
    pub token_db_description: Option<String>,
    pub token_fips_description: Option<String>,
    pub slot_crypto_description: Option<String>,
    pub slot_db_description: Option<String>,
    pub slot_fips_description: Option<String>,
    pub update_description: Option<String>,
    pub min_pin_len: usize,
    pub read_only: bool,
    pub no_mod_db: bool,
    pub no_cert_db: bool,
    pub no_key_db: bool,
    pub force_open: bool,
    pub password_required: bool,
    pub optimize_space: bool,
    /* tokens: currently unsupported */
}

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

impl NSSConfig {
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
            _ => b' ',
        };
        let valx = if find != b' ' { idx + 2 } else { idx + 1 };
        idx = valx;

        while idx < args.len() {
            if let Some(pos) = args[idx..].iter().position(|&x| x == find) {
                idx = pos;

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
            if idx == args.len() && find != ' ' as u8 {
                return Err(CKR_ARGUMENTS_BAD)?;
            }
        }

        value = String::from_utf8_lossy(&args[valx..idx]).to_string();

        if idx < args.len() {
            idx += 1;
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

    /* parse nss configuration string */
    pub fn from_args(args: &str) -> Result<NSSConfig> {
        let mut config: NSSConfig = Default::default();

        let bargs = args.as_bytes();
        let mut idx = 0usize;

        while idx < bargs.len() {
            idx = config.parse_parameter(&bargs[idx..])?;
        }
        Ok(config)
    }

    pub fn get_token_label_as_bytes(&self) -> &[u8] {
        #[cfg(feature = "fips")]
        let label = &self.token_fips_description;
        #[cfg(not(feature = "fips"))]
        let label = &self.token_db_description;
        match label {
            Some(ref s) => s.as_bytes(),
            None => storage::TOKEN_LABEL.as_bytes(),
        }
    }
}
