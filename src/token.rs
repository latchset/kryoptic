// Copyright 2023 Simo Sorce
// See LICENSE.txt file for terms

use std::vec::Vec;

use serde::{Serialize, Deserialize};
use serde_json;

use super::interface;
use super::object;
use super::error;

static TOKEN_LABEL: [interface::CK_UTF8CHAR; 32usize] = *b"Kryoptic FIPS Token             ";
static MANUFACTURER_ID: [interface::CK_UTF8CHAR; 32usize] = *b"Kryoptic                        ";
static TOKEN_MODEL: [interface::CK_UTF8CHAR; 16usize] = *b"FIPS-140-3 v1   ";
static TOKEN_SERIAL: [interface::CK_UTF8CHAR; 16usize] = *b"0000000000000000";

use object::KeyObject;
use error::{KResult, KError};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Token {
    #[serde(skip_serializing, skip_deserializing)]
    info: interface::CK_TOKEN_INFO,
    key_objects: Vec<Box<KeyObject>>,
}

impl Token {
    pub fn load(filename: &str) -> KResult<Token> {

        let mut t = Token {
            info: interface::CK_TOKEN_INFO {
                label: TOKEN_LABEL,
                manufacturerID: MANUFACTURER_ID,
                model: TOKEN_MODEL,
                serialNumber: TOKEN_SERIAL,
                flags: Token::token_flags(),
                ulMaxSessionCount: interface::CK_EFFECTIVELY_INFINITE,
                ulSessionCount: 0,
                ulMaxRwSessionCount: interface::CK_EFFECTIVELY_INFINITE,
                ulRwSessionCount: 0,
                ulMaxPinLen: interface::CK_EFFECTIVELY_INFINITE,
                ulMinPinLen: interface::CK_EFFECTIVELY_INFINITE,
                ulTotalPublicMemory: 0,
                ulFreePublicMemory: 0,
                ulTotalPrivateMemory: 0,
                ulFreePrivateMemory: 0,
                hardwareVersion: interface::CK_VERSION {
                    major: 0,
                    minor: 0,
                },
                firmwareVersion: interface::CK_VERSION {
                    major: 0,
                    minor: 0,
                },
                utcTime: *b"0000000000000000",
            },
            key_objects: Vec::new(),
        };

        let file = match std::fs::File::open(filename) {
            Ok(f) => f,
            Err(e) => {
                return Err(KError::FileError(e));
            }
        };
        match serde_json::from_reader::<std::fs::File, Token>(file) {
            Ok(j) => t.key_objects = j.key_objects,
            Err(e) => {
                return Err(KError::JsonError(e));
            }
        }
        Ok(t)
    }

    pub fn save(&self, filename: &str) -> KResult<()> {
        let j = match serde_json::to_string(&self) {
            Ok(j) => {
                j
            },
            Err(e) => {
                return Err(KError::JsonError(e));
            }
        };
        match std::fs::write(filename, j) {
            Ok(_) => Ok(()),
            Err(e) => Err(KError::FileError(e)),
        }
    }

    fn token_flags() -> interface::CK_FLAGS {
        // FIXME: most of these flags need to be set dynamically
        interface::CKF_RNG | interface::CKF_LOGIN_REQUIRED | interface::CKF_TOKEN_INITIALIZED
    }

    pub fn get_token_info(&self) -> &interface:: CK_TOKEN_INFO {
        &self.info
    }
}
