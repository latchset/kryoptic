// Copyright 2023 Simo Sorce
// See LICENSE.txt file for terms

use std::vec::Vec;

use serde::{Serialize, Deserialize};
use serde_json;

use super::interface;
use super::object;
use super::error;

use interface::*;
use object::{Object, JsonObject};
use error::{KResult, KError};
use super::err_rv;

use getrandom;

static TOKEN_LABEL: [CK_UTF8CHAR; 32usize] = *b"Kryoptic FIPS Token             ";
static MANUFACTURER_ID: [CK_UTF8CHAR; 32usize] = *b"Kryoptic                        ";
static TOKEN_MODEL: [CK_UTF8CHAR; 16usize] = *b"FIPS-140-3 v1   ";
static TOKEN_SERIAL: [CK_UTF8CHAR; 16usize] = *b"0000000000000000";

#[derive(Debug, Clone)]
pub struct Token {
    info: CK_TOKEN_INFO,
    objects: Vec<Object>, /* FIXME: convert to hashMap ? */
    login: bool,
}

impl Token {
    pub fn load(filename: &str) -> KResult<Token> {

        let mut t = Token {
            info: CK_TOKEN_INFO {
                label: TOKEN_LABEL,
                manufacturerID: MANUFACTURER_ID,
                model: TOKEN_MODEL,
                serialNumber: TOKEN_SERIAL,
                flags: Token::token_flags(),
                ulMaxSessionCount: CK_EFFECTIVELY_INFINITE,
                ulSessionCount: 0,
                ulMaxRwSessionCount: CK_EFFECTIVELY_INFINITE,
                ulRwSessionCount: 0,
                ulMaxPinLen: CK_EFFECTIVELY_INFINITE,
                ulMinPinLen: CK_EFFECTIVELY_INFINITE,
                ulTotalPublicMemory: 0,
                ulFreePublicMemory: 0,
                ulTotalPrivateMemory: 0,
                ulFreePrivateMemory: 0,
                hardwareVersion: CK_VERSION {
                    major: 0,
                    minor: 0,
                },
                firmwareVersion: CK_VERSION {
                    major: 0,
                    minor: 0,
                },
                utcTime: *b"0000000000000000",
            },
            objects: Vec::new(),
            login: false,
        };

        let file = match std::fs::File::open(filename) {
            Ok(f) => f,
            Err(e) => {
                return Err(KError::FileError(e));
            }
        };
        match serde_json::from_reader::<std::fs::File, JsonToken>(file) {
            Ok(j) => t.objects = object::json_to_objects(&j.objects),
            Err(e) => return Err(KError::JsonError(e)),
        }
        Ok(t)
    }

    pub fn save(&self, filename: &str) -> KResult<()> {
        let token = JsonToken {
            objects: object::objects_to_json(&self.objects)
        };
        let j = match serde_json::to_string(&token) {
            Ok(j) => j,
            Err(e) => return Err(KError::JsonError(e)),
        };
        match std::fs::write(filename, j) {
            Ok(_) => Ok(()),
            Err(e) => Err(KError::FileError(e)),
        }
    }

    fn token_flags() -> CK_FLAGS {
        // FIXME: most of these flags need to be set dynamically
        CKF_RNG | CKF_LOGIN_REQUIRED | CKF_TOKEN_INITIALIZED
    }

    pub fn get_token_info(&self) -> &CK_TOKEN_INFO {
        &self.info
    }

    pub fn search(&self, template: &[CK_ATTRIBUTE]) -> KResult<Vec<CK_OBJECT_HANDLE>> {
        let mut handles = Vec::<CK_OBJECT_HANDLE>::new();
        for o in self.objects.iter() {
            if !self.login && o.is_private()? {
                continue;
            }
            if o.match_template(template) {
                handles.push(o.get_handle());
            }
        }
        Ok(handles)
    }

    pub fn get_object_attrs(&self, handle: CK_OBJECT_HANDLE, template: &mut [CK_ATTRIBUTE]) -> KResult<()> {
        for o in self.objects.iter() {
            if o.get_handle() == handle {
                if !self.login && o.is_private()? {
                    break;
                }
                return o.fill_template(template)
            }
        }
        err_rv!(CKR_OBJECT_HANDLE_INVALID)
    }

    pub fn generate_random(&self, buffer: &mut [u8]) -> KResult<()> {
        /* NOTE: this is just a placeholder to get somethjing going */
        if buffer.len() > 256 {
            return err_rv!(CKR_ARGUMENTS_BAD);
        }
        if getrandom::getrandom(buffer).is_err() {
            return err_rv!(CKR_GENERAL_ERROR)
        }
        Ok(())
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct JsonToken {
    objects: Vec<JsonObject>,
}
