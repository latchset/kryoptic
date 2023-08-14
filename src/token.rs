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

use object::{Object, JsonObject};
use error::{KResult, KError, CkRvError};

#[derive(Debug, Clone)]
pub struct Token {
    info: interface::CK_TOKEN_INFO,
    objects: Vec<Object>, /* FIXME: convert to hashMap ? */
    login: bool,
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

    pub fn search(&self, template: &[interface::CK_ATTRIBUTE]) -> KResult<std::vec::Vec<interface::CK_OBJECT_HANDLE>> {
        let mut handles = Vec::<interface::CK_OBJECT_HANDLE>::new();
        for o in self.objects.iter() {
            if self.login == false {
                match o.is_private() {
                    Ok(p) => {
                        if p == true {
                            continue;
                        }
                    },
                    Err(e) => return Err(e),
                }
            }
            if o.match_template(template) {
                handles.push(o.get_handle());
            }
        }
        Ok(handles)
    }

    pub fn get_object_attrs(&self, handle: interface::CK_OBJECT_HANDLE, template: &mut [interface::CK_ATTRIBUTE]) -> KResult<()> {
        for o in self.objects.iter() {
            if !self.login && o.is_private()? {
                continue;
            }
            if o.get_handle() == handle {
                return o.fill_template(template)
            }
        }
        Err(KError::RvError(CkRvError{ rv: interface::CKR_OBJECT_HANDLE_INVALID}))
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct JsonToken {
    objects: Vec<JsonObject>,
}
