// Copyright 2023 Simo Sorce
// See LICENSE.txt file for terms

use std::vec::Vec;

use serde::{Serialize, Deserialize};
use serde_json;

use super::interface;
use super::session;
use super::object;

static TOKEN_LABEL: [interface::CK_UTF8CHAR; 32usize] = *b"Kryoptic FIPS Token             ";
static MANUFACTURER_ID: [interface::CK_UTF8CHAR; 32usize] = *b"Kryoptic                        ";
static TOKEN_MODEL: [interface::CK_UTF8CHAR; 16usize] = *b"FIPS-140-3 v1   ";
static TOKEN_SERIAL: [interface::CK_UTF8CHAR; 16usize] = *b"0000000000000000";

use interface::{CK_RV, CKR_OK};
use object::KeyObject;
use session::Session;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Token {
    #[serde(skip_serializing, skip_deserializing)]
    info: interface::CK_TOKEN_INFO,
    objects: Vec<Box<KeyObject>>,
    #[serde(skip_serializing, skip_deserializing)]
    next_handle: interface::CK_SESSION_HANDLE,
    #[serde(skip_serializing, skip_deserializing)]
    sessions: Vec<Session>,
}

impl Token {
    pub fn load(filename: &str) -> Result<Token, CK_RV> {

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
            next_handle: 1,
            sessions: Vec::new(),
        };

        let file = match std::fs::File::open(filename) {
            Ok(f) => f,
            Err(e) => {
                println!("Failed to open {filename}: {e:?}");
                return Err(interface::CKR_GENERAL_ERROR);
            }
        };
        match serde_json::from_reader::<std::fs::File, Token>(file) {
            Ok(j) => t.objects = j.objects,
            Err(e) => {
                println!("{e:?}");
                return Err(interface::CKR_GENERAL_ERROR);
            }
        }
        Ok(t)
    }

    fn token_flags() -> interface::CK_FLAGS {
        // FIXME: most of these flags need to be set dynamically
        interface::CKF_RNG | interface::CKF_LOGIN_REQUIRED | interface::CKF_TOKEN_INITIALIZED
    }

    pub fn test_token() -> Token {
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
            next_handle: 1,
            sessions: Vec::new(),
        };

        t.objects.push(Box::new(KeyObject::test_object()));

        t
    }

    pub fn get_token_info(&self) -> &interface:: CK_TOKEN_INFO {
        &self.info
    }

    pub fn get_new_session(&mut self, flags: interface::CK_FLAGS) -> (Option<Session>, CK_RV) {
        let handle = self.next_handle;
        self.next_handle += 1;
        let (s, res) = Session::new(handle, flags);
        if res != CKR_OK {
            return (None, res)
        }
        self.sessions.push(s.unwrap());

        (Some(*self.sessions.last().unwrap()), CKR_OK)
    }
}
