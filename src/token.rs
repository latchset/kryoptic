// Copyright 2023 Simo Sorce
// See LICENSE.txt file for terms

use std::vec::Vec;

use super::interface;
use super::session;
use super::object;

static TOKEN_LABEL: [interface::CK_UTF8CHAR; 32usize] = *b"Kryoptic FIPS Token             ";
static MANUFACTURER_ID: [interface::CK_UTF8CHAR; 32usize] = *b"Kryoptic                        ";
static TOKEN_MODEL: [interface::CK_UTF8CHAR; 16usize] = *b"FIPS-140-3 v1   ";
static TOKEN_SERIAL: [interface::CK_UTF8CHAR; 16usize] = *b"0000000000000000";

use interface::{CK_RV, CKR_OK};
use object::Object;
use session::Session;

#[derive(Debug)]
pub struct Token {
    token_info: interface::CK_TOKEN_INFO,
    token_objects: Vec<Box<dyn Object>>,
    next_handle: interface::CK_SESSION_HANDLE,
    token_sessions: Vec<Session>,
}

impl Token {
    pub fn new() -> Token {
        Token {
            token_info: interface::CK_TOKEN_INFO {
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
            token_objects: Vec::new(),
            next_handle: 1,
            token_sessions: Vec::new(),
        }
    }

    fn token_flags() -> interface::CK_FLAGS {
        // FIXME: most of these flags need to be set dynamically
        interface::CKF_RNG | interface::CKF_LOGIN_REQUIRED | interface::CKF_TOKEN_INITIALIZED
    }

    pub fn get_token_info(&self) -> &interface:: CK_TOKEN_INFO {
        &self.token_info
    }

    pub fn get_new_session(&mut self, flags: interface::CK_FLAGS) -> (Option<Session>, CK_RV) {
        let handle = self.next_handle;
        self.next_handle += 1;
        let (s, res) = Session::new(handle, flags);
        if res != CKR_OK {
            return (None, res)
        }
        self.token_sessions.push(s.unwrap());

        (Some(*self.token_sessions.last().unwrap()), CKR_OK)
    }
}
