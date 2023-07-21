// Copyright 2023 Simo Sorce
// See LICENSE.txt file for terms

use std::sync::{RwLock};

use super::interface;
use super::token::Token;
use super::session::Session;

static SLOT_DESCRIPTION: [interface::CK_UTF8CHAR; 64usize] = *b"Kryoptic SLot                                                   ";
static MANUFACTURER_ID: [interface::CK_UTF8CHAR; 32usize] = *b"Kryoptic                        ";

#[derive(Debug)]
pub struct Slot {
    slot_info: interface::CK_SLOT_INFO,
    token: RwLock<Token>,
}

impl Slot {
    pub fn new() -> Slot {
        Slot {
            slot_info: interface::CK_SLOT_INFO {
                slotDescription: SLOT_DESCRIPTION,
                manufacturerID: MANUFACTURER_ID,
                flags: interface::CKF_TOKEN_PRESENT,
                hardwareVersion: interface::CK_VERSION {
                    major: 0,
                    minor: 0,
                },
                firmwareVersion: interface::CK_VERSION {
                    major: 0,
                    minor: 0,
                },
            },
            token: RwLock::new(Token::new()),
        }
    }

    pub fn get_token_info(&self) -> interface:: CK_TOKEN_INFO {
        let tok = self.token.read().unwrap();
        *tok.get_token_info()
    }

    pub fn get_slot_info(&self) -> &interface:: CK_SLOT_INFO {
        &self.slot_info
    }

    pub fn open_session(&mut self, flags: interface::CK_FLAGS) -> (Option<Session>, interface::CK_RV) {
        let mut tok = self.token.write().unwrap();
        tok.get_new_session(flags)
    }
}
