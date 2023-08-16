// Copyright 2023 Simo Sorce
// See LICENSE.txt file for terms

use std::sync::{RwLock,RwLockReadGuard, RwLockWriteGuard};

use super::error;
use super::interface;
use super::token::Token;

use interface::*;
use error::{KResult, KError};
use super::err_rv;

static SLOT_DESCRIPTION: [CK_UTF8CHAR; 64usize] = *b"Kryoptic SLot                                                   ";
static MANUFACTURER_ID: [CK_UTF8CHAR; 32usize] = *b"Kryoptic                        ";

#[derive(Debug)]
pub struct Slot {
    slot_info: CK_SLOT_INFO,
    token: RwLock<Token>,
}

impl Slot {
    pub fn new(filename: &str) -> KResult<Slot> {
        let token = Token::load(filename)?;
        Ok(Slot {
            slot_info: CK_SLOT_INFO {
                slotDescription: SLOT_DESCRIPTION,
                manufacturerID: MANUFACTURER_ID,
                flags: CKF_TOKEN_PRESENT,
                hardwareVersion: CK_VERSION {
                    major: 0,
                    minor: 0,
                },
                firmwareVersion: CK_VERSION {
                    major: 0,
                    minor: 0,
                },
            },
            token: RwLock::new(token),
        })
    }

    pub fn get_token_info(&self) -> CK_TOKEN_INFO {
        let tok = self.token.read().unwrap();
        *tok.get_token_info()
    }

    pub fn get_slot_info(&self) -> &CK_SLOT_INFO {
        &self.slot_info
    }

    pub fn get_token(&self) -> KResult<RwLockReadGuard<'_, Token>> {
        match self.token.read() {
            Ok(token) => Ok(token),
            Err(_) => err_rv!(CKR_GENERAL_ERROR),
        }
    }

    pub fn get_token_mut(&self) -> KResult<RwLockWriteGuard<'_, Token>> {
        match self.token.write() {
            Ok(token) => Ok(token),
            Err(_) => err_rv!(CKR_GENERAL_ERROR),
        }
    }
}
