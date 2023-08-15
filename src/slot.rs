// Copyright 2023 Simo Sorce
// See LICENSE.txt file for terms

use std::sync::{RwLock};

use super::error;
use super::interface;
use super::token::Token;

use error::KResult;
use interface::*;

static SLOT_DESCRIPTION: [CK_UTF8CHAR; 64usize] = *b"Kryoptic SLot                                                   ";
static MANUFACTURER_ID: [CK_UTF8CHAR; 32usize] = *b"Kryoptic                        ";

#[derive(Debug)]
pub struct Slot {
    slot_info: CK_SLOT_INFO,
    token: RwLock<Token>,
}

impl Slot {
    pub fn new(filename: &str) -> KResult<Slot> {
        let token = match Token::load(filename) {
            Ok(t) => t,
            Err(e) => return Err(e),
        };
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

    pub fn token_save(&self, filename: &str) -> KResult<()> {
        let token = self.token.read().unwrap();
        token.save(filename)
    }

    pub fn get_token_info(&self) -> CK_TOKEN_INFO {
        let tok = self.token.read().unwrap();
        *tok.get_token_info()
    }

    pub fn get_slot_info(&self) -> &CK_SLOT_INFO {
        &self.slot_info
    }

    pub fn search(&self, template: &[CK_ATTRIBUTE]) -> KResult<std::vec::Vec<CK_OBJECT_HANDLE>> {
        let token = self.token.read().unwrap();
        token.search(template)
    }

    pub fn get_object_attrs(&self, handle: CK_OBJECT_HANDLE, template: &mut [CK_ATTRIBUTE]) -> KResult<()> {
        let token = self.token.read().unwrap();
        token.get_object_attrs(handle, template)
    }
}
