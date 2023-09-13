// Copyright 2023 Simo Sorce
// See LICENSE.txt file for terms

use std::sync::{RwLock, RwLockReadGuard, RwLockWriteGuard};

use super::error;
use super::interface;
use super::token::Token;

use super::err_rv;
use error::{KError, KResult};
use interface::*;

static SLOT_DESCRIPTION: [CK_UTF8CHAR; 64usize] =
    *b"Kryoptic SLot                                                   ";
static MANUFACTURER_ID: [CK_UTF8CHAR; 32usize] =
    *b"Kryoptic                        ";

#[derive(Debug)]
pub struct Slot {
    slot_info: CK_SLOT_INFO,
    token: RwLock<Token>,
}

impl Slot {
    pub fn new(slot_id: CK_SLOT_ID, filename: String) -> KResult<Slot> {
        let mut token = Token::new(slot_id, filename);
        token.load()?;
        Ok(Slot {
            slot_info: CK_SLOT_INFO {
                slotDescription: SLOT_DESCRIPTION,
                manufacturerID: MANUFACTURER_ID,
                flags: CKF_TOKEN_PRESENT,
                hardwareVersion: CK_VERSION { major: 0, minor: 0 },
                firmwareVersion: CK_VERSION { major: 0, minor: 0 },
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
            Ok(token) => {
                if token.is_initialized() {
                    Ok(token)
                } else {
                    /* FIXME: once we have CKR_TOKEN_NOT_INITIALIZED as an
                     * available error, we should rreturn that instead */
                    err_rv!(KRYERR_TOKEN_NOT_INITIALIZED)
                }
            }
            Err(_) => err_rv!(CKR_GENERAL_ERROR),
        }
    }

    pub fn get_token_mut(
        &self,
        nochecks: bool,
    ) -> KResult<RwLockWriteGuard<'_, Token>> {
        match self.token.write() {
            Ok(token) => {
                if nochecks {
                    Ok(token)
                } else if token.is_initialized() {
                    Ok(token)
                } else {
                    /* FIXME: once we have CKR_TOKEN_NOT_INITIALIZED as an
                     * available error, we should rreturn that instead */
                    err_rv!(KRYERR_TOKEN_NOT_INITIALIZED)
                }
            }
            Err(_) => err_rv!(CKR_GENERAL_ERROR),
        }
    }
}
