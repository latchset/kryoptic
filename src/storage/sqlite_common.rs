// Copyright 2024 Simo Sorce
// See LICENSE.txt file for terms

use std::sync::MutexGuard;

use crate::error::Result;
use crate::interface::*;

use rusqlite;

const CHECK_DB_TABLE: &str =
    "SELECT count(*) FROM sqlite_master WHERE type='table' AND name = ?";

pub fn check_table(
    conn: MutexGuard<'_, rusqlite::Connection>,
    tablename: &str,
) -> Result<()> {
    let mut stmt = conn.prepare(CHECK_DB_TABLE)?;
    let mut rows = stmt.query(rusqlite::params![tablename])?;
    if let Some(row) = rows.next()? {
        match row.get(0)? {
            1 => (),
            0 => return Err(CKR_CRYPTOKI_NOT_INITIALIZED)?,
            _ => return Err(CKR_DEVICE_ERROR)?,
        }
    } else {
        return Err(CKR_CRYPTOKI_NOT_INITIALIZED)?;
    }
    match rows.next() {
        Ok(None) => Ok(()),
        Ok(_) => Err(CKR_DEVICE_ERROR)?,
        Err(e) => Err(e)?,
    }
}
