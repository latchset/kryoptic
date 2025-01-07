// Copyright 2024 Simo Sorce
// See LICENSE.txt file for terms

use std::sync::MutexGuard;

use crate::error::{Error, Result};
use crate::interface::*;
use rusqlite::{Error as rlError, ErrorCode};

use rusqlite;

impl From<rlError> for Error {
    fn from(error: rlError) -> Error {
        match error {
            rlError::SqliteFailure(_, _) => match error.sqlite_error_code() {
                Some(e) => match e {
                    ErrorCode::ConstraintViolation
                    | ErrorCode::TypeMismatch
                    | ErrorCode::ApiMisuse
                    | ErrorCode::ParameterOutOfRange => {
                        Error::ck_rv_from_error(CKR_GENERAL_ERROR, error)
                    }
                    ErrorCode::DatabaseBusy
                    | ErrorCode::DatabaseLocked
                    | ErrorCode::FileLockingProtocolFailed => {
                        Error::ck_rv_from_error(
                            CKR_TOKEN_RESOURCE_EXCEEDED,
                            error,
                        )
                    }
                    ErrorCode::OutOfMemory => {
                        Error::ck_rv_from_error(CKR_DEVICE_MEMORY, error)
                    }
                    ErrorCode::CannotOpen
                    | ErrorCode::NotFound
                    | ErrorCode::PermissionDenied => {
                        Error::ck_rv_from_error(CKR_TOKEN_NOT_RECOGNIZED, error)
                    }
                    ErrorCode::ReadOnly => Error::ck_rv_from_error(
                        CKR_TOKEN_WRITE_PROTECTED,
                        error,
                    ),
                    ErrorCode::TooBig => {
                        Error::ck_rv_from_error(CKR_DATA_LEN_RANGE, error)
                    }
                    _ => Error::ck_rv_from_error(CKR_DEVICE_ERROR, error),
                },
                None => Error::ck_rv_from_error(CKR_GENERAL_ERROR, error),
            },
            _ => Error::ck_rv_from_error(CKR_GENERAL_ERROR, error),
        }
    }
}

impl<T> From<std::sync::PoisonError<std::sync::MutexGuard<'_, T>>> for Error {
    fn from(_: std::sync::PoisonError<std::sync::MutexGuard<'_, T>>) -> Error {
        Error::ck_rv(CKR_CANT_LOCK)
    }
}

pub fn check_table(
    conn: &MutexGuard<'_, rusqlite::Connection>,
    schema: &str,
    tablename: &str,
) -> Result<()> {
    let sql = if schema.len() > 0 {
        format!("SELECT count(*) FROM {}.sqlite_master WHERE type='table' AND name = '{}'", schema, tablename)
    } else {
        format!("SELECT count(*) FROM sqlite_master WHERE type='table' AND name = '{}'", tablename)
    };
    let mut stmt = conn.prepare(&sql)?;
    let mut rows = stmt.query(rusqlite::params![])?;
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

pub fn set_secure_delete(
    conn: &MutexGuard<'_, rusqlite::Connection>,
) -> Result<()> {
    Ok(conn.execute_batch("PRAGMA secure_delete = ON")?)
}
