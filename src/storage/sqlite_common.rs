// Copyright 2024 Simo Sorce
// See LICENSE.txt file for terms

//! This module provides common utilities and error handling conversions
//! for storage backends implemented using the `rusqlite` crate.

use std::sync::MutexGuard;

use crate::error::{Error, Result};
use crate::pkcs11::*;

use rusqlite;
use rusqlite::{Error as rlError, ErrorCode};

/// Converts `rusqlite::Error` into the crate's custom `Error` type, mapping
/// specific SQLite error codes to appropriate PKCS#11 `CK_RV` return values.
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

/// Converts `std::sync::PoisonError` (from Mutex locking) into `CKR_CANT_LOCK`.
impl<T> From<std::sync::PoisonError<std::sync::MutexGuard<'_, T>>> for Error {
    fn from(_: std::sync::PoisonError<std::sync::MutexGuard<'_, T>>) -> Error {
        Error::ck_rv(CKR_CANT_LOCK)
    }
}

/// Checks if a table exists within the specified schema (or main) in the
/// SQLite database.
///
/// Returns `Ok(())` if the table exists, `CKR_CRYPTOKI_NOT_INITIALIZED` if
/// not, or other errors for database issues.
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
    match rows.next()? {
        Some(row) => match row.get(0)? {
            1 => (),
            0 => return Err(CKR_CRYPTOKI_NOT_INITIALIZED)?,
            _ => return Err(CKR_DEVICE_ERROR)?,
        },
        _ => {
            return Err(CKR_CRYPTOKI_NOT_INITIALIZED)?;
        }
    }
    match rows.next() {
        Ok(None) => Ok(()),
        Ok(_) => Err(CKR_DEVICE_ERROR)?,
        Err(e) => Err(e)?,
    }
}

/// Enables the `secure_delete` pragma on the SQLite connection.
/// This helps ensure deleted data is overwritten, enhancing security.
pub fn set_secure_delete(
    conn: &MutexGuard<'_, rusqlite::Connection>,
) -> Result<()> {
    Ok(conn.execute_batch("PRAGMA secure_delete = ON")?)
}
