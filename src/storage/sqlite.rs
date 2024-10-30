// Copyright 2024 Simo Sorce
// See LICENSE.txt file for terms

use std::sync::{Arc, Mutex, MutexGuard};

use crate::attribute::{string_to_ck_date, AttrType, Attribute};
use crate::error::{Error, Result};
use crate::interface::*;
use crate::object::Object;
use crate::storage::aci::StorageACI;
use crate::storage::format::{StdStorageFormat, StorageRaw};
use crate::storage::{Storage, StorageDBInfo};

use itertools::Itertools;
use rusqlite::types::Value;
use rusqlite::{params, Connection, Rows, Statement, Transaction};
use rusqlite::{Error as rlError, ErrorCode};

fn bad_code<E: std::error::Error + 'static>(error: E) -> Error {
    Error::ck_rv_from_error(CKR_GENERAL_ERROR, error)
}

fn bad_storage<E: std::error::Error + 'static>(error: E) -> Error {
    Error::ck_rv_from_error(CKR_DEVICE_MEMORY, error)
}

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

const OBJECTS_TABLE: &str = "objects";
const DROP_DB_TABLE: &str = "DROP TABLE objects";
const CREATE_DB_TABLE: &str = "CREATE TABLE objects (id int NOT NULL, attr int NOT NULL, val blob, UNIQUE (id, attr))";
const CHECK_DB_TABLE: &str =
    "SELECT count(*) FROM sqlite_master WHERE type='table' AND name = ?";

/* search by filter constants */
const SEARCH_ALL: &str = "SELECT * FROM objects";
const SEARCH_NEST: &str = " WHERE id IN ( ";
const SEARCH_OBJ_ID: &str = "SELECT id FROM objects WHERE attr = ? AND val = ?";
const SEARCH_CONCAT: &str = " INTERSECT ";
const SEARCH_CLOSE: &str = " )";
const SEARCH_ORDER: &str = " ORDER by id";

const SEARCH_BY_SINGLE_ATTR: &str = "SELECT * FROM objects WHERE id IN (SELECT id FROM objects WHERE attr = ? AND val = ?)";
const UPDATE_ATTR: &str = "INSERT OR REPLACE INTO objects VALUES (?, ?, ?)";
const DELETE_OBJ: &str = "DELETE FROM objects WHERE id = ?";
const MAX_ID: &str = "SELECT IFNULL(MAX(id), 0) FROM objects";

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

#[derive(Debug)]
pub struct SqliteStorage {
    filename: String,
    conn: Arc<Mutex<Connection>>,
}

impl SqliteStorage {
    fn rows_to_objects(mut rows: Rows) -> Result<Vec<Object>> {
        let mut objid = 0;
        let mut objects = Vec::<Object>::new();
        while let Some(row) = rows.next().map_err(bad_storage)? {
            let id: i32 = row.get(0).map_err(bad_storage)?;
            let atype: CK_ULONG = row.get(1).map_err(bad_storage)?;
            let val = row.get_ref(2).map_err(bad_storage)?;
            if objid != id {
                objid = id;
                objects.push(Object::new());
            }
            if let Some(obj) = objects.last_mut() {
                let attrtype = AttrType::attr_id_to_attrtype(atype)?;
                let attr = match attrtype {
                    AttrType::BoolType => {
                        match val.as_i64_or_null().map_err(bad_storage)? {
                            Some(b) => Attribute::from_bool(atype, b != 0),
                            None => return Err(CKR_ATTRIBUTE_VALUE_INVALID)?,
                        }
                    }
                    AttrType::NumType => {
                        match val.as_i64_or_null().map_err(bad_storage)? {
                            Some(n) => {
                                let val = Self::val_to_ulong(n)?;
                                Attribute::from_ulong(atype, val)
                            }
                            None => return Err(CKR_ATTRIBUTE_VALUE_INVALID)?,
                        }
                    }
                    AttrType::StringType => match val
                        .as_str_or_null()
                        .map_err(bad_storage)?
                    {
                        Some(s) => Attribute::from_string(atype, s.to_string()),
                        None => return Err(CKR_ATTRIBUTE_VALUE_INVALID)?,
                    },
                    AttrType::BytesType => {
                        match val.as_blob_or_null().map_err(bad_storage)? {
                            Some(v) => Attribute::from_bytes(atype, v.to_vec()),
                            None => Attribute::from_bytes(atype, Vec::new()),
                        }
                    }
                    AttrType::DateType => {
                        match val.as_str_or_null().map_err(bad_storage)? {
                            Some(s) => Attribute::from_date(
                                atype,
                                string_to_ck_date(s)?,
                            ),
                            None => return Err(CKR_ATTRIBUTE_VALUE_INVALID)?,
                        }
                    }
                    AttrType::DenyType | AttrType::IgnoreType => {
                        return Err(CKR_ATTRIBUTE_TYPE_INVALID)?
                    }
                };
                obj.set_attr(attr)?;
            } else {
                return Err(CKR_GENERAL_ERROR)?;
            }
        }
        Ok(objects)
    }

    fn store_object(
        tx: &mut Transaction,
        uid: &String,
        obj: Object,
    ) -> Result<()> {
        let objid = match Self::delete_object(tx, uid)? {
            0 => {
                /* find new id to use for new object */
                let mut maxid = 0;
                let mut stmt = tx.prepare(MAX_ID).map_err(bad_code)?;
                let mut rows = stmt.query([]).map_err(bad_code)?;
                while let Some(row) = rows.next().map_err(bad_storage)? {
                    maxid = row.get(0).map_err(bad_storage)?;
                }
                maxid + 1
            }
            x => x,
        };
        let mut stmt = tx.prepare(UPDATE_ATTR).map_err(bad_storage)?;
        for a in obj.get_attributes() {
            let col_id = Value::from(i32::try_from(objid)?);
            let col_attr = Value::from(u32::try_from(a.get_type())?);
            let col_val = match a.get_attrtype() {
                AttrType::BoolType => Value::from(a.to_bool()?),
                AttrType::NumType => Self::num_to_val(a.to_ulong()?)?,
                AttrType::StringType => Value::from(a.to_string()?),
                AttrType::BytesType => Value::from(a.to_bytes()?.clone()),
                AttrType::DateType => Value::from(a.to_date_string()?),
                AttrType::DenyType | AttrType::IgnoreType => continue,
            };
            let _ = stmt
                .execute(params!(col_id, col_attr, col_val))
                .map_err(bad_storage)?;
        }
        Ok(())
    }

    fn delete_object(tx: &mut Transaction, uid: &String) -> Result<i32> {
        let mut stmt = tx.prepare(SEARCH_OBJ_ID).map_err(bad_storage)?;
        let objid = match stmt
            .query_row(params![CKA_UNIQUE_ID, uid], |row| row.get(0))
        {
            Ok(r) => r,
            Err(e) => match e {
                rusqlite::Error::QueryReturnedNoRows => 0,
                _ => return Err(CKR_DEVICE_MEMORY)?,
            },
        };
        /* remove old object */
        if objid != 0 {
            stmt = tx.prepare(DELETE_OBJ).map_err(bad_code)?;
            stmt.execute(params![objid]).map_err(bad_storage)?;
        }
        Ok(objid)
    }

    fn num_to_val(ulong: CK_ULONG) -> Result<Value> {
        /* CK_UNAVAILABLE_INFORMATION need to be special cased */
        /* for storage compatibility CK_ULONGs can only be stored as u32
         * values and PKCS#11 spec pay attentions to never allocate numbers
         * bigger than what can be stored in a u32. However the value of
         * CK_UNAVAILABLE_INFORMATION is defined as CK_ULONG::MAX which is
         * a larger number than what we can store in a u32.
         * Sqlite however can store i64 numbers, so we store -1 to indicate
         * this special case to the decoding side as well */
        let val = if ulong == CK_UNAVAILABLE_INFORMATION {
            -1
        } else {
            /* we need to catch as an error any value > u32::MAX so we always
             * try_from a u32 first to check the boundaries. */
            i64::try_from(u32::try_from(ulong)?)?
        };
        Ok(Value::from(val))
    }

    fn val_to_ulong(val: i64) -> Result<CK_ULONG> {
        /* we need to map back CK_UNAVAILABLE_INFORMATION's special case */
        if val == -1 {
            Ok(CK_UNAVAILABLE_INFORMATION)
        } else {
            Ok(CK_ULONG::try_from(val)?)
        }
    }
}

impl StorageRaw for SqliteStorage {
    fn is_initialized(&self) -> Result<()> {
        let conn = self.conn.lock()?;
        check_table(conn, OBJECTS_TABLE)
    }

    fn db_reset(&mut self) -> Result<()> {
        let mut conn = self.conn.lock()?;
        let mut tx = conn.transaction().map_err(bad_storage)?;
        tx.set_drop_behavior(rusqlite::DropBehavior::Rollback);
        /* the drop can fail when files are empty (new) */
        let _ = tx.execute(DROP_DB_TABLE, params![]);
        tx.execute(CREATE_DB_TABLE, params![])
            .map_err(bad_storage)?;
        tx.commit().map_err(bad_storage)
    }

    fn open(&mut self) -> Result<()> {
        self.conn = match Connection::open(&self.filename) {
            Ok(c) => Arc::new(Mutex::from(c)),
            Err(_) => return Err(CKR_TOKEN_NOT_PRESENT)?,
        };
        Ok(())
    }

    fn flush(&mut self) -> Result<()> {
        Ok(())
    }

    fn fetch_by_uid(
        &self,
        uid: &String,
        attrs: &[CK_ATTRIBUTE],
    ) -> Result<Object> {
        let conn = self.conn.lock()?;
        let mut stmt: Statement;
        let rows = if attrs.len() == 0 {
            stmt = conn.prepare(SEARCH_BY_SINGLE_ATTR).map_err(bad_code)?;
            stmt.query(params![CKA_UNIQUE_ID, uid]).map_err(bad_code)?
        } else {
            let mut params = Vec::<Value>::with_capacity(attrs.len() + 2);
            params.push(Value::from(u32::try_from(CKA_UNIQUE_ID)?));
            params.push(Value::from(uid.clone()));

            for a in attrs {
                params.push(Value::from(u32::try_from(a.type_)?));
            }
            let formatter = attrs
                .iter()
                .format_with(" OR ", |_, f| f(&format!("attr = ?")));
            let sql = format!("{} AND ({})", SEARCH_BY_SINGLE_ATTR, formatter);
            stmt = conn.prepare(&sql).map_err(bad_code)?;
            stmt.query(rusqlite::params_from_iter(params))
                .map_err(bad_code)?
        };
        let mut objects = Self::rows_to_objects(rows)?;
        match objects.len() {
            0 => Err(Error::not_found(uid.clone())),
            1 => Ok(objects.pop().unwrap()),
            _ => Err(CKR_GENERAL_ERROR)?,
        }
    }

    fn search(&self, template: &[CK_ATTRIBUTE]) -> Result<Vec<Object>> {
        let conn = self.conn.lock()?;
        let mut search_query = String::from(SEARCH_ALL);
        let mut subqcount = 0;
        let mut search_params = Vec::<Value>::with_capacity(template.len() * 2);
        for a in template {
            /* add subqueries */
            if subqcount == 0 {
                search_query.push_str(SEARCH_NEST);
            } else {
                search_query.push_str(SEARCH_CONCAT);
            }
            search_query.push_str(SEARCH_OBJ_ID);
            /* add parameters */
            search_params.push(Value::from(u32::try_from(a.type_)?));
            search_params.push(match AttrType::attr_id_to_attrtype(a.type_)? {
                AttrType::BoolType => Value::from(a.to_bool()?),
                AttrType::NumType => Self::num_to_val(a.to_ulong()?)?,
                AttrType::StringType => Value::from(a.to_string()?),
                AttrType::BytesType => Value::from(a.to_buf()?),
                AttrType::DateType => {
                    Value::from(a.to_attribute()?.to_date_string()?)
                }
                AttrType::DenyType | AttrType::IgnoreType => {
                    return Err(CKR_ATTRIBUTE_TYPE_INVALID)?
                }
            });
            subqcount += 1;
        }
        if subqcount > 0 {
            search_query.push_str(SEARCH_CLOSE);
        }
        /* finally make sure results return ordered by id,
         * this simplifies conversion to actual Objects */
        search_query.push_str(SEARCH_ORDER);

        let mut stmt = conn.prepare(&search_query).map_err(bad_code)?;
        let rows = stmt
            .query(rusqlite::params_from_iter(search_params))
            .map_err(bad_code)?;
        Ok(Self::rows_to_objects(rows)?)
    }

    fn store_obj(&mut self, obj: Object) -> Result<()> {
        let uid = obj.get_attr_as_string(CKA_UNIQUE_ID)?;
        let mut conn = self.conn.lock()?;
        let mut tx = conn.transaction().map_err(bad_storage)?;
        tx.set_drop_behavior(rusqlite::DropBehavior::Rollback);
        Self::store_object(&mut tx, &uid, obj)?;
        tx.commit().map_err(bad_storage)
    }

    fn remove_by_uid(&mut self, uid: &String) -> Result<()> {
        let mut conn = self.conn.lock()?;
        let mut tx = conn.transaction().map_err(bad_storage)?;
        tx.set_drop_behavior(rusqlite::DropBehavior::Rollback);
        Self::delete_object(&mut tx, &uid)?;
        tx.commit().map_err(bad_storage)
    }
}

#[derive(Debug)]
pub struct SqliteDBInfo {
    db_type: &'static str,
    db_suffix: &'static str,
}

impl StorageDBInfo for SqliteDBInfo {
    fn new(&self, conf: &Option<String>) -> Result<Box<dyn Storage>> {
        let raw_store = Box::new(SqliteStorage {
            filename: match conf {
                Some(s) => s.clone(),
                None => String::from(""),
            },
            conn: Arc::new(Mutex::from(Connection::open_in_memory()?)),
        });
        Ok(Box::new(StdStorageFormat::new(
            raw_store,
            StorageACI::new(true),
        )))
    }

    fn dbtype(&self) -> &str {
        self.db_type
    }

    fn dbsuffix(&self) -> &str {
        self.db_suffix
    }
}

pub static DBINFO: SqliteDBInfo = SqliteDBInfo {
    db_type: "sqlite",
    db_suffix: ".sql",
};
