// Copyright 2024 Simo Sorce
// See LICENSE.txt file for terms

//! This module provides a storage backend implementation (`SqliteStorage`)
//! that fulfills the `StorageRaw` trait using a single SQLite database file
//! for persistence.

use std::sync::{Arc, Mutex};

use crate::attribute::{AttrType, Attribute};
use crate::error::{Error, Result};
use crate::misc::copy_sized_string;
use crate::object::Object;
use crate::storage::aci::{StorageACI, StorageAuthInfo};
use crate::storage::format::{StdStorageFormat, StorageRaw};
use crate::storage::sqlite_common::{check_table, set_secure_delete};
use crate::storage::{Storage, StorageDBInfo, StorageTokenInfo};

use itertools::Itertools;
use pkcs11::*;
use rusqlite::types::{Value, ValueRef};
use rusqlite::{
    params, params_from_iter, Connection, Rows, Statement, Transaction,
};

/// Helper to wrap general errors from this module.
fn bad_code<E: std::error::Error + 'static>(error: E) -> Error {
    Error::ck_rv_from_error(CKR_GENERAL_ERROR, error)
}

/// Helper to wrap storage/memory related errors from this module.
fn bad_storage<E: std::error::Error + 'static>(error: E) -> Error {
    Error::ck_rv_from_error(CKR_DEVICE_MEMORY, error)
}

const DB_VERSION_COL: &str = "version";
const DB_VERSION: &str = "v1";
const TOKEN_INFO_META: &str = "TOKEN INFO";

const DROP_META_TABLE: &str = "DROP TABLE meta";
const CREATE_META_TABLE: &str =
    "CREATE TABLE meta (name TEXT NOT NULL, id INTEGER, value TEXT, data BLOB, UNIQUE(name, value))";

const OBJECTS_TABLE: &str = "objects";
const DROP_OBJ_TABLE: &str = "DROP TABLE objects";
const CREATE_OBJ_TABLE: &str = "CREATE TABLE objects (id int NOT NULL, attr int NOT NULL, val blob, UNIQUE (id, attr))";

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

/// Implements the `StorageRaw` trait using a single SQLite database file.
#[derive(Debug)]
pub struct SqliteStorage {
    /// Path to the SQLite database file.
    filename: String,
    /// Thread-safe connection to the SQLite database.
    conn: Arc<Mutex<Connection>>,
}

impl SqliteStorage {
    /// Helper to add a boolean attribute to an `Object` from an SQLite
    /// `ValueRef`.
    fn add_bool(
        obj: &mut Object,
        atype: CK_ATTRIBUTE_TYPE,
        val: ValueRef,
    ) -> Result<()> {
        obj.set_attr(match val.as_i64_or_null().map_err(bad_storage)? {
            Some(b) => Attribute::from_bool(atype, b != 0),
            None => return Err(CKR_ATTRIBUTE_VALUE_INVALID)?,
        })
    }

    /// Helper to add a numeric (CK_ULONG) attribute to an `Object` from an
    /// SQLite `ValueRef`.
    fn add_num(
        obj: &mut Object,
        atype: CK_ATTRIBUTE_TYPE,
        val: ValueRef,
    ) -> Result<()> {
        obj.set_attr(match val.as_i64_or_null().map_err(bad_storage)? {
            Some(n) => Attribute::from_ulong(atype, Self::val_to_ulong(n)?),
            None => return Err(CKR_ATTRIBUTE_VALUE_INVALID)?,
        })
    }

    /// Helper to add a string attribute to an `Object` from an SQLite
    /// `ValueRef`.
    fn add_string(
        obj: &mut Object,
        atype: CK_ATTRIBUTE_TYPE,
        val: ValueRef,
    ) -> Result<()> {
        obj.set_attr(match val.as_str_or_null().map_err(bad_storage)? {
            Some(s) => Attribute::from_string(atype, s.to_string()),
            None => return Err(CKR_ATTRIBUTE_VALUE_INVALID)?,
        })
    }

    /// Helper to add a byte array attribute to an `Object` from an SQLite
    /// `ValueRef`.
    fn add_byte_array(
        obj: &mut Object,
        atype: CK_ATTRIBUTE_TYPE,
        val: ValueRef,
    ) -> Result<()> {
        obj.set_attr(match val.as_blob_or_null().map_err(bad_storage)? {
            Some(v) => Attribute::from_bytes(atype, v.to_vec()),
            None => Attribute::from_bytes(atype, Vec::new()),
        })
    }

    /// Helper to add a CK_ULONG array attribute to an `Object` from an SQLite
    /// `ValueRef`.
    fn add_ulong_array(
        obj: &mut Object,
        atype: CK_ATTRIBUTE_TYPE,
        val: ValueRef,
    ) -> Result<()> {
        obj.set_attr(match val.as_blob_or_null().map_err(bad_storage)? {
            Some(blob) => {
                let ulen = std::mem::size_of::<u64>();
                if blob.len() % ulen != 0 {
                    return Err(CKR_DEVICE_MEMORY)?;
                }
                let vlen = blob.len() / ulen;
                let mut v = Vec::with_capacity(vlen);

                let mut idx = 0;
                while idx < blob.len() {
                    let chunk = &blob[idx..(idx + ulen)];
                    idx += ulen;
                    let u64val = u64::from_le_bytes(chunk.try_into()?);
                    v.push(CK_ULONG::try_from(u64val)?);
                }
                Attribute::from_ulong_array(atype, v)
            }
            None => Attribute::from_ulong_array(atype, Vec::new()),
        })
    }

    /// Helper to add a date attribute to an `Object` from an SQLite
    /// `ValueRef`.
    fn add_date(
        obj: &mut Object,
        atype: CK_ATTRIBUTE_TYPE,
        val: ValueRef,
    ) -> Result<()> {
        obj.set_attr(match val.as_str_or_null().map_err(bad_storage)? {
            Some(s) => {
                if s.len() == 0 {
                    /* special case for default empty value */
                    Attribute::from_date_bytes(atype, Vec::new())
                } else {
                    Attribute::from_date(atype, string_to_ck_date(s)?)
                }
            }
            None => return Err(CKR_ATTRIBUTE_VALUE_INVALID)?,
        })
    }

    /// Converts multiple rows from an SQLite query result (`Rows`) into a
    /// vector of `Object`s. Assumes rows are ordered by object ID and contain
    /// attribute type and value columns.
    fn rows_to_objects(mut rows: Rows) -> Result<Vec<Object>> {
        let mut objid = 0;
        let mut objects = Vec::<Object>::new();
        while let Some(row) = rows.next().map_err(bad_storage)? {
            let id: i32 = row.get(0).map_err(bad_storage)?;
            let atype: CK_ATTRIBUTE_TYPE = row.get(1).map_err(bad_storage)?;
            let val = row.get_ref(2).map_err(bad_storage)?;
            if objid != id {
                objid = id;
                objects.push(Object::new());
            }
            match objects.last_mut() {
                Some(obj) => {
                    let attrtype = AttrType::attr_id_to_attrtype(atype)?;
                    match attrtype {
                        AttrType::BoolType => Self::add_bool(obj, atype, val)?,
                        AttrType::NumType => Self::add_num(obj, atype, val)?,
                        AttrType::StringType => {
                            Self::add_string(obj, atype, val)?
                        }
                        AttrType::BytesType => {
                            Self::add_byte_array(obj, atype, val)?
                        }
                        AttrType::UlongArrayType => {
                            Self::add_ulong_array(obj, atype, val)?
                        }
                        AttrType::DateType => Self::add_date(obj, atype, val)?,
                        AttrType::DenyType | AttrType::IgnoreType => {
                            return Err(CKR_ATTRIBUTE_TYPE_INVALID)?
                        }
                    };
                }
                _ => {
                    return Err(CKR_GENERAL_ERROR)?;
                }
            }
        }
        Ok(objects)
    }

    /// Stores a metadata entry (key-value pair, potentially with an associated
    /// ID or BLOB) into the `meta` table within a transaction.
    ///
    /// Uses INSERT OR REPLACE.
    fn store_meta(
        tx: &mut Transaction,
        name: &str,
        id: Option<u32>,
        value: Option<&str>,
        data: Option<&[u8]>,
    ) -> Result<()> {
        let mut sql = String::from("INSERT OR REPLACE INTO meta (name");
        let mut params = Vec::<Value>::with_capacity(4);

        params.push(Value::from(ValueRef::from(name)));

        if let Some(i) = id {
            sql.push_str(", id");
            params.push(Value::from(i as i64));
        }
        if let Some(v) = value {
            sql.push_str(", value");
            params.push(Value::from(ValueRef::from(v)));
        }
        if let Some(d) = data {
            sql.push_str(", data");
            params.push(Value::from(ValueRef::from(d)));
        }
        sql.push_str(") VALUES(?");

        for _ in 1..params.len() {
            sql.push_str(", ?");
        }
        sql.push_str(")");

        let mut stmt = tx.prepare(&sql)?;
        let _ = stmt.execute(params_from_iter(params))?;
        Ok(())
    }

    /// Stores all attributes of an `Object` into the `objects` table within a
    /// transaction.
    ///
    /// First deletes any existing attributes for the object's UID, assigns a
    /// new numeric ID if necessary, then inserts each attribute as a separate
    /// row (id, attr_type, value).
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
                AttrType::UlongArrayType => Value::from({
                    let ulen = std::mem::size_of::<u64>();
                    let vu = a.to_ulong_array()?;
                    let mut v = Vec::<u8>::with_capacity(vu.len() * ulen);
                    for elem in vu.iter() {
                        let el64 = u64::try_from(*elem)?;
                        v.extend_from_slice(&el64.to_le_bytes());
                    }
                    v
                }),
                AttrType::DateType => Value::from(a.to_date_string()?),
                AttrType::DenyType | AttrType::IgnoreType => continue,
            };
            let _ = stmt
                .execute(params!(col_id, col_attr, col_val))
                .map_err(bad_storage)?;
        }
        Ok(())
    }

    /// Deletes all rows associated with an object's UID from the `objects`
    /// table within a transaction.
    ///
    /// Returns the numeric ID of the deleted object, or 0 if the object was
    /// not found.
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

    /// Converts a `CK_ULONG` value to a `rusqlite::Value` (specifically
    /// `Value::Integer`).
    ///
    /// Handles the special case `CK_UNAVAILABLE_INFORMATION` by storing it
    /// as -1, as SQLite's INTEGER might not store the full `u64` range
    /// required by CK_ULONG_MAX on some platforms, while ensuring standard
    /// PKCS#11 values fit within `i64`.
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

    /// Converts an `i64` value retrieved from SQLite back to a `CK_ULONG`.
    /// Handles the special case -1, mapping it back to
    /// `CK_UNAVAILABLE_INFORMATION`.
    fn val_to_ulong(val: i64) -> Result<CK_ULONG> {
        /* we need to map back CK_UNAVAILABLE_INFORMATION's special case */
        if val == -1 {
            Ok(CK_UNAVAILABLE_INFORMATION)
        } else {
            Ok(CK_ULONG::try_from(val)?)
        }
    }
}

const USER_FLAGS: &str = "USER FLAGS";
const USER_COUNTER: &str = "USER COUNTER";
const USER_DATA: &str = "USER DATA";
const USER_FLAGS_DEFAULT_PIN: u32 = 1;

/// Implementation of the low-level `StorageRaw` trait for `SqliteStorage`.
impl StorageRaw for SqliteStorage {
    fn is_initialized(&self) -> Result<()> {
        let conn = self.conn.lock()?;
        check_table(&conn, "", OBJECTS_TABLE)
    }

    fn db_reset(&mut self) -> Result<()> {
        let mut conn = self.conn.lock()?;
        let mut tx = conn.transaction().map_err(bad_storage)?;
        tx.set_drop_behavior(rusqlite::DropBehavior::Rollback);
        /* the drops can fail when files are empty (new) */
        let _ = tx.execute(DROP_META_TABLE, params![]);
        tx.execute(CREATE_META_TABLE, params![])
            .map_err(bad_storage)?;
        Self::store_meta(
            &mut tx,
            DB_VERSION_COL,
            None,
            Some(DB_VERSION),
            None,
        )?;
        let _ = tx.execute(DROP_OBJ_TABLE, params![]);
        tx.execute(CREATE_OBJ_TABLE, params![])
            .map_err(bad_storage)?;
        tx.commit().map_err(bad_storage)
    }

    fn open(&mut self) -> Result<()> {
        self.conn = match Connection::open(&self.filename) {
            Ok(c) => Arc::new(Mutex::from(c)),
            Err(_) => return Err(CKR_TOKEN_NOT_PRESENT)?,
        };
        /* Ensure secure delete is always set on the db */
        let conn = self.conn.lock()?;
        set_secure_delete(&conn)
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
                AttrType::UlongArrayType => Value::from({
                    let su = a.to_slice()?;
                    let slen = std::mem::size_of::<CK_ULONG>();
                    if su.len() % slen != 0 {
                        return Err(CKR_ATTRIBUTE_VALUE_INVALID)?;
                    }
                    let ulen = std::mem::size_of::<u64>();
                    let mut v =
                        Vec::<u8>::with_capacity((su.len() / slen) * ulen);

                    let mut idx = 0;
                    while idx < su.len() {
                        let elem = &su[idx..(idx + slen)];
                        idx += slen;
                        let sval = CK_ULONG::from_ne_bytes(elem.try_into()?);
                        let u64val = u64::try_from(sval)?;
                        v.extend_from_slice(&u64val.to_le_bytes());
                    }
                    v
                }),
                AttrType::DateType => {
                    Value::from(Attribute::from_ck_attr(a)?.to_date_string()?)
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

    fn fetch_token_info(&self) -> Result<StorageTokenInfo> {
        let mut info = StorageTokenInfo::default();
        let conn = self.conn.lock()?;
        let mut stmt =
            conn.prepare("SELECT value, data from meta WHERE name=?")?;
        let mut rows =
            stmt.query(params![Value::from(ValueRef::from(TOKEN_INFO_META))])?;
        while let Some(row) = rows.next()? {
            let name: String = row.get(0)?;
            let value: Vec<u8> = row.get(1)?;
            match name.as_str() {
                "label" => copy_sized_string(value.as_slice(), &mut info.label),
                "manufacturer" => {
                    copy_sized_string(value.as_slice(), &mut info.manufacturer)
                }
                "model" => copy_sized_string(value.as_slice(), &mut info.model),
                "serial" => {
                    copy_sized_string(value.as_slice(), &mut info.serial)
                }
                "flags" => {
                    info.flags = CK_FLAGS::try_from(u32::from_le_bytes(
                        value.try_into()?,
                    ))?
                }
                _ => (), /* ignore unknown values for forward compatibility */
            }
        }
        Ok(info)
    }

    fn store_token_info(&mut self, info: &StorageTokenInfo) -> Result<()> {
        let mut conn = self.conn.lock()?;
        let mut tx = conn.transaction().map_err(bad_storage)?;
        tx.set_drop_behavior(rusqlite::DropBehavior::Rollback);

        Self::store_meta(
            &mut tx,
            TOKEN_INFO_META,
            None,
            Some("label"),
            Some(&info.label as &[u8]),
        )?;
        Self::store_meta(
            &mut tx,
            TOKEN_INFO_META,
            None,
            Some("manufacturer"),
            Some(&info.manufacturer as &[u8]),
        )?;
        Self::store_meta(
            &mut tx,
            TOKEN_INFO_META,
            None,
            Some("model"),
            Some(&info.model as &[u8]),
        )?;
        Self::store_meta(
            &mut tx,
            TOKEN_INFO_META,
            None,
            Some("serial"),
            Some(&info.serial as &[u8]),
        )?;
        /* filter out runtime flags */
        let flags = info.flags
            & (CKF_LOGIN_REQUIRED
                | CKF_TOKEN_INITIALIZED
                | CKF_WRITE_PROTECTED);
        let flags32 = u32::try_from(flags)?;
        Self::store_meta(
            &mut tx,
            "TOKEN INFO",
            None,
            Some("flags"),
            Some(&flags32.to_le_bytes() as &[u8]),
        )?;

        tx.commit().map_err(bad_storage)
    }

    fn fetch_user(&self, uid: &str) -> Result<StorageAuthInfo> {
        let conn = self.conn.lock()?;
        let mut stmt = conn.prepare(
            "SELECT name, data from meta WHERE (name in (?, ?, ?) AND value=?)",
        )?;
        let mut rows = stmt.query(params![
            Value::from(ValueRef::from(USER_FLAGS)),
            Value::from(ValueRef::from(USER_COUNTER)),
            Value::from(ValueRef::from(USER_DATA)),
            Value::from(ValueRef::from(uid))
        ])?;
        let mut info = StorageAuthInfo::default();
        while let Some(row) = rows.next()? {
            let name: String = row.get(0)?;
            let data: Vec<u8> = row.get(1)?;
            match name.as_str() {
                USER_FLAGS => {
                    let flags32 = u32::from_le_bytes(data.try_into()?);
                    if flags32 & USER_FLAGS_DEFAULT_PIN != 0 {
                        info.default_pin = true;
                    }
                }
                USER_COUNTER => {
                    info.cur_attempts = CK_ULONG::try_from(u32::from_le_bytes(
                        data.try_into()?,
                    ))?
                }
                USER_DATA => info.user_data = Some(data),
                _ => (), /* ignore unknown values for forward compatibility */
            }
        }
        if info.user_data.is_none() {
            return Err(CKR_USER_PIN_NOT_INITIALIZED)?;
        }
        Ok(info)
    }

    fn store_user(&mut self, uid: &str, data: &StorageAuthInfo) -> Result<()> {
        let mut conn = self.conn.lock()?;
        let mut tx = conn.transaction().map_err(bad_storage)?;
        tx.set_drop_behavior(rusqlite::DropBehavior::Rollback);

        if data.default_pin {
            let flags32 = USER_FLAGS_DEFAULT_PIN;
            Self::store_meta(
                &mut tx,
                USER_FLAGS,
                None,
                Some(uid),
                Some(&flags32.to_le_bytes() as &[u8]),
            )?;
        }

        let counter32 = u32::try_from(data.cur_attempts)?;
        Self::store_meta(
            &mut tx,
            USER_COUNTER,
            None,
            Some(uid),
            Some(&counter32.to_le_bytes() as &[u8]),
        )?;

        if let Some(blob) = &data.user_data {
            Self::store_meta(
                &mut tx,
                USER_DATA,
                None,
                Some(uid),
                Some(blob.as_slice()),
            )?;
        }
        tx.commit().map_err(bad_storage)
    }
}

/// Information provider for the SQLite storage backend discovery.
#[derive(Debug)]
pub struct SqliteDBInfo {
    /// The unique type name for this backend ("sqlite").
    db_type: &'static str,
}

/// Implementation of the `StorageDBInfo` trait for the SQLite backend.
impl StorageDBInfo for SqliteDBInfo {
    /// Creates a new SQLite storage instance, wrapping it in the standard
    /// ACI layer.
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

    /// Returns the type name "sqlite".
    fn dbtype(&self) -> &str {
        self.db_type
    }
}

/// Static instance of the SQLite storage backend information provider.
pub static DBINFO: SqliteDBInfo = SqliteDBInfo { db_type: "sqlite" };
