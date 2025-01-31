// Copyright 2024 Simo Sorce
// See LICENSE.txt file for terms

use std::fmt::Write as _;
use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard};

use crate::attribute::{AttrType, Attribute, CkAttrs};
use crate::error::{Error, Result};
use crate::interface::*;
use crate::misc::{copy_sized_string, zeromem};
use crate::object::Object;
use crate::storage;
use crate::storage::sqlite_common::{check_table, set_secure_delete};
use crate::storage::{Storage, StorageDBInfo, StorageTokenInfo};
use crate::token::TokenFacilities;
use crate::CSPRNG;

use itertools::Itertools;
use rusqlite::types::{FromSqlError, Value, ValueRef};
use rusqlite::{params, Connection, OpenFlags, Rows, Transaction};

mod attrs;
use attrs::*;
pub mod ci;
mod config;
use ci::*;
use config::*;

impl From<std::fmt::Error> for Error {
    fn from(_: std::fmt::Error) -> Error {
        Error::ck_rv(CKR_GENERAL_ERROR)
    }
}

impl From<FromSqlError> for Error {
    fn from(_: FromSqlError) -> Error {
        Error::ck_rv(CKR_GENERAL_ERROR)
    }
}

/* NSS db versions */
const CERT_DB_VERSION: usize = 9;
const KEY_DB_VERSION: usize = 4;
const NSS_PUBLIC_TABLE: &str = "nssPublic";
const NSS_PUBLIC_SCHEMA: &str = "public";
const NSS_PRIVATE_TABLE: &str = "nssPrivate";
const NSS_PRIVATE_SCHEMA: &str = "private";
const NSS_SPECIAL_NULL_VALUE: [u8; 3] = [0xa5, 0x0, 0x5a];

const NSS_ID_PREFIX: &str = "NSSID";

/* SFTK_MAX_PIN in NSS code */
const NSS_PIN_MAX: usize = 500;
/* SHA1_LENGTH in NSS code */
const NSS_PIN_SALT_LEN: usize = 20;

fn nss_id_format(table: &str, id: u32) -> String {
    format!("{}-{}-{}", NSS_ID_PREFIX, table, id)
}

fn nss_id_parse(nssid: &str) -> Result<(String, u32)> {
    let mut tokens = nssid.split('-');
    match tokens.next() {
        Some(p) => {
            if p != NSS_ID_PREFIX {
                return Err(CKR_GENERAL_ERROR)?;
            }
        }
        None => return Err(CKR_GENERAL_ERROR)?,
    }
    let table = match tokens.next() {
        Some(t) => t,
        None => return Err(CKR_GENERAL_ERROR)?,
    };
    let id = match tokens.next() {
        Some(i) => u32::from_str_radix(i, 10)?,
        None => return Err(CKR_GENERAL_ERROR)?,
    };
    if tokens.next().is_some() {
        return Err(CKR_GENERAL_ERROR)?;
    }

    Ok((table.to_string(), id))
}

fn nss_col_to_type(col: &str) -> Result<CK_ULONG> {
    Ok(CK_ULONG::from_str_radix(&col[1..], 16)?)
}

fn num_to_val(ulong: CK_ULONG) -> Result<Value> {
    /* CK_UNAVAILABLE_INFORMATION need to be special cased */
    /* for storage compatibility CK_ULONGs can only be stored as u32
     * values and PKCS#11 spec pay attentions to never allocate numbers
     * bigger than what can be stored as a u32. However the value of
     * CK_UNAVAILABLE_INFORMATION is defined as CK_ULONG::MAX which is
     * a larger number than what we can store in a u32.
     * ensure we store any CK_ULONG as a vector of 4 bytes in big
     * endian format, and map ULONG::MAX to u32::MAX */
    let val = if ulong == CK_UNAVAILABLE_INFORMATION {
        u32::MAX
    } else {
        /* we need to catch as an error any value > u32::MAX so we always
         * try_from a u32 first to check the boundaries. */
        u32::try_from(ulong)?
    };
    Ok(Value::from(val.to_be_bytes().to_vec()))
}

static NSS_PASS_CHECK: &[u8; 14] = b"password-check";

struct NSSSearchQuery {
    public: Option<String>,
    private: Option<String>,
    params: Vec<Value>,
}

#[derive(Debug)]
pub struct NSSStorage {
    config: NSSConfig,
    conn: Arc<Mutex<Connection>>,
    keys: KeysWithCaching,
}

impl NSSStorage {
    fn get_token_info(&self) -> Result<StorageTokenInfo> {
        let mut info = StorageTokenInfo {
            label: [0; 32],
            manufacturer: [0; 32],
            model: [0; 16],
            serial: [0; 16],
            flags: CKF_TOKEN_INITIALIZED,
        };
        copy_sized_string(
            self.config.get_token_label_as_bytes(),
            &mut info.label,
        );
        copy_sized_string(
            storage::MANUFACTURER_ID.as_bytes(),
            &mut info.manufacturer,
        );
        if self.config.password_required {
            info.flags |= CKF_LOGIN_REQUIRED;
        }
        match self.fetch_password() {
            Ok(_) => info.flags |= CKF_USER_PIN_INITIALIZED,
            Err(e) => {
                if e.rv() != CKR_USER_PIN_NOT_INITIALIZED {
                    return Err(e);
                }
            }
        }
        Ok(info)
    }

    fn db_uri(path: &str, read_only: bool) -> Result<String> {
        let mut encoded_path = String::new();
        for c in path.as_bytes() {
            /* TODO: Find a small crate that can do URI Encoding
             * without carring huge HTTP dependencies */
            if (*c as char).is_ascii_alphanumeric() {
                encoded_path.push(*c as char);
            } else {
                write!(&mut encoded_path, "%{:02X}", *c)?;
            }
        }
        let mode = if read_only { "mode=ro" } else { "mode=rwc" };
        Ok(format!("file:{}?{}&cache=private", &encoded_path, mode))
    }

    fn db_attach(
        conn: &mut MutexGuard<'_, rusqlite::Connection>,
        path: &str,
        name: &str,
        read_only: bool,
    ) -> Result<()> {
        let uri = Self::db_uri(path, read_only)?;
        let attach = format!("ATTACH DATABASE '{}' AS {}", uri, name);
        if conn.execute(&attach, params![]).is_err() {
            return Err(CKR_TOKEN_NOT_PRESENT)?;
        }
        Ok(())
    }

    fn new_main_tables(
        tx: &mut Transaction,
        schema: &str,
        table: &str,
    ) -> Result<()> {
        /* the drop can fail when files are empty (new) */
        let _ =
            tx.execute(&format!("DROP TABLE {}.{}", schema, table), params![]);

        /* prep the monster tables NSSDB uses */
        let formatter = NSS_KNOWN_ATTRIBUTES
            .iter()
            .format_with(", ", |a, f| f(&format_args!("a{:x}", a)));
        let columns = format!(", {}", formatter);

        /* main tables */
        let sql = format!(
            "CREATE TABLE {}.{} (id PRIMARY KEY UNIQUE ON CONFLICT ABORT{})",
            schema, table, columns
        );
        tx.execute(&sql, params![])?;

        /* indexes */

        /* a81 is CKA_ISSUER (81 hex, 129 dec) */
        let sql = format!("CREATE INDEX {}.issuer ON {} (a81)", schema, table);
        tx.execute(&sql, params![])?;

        /* a101 is CKA_SUBJECT (101 hex, 257 dec) */
        let sql =
            format!("CREATE INDEX {}.subject ON {} (a101)", schema, table);
        tx.execute(&sql, params![])?;

        /* a3 is CKA_LABEL */
        let sql = format!("CREATE INDEX {}.label ON {} (a3)", schema, table);
        tx.execute(&sql, params![])?;

        /* a102 is CKA_ID (102 hex, 258 dec) */
        let sql = format!("CREATE INDEX {}.ckaid ON {} (a102)", schema, table);
        tx.execute(&sql, params![])?;

        Ok(())
    }

    fn certsfile(&self) -> Result<String> {
        let cdir = match self.config.configdir {
            Some(ref c) => c,
            None => return Err(CKR_TOKEN_NOT_RECOGNIZED)?,
        };
        Ok(format!(
            "{}/{}cert{}.db",
            cdir, self.config.cert_prefix, CERT_DB_VERSION
        ))
    }

    fn keysfile(&self) -> Result<String> {
        let cdir = match self.config.configdir {
            Some(ref c) => c,
            None => return Err(CKR_TOKEN_NOT_RECOGNIZED)?,
        };
        Ok(format!(
            "{}/{}key{}.db",
            cdir, self.config.key_prefix, KEY_DB_VERSION
        ))
    }

    fn initialize(&mut self) -> Result<()> {
        let mut conn = self.conn.lock()?;
        let mut tx = conn.transaction()?;
        tx.set_drop_behavior(rusqlite::DropBehavior::Rollback);

        /* we assume the correct databases are attached since db_open()
         * even if they were not initialized (empty) */

        /* public keys / certs db */
        if !self.config.no_cert_db {
            Self::new_main_tables(
                &mut tx,
                NSS_PUBLIC_SCHEMA,
                NSS_PUBLIC_TABLE,
            )?;
        }

        /* Keys DB */
        if !self.config.no_key_db {
            Self::new_main_tables(
                &mut tx,
                NSS_PRIVATE_SCHEMA,
                NSS_PRIVATE_TABLE,
            )?;

            /* the drop can fail when files are empty (new) */
            let _ = tx.execute(
                &format!("DROP TABLE {}.metaData", NSS_PRIVATE_SCHEMA),
                params![],
            );
            /* metadata */
            tx.execute(&format!("CREATE TABLE {}.metaData (id PRIMARY KEY UNIQUE ON CONFLICT REPLACE, item1, item2)", NSS_PRIVATE_SCHEMA), params![])?;
        }

        tx.commit()?;
        Ok(())
    }

    fn rows_to_object(mut rows: Rows, all_cols: bool) -> Result<Object> {
        let mut obj = Object::new();

        /* FIXME: move sourcing columns to db open */
        let cols = match rows.as_ref() {
            Some(s) => {
                let cstr = s.column_names();
                let mut ctypes = Vec::<CK_ULONG>::with_capacity(cstr.len());
                for cs in &cstr {
                    ctypes.push(nss_col_to_type(cs)?);
                }
                ctypes
            }
            None => return Err(CKR_GENERAL_ERROR)?,
        };

        let first = if all_cols { 1 } else { 0 };

        if let Some(row) = rows.next()? {
            for i in first..cols.len() {
                /* skip NSS vendor attributes */
                if ignore_attribute(cols[i]) {
                    continue;
                }
                let bn: Option<&[u8]> = row.get_ref(i)?.as_blob_or_null()?;
                let blob: &[u8] = match bn {
                    Some(ref b) => b,
                    None => continue,
                };
                let atype = AttrType::attr_id_to_attrtype(cols[i])?;
                let attr = match atype {
                    AttrType::NumType => {
                        if blob.len() != 4 {
                            return Err(CKR_ATTRIBUTE_VALUE_INVALID)?;
                        }
                        let bytes: [u8; 4] = match blob.try_into() {
                            Ok(b) => b,
                            Err(_) => return Err(CKR_ATTRIBUTE_VALUE_INVALID)?,
                        };
                        let number = u32::from_be_bytes(bytes);
                        let ulong = number as CK_ULONG;
                        Attribute::from_attr_slice(
                            cols[i],
                            atype,
                            &ulong.to_ne_bytes(),
                        )
                    }
                    AttrType::BoolType
                    | AttrType::StringType
                    | AttrType::BytesType
                    | AttrType::DateType => {
                        if blob == &NSS_SPECIAL_NULL_VALUE {
                            Attribute::from_attr_slice(cols[i], atype, &[])
                        } else {
                            Attribute::from_attr_slice(cols[i], atype, blob)
                        }
                    }
                    AttrType::IgnoreType => {
                        Attribute::from_attr_slice(cols[i], atype, &[])
                    }
                    AttrType::DenyType => {
                        return Err(CKR_ATTRIBUTE_TYPE_INVALID)?
                    }
                };
                obj.set_attr(attr)?;
            }
        }

        /* ensure only one row was returned */
        match rows.next() {
            Ok(r) => match r {
                Some(_) => Err(CKR_GENERAL_ERROR)?,
                None => Ok(obj),
            },
            Err(_) => Err(CKR_GENERAL_ERROR)?,
        }
    }

    fn prepare_fetch(
        table: &str,
        objid: u32,
        attrs: &[CK_ATTRIBUTE],
    ) -> Result<NSSSearchQuery> {
        let columns: String;
        if attrs.len() == 0 {
            columns = "*".to_string();
        } else {
            let formatter = attrs
                .iter()
                .format_with(", ", |a, f| f(&format_args!("a{:x}", a.type_)));
            columns = format!("{}", formatter);
        }
        let mut query = NSSSearchQuery {
            public: None,
            private: None,
            params: Vec::<Value>::with_capacity(1),
        };
        let sql = format!(
            "SELECT DISTINCT {} FROM {} WHERE id = ? LIMIT 1",
            columns, table
        );
        match table {
            NSS_PUBLIC_TABLE => query.public = Some(sql),
            NSS_PRIVATE_TABLE => query.private = Some(sql),
            _ => return Err(CKR_GENERAL_ERROR)?,
        }

        query.params.push(Value::from(objid));

        Ok(query)
    }

    fn fetch_by_nssid(
        &self,
        table: &str,
        objid: u32,
        attrs: &[CK_ATTRIBUTE],
    ) -> Result<Object> {
        let query = Self::prepare_fetch(table, objid, &attrs)?;
        let sql = if let Some(ref public) = query.public {
            public
        } else if let Some(ref private) = query.private {
            private
        } else {
            return Err(CKR_GENERAL_ERROR)?;
        };
        let conn = self.conn.lock()?;
        let mut stmt = conn.prepare(sql)?;
        let rows = stmt.query(rusqlite::params_from_iter(query.params))?;
        Self::rows_to_object(rows, attrs.len() == 0)
    }

    /* Searching for Objects:
     * SELECT ALL id FROM <nssPublic|nssPrivate> WHERE a<1a2b>=$DATA<0>
     *      AND a<3c4d>=$DATA<1> AND a<5e6f>=$DATA<2> ...
     * $DATA<x> is replaced by the raw value of the attributes in the
     * template and the column name is the concatenation of character
     * 'a' + the hex representation of the attribute ID as defined in
     * PKCS#11.
     * Unfortunately preprocessing is needed to find out whether the
     * certs or keys databases or both need to be searched.
     */
    fn prepare_search(template: &[CK_ATTRIBUTE]) -> Result<NSSSearchQuery> {
        let mut do_private = true;
        let mut do_public = true;
        let mut query = NSSSearchQuery {
            public: None,
            private: None,
            params: Vec::<Value>::with_capacity(template.len()),
        };

        /* find which tables we are going to use */
        for attr in template {
            if attr.type_ == CKA_CLASS {
                if attr.pValue != std::ptr::null_mut() {
                    let t = attr.to_ulong()?;
                    match t {
                        CKO_PRIVATE_KEY | CKO_SECRET_KEY => do_public = false,
                        CKO_PUBLIC_KEY | CKO_CERTIFICATE => do_private = false,
                        _ => return Err(CKR_ATTRIBUTE_VALUE_INVALID)?,
                    }
                }
            }
            /* In NSSDB sensitive attributes are encrypted, so we can check
             * if the template is searching for any of the encrypted
             * attributes and if so just fail immediately */
            if is_sensitive_attribute(attr.type_) {
                return Err(CKR_ATTRIBUTE_SENSITIVE)?;
            }
        }

        /* if neither was excluded we may be asked for both */
        if do_private {
            query.private =
                Some(format!("SELECT ALL id FROM {} ", NSS_PRIVATE_TABLE));
        }
        if do_public {
            query.public =
                Some(format!("SELECT ALL id FROM {} ", NSS_PUBLIC_TABLE));
        }

        for idx in 0..template.len() {
            static CONCAT: &str = " AND";
            static WHERE: &str = " WHERE";
            let atype = AttrType::attr_id_to_attrtype(template[idx].type_)?;
            let atval = u32::try_from(template[idx].type_)?;

            if let Some(ref mut prv) = query.private {
                if idx != 0 {
                    prv.push_str(CONCAT);
                } else {
                    prv.push_str(WHERE);
                }
                write!(prv, " a{:x} = ?", atval)?;
            }

            if let Some(ref mut pbl) = query.public {
                if idx != 0 {
                    pbl.push_str(CONCAT);
                } else {
                    pbl.push_str(WHERE);
                }
                write!(pbl, " a{:x} = ?", atval)?;
            }

            /* NSS Encodes explicitly empty attributes with a weird 3 bytes value,
             * so we have to account for that when searching */
            if template[idx].ulValueLen == 0 {
                let val: &[u8] = &NSS_SPECIAL_NULL_VALUE;
                query.params.push(ValueRef::from(val).into());
            } else {
                query.params.push(match atype {
                    AttrType::NumType => num_to_val(template[idx].to_ulong()?)?,
                    _ => Value::from(template[idx].to_buf()?),
                });
            }
        }
        Ok(query)
    }

    fn search_with_params(
        conn: &mut MutexGuard<'_, rusqlite::Connection>,
        query: &str,
        params: Vec<Value>,
        table: &str,
    ) -> Result<Vec<String>> {
        let mut stmt = conn.prepare(query)?;
        let mut rows = stmt.query(rusqlite::params_from_iter(params))?;
        let mut result = Vec::<String>::new();
        while let Some(row) = rows.next()? {
            let id: u32 = row.get(0)?;
            result.push(nss_id_format(table, id));
        }
        Ok(result)
    }

    fn search_databases(
        &self,
        template: &[CK_ATTRIBUTE],
    ) -> Result<Vec<String>> {
        let mut result = Vec::<String>::new();
        let query = Self::prepare_search(template)?;
        let mut conn = self.conn.lock()?;
        if let Some(ref sql) = query.public {
            let mut public = Self::search_with_params(
                &mut conn,
                sql,
                query.params.clone(),
                NSS_PUBLIC_TABLE,
            )?;
            result.append(&mut public);
        }
        if let Some(ref sql) = query.private {
            let mut private = Self::search_with_params(
                &mut conn,
                sql,
                query.params,
                NSS_PRIVATE_TABLE,
            )?;
            result.append(&mut private);
        }
        Ok(result)
    }

    fn fetch_metadata(&self, name: &str) -> Result<(Vec<u8>, Vec<u8>)> {
        static SQL: &str = "SELECT ALL item1, item2 FROM metaData WHERE id = ?";
        let conn = self.conn.lock()?;
        let mut stmt = conn.prepare(SQL)?;
        let mut rows = stmt.query(params![name])?;
        match rows.next()? {
            Some(row) => {
                let item1 = row.get_ref(0)?.as_blob()?;
                let item2 = match row.get_ref(1)?.as_blob_or_null()? {
                    Some(b) => b,
                    None => &[],
                };
                Ok((item1.to_vec(), item2.to_vec()))
            }
            None => Err(CKR_OBJECT_HANDLE_INVALID)?,
        }
    }

    fn fetch_password(&self) -> Result<(Vec<u8>, Vec<u8>)> {
        match self.fetch_metadata("password") {
            Ok((salt, value)) => Ok((salt, value)),
            Err(e) => match e.rv() {
                CKR_OBJECT_HANDLE_INVALID => Err(CKR_USER_PIN_NOT_INITIALIZED)?,
                _ => Err(e)?,
            },
        }
    }

    fn fetch_signature(
        &self,
        dbtype: &str,
        nssobjid: u32,
        atype: CK_ATTRIBUTE_TYPE,
    ) -> Result<Vec<u8>> {
        let name = format!("sig_{}_{:08x}_{:08x}", dbtype, nssobjid, atype);
        let (value, _) = self.fetch_metadata(&name)?;
        Ok(value)
    }

    fn save_metadata(
        tx: &mut Transaction,
        name: &str,
        item1: &[u8],
        item2: &[u8],
    ) -> Result<()> {
        static SQL: &str =
            "INSERT INTO metaData (id,item1,item2) VALUES(?,?,?)";
        let mut stmt = tx.prepare(SQL)?;
        let _ = stmt.execute(params![
            Value::from(name.to_string()),
            Value::from(item1.to_vec()),
            Value::from(item2.to_vec()),
        ])?;
        Ok(())
    }

    fn save_password(&mut self, item1: &[u8], item2: &[u8]) -> Result<()> {
        let mut conn = self.conn.lock()?;
        let mut tx = conn.transaction()?;
        tx.set_drop_behavior(rusqlite::DropBehavior::Rollback);
        Self::save_metadata(&mut tx, "password", item1, item2)?;
        tx.commit()?;
        Ok(())
    }

    fn get_next_id(tx: &mut Transaction, table: &str) -> Result<u32> {
        let max_query = format!("select MAX(id) from {}", table);
        let mut id: u32;
        let mut stmt = tx.prepare(&max_query)?;
        let mut rows = stmt.query([])?;
        if let Some(row) = rows.next()? {
            let maxid: i64 = match row.get_ref(0)?.as_i64_or_null()? {
                Some(n) => n,
                None => 0,
            };
            if maxid > 0 && maxid < 0x3fffffff {
                id = u32::try_from(maxid + 1)?;
            } else {
                /* we are wrapping or starting anew, so we need to loop
                 * until we find a free spot */
                let next_query = format!("select id from {} where id=?", table);
                let mut stmt = tx.prepare(&next_query)?;
                id = 1;
                while id < 0x40000000 {
                    let mut rows = stmt.query([Value::from(id)])?;
                    if rows.next()?.is_none() {
                        /* free found */
                        break;
                    }
                    id += 1;
                }
                if id > 0x3fffffff {
                    return Err(CKR_OBJECT_HANDLE_INVALID)?;
                }
            }
        } else {
            return Err(CKR_GENERAL_ERROR)?;
        }
        Ok(id)
    }

    fn store_object(
        tx: &mut Transaction,
        table: &str,
        obj: &Object,
    ) -> Result<u32> {
        /* get next available id */
        let id = Self::get_next_id(tx, table)?;

        let attrs = obj.get_attributes();
        let mut atypes =
            Vec::<CK_ATTRIBUTE_TYPE>::with_capacity(1 + attrs.len());
        let mut params = Vec::<Value>::with_capacity(1 + attrs.len());
        params.push(Value::from(id));

        for a in attrs {
            let a_type = a.get_type();

            if is_skippable_attribute(a_type) {
                /* this is an attribute we always set on objects,
                 * but NSS does not store in the DB */
                continue;
            } else if !is_db_attribute(a_type) {
                /* NSS does not know about this attribute */
                return Err(CKR_ATTRIBUTE_TYPE_INVALID)?;
            }

            atypes.push(a_type);

            let a_val = a.get_value();
            params.push(if a_val.len() == 0 {
                ValueRef::from(&NSS_SPECIAL_NULL_VALUE as &[u8]).into()
            } else {
                match a.get_attrtype() {
                    AttrType::NumType => num_to_val(a.to_ulong()?)?,
                    AttrType::DenyType | AttrType::IgnoreType => {
                        ValueRef::from(&NSS_SPECIAL_NULL_VALUE as &[u8]).into()
                    }
                    _ => ValueRef::from(a_val.as_slice()).into(),
                }
            });
        }
        let aformatter = atypes
            .iter()
            .format_with(", ", |a, f| f(&format_args!("a{:x}", a)));
        let pformatter =
            params.iter().format_with(", ", |_, f| f(&format!("?")));
        let sql = format!(
            "INSERT INTO {} (id, {}) VALUES ({})",
            table, aformatter, pformatter
        );

        let mut stmt = tx.prepare(&sql)?;
        let _ = stmt.execute(rusqlite::params_from_iter(params))?;

        Ok(id)
    }

    fn store_signature(
        tx: &mut Transaction,
        dbtype: &str,
        nssobjid: u32,
        atype: CK_ULONG,
        val: &[u8],
    ) -> Result<()> {
        let name = format!("sig_{}_{:08x}_{:08x}", dbtype, nssobjid, atype);
        Self::save_metadata(tx, &name, val, &[])
    }

    fn store_attributes(
        tx: &mut Transaction,
        table: &str,
        id: u32,
        attrs: &CkAttrs,
    ) -> Result<()> {
        let mut atypes =
            Vec::<CK_ATTRIBUTE_TYPE>::with_capacity(1 + attrs.len());
        let mut params = Vec::<Value>::with_capacity(1 + attrs.len());
        for a in attrs.as_slice() {
            let attr = a.to_attribute()?;
            let a_type = attr.get_type();

            if is_skippable_attribute(a_type) {
                /* this is an attribute we always set on objects,
                 * but NSS does not store in the DB */
                continue;
            } else if !is_db_attribute(a_type) {
                /* NSS does not know about this attribute */
                return Err(CKR_ATTRIBUTE_TYPE_INVALID)?;
            }

            atypes.push(a.type_);

            let a_val = attr.get_value();
            params.push(if a_val.len() == 0 {
                ValueRef::from(&NSS_SPECIAL_NULL_VALUE as &[u8]).into()
            } else {
                match attr.get_attrtype() {
                    AttrType::NumType => num_to_val(attr.to_ulong()?)?,
                    AttrType::DenyType | AttrType::IgnoreType => {
                        ValueRef::from(&NSS_SPECIAL_NULL_VALUE as &[u8]).into()
                    }
                    _ => ValueRef::from(a_val.as_slice()).into(),
                }
            });
        }
        params.push(Value::from(id));

        let formatter = atypes
            .iter()
            .format_with(", ", |a, f| f(&format_args!("a{:x}=?", a)));
        let sql = format!("UPDATE {} SET {} WHERE id=?", table, formatter);

        let mut stmt = tx.prepare(&sql)?;
        let _ = stmt.execute(rusqlite::params_from_iter(params))?;
        Ok(())
    }
}

impl Storage for NSSStorage {
    fn open(&mut self) -> Result<StorageTokenInfo> {
        let mut ret = CKR_OK;
        let mut conn = self.conn.lock()?;

        /* Ensure secure delete is always set on the db
         * Doing this before the attach statements ensures the
         * same setting applies to all of the databases
         */
        set_secure_delete(&conn)?;

        if !self.config.no_cert_db {
            Self::db_attach(
                &mut conn,
                &self.certsfile()?,
                NSS_PUBLIC_SCHEMA,
                self.config.read_only,
            )?;
            match check_table(&mut conn, NSS_PUBLIC_SCHEMA, NSS_PUBLIC_TABLE) {
                Ok(_) => (),
                Err(e) => ret = e.rv(),
            }
        }
        if !self.config.no_key_db {
            Self::db_attach(
                &mut conn,
                &self.keysfile()?,
                NSS_PRIVATE_SCHEMA,
                self.config.read_only,
            )?;
            match check_table(&mut conn, NSS_PRIVATE_SCHEMA, NSS_PRIVATE_TABLE)
            {
                Ok(_) => (),
                Err(e) => ret = e.rv(),
            }
        }
        if ret != CKR_OK {
            return Err(ret)?;
        }
        /* ensure we drop the lock here, otherwise we deadlock inside
         * get_token_info() where we try to acquire it again to search
         * the database. */
        drop(conn);
        self.get_token_info()
    }

    fn reinit(
        &mut self,
        _facilities: &TokenFacilities,
    ) -> Result<StorageTokenInfo> {
        self.initialize()?;
        self.keys = KeysWithCaching::default();
        self.get_token_info()
    }

    fn flush(&mut self) -> Result<()> {
        Ok(())
    }

    fn fetch(
        &self,
        facilities: &TokenFacilities,
        handle: CK_OBJECT_HANDLE,
        attributes: &[CK_ATTRIBUTE],
    ) -> Result<Object> {
        let nssid = match facilities.handles.get(handle) {
            Some(id) => id,
            None => return Err(CKR_OBJECT_HANDLE_INVALID)?,
        };
        let (table, nssobjid) = nss_id_parse(nssid)?;

        /* the values don't matter, only the type */
        let dnm: CK_ULONG = 0;
        let mut attrs = CkAttrs::from(attributes);
        /* we need CKA_CLASS and CKA_KEY_TYPE to be present in
         * order to get sensitive attrs from the factory later */
        if attributes.len() != 0 {
            attrs.add_missing_ulong(CKA_CLASS, &dnm);
            /* it is safe to add CKA_KEY_TYPE even if the object
             * is not a key, the attribute will simply not be returned
             * in that case */
            attrs.add_missing_ulong(CKA_KEY_TYPE, &dnm);
            attrs.add_missing_ulong(CKA_CERTIFICATE_TYPE, &dnm);
            attrs.add_missing_ulong(CKA_EXTRACTABLE, &dnm);
            attrs.add_missing_ulong(CKA_SENSITIVE, &dnm);
            /* we can not query a DB for these */
            for a in NSS_SKIP_ATTRIBUTES {
                let _ = attrs.remove_ulong(a);
            }
        }
        let mut obj =
            self.fetch_by_nssid(&table, nssobjid, attrs.as_slice())?;
        if self.keys.available() {
            if table == NSS_PRIVATE_TABLE {
                for typ in NSS_SENSITIVE_ATTRIBUTES {
                    let encval = match obj.get_attr(typ) {
                        Some(attr) => attr.get_value(),
                        None => continue,
                    };
                    let plain = decrypt_data(facilities, &self.keys, encval)?;
                    obj.set_attr(Attribute::from_bytes(typ, plain))?;
                }
            }

            for typ in AUTHENTICATED_ATTRIBUTES {
                let value = match obj.get_attr(typ) {
                    Some(attr) => attr.get_value(),
                    None => continue,
                };
                let dbtype = match table.as_str() {
                    NSS_PUBLIC_TABLE => "cert",
                    NSS_PRIVATE_TABLE => "key",
                    _ => return Err(CKR_GENERAL_ERROR)?,
                };
                let sdbtype = u32::try_from(typ)?;
                let signature = self.fetch_signature(dbtype, nssobjid, typ)?;
                check_signature(
                    facilities,
                    &self.keys,
                    value.as_slice(),
                    signature.as_slice(),
                    nssobjid,
                    sdbtype,
                )?;
            }
        }
        /* add back the attributes that we requested, but that do not exist in DB */
        for a in NSS_SKIP_ATTRIBUTES {
            let factory = facilities.factories.get_object_factory(&obj)?;
            match attributes.iter().position(|r| r.type_ == a) {
                Some(_) => {
                    factory.set_attribute_default(a, &mut obj)?;
                    #[cfg(feature = "pkcs11_3_2")]
                    if a == CKA_OBJECT_VALIDATION_FLAGS {
                        /* All keys stored in the database are considered
                         * FIPS approved, on the assumption you can't import
                         * or create non-approved keys in the first place
                         */
                        obj.set_attr(Attribute::from_ulong(
                            CKA_OBJECT_VALIDATION_FLAGS,
                            crate::fips::indicators::KRF_FIPS,
                        ))?;
                    }
                }
                None => (),
            }
        }

        obj.set_handle(handle);
        Ok(obj)
    }

    fn store(
        &mut self,
        facilities: &mut TokenFacilities,
        mut obj: Object,
    ) -> Result<CK_OBJECT_HANDLE> {
        let (table, dbtype) = match obj.get_attr_as_ulong(CKA_CLASS)? {
            CKO_PRIVATE_KEY | CKO_SECRET_KEY => (NSS_PRIVATE_TABLE, "key"),
            CKO_PUBLIC_KEY | CKO_CERTIFICATE => (NSS_PUBLIC_TABLE, "cert"),
            _ => return Err(CKR_ATTRIBUTE_VALUE_INVALID)?,
        };

        if !self.keys.available() {
            return Err(CKR_USER_NOT_LOGGED_IN)?;
        }

        /* remove any ephemeral attributes before storage */
        let factory = facilities.factories.get_object_factory(&obj)?;
        for typ in factory.get_data().get_ephemeral() {
            obj.del_attr(*typ);
        }

        if table == NSS_PRIVATE_TABLE {
            for typ in NSS_SENSITIVE_ATTRIBUTES {
                /* NOTE: this will not handle correctly empty attributes or
                 * num types, but there are no sensitive ones */
                let plain = match obj.get_attr(typ) {
                    Some(attr) => attr.get_value(),
                    None => continue,
                };
                let encval = encrypt_data(
                    facilities,
                    &self.keys,
                    NSS_MP_PBE_ITERATION_COUNT,
                    plain.as_slice(),
                )?;
                obj.set_attr(Attribute::from_bytes(typ, encval))?;
            }
        }

        let mut conn = self.conn.lock()?;
        let mut tx = conn.transaction()?;
        tx.set_drop_behavior(rusqlite::DropBehavior::Rollback);
        let nssobjid = match Self::store_object(&mut tx, table, &obj) {
            Ok(id) => id,
            Err(e) => {
                /* FIXME retry once on abort in case there was a race
                 * with picking next id ? */
                return Err(e);
            }
        };

        for typ in AUTHENTICATED_ATTRIBUTES {
            /* NOTE: this will not handle correctly empty attributes or
             * num types, but there are no authenticated ones */
            let value = match obj.get_attr(typ) {
                Some(attr) => attr.get_value(),
                None => continue,
            };
            let sig = make_signature(
                facilities,
                &self.keys,
                value.as_slice(),
                nssobjid,
                u32::try_from(typ)?,
                NSS_MP_PBE_ITERATION_COUNT,
            )?;
            Self::store_signature(
                &mut tx,
                dbtype,
                nssobjid,
                typ,
                sig.as_slice(),
            )?;
        }

        tx.commit()?;

        /* create new handle for this object */
        let handle = facilities.handles.next();
        facilities
            .handles
            .insert(handle, nss_id_format(table, nssobjid))?;
        Ok(handle)
    }

    fn update(
        &mut self,
        facilities: &TokenFacilities,
        handle: CK_OBJECT_HANDLE,
        template: &[CK_ATTRIBUTE],
    ) -> Result<()> {
        let nssid = match facilities.handles.get(handle) {
            Some(id) => id,
            None => return Err(CKR_OBJECT_HANDLE_INVALID)?,
        };
        let (table, nssobjid) = nss_id_parse(nssid)?;

        if !self.keys.available() {
            return Err(CKR_USER_NOT_LOGGED_IN)?;
        }

        let mut attrs = CkAttrs::from(template);

        if table == NSS_PRIVATE_TABLE {
            for typ in NSS_SENSITIVE_ATTRIBUTES {
                /* NOTE: this will not handle correctly empty attributes or
                 * num types, but there are no sensitive ones */
                match attrs.find_attr(typ) {
                    Some(a) => {
                        let plain = a.to_buf()?;
                        let encval = encrypt_data(
                            facilities,
                            &self.keys,
                            NSS_MP_PBE_ITERATION_COUNT,
                            plain.as_slice(),
                        )?;
                        attrs.insert_unique_vec(a.type_, encval)?;
                    }
                    None => (),
                }
            }
        }

        let mut conn = self.conn.lock()?;
        let mut tx = conn.transaction()?;
        tx.set_drop_behavior(rusqlite::DropBehavior::Rollback);
        Self::store_attributes(&mut tx, &table, nssobjid, &attrs)?;

        for typ in AUTHENTICATED_ATTRIBUTES {
            /* NOTE: this will not handle correctly empty attributes or
             * num types, but there are no authenticated ones */
            match attrs.find_attr(typ) {
                Some(a) => {
                    let value = a.to_buf()?;
                    let sig = make_signature(
                        facilities,
                        &self.keys,
                        value.as_slice(),
                        nssobjid,
                        u32::try_from(typ)?,
                        NSS_MP_PBE_ITERATION_COUNT,
                    )?;
                    Self::store_signature(
                        &mut tx,
                        if table == NSS_PUBLIC_TABLE {
                            "cert"
                        } else {
                            "key"
                        },
                        nssobjid,
                        typ,
                        sig.as_slice(),
                    )?;
                }
                None => (),
            }
        }

        Ok(tx.commit()?)
    }

    fn search(
        &self,
        facilities: &mut TokenFacilities,
        template: &[CK_ATTRIBUTE],
    ) -> Result<Vec<CK_OBJECT_HANDLE>> {
        let mut ids = self.search_databases(template)?;
        let mut result = Vec::<CK_OBJECT_HANDLE>::with_capacity(ids.len());
        for id in ids.drain(..) {
            let handle = match facilities.handles.get_by_uid(&id) {
                Some(h) => *h,
                None => {
                    let h = facilities.handles.next();
                    facilities.handles.insert(h, id)?;
                    h
                }
            };
            result.push(handle);
        }
        Ok(result)
    }

    fn remove(
        &mut self,
        _facilities: &TokenFacilities,
        _handle: CK_OBJECT_HANDLE,
    ) -> Result<()> {
        Err(CKR_FUNCTION_NOT_SUPPORTED)?
    }

    fn load_token_info(&self) -> Result<StorageTokenInfo> {
        self.get_token_info()
    }

    fn store_token_info(&mut self, _info: &StorageTokenInfo) -> Result<()> {
        /* we can't store the token info back as NSSDB has
         * no place for that info and uses a mix of configuration
         * and env vars to define the labels anb stuff, so we just
         * lie and ignore the request */
        Ok(())
    }

    fn auth_user(
        &mut self,
        facilities: &TokenFacilities,
        user_type: CK_USER_TYPE,
        pin: &[u8],
        flag: &mut CK_FLAGS,
        check_only: bool,
    ) -> Result<()> {
        /* NSS supports only a CK_USER password,
         * CKU_SO is allowed only when no pin is set yet */
        match user_type {
            CKU_USER => (),
            CKU_SO => match self.fetch_password() {
                Ok(_) => return Err(CKR_USER_TYPE_INVALID)?,
                Err(e) => {
                    if e.rv() == CKR_USER_PIN_NOT_INITIALIZED {
                        return Ok(());
                    }
                    return Err(e);
                }
            },
            _ => return Err(CKR_USER_TYPE_INVALID)?,
        }

        /* The principal encryption key is derived via simple SHA1
         * from the pin and a salt stored on the password entry.
         * The data stored on the password entry is just a known
         * plaintext that can be obtained by deriving the encryption
         * key through pbkdf2 and then decrypting the entry according
         * to the chosen algorithm. The data is a structured ASN.1
         * structure that includes in formation about which algorithm
         * to use for the decryption.
         * NOTE: to allow key caching we set the key unchecked, and
         * then remove it on failure or if only a check was requested */
        let (salt, data) = self.fetch_password()?;
        let enckey = enckey_derive(facilities, pin, salt.as_slice())?;
        let originally_set = self.keys.available();
        if originally_set && self.keys.check_key(enckey.as_slice()) {
            return Ok(());
        }
        self.keys.set_key(enckey);
        let check = match decrypt_data(facilities, &self.keys, data.as_slice())
        {
            Ok(plain) => {
                if plain.as_slice() == NSS_PASS_CHECK {
                    Ok(())
                } else {
                    Err(CKR_PIN_INCORRECT)?
                }
            }
            Err(e) => Err(e),
        };
        if check.is_err() {
            /* unconditionally remove the key on failure */
            self.keys.unset_key();
            return check;
        }

        /* NSS does not support any error counter for authentication attempts */
        *flag = 0;

        if check_only && !originally_set {
            self.keys.unset_key();
        }
        Ok(())
    }

    fn unauth_user(&mut self, _user_type: CK_USER_TYPE) -> Result<()> {
        Ok(self.keys.unset_key())
    }

    fn set_user_pin(
        &mut self,
        facilities: &TokenFacilities,
        user_type: CK_USER_TYPE,
        pin: &[u8],
    ) -> Result<()> {
        if user_type != CKU_USER {
            return Err(CKR_USER_TYPE_INVALID)?;
        }

        if pin.len() > NSS_PIN_MAX {
            return Err(CKR_PIN_LEN_RANGE)?;
        }
        let mut salt: [u8; NSS_PIN_SALT_LEN] = [0u8; NSS_PIN_SALT_LEN];
        CSPRNG.with(|rng| rng.borrow_mut().generate_random(&mut salt))?;

        let enckey = enckey_derive(facilities, pin, &salt)?;
        let mut newkeys = KeysWithCaching::default();
        newkeys.set_key(enckey);

        let iterations = match pin.len() {
            0 => 1,
            _ => {
                /* FIXME: support env vars to change default */
                NSS_MP_PBE_ITERATION_COUNT
            }
        };
        let mut encdata =
            encrypt_data(facilities, &newkeys, iterations, NSS_PASS_CHECK)?;

        /* FIXME: need to re-encode all encrypted/integrity protected attributes */

        /* now that the pin has changed all cached keys are invalid, replace the lot */
        self.keys = newkeys;
        /* changing the pin does not leave the token logged in */
        self.keys.unset_key();

        let result = self.save_password(&salt, encdata.as_slice());
        zeromem(encdata.as_mut_slice());
        result
    }
}

#[derive(Debug)]
pub struct NSSDBInfo {
    db_type: &'static str,
}

impl StorageDBInfo for NSSDBInfo {
    fn new(&self, conf: &Option<String>) -> Result<Box<dyn Storage>> {
        let args = match conf {
            Some(a) => {
                if a.starts_with("nssdb:") {
                    a[6..].to_string()
                } else {
                    a.clone()
                }
            }
            None => return Err(CKR_ARGUMENTS_BAD)?,
        };

        let config = NSSConfig::from_args(&args)?;

        /* may have to create the token directory */
        let cdir = match config.configdir {
            Some(ref c) => c,
            None => return Err(CKR_TOKEN_NOT_RECOGNIZED)?,
        };
        if !Path::new(cdir).exists() {
            std::fs::create_dir_all(cdir)?;
        }

        /* NSS does not have generic storage, instead it uses different
         * databases for different object types, so we create an in memory
         * database to set all common options, and then we attach each
         * database file so we can operate on all of them with a single
         * connection. Note: in order to create the database we need to
         * have both the R/W and Create flags, the URIs generate will
         * properly mark the attached databases as read-only if needed */
        let flags = OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_CREATE
            | OpenFlags::SQLITE_OPEN_PRIVATE_CACHE
            | OpenFlags::SQLITE_OPEN_URI;
        let conn = Arc::new(Mutex::from(
            Connection::open_in_memory_with_flags(flags)?,
        ));

        Ok(Box::new(NSSStorage {
            config: config,
            conn: conn,
            keys: KeysWithCaching::default(),
        }))
    }

    fn dbtype(&self) -> &str {
        self.db_type
    }
}

pub static DBINFO: NSSDBInfo = NSSDBInfo { db_type: "nssdb" };
