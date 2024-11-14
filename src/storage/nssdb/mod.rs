// Copyright 2024 Simo Sorce
// See LICENSE.txt file for terms

use std::fmt::Write as _;
use std::path::Path;
use std::sync::{Arc, Mutex};

use crate::attribute::{AttrType, Attribute, CkAttrs};
use crate::error::{Error, Result};
use crate::interface::*;
use crate::misc::copy_sized_string;
use crate::object::Object;
use crate::storage;
use crate::storage::sqlite_common::check_table;
use crate::storage::{Storage, StorageDBInfo, StorageTokenInfo};
use crate::token::TokenFacilities;
use crate::CSPRNG;

use rusqlite::types::{FromSqlError, Value, ValueRef};
use rusqlite::{params, Connection, Rows, Transaction};
use zeroize::Zeroize;

mod attrs;
use attrs::*;
mod ci;
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
const NSS_PRIVATE_TABLE: &str = "nssPrivate";
const NSS_SPECIAL_NULL_VALUE: [u8; 3] = [0xa5, 0x0, 0x5a];

const NSS_ID_PREFIX: &str = "NSSID";

/* SFTK_MAX_PIN in NSS code */
const NSS_PIN_MAX: usize = 500;
/* SHA1_LENGTH in NSS code */
const NSS_PIN_SALT_LEN: usize = 20;

fn nss_id_format(table: &str, id: i32) -> String {
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

static NSS_PASS_CHECK: &[u8; 14] = b"password-check";

struct NSSSearchQuery {
    certs: Option<String>,
    keys: Option<String>,
    params: Vec<Value>,
}

#[derive(Debug)]
pub struct NSSStorage {
    config: NSSConfig,
    certs: Option<Arc<Mutex<Connection>>>,
    keys: Option<Arc<Mutex<Connection>>>,
    enckey: Option<Vec<u8>>,
}

impl Drop for NSSStorage {
    fn drop(&mut self) {
        if let Some(ref mut key) = &mut self.enckey {
            key.zeroize();
        }
    }
}

impl NSSStorage {
    fn is_initialized(
        &self,
        check: &Arc<Mutex<Connection>>,
        tablename: &str,
    ) -> Result<()> {
        let conn = check.lock()?;
        check_table(conn, tablename)
    }

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
            info.flags = CKF_LOGIN_REQUIRED;
        }
        Ok(info)
    }

    fn db_open(
        &self,
        path: &str,
        checktable: Option<&str>,
    ) -> Result<Arc<Mutex<Connection>>> {
        let exists = Path::new(path).exists();
        if self.config.read_only {
            /* have to check explicitly because ::open() creates a new
             * file if it does not exist */
            if !exists {
                return Err(CKR_TOKEN_NOT_PRESENT)?;
            }
        } else {
            /* may have to create the token directory */
            let cdir = match self.config.configdir {
                Some(ref c) => c,
                None => return Err(CKR_TOKEN_NOT_RECOGNIZED)?,
            };
            if !Path::new(cdir).exists() {
                std::fs::create_dir_all(cdir)?;
            }
        }
        match Connection::open(path) {
            Ok(c) => {
                let conn = Arc::new(Mutex::from(c));
                match checktable {
                    Some(ct) => self.is_initialized(&conn, ct)?,
                    None => (),
                }
                Ok(conn)
            }
            Err(_) => Err(CKR_TOKEN_NOT_PRESENT)?,
        }
    }

    fn new_main_tables(tx: &mut Transaction, table: &str) -> Result<()> {
        /* the drop can fail when files are empty (new) */
        let _ = tx.execute(&format!("DROP TABLE {}", table), params![]);

        /* prep the monster tables NSSDB uses */
        let mut columns = String::new();
        for c in NSS_KNOWN_ATTRIBUTES.iter() {
            write!(&mut columns, ", a{:x}", c)?;
        }

        /* main tables */
        let sql = format!(
            "CREATE TABLE {} (id PRIMARY KEY UNIQUE ON CONFLICT ABORT{})",
            table, &columns
        );
        tx.execute(&sql, params![])?;

        /* indexes */
        let sql = format!("CREATE INDEX issuer ON {} (a81)", table);
        tx.execute(&sql, params![])?;
        let sql = format!("CREATE INDEX subject ON {} (a101)", table);
        tx.execute(&sql, params![])?;
        let sql = format!("CREATE INDEX label ON {} (a3)", table);
        tx.execute(&sql, params![])?;
        let sql = format!("CREATE INDEX ckaid ON {} (a102)", table);
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
        /* we have to take one transaction at a time, which means one db
         * can remain messed up if there is a failure ... */

        /* public keys / certs db */
        if !self.config.no_cert_db {
            if self.certs.is_none() {
                self.certs = Some(self.db_open(&self.certsfile()?, None)?);
            }
            match &self.certs {
                Some(c) => {
                    let mut conn = c.lock()?;
                    let mut tx = conn.transaction()?;
                    tx.set_drop_behavior(rusqlite::DropBehavior::Rollback);
                    Self::new_main_tables(&mut tx, NSS_PUBLIC_TABLE)?;
                    tx.commit()?;
                }
                None => Err(CKR_GENERAL_ERROR)?,
            }
        }

        /* Keys DB */
        if !self.config.no_key_db {
            if self.keys.is_none() {
                self.keys = Some(self.db_open(&self.keysfile()?, None)?);
            }
            match &self.keys {
                Some(c) => {
                    let mut conn = c.lock()?;
                    let mut tx = conn.transaction()?;
                    tx.set_drop_behavior(rusqlite::DropBehavior::Rollback);
                    Self::new_main_tables(&mut tx, NSS_PRIVATE_TABLE)?;

                    /* the drop can fail when files are empty (new) */
                    let _ = tx.execute("DROP TABLE metaData", params![]);
                    /* metadata */
                    tx.execute("CREATE TABLE metaData (id PRIMARY KEY UNIQUE ON CONFLICT REPLACE, item1, item2)", params![])?;
                    tx.commit()?;
                }
                None => Err(CKR_GENERAL_ERROR)?,
            }
        }

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
        let mut columns: String;
        if attrs.len() == 0 {
            columns = "*".to_string();
        } else {
            columns = String::new();
            for i in 0..attrs.len() {
                if i == 0 {
                    write!(&mut columns, "a{:x}", attrs[0].type_)?;
                } else {
                    write!(&mut columns, ", a{:x}", attrs[i].type_)?;
                }
            }
        }
        let mut query = NSSSearchQuery {
            certs: None,
            keys: None,
            params: Vec::<Value>::with_capacity(1),
        };
        let sql = format!(
            "SELECT DISTINCT {} FROM {} WHERE id = ? LIMIT 1",
            columns, table
        );
        match table {
            NSS_PUBLIC_TABLE => query.certs = Some(sql),
            NSS_PRIVATE_TABLE => query.keys = Some(sql),
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
        let (conn, sql) = if let Some(ref sql) = query.certs {
            match self.certs {
                Some(ref conn) => (conn.lock()?, sql),
                None => return Err(CKR_GENERAL_ERROR)?,
            }
        } else if let Some(ref sql) = query.keys {
            match self.keys {
                Some(ref conn) => (conn.lock()?, sql),
                None => return Err(CKR_GENERAL_ERROR)?,
            }
        } else {
            return Err(CKR_GENERAL_ERROR)?;
        };
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
        let mut do_keys = true;
        let mut do_certs = true;
        let mut query = NSSSearchQuery {
            certs: None,
            keys: None,
            params: Vec::<Value>::with_capacity(template.len()),
        };

        /* find which tables we are going to use */
        for idx in 0..template.len() {
            if template[idx].type_ == CKA_CLASS {
                if template[idx].pValue != std::ptr::null_mut() {
                    let t = template[idx].to_ulong()?;
                    match t {
                        CKO_PRIVATE_KEY => do_certs = false,
                        CKO_PUBLIC_KEY | CKO_CERTIFICATE => do_keys = false,
                        _ => return Err(CKR_ATTRIBUTE_VALUE_INVALID)?,
                    }
                }
            }
            /* In NSSDB sensitive attributes are encrypted, so we can check
             * if the template is searching for any of the encrypted
             * attributes and if so just fail immediately */
            if is_sensitive_attribute(template[idx].type_) {
                return Err(CKR_ATTRIBUTE_SENSITIVE)?;
            }
        }

        /* if neither was excluded we may be asked for both */
        if do_keys {
            query.keys = Some(format!(
                "SELECT ALL id FROM {} WHERE ",
                NSS_PRIVATE_TABLE
            ));
        }
        if do_certs {
            query.certs =
                Some(format!("SELECT ALL id FROM {} WHERE ", NSS_PUBLIC_TABLE));
        }

        for idx in 0..template.len() {
            static CONCAT: &str = " AND";
            let atype = AttrType::attr_id_to_attrtype(template[idx].type_)?;
            let atval = u32::try_from(template[idx].type_)?;

            if let Some(ref mut keys) = query.keys {
                if idx != 0 {
                    keys.push_str(CONCAT);
                }
                write!(keys, " a{:x} = ?", atval)?;
            }

            if let Some(ref mut certs) = query.certs {
                if idx != 0 {
                    certs.push_str(CONCAT);
                }
                write!(certs, " a{:x} = ?", atval)?;
            }

            /* NSS Encodes explicitly empty attributes with a weird 3 bytes value,
             * so we have to account for that when searching */
            if template[idx].ulValueLen == 0 {
                let val: &[u8] = &NSS_SPECIAL_NULL_VALUE;
                query.params.push(ValueRef::from(val).into());
            } else {
                match atype {
                    AttrType::NumType => {
                        let val = template[idx].to_ulong()?;
                        query.params.push(Value::from(
                            u32::try_from(val)?.to_be_bytes().to_vec(),
                        ));
                    }
                    _ => {
                        query.params.push(Value::from(template[idx].to_buf()?))
                    }
                }
            }
        }
        Ok(query)
    }

    fn search_with_params(
        aconn: &Arc<Mutex<Connection>>,
        query: &str,
        params: Vec<Value>,
        table: &str,
    ) -> Result<Vec<String>> {
        let conn = aconn.lock()?;
        let mut stmt = conn.prepare(query)?;
        let mut rows = stmt.query(rusqlite::params_from_iter(params))?;
        let mut result = Vec::<String>::new();
        while let Some(row) = rows.next()? {
            let id: i32 = row.get(0)?;
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
        if let Some(ref sql) = query.certs {
            if let Some(ref conn) = self.certs {
                let mut certs = Self::search_with_params(
                    conn,
                    sql,
                    query.params.clone(),
                    NSS_PUBLIC_TABLE,
                )?;
                result.append(&mut certs);
            } else {
                return Err(CKR_GENERAL_ERROR)?;
            }
        }
        if let Some(ref sql) = query.keys {
            if let Some(ref conn) = self.keys {
                let mut keys = Self::search_with_params(
                    conn,
                    sql,
                    query.params,
                    NSS_PRIVATE_TABLE,
                )?;
                result.append(&mut keys);
            } else {
                return Err(CKR_GENERAL_ERROR)?;
            }
        }
        Ok(result)
    }

    fn fetch_metadata(&self, name: &str) -> Result<(Vec<u8>, Vec<u8>)> {
        static SQL: &str = "SELECT ALL item1, item2 FROM metaData WHERE id = ?";
        let conn = match self.keys {
            Some(ref conn) => conn.lock()?,
            None => return Err(CKR_GENERAL_ERROR)?,
        };
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
        &mut self,
        name: &str,
        item1: &[u8],
        item2: &[u8],
    ) -> Result<()> {
        static SQL: &str =
            "INSERT INTO metaData (id,item1,item2) VALUES(?,?,?);";
        let conn = match self.keys {
            Some(ref conn) => conn.lock()?,
            None => return Err(CKR_GENERAL_ERROR)?,
        };
        let mut stmt = conn.prepare(SQL)?;
        let _ = stmt.execute(params![
            Value::from(name.to_string()),
            Value::from(item1.to_vec()),
            Value::from(item2.to_vec()),
        ])?;
        Ok(())
    }

    fn save_password(&mut self, item1: &[u8], item2: &[u8]) -> Result<()> {
        self.save_metadata("password", item1, item2)
    }
}

impl Storage for NSSStorage {
    fn open(&mut self) -> Result<StorageTokenInfo> {
        /* NSS does not have generic storage, instead it uses different
         * databases for different object types */
        if !self.config.no_cert_db {
            self.certs =
                Some(self.db_open(&self.certsfile()?, Some(NSS_PUBLIC_TABLE))?);
        }
        if !self.config.no_key_db {
            self.keys =
                Some(self.db_open(&self.keysfile()?, Some(NSS_PRIVATE_TABLE))?);
        }
        self.get_token_info()
    }

    fn reinit(
        &mut self,
        _facilities: &TokenFacilities,
    ) -> Result<StorageTokenInfo> {
        self.initialize()?;
        self.enckey = None;
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
        }
        let mut obj =
            self.fetch_by_nssid(&table, nssobjid, attrs.as_slice())?;
        let ats = facilities.factories.get_sensitive_attrs(&obj)?;
        if let Some(ref enckey) = self.enckey {
            for typ in ats {
                let encval = match obj.get_attr(typ) {
                    Some(attr) => attr.get_value(),
                    None => continue,
                };
                let plain =
                    decrypt_data(facilities, enckey.as_slice(), encval)?;
                obj.set_attr(Attribute::from_bytes(typ, plain))?;
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
                    enckey.as_slice(),
                    value.as_slice(),
                    signature.as_slice(),
                    nssobjid,
                    sdbtype,
                )?;
            }
        }

        obj.set_handle(handle);
        Ok(obj)
    }

    fn store(
        &mut self,
        _faclities: &mut TokenFacilities,
        _obj: Object,
    ) -> Result<CK_OBJECT_HANDLE> {
        Err(CKR_FUNCTION_NOT_SUPPORTED)?
    }

    fn update(
        &mut self,
        _facilities: &TokenFacilities,
        _handle: CK_OBJECT_HANDLE,
        _template: &[CK_ATTRIBUTE],
    ) -> Result<()> {
        Err(CKR_FUNCTION_NOT_SUPPORTED)?
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
         * to use for the decryption. */
        let (salt, data) = self.fetch_password()?;
        let mut enckey = enckey_derive(facilities, pin, salt.as_slice())?;
        let plain =
            decrypt_data(facilities, enckey.as_slice(), data.as_slice())?;
        if plain.as_slice() != NSS_PASS_CHECK {
            return Err(CKR_PIN_INCORRECT)?;
        }

        /* NSS does not support any error counter for authentication attempts */
        *flag = 0;

        if !check_only {
            self.enckey = Some(enckey);
        } else {
            enckey.zeroize();
        }
        Ok(())
    }

    fn unauth_user(&mut self, _user_type: CK_USER_TYPE) -> Result<()> {
        self.enckey = None;
        Ok(())
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

        let newenckey = enckey_derive(facilities, pin, &salt)?;

        let iterations = match pin.len() {
            0 => 1,
            _ => {
                /* FIXME: support env vars to change default */
                NSS_MP_PBE_ITERATION_COUNT
            }
        };
        let mut encdata = encrypt_data(
            facilities,
            newenckey.as_slice(),
            &salt,
            iterations,
            NSS_PASS_CHECK,
        )?;

        /* FIXME: need to re-encode all encrypted/integrity protected attributes */

        let result = self.save_password(&salt, encdata.as_slice());
        encdata.zeroize();
        result
    }
}

#[derive(Debug)]
pub struct NSSDBInfo {
    db_type: &'static str,
    db_suffix: &'static str,
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
        Ok(Box::new(NSSStorage {
            config: NSSConfig::from_args(&args)?,
            certs: None,
            keys: None,
            enckey: None,
        }))
    }

    fn dbtype(&self) -> &str {
        self.db_type
    }

    fn dbsuffix(&self) -> &str {
        self.db_suffix
    }
}

pub static DBINFO: NSSDBInfo = NSSDBInfo {
    db_type: "nssdb",
    db_suffix: "",
};
