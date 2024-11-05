// Copyright 2024 Simo Sorce
// See LICENSE.txt file for terms

use std::fmt::Write as _;
use std::path::Path;
use std::sync::{Arc, Mutex};

use crate::attribute::{AttrType, Attribute, CkAttrs};
use crate::error::{Error, Result};
use crate::interface::*;
use crate::kasn1::oid::*;
use crate::kasn1::pkcs::*;
use crate::misc::copy_sized_string;
use crate::object::Object;
use crate::storage;
use crate::storage::sqlite_common::check_table;
use crate::storage::{Storage, StorageDBInfo, StorageTokenInfo};
use crate::token::TokenFacilities;
use crate::{byte_ptr, sizeof, void_ptr};

use rusqlite::types::{FromSqlError, Value, ValueRef};
use rusqlite::{Connection, Rows};
use zeroize::Zeroize;

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

#[derive(
    asn1::Asn1Read, asn1::Asn1Write, PartialEq, Hash, Clone, Eq, Debug,
)]
pub struct BrokenAlgorithmIdentifier<'a> {
    pub oid: asn1::DefinedByMarker<asn1::ObjectIdentifier>,
    #[defined_by(oid)]
    pub params: BrokenAlgorithmParameters<'a>,
}

#[derive(
    asn1::Asn1DefinedByRead,
    asn1::Asn1DefinedByWrite,
    PartialEq,
    Eq,
    Hash,
    Clone,
    Debug,
)]
pub enum BrokenAlgorithmParameters<'a> {
    #[defined_by(PBES2_OID)]
    Pbes2(BrokenPBES2Params<'a>),
    #[defined_by(PBMAC1_OID)]
    Pbmac1(PBMAC1Params<'a>),

    #[defined_by(AES_128_CBC_OID)]
    Aes128Cbc(&'a [u8]),
    #[defined_by(AES_256_CBC_OID)]
    Aes256Cbc(&'a [u8]),
    #[defined_by(HMAC_WITH_SHA256_OID)]
    HmacWithSha256(Option<asn1::Null>),
}

#[derive(
    asn1::Asn1Read, asn1::Asn1Write, PartialEq, Eq, Hash, Clone, Debug,
)]
pub struct BrokenPBES2Params<'a> {
    pub key_derivation_func: Box<AlgorithmIdentifier<'a>>,
    pub encryption_scheme: Box<BrokenAlgorithmIdentifier<'a>>,
}

#[derive(
    asn1::Asn1Read, asn1::Asn1Write, PartialEq, Eq, Hash, Clone, Debug,
)]
struct NSSEncryptedDataInfo<'a> {
    pub algorithm: Box<BrokenAlgorithmIdentifier<'a>>,
    pub enc_or_sig_data: &'a [u8],
}

fn pbkdf2_derive(
    facilities: &TokenFacilities,
    params: &PBKDF2Params,
    secret: &[u8],
    key_template: &[CK_ATTRIBUTE],
) -> Result<Object> {
    let mech = facilities.mechanisms.get(CKM_PKCS5_PBKD2)?;

    let ck_params = CK_PKCS5_PBKD2_PARAMS2 {
        saltSource: CKZ_SALT_SPECIFIED,
        pSaltSourceData: void_ptr!(params.salt.as_ptr()),
        ulSaltSourceDataLen: CK_ULONG::try_from(params.salt.len())?,
        iterations: CK_ULONG::try_from(params.iteration_count)?,
        prf: match params.prf.oid() {
            &HMAC_WITH_SHA1_OID => CKP_PKCS5_PBKD2_HMAC_SHA1,
            &HMAC_WITH_SHA256_OID => CKP_PKCS5_PBKD2_HMAC_SHA256,
            _ => return Err(CKR_MECHANISM_PARAM_INVALID)?,
        },
        pPrfData: std::ptr::null_mut(),
        ulPrfDataLen: 0,
        pPassword: byte_ptr!(secret.as_ptr()),
        ulPasswordLen: CK_ULONG::try_from(secret.len())?,
    };

    mech.generate_key(
        &CK_MECHANISM {
            mechanism: CKM_PKCS5_PBKD2,
            pParameter: void_ptr!(&ck_params),
            ulParameterLen: sizeof!(CK_PKCS5_PBKD2_PARAMS2),
        },
        key_template,
        &facilities.mechanisms,
        &facilities.factories,
    )
}

fn aes_cbc_decrypt(
    facilities: &TokenFacilities,
    key: &Object,
    iv: &[u8],
    data: &[u8],
) -> Result<Vec<u8>> {
    let mut adj_iv_vec: Vec<u8>;

    /* NSS has a Broken IV in the encoded data, so we need to adjust
     * the IV we get from the decoding and prepend it with 0x04 0x0E
     * which are thebytes that make a 16 bytes buffer "look like" a
     * DER encoded OCTET_STRING. */
    let adj_iv = match iv.len() {
        14 => {
            adj_iv_vec = Vec::with_capacity(16);
            adj_iv_vec.extend_from_slice(&[4, 14]);
            adj_iv_vec.extend_from_slice(iv);
            adj_iv_vec.as_slice()
        }
        16 => iv,
        _ => return Err(CKR_ARGUMENTS_BAD)?,
    };

    let ck_mech = CK_MECHANISM {
        mechanism: CKM_AES_CBC_PAD,
        pParameter: void_ptr!(adj_iv),
        ulParameterLen: CK_ULONG::try_from(adj_iv.len())?,
    };
    let mech = facilities.mechanisms.get(CKM_AES_CBC_PAD)?;
    let mut op = mech.decryption_new(&ck_mech, key)?;
    let mut plain = vec![0u8; op.decryption_len(data.len(), false)?];
    let len = op.decrypt(data, &mut plain)?;
    plain.resize(len, 0);
    Ok(plain)
}

pub fn decrypt_data(
    facilities: &TokenFacilities,
    secret: &[u8],
    data: &[u8],
) -> Result<Vec<u8>> {
    let info = match asn1::parse_single::<NSSEncryptedDataInfo>(data) {
        Ok(i) => i,
        Err(e) => {
            print!("{}", e);
            return Err(CKR_DATA_INVALID)?;
        }
    };

    let pbes2 = match &info.algorithm.params {
        BrokenAlgorithmParameters::Pbes2(ref params) => params,
        _ => return Err(CKR_MECHANISM_INVALID)?,
    };

    let key = match &pbes2.key_derivation_func.params {
        AlgorithmParameters::Pbkdf2(ref params) => {
            let ck_class: CK_OBJECT_CLASS = CKO_SECRET_KEY;
            let ck_key_type: CK_KEY_TYPE = CKK_AES;
            let ck_key_len: CK_ULONG = match params.key_length {
                Some(l) => CK_ULONG::try_from(l)?,
                None => return Err(CKR_MECHANISM_PARAM_INVALID)?,
            };
            let ck_true: CK_BBOOL = CK_TRUE;
            let mut key_template = CkAttrs::with_capacity(5);
            key_template.add_ulong(CKA_CLASS, &ck_class);
            key_template.add_ulong(CKA_KEY_TYPE, &ck_key_type);
            key_template.add_ulong(CKA_VALUE_LEN, &ck_key_len);
            key_template.add_bool(CKA_DECRYPT, &ck_true);
            key_template.add_bool(CKA_ENCRYPT, &ck_true);

            pbkdf2_derive(facilities, params, secret, key_template.as_slice())?
        }
        _ => return Err(CKR_MECHANISM_INVALID)?,
    };
    match &pbes2.encryption_scheme.params {
        BrokenAlgorithmParameters::Aes128Cbc(ref iv) => {
            aes_cbc_decrypt(facilities, &key, iv, info.enc_or_sig_data)
        }
        BrokenAlgorithmParameters::Aes256Cbc(ref iv) => {
            aes_cbc_decrypt(facilities, &key, iv, info.enc_or_sig_data)
        }
        _ => Err(CKR_MECHANISM_INVALID)?,
    }
}

/* NSS has a hardcoded list of attributes that are authenticated,
 * some are vendor defined attributes */
const AUTHENTICATED_ATTRIBUTES: [CK_ATTRIBUTE_TYPE; 2] = [
    CKA_MODULUS,
    CKA_PUBLIC_EXPONENT,
    //CKA_CERT_SHA1_HASH,
    //CKA_CERT_MD5_HASH,
    //CKA_TRUST_SERVER_AUTH,
    //CKA_TRUST_CLIENT_AUTH,
    //CKA_TRUST_EMAIL_PROTECTION,
    //CKA_TRUST_CODE_SIGNING,
    //CKA_TRUST_STEP_UP_APPROVED,
    //CKA_NSS_OVERRIDE_EXTENSIONS,
];

fn hmac_verify(
    facilities: &TokenFacilities,
    mechanism: CK_MECHANISM_TYPE,
    key: &Object,
    nssobjid: u32,
    sdbtype: u32,
    plaintext: &[u8],
    signature: &[u8],
) -> Result<()> {
    let siglen = CK_ULONG::try_from(signature.len())?;
    let ck_mech = CK_MECHANISM {
        mechanism: mechanism,
        pParameter: void_ptr!(&siglen),
        ulParameterLen: sizeof!(CK_ULONG),
    };
    let mech = facilities.mechanisms.get(mechanism)?;
    let mut op = mech.verify_new(&ck_mech, key)?;
    let objid = nssobjid.to_be_bytes();
    op.verify_update(&objid)?;
    let attrtype = sdbtype.to_be_bytes();
    op.verify_update(&attrtype)?;
    op.verify_update(plaintext)?;
    op.verify_final(signature)
}

fn check_signature(
    facilities: &TokenFacilities,
    secret: &[u8],
    attribute: &[u8],
    signature: &[u8],
    nssobjid: u32,
    sdbtype: u32,
) -> Result<()> {
    let info = match asn1::parse_single::<NSSEncryptedDataInfo>(signature) {
        Ok(i) => i,
        Err(e) => {
            print!("{}", e);
            return Err(CKR_DATA_INVALID)?;
        }
    };

    let pbmac1 = match &info.algorithm.params {
        BrokenAlgorithmParameters::Pbmac1(ref params) => params,
        _ => return Err(CKR_MECHANISM_INVALID)?,
    };

    let key = match &pbmac1.key_derivation_func.params {
        AlgorithmParameters::Pbkdf2(ref params) => {
            let ck_class: CK_OBJECT_CLASS = CKO_SECRET_KEY;
            let ck_key_type: CK_KEY_TYPE = CKK_GENERIC_SECRET;
            let ck_key_len: CK_ULONG = match params.key_length {
                Some(l) => CK_ULONG::try_from(l)?,
                None => return Err(CKR_MECHANISM_PARAM_INVALID)?,
            };
            let ck_true: CK_BBOOL = CK_TRUE;
            let mut key_template = CkAttrs::with_capacity(5);
            key_template.add_ulong(CKA_CLASS, &ck_class);
            key_template.add_ulong(CKA_KEY_TYPE, &ck_key_type);
            key_template.add_ulong(CKA_VALUE_LEN, &ck_key_len);
            key_template.add_bool(CKA_SIGN, &ck_true);
            key_template.add_bool(CKA_VERIFY, &ck_true);

            pbkdf2_derive(facilities, params, secret, key_template.as_slice())?
        }
        _ => return Err(CKR_MECHANISM_INVALID)?,
    };

    match &pbmac1.message_auth_scheme.params {
        AlgorithmParameters::HmacWithSha256(None) => hmac_verify(
            facilities,
            CKM_SHA256_HMAC_GENERAL,
            &key,
            nssobjid,
            sdbtype,
            attribute,
            info.enc_or_sig_data,
        ),
        _ => Err(CKR_MECHANISM_INVALID)?,
    }
}

fn enckey_derive(
    facilities: &TokenFacilities,
    pin: &[u8],
    salt: &[u8],
) -> Result<Vec<u8>> {
    let mech = facilities.mechanisms.get(CKM_SHA_1)?;
    let mut op = mech.digest_new(&CK_MECHANISM {
        mechanism: CKM_SHA_1,
        pParameter: std::ptr::null_mut(),
        ulParameterLen: 0,
    })?;
    op.digest_update(salt)?;
    op.digest_update(pin)?;
    let mut digest = vec![0u8; op.digest_len()?];
    op.digest_final(digest.as_mut_slice())?;
    Ok(digest)
}

/* Mostly documented at:
 * https://nss-crypto.org/reference/security/nss/legacy/pkcs11/module_specs/index.html
 */
#[derive(Debug)]
struct NSSConfig {
    configdir: Option<String>,
    updatedir: Option<String>,
    updateid: Option<String>,
    secmod: String,
    manufacturer: Option<String>,
    library_description: Option<String>,
    cert_prefix: String,
    key_prefix: String,
    token_crypto_description: Option<String>,
    token_db_description: Option<String>,
    token_fips_description: Option<String>,
    slot_crypto_description: Option<String>,
    slot_db_description: Option<String>,
    slot_fips_description: Option<String>,
    update_description: Option<String>,
    min_pin_len: usize,
    read_only: bool,
    no_mod_db: bool,
    no_cert_db: bool,
    no_key_db: bool,
    force_open: bool,
    password_required: bool,
    optimize_space: bool,
    /* tokens: currently unsupported */
}

impl Default for NSSConfig {
    fn default() -> Self {
        NSSConfig {
            configdir: None,
            updatedir: None,
            updateid: None,
            secmod: String::from("secmod.db"),
            manufacturer: None,
            library_description: None,
            cert_prefix: String::from(""),
            key_prefix: String::from(""),
            token_crypto_description: None,
            token_db_description: None,
            token_fips_description: None,
            slot_crypto_description: None,
            slot_db_description: None,
            slot_fips_description: None,
            update_description: None,
            min_pin_len: 0,
            read_only: false,
            no_mod_db: false,
            no_cert_db: false,
            no_key_db: false,
            force_open: false,
            password_required: false,
            optimize_space: false,
        }
    }
}

impl NSSConfig {
    fn parse_flags(&mut self, args: &[u8]) -> Result<()> {
        let mut idx = 0;
        while idx < args.len() {
            let next = match args[idx..].iter().position(|&x| x == ',' as u8) {
                Some(n) => n,
                None => args.len(),
            };
            let flag = String::from_utf8_lossy(&args[idx..next]).to_lowercase();
            match flag.as_str() {
                "readonly" => self.read_only = true,
                "nomoddb" => self.no_mod_db = true,
                "nocertdb" => self.no_cert_db = true,
                "nokeydb" => self.no_key_db = true,
                "forceopen" => self.force_open = true,
                "passwordrequired" => self.password_required = true,
                "optimizespace" => self.optimize_space = true,
                _ => return Err(CKR_ARGUMENTS_BAD)?,
            }
            idx = next + 1;
        }
        Ok(())
    }

    fn parse_parameter(&mut self, args: &[u8]) -> Result<usize> {
        let name: String;
        let value: String;

        /* find param name */
        let mut idx = match args.iter().position(|&x| x == '=' as u8) {
            Some(x) => x,
            None => Err(CKR_ARGUMENTS_BAD)?,
        };

        if args.len() <= idx + 2 {
            return Err(CKR_ARGUMENTS_BAD)?;
        }

        name = String::from_utf8_lossy(&args[0..idx]).to_lowercase();

        let find = match char::from(args[idx + 1]) {
            '\'' => b'\'',
            '\"' => b'\"',
            '(' => b')',
            '{' => b'}',
            '[' => b']',
            '<' => b'>',
            _ => b' ',
        };
        let valx = if find != b' ' { idx + 2 } else { idx + 1 };
        idx = valx;

        while idx < args.len() {
            if let Some(pos) = args[idx..].iter().position(|&x| x == find) {
                idx = pos;

                /* backtrack check for escapes */
                let mut esc = 0;
                while esc < pos {
                    if args[pos - 1 - esc] == '\\' as u8 {
                        esc += 1;
                    } else {
                        break;
                    }
                }
                if esc % 2 == 1 {
                    idx += 1;
                    /* escaped */
                    continue;
                }
                break;
            } else {
                idx = args.len();
            }
        }
        if idx >= args.len() {
            /* This may be the last parameter, in which case it is ok
             * if not trailing space is present otherwise error out */
            if idx == args.len() && find != ' ' as u8 {
                return Err(CKR_ARGUMENTS_BAD)?;
            }
        }

        value = String::from_utf8_lossy(&args[valx..idx]).to_string();

        if idx < args.len() {
            idx += 1;
        }

        match name.as_str() {
            "configdir" => self.configdir = Some(value),
            "updatedir" => self.updatedir = Some(value),
            "updateid" => self.updateid = Some(value),
            "secmod" => self.secmod = value,
            "manufacturerid" => self.manufacturer = Some(value),
            "librarydescription" => self.library_description = Some(value),
            "certprefix" => self.cert_prefix = value,
            "keyprefix" => self.key_prefix = value,
            "cryptotokendescription" => {
                self.token_crypto_description = Some(value)
            }
            "dbtokendescription" => self.token_db_description = Some(value),
            "fipstokendescription" => self.token_fips_description = Some(value),
            "cryptoslotdescription" => {
                self.slot_crypto_description = Some(value)
            }
            "dbslotdescription" => self.slot_db_description = Some(value),
            "fipsslotdescription" => self.slot_fips_description = Some(value),
            "updatetokendescription" => self.update_description = Some(value),
            "minpwlen" => self.min_pin_len = value.parse::<usize>()?,
            "flags" => self.parse_flags(value.as_bytes())?,
            _ => return Err(CKR_ARGUMENTS_BAD)?,
        }

        Ok(idx)
    }

    /* parse nss configuration string */
    fn from_args(args: &str) -> Result<NSSConfig> {
        let mut config: NSSConfig = Default::default();

        let bargs = args.as_bytes();
        let mut idx = 0usize;

        while idx < bargs.len() {
            idx = config.parse_parameter(&bargs[idx..])?;
        }
        Ok(config)
    }

    #[cfg(feature = "fips")]
    fn get_token_label_as_bytes(&self) -> &[u8] {
        match self.token_fips_description {
            Some(ref s) => s.as_bytes(),
            None => storage::TOKEN_LABEL.as_bytes(),
        }
    }
    #[cfg(not(feature = "fips"))]
    fn get_token_label_as_bytes(&self) -> &[u8] {
        match self.token_db_description {
            Some(ref s) => s.as_bytes(),
            None => storage::TOKEN_LABEL.as_bytes(),
        }
    }
}

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
        ro: bool,
        checktable: &str,
    ) -> Result<Arc<Mutex<Connection>>> {
        if ro {
            /* have to check explicitly because ::open() creates a new
             * file if it does not exist */
            if !Path::new(path).exists() {
                return Err(CKR_TOKEN_NOT_PRESENT)?;
            }
        }
        match Connection::open(path) {
            Ok(c) => {
                let conn = Arc::new(Mutex::from(c));
                self.is_initialized(&conn, checktable)?;
                Ok(conn)
            }
            Err(_) => Err(CKR_TOKEN_NOT_PRESENT)?,
        }
    }

    fn rows_to_object(mut rows: Rows, all_cols: bool) -> Result<Object> {
        let mut obj = Object::new();

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
                let bn: Option<&[u8]> = row.get_ref(i)?.as_blob_or_null()?;
                let blob: &[u8] = match bn {
                    Some(ref b) => b,
                    None => continue,
                };
                let atype = match AttrType::attr_id_to_attrtype(cols[i]) {
                    Ok(a) => a,
                    Err(e) => {
                        if cols[i] > CKA_VENDOR_DEFINED {
                            /* FIXME: handle NSS vendor attributes */
                            continue;
                        } else {
                            return Err(e);
                        }
                    }
                };
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
                    break;
                }
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
        let mut rows = stmt.query(rusqlite::params![name])?;
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
}

impl Storage for NSSStorage {
    fn open(&mut self) -> Result<StorageTokenInfo> {
        /* NSS does not have generic storage, instead it uses different
         * databases for different object types */
        let cdir = match self.config.configdir {
            Some(ref c) => c,
            None => return Err(CKR_TOKEN_NOT_RECOGNIZED)?,
        };
        let certsfile = format!(
            "{}/{}cert{}.db",
            cdir, self.config.cert_prefix, CERT_DB_VERSION
        );
        let keysfile = format!(
            "{}/{}key{}.db",
            cdir, self.config.key_prefix, KEY_DB_VERSION
        );
        if !self.config.no_cert_db {
            self.certs = Some(self.db_open(
                &certsfile,
                self.config.read_only,
                NSS_PUBLIC_TABLE,
            )?);
        }
        if !self.config.no_key_db {
            self.keys = Some(self.db_open(
                &keysfile,
                self.config.read_only,
                NSS_PRIVATE_TABLE,
            )?);
        }
        self.get_token_info()
    }

    fn reinit(
        &mut self,
        _facilities: &TokenFacilities,
    ) -> Result<StorageTokenInfo> {
        Err(CKR_FUNCTION_NOT_SUPPORTED)?
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

    fn search(
        &self,
        facilities: &mut TokenFacilities,
        template: &[CK_ATTRIBUTE],
    ) -> Result<Vec<CK_OBJECT_HANDLE>> {
        let mut ids = self.search_databases(template)?;
        let mut result = Vec::<CK_OBJECT_HANDLE>::with_capacity(ids.len());
        for id in ids.drain(..) {
            /* FIXME: check for sensitive ! */
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
        Err(CKR_FUNCTION_NOT_SUPPORTED)?
    }

    fn auth_user(
        &mut self,
        facilities: &TokenFacilities,
        user_type: CK_USER_TYPE,
        pin: &[u8],
        flag: &mut CK_FLAGS,
        check_only: bool,
    ) -> Result<()> {
        /* NSS supports only a CK_USER password, no CKU_SO */
        if user_type != CKU_USER {
            return Err(CKR_USER_TYPE_INVALID)?;
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
        _facilities: &TokenFacilities,
        _user_type: CK_USER_TYPE,
        _pin: &[u8],
    ) -> Result<()> {
        Err(CKR_FUNCTION_NOT_SUPPORTED)?
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
