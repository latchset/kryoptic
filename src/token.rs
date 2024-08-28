// Copyright 2023 Simo Sorce
// See LICENSE.txt file for terms

use std::borrow::Cow;
use std::collections::HashMap;
use std::vec::Vec;

use super::aes;
use super::attribute;
use super::ecc;
#[cfg(not(feature = "fips"))]
use super::eddsa;
use super::error;
use super::hash;
use super::hkdf;
use super::hmac;
use super::interface;
use super::mechanism;
use super::object;
use super::pbkdf2;
use super::rsa;
use super::sp800_108;
use super::sshkdf;
use super::storage;
use super::tlskdf;

use super::{err_rv, get_random_data, sizeof, to_rv};
use error::Result;
use interface::*;
use mechanism::Mechanisms;
use object::{Object, ObjectFactories};
use storage::Storage;

use hex;

#[cfg(feature = "fips")]
use super::fips;

#[cfg(feature = "fips")]
const TOKEN_LABEL: &str = "Kryoptic FIPS Token";
#[cfg(not(feature = "fips"))]
const TOKEN_LABEL: &str = "Kryoptic Soft Token";

const MANUFACTURER_ID: &str = "Kryoptic Project";

#[cfg(feature = "fips")]
const TOKEN_MODEL: &str = "FIPS-140-3 v1";
#[cfg(not(feature = "fips"))]
const TOKEN_MODEL: &str = "v1";

const SO_PIN_UID: &str = "0";
const USER_PIN_UID: &str = "1";
const TOKEN_INFO_UID: &str = "2";

const MAX_LOGIN_ATTEMPTS: CK_ULONG = 10;

const USER_PIN_IV: &str = "USRPIN IV UNWRAP";
const USER_PIN_AAD: &str = "USRPIN AUTH_DATA";
const DEFPIN_SALT: &str = "DEFAULT SALT DATA"; /* at least 16 bytes for FIPS */
#[cfg(test)]
const DEFPIN_ITER: usize = 1000;
#[cfg(not(test))]
const DEFPIN_ITER: usize = 10000;
const DEFAULT_IV_SIZE: usize = 12; /* 96 bits as required by FIPS for AES GCM */

#[cfg(feature = "fips")]
fn default_password() -> Vec<u8> {
    const DEFPIN_PASS: &str = "DEFAULT PASSWORD";
    DEFPIN_PASS.as_bytes().to_vec()
}
#[cfg(not(feature = "fips"))]
fn default_password() -> Vec<u8> {
    vec![0u8; 0]
}

fn copy_sized_string(s: &[u8], d: &mut [u8]) {
    let mut slen = s.len();
    match s.last() {
        None => return,
        Some(c) => {
            if *c == b'\0' {
                slen -= 1;
            }
        }
    }
    if slen >= d.len() {
        d.copy_from_slice(&s[..d.len()]);
    } else {
        d[..slen].copy_from_slice(&s[..slen]);
        d[slen..].fill(0x20); /* space in ASCII/UTF8 */
    }
}

#[derive(Debug, Clone)]
pub struct Handles {
    map: HashMap<CK_OBJECT_HANDLE, String>,
    rev: HashMap<String, CK_OBJECT_HANDLE>,
    next: CK_OBJECT_HANDLE,
}

impl Handles {
    pub fn new() -> Handles {
        Handles {
            map: HashMap::new(),
            rev: HashMap::new(),
            next: 1,
        }
    }

    pub fn insert(&mut self, handle: CK_OBJECT_HANDLE, value: String) {
        if let Some(val) = self.rev.insert(value.clone(), handle) {
            /* this uid was already mapped */
            if val != handle {
                let _ = self.map.remove(&val);
            }
        }
        if let Some(uid) = self.map.insert(handle, value) {
            /* this handle was already mapped */
            if &uid != self.map.get(&handle).unwrap() {
                let _ = self.rev.remove(&uid);
            }
        }
    }

    pub fn get(&self, handle: CK_OBJECT_HANDLE) -> Option<&String> {
        self.map.get(&handle)
    }

    pub fn get_by_uid(&self, uid: &String) -> Option<&CK_OBJECT_HANDLE> {
        self.rev.get(uid)
    }

    pub fn remove(&mut self, handle: CK_OBJECT_HANDLE) {
        if let Some(uid) = self.map.remove(&handle) {
            let _ = self.rev.remove(&uid);
        }
    }

    fn next(&mut self) -> CK_OBJECT_HANDLE {
        let next = self.next;
        self.next += 1;
        next
    }
}

#[derive(Debug)]
pub struct Token {
    info: CK_TOKEN_INFO,
    filename: String,
    object_factories: ObjectFactories,
    mechanisms: Mechanisms,
    storage: Box<dyn Storage>,
    session_objects: HashMap<CK_OBJECT_HANDLE, Object>,
    handles: Handles,
    kek: Option<Object>,
    so_logged_in: bool,
}

impl Token {
    pub fn new(filename: String) -> Result<Token> {
        /* when no filename is provided we assume a memory only
         * token that has no backing store */
        let store = if filename.ends_with(".json") {
            storage::json::json()
        } else if filename.ends_with(".sql") {
            storage::sqlite::sqlite()
        } else {
            storage::memory::memory()
        };

        let mut token: Token = Token {
            info: CK_TOKEN_INFO {
                label: [0u8; 32],
                manufacturerID: [0u8; 32],
                model: [0u8; 16],
                serialNumber: [0u8; 16],
                flags: CKF_RNG | CKF_LOGIN_REQUIRED,
                ulMaxSessionCount: CK_EFFECTIVELY_INFINITE,
                ulSessionCount: 0,
                ulMaxRwSessionCount: CK_EFFECTIVELY_INFINITE,
                ulRwSessionCount: 0,
                ulMaxPinLen: CK_EFFECTIVELY_INFINITE,
                ulMinPinLen: 8,
                ulTotalPublicMemory: 0,
                ulFreePublicMemory: CK_EFFECTIVELY_INFINITE,
                ulTotalPrivateMemory: 0,
                ulFreePrivateMemory: CK_EFFECTIVELY_INFINITE,
                hardwareVersion: CK_VERSION { major: 0, minor: 0 },
                firmwareVersion: CK_VERSION { major: 0, minor: 0 },
                utcTime: *b"0000000000000000",
            },
            filename: filename,
            object_factories: ObjectFactories::new(),
            mechanisms: Mechanisms::new(),
            storage: store,
            session_objects: HashMap::new(),
            handles: Handles::new(),
            kek: None,
            so_logged_in: false,
        };

        /* default strings */
        copy_sized_string(TOKEN_LABEL.as_bytes(), &mut token.info.label);
        copy_sized_string(
            MANUFACTURER_ID.as_bytes(),
            &mut token.info.manufacturerID,
        );
        copy_sized_string(TOKEN_MODEL.as_bytes(), &mut token.info.model);

        /* register mechanisms and factories */
        object::register(&mut token.mechanisms, &mut token.object_factories);
        aes::register(&mut token.mechanisms, &mut token.object_factories);
        rsa::register(&mut token.mechanisms, &mut token.object_factories);
        ecc::register(&mut token.mechanisms, &mut token.object_factories);
        #[cfg(not(feature = "fips"))]
        eddsa::register(&mut token.mechanisms, &mut token.object_factories);
        hash::register(&mut token.mechanisms, &mut token.object_factories);
        hmac::register(&mut token.mechanisms, &mut token.object_factories);
        hkdf::register(&mut token.mechanisms, &mut token.object_factories);
        pbkdf2::register(&mut token.mechanisms, &mut token.object_factories);
        sp800_108::register(&mut token.mechanisms, &mut token.object_factories);
        sshkdf::register(&mut token.mechanisms, &mut token.object_factories);
        tlskdf::register(&mut token.mechanisms, &mut token.object_factories);

        #[cfg(feature = "fips")]
        fips::register(&mut token.mechanisms, &mut token.object_factories);

        if token.filename.len() > 0 {
            match token.storage.open(&token.filename) {
                Ok(()) => {
                    token.load_token_info()?;
                    token.info.flags |= CKF_TOKEN_INITIALIZED;
                    #[cfg(not(test))]
                    {
                        token.info.flags &= !CKF_RESTORE_KEY_NOT_NEEDED;
                    }
                }
                Err(err) => match err.rv() {
                    CKR_CRYPTOKI_NOT_INITIALIZED => {
                        token.info.flags &= !CKF_TOKEN_INITIALIZED
                    }
                    _ => return Err(err),
                },
            }
        } else {
            token.info.flags &= !CKF_LOGIN_REQUIRED;
            token.info.flags |= CKF_TOKEN_INITIALIZED;
            token.info.flags |= CKF_RESTORE_KEY_NOT_NEEDED;
        }

        if token.info.flags & CKF_TOKEN_INITIALIZED != 0 {
            token.init_pin_flags()?;
        }

        #[cfg(feature = "fips")]
        fips::token_init(&mut token)?;

        Ok(token)
    }

    #[cfg(test)]
    pub fn use_encryption(&mut self, enc: bool) {
        if enc {
            self.info.flags |= CKF_RESTORE_KEY_NOT_NEEDED;
        } else {
            self.info.flags &= !CKF_RESTORE_KEY_NOT_NEEDED;
        }
    }

    pub fn get_filename(&self) -> &String {
        &self.filename
    }

    pub fn is_initialized(&self) -> bool {
        self.info.flags & CKF_TOKEN_INITIALIZED == CKF_TOKEN_INITIALIZED
    }

    fn is_login_required(&self) -> bool {
        self.info.flags & CKF_LOGIN_REQUIRED == CKF_LOGIN_REQUIRED
    }

    fn load_token_info(&mut self) -> Result<()> {
        let uid = TOKEN_INFO_UID.to_string();
        let obj = match self.storage.fetch_by_uid(&uid) {
            Ok(o) => o,
            Err(e) => {
                if e.attr_not_found() {
                    /* it is ok if no token data is stored yet,
                     * we'll use defaults */
                    return Ok(());
                } else {
                    return Err(e);
                }
            }
        };
        if obj.get_attr_as_ulong(CKA_CLASS)? != KRO_TOKEN_DATA {
            return err_rv!(CKR_TOKEN_NOT_RECOGNIZED);
        }
        let label = obj
            .get_attr_as_string(CKA_LABEL)
            .map_err(|_| to_rv!(CKR_TOKEN_NOT_RECOGNIZED))?;
        copy_sized_string(label.as_bytes(), &mut self.info.label);
        let issuer = obj
            .get_attr_as_string(KRA_MANUFACTURER_ID)
            .map_err(|_| to_rv!(CKR_TOKEN_NOT_RECOGNIZED))?;
        copy_sized_string(issuer.as_bytes(), &mut self.info.manufacturerID);
        let model = obj
            .get_attr_as_string(KRA_MODEL)
            .map_err(|_| to_rv!(CKR_TOKEN_NOT_RECOGNIZED))?;
        copy_sized_string(model.as_bytes(), &mut self.info.model);
        let serial = obj
            .get_attr_as_string(KRA_SERIAL_NUMBER)
            .map_err(|_| to_rv!(CKR_TOKEN_NOT_RECOGNIZED))?;
        copy_sized_string(serial.as_bytes(), &mut self.info.serialNumber);
        self.info.flags = obj
            .get_attr_as_ulong(KRA_FLAGS)
            .map_err(|_| to_rv!(CKR_TOKEN_NOT_RECOGNIZED))?;

        Ok(())
    }

    fn store_token_info(&mut self) -> Result<()> {
        let uid = TOKEN_INFO_UID.to_string();
        let mut obj = match self.storage.fetch_by_uid(&uid) {
            Ok(o) => o.clone(),
            Err(_) => {
                let mut o = Object::new();
                o.set_attr(attribute::from_string(CKA_UNIQUE_ID, uid.clone()))?;
                o.set_attr(attribute::from_bool(CKA_TOKEN, true))?;
                o.set_attr(attribute::from_ulong(CKA_CLASS, KRO_TOKEN_DATA))?;
                o
            }
        };
        obj.set_attr(attribute::string_from_sized(
            CKA_LABEL,
            &self.info.label,
        ))?;
        obj.set_attr(attribute::string_from_sized(
            KRA_MANUFACTURER_ID,
            &self.info.manufacturerID,
        ))?;
        obj.set_attr(attribute::string_from_sized(
            KRA_MODEL,
            &self.info.model,
        ))?;
        obj.set_attr(attribute::string_from_sized(
            KRA_SERIAL_NUMBER,
            &self.info.serialNumber,
        ))?;
        obj.set_attr(attribute::from_ulong(KRA_FLAGS, self.info.flags))?;

        self.storage.store(&uid, obj)?;
        return Ok(());
    }

    fn fetch_pin_object(&mut self, uid: &str) -> Result<Object> {
        let obj = match self.storage.fetch_by_uid(&uid.to_string()) {
            Ok(o) => o,
            Err(e) => {
                if e.attr_not_found() {
                    return err_rv!(CKR_USER_PIN_NOT_INITIALIZED);
                } else {
                    return Err(e);
                }
            }
        };
        if obj.get_attr_as_ulong(CKA_CLASS)? != CKO_SECRET_KEY {
            return err_rv!(CKR_GENERAL_ERROR);
        }
        if obj.get_attr_as_ulong(CKA_KEY_TYPE)? != CKK_GENERIC_SECRET {
            return err_rv!(CKR_GENERAL_ERROR);
        }
        Ok(obj)
    }

    fn store_pin_object(
        &mut self,
        uid: String,
        label: String,
        wrapped: Vec<u8>,
    ) -> Result<()> {
        match self.storage.fetch_by_uid(&uid) {
            Ok(o) => {
                let mut obj = o.clone();
                obj.set_attr(attribute::from_string(CKA_LABEL, label))?;
                obj.set_attr(attribute::from_bytes(CKA_VALUE, wrapped))?;
                obj.set_attr(attribute::from_ulong(KRA_LOGIN_ATTEMPTS, 0))?;
                self.storage.store(&uid, obj)?;
            }
            Err(_) => {
                let mut obj = Object::new();
                obj.set_attr(attribute::from_string(
                    CKA_UNIQUE_ID,
                    uid.clone(),
                ))?;
                obj.set_attr(attribute::from_bool(CKA_TOKEN, true))?;
                obj.set_attr(attribute::from_ulong(CKA_CLASS, CKO_SECRET_KEY))?;
                obj.set_attr(attribute::from_ulong(
                    CKA_KEY_TYPE,
                    CKK_GENERIC_SECRET,
                ))?;
                obj.set_attr(attribute::from_string(CKA_LABEL, label))?;
                obj.set_attr(attribute::from_bytes(CKA_VALUE, wrapped))?;
                obj.set_attr(attribute::from_ulong(
                    KRA_MAX_LOGIN_ATTEMPTS,
                    MAX_LOGIN_ATTEMPTS,
                ))?;
                obj.set_attr(attribute::from_ulong(KRA_LOGIN_ATTEMPTS, 0))?;

                self.storage.store(&uid, obj)?;
            }
        }
        return Ok(());
    }

    fn parse_pin_label(&self, label: &str) -> Result<(String, usize)> {
        let parts: Vec<_> = label.split(":").collect();
        if parts.len() != 2 {
            return err_rv!(CKR_GENERAL_ERROR);
        }
        Ok((
            parts[0].to_string(),
            match parts[1].parse() {
                Ok(u) => u,
                Err(_) => return err_rv!(CKR_GENERAL_ERROR),
            },
        ))
    }

    fn pin_to_key(
        &mut self,
        pin: &Vec<u8>,
        salt: &str,
        iterations: usize,
    ) -> Result<Object> {
        let params = CK_PKCS5_PBKD2_PARAMS2 {
            saltSource: CKZ_DATA_SPECIFIED,
            pSaltSourceData: salt.as_ptr() as *const _ as *mut _,
            ulSaltSourceDataLen: salt.len() as CK_ULONG,
            iterations: iterations as CK_ULONG,
            prf: CKP_PKCS5_PBKD2_HMAC_SHA512,
            pPrfData: std::ptr::null_mut(),
            ulPrfDataLen: 0,
            pPassword: pin.as_ptr() as *const _ as *mut _,
            ulPasswordLen: pin.len() as CK_ULONG,
        };
        let class = CKO_SECRET_KEY;
        let keytyp = CKK_AES;
        let keylen = aes::MAX_AES_SIZE_BYTES as CK_ULONG;
        let truebool: CK_BBOOL = CK_TRUE;
        let mut template = attribute::CkAttrs::with_capacity(5);
        template.add_ulong(CKA_CLASS, &class);
        template.add_ulong(CKA_KEY_TYPE, &keytyp);
        template.add_ulong(CKA_VALUE_LEN, &keylen);
        template.add_bool(CKA_WRAP, &truebool);
        template.add_bool(CKA_UNWRAP, &truebool);
        let pbkdf2 = self.mechanisms.get(CKM_PKCS5_PBKD2)?;
        pbkdf2.generate_key(
            &CK_MECHANISM {
                mechanism: CKM_PKCS5_PBKD2,
                pParameter: &params as *const _ as *mut _,
                ulParameterLen: sizeof!(CK_PKCS5_PBKD2_PARAMS2),
            },
            template.as_slice(),
            &self.mechanisms,
            &self.object_factories,
        )
    }

    fn wrapping_params(&self) -> CK_GCM_PARAMS {
        CK_GCM_PARAMS {
            pIv: USER_PIN_IV.as_ptr() as *mut CK_BYTE,
            ulIvLen: USER_PIN_IV.len() as CK_ULONG,
            ulIvBits: (USER_PIN_IV.len() * 8) as CK_ULONG,
            pAAD: USER_PIN_AAD.as_ptr() as *mut CK_BYTE,
            ulAADLen: USER_PIN_AAD.len() as CK_ULONG,
            ulTagBits: 64 as CK_ULONG,
        }
    }

    fn wrap_kek(
        &mut self,
        wrapper: &Object,
        mut kek: Object,
    ) -> Result<Vec<u8>> {
        let vlen = kek.get_attr_as_ulong(CKA_VALUE_LEN)?;
        let bs = aes::AES_BLOCK_SIZE;
        let mut buf = vec![0u8; (((vlen as usize + bs) / bs) + 1) * bs];
        let mut blen = buf.len() as CK_ULONG;
        let aes = self.mechanisms.get(CKM_AES_GCM)?;
        let factory = self.object_factories.get_object_factory(&kek)?;
        /* need to do this or wrap_key will fail */
        kek.set_attr(attribute::from_bool(CKA_EXTRACTABLE, true))?;
        aes.wrap_key(
            &CK_MECHANISM {
                mechanism: CKM_AES_GCM,
                pParameter: &self.wrapping_params() as *const _ as *mut _,
                ulParameterLen: sizeof!(CK_GCM_PARAMS),
            },
            wrapper,
            &kek,
            buf.as_mut_ptr() as *mut u8,
            &mut blen,
            factory,
        )?;
        unsafe { buf.set_len(blen as usize) };
        Ok(buf)
    }

    fn unwrap_kek(&self, wrapper: &Object, wrapped: &[u8]) -> Result<Object> {
        let class = CKO_SECRET_KEY;
        let keytyp = CKK_AES;
        let keylen = aes::MAX_AES_SIZE_BYTES as CK_ULONG;
        let truebool: CK_BBOOL = CK_TRUE;
        let mut template = attribute::CkAttrs::with_capacity(5);
        template.add_ulong(CKA_CLASS, &class);
        template.add_ulong(CKA_KEY_TYPE, &keytyp);
        template.add_ulong(CKA_VALUE_LEN, &keylen);
        template.add_bool(CKA_ENCRYPT, &truebool);
        template.add_bool(CKA_DECRYPT, &truebool);
        let aes = self.mechanisms.get(CKM_AES_GCM)?;
        Ok(aes.unwrap_key(
            &CK_MECHANISM {
                mechanism: CKM_AES_GCM,
                pParameter: &self.wrapping_params() as *const _ as *mut _,
                ulParameterLen: sizeof!(CK_GCM_PARAMS),
            },
            wrapper,
            wrapped,
            template.as_slice(),
            self.object_factories
                .get_obj_factory_from_key_template(template.as_slice())?,
        )?)
    }

    fn update_pin_flags(&mut self, obj: &Object) -> Result<()> {
        let uid = obj.get_attr_as_string(CKA_UNIQUE_ID)?;
        let is_so = match uid.as_str() {
            SO_PIN_UID => true,
            USER_PIN_UID => false,
            _ => return err_rv!(CKR_GENERAL_ERROR),
        };
        let max = obj.get_attr_as_ulong(KRA_MAX_LOGIN_ATTEMPTS)?;
        let attempts = obj.get_attr_as_ulong(KRA_LOGIN_ATTEMPTS)?;
        match max - attempts {
            0 => {
                if is_so {
                    self.info.flags |= CKF_SO_PIN_LOCKED;
                } else {
                    self.info.flags |= CKF_USER_PIN_LOCKED;
                }
            }
            1 => {
                if is_so {
                    self.info.flags |= CKF_SO_PIN_FINAL_TRY;
                } else {
                    self.info.flags |= CKF_USER_PIN_FINAL_TRY;
                }
            }
            2 | 3 => {
                if is_so {
                    self.info.flags |= CKF_SO_PIN_COUNT_LOW;
                } else {
                    self.info.flags |= CKF_USER_PIN_COUNT_LOW;
                }
            }
            _ => {
                if attempts == 0 {
                    self.info.flags &= if is_so {
                        !(CKF_SO_PIN_FINAL_TRY | CKF_SO_PIN_COUNT_LOW)
                    } else {
                        !(CKF_USER_PIN_FINAL_TRY | CKF_USER_PIN_COUNT_LOW)
                    }
                }
            }
        }
        Ok(())
    }

    fn init_pin_flags(&mut self) -> Result<()> {
        let so = self.fetch_pin_object(SO_PIN_UID)?;
        self.update_pin_flags(&so)?;
        let so_label = so.get_attr_as_string(CKA_LABEL)?;
        if self.parse_pin_label(so_label.as_str())?.0 == DEFPIN_SALT {
            self.info.flags |= CKF_SO_PIN_TO_BE_CHANGED;
        }
        let user = self.fetch_pin_object(USER_PIN_UID)?;
        self.update_pin_flags(&user)?;
        let user_label = user.get_attr_as_string(CKA_LABEL)?;
        if self.parse_pin_label(user_label.as_str())?.0 == DEFPIN_SALT {
            self.info.flags |= CKF_USER_PIN_TO_BE_CHANGED;
        } else {
            self.info.flags |= CKF_USER_PIN_INITIALIZED;
        }
        Ok(())
    }

    fn reset_user_pin(&mut self) -> Result<()> {
        let class = CKO_SECRET_KEY;
        let keytyp = CKK_AES;
        let keylen = aes::MAX_AES_SIZE_BYTES as CK_ULONG;
        let mut template = attribute::CkAttrs::with_capacity(3);
        template.add_ulong(CKA_CLASS, &class);
        template.add_ulong(CKA_KEY_TYPE, &keytyp);
        template.add_ulong(CKA_VALUE_LEN, &keylen);
        let aes = self.mechanisms.get(CKM_AES_KEY_GEN)?;
        let kek = aes.generate_key(
            &CK_MECHANISM {
                mechanism: CKM_AES_KEY_GEN,
                pParameter: std::ptr::null_mut(),
                ulParameterLen: 0,
            },
            template.as_slice(),
            &self.mechanisms,
            &self.object_factories,
        )?;
        /* the default pin is the null pin
         * Except in FIPS mode where OpenSSL refuses empty passwords */
        let key =
            self.pin_to_key(&default_password(), DEFPIN_SALT, DEFPIN_ITER)?;
        let wrapped = self.wrap_kek(&key, kek)?;
        self.store_pin_object(
            USER_PIN_UID.to_string(),
            format!("{}:{}", DEFPIN_SALT, DEFPIN_ITER),
            wrapped,
        )
    }

    fn random_pin_salt(&self) -> Result<String> {
        let mut data = [0u8; 8];
        get_random_data(&mut data)?;
        Ok(hex::encode(data))
    }

    pub fn set_pin(
        &mut self,
        user_type: CK_USER_TYPE,
        pin: &Vec<u8>,
        old: &Vec<u8>,
    ) -> Result<()> {
        let utype = match user_type {
            CK_UNAVAILABLE_INFORMATION => {
                if self.so_logged_in {
                    CKU_SO
                } else {
                    CKU_USER
                }
            }
            CKU_USER => CKU_USER,
            CKU_SO => CKU_SO,
            _ => return err_rv!(CKR_GENERAL_ERROR),
        };

        match utype {
            CKU_USER => {
                if self.so_logged_in && old.len() == 0 {
                    /* this is a forced change,
                     * which will make all existing secrets unreadable */
                    self.reset_user_pin()?;
                }
                let kek = if old.len() == 0 {
                    /* In FIPS mode OpenSSL's PBKDF2 does not accept empty
                     * passwords, so we replace it for a default password
                     * during initialization */
                    self.check_user_login(&default_password())?
                } else {
                    self.check_user_login(old)?
                };
                let salt = self.random_pin_salt()?;
                let key = self.pin_to_key(pin, salt.as_str(), DEFPIN_ITER)?;
                let wrapped = self.wrap_kek(&key, kek)?;
                self.store_pin_object(
                    USER_PIN_UID.to_string(),
                    format!("{}:{}", salt, DEFPIN_ITER),
                    wrapped,
                )?;

                if old.len() != 0 {
                    self.info.flags |= CKF_USER_PIN_INITIALIZED;
                }
            }
            CKU_SO => {
                if self.is_initialized() {
                    /* When the token is not yet initialized, the set_pin
                     * operation is used to set the initial SO PIN, so we
                     * can't check the old one in that case as we'd fail.
                     */
                    self.check_so_login(old)?;
                }
                let salt = if pin.len() != 0 {
                    self.random_pin_salt()?
                } else {
                    DEFPIN_SALT.to_string()
                };
                let derived =
                    self.pin_to_key(pin, salt.as_str(), DEFPIN_ITER)?;
                let value = derived.get_attr_as_bytes(CKA_VALUE)?;
                /* TODO: should we store a copy of the kek with
                 * the so token for recovery reasons ? */
                self.store_pin_object(
                    SO_PIN_UID.to_string(),
                    format!("{}:{}", salt, DEFPIN_ITER),
                    value.clone(),
                )?;
            }
            _ => return err_rv!(CKR_GENERAL_ERROR),
        }
        Ok(())
    }

    pub fn initialize(&mut self, pin: &Vec<u8>, label: &Vec<u8>) -> Result<()> {
        if self.is_initialized() {
            self.check_so_login(pin)?;
        };

        /* this inits from scratch or deletes and reinits an existing db */
        self.storage.reinit()?;

        self.handles = Handles::new();
        self.session_objects.clear();
        self.so_logged_in = false;
        self.kek = None;

        /* mark uninitialized otherwise set_pin() will fail trying to verify
         * the SO PIN from storage (which has just been obliterated) */
        self.info.flags &= !CKF_TOKEN_INITIALIZED;

        /* Add SO PIN */
        self.set_pin(CKU_SO, pin, &vec![0u8; 0])?;
        /* Generate KEK and store with empty User PIN */
        self.reset_user_pin()?;

        copy_sized_string(label.as_slice(), &mut self.info.label);
        self.store_token_info()?;

        self.init_pin_flags()?;

        #[cfg(feature = "fips")]
        if fips::token_init(self).is_err() {
            return err_rv!(CKR_GENERAL_ERROR);
        }

        self.info.flags |= CKF_TOKEN_INITIALIZED;

        Ok(())
    }

    fn update_pin_attempts(
        &mut self,
        uid: String,
        attempts: CK_ULONG,
    ) -> Result<()> {
        let mut obj = self.storage.fetch_by_uid(&uid)?.clone();
        obj.set_attr(attribute::from_ulong(KRA_LOGIN_ATTEMPTS, attempts))?;
        self.storage.store(&uid, obj)
    }

    fn check_so_login(&mut self, pin: &Vec<u8>) -> Result<()> {
        let mut obj = self.fetch_pin_object(SO_PIN_UID)?;

        let stored_attempts = obj.get_attr_as_ulong(KRA_LOGIN_ATTEMPTS)?;
        let max = obj.get_attr_as_ulong(KRA_MAX_LOGIN_ATTEMPTS)?;
        if stored_attempts >= max {
            return err_rv!(CKR_PIN_LOCKED);
        }

        let label = obj.get_attr_as_string(CKA_LABEL)?;
        let (salt, iterations) = self.parse_pin_label(label.as_str())?;
        let key = self.pin_to_key(pin, salt.as_str(), iterations)?;

        let stored_value = obj.get_attr_as_bytes(CKA_VALUE)?;
        let value = key.get_attr_as_bytes(CKA_VALUE)?;

        let mut attempts = stored_attempts;
        if value == stored_value {
            attempts = 0;
        } else {
            attempts += 1;
        }

        /* Store attempts back to token */
        if stored_attempts != attempts {
            let _ = self.update_pin_attempts(SO_PIN_UID.to_string(), attempts);

            /* set token info */
            obj.set_attr(attribute::from_ulong(KRA_LOGIN_ATTEMPTS, attempts))?;
            self.update_pin_flags(&obj)?;
        }

        if attempts == 0 {
            return Ok(());
        }
        if self.info.flags & CKF_SO_PIN_LOCKED != 0 {
            return err_rv!(CKR_PIN_LOCKED);
        }
        return err_rv!(CKR_PIN_INCORRECT);
    }

    fn check_user_login(&mut self, pin: &Vec<u8>) -> Result<Object> {
        let mut obj = self.fetch_pin_object(USER_PIN_UID)?;

        let stored_attempts = obj.get_attr_as_ulong(KRA_LOGIN_ATTEMPTS)?;
        let max = obj.get_attr_as_ulong(KRA_MAX_LOGIN_ATTEMPTS)?;
        if stored_attempts >= max {
            return err_rv!(CKR_PIN_LOCKED);
        }

        let label = obj.get_attr_as_string(CKA_LABEL)?;
        let (salt, iterations) = self.parse_pin_label(label.as_str())?;
        let key = self.pin_to_key(pin, salt.as_str(), iterations)?;

        let mut attempts = stored_attempts;
        let kek = match self
            .unwrap_kek(&key, obj.get_attr_as_bytes(CKA_VALUE)?.as_slice())
        {
            Ok(k) => {
                attempts = 0;
                Some(k)
            }
            Err(_) => {
                attempts += 1;
                None
            }
        };

        /* Store attempts back to token */
        if stored_attempts != attempts {
            let _ =
                self.update_pin_attempts(USER_PIN_UID.to_string(), attempts);

            /* set token info */
            obj.set_attr(attribute::from_ulong(KRA_LOGIN_ATTEMPTS, attempts))?;
            self.update_pin_flags(&obj)?;
        }

        if attempts == 0 {
            return Ok(kek.unwrap());
        }
        if self.info.flags & CKF_USER_PIN_LOCKED != 0 {
            return err_rv!(CKR_PIN_LOCKED);
        }
        return err_rv!(CKR_PIN_INCORRECT);
    }

    pub fn is_logged_in(&self, user_type: CK_USER_TYPE) -> bool {
        if user_type != CKU_SO && !self.is_login_required() {
            return true;
        }
        match user_type {
            KRY_UNSPEC => self.so_logged_in || self.kek.is_some(),
            CKU_SO => self.so_logged_in,
            CKU_USER => self.kek.is_some(),
            _ => false,
        }
    }

    pub fn login(&mut self, user_type: CK_USER_TYPE, pin: &Vec<u8>) -> CK_RV {
        if !self.is_login_required() {
            return CKR_OK;
        }
        match user_type {
            CKU_SO => {
                if self.so_logged_in {
                    return CKR_USER_ALREADY_LOGGED_IN;
                }
                if self.kek.is_some() {
                    return CKR_USER_ANOTHER_ALREADY_LOGGED_IN;
                }
                match self.check_so_login(pin) {
                    Ok(()) => {
                        self.so_logged_in = true;
                        CKR_OK
                    }
                    Err(e) => e.rv(),
                }
            }
            CKU_USER => {
                if self.kek.is_some() {
                    return CKR_USER_ALREADY_LOGGED_IN;
                }
                if self.so_logged_in {
                    return CKR_USER_ANOTHER_ALREADY_LOGGED_IN;
                }
                match self.check_user_login(pin) {
                    Ok(kek) => {
                        self.kek = Some(kek);
                        CKR_OK
                    }
                    Err(e) => e.rv(),
                }
            }
            CKU_CONTEXT_SPECIFIC => match self.check_user_login(pin) {
                Ok(_) => CKR_OK,
                Err(e) => e.rv(),
            },
            _ => CKR_USER_TYPE_INVALID,
        }
    }

    pub fn logout(&mut self) -> CK_RV {
        let mut ret = CKR_USER_NOT_LOGGED_IN;
        if !self.is_login_required() {
            ret = CKR_OK;
        }
        if self.kek.is_some() {
            self.kek = None;
            ret = CKR_OK;
        }
        if self.so_logged_in {
            self.so_logged_in = false;
            ret = CKR_OK;
        }
        if ret != CKR_OK {
            return ret;
        }

        self.clear_private_session_objects();

        CKR_OK
    }

    pub fn save(&mut self) -> Result<()> {
        self.storage.flush()
    }

    fn clear_private_session_objects(&mut self) {
        let mut priv_handles = Vec::<CK_OBJECT_HANDLE>::new();
        for (handle, obj) in self.session_objects.iter() {
            if obj.is_private() {
                priv_handles.push(*handle);
            }
        }

        /* remove all private session objects */
        for handle in priv_handles {
            let _ = self.session_objects.remove(&handle);
            self.handles.remove(handle);
        }
    }

    fn clear_session_objects(&mut self, session: CK_SESSION_HANDLE) {
        /* intentionally matches only valid handles, as we use invalid
         * handles in some places to preserve special internal objects
         * like validation objects in FIPS mode */
        let mut handles: Vec<CK_OBJECT_HANDLE> = Vec::new();
        for (_, obj) in self.session_objects.iter() {
            if obj.get_session() == session {
                handles.push(obj.get_handle());
            }
        }

        for h in handles {
            let _ = self.session_objects.remove(&h);
            self.handles.remove(h);
        }
    }

    /* We should probably have lifetimes to ensure iv and aad are around for
     * the lifetime of the returned structure, but this will require substantial
     * reworking of the bindings, so for now we just get this comment.
     * ENSURE the arguments stay in scope until CK_GCM_PARAMS is needed
     * */
    fn encryption_params(&self, iv: &[u8], aad: &[u8]) -> CK_GCM_PARAMS {
        CK_GCM_PARAMS {
            pIv: iv.as_ptr() as *mut CK_BYTE,
            ulIvLen: iv.len() as CK_ULONG,
            ulIvBits: (iv.len() * 8) as CK_ULONG,
            pAAD: aad.as_ptr() as *mut CK_BYTE,
            ulAADLen: aad.len() as CK_ULONG,
            ulTagBits: 64 as CK_ULONG,
        }
    }

    fn encrypt_value(&self, uid: &String, val: &Vec<u8>) -> Result<Vec<u8>> {
        if let Some(ref kek) = self.kek {
            let mut iv = [0u8; DEFAULT_IV_SIZE];
            get_random_data(&mut iv)?;
            let mut params = self.encryption_params(&iv, uid.as_bytes());
            let mech: CK_MECHANISM = CK_MECHANISM {
                mechanism: CKM_AES_GCM,
                pParameter: &mut params as *mut interface::CK_GCM_PARAMS
                    as *mut _,
                ulParameterLen: sizeof!(CK_GCM_PARAMS),
            };
            let aes = self.mechanisms.get(CKM_AES_GCM)?;
            let mut op = aes.encryption_new(&mech, &kek)?;
            let mut clen: CK_ULONG =
                (op.encryption_len(val.len() as CK_ULONG)? + DEFAULT_IV_SIZE)
                    as CK_ULONG;
            let mut cipher = Vec::<u8>::with_capacity(clen as usize);
            cipher.extend_from_slice(&iv);
            cipher.resize(clen as usize, 0);
            clen -= iv.len() as CK_ULONG;
            op.encrypt(
                val.as_slice(),
                cipher.as_mut_slice()[DEFAULT_IV_SIZE..].as_mut_ptr(),
                &mut clen,
            )?;

            unsafe { cipher.set_len(clen as usize + DEFAULT_IV_SIZE) };
            return Ok(cipher);
        } else {
            return err_rv!(CKR_GENERAL_ERROR);
        }
    }

    fn object_to_storage(
        &mut self,
        mut obj: Object,
        encrypt: bool,
    ) -> Result<()> {
        let uid = obj.get_attr_as_string(CKA_UNIQUE_ID)?;
        if encrypt && self.info.flags & CKF_RESTORE_KEY_NOT_NEEDED != 0 {
            let ats = self.object_factories.get_sensitive_attrs(&obj)?;
            for typ in ats {
                let plain = obj.get_attr_as_bytes(typ)?;
                let encval = self.encrypt_value(&uid, plain)?;

                /* now replace the clear text val with the encrypted one */
                obj.set_attr(attribute::from_bytes(typ, encval))?;
            }
        }
        self.storage.store(&uid, obj)
    }

    fn decrypt_value(&self, uid: &String, val: &Vec<u8>) -> Result<Vec<u8>> {
        if let Some(ref kek) = self.kek {
            let mut params = self.encryption_params(
                &val.as_slice()[..DEFAULT_IV_SIZE],
                uid.as_bytes(),
            );
            let mech: CK_MECHANISM = CK_MECHANISM {
                mechanism: CKM_AES_GCM,
                pParameter: &mut params as *mut interface::CK_GCM_PARAMS
                    as *mut _,
                ulParameterLen: sizeof!(CK_GCM_PARAMS),
            };
            let aes = self.mechanisms.get(CKM_AES_GCM)?;
            let mut op = aes.decryption_new(&mech, &kek)?;
            let mut plen: CK_ULONG = op
                .decryption_len((val.len() - DEFAULT_IV_SIZE) as CK_ULONG)?
                as CK_ULONG;
            let mut plain = Vec::<u8>::with_capacity(plen as usize);
            op.decrypt(
                &val.as_slice()[DEFAULT_IV_SIZE..],
                plain.as_mut_ptr(),
                &mut plen,
            )?;

            unsafe { plain.set_len(plen as usize) };
            return Ok(plain);
        } else {
            return err_rv!(CKR_GENERAL_ERROR);
        }
    }

    fn object_from_storage(
        &self,
        uid: &String,
        decrypt: bool,
    ) -> Result<Object> {
        let mut obj = self.storage.fetch_by_uid(uid)?;
        if decrypt && self.info.flags & CKF_RESTORE_KEY_NOT_NEEDED != 0 {
            let ats = self.object_factories.get_sensitive_attrs(&obj)?;
            for typ in ats {
                let encval = obj.get_attr_as_bytes(typ)?;
                let plain = self.decrypt_value(uid, encval)?;

                /* now replace the encrypted val with the clear text one */
                obj.set_attr(attribute::from_bytes(typ, plain))?;
            }
        }
        Ok(obj)
    }

    pub fn get_object_by_handle(
        &mut self,
        o_handle: CK_OBJECT_HANDLE,
    ) -> Result<Object> {
        let is_logged_in = self.is_logged_in(KRY_UNSPEC);
        let mut obj = match self.handles.get(o_handle) {
            Some(s) => {
                if let Some(o) = self.session_objects.get(&o_handle) {
                    o.clone()
                } else {
                    self.object_from_storage(s, true)?
                }
            }
            None => return err_rv!(CKR_OBJECT_HANDLE_INVALID),
        };
        if !is_logged_in && obj.is_token() && obj.is_private() {
            return err_rv!(CKR_USER_NOT_LOGGED_IN);
        }
        if obj.is_sensitive() {
            obj.set_zeroize()
        }
        Ok(obj)
    }

    pub fn insert_object(
        &mut self,
        s_handle: CK_SESSION_HANDLE,
        mut obj: Object,
    ) -> Result<CK_OBJECT_HANDLE> {
        let uid = obj.get_attr_as_string(CKA_UNIQUE_ID)?;
        let is_token = obj.is_token();
        if is_token {
            if !self.is_logged_in(KRY_UNSPEC) {
                return err_rv!(CKR_USER_NOT_LOGGED_IN);
            }
        } else {
            obj.set_session(s_handle);
        }
        let handle = self.handles.next();
        obj.set_handle(handle);
        self.handles.insert(handle, uid.clone());
        if obj.is_token() {
            self.object_to_storage(obj, true)?;
        } else {
            self.session_objects.insert(handle, obj);
        }
        Ok(handle)
    }

    pub fn create_object(
        &mut self,
        s_handle: CK_SESSION_HANDLE,
        template: &[CK_ATTRIBUTE],
    ) -> Result<CK_OBJECT_HANDLE> {
        let object = self.object_factories.create(template)?;
        self.insert_object(s_handle, object)
    }

    pub fn destroy_object(&mut self, o_handle: CK_OBJECT_HANDLE) -> Result<()> {
        match self.session_objects.get(&o_handle) {
            Some(obj) => {
                if !obj.is_destroyable() {
                    return err_rv!(CKR_ACTION_PROHIBITED);
                }
                let _ = self.session_objects.remove(&o_handle);
            }
            None => {
                let uid = match self.handles.get(o_handle) {
                    Some(u) => u,
                    None => return err_rv!(CKR_OBJECT_HANDLE_INVALID),
                };
                let obj = self.object_from_storage(uid, false)?;
                if !obj.is_destroyable() {
                    return err_rv!(CKR_ACTION_PROHIBITED);
                }
                let _ = self.storage.remove_by_uid(&uid);
            }
        }
        self.handles.remove(o_handle);
        Ok(())
    }

    pub fn get_token_info(&self) -> &CK_TOKEN_INFO {
        &self.info
    }

    pub fn get_object_attrs(
        &mut self,
        o_handle: CK_OBJECT_HANDLE,
        template: &mut [CK_ATTRIBUTE],
    ) -> Result<()> {
        let is_logged = self.is_logged_in(KRY_UNSPEC);
        let obj = match self.handles.get(o_handle) {
            Some(uid) => {
                if let Some(o) = self.session_objects.get(&o_handle) {
                    Cow::Borrowed(o)
                } else {
                    Cow::Owned(self.object_from_storage(uid, false)?)
                }
            }
            None => return err_rv!(CKR_OBJECT_HANDLE_INVALID),
        };
        if !is_logged && obj.is_token() && obj.is_private() {
            /* do not reveal if the object exists or not */
            return err_rv!(CKR_OBJECT_HANDLE_INVALID);
        }
        self.object_factories.get_object_attributes(&obj, template)
    }

    pub fn set_object_attrs(
        &mut self,
        o_handle: CK_OBJECT_HANDLE,
        template: &mut [CK_ATTRIBUTE],
    ) -> Result<()> {
        let uid = match self.handles.get(o_handle) {
            Some(u) => u,
            None => return err_rv!(CKR_OBJECT_HANDLE_INVALID),
        };
        if let Some(mut obj) = self.session_objects.get_mut(&o_handle) {
            return self
                .object_factories
                .set_object_attributes(&mut obj, template);
        } else {
            /* no need to decrypt because Sensitive attributes
             * cannot be changed via this function */
            let mut obj = self.object_from_storage(uid, false)?;
            self.object_factories
                .set_object_attributes(&mut obj, template)?;
            self.object_to_storage(obj, false)
        }
    }

    pub fn drop_session_objects(&mut self, handle: CK_SESSION_HANDLE) {
        self.clear_session_objects(handle);
    }

    pub fn get_mechs_num(&self) -> usize {
        self.mechanisms.len()
    }

    pub fn get_mechs_list(&self) -> Vec<CK_MECHANISM_TYPE> {
        self.mechanisms.list()
    }

    pub fn get_mech_info(
        &self,
        typ: CK_MECHANISM_TYPE,
    ) -> Result<&CK_MECHANISM_INFO> {
        match self.mechanisms.info(typ) {
            Some(m) => Ok(m),
            None => err_rv!(CKR_MECHANISM_INVALID),
        }
    }

    pub fn get_object_size(&self, o_handle: CK_OBJECT_HANDLE) -> Result<usize> {
        match self.handles.get(o_handle) {
            Some(s) => {
                if let Some(o) = self.session_objects.get(&o_handle) {
                    o.rough_size()
                } else {
                    self.object_from_storage(s, false)?.rough_size()
                }
            }
            None => err_rv!(CKR_OBJECT_HANDLE_INVALID),
        }
    }

    pub fn copy_object(
        &mut self,
        s_handle: CK_SESSION_HANDLE,
        o_handle: CK_OBJECT_HANDLE,
        template: &[CK_ATTRIBUTE],
    ) -> Result<CK_OBJECT_HANDLE> {
        let is_logged_in = self.is_logged_in(KRY_UNSPEC);
        let obj: Cow<'_, Object> = match self.handles.get(o_handle) {
            Some(uid) => {
                if let Some(o) = self.session_objects.get_mut(&o_handle) {
                    Cow::Borrowed(o)
                } else {
                    Cow::Owned(self.object_from_storage(uid, true)?)
                }
            }
            None => return err_rv!(CKR_OBJECT_HANDLE_INVALID),
        };
        if !is_logged_in && obj.is_token() && obj.is_private() {
            return err_rv!(CKR_USER_NOT_LOGGED_IN);
        }
        let newobj = self.object_factories.copy(&obj, template)?;
        self.insert_object(s_handle, newobj)
    }

    pub fn search_objects(
        &mut self,
        template: &[CK_ATTRIBUTE],
    ) -> Result<Vec<CK_OBJECT_HANDLE>> {
        let mut handles = Vec::<CK_OBJECT_HANDLE>::new();
        let is_logged_in = self.is_logged_in(KRY_UNSPEC);

        /* First add internal session objects */
        for (_, o) in &self.session_objects {
            if o.is_sensitive() {
                match self.object_factories.check_sensitive(o, template) {
                    Err(_) => continue,
                    Ok(()) => (),
                }
            }
            if o.match_template(template) {
                handles.push(o.get_handle());
            }
        }

        /* Then search storage */
        let ret = self.storage.search(template)?;
        for o in ret {
            if !is_logged_in && o.is_private() {
                continue;
            }

            if o.is_sensitive() {
                match self.object_factories.check_sensitive(&o, template) {
                    Err(_) => continue,
                    Ok(()) => (),
                }
            }

            let uid = match o.get_attr_as_string(CKA_UNIQUE_ID) {
                Ok(s) => s,
                Err(_) => return err_rv!(CKR_GENERAL_ERROR),
            };
            let handle = match self.handles.get_by_uid(&uid) {
                Some(h) => *h,
                None => {
                    let h = self.handles.next();
                    self.handles.insert(h, uid.clone());
                    h
                }
            };

            /* do not return internal objects */
            if let Ok(numuid) = uid.parse::<usize>() {
                if numuid < 10 {
                    continue;
                }
            }
            handles.push(handle);
        }
        Ok(handles)
    }

    pub fn get_mechanisms(&self) -> &Mechanisms {
        &self.mechanisms
    }

    pub fn get_object_factories(&self) -> &ObjectFactories {
        &self.object_factories
    }
}
