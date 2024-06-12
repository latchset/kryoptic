// Copyright 2023 Simo Sorce
// See LICENSE.txt file for terms

use std::collections::HashMap;
use std::vec::Vec;

use super::aes;
use super::attribute;
use super::ecc;
use super::error;
use super::hash;
use super::interface;
use super::kdf;
use super::mechanism;
use super::object;
use super::rsa;
use super::storage;

use super::{err_rv, to_rv};
use error::{KError, KResult};
use interface::*;
use mechanism::Mechanisms;
use object::{Object, ObjectFactories};
use storage::Storage;

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

fn copy_sized_string(s: &[u8], d: &mut [u8]) {
    if s.len() >= d.len() {
        d.copy_from_slice(&s[..d.len()]);
    } else {
        d[..s.len()].copy_from_slice(s);
        d[s.len()..].fill(0x20); /* space in ASCII/UTF8 */
    }
}

#[derive(Debug, Clone)]
struct LoginData {
    pin: Option<Vec<u8>>,
    max_attempts: CK_ULONG,
    attempts: CK_ULONG,
    logged_in: bool,
}

impl LoginData {
    fn check_pin(&mut self, pin: &Vec<u8>) -> CK_RV {
        if self.attempts >= self.max_attempts {
            return CKR_PIN_LOCKED;
        }
        match &self.pin {
            Some(p) => {
                if p == pin {
                    self.logged_in = true;
                    self.attempts = 0;
                    CKR_OK
                } else {
                    self.attempts += 1;
                    CKR_PIN_INCORRECT
                }
            }
            None => CKR_USER_PIN_NOT_INITIALIZED,
        }
    }

    fn set_pin(&mut self, info: &CK_TOKEN_INFO, pin: &Vec<u8>) -> CK_RV {
        let pin_len = pin.len() as CK_ULONG;
        if info.ulMaxPinLen != CK_EFFECTIVELY_INFINITE {
            if pin_len > info.ulMaxPinLen {
                return CKR_PIN_LEN_RANGE;
            }
        }
        if pin_len < info.ulMinPinLen {
            return CKR_PIN_LEN_RANGE;
        }
        self.pin = Some(pin.clone());
        if self.max_attempts == 0 {
            self.max_attempts = 10;
        }
        self.attempts = 0;
        CKR_OK
    }

    fn change_pin(
        &mut self,
        info: &CK_TOKEN_INFO,
        pin: &Vec<u8>,
        old: &Vec<u8>,
    ) -> CK_RV {
        let ret = self.check_pin(old);
        if ret != CKR_OK {
            return ret;
        }
        self.set_pin(info, pin)
    }
}

#[derive(Debug, Clone)]
pub struct Handles {
    map: HashMap<CK_OBJECT_HANDLE, String>,
    next: CK_OBJECT_HANDLE,
}

impl Handles {
    pub fn new() -> Handles {
        Handles {
            map: HashMap::new(),
            next: 1,
        }
    }

    pub fn insert(
        &mut self,
        handle: CK_OBJECT_HANDLE,
        value: String,
    ) -> Option<String> {
        self.map.insert(handle, value)
    }

    pub fn get(&self, handle: CK_OBJECT_HANDLE) -> Option<&String> {
        self.map.get(&handle)
    }

    pub fn remove(&mut self, handle: CK_OBJECT_HANDLE) -> Option<String> {
        self.map.remove(&handle)
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
    handles: Handles,
    so_login: LoginData,
    user_login: LoginData,
}

impl Token {
    pub fn new(filename: String) -> KResult<Token> {
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
            handles: Handles::new(),
            so_login: LoginData {
                pin: None,
                max_attempts: 0,
                attempts: 0,
                logged_in: false,
            },
            user_login: LoginData {
                pin: None,
                max_attempts: 0,
                attempts: 0,
                logged_in: false,
            },
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
        hash::register(&mut token.mechanisms, &mut token.object_factories);
        kdf::register(&mut token.mechanisms, &mut token.object_factories);

        if token.filename.len() > 0 {
            match token.storage.open(&token.filename) {
                Ok(()) => {
                    token.load_token_info()?;
                    token.info.flags |= CKF_TOKEN_INITIALIZED;
                }
                Err(err) => match err {
                    KError::RvError(ref e) => {
                        /* empty file is legal but leaves the token uninitialized */
                        if e.rv != CKR_CRYPTOKI_NOT_INITIALIZED {
                            return Err(err);
                        }
                        token.info.flags &= !CKF_TOKEN_INITIALIZED;
                    }
                    _ => return Err(err),
                },
            }
        } else {
            token.info.flags &= !CKF_LOGIN_REQUIRED;
            token.info.flags |= CKF_TOKEN_INITIALIZED;
        }

        if token.is_initialized() {
            token.update_token_pin_flags();
        }

        Ok(token)
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

    fn update_token_pin_flags(&mut self) {
        if self.so_login.pin.is_none() {
            let _ = self.get_so_login_data();
        }
        if self.so_login.pin.is_none() {
            self.info.flags |= CKF_SO_PIN_TO_BE_CHANGED;
        } else {
            self.info.flags &= !CKF_SO_PIN_TO_BE_CHANGED;
            if self.so_login.attempts >= self.so_login.max_attempts {
                self.info.flags |= CKF_SO_PIN_LOCKED;
                self.info.flags &= !CKF_SO_PIN_FINAL_TRY;
                self.info.flags &= !CKF_SO_PIN_COUNT_LOW;
            } else {
                if self.so_login.attempts + 1 == self.so_login.max_attempts {
                    self.info.flags |= CKF_SO_PIN_FINAL_TRY;
                } else {
                    self.info.flags &= !CKF_SO_PIN_FINAL_TRY;
                }
                if self.so_login.attempts > 0 {
                    self.info.flags |= CKF_SO_PIN_COUNT_LOW;
                } else {
                    self.info.flags &= !CKF_SO_PIN_COUNT_LOW;
                }
            }
        }
        if self.user_login.pin.is_none() {
            let _ = self.get_user_login_data();
        }
        if self.user_login.pin.is_none() {
            self.info.flags |= CKF_USER_PIN_TO_BE_CHANGED;
        } else {
            self.info.flags &= !CKF_USER_PIN_TO_BE_CHANGED;
            if self.user_login.attempts >= self.user_login.max_attempts {
                self.info.flags |= CKF_USER_PIN_LOCKED;
                self.info.flags &= !CKF_USER_PIN_FINAL_TRY;
                self.info.flags &= !CKF_USER_PIN_COUNT_LOW;
            } else {
                if self.user_login.attempts + 1 == self.user_login.max_attempts
                {
                    self.info.flags |= CKF_USER_PIN_FINAL_TRY;
                } else {
                    self.info.flags &= !CKF_USER_PIN_FINAL_TRY;
                }
                if self.user_login.attempts > 0 {
                    self.info.flags |= CKF_USER_PIN_COUNT_LOW;
                } else {
                    self.info.flags &= !CKF_USER_PIN_COUNT_LOW;
                }
            }
        }
    }

    fn store_pin_object(
        &mut self,
        uid: String,
        label: String,
        pin: Vec<u8>,
    ) -> KResult<()> {
        match self.storage.fetch_by_uid(&uid) {
            Ok(o) => {
                let mut obj = o.clone();
                obj.set_attr(attribute::from_bytes(CKA_VALUE, pin))?;
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
                obj.set_attr(attribute::from_bytes(CKA_VALUE, pin))?;
                self.storage.store(&uid, obj)?;
            }
        }
        return Ok(());
    }

    fn load_token_info(&mut self) -> KResult<()> {
        let uid = TOKEN_INFO_UID.to_string();
        let obj = match self.storage.fetch_by_uid(&uid) {
            Ok(o) => o,
            Err(e) => match e {
                KError::NotFound(_) => {
                    /* it is ok if not token data is stored yet,
                     * we'll use defaults */
                    return Ok(());
                }
                KError::RvError(e) => return err_rv!(e.rv),
                _ => return err_rv!(CKR_GENERAL_ERROR),
            },
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

    fn store_token_info(&mut self) -> KResult<()> {
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

    pub fn initialize(&mut self, pin: &Vec<u8>, label: &Vec<u8>) -> CK_RV {
        let ret = if self.is_initialized() {
            self.login(CKU_SO, pin)
        } else {
            self.so_login.set_pin(&self.info, pin)
        };
        if ret != CKR_OK {
            return ret;
        }
        self.so_login.logged_in = false;
        match self.storage.reinit() {
            Ok(()) => {
                self.handles = Handles::new();
            }
            Err(_) => return CKR_GENERAL_ERROR,
        }

        /* add pin to so_object */
        if self
            .store_pin_object(
                SO_PIN_UID.to_string(),
                "SO PIN".to_string(),
                pin.clone(),
            )
            .is_err()
        {
            return CKR_GENERAL_ERROR;
        }

        copy_sized_string(label.as_slice(), &mut self.info.label);
        if self.store_token_info().is_err() {
            return CKR_GENERAL_ERROR;
        }
        self.info.flags |= CKF_TOKEN_INITIALIZED;
        self.update_token_pin_flags();
        CKR_OK
    }

    pub fn is_logged_in(&self, user_type: CK_USER_TYPE) -> bool {
        if user_type != CKU_SO && !self.is_login_required() {
            return true;
        }
        match user_type {
            KRY_UNSPEC => self.so_login.logged_in || self.user_login.logged_in,
            CKU_SO => self.so_login.logged_in,
            CKU_USER => self.user_login.logged_in,
            _ => false,
        }
    }

    fn clear_private_session_objects(&mut self) {
        let mut priv_uids = Vec::<String>::new();
        for obj in &self.storage.get_all_cached() {
            if obj.is_private() {
                let oh = obj.get_handle();
                if oh != CK_INVALID_HANDLE {
                    let _ = self.handles.remove(oh);
                }
                if !obj.is_token() {
                    /* not a token object, therefore we need to destroy it */
                    if let Ok(uid) = obj.get_attr_as_string(CKA_UNIQUE_ID) {
                        priv_uids.push(uid.clone());
                    }
                }
            }
        }

        /* remove all private session objects */
        for uid in priv_uids {
            let _ = self.storage.remove_by_uid(&uid);
        }
    }

    fn clear_session_objects(&mut self, handle: CK_SESSION_HANDLE) {
        let mut handles: Vec<CK_OBJECT_HANDLE> = Vec::new();
        for obj in &self.storage.get_all_cached() {
            if obj.get_session() == handle {
                if !obj.is_token() {
                    handles.push(obj.get_handle());
                }
            }
        }

        for h in handles {
            if let Some(uid) = self.handles.remove(h) {
                let _ = self.storage.remove_by_uid(&uid);
            }
        }
    }

    pub fn get_object_by_handle(
        &mut self,
        o_handle: CK_OBJECT_HANDLE,
    ) -> KResult<&Object> {
        let is_logged_in = self.is_logged_in(KRY_UNSPEC);
        let obj = match self.handles.get(o_handle) {
            Some(s) => self.storage.fetch_by_uid(s)?,
            None => return err_rv!(CKR_OBJECT_HANDLE_INVALID),
        };
        if !is_logged_in && obj.is_private() {
            return err_rv!(CKR_USER_NOT_LOGGED_IN);
        }
        Ok(obj)
    }

    fn fetch_pin_data(
        &mut self,
        uid: &str,
        label: &str,
    ) -> KResult<(Vec<u8>, CK_ULONG)> {
        let obj = match self.storage.fetch_by_uid(&uid.to_string()) {
            Ok(o) => o,
            Err(e) => match e {
                KError::NotFound(_) => {
                    return err_rv!(CKR_USER_PIN_NOT_INITIALIZED);
                }
                KError::RvError(e) => return err_rv!(e.rv),
                _ => return err_rv!(CKR_GENERAL_ERROR),
            },
        };
        if obj.get_attr_as_ulong(CKA_CLASS)? != CKO_SECRET_KEY {
            return err_rv!(CKR_GENERAL_ERROR);
        }
        if obj.get_attr_as_ulong(CKA_KEY_TYPE)? != CKK_GENERIC_SECRET {
            return err_rv!(CKR_GENERAL_ERROR);
        }
        if obj.get_attr_as_string(CKA_LABEL)? != label {
            return err_rv!(CKR_GENERAL_ERROR);
        }
        let value = obj.get_attr_as_bytes(CKA_VALUE)?;
        let max = match obj.get_attr_as_ulong(KRA_MAX_LOGIN_ATTEMPTS) {
            Ok(n) => n,
            Err(_) => 10,
        };

        Ok((value.clone(), max as CK_ULONG))
    }

    fn get_so_login_data(&mut self) -> KResult<()> {
        if self.so_login.pin.is_none() {
            let (pin, max) = self.fetch_pin_data(SO_PIN_UID, "SO PIN")?;
            self.so_login.pin = Some(pin);
            self.so_login.max_attempts = max;
        }
        Ok(())
    }

    fn get_user_login_data(&mut self) -> KResult<()> {
        if self.user_login.pin.is_none() {
            let (pin, max) = self.fetch_pin_data(USER_PIN_UID, "User PIN")?;
            self.user_login.pin = Some(pin);
            self.user_login.max_attempts = max;
        }
        Ok(())
    }

    pub fn login(&mut self, user_type: CK_USER_TYPE, pin: &Vec<u8>) -> CK_RV {
        if !self.is_login_required() {
            return CKR_OK;
        }
        let result = match user_type {
            CKU_SO => {
                if self.so_login.logged_in {
                    return CKR_USER_ALREADY_LOGGED_IN;
                }
                if self.user_login.logged_in {
                    return CKR_USER_ANOTHER_ALREADY_LOGGED_IN;
                }
                match self.get_so_login_data() {
                    Ok(_) => (),
                    Err(e) => match e {
                        KError::RvError(e) => return e.rv,
                        _ => return CKR_GENERAL_ERROR,
                    },
                }
                self.so_login.check_pin(pin)
            }
            CKU_USER => {
                if self.user_login.logged_in {
                    return CKR_USER_ALREADY_LOGGED_IN;
                }
                if self.so_login.logged_in {
                    return CKR_USER_ANOTHER_ALREADY_LOGGED_IN;
                }
                match self.get_user_login_data() {
                    Ok(_) => (),
                    Err(e) => match e {
                        KError::RvError(e) => return e.rv,
                        _ => return CKR_GENERAL_ERROR,
                    },
                }
                self.user_login.check_pin(pin)
            }
            _ => return CKR_USER_TYPE_INVALID,
        };
        self.update_token_pin_flags();
        result
    }

    pub fn logout(&mut self) -> CK_RV {
        let mut ret = CKR_USER_NOT_LOGGED_IN;
        if !self.is_login_required() {
            ret = CKR_OK;
        }
        if self.user_login.logged_in {
            self.user_login.logged_in = false;
            ret = CKR_OK;
        }
        if self.so_login.logged_in {
            self.so_login.logged_in = false;
            ret = CKR_OK;
        }
        if ret != CKR_OK {
            return ret;
        }

        self.clear_private_session_objects();

        CKR_OK
    }

    pub fn set_pin(
        &mut self,
        user_type: CK_USER_TYPE,
        pin: &Vec<u8>,
        old: Option<&Vec<u8>>,
    ) -> CK_RV {
        let utype = match user_type {
            CK_UNAVAILABLE_INFORMATION => {
                if self.so_login.logged_in {
                    CKU_SO
                } else {
                    CKU_USER
                }
            }
            CKU_USER => CKU_USER,
            CKU_SO => CKU_SO,
            _ => return CKR_GENERAL_ERROR,
        };

        match utype {
            CKU_USER => {
                let ret = if self.so_login.logged_in {
                    self.user_login.set_pin(&self.info, pin)
                } else {
                    if old.is_none() {
                        return CKR_PIN_INCORRECT;
                    }
                    self.user_login.change_pin(&self.info, pin, old.unwrap())
                };
                if ret != CKR_OK {
                    return ret;
                }
                /* update pin in storage */
                match self.store_pin_object(
                    USER_PIN_UID.to_string(),
                    "User PIN".to_string(),
                    pin.clone(),
                ) {
                    Ok(()) => (),
                    Err(_) => return CKR_GENERAL_ERROR,
                }
            }
            CKU_SO => {
                if old.is_none() {
                    return CKR_PIN_INCORRECT;
                }
                let ret =
                    self.so_login.change_pin(&self.info, pin, old.unwrap());
                if ret != CKR_OK {
                    return ret;
                }
                /* update pin in storage */
                match self.store_pin_object(
                    SO_PIN_UID.to_string(),
                    "SO PIN".to_string(),
                    pin.clone(),
                ) {
                    Ok(()) => (),
                    Err(_) => return CKR_GENERAL_ERROR,
                }
            }
            _ => return CKR_GENERAL_ERROR,
        }

        /* If we set a PIN it means we switched to require Logins */
        self.info.flags |= CKF_LOGIN_REQUIRED;

        self.update_token_pin_flags();

        CKR_OK
    }

    pub fn save(&mut self) -> KResult<()> {
        self.storage.flush()
    }

    pub fn insert_object(
        &mut self,
        s_handle: CK_SESSION_HANDLE,
        mut obj: Object,
    ) -> KResult<CK_OBJECT_HANDLE> {
        let uid = obj.get_attr_as_string(CKA_UNIQUE_ID)?;
        let is_token = match obj.get_attr_as_bool(CKA_TOKEN) {
            Ok(t) => t,
            Err(_) => return err_rv!(CKR_GENERAL_ERROR),
        };
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
        self.storage.store(&uid, obj)?;
        Ok(handle)
    }

    pub fn create_object(
        &mut self,
        s_handle: CK_SESSION_HANDLE,
        template: &[CK_ATTRIBUTE],
    ) -> KResult<CK_OBJECT_HANDLE> {
        if !self.is_logged_in(KRY_UNSPEC) {
            return err_rv!(CKR_USER_NOT_LOGGED_IN);
        }

        let object = self.object_factories.create(template)?;
        self.insert_object(s_handle, object)
    }

    pub fn destroy_object(
        &mut self,
        o_handle: CK_OBJECT_HANDLE,
    ) -> KResult<()> {
        let obj = match self.handles.get(o_handle) {
            Some(s) => self.storage.fetch_by_uid(s)?,
            None => return err_rv!(CKR_OBJECT_HANDLE_INVALID),
        };
        if !obj.is_destroyable() {
            return err_rv!(CKR_ACTION_PROHIBITED);
        }
        if let Some(uid) = self.handles.remove(o_handle) {
            self.storage.remove_by_uid(&uid)
        } else {
            err_rv!(CKR_OBJECT_HANDLE_INVALID)
        }
    }

    pub fn get_token_info(&self) -> &CK_TOKEN_INFO {
        &self.info
    }

    pub fn get_object_attrs(
        &mut self,
        o_handle: CK_OBJECT_HANDLE,
        template: &mut [CK_ATTRIBUTE],
    ) -> KResult<()> {
        let is_logged = self.is_logged_in(KRY_UNSPEC);
        let obj = match self.handles.get(o_handle) {
            Some(s) => self.storage.fetch_by_uid(s)?,
            None => return err_rv!(CKR_OBJECT_HANDLE_INVALID),
        };
        if !is_logged && obj.is_private() {
            /* do not reveal if the object exists or not */
            return err_rv!(CKR_OBJECT_HANDLE_INVALID);
        }
        self.object_factories.get_object_attributes(obj, template)
    }

    pub fn set_object_attrs(
        &mut self,
        o_handle: CK_OBJECT_HANDLE,
        template: &mut [CK_ATTRIBUTE],
    ) -> KResult<()> {
        let uid = match self.handles.get(o_handle) {
            Some(u) => u,
            None => return err_rv!(CKR_OBJECT_HANDLE_INVALID),
        };
        let mut obj = self.storage.fetch_by_uid(uid)?.clone();
        self.object_factories
            .set_object_attributes(&mut obj, template)?;
        self.storage.store(uid, obj)
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
    ) -> KResult<&CK_MECHANISM_INFO> {
        match self.mechanisms.info(typ) {
            Some(m) => Ok(m),
            None => err_rv!(CKR_MECHANISM_INVALID),
        }
    }

    pub fn get_object_size(
        &self,
        o_handle: CK_OBJECT_HANDLE,
    ) -> KResult<usize> {
        /* no need to force fetch from storage, this is always just an estimate */
        match self.handles.get(o_handle) {
            Some(s) => self.storage.get_cached_by_uid(s)?.rough_size(),
            None => err_rv!(CKR_OBJECT_HANDLE_INVALID),
        }
    }

    pub fn copy_object(
        &mut self,
        s_handle: CK_SESSION_HANDLE,
        o_handle: CK_OBJECT_HANDLE,
        template: &[CK_ATTRIBUTE],
    ) -> KResult<CK_OBJECT_HANDLE> {
        let is_logged_in = self.is_logged_in(KRY_UNSPEC);
        let obj = match self.handles.get(o_handle) {
            Some(s) => self.storage.fetch_by_uid(s)?,
            None => return err_rv!(CKR_OBJECT_HANDLE_INVALID),
        };
        if !is_logged_in && obj.is_private() {
            return err_rv!(CKR_USER_NOT_LOGGED_IN);
        }
        let newobj = self.object_factories.copy(obj, template)?;
        self.insert_object(s_handle, newobj)
    }

    pub fn search_objects(
        &mut self,
        template: &[CK_ATTRIBUTE],
    ) -> KResult<Vec<CK_OBJECT_HANDLE>> {
        let mut handles = Vec::<CK_OBJECT_HANDLE>::new();
        let mut needs_handle = Vec::<String>::new();
        let is_logged_in = self.is_logged_in(KRY_UNSPEC);
        let ret = self.storage.search(template)?;
        for o in ret {
            if !is_logged_in && o.is_private() {
                continue;
            }

            if o.is_sensitive() {
                match self.object_factories.check_sensitive(o, template) {
                    Err(_) => continue,
                    Ok(()) => (),
                }
            }

            let oh = o.get_handle();
            if oh == CK_INVALID_HANDLE {
                let uid = match o.get_attr_as_string(CKA_UNIQUE_ID) {
                    Ok(s) => s,
                    Err(_) => return err_rv!(CKR_GENERAL_ERROR),
                };
                needs_handle.push(uid.clone());
            } else {
                handles.push(oh);
            }
        }
        while let Some(uid) = needs_handle.pop() {
            /* do not return internal objects */
            if let Ok(numuid) = uid.parse::<usize>() {
                if numuid < 10 {
                    continue;
                }
            }
            let oh = self.handles.next();
            let obj = match self.storage.get_cached_by_uid_mut(&uid) {
                Ok(o) => o,
                Err(_) => continue,
            };
            obj.set_handle(oh);
            self.handles.insert(oh, uid);
            handles.push(oh);
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
