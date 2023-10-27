// Copyright 2023 Simo Sorce
// See LICENSE.txt file for terms

use std::collections::HashMap;
use std::vec::Vec;

use serde::{Deserialize, Serialize};
use serde_json;

use super::attribute;
use super::error;
use super::interface;
use super::mechanism;
use super::object;
use super::rsa;
use super::session;
use super::sha2;

use super::{err_not_found, err_rv};
use error::{KError, KResult};
use interface::*;
use mechanism::{Mechanisms, Operation};
use object::{Object, ObjectTemplates};
use session::{Session, Sessions};

use std::collections::hash_map::Iter;

use getrandom;

static TOKEN_LABEL: [CK_UTF8CHAR; 32usize] =
    *b"Kryoptic FIPS Token             ";
static MANUFACTURER_ID: [CK_UTF8CHAR; 32usize] =
    *b"Kryoptic                        ";
static TOKEN_MODEL: [CK_UTF8CHAR; 16usize] = *b"FIPS-140-3 v1   ";
static TOKEN_SERIAL: [CK_UTF8CHAR; 16usize] = *b"0000000000000000";

#[derive(Debug, Serialize, Deserialize)]
struct JsonToken {
    objects: Vec<JsonObject>,
}

#[derive(Debug, Serialize, Deserialize)]
struct JsonObject {
    attributes: serde_json::Map<String, serde_json::Value>,
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
        self.max_attempts = 10;
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

#[derive(Debug)]
pub struct RNG {
    initialized: bool,
}

impl RNG {
    pub fn new() -> RNG {
        RNG { initialized: true }
    }

    /* NOTE: this is just a placeholder to get somethjing going */
    pub fn generate_random(&self, buffer: &mut [u8]) -> KResult<()> {
        if !self.initialized {
            return err_rv!(CKR_GENERAL_ERROR);
        }
        if buffer.len() > 256 {
            return err_rv!(CKR_ARGUMENTS_BAD);
        }
        if getrandom::getrandom(buffer).is_err() {
            return err_rv!(CKR_GENERAL_ERROR);
        }
        Ok(())
    }
}

#[derive(Debug)]
pub struct TokenObjects {
    objects: HashMap<String, Object>,
    handles: HashMap<CK_OBJECT_HANDLE, String>,
    next_handle: CK_OBJECT_HANDLE,
}

impl TokenObjects {
    fn new() -> TokenObjects {
        TokenObjects {
            objects: HashMap::new(),
            handles: HashMap::new(),
            next_handle: 1,
        }
    }

    fn initialize(&mut self) {
        self.objects = HashMap::new();
        self.handles = HashMap::new();
        self.next_handle = 1;
    }

    fn get(&self, uid: &String) -> Option<&Object> {
        self.objects.get(uid)
    }

    pub fn get_mut(&mut self, uid: &String) -> Option<&mut Object> {
        self.objects.get_mut(uid)
    }

    fn insert(&mut self, uid: String, obj: Object) {
        self.objects.insert(uid, obj);
    }

    pub fn iter(&self) -> Iter<'_, String, Object> {
        self.objects.iter()
    }

    pub fn remove(
        &mut self,
        handle: CK_OBJECT_HANDLE,
        session_only: bool,
    ) -> KResult<()> {
        let uid = match self.handles.get(&handle) {
            Some(u) => u,
            None => return err_rv!(CKR_OBJECT_HANDLE_INVALID),
        };
        let obj = match self.objects.get(uid) {
            Some(o) => o,
            None => {
                self.handles.remove(&handle);
                return err_rv!(CKR_OBJECT_HANDLE_INVALID);
            }
        };
        if session_only && obj.is_token() {
            return err_rv!(CKR_ACTION_PROHIBITED);
        }

        self.objects.remove(uid);
        self.handles.remove(&handle);
        Ok(())
    }

    pub fn next_handle(&mut self) -> CK_OBJECT_HANDLE {
        let next = self.next_handle;
        self.next_handle += 1;
        next
    }

    fn get_by_handle(&self, handle: CK_OBJECT_HANDLE) -> KResult<&Object> {
        match self.handles.get(&handle) {
            Some(s) => match self.objects.get(s) {
                Some(o) => Ok(o),
                None => err_not_found! {s.clone()},
            },
            None => err_rv!(CKR_OBJECT_HANDLE_INVALID),
        }
    }

    fn get_by_handle_mut(
        &mut self,
        handle: CK_OBJECT_HANDLE,
    ) -> KResult<&mut Object> {
        match self.handles.get(&handle) {
            Some(s) => match self.objects.get_mut(s) {
                Some(o) => Ok(o),
                None => err_not_found! {s.clone()},
            },
            None => err_rv!(CKR_OBJECT_HANDLE_INVALID),
        }
    }

    pub fn insert_handle(&mut self, oh: CK_OBJECT_HANDLE, uid: String) {
        self.handles.insert(oh, uid);
    }

    fn object_to_json(&self, o: &Object) -> JsonObject {
        let mut jo = JsonObject {
            attributes: serde_json::Map::new(),
        };
        for a in o.get_attributes() {
            jo.attributes.insert(a.name(), a.json_value());
        }
        jo
    }

    fn to_json(&self) -> Vec<JsonObject> {
        let mut jobjs = Vec::new();

        for (_h, o) in &self.objects {
            if !o.is_token() {
                continue;
            }
            jobjs.push(self.object_to_json(o));
        }
        jobjs
    }

    fn from_json(&mut self, jobjs: &Vec<JsonObject>) -> KResult<()> {
        for jo in jobjs {
            let mut obj = Object::new();
            let mut uid: String = String::new();
            for (key, val) in &jo.attributes {
                let attr = attribute::from_value(key.clone(), &val)?;
                obj.set_attr(attr)?;
                if key == "CKA_UNIQUE_ID" {
                    uid = match val.as_str() {
                        Some(s) => s.to_string(),
                        None => return err_rv!(CKR_DEVICE_ERROR),
                    }
                }
            }
            if uid.len() == 0 {
                return err_rv!(CKR_DEVICE_ERROR);
            }
            self.objects.insert(uid, obj);
        }
        Ok(())
    }

    fn clear_private_session_objects(&mut self) -> Vec<CK_OBJECT_HANDLE> {
        let mut priv_handles = Vec::<CK_OBJECT_HANDLE>::new();
        let mut priv_uids = Vec::<String>::new();
        for (_, obj) in &self.objects {
            if obj.is_private() {
                let oh = obj.get_handle();
                if oh != CK_UNAVAILABLE_INFORMATION {
                    priv_handles.push(oh);
                    let _ = self.handles.remove(&oh);
                }
                if !obj.is_token() {
                    /* not a token object, therefore we need to destroy it */
                    let uid = match obj.get_attr_as_string(CKA_UNIQUE_ID) {
                        Ok(u) => u,
                        Err(_) => continue,
                    };
                    priv_uids.push(uid.clone());
                }
            }
        }

        /* remove all private session objects */
        for uid in priv_uids {
            self.objects.remove(&uid);
        }
        priv_handles
    }

    pub fn clear_session_objects(&mut self, handles: &Vec<CK_OBJECT_HANDLE>) {
        for oh in handles {
            let _ = self.remove(*oh, true);
        }
    }

    pub fn object_rough_size(
        &self,
        handle: CK_OBJECT_HANDLE,
    ) -> KResult<usize> {
        let obj = self.get_by_handle(handle)?;
        let jo = self.object_to_json(obj);
        match serde_json::to_string(&jo) {
            Ok(js) => Ok(js.len()),
            Err(_) => err_rv!(CKR_GENERAL_ERROR),
        }
    }
}

#[derive(Debug)]
pub struct Token {
    info: CK_TOKEN_INFO,
    slot_id: CK_SLOT_ID,
    filename: String,
    object_templates: ObjectTemplates,
    mechanisms: Mechanisms,
    sessions: Sessions,
    objects: TokenObjects,
    dirty: bool,
    so_login: LoginData,
    user_login: LoginData,
    rng: RNG,
}

impl Token {
    pub fn new(slot_id: CK_SLOT_ID, filename: String) -> Token {
        let mut token: Token = Token {
            info: CK_TOKEN_INFO {
                label: TOKEN_LABEL,
                manufacturerID: MANUFACTURER_ID,
                model: TOKEN_MODEL,
                serialNumber: TOKEN_SERIAL,
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
            slot_id: slot_id,
            filename: filename,
            object_templates: ObjectTemplates::new(),
            mechanisms: Mechanisms::new(),
            sessions: Sessions::new(),
            objects: TokenObjects::new(),
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
            dirty: false,
            rng: RNG::new(),
        };

        /* register mechanisms and templates */
        rsa::register(&mut token.mechanisms, &mut token.object_templates);
        sha2::register(&mut token.mechanisms, &mut token.object_templates);

        token
    }

    pub fn get_filename(&self) -> &String {
        &self.filename
    }

    pub fn load(&mut self) -> KResult<()> {
        if self.is_initialized() {
            return err_rv!(CKR_GENERAL_ERROR);
        }
        match std::fs::File::open(&self.filename) {
            Ok(f) => {
                match serde_json::from_reader::<std::fs::File, JsonToken>(f) {
                    Ok(j) => self.objects.from_json(&j.objects)?,
                    Err(e) => return Err(KError::JsonError(e)),
                }
            }
            Err(e) => match e.kind() {
                std::io::ErrorKind::NotFound => return Ok(()),
                _ => return Err(KError::FileError(e)),
            },
        };
        self.info.flags |= CKF_TOKEN_INITIALIZED;
        Ok(())
    }

    pub fn is_initialized(&self) -> bool {
        self.info.flags & CKF_TOKEN_INITIALIZED == CKF_TOKEN_INITIALIZED
    }

    fn store_pin_object(
        &mut self,
        uid: String,
        label: String,
        pin: Vec<u8>,
    ) -> KResult<()> {
        match self.objects.get_mut(&uid) {
            Some(obj) => {
                obj.set_attr(attribute::from_bytes(CKA_VALUE, pin))?;
            }
            None => {
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
                self.objects.insert(uid, obj);
            }
        }
        return Ok(());
    }

    pub fn initialize(&mut self, pin: &Vec<u8>, _label: &Vec<u8>) -> CK_RV {
        let ret = if self.is_initialized() {
            self.login(CKU_SO, pin)
        } else {
            self.so_login.set_pin(&self.info, pin)
        };
        if ret != CKR_OK {
            return ret;
        }
        self.so_login.logged_in = false;
        self.objects.initialize();
        self.dirty = true;

        /* add pin to so_object */
        match self.store_pin_object(
            "0".to_string(),
            "SO PIN".to_string(),
            pin.clone(),
        ) {
            Ok(()) => (),
            Err(_) => return CKR_GENERAL_ERROR,
        }

        match self.save() {
            Ok(_) => {
                self.info.flags |= CKF_TOKEN_INITIALIZED;
                CKR_OK
            }
            Err(_) => CKR_GENERAL_ERROR,
        }
    }

    pub fn get_object_by_handle(
        &self,
        handle: CK_OBJECT_HANDLE,
        checks: bool,
    ) -> KResult<&Object> {
        let obj = match self.objects.get_by_handle(handle) {
            Ok(o) => o,
            Err(e) => return Err(e),
        };
        if checks && !self.user_login.logged_in && obj.is_private() {
            return err_rv!(CKR_OBJECT_HANDLE_INVALID);
        }
        Ok(obj)
    }

    fn validate_pin_obj(
        &self,
        obj: &Object,
        label: String,
    ) -> KResult<(Vec<u8>, CK_ULONG)> {
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
        let max = match obj.get_attr_as_ulong(KRYATTR_MAX_LOGIN_ATTEMPTS) {
            Ok(n) => n,
            Err(_) => 10,
        };

        Ok((value.clone(), max as CK_ULONG))
    }

    fn get_so_login_data(&mut self) -> KResult<()> {
        if self.so_login.pin.is_none() {
            let obj = match self.objects.get(&"0".to_string()) {
                Some(o) => o,
                None => return err_rv!(CKR_GENERAL_ERROR),
            };
            let (pin, max) =
                self.validate_pin_obj(obj, "SO PIN".to_string())?;
            self.so_login.pin = Some(pin);
            self.so_login.max_attempts = max;
        }
        Ok(())
    }

    fn get_user_login_data(&mut self) -> KResult<()> {
        if self.user_login.pin.is_none() {
            let obj = match self.objects.get(&"1".to_string()) {
                Some(o) => o,
                None => return err_rv!(CKR_USER_PIN_NOT_INITIALIZED),
            };
            let (pin, max) =
                self.validate_pin_obj(obj, "User PIN".to_string())?;
            self.user_login.pin = Some(pin);
            self.user_login.max_attempts = max;
        }
        Ok(())
    }

    pub fn login(&mut self, user_type: CK_USER_TYPE, pin: &Vec<u8>) -> CK_RV {
        let mut ret = match user_type {
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
        if ret != CKR_OK {
            return ret;
        }

        /* change session states to logged in values */
        ret = self.sessions.change_session_states(user_type);
        if ret != CKR_OK {
            match user_type {
                CKU_SO => self.so_login.logged_in = false,
                CKU_USER => self.user_login.logged_in = false,
                _ => return CKR_GENERAL_ERROR,
            }
            self.sessions.invalidate_session_states();
        }
        ret
    }

    pub fn logout(&mut self) -> CK_RV {
        let mut ret = CKR_USER_NOT_LOGGED_IN;
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

        /* remove private session objects and return all the removed handles */
        let mut priv_handles = self.objects.clear_private_session_objects();

        /* remove all refrences to private session handles for removed objects */
        priv_handles.sort_unstable();
        for s in self.sessions.get_sessions_iter_mut() {
            let mut pub_handles = Vec::<CK_OBJECT_HANDLE>::new();
            for oh in s.get_object_handles() {
                match priv_handles.binary_search(oh) {
                    Ok(_) => continue,
                    Err(_) => pub_handles.push(*oh),
                }
            }
            /* replace handles list with the remaining public object handles only */
            s.set_object_handles(pub_handles);
        }

        /* reset all session states */
        self.sessions.invalidate_session_states();
        CKR_OK
    }

    pub fn is_logged_in(&self, user_type: CK_USER_TYPE) -> bool {
        match user_type {
            CK_UNAVAILABLE_INFORMATION => {
                self.so_login.logged_in || self.user_login.logged_in
            }
            CKU_SO => self.so_login.logged_in,
            CKU_USER => self.user_login.logged_in,
            _ => false,
        }
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
                    "1".to_string(),
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
                    "0".to_string(),
                    "SO PIN".to_string(),
                    pin.clone(),
                ) {
                    Ok(()) => (),
                    Err(_) => return CKR_GENERAL_ERROR,
                }
            }
            _ => return CKR_GENERAL_ERROR,
        }

        self.dirty = true;
        match self.save() {
            Ok(()) => CKR_OK,
            Err(_) => CKR_GENERAL_ERROR,
        }
    }

    pub fn save(&self) -> KResult<()> {
        if !self.dirty {
            return Ok(());
        }
        let token = JsonToken {
            objects: self.objects.to_json(),
        };
        let j = match serde_json::to_string_pretty(&token) {
            Ok(j) => j,
            Err(e) => return Err(KError::JsonError(e)),
        };
        match std::fs::write(&self.filename, j) {
            Ok(_) => Ok(()),
            Err(e) => Err(KError::FileError(e)),
        }
    }

    fn insert_object(
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
            if !self.sessions.get_session(s_handle)?.is_writable() {
                return err_rv!(CKR_SESSION_READ_ONLY);
            }
            self.dirty = true;
        }
        let handle = self.objects.next_handle();
        obj.set_handle(handle);
        self.objects.insert_handle(handle, uid.clone());
        self.objects.insert(uid.clone(), obj);
        if !is_token {
            self.sessions.get_session_mut(s_handle)?.add_handle(handle);
        }
        Ok(handle)
    }

    pub fn create_object(
        &mut self,
        s_handle: CK_SESSION_HANDLE,
        template: &[CK_ATTRIBUTE],
    ) -> KResult<CK_OBJECT_HANDLE> {
        /* check that session is valid */
        let _ = self.sessions.get_session(s_handle)?;

        if !self.user_login.logged_in {
            return err_rv!(CKR_USER_NOT_LOGGED_IN);
        }

        let object = self.object_templates.create(template)?;
        self.insert_object(s_handle, object)
    }

    pub fn destroy_object(
        &mut self,
        s_handle: CK_SESSION_HANDLE,
        o_handle: CK_OBJECT_HANDLE,
    ) -> KResult<()> {
        let session = self.sessions.get_session_mut(s_handle)?;
        let obj = self.objects.get_by_handle(o_handle)?;
        if obj.is_private() && !self.user_login.logged_in {
            return err_rv!(CKR_ACTION_PROHIBITED);
        }
        if obj.is_token() && !session.is_writable() {
            return err_rv!(CKR_ACTION_PROHIBITED);
        }
        if !obj.is_destroyable() {
            return err_rv!(CKR_ACTION_PROHIBITED);
        }
        self.objects.remove(o_handle, false)
    }

    pub fn get_token_info(&self) -> &CK_TOKEN_INFO {
        &self.info
    }

    pub fn get_object_attrs(
        &self,
        handle: CK_OBJECT_HANDLE,
        template: &mut [CK_ATTRIBUTE],
    ) -> KResult<()> {
        match self.get_object_by_handle(handle, true) {
            Ok(o) => self.object_templates.get_object_attributes(o, template),
            Err(e) => Err(e),
        }
    }

    pub fn set_object_attrs(
        &mut self,
        s_handle: CK_SESSION_HANDLE,
        handle: CK_OBJECT_HANDLE,
        template: &mut [CK_ATTRIBUTE],
    ) -> KResult<()> {
        let obj = match self.objects.get_by_handle_mut(handle) {
            Ok(o) => o,
            Err(e) => return Err(e),
        };
        if !self.user_login.logged_in {
            if obj.is_private() {
                return err_rv!(CKR_OBJECT_HANDLE_INVALID);
            }
        }
        if obj.is_token() {
            if !self.user_login.logged_in {
                return err_rv!(CKR_USER_NOT_LOGGED_IN);
            }
            if !self.sessions.get_session(s_handle)?.is_writable() {
                return err_rv!(CKR_SESSION_READ_ONLY);
            }
        }
        self.object_templates.set_object_attributes(obj, template)?;
        self.dirty = true;
        Ok(())
    }

    pub fn generate_random(&self, buffer: &mut [u8]) -> KResult<()> {
        self.rng.generate_random(buffer)
    }

    pub fn new_session(
        &mut self,
        handle: CK_SESSION_HANDLE,
        flags: CK_FLAGS,
    ) -> KResult<&Session> {
        self.sessions.new_session(self.slot_id, handle, flags)
    }

    pub fn get_session(&self, handle: CK_SESSION_HANDLE) -> KResult<&Session> {
        self.sessions.get_session(handle)
    }

    pub fn drop_session(&mut self, handle: CK_SESSION_HANDLE) -> KResult<()> {
        let session = self.sessions.get_session(handle)?;
        let handles = session.get_object_handles();
        self.objects.clear_session_objects(handles);
        self.sessions.drop_session(handle)
    }

    pub fn drop_all_sessions(&mut self) {
        for s in self.sessions.get_sessions() {
            let handles = s.get_object_handles();
            self.objects.clear_session_objects(handles);
        }
        self.sessions.drop_all_sessions();
    }

    pub fn has_sessions(&self) -> bool {
        self.sessions.has_sessions()
    }

    pub fn has_ro_sessions(&self) -> bool {
        self.sessions.has_ro_sessions()
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
        s_handle: CK_SESSION_HANDLE,
        o_handle: CK_OBJECT_HANDLE,
    ) -> KResult<usize> {
        let _ = self.sessions.get_session(s_handle)?;
        self.objects.object_rough_size(o_handle)
    }

    pub fn copy_object(
        &mut self,
        s_handle: CK_SESSION_HANDLE,
        o_handle: CK_OBJECT_HANDLE,
        template: &[CK_ATTRIBUTE],
    ) -> KResult<CK_OBJECT_HANDLE> {
        /* check that session is valid */
        let _ = self.sessions.get_session(s_handle)?;

        let obj = self.objects.get_by_handle(o_handle)?;
        if obj.is_private() && !self.user_login.logged_in {
            return err_rv!(CKR_ACTION_PROHIBITED);
        }
        let newobj = self.object_templates.copy(obj, template)?;
        self.insert_object(s_handle, newobj)
    }

    pub fn search_objects(
        &mut self,
        handle: CK_SESSION_HANDLE,
        template: &[CK_ATTRIBUTE],
    ) -> KResult<()> {
        let logged_in = self.user_login.logged_in;
        let session = self.sessions.get_session_mut(handle)?;
        session.new_search_operation(logged_in)?;
        let operation = match session.get_operation_mut() {
            Operation::Search(op) => op,
            Operation::Empty => return err_rv!(CKR_OPERATION_NOT_INITIALIZED),
            _ => return err_rv!(CKR_OPERATION_ACTIVE),
        };
        operation.search(&self.object_templates, &mut self.objects, template)
    }

    pub fn search_results(
        &mut self,
        handle: CK_SESSION_HANDLE,
        max: usize,
    ) -> KResult<Vec<CK_OBJECT_HANDLE>> {
        let session = self.sessions.get_session_mut(handle)?;
        let operation = match session.get_operation_mut() {
            Operation::Search(op) => op,
            Operation::Empty => return err_rv!(CKR_OPERATION_NOT_INITIALIZED),
            _ => return err_rv!(CKR_OPERATION_ACTIVE),
        };
        operation.results(max)
    }

    pub fn search_final(&mut self, handle: CK_SESSION_HANDLE) -> KResult<()> {
        let session = self.sessions.get_session_mut(handle)?;
        match session.get_operation() {
            Operation::Search(_) => (),
            Operation::Empty => return err_rv!(CKR_OPERATION_NOT_INITIALIZED),
            _ => return err_rv!(CKR_OPERATION_ACTIVE),
        };
        session.set_operation(Operation::Empty);
        Ok(())
    }

    pub fn encrypt_init(
        &mut self,
        handle: CK_SESSION_HANDLE,
        data: &CK_MECHANISM,
        key: CK_OBJECT_HANDLE,
    ) -> KResult<()> {
        let session = self.sessions.get_session(handle)?;
        match session.get_operation() {
            Operation::Empty => (),
            _ => return err_rv!(CKR_OPERATION_ACTIVE),
        }
        let mech = self.mechanisms.get(data.mechanism)?;
        let obj = self.get_object_by_handle(key, true)?;
        if mech.info().flags & CKF_ENCRYPT == CKF_ENCRYPT {
            let operation = mech.encryption_new(data, obj)?;
            let session = self.sessions.get_session_mut(handle)?;
            session.set_operation(Operation::Encryption(operation));
            Ok(())
        } else {
            err_rv!(CKR_MECHANISM_INVALID)
        }
    }

    pub fn encrypt(
        &mut self,
        handle: CK_SESSION_HANDLE,
        plain: CK_BYTE_PTR,
        plain_len: CK_ULONG,
        cipher: CK_BYTE_PTR,
        cipher_len: CK_ULONG_PTR,
    ) -> KResult<()> {
        let session = self.sessions.get_session_mut(handle)?;
        let operation = match session.get_operation_mut() {
            Operation::Encryption(op) => op,
            Operation::Empty => return err_rv!(CKR_OPERATION_NOT_INITIALIZED),
            _ => return err_rv!(CKR_OPERATION_ACTIVE),
        };
        if operation.finalized() {
            return err_rv!(CKR_OPERATION_NOT_INITIALIZED);
        }
        let result = operation.encrypt(
            &mut self.rng,
            plain,
            plain_len,
            cipher,
            cipher_len,
        );

        if operation.finalized() {
            session.set_operation(Operation::Empty);
        }

        result
    }

    pub fn encrypt_update(
        &mut self,
        handle: CK_SESSION_HANDLE,
        plain: CK_BYTE_PTR,
        plain_len: CK_ULONG,
        cipher: CK_BYTE_PTR,
        cipher_len: CK_ULONG_PTR,
    ) -> KResult<()> {
        let session = self.sessions.get_session_mut(handle)?;
        let operation = match session.get_operation_mut() {
            Operation::Encryption(op) => op,
            Operation::Empty => return err_rv!(CKR_OPERATION_NOT_INITIALIZED),
            _ => return err_rv!(CKR_OPERATION_ACTIVE),
        };
        if operation.finalized() {
            return err_rv!(CKR_OPERATION_NOT_INITIALIZED);
        }
        let result = operation.encrypt_update(
            &mut self.rng,
            plain,
            plain_len,
            cipher,
            cipher_len,
        );

        if operation.finalized() {
            session.set_operation(Operation::Empty);
        }

        result
    }

    pub fn encrypt_final(
        &mut self,
        handle: CK_SESSION_HANDLE,
        cipher: CK_BYTE_PTR,
        cipher_len: CK_ULONG_PTR,
    ) -> KResult<()> {
        let session = self.sessions.get_session_mut(handle)?;
        let operation = match session.get_operation_mut() {
            Operation::Encryption(op) => op,
            Operation::Empty => return err_rv!(CKR_OPERATION_NOT_INITIALIZED),
            _ => return err_rv!(CKR_OPERATION_ACTIVE),
        };
        if operation.finalized() {
            return err_rv!(CKR_OPERATION_NOT_INITIALIZED);
        }
        if cipher.is_null() && cipher_len.is_null() {
            /* internal convention to ask to terminate the operation */
            session.set_operation(Operation::Empty);
            return Ok(());
        }

        let result = operation.encrypt_final(&mut self.rng, cipher, cipher_len);
        if operation.finalized() {
            session.set_operation(Operation::Empty);
        }

        result
    }

    pub fn decrypt_init(
        &mut self,
        handle: CK_SESSION_HANDLE,
        data: &CK_MECHANISM,
        key: CK_OBJECT_HANDLE,
    ) -> KResult<()> {
        let session = self.sessions.get_session(handle)?;
        match session.get_operation() {
            Operation::Empty => (),
            _ => return err_rv!(CKR_OPERATION_ACTIVE),
        }
        let mech = self.mechanisms.get(data.mechanism)?;
        let obj = self.get_object_by_handle(key, true)?;
        if mech.info().flags & CKF_DECRYPT == CKF_DECRYPT {
            let operation = mech.decryption_new(data, obj)?;
            let session = self.sessions.get_session_mut(handle)?;
            session.set_operation(Operation::Decryption(operation));
            Ok(())
        } else {
            err_rv!(CKR_MECHANISM_INVALID)
        }
    }

    pub fn decrypt(
        &mut self,
        handle: CK_SESSION_HANDLE,
        cipher: CK_BYTE_PTR,
        cipher_len: CK_ULONG,
        plain: CK_BYTE_PTR,
        plain_len: CK_ULONG_PTR,
    ) -> KResult<()> {
        let session = self.sessions.get_session_mut(handle)?;
        let operation = match session.get_operation_mut() {
            Operation::Decryption(op) => op,
            Operation::Empty => return err_rv!(CKR_OPERATION_NOT_INITIALIZED),
            _ => return err_rv!(CKR_OPERATION_ACTIVE),
        };
        if operation.finalized() {
            return err_rv!(CKR_OPERATION_NOT_INITIALIZED);
        }
        let result = operation.decrypt(
            &mut self.rng,
            cipher,
            cipher_len,
            plain,
            plain_len,
        );

        if operation.finalized() {
            session.set_operation(Operation::Empty);
        }

        result
    }

    pub fn decrypt_update(
        &mut self,
        handle: CK_SESSION_HANDLE,
        cipher: CK_BYTE_PTR,
        cipher_len: CK_ULONG,
        plain: CK_BYTE_PTR,
        plain_len: CK_ULONG_PTR,
    ) -> KResult<()> {
        let session = self.sessions.get_session_mut(handle)?;
        let operation = match session.get_operation_mut() {
            Operation::Decryption(op) => op,
            Operation::Empty => return err_rv!(CKR_OPERATION_NOT_INITIALIZED),
            _ => return err_rv!(CKR_OPERATION_ACTIVE),
        };
        if operation.finalized() {
            return err_rv!(CKR_OPERATION_NOT_INITIALIZED);
        }
        let result = operation.decrypt_update(
            &mut self.rng,
            cipher,
            cipher_len,
            plain,
            plain_len,
        );

        if operation.finalized() {
            session.set_operation(Operation::Empty);
        }

        result
    }

    pub fn decrypt_final(
        &mut self,
        handle: CK_SESSION_HANDLE,
        plain: CK_BYTE_PTR,
        plain_len: CK_ULONG_PTR,
    ) -> KResult<()> {
        let session = self.sessions.get_session_mut(handle)?;
        let operation = match session.get_operation_mut() {
            Operation::Decryption(op) => op,
            Operation::Empty => return err_rv!(CKR_OPERATION_NOT_INITIALIZED),
            _ => return err_rv!(CKR_OPERATION_ACTIVE),
        };
        if operation.finalized() {
            return err_rv!(CKR_OPERATION_NOT_INITIALIZED);
        }
        if plain.is_null() && plain_len.is_null() {
            /* internal convention to ask to terminate the operation */
            session.set_operation(Operation::Empty);
            return Ok(());
        }

        let result = operation.decrypt_final(&mut self.rng, plain, plain_len);

        if operation.finalized() {
            session.set_operation(Operation::Empty);
        }

        result
    }

    pub fn digest_init(
        &mut self,
        handle: CK_SESSION_HANDLE,
        data: &CK_MECHANISM,
    ) -> KResult<()> {
        let session = self.sessions.get_session(handle)?;
        match session.get_operation() {
            Operation::Empty => (),
            _ => return err_rv!(CKR_OPERATION_ACTIVE),
        }
        let mech = self.mechanisms.get(data.mechanism)?;
        if mech.info().flags & CKF_DIGEST == CKF_DIGEST {
            let operation = mech.digest_new(data)?;
            let session = self.sessions.get_session_mut(handle)?;
            session.set_operation(Operation::Digest(operation));
            Ok(())
        } else {
            err_rv!(CKR_MECHANISM_INVALID)
        }
    }

    pub fn digest(
        &mut self,
        handle: CK_SESSION_HANDLE,
        data: &[u8],
        digest: CK_BYTE_PTR,
        digest_len: CK_ULONG_PTR,
    ) -> KResult<()> {
        let session = self.sessions.get_session_mut(handle)?;
        let operation = match session.get_operation_mut() {
            Operation::Digest(op) => op,
            Operation::Empty => return err_rv!(CKR_OPERATION_NOT_INITIALIZED),
            _ => return err_rv!(CKR_OPERATION_ACTIVE),
        };
        if operation.finalized() {
            return err_rv!(CKR_OPERATION_NOT_INITIALIZED);
        }
        let result = operation.digest(data, digest, digest_len);

        if operation.finalized() {
            session.set_operation(Operation::Empty);
        }

        result
    }

    pub fn digest_update(
        &mut self,
        handle: CK_SESSION_HANDLE,
        data: &[u8],
    ) -> KResult<()> {
        let session = self.sessions.get_session_mut(handle)?;
        let operation = match session.get_operation_mut() {
            Operation::Digest(op) => op,
            Operation::Empty => return err_rv!(CKR_OPERATION_NOT_INITIALIZED),
            _ => return err_rv!(CKR_OPERATION_ACTIVE),
        };
        if operation.finalized() {
            return err_rv!(CKR_OPERATION_NOT_INITIALIZED);
        }
        let result = operation.digest_update(data);

        if operation.finalized() {
            session.set_operation(Operation::Empty);
        }

        result
    }

    pub fn digest_key(
        &mut self,
        handle: CK_SESSION_HANDLE,
        key: CK_OBJECT_HANDLE,
    ) -> KResult<()> {
        let session = self.sessions.get_session_mut(handle)?;
        let operation = match session.get_operation_mut() {
            Operation::Digest(op) => op,
            Operation::Empty => return err_rv!(CKR_OPERATION_NOT_INITIALIZED),
            _ => return err_rv!(CKR_OPERATION_ACTIVE),
        };
        if operation.finalized() {
            return err_rv!(CKR_OPERATION_NOT_INITIALIZED);
        }
        let obj = match self.objects.get_by_handle(key) {
            Ok(o) => o,
            Err(e) => return Err(e),
        };
        if !self.user_login.logged_in && obj.is_private() {
            return err_rv!(CKR_KEY_HANDLE_INVALID);
        }
        if obj.get_attr_as_ulong(CKA_CLASS)? != CKO_SECRET_KEY {
            return err_rv!(CKR_KEY_HANDLE_INVALID);
        }
        if obj.get_attr_as_ulong(CKA_KEY_TYPE)? != CKK_GENERIC_SECRET {
            return err_rv!(CKR_KEY_INDIGESTIBLE);
        }
        let data = obj.get_attr_as_bytes(CKA_VALUE)?;
        let result = operation.digest_update(data);

        if operation.finalized() {
            session.set_operation(Operation::Empty);
        }

        result
    }

    pub fn digest_final(
        &mut self,
        handle: CK_SESSION_HANDLE,
        digest: CK_BYTE_PTR,
        digest_len: CK_ULONG_PTR,
    ) -> KResult<()> {
        let session = self.sessions.get_session_mut(handle)?;
        let operation = match session.get_operation_mut() {
            Operation::Digest(op) => op,
            Operation::Empty => return err_rv!(CKR_OPERATION_NOT_INITIALIZED),
            _ => return err_rv!(CKR_OPERATION_ACTIVE),
        };
        if operation.finalized() {
            return err_rv!(CKR_OPERATION_NOT_INITIALIZED);
        }
        if digest.is_null() && digest_len.is_null() {
            /* internal convention to ask to terminate the operation */
            session.set_operation(Operation::Empty);
            return Ok(());
        }

        let result = operation.digest_final(digest, digest_len);

        if operation.finalized() {
            session.set_operation(Operation::Empty);
        }

        result
    }
}
