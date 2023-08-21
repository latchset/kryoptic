// Copyright 2023 Simo Sorce
// See LICENSE.txt file for terms

use std::collections::HashMap;
use std::vec::Vec;

use serde::{Serialize, Deserialize};
use serde_json;

use super::interface;
use super::attribute;
use super::session;
use super::object;
use super::error;

use interface::*;
use session::Session;
use object::Object;
use error::{KResult, KError};
use super::{err_rv, err_not_found};

use getrandom;

static TOKEN_LABEL: [CK_UTF8CHAR; 32usize] = *b"Kryoptic FIPS Token             ";
static MANUFACTURER_ID: [CK_UTF8CHAR; 32usize] = *b"Kryoptic                        ";
static TOKEN_MODEL: [CK_UTF8CHAR; 16usize] = *b"FIPS-140-3 v1   ";
static TOKEN_SERIAL: [CK_UTF8CHAR; 16usize] = *b"0000000000000000";

#[derive(Debug, Serialize, Deserialize)]
struct JsonToken {
    objects: Vec<JsonObject>,
}

#[derive(Debug, Serialize, Deserialize)]
struct JsonObject {
    attributes: serde_json::Map<String, serde_json::Value>
}

#[derive(Debug, Clone)]
struct LoginData {
    user_pin: Option<Vec<u8>>,
    max_attempts: CK_ULONG,
    attempts: CK_ULONG,
    logged_in: bool,
}

#[derive(Debug, Clone)]
pub struct Token {
    info: CK_TOKEN_INFO,
    objects: HashMap<String, Object>,
    dirty: bool,
    login: LoginData,
    handles: HashMap<CK_OBJECT_HANDLE, String>,
    next_handle: CK_OBJECT_HANDLE,
}

impl Token {
    pub fn load(filename: &str) -> KResult<Token> {

        let mut t = Token {
            info: CK_TOKEN_INFO {
                label: TOKEN_LABEL,
                manufacturerID: MANUFACTURER_ID,
                model: TOKEN_MODEL,
                serialNumber: TOKEN_SERIAL,
                flags: Token::token_flags(),
                ulMaxSessionCount: CK_EFFECTIVELY_INFINITE,
                ulSessionCount: 0,
                ulMaxRwSessionCount: CK_EFFECTIVELY_INFINITE,
                ulRwSessionCount: 0,
                ulMaxPinLen: CK_EFFECTIVELY_INFINITE,
                ulMinPinLen: CK_EFFECTIVELY_INFINITE,
                ulTotalPublicMemory: 0,
                ulFreePublicMemory: 0,
                ulTotalPrivateMemory: 0,
                ulFreePrivateMemory: 0,
                hardwareVersion: CK_VERSION {
                    major: 0,
                    minor: 0,
                },
                firmwareVersion: CK_VERSION {
                    major: 0,
                    minor: 0,
                },
                utcTime: *b"0000000000000000",
            },
            objects: HashMap::new(),
            login: LoginData {
                user_pin: None,
                max_attempts: 0,
                attempts: 0,
                logged_in: false,
            },
            dirty: false,
            handles: HashMap::new(),
            next_handle: 1,
        };

        let file = match std::fs::File::open(filename) {
            Ok(f) => f,
            Err(e) => {
                return Err(KError::FileError(e));
            }
        };
        match serde_json::from_reader::<std::fs::File, JsonToken>(file) {
            Ok(j) => t.json_to_objects(&j.objects)?,
            Err(e) => return Err(KError::JsonError(e)),
        }
        Ok(t)
    }

    fn next_object_handle(&mut self) -> CK_SESSION_HANDLE {
        /* if we ever implement reloading from file,
         * we'll want to pass the CKA_UNIQUE_ID object to this call and look
         * in the handles cache to see if a handle has already been assigned
         * to this object before */
        let handle = self.next_handle;
        self.next_handle += 1;
        handle
    }

    fn objects_to_json(&self) -> Vec<JsonObject> {
        let mut jobjs = Vec::new();

        for (_h, o) in &self.objects {
            match o.get_attr_as_bool(CKA_TOKEN) {
                Ok(t) => if !t {
                    continue;
                },
                Err(_) => continue,
            }
            let mut jo = JsonObject {
                attributes: serde_json::Map::new()
            };
            for a in o.get_attributes() {
                jo.attributes.insert(a.name(), a.json_value());
            }
            jobjs.push(jo);
        }
        jobjs
    }

    fn json_to_objects(&mut self, jobjs: &Vec<JsonObject>) -> KResult<()> {
        for jo in jobjs {
            let mut obj = Object::new(self.next_object_handle());
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
            self.handles.insert(obj.get_handle(), uid.clone());
            self.objects.insert(uid, obj);
        }
        Ok(())
    }

    pub fn get_object_by_handle(&self, handle: CK_OBJECT_HANDLE, checks: bool) -> KResult<&Object> {
        let obj = match self.handles.get(&handle) {
            Some(s) => match self.objects.get(s) {
                Some(o) => o,
                None => return err_not_found!{s.clone()},
            },
            None => return err_rv!(CKR_OBJECT_HANDLE_INVALID),
        };
        if checks && !self.login.logged_in && obj.is_private() {
            return err_rv!(CKR_OBJECT_HANDLE_INVALID)
        }
        Ok(obj)
    }

    fn get_login_data(&mut self) -> KResult<()> {
        let obj = match self.objects.get(&"1".to_string()) {
            Some(o) => o,
            None => return err_rv!(CKR_USER_PIN_NOT_INITIALIZED),
        };
        if obj.get_attr_as_ulong(CKA_CLASS)? != CKO_SECRET_KEY {
            return err_rv!(CKR_GENERAL_ERROR);
        }
        if obj.get_attr_as_ulong(CKA_KEY_TYPE)? != CKK_GENERIC_SECRET {
            return err_rv!(CKR_GENERAL_ERROR);
        }
        if obj.get_attr_as_string(CKA_LABEL)? != "User PIN" {
            return err_rv!(CKR_GENERAL_ERROR);
        }
        let value = obj.get_attr_as_bytes(CKA_VALUE)?;
        let max = match obj.get_attr_as_ulong(KRYATTR_MAX_LOGIN_ATTEMPTS) {
            Ok(n) => n,
            Err(_) => 10,
        };

        self.login.user_pin = Some(value.clone());
        self.login.max_attempts = max;
        Ok(())
    }

    pub fn login(&mut self, user_type: CK_USER_TYPE, pin: &Vec<u8>) -> CK_RV {
        match user_type {
            CKU_SO => {
                /* not supported yet */
                return CKR_OPERATION_NOT_INITIALIZED;
            },
            CKU_USER => {
                if self.login.user_pin.is_none() {
                    match self.get_login_data() {
                        Ok(_) => (),
                        Err(_) => return CKR_USER_PIN_NOT_INITIALIZED,
                    }
                }

                if self.login.attempts >= self.login.max_attempts {
                    return CKR_PIN_LOCKED
                }
                if self.login.logged_in {
                    return CKR_USER_ALREADY_LOGGED_IN
                }
                match &self.login.user_pin {
                    Some(p) => {
                        if p == pin {
                            self.login.logged_in = true;
                            self.login.attempts = 0;
                            return CKR_OK;
                        }
                        self.login.attempts += 1;
                        return CKR_PIN_INCORRECT;
                    },
                    None => {
                        return CKR_USER_PIN_NOT_INITIALIZED
                    }
                }
            },
            CKU_CONTEXT_SPECIFIC => {
                /* not supported yet */
                return CKR_OPERATION_NOT_INITIALIZED;
            },
            _ => return CKR_USER_TYPE_INVALID,
        }
    }

    pub fn logout(&mut self) -> CK_RV {
        if !self.login.logged_in {
            return CKR_USER_NOT_LOGGED_IN;
        }
        self.login.logged_in = false;
        CKR_OK
    }

    pub fn save(&self, filename: &str) -> KResult<()> {
        if !self.dirty {
            return Ok(())
        }
        let token = JsonToken {
            objects: self.objects_to_json(),
        };
        let j = match serde_json::to_string_pretty(&token) {
            Ok(j) => j,
            Err(e) => return Err(KError::JsonError(e)),
        };
        match std::fs::write(filename, j) {
            Ok(_) => Ok(()),
            Err(e) => Err(KError::FileError(e)),
        }
    }

    pub fn create_object(&mut self, session: &mut Session, template: &[CK_ATTRIBUTE]) -> KResult<CK_OBJECT_HANDLE> {

        if !self.login.logged_in {
            return err_rv!(CKR_USER_NOT_LOGGED_IN);
        }

        let obj = object::create(self.next_object_handle(), template)?;
        let handle = obj.get_handle();
        match obj.get_attr_as_bool(CKA_TOKEN) {
            Ok(t) => if t {
                if !session.is_writable() {
                    return err_rv!(CKR_SESSION_READ_ONLY);
                }
                self.dirty = true;
            } else {
                session.add_handle(handle);
            },
            Err(_) => return err_rv!(CKR_GENERAL_ERROR),
        }
        let uid = obj.get_attr_as_string(CKA_UNIQUE_ID)?;
        self.handles.insert(handle, uid.clone());
        self.objects.insert(uid.clone(), obj);
        Ok(handle)
    }

    fn token_flags() -> CK_FLAGS {
        // FIXME: most of these flags need to be set dynamically
        CKF_RNG | CKF_LOGIN_REQUIRED | CKF_TOKEN_INITIALIZED
    }

    pub fn get_token_info(&self) -> &CK_TOKEN_INFO {
        &self.info
    }

    pub fn search(&self, session: &mut Session, template: &[CK_ATTRIBUTE]) -> KResult<()> {
        session.reset_search_handles();

        for (_, o) in &self.objects {
            if !self.login.logged_in && o.is_private() {
                continue;
            }

            if o.match_template(template) {
                session.add_search_handle(o.get_handle());
            }
        }
        Ok(())
    }

    pub fn get_object_attrs(&self, handle: CK_OBJECT_HANDLE, template: &mut [CK_ATTRIBUTE]) -> KResult<()> {
        match self.get_object_by_handle(handle, true) {
            Ok(o) => o.fill_template(template),
            Err(e) => return Err(e),
        }
    }

    pub fn generate_random(&self, buffer: &mut [u8]) -> KResult<()> {
        /* NOTE: this is just a placeholder to get somethjing going */
        if buffer.len() > 256 {
            return err_rv!(CKR_ARGUMENTS_BAD);
        }
        if getrandom::getrandom(buffer).is_err() {
            return err_rv!(CKR_GENERAL_ERROR)
        }
        Ok(())
    }
}
