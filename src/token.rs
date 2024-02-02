// Copyright 2023 Simo Sorce
// See LICENSE.txt file for terms

use std::collections::HashMap;
use std::vec::Vec;

use super::aes;
use super::attribute;
use super::error;
use super::hash;
use super::hmac;
use super::interface;
use super::mechanism;
use super::object;
use super::rsa;
use super::storage;

use super::{err_not_found, err_rv};
use error::{KError, KResult};
use interface::*;
use mechanism::Mechanisms;
use object::{Object, ObjectTemplates};

use std::collections::hash_map::Iter;

static TOKEN_LABEL: [CK_UTF8CHAR; 32usize] =
    *b"Kryoptic FIPS Token             ";
static MANUFACTURER_ID: [CK_UTF8CHAR; 32usize] =
    *b"Kryoptic                        ";
static TOKEN_MODEL: [CK_UTF8CHAR; 16usize] = *b"FIPS-140-3 v1   ";
static TOKEN_SERIAL: [CK_UTF8CHAR; 16usize] = *b"0000000000000000";

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

    pub fn len(&self) -> usize {
        self.objects.len()
    }

    fn get(&self, uid: &String) -> Option<&Object> {
        self.objects.get(uid)
    }

    pub fn get_mut(&mut self, uid: &String) -> Option<&mut Object> {
        self.objects.get_mut(uid)
    }

    pub fn insert(&mut self, uid: String, obj: Object) {
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

    fn clear_private_session_objects(&mut self) {
        let mut priv_uids = Vec::<String>::new();
        for (_, obj) in &self.objects {
            if obj.is_private() {
                let oh = obj.get_handle();
                if oh != CK_INVALID_HANDLE {
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
    }

    pub fn clear_session_objects(&mut self, handle: CK_SESSION_HANDLE) {
        let mut handles: Vec<CK_OBJECT_HANDLE> = Vec::new();
        for (_, obj) in &self.objects {
            if obj.get_session() == handle {
                handles.push(obj.get_handle());
            }
        }

        for oh in handles {
            let _ = self.remove(oh, true);
        }
    }

    pub fn object_rough_size(
        &self,
        handle: CK_OBJECT_HANDLE,
    ) -> KResult<usize> {
        let obj = self.get_by_handle(handle)?;
        let jo = storage::JsonObject::from_object(obj);
        jo.rough_size()
    }
}

#[derive(Debug)]
pub struct Token {
    info: CK_TOKEN_INFO,
    filename: String,
    object_templates: ObjectTemplates,
    mechanisms: Mechanisms,
    objects: TokenObjects,
    memory_only: bool,
    dirty: bool,
    so_login: LoginData,
    user_login: LoginData,
}

impl Token {
    pub fn new(filename: String) -> KResult<Token> {
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
            filename: filename,
            object_templates: ObjectTemplates::new(),
            mechanisms: Mechanisms::new(),
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
            memory_only: false,
            dirty: false,
        };

        /* register mechanisms and templates */
        object::register(&mut token.mechanisms, &mut token.object_templates);
        aes::register(&mut token.mechanisms, &mut token.object_templates);
        rsa::register(&mut token.mechanisms, &mut token.object_templates);
        hash::register(&mut token.mechanisms, &mut token.object_templates);
        hmac::register(&mut token.mechanisms, &mut token.object_templates);

        /* when no filename is provided we assume a memory only
         * token that has no backing store */
        if token.filename.len() > 0 {
            match storage::JsonToken::load(&token.filename) {
                Ok(jt) => {
                    jt.to_objects(&mut token.objects)?;
                    token.info.flags |= CKF_TOKEN_INITIALIZED;
                }
                Err(err) => match err {
                    KError::RvError(ref e) => {
                        if e.rv != CKR_CRYPTOKI_NOT_INITIALIZED {
                            /* empty file is legal but leaves the token uninitialized */
                            return Err(err);
                        }
                    }
                    _ => return Err(err),
                },
            }
        } else {
            token.memory_only = true;
            token.info.flags &= !CKF_LOGIN_REQUIRED;
            token.info.flags |= CKF_TOKEN_INITIALIZED;
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

    pub fn get_object_by_handle(
        &self,
        handle: CK_OBJECT_HANDLE,
        checks: bool,
    ) -> KResult<&Object> {
        let obj = match self.objects.get_by_handle(handle) {
            Ok(o) => o,
            Err(e) => return Err(e),
        };
        if checks && !self.is_logged_in(KRY_UNSPEC) && obj.is_private() {
            return err_rv!(CKR_USER_NOT_LOGGED_IN);
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
        if !self.is_login_required() {
            return CKR_OK;
        }
        match user_type {
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
        }
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

        self.objects.clear_private_session_objects();

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

        /* If we set a PIN it means we switched to require Logins */
        self.info.flags |= CKF_LOGIN_REQUIRED;

        self.dirty = true;
        match self.save() {
            Ok(()) => CKR_OK,
            Err(_) => CKR_GENERAL_ERROR,
        }
    }

    pub fn save(&self) -> KResult<()> {
        if !self.dirty || self.memory_only {
            return Ok(());
        }
        let jt = storage::JsonToken::from_objects(&self.objects);
        jt.save(&self.filename)
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
            self.dirty = true;
        } else {
            obj.set_session(s_handle);
        }
        let handle = self.objects.next_handle();
        obj.set_handle(handle);
        self.objects.insert_handle(handle, uid.clone());
        self.objects.insert(uid.clone(), obj);
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

        let object = self.object_templates.create(template)?;
        self.insert_object(s_handle, object)
    }

    pub fn destroy_object(
        &mut self,
        o_handle: CK_OBJECT_HANDLE,
    ) -> KResult<()> {
        let obj = self.objects.get_by_handle(o_handle)?;
        if !obj.is_destroyable() {
            return err_rv!(CKR_ACTION_PROHIBITED);
        }
        self.objects.remove(o_handle, false)?;
        Ok(())
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
            Err(e) => match e {
                KError::RvError(e) => {
                    if e.rv == CKR_USER_NOT_LOGGED_IN {
                        err_rv!(CKR_OBJECT_HANDLE_INVALID)
                    } else {
                        err_rv!(e.rv)
                    }
                }
                _ => Err(e),
            },
        }
    }

    pub fn set_object_attrs(
        &mut self,
        handle: CK_OBJECT_HANDLE,
        template: &mut [CK_ATTRIBUTE],
    ) -> KResult<()> {
        let obj = match self.objects.get_by_handle_mut(handle) {
            Ok(o) => o,
            Err(e) => return Err(e),
        };
        self.object_templates.set_object_attributes(obj, template)?;
        self.dirty = true;
        Ok(())
    }

    pub fn drop_session_objects(&mut self, handle: CK_SESSION_HANDLE) {
        self.objects.clear_session_objects(handle);
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
        self.objects.object_rough_size(o_handle)
    }

    pub fn copy_object(
        &mut self,
        s_handle: CK_SESSION_HANDLE,
        o_handle: CK_OBJECT_HANDLE,
        template: &[CK_ATTRIBUTE],
    ) -> KResult<CK_OBJECT_HANDLE> {
        let obj = self.objects.get_by_handle(o_handle)?;
        let newobj = self.object_templates.copy(obj, template)?;
        self.insert_object(s_handle, newobj)
    }

    pub fn search_objects(
        &mut self,
        template: &[CK_ATTRIBUTE],
    ) -> KResult<Vec<CK_OBJECT_HANDLE>> {
        let mut handles = Vec::<CK_OBJECT_HANDLE>::new();
        let mut needs_handle = Vec::<String>::new();
        for (_, o) in self.objects.iter() {
            if !self.is_logged_in(KRY_UNSPEC) && o.is_private() {
                continue;
            }

            if o.is_sensitive() {
                match self.object_templates.check_sensitive(o, template) {
                    Err(_) => continue,
                    Ok(()) => (),
                }
            }

            if o.match_template(template) {
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
        }
        while let Some(uid) = needs_handle.pop() {
            let oh = self.objects.next_handle();
            let obj = match self.objects.get_mut(&uid) {
                Some(o) => o,
                None => continue,
            };
            obj.set_handle(oh);
            self.objects.insert_handle(oh, uid);
            handles.push(oh);
        }
        Ok(handles)
    }

    pub fn get_mech(
        &self,
        mech_type: CK_MECHANISM_TYPE,
    ) -> KResult<&Box<dyn mechanism::Mechanism>> {
        self.mechanisms.get(mech_type)
    }

    pub fn get_obj_template(
        &self,
        obj: &Object,
    ) -> KResult<&Box<dyn object::ObjectTemplate>> {
        self.object_templates.get_object_template(obj)
    }

    pub fn get_obj_template_from_key_template(
        &self,
        attrs: &[CK_ATTRIBUTE],
    ) -> KResult<&Box<dyn object::ObjectTemplate>> {
        let class = match attrs.iter().position(|x| x.type_ == CKA_CLASS) {
            Some(idx) => attrs[idx].to_ulong()?,
            None => return err_rv!(CKR_TEMPLATE_INCONSISTENT),
        };
        let key_type = match attrs.iter().position(|x| x.type_ == CKA_KEY_TYPE)
        {
            Some(idx) => attrs[idx].to_ulong()?,
            None => return err_rv!(CKR_TEMPLATE_INCONSISTENT),
        };
        self.object_templates
            .get_template(object::ObjectType::new(class, key_type))
    }
}
