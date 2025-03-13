// Copyright 2023 Simo Sorce
// See LICENSE.txt file for terms

use std::borrow::Cow;
use std::collections::HashMap;
use std::vec::Vec;

use crate::attribute::CkAttrs;
use crate::error::Result;
#[cfg(feature = "fips")]
use crate::fips;
use crate::interface::*;
use crate::mechanism::Mechanisms;
use crate::misc::copy_sized_string;
use crate::object::{Object, ObjectFactories};
use crate::register_all;
use crate::storage::*;

use bimap;

#[derive(Debug)]
pub struct Handles {
    map: bimap::hash::BiHashMap<CK_OBJECT_HANDLE, String>,
    next: CK_OBJECT_HANDLE,
}

impl Handles {
    pub fn new() -> Handles {
        Handles {
            map: bimap::hash::BiHashMap::new(),
            next: 1,
        }
    }

    pub fn insert(
        &mut self,
        handle: CK_OBJECT_HANDLE,
        value: String,
    ) -> Result<()> {
        match self.map.insert_no_overwrite(handle, value) {
            Ok(()) => Ok(()),
            Err(_) => Err(CKR_GENERAL_ERROR)?,
        }
    }

    pub fn get(&self, handle: CK_OBJECT_HANDLE) -> Option<&String> {
        self.map.get_by_left(&handle)
    }

    pub fn get_by_uid(&self, uid: &String) -> Option<&CK_OBJECT_HANDLE> {
        self.map.get_by_right(uid)
    }

    pub fn remove(&mut self, handle: CK_OBJECT_HANDLE) {
        let _ = self.map.remove_by_left(&handle);
    }

    pub fn next(&mut self) -> CK_OBJECT_HANDLE {
        let next = self.next;
        self.next += 1;
        next
    }
}

#[derive(Debug)]
pub struct TokenFacilities {
    pub mechanisms: Mechanisms,
    pub factories: ObjectFactories,
    pub handles: Handles,
}

#[derive(Debug)]
pub struct Token {
    info: CK_TOKEN_INFO,
    facilities: TokenFacilities,
    storage: Box<dyn Storage>,
    session_objects: HashMap<CK_OBJECT_HANDLE, Object>,
    logged: CK_USER_TYPE,
}

impl Token {
    pub fn new(dbtype: &str, dbargs: Option<String>) -> Result<Token> {
        let mut token: Token = Token {
            info: CK_TOKEN_INFO {
                label: [0u8; 32],
                manufacturerID: [0u8; 32],
                model: [0u8; 16],
                serialNumber: [0u8; 16],
                flags: CKF_RNG,
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
            facilities: TokenFacilities {
                mechanisms: Mechanisms::new(),
                factories: ObjectFactories::new(),
                handles: Handles::new(),
            },
            storage: new_storage(dbtype, &dbargs)?,
            session_objects: HashMap::new(),
            logged: KRY_UNSPEC,
        };

        /* register mechanisms and factories */
        register_all(
            &mut token.facilities.mechanisms,
            &mut token.facilities.factories,
        );

        match token.storage.open() {
            Ok(info) => token.fill_token_info(&info),
            Err(err) => match err.rv() {
                CKR_CRYPTOKI_NOT_INITIALIZED => {
                    token.info.flags &= !CKF_TOKEN_INITIALIZED
                }
                _ => return Err(err),
            },
        }

        #[cfg(feature = "fips")]
        fips::token_init(&mut token)?;

        Ok(token)
    }

    fn fill_token_info(&mut self, info: &StorageTokenInfo) {
        self.info.label = info.label;
        self.info.manufacturerID = info.manufacturer;
        self.info.model = info.model;
        self.info.serialNumber = info.serial;
        self.info.flags = info.flags | CKF_RNG;
    }

    pub fn get_token_info(&self) -> &CK_TOKEN_INFO {
        &self.info
    }

    pub fn is_initialized(&self) -> bool {
        self.info.flags & CKF_TOKEN_INITIALIZED == CKF_TOKEN_INITIALIZED
    }

    pub fn initialize(&mut self, pin: &[u8], label: &[u8]) -> Result<()> {
        if self.is_initialized() {
            self.auth_user(CKU_SO, pin, true)?;
        };

        self.facilities.handles = Handles::new();
        self.session_objects.clear();
        self.logged = KRY_UNSPEC;

        /* this inits from scratch or deletes and reinits an existing db */
        let mut info = self.storage.reinit(&self.facilities)?;

        /* Add SO PIN */
        match self.set_pin(CKU_SO, pin, &[]) {
            Ok(()) => (),
            Err(e) => {
                /* not all storage dbs support setting a CKU_SO Pin */
                if e.rv() != CKR_USER_TYPE_INVALID {
                    return Err(e);
                }
            }
        }

        /* copy Label */
        copy_sized_string(label, &mut info.label);

        /* save token info with provided label */
        self.storage.store_token_info(&info)?;

        /* copy info on Token object */
        self.fill_token_info(&info);

        /* IMPORTANT: we always forcibly unauth here (A reinit
         * creates the token as if CKU_SO was logged in in oreder
         * to properly store data and set PINs).
         * The caller must ensure authentication after a reset
         * to be able to correctly access the database. */
        self.storage.unauth_user(CKU_SO)?;

        #[cfg(feature = "fips")]
        if fips::token_init(self).is_err() {
            return Err(CKR_GENERAL_ERROR)?;
        }

        Ok(())
    }

    pub fn set_pin(
        &mut self,
        user_type: CK_USER_TYPE,
        pin: &[u8],
        old: &[u8],
    ) -> Result<()> {
        let utype = match user_type {
            CK_UNAVAILABLE_INFORMATION => self.logged,
            CKU_USER => CKU_USER,
            CKU_SO => CKU_SO,
            _ => return Err(CKR_GENERAL_ERROR)?,
        };

        if old.len() != 0 {
            self.auth_user(utype, old, true)?;
        }

        self.storage.set_user_pin(&self.facilities, utype, pin)?;

        if utype == CKU_USER {
            self.info.flags |= CKF_USER_PIN_INITIALIZED;
        }
        Ok(())
    }

    pub fn is_logged_in(&self, user_type: CK_USER_TYPE) -> bool {
        match user_type {
            KRY_UNSPEC => self.logged == CKU_SO || self.logged == CKU_USER,
            CKU_SO => self.logged == CKU_SO,
            CKU_USER => self.logged == CKU_USER,
            _ => false,
        }
    }

    fn update_auth_flags(&mut self, user_type: CK_USER_TYPE, flags: CK_FLAGS) {
        match user_type {
            CKU_USER => {
                self.info.flags &= !(CKF_USER_PIN_LOCKED
                    | CKF_USER_PIN_FINAL_TRY
                    | CKF_USER_PIN_COUNT_LOW);
                self.info.flags |= flags;
            }
            CKU_SO => {
                self.info.flags &= !(CKF_SO_PIN_LOCKED
                    | CKF_SO_PIN_FINAL_TRY
                    | CKF_SO_PIN_COUNT_LOW);
                self.info.flags |= flags;
            }
            _ => (),
        }
    }

    fn auth_user(
        &mut self,
        user_type: CK_USER_TYPE,
        pin: &[u8],
        check_only: bool,
    ) -> Result<()> {
        if user_type != CKU_SO && user_type != CKU_USER {
            return Err(CKR_USER_TYPE_INVALID)?;
        }
        let mut flags: CK_FLAGS = 0;
        let ret = self.storage.auth_user(
            &self.facilities,
            user_type,
            pin,
            &mut flags,
            check_only,
        );
        self.update_auth_flags(user_type, flags);
        if ret.is_err() {
            return ret;
        }
        if !check_only {
            self.logged = user_type;
        }
        Ok(())
    }

    pub fn login(&mut self, user_type: CK_USER_TYPE, pin: &[u8]) -> CK_RV {
        let result = match user_type {
            CKU_SO | CKU_USER => {
                if user_type == self.logged {
                    return CKR_USER_ALREADY_LOGGED_IN;
                }
                if self.logged != KRY_UNSPEC {
                    return CKR_USER_ANOTHER_ALREADY_LOGGED_IN;
                }
                self.auth_user(user_type, pin, false)
            }
            CKU_CONTEXT_SPECIFIC => self.auth_user(self.logged, pin, true),
            _ => return CKR_USER_TYPE_INVALID,
        };
        match result {
            Ok(()) => CKR_OK,
            Err(e) => e.rv(),
        }
    }

    pub fn logout(&mut self) -> CK_RV {
        match self.logged {
            KRY_UNSPEC => CKR_USER_NOT_LOGGED_IN,
            CKU_SO | CKU_USER => {
                self.clear_private_session_objects();
                let user_type = self.logged;
                self.logged = KRY_UNSPEC;
                if self.storage.unauth_user(user_type).is_err() {
                    return CKR_GENERAL_ERROR;
                }
                CKR_OK
            }
            _ => CKR_GENERAL_ERROR,
        }
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
            self.facilities.handles.remove(handle);
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
            self.facilities.handles.remove(h);
        }
    }

    pub fn drop_session_objects(&mut self, handle: CK_SESSION_HANDLE) {
        self.clear_session_objects(handle);
    }

    pub fn get_mechs_num(&self) -> usize {
        self.facilities.mechanisms.len()
    }

    pub fn get_mechs_list(&self) -> Vec<CK_MECHANISM_TYPE> {
        self.facilities.mechanisms.list()
    }

    pub fn get_mech_info(
        &self,
        typ: CK_MECHANISM_TYPE,
    ) -> Result<&CK_MECHANISM_INFO> {
        match self.facilities.mechanisms.info(typ) {
            Some(m) => Ok(m),
            None => Err(CKR_MECHANISM_INVALID)?,
        }
    }

    pub fn get_mechanisms(&self) -> &Mechanisms {
        &self.facilities.mechanisms
    }

    pub fn get_object_factories(&self) -> &ObjectFactories {
        &self.facilities.factories
    }

    pub fn get_object_by_handle(
        &mut self,
        o_handle: CK_OBJECT_HANDLE,
    ) -> Result<Object> {
        let mut obj = match self.session_objects.get(&o_handle) {
            Some(o) => o.clone(),
            None => self.storage.fetch(&self.facilities, o_handle, &[])?,
        };
        if !self.is_logged_in(KRY_UNSPEC) && obj.is_token() && obj.is_private()
        {
            return Err(CKR_USER_NOT_LOGGED_IN)?;
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
        let handle: CK_OBJECT_HANDLE;
        if obj.is_token() {
            if !self.is_logged_in(KRY_UNSPEC) {
                return Err(CKR_USER_NOT_LOGGED_IN)?;
            }
            handle = self.storage.store(&mut self.facilities, obj)?;
        } else {
            handle = self.facilities.handles.next();
            obj.set_handle(handle);
            obj.set_session(s_handle);
            let uid = obj.get_attr_as_string(CKA_UNIQUE_ID)?;
            self.facilities.handles.insert(handle, uid)?;
            self.session_objects.insert(handle, obj);
        }
        Ok(handle)
    }

    pub fn create_object(
        &mut self,
        s_handle: CK_SESSION_HANDLE,
        template: &[CK_ATTRIBUTE],
    ) -> Result<CK_OBJECT_HANDLE> {
        let object = self.facilities.factories.create(template)?;
        self.insert_object(s_handle, object)
    }

    pub fn destroy_object(&mut self, o_handle: CK_OBJECT_HANDLE) -> Result<()> {
        match self.session_objects.get(&o_handle) {
            Some(obj) => {
                if !obj.is_destroyable() {
                    return Err(CKR_ACTION_PROHIBITED)?;
                }
                let _ = self.session_objects.remove(&o_handle);
            }
            None => {
                let destroyable: CK_ATTRIBUTE = CK_ATTRIBUTE {
                    type_: CKA_DESTROYABLE,
                    pValue: std::ptr::null_mut(),
                    ulValueLen: 0,
                };
                let obj = self.storage.fetch(
                    &self.facilities,
                    o_handle,
                    &[destroyable],
                )?;
                if !obj.is_destroyable() {
                    return Err(CKR_ACTION_PROHIBITED)?;
                }
                let _ = self.storage.remove(&self.facilities, o_handle);
            }
        }
        self.facilities.handles.remove(o_handle);
        Ok(())
    }

    pub fn get_object_attrs(
        &mut self,
        o_handle: CK_OBJECT_HANDLE,
        template: &mut [CK_ATTRIBUTE],
    ) -> Result<()> {
        let is_logged = self.is_logged_in(KRY_UNSPEC);

        /* value does not matter, only type does */
        let dnm: CK_BBOOL = CK_FALSE;
        let mut attrs = CkAttrs::from(template);
        if !is_logged {
            attrs.add_bool(CKA_TOKEN, &dnm);
            attrs.add_bool(CKA_PRIVATE, &dnm);
        }

        let obj = match self.session_objects.get(&o_handle) {
            Some(o) => Cow::Borrowed(o),
            None => Cow::Owned(self.storage.fetch(
                &self.facilities,
                o_handle,
                attrs.as_slice(),
            )?),
        };
        if !is_logged && obj.is_token() && obj.is_private() {
            /* do not reveal if the object exists or not */
            return Err(CKR_OBJECT_HANDLE_INVALID)?;
        }
        drop(attrs);
        self.facilities
            .factories
            .get_object_attributes(&obj, template)
    }

    pub fn set_object_attrs(
        &mut self,
        o_handle: CK_OBJECT_HANDLE,
        template: &mut [CK_ATTRIBUTE],
    ) -> Result<()> {
        match self.session_objects.get_mut(&o_handle) {
            Some(mut obj) => self
                .facilities
                .factories
                .get_object_factory(obj)?
                .set_object_attributes(&mut obj, template),
            None => {
                if !self.is_logged_in(KRY_UNSPEC) {
                    return Err(CKR_USER_NOT_LOGGED_IN)?;
                }
                /* We just need the object type to find the correct factory */
                /* value does not matter, only type does */
                let dnmu = CK_UNAVAILABLE_INFORMATION;
                let dnmb = CK_FALSE;
                let mut attrs = CkAttrs::with_capacity(3);
                attrs.add_ulong(CKA_CLASS, &dnmu);
                attrs.add_ulong(CKA_KEY_TYPE, &dnmu);
                attrs.add_bool(CKA_MODIFIABLE, &dnmb);

                let obj = self.storage.fetch(
                    &self.facilities,
                    o_handle,
                    attrs.as_slice(),
                )?;
                let factory =
                    self.facilities.factories.get_object_factory(&obj)?;
                if !obj.is_modifiable() {
                    return Err(CKR_ACTION_PROHIBITED)?;
                }
                factory.check_set_attributes(template)?;
                self.storage.update(&self.facilities, o_handle, template)
            }
        }
    }

    pub fn get_object_size(&self, o_handle: CK_OBJECT_HANDLE) -> Result<usize> {
        let obj = match self.session_objects.get(&o_handle) {
            Some(o) => Cow::Borrowed(o),
            _ => Cow::Owned(self.storage.fetch(
                &self.facilities,
                o_handle,
                &[],
            )?),
        };
        obj.rough_size()
    }

    pub fn copy_object(
        &mut self,
        s_handle: CK_SESSION_HANDLE,
        o_handle: CK_OBJECT_HANDLE,
        template: &[CK_ATTRIBUTE],
    ) -> Result<CK_OBJECT_HANDLE> {
        let obj = match self.session_objects.get_mut(&o_handle) {
            Some(o) => Cow::Borrowed(o),
            _ => {
                let o =
                    self.storage.fetch(&mut self.facilities, o_handle, &[])?;
                if !self.is_logged_in(KRY_UNSPEC) && o.is_private() {
                    return Err(CKR_USER_NOT_LOGGED_IN)?;
                }
                Cow::Owned(o)
            }
        };
        let newobj = self.facilities.factories.copy(&obj, template)?;
        self.insert_object(s_handle, newobj)
    }

    pub fn search_objects(
        &mut self,
        template: &[CK_ATTRIBUTE],
    ) -> Result<Vec<CK_OBJECT_HANDLE>> {
        let mut tmpl = CkAttrs::from(template);
        let mut handles = Vec::<CK_OBJECT_HANDLE>::new();

        /* First add internal session objects */
        for (_, o) in &self.session_objects {
            if o.is_sensitive() {
                match self.facilities.factories.check_sensitive(o, template) {
                    Err(_) => continue,
                    Ok(()) => (),
                }
            }
            if o.match_template(template) {
                handles.push(o.get_handle());
            }
        }

        if !self.is_logged_in(KRY_UNSPEC) {
            tmpl.add_owned_bool(CKA_PRIVATE, CK_FALSE)?;
        }

        /* Then search storage */
        let mut storage_handles =
            self.storage.search(&mut self.facilities, tmpl.as_slice())?;
        handles.append(&mut storage_handles);
        Ok(handles)
    }
}
