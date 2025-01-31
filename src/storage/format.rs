// Copyright 2024 Simo Sorce
// See LICENSE.txt file for terms

use std::fmt::Debug;

use crate::attribute::{Attribute, CkAttrs};
use crate::error::Result;
use crate::interface::*;
use crate::object::Object;
use crate::storage::aci::{StorageACI, StorageAuthInfo};
use crate::storage::{Storage, StorageTokenInfo};
use crate::token::TokenFacilities;

pub fn user_flags(
    user_type: CK_USER_TYPE,
    info: &StorageAuthInfo,
    flag: &mut CK_FLAGS,
) {
    let remaining = if info.locked() {
        0
    } else {
        info.max_attempts - info.cur_attempts
    };
    if user_type == CKU_SO {
        *flag |= match remaining {
            0 => CKF_SO_PIN_LOCKED,
            1 => CKF_SO_PIN_FINAL_TRY,
            2 | 3 => CKF_SO_PIN_COUNT_LOW,
            _ => 0,
        };
        if info.default_pin {
            *flag |= CKF_SO_PIN_TO_BE_CHANGED;
        }
    } else if user_type == CKU_USER {
        *flag |= match remaining {
            0 => CKF_USER_PIN_LOCKED,
            1 => CKF_USER_PIN_FINAL_TRY,
            2 | 3 => CKF_USER_PIN_COUNT_LOW,
            _ => 0,
        };
        if info.default_pin {
            *flag |= CKF_USER_PIN_TO_BE_CHANGED;
        } else {
            *flag |= CKF_USER_PIN_INITIALIZED;
        }
    }
}

#[cfg(feature = "fips")]
fn checked_pin(pin: &[u8]) -> &[u8] {
    const DEFAULT_PIN_FIPS: &str = "DEFAULT PIN FIPS";
    if pin.len() == 0 {
        DEFAULT_PIN_FIPS.as_bytes()
    } else {
        pin
    }
}
#[cfg(not(feature = "fips"))]
fn checked_pin(pin: &[u8]) -> &[u8] {
    pin
}

pub const SO_ID: &str = "SO";
pub const USER_ID: &str = "USER";

fn get_pin_uid(user_type: CK_USER_TYPE) -> Result<&'static str> {
    match user_type {
        CKU_SO => Ok(SO_ID),
        CKU_USER => Ok(USER_ID),
        _ => return Err(CKR_GENERAL_ERROR)?,
    }
}

pub trait StorageRaw: Debug + Send + Sync {
    fn is_initialized(&self) -> Result<()> {
        Err(CKR_GENERAL_ERROR)?
    }
    fn db_reset(&mut self) -> Result<()> {
        Err(CKR_GENERAL_ERROR)?
    }
    fn open(&mut self) -> Result<()> {
        Err(CKR_GENERAL_ERROR)?
    }
    fn flush(&mut self) -> Result<()> {
        Err(CKR_GENERAL_ERROR)?
    }
    fn fetch_by_uid(
        &self,
        _uid: &String,
        _attrs: &[CK_ATTRIBUTE],
    ) -> Result<Object> {
        Err(CKR_GENERAL_ERROR)?
    }
    fn search(&self, _template: &[CK_ATTRIBUTE]) -> Result<Vec<Object>> {
        Err(CKR_GENERAL_ERROR)?
    }
    fn store_obj(&mut self, _obj: Object) -> Result<()> {
        Err(CKR_GENERAL_ERROR)?
    }
    fn remove_by_uid(&mut self, _uid: &String) -> Result<()> {
        Err(CKR_GENERAL_ERROR)?
    }
    fn fetch_token_info(&self) -> Result<StorageTokenInfo> {
        Err(CKR_GENERAL_ERROR)?
    }
    fn store_token_info(&mut self, _info: &StorageTokenInfo) -> Result<()> {
        Err(CKR_GENERAL_ERROR)?
    }
    fn fetch_user(&self, _uid: &str) -> Result<StorageAuthInfo> {
        Err(CKR_GENERAL_ERROR)?
    }
    fn store_user(
        &mut self,
        _uid: &str,
        _data: &StorageAuthInfo,
    ) -> Result<()> {
        Err(CKR_GENERAL_ERROR)?
    }
}

#[derive(Debug)]
pub struct StdStorageFormat {
    store: Box<dyn StorageRaw>,
    aci: StorageACI,
}

impl StdStorageFormat {
    pub fn new(
        store: Box<dyn StorageRaw>,
        aci: StorageACI,
    ) -> StdStorageFormat {
        StdStorageFormat {
            store: store,
            aci: aci,
        }
    }

    fn init_pin_flags(&mut self) -> Result<CK_FLAGS> {
        let mut so_flags: CK_FLAGS = 0;
        let info = self.store.fetch_user(SO_ID)?;
        user_flags(CKU_SO, &info, &mut so_flags);

        let mut usr_flags: CK_FLAGS = 0;
        match self.store.fetch_user(USER_ID) {
            Ok(info) => {
                user_flags(CKU_USER, &info, &mut usr_flags);
            }
            Err(e) => {
                /* if the user object is not available we just ignore it.
                 * This happen on DB resets, and initialization, until a pin
                 * is set */
                if e.rv() != CKR_USER_PIN_NOT_INITIALIZED {
                    return Err(e);
                }
            }
        };
        Ok(so_flags | usr_flags)
    }

    fn default_so_pin(&mut self, facilities: &TokenFacilities) -> Result<()> {
        let data =
            self.aci
                .key_to_user_data(facilities, SO_ID, checked_pin(&[]))?;
        self.store.store_user(SO_ID, &data)
    }

    fn default_token_info(
        &mut self,
        encrypted: bool,
    ) -> Result<StorageTokenInfo> {
        /* TOKEN INFO */
        let mut info = StorageTokenInfo::default();
        info.flags |= CKF_TOKEN_INITIALIZED;
        if encrypted {
            info.flags |= CKF_LOGIN_REQUIRED;
        }
        self.store.store_token_info(&info)?;
        Ok(info)
    }
}

impl Storage for StdStorageFormat {
    fn open(&mut self) -> Result<StorageTokenInfo> {
        self.store.open()?;
        self.store.is_initialized()?;
        let mut info = self.load_token_info()?;
        info.flags |= self.init_pin_flags()?;
        Ok(info)
    }

    fn reinit(
        &mut self,
        facilities: &TokenFacilities,
    ) -> Result<StorageTokenInfo> {
        self.store.db_reset()?;
        /* Create new KEK so default auth objects can be generated */
        self.aci.reset(facilities)?;
        self.default_so_pin(facilities)?;
        let mut info = self.default_token_info(self.aci.encrypts())?;
        info.flags |= self.init_pin_flags()?;
        Ok(info)
    }

    fn flush(&mut self) -> Result<()> {
        self.store.flush()
    }

    fn fetch(
        &self,
        facilities: &TokenFacilities,
        handle: CK_OBJECT_HANDLE,
        attributes: &[CK_ATTRIBUTE],
    ) -> Result<Object> {
        let uid = match facilities.handles.get(handle) {
            Some(u) => u,
            None => return Err(CKR_OBJECT_HANDLE_INVALID)?,
        };
        /* the values don't matter, only the type */
        let dnm: CK_ULONG = 0;
        let mut attrs = CkAttrs::from(attributes);
        /* we need object defining attributes to be present in
         * order to get sensitive attrs from the factory later */
        if attributes.len() != 0 {
            attrs.add_missing_ulong(CKA_CLASS, &dnm);
            /* it is safe to add attributes even if the objects
             * are not of the correct type, the attribute will simply
             * not be returned in that case */
            attrs.add_missing_ulong(CKA_KEY_TYPE, &dnm);
            attrs.add_missing_ulong(CKA_CERTIFICATE_TYPE, &dnm);
            /* We also need to know whether the object is sensible/extractable
             * so that the token code can decide whether it is ok to return
             * some attributes or not */
            attrs.add_missing_ulong(CKA_SENSITIVE, &dnm);
            attrs.add_missing_ulong(CKA_EXTRACTABLE, &dnm);
        }

        let mut obj = self.store.fetch_by_uid(&uid, attrs.as_slice())?;
        let factory = facilities.factories.get_object_factory(&obj)?;
        let ats = factory.get_data().get_sensitive();
        if self.aci.encrypts() {
            for typ in ats {
                /* replace the encrypted val with the clear text one
                 * if the value was requested */
                let encval = match obj.get_attr(*typ) {
                    Some(attr) => attr.get_value(),
                    None => continue,
                };
                let plain = self.aci.decrypt_value(facilities, uid, encval)?;
                obj.set_attr(Attribute::from_bytes(*typ, plain))?;
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
        let uid = obj.get_attr_as_string(CKA_UNIQUE_ID)?;
        if self.aci.encrypts() {
            let factory = facilities.factories.get_object_factory(&obj)?;
            let ats = factory.get_data().get_sensitive();
            for typ in ats {
                /* replace the clear text val with the encrypted one */
                let plain = match obj.get_attr(*typ) {
                    Some(attr) => attr.get_value(),
                    None => continue,
                };
                let encval = self.aci.encrypt_value(facilities, &uid, plain)?;
                obj.set_attr(Attribute::from_bytes(*typ, encval))?;
            }
        }
        let mut handle = obj.get_handle();
        if handle == CK_INVALID_HANDLE {
            handle = facilities.handles.next();
            facilities.handles.insert(handle, uid)?;
        }
        self.store.store_obj(obj)?;
        Ok(handle)
    }

    fn update(
        &mut self,
        facilities: &TokenFacilities,
        handle: CK_OBJECT_HANDLE,
        template: &[CK_ATTRIBUTE],
    ) -> Result<()> {
        let uid = match facilities.handles.get(handle) {
            Some(u) => u,
            None => return Err(CKR_OBJECT_HANDLE_INVALID)?,
        };

        let mut obj = self.store.fetch_by_uid(&uid, &[])?;

        let mut attrs = CkAttrs::from(template);

        if self.aci.encrypts() {
            let factory = facilities.factories.get_object_factory(&obj)?;
            let ats = factory.get_data().get_sensitive();
            for typ in ats {
                /* replace the clear text val with the encrypted one */
                match attrs.find_attr(*typ) {
                    Some(a) => {
                        let plain = a.to_buf()?;
                        let encval =
                            self.aci.encrypt_value(facilities, &uid, &plain)?;
                        attrs.insert_unique_vec(a.type_, encval)?;
                    }
                    None => (),
                }
            }
        }

        for ck_attr in attrs.as_slice() {
            obj.set_attr(ck_attr.to_attribute()?)?;
        }
        self.store.store_obj(obj)
    }

    fn search(
        &self,
        facilities: &mut TokenFacilities,
        template: &[CK_ATTRIBUTE],
    ) -> Result<Vec<CK_OBJECT_HANDLE>> {
        let mut objects = self.store.search(template)?;
        let mut result = Vec::<CK_OBJECT_HANDLE>::with_capacity(objects.len());
        for mut obj in objects.drain(..) {
            if obj.is_sensitive() {
                obj.set_zeroize();
                match facilities.factories.check_sensitive(&obj, template) {
                    Err(_) => continue,
                    Ok(()) => (),
                }
            }
            if let Ok(uid) = obj.get_attr_as_string(CKA_UNIQUE_ID) {
                /* do not return internal objects */
                if let Ok(numuid) = uid.parse::<usize>() {
                    if numuid < 10 {
                        continue;
                    }
                }
                let handle = match facilities.handles.get_by_uid(&uid) {
                    Some(h) => *h,
                    None => {
                        let h = facilities.handles.next();
                        facilities.handles.insert(h, uid)?;
                        h
                    }
                };
                result.push(handle);
            }
        }
        Ok(result)
    }

    fn remove(
        &mut self,
        facilities: &TokenFacilities,
        handle: CK_OBJECT_HANDLE,
    ) -> Result<()> {
        let uid = match facilities.handles.get(handle) {
            Some(u) => u,
            None => return Err(CKR_OBJECT_HANDLE_INVALID)?,
        };
        self.store.remove_by_uid(&uid)
    }

    fn load_token_info(&self) -> Result<StorageTokenInfo> {
        self.store.fetch_token_info()
    }

    fn store_token_info(&mut self, info: &StorageTokenInfo) -> Result<()> {
        self.store.store_token_info(info)
    }

    fn auth_user(
        &mut self,
        facilities: &TokenFacilities,
        user_type: CK_USER_TYPE,
        pin: &[u8],
        flag: &mut CK_FLAGS,
        check_only: bool,
    ) -> Result<()> {
        let uid = get_pin_uid(user_type)?;
        let mut user_data = self.store.fetch_user(uid)?;
        let update = self.aci.authenticate(
            facilities,
            &uid,
            &mut user_data,
            checked_pin(pin),
            !check_only,
        )?;

        if update {
            let _ = self.store.store_user(uid, &user_data);
        }

        if user_data.cur_attempts == 0 {
            *flag = 0;
            return Ok(());
        }
        user_flags(user_type, &user_data, flag);
        if user_data.locked() {
            Err(CKR_PIN_LOCKED)?
        } else {
            Err(CKR_PIN_INCORRECT)?
        }
    }

    fn unauth_user(&mut self, user_type: CK_USER_TYPE) -> Result<()> {
        /* check it exists so we return the correct error */
        let _ = self.store.fetch_user(get_pin_uid(user_type)?)?;
        self.aci.unauth();
        Ok(())
    }

    fn set_user_pin(
        &mut self,
        facilities: &TokenFacilities,
        user_type: CK_USER_TYPE,
        pin: &[u8],
    ) -> Result<()> {
        let uid = get_pin_uid(user_type)?;
        let data = self.aci.key_to_user_data(facilities, uid, pin)?;
        self.store.store_user(uid, &data)
    }
}
