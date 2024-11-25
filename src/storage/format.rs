// Copyright 2024 Simo Sorce
// See LICENSE.txt file for terms

use std::fmt::Debug;

use crate::attribute::{Attribute, CkAttrs};
use crate::error::Result;
use crate::interface::*;
use crate::misc::copy_sized_string;
use crate::object::Object;
use crate::storage;
use crate::storage::aci::{StorageACI, StorageAuthInfo};
use crate::storage::{Storage, StorageTokenInfo};
use crate::token::TokenFacilities;

pub static SO_PIN_FLAGS: [CK_FLAGS; 4] = [
    CKF_SO_PIN_LOCKED,    /* 0 attempts left */
    CKF_SO_PIN_FINAL_TRY, /* 1 attempt left */
    CKF_SO_PIN_COUNT_LOW, /* 2 or 3 .. */
    CKF_SO_PIN_COUNT_LOW, /* attempts left */
];

pub static USER_PIN_FLAGS: [CK_FLAGS; 4] = [
    CKF_USER_PIN_LOCKED,    /* 0 attempts left */
    CKF_USER_PIN_FINAL_TRY, /* 1 attempt left */
    CKF_USER_PIN_COUNT_LOW, /* 2 or 3 .. */
    CKF_USER_PIN_COUNT_LOW, /* attempts left */
];

const SO_OBJ_UID: &str = "0";
const USER_OBJ_UID: &str = "1";
const TOKEN_INFO_UID: &str = "2";

pub fn so_obj_uid() -> String {
    SO_OBJ_UID.to_string()
}

pub fn user_obj_uid() -> String {
    USER_OBJ_UID.to_string()
}

pub fn token_info_uid() -> String {
    TOKEN_INFO_UID.to_string()
}

pub fn user_flags(
    user_type: CK_USER_TYPE,
    info: &StorageAuthInfo,
    flag: &mut CK_FLAGS,
) {
    let remaining = if info.locked {
        0
    } else {
        info.max_attempts - info.cur_attempts
    };
    if remaining > 3 {
        *flag = 0;
    } else if user_type == CKU_SO {
        /* casting here is fine because remaining is guaranteed to fit */
        *flag = SO_PIN_FLAGS[remaining as usize];
    } else if user_type == CKU_USER {
        *flag = USER_PIN_FLAGS[remaining as usize];
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

fn get_pin_uid(user_type: CK_USER_TYPE) -> Result<String> {
    match user_type {
        CKU_SO => Ok(so_obj_uid()),
        CKU_USER => Ok(user_obj_uid()),
        _ => return Err(CKR_GENERAL_ERROR)?,
    }
}

pub fn object_to_token_info(obj: &Object) -> Result<StorageTokenInfo> {
    if obj.get_attr_as_ulong(CKA_CLASS)? != KRO_TOKEN_DATA {
        return Err(CKR_TOKEN_NOT_RECOGNIZED)?;
    }
    let label = obj
        .get_attr_as_string(CKA_LABEL)
        .map_err(|_| CKR_TOKEN_NOT_RECOGNIZED)?;
    let manufacturer = obj
        .get_attr_as_string(KRA_MANUFACTURER_ID)
        .map_err(|_| CKR_TOKEN_NOT_RECOGNIZED)?;
    let model = obj
        .get_attr_as_string(KRA_MODEL)
        .map_err(|_| CKR_TOKEN_NOT_RECOGNIZED)?;
    let serial = obj
        .get_attr_as_string(KRA_SERIAL_NUMBER)
        .map_err(|_| CKR_TOKEN_NOT_RECOGNIZED)?;
    let mut info = StorageTokenInfo {
        label: [0; 32],
        manufacturer: [0; 32],
        model: [0; 16],
        serial: [0; 16],
        flags: obj
            .get_attr_as_ulong(KRA_FLAGS)
            .map_err(|_| CKR_TOKEN_NOT_RECOGNIZED)?,
    };
    copy_sized_string(label.as_bytes(), &mut info.label);
    copy_sized_string(manufacturer.as_bytes(), &mut info.manufacturer);
    copy_sized_string(model.as_bytes(), &mut info.model);
    copy_sized_string(serial.as_bytes(), &mut info.serial);
    Ok(info)
}

pub fn token_info_to_object(
    info: &StorageTokenInfo,
    obj: &mut Object,
) -> Result<()> {
    obj.set_attr(Attribute::string_from_sized(CKA_LABEL, &info.label))?;
    obj.set_attr(Attribute::string_from_sized(
        KRA_MANUFACTURER_ID,
        &info.manufacturer,
    ))?;
    obj.set_attr(Attribute::string_from_sized(KRA_MODEL, &info.model))?;
    obj.set_attr(Attribute::string_from_sized(
        KRA_SERIAL_NUMBER,
        &info.serial,
    ))?;

    /* filter out runtime flags */
    let flags = info.flags
        & (CKF_LOGIN_REQUIRED | CKF_TOKEN_INITIALIZED | CKF_WRITE_PROTECTED);
    obj.set_attr(Attribute::from_ulong(KRA_FLAGS, flags))?;
    Ok(())
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
        let uid = get_pin_uid(CKU_SO)?;
        let obj = match self.store.fetch_by_uid(&uid, &[]) {
            Ok(o) => o,
            Err(e) => {
                if e.attr_not_found() {
                    return Err(CKR_USER_PIN_NOT_INITIALIZED)?;
                } else {
                    return Err(e);
                }
            }
        };
        let info = self.aci.user_attempts(&obj)?;
        user_flags(CKU_SO, &info, &mut so_flags);
        if self.aci.auth_object_is_default(&obj)? {
            so_flags |= CKF_SO_PIN_TO_BE_CHANGED;
        }

        let mut usr_flags: CK_FLAGS = 0;
        let uid = get_pin_uid(CKU_USER)?;
        match self.store.fetch_by_uid(&uid, &[]) {
            Ok(obj) => {
                let info = self.aci.user_attempts(&obj)?;
                user_flags(CKU_USER, &info, &mut usr_flags);
                if self.aci.auth_object_is_default(&obj)? {
                    usr_flags |= CKF_USER_PIN_TO_BE_CHANGED;
                } else {
                    usr_flags |= CKF_USER_PIN_INITIALIZED;
                }
            }
            Err(e) => {
                /* if the user object is not available we just ignore it.
                 * This happen on DB resets, and initialization, until a pin
                 * is set */
                if !e.attr_not_found() {
                    return Err(e);
                }
            }
        };
        Ok(so_flags | usr_flags)
    }

    fn default_so_pin(&mut self, facilities: &TokenFacilities) -> Result<()> {
        let auth_obj = self.aci.make_auth_object(
            facilities,
            &get_pin_uid(CKU_SO)?,
            checked_pin(&[]),
        )?;
        self.store.store_obj(auth_obj)
    }

    fn default_token_info(
        &mut self,
        encrypted: bool,
    ) -> Result<StorageTokenInfo> {
        /* TOKEN INFO */
        let mut info = StorageTokenInfo {
            label: [0u8; 32],
            manufacturer: [0u8; 32],
            model: [0u8; 16],
            serial: [0u8; 16],
            flags: CKF_TOKEN_INITIALIZED,
        };
        if encrypted {
            info.flags |= CKF_LOGIN_REQUIRED;
        }

        /* default strings */
        copy_sized_string(storage::TOKEN_LABEL.as_bytes(), &mut info.label);
        copy_sized_string(
            storage::MANUFACTURER_ID.as_bytes(),
            &mut info.manufacturer,
        );
        copy_sized_string(storage::TOKEN_MODEL.as_bytes(), &mut info.model);

        let mut obj = Object::new();
        obj.set_attr(Attribute::from_string(CKA_UNIQUE_ID, token_info_uid()))?;
        obj.set_attr(Attribute::from_bool(CKA_TOKEN, true))?;
        obj.set_attr(Attribute::from_ulong(CKA_CLASS, KRO_TOKEN_DATA))?;
        token_info_to_object(&info, &mut obj)?;
        let info = object_to_token_info(&obj)?;
        self.store.store_obj(obj)?;
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
        }

        let mut obj = self.store.fetch_by_uid(&uid, attrs.as_slice())?;
        let ats = facilities.factories.get_sensitive_attrs(&obj)?;
        if self.aci.encrypts() {
            for typ in ats {
                /* replace the encrypted val with the clear text one
                 * if the value was requested */
                let encval = match obj.get_attr(typ) {
                    Some(attr) => attr.get_value(),
                    None => continue,
                };
                let plain = self.aci.decrypt_value(facilities, uid, encval)?;
                obj.set_attr(Attribute::from_bytes(typ, plain))?;
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
            let ats = facilities.factories.get_sensitive_attrs(&obj)?;
            for typ in ats {
                /* replace the clear text val with the encrypted one */
                let plain = obj.get_attr_as_bytes(typ)?;
                let encval = self.aci.encrypt_value(facilities, &uid, plain)?;
                obj.set_attr(Attribute::from_bytes(typ, encval))?;
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
            let ats = facilities.factories.get_sensitive_attrs(&obj)?;
            for typ in ats {
                /* replace the clear text val with the encrypted one */
                match attrs.find_attr(typ) {
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
        let obj = self.store.fetch_by_uid(&token_info_uid(), &[])?;
        object_to_token_info(&obj)
    }

    fn store_token_info(&mut self, info: &StorageTokenInfo) -> Result<()> {
        let uid = token_info_uid();
        let mut obj = self.store.fetch_by_uid(&uid, &[])?;
        token_info_to_object(info, &mut obj)?;
        self.store.store_obj(obj)
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
        let mut auth_obj = match self.store.fetch_by_uid(&uid, &[]) {
            Ok(o) => o,
            Err(e) => {
                if e.attr_not_found() {
                    return Err(CKR_USER_PIN_NOT_INITIALIZED)?;
                } else {
                    return Err(e);
                }
            }
        };
        let info = self.aci.authenticate(
            facilities,
            &mut auth_obj,
            checked_pin(pin),
            !check_only,
        )?;

        if info.update_obj {
            let _ = self.store.store_obj(auth_obj);
        }

        if info.cur_attempts == 0 {
            *flag = 0;
            return Ok(());
        }
        user_flags(user_type, &info, flag);
        if info.locked {
            Err(CKR_PIN_LOCKED)?
        } else {
            Err(CKR_PIN_INCORRECT)?
        }
    }

    fn unauth_user(&mut self, user_type: CK_USER_TYPE) -> Result<()> {
        let uid = get_pin_uid(user_type)?;
        let _ = match self.store.fetch_by_uid(&uid, &[]) {
            Ok(o) => o,
            Err(e) => {
                if e.attr_not_found() {
                    return Err(CKR_USER_PIN_NOT_INITIALIZED)?;
                } else {
                    return Err(e);
                }
            }
        };
        self.aci.unauth();
        Ok(())
    }

    fn set_user_pin(
        &mut self,
        facilities: &TokenFacilities,
        user_type: CK_USER_TYPE,
        pin: &[u8],
    ) -> Result<()> {
        let obj = self.aci.make_auth_object(
            facilities,
            &get_pin_uid(user_type)?,
            pin,
        )?;
        self.store.store_obj(obj)
    }
}
