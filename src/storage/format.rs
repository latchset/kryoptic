// Copyright 2024 Simo Sorce
// See LICENSE.txt file for terms

//! This module defines the standard storage format logic (`StdStorageFormat`).
//! It acts as a bridge between the high-level `Storage` trait (used by `Token`)
//! and the low-level `StorageRaw` trait (implemented by specific backends like
//! JSON or SQLite), applying Authentication, Confidentiality, and Integrity
//! (ACI) services via the `StorageACI` helper.

use std::fmt::Debug;

use crate::attribute::{Attribute, CkAttrs};
use crate::error::Result;
#[cfg(feature = "fips")]
use crate::fips::indicators::add_missing_validation_flag;
use crate::object::Object;
use crate::pkcs11::*;
use crate::storage::aci::{StorageACI, StorageAuthInfo};
use crate::storage::{Storage, StorageTokenInfo};
use crate::token::TokenFacilities;
use crate::CSPRNG;

use hex;

/// Calculates and sets PIN status flags based on authentication info.
///
/// Updates the provided `flag` variable with flags like `CKF_*_PIN_LOCKED`,
/// `CKF_*_PIN_FINAL_TRY`, `CKF_*_PIN_COUNT_LOW`, `CKF_*_PIN_TO_BE_CHANGED`,
/// and `CKF_USER_PIN_INITIALIZED` based on the user type and `StorageAuthInfo`.
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

/// Returns a default PIN for FIPS mode initialization if the input is empty.
/// Otherwise, returns the input PIN slice.
#[cfg(feature = "fips")]
fn checked_pin(pin: &[u8]) -> &[u8] {
    const DEFAULT_PIN_FIPS: &str = "DEFAULT PIN FIPS";
    if pin.len() == 0 {
        DEFAULT_PIN_FIPS.as_bytes()
    } else {
        pin
    }
}

/// Returns the input PIN slice (no default in non-FIPS mode).
#[cfg(not(feature = "fips"))]
fn checked_pin(pin: &[u8]) -> &[u8] {
    pin
}

pub const SO_ID: &str = "SO";
pub const USER_ID: &str = "USER";

/// Maps a PKCS#11 user type (`CK_USER_TYPE`) to its internal storage ID string.
fn get_pin_uid(user_type: CK_USER_TYPE) -> Result<&'static str> {
    match user_type {
        CKU_SO => Ok(SO_ID),
        CKU_USER => Ok(USER_ID),
        _ => return Err(CKR_GENERAL_ERROR)?,
    }
}

/// Trait defining the low-level interface for specific storage backends
/// (e.g., JSON file, SQLite database).
///
/// This trait deals with raw, potentially unencrypted data and basic
/// database operations. The `StdStorageFormat` struct wraps an implementation
/// of this trait to add the necessary ACI layer.
pub trait StorageRaw: Debug + Send + Sync {
    /// Checks if the underlying storage medium has been initialized.
    fn is_initialized(&self) -> Result<()> {
        Err(CKR_GENERAL_ERROR)?
    }
    /// Resets the storage backend to an uninitialized state, deleting all data.
    fn db_reset(&mut self) -> Result<()> {
        Err(CKR_GENERAL_ERROR)?
    }
    /// Opens the storage backend (e.g., opens file, connects to database).
    fn open(&mut self) -> Result<()> {
        Err(CKR_GENERAL_ERROR)?
    }
    /// Flushes any pending changes to the persistent storage medium.
    fn flush(&mut self) -> Result<()> {
        Err(CKR_GENERAL_ERROR)?
    }
    /// Fetches a raw object representation by its internal UID.
    /// `attrs` can provide hints about needed attributes, but the backend
    /// might return more attributes than requested.
    fn fetch_by_uid(
        &self,
        _uid: &String,
        _attrs: &[CK_ATTRIBUTE],
    ) -> Result<Object> {
        Err(CKR_GENERAL_ERROR)?
    }
    /// Searches for raw objects matching the provided template.
    fn search(&self, _template: &[CK_ATTRIBUTE]) -> Result<Vec<Object>> {
        Err(CKR_GENERAL_ERROR)?
    }
    /// Stores a raw object representation persistently. Assumes the object's
    /// UID is already set correctly. Overwrites if an object with the same
    /// UID exists.
    fn store_obj(&mut self, _obj: Object) -> Result<()> {
        Err(CKR_GENERAL_ERROR)?
    }
    /// Removes a raw object by its internal UID.
    fn remove_by_uid(&mut self, _uid: &String) -> Result<()> {
        Err(CKR_GENERAL_ERROR)?
    }
    /// Fetches the raw token information structure from storage.
    fn fetch_token_info(&self) -> Result<StorageTokenInfo> {
        Err(CKR_GENERAL_ERROR)?
    }
    /// Stores the raw token information structure persistently.
    fn store_token_info(&mut self, _info: &StorageTokenInfo) -> Result<()> {
        Err(CKR_GENERAL_ERROR)?
    }
    /// Fetches the raw authentication information for a specific user ID
    /// ("SO" or "USER").
    fn fetch_user(&self, _uid: &str) -> Result<StorageAuthInfo> {
        Err(CKR_GENERAL_ERROR)?
    }
    /// Stores the raw authentication information for a specific user ID
    /// ("SO" or "USER").
    fn store_user(
        &mut self,
        _uid: &str,
        _data: &StorageAuthInfo,
    ) -> Result<()> {
        Err(CKR_GENERAL_ERROR)?
    }
}

/// Implements the standard `Storage` trait by wrapping a `StorageRaw` backend
/// and applying Authentication, Confidentiality, and Integrity (ACI) services.
#[derive(Debug)]
pub struct StdStorageFormat {
    /// The underlying raw storage implementation (e.g., JSON, SQLite).
    store: Box<dyn StorageRaw>,
    /// The ACI helper managing encryption keys and authentication state.
    aci: StorageACI,
}

impl StdStorageFormat {
    /// Instantiates a new storage manager
    pub fn new(
        store: Box<dyn StorageRaw>,
        aci: StorageACI,
    ) -> StdStorageFormat {
        StdStorageFormat {
            store: store,
            aci: aci,
        }
    }

    /// Initializes PIN status flags by fetching auth info for SO and User
    /// from the raw storage.
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

    /// Sets the default SO PIN during token initialization.
    fn default_so_pin(&mut self, facilities: &TokenFacilities) -> Result<()> {
        let data =
            self.aci
                .key_to_user_data(facilities, SO_ID, checked_pin(&[]))?;
        self.store.store_user(SO_ID, &data)
    }

    /// Creates and stores the default token info during initialization.
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
        /* Generate and store a random serial number */
        let mut value: [u8; 8] = [0u8; 8];
        CSPRNG.with(|rng| rng.borrow_mut().generate_random(&mut value))?;
        info.serial.copy_from_slice(hex::encode(value).as_bytes());
        self.store.store_token_info(&info)?;
        Ok(info)
    }
}

impl Storage for StdStorageFormat {
    /// Opens the underlying raw storage and populates token PIN flags.
    fn open(&mut self) -> Result<StorageTokenInfo> {
        self.store.open()?;
        self.store.is_initialized()?;
        let mut info = self.load_token_info()?;
        info.flags |= self.init_pin_flags()?;
        Ok(info)
    }

    /// Resets the raw storage, generates a new ACI master key, sets default
    /// SO PIN.
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

    /// Flushes the underlying raw storage.
    fn flush(&mut self) -> Result<()> {
        self.store.flush()
    }

    /// Fetches an object, handling potential decryption of sensitive
    /// attributes.
    ///
    /// Retrieves the raw object using UID from handle map,
    /// then uses ACI to decrypt.
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
            #[cfg(feature = "fips")]
            {
                /* We need these to be able to derive object validation flag */
                attrs.add_missing_ulong(CKA_EC_PARAMS, &dnm);
                attrs.add_missing_ulong(CKA_VALUE_LEN, &dnm);
                attrs.add_missing_ulong(CKA_MODULUS, &dnm);
            }
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

        #[cfg(feature = "fips")]
        add_missing_validation_flag(&mut obj);

        obj.set_handle(handle);
        Ok(obj)
    }

    /// Stores an object, handling potential encryption of sensitive attributes.
    ///
    /// Uses ACI to encrypt sensitive parts, then stores the raw object.
    /// Assigns handle.
    fn store(
        &mut self,
        facilities: &mut TokenFacilities,
        mut obj: Object,
    ) -> Result<CK_OBJECT_HANDLE> {
        let factory = facilities.factories.get_object_factory(&obj)?;
        let uid = obj.get_attr_as_string(CKA_UNIQUE_ID)?;
        if self.aci.encrypts() {
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

        /* remove any ephemeral attributes before storage */
        for typ in factory.get_data().get_ephemeral() {
            obj.del_attr(*typ);
        }

        let mut handle = obj.get_handle();
        if handle == CK_INVALID_HANDLE {
            handle = facilities.handles.next();
            facilities.handles.insert(handle, uid)?;
        }
        self.store.store_obj(obj)?;
        Ok(handle)
    }

    /// Updates object attributes, handling potential encryption.
    ///
    /// Fetches the object type, uses ACI to encrypt sensitive attributes in
    /// the template, then updates the raw storage.
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
        let factory = facilities.factories.get_object_factory(&obj)?;

        let mut attrs = CkAttrs::from(template);

        if self.aci.encrypts() {
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
            obj.set_attr(Attribute::from_ck_attr(ck_attr)?)?;
        }

        /* remove any ephemeral attributes before storage */
        for typ in factory.get_data().get_ephemeral() {
            obj.del_attr(*typ);
        }

        self.store.store_obj(obj)
    }

    /// Searches for objects matching the template.
    ///
    /// Performs the search on the raw storage backend, potentially adding
    /// `CKA_PRIVATE=false` if the user is not logged in.
    /// Assigns handles to results.
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

    /// Removes an object from storage by handle (via UID lookup).
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

    /// Loads token info directly from raw storage.
    fn load_token_info(&self) -> Result<StorageTokenInfo> {
        self.store.fetch_token_info()
    }

    /// Stores token info directly to raw storage.
    fn store_token_info(&mut self, info: &StorageTokenInfo) -> Result<()> {
        self.store.store_token_info(info)
    }

    /// Authenticates a user via the ACI layer.
    ///
    /// Fetches raw auth info, calls `aci.authenticate`, updates stored auth
    /// info if needed, and sets PIN status flags.
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

    /// Unauthenticates a user via the ACI layer (clears the master key).
    fn unauth_user(&mut self, user_type: CK_USER_TYPE) -> Result<()> {
        /* check it exists so we return the correct error */
        let _ = self.store.fetch_user(get_pin_uid(user_type)?)?;
        self.aci.unauth();
        Ok(())
    }

    /// Sets a user's PIN via the ACI layer.
    ///
    /// Creates new encrypted auth info using `aci.key_to_user_data` and
    /// stores it.
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
