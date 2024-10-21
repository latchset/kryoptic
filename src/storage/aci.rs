// Copyright 2024 Simo Sorce
// See LICENSE.txt file for terms

use std::fmt::Debug;

use crate::aes;
use crate::attribute::{Attribute, CkAttrs};
use crate::error::Result;
use crate::interface::*;
use crate::object::Object;
use crate::token::TokenFacilities;
use crate::{byte_ptr, get_random_data, sizeof, void_ptr};

const DEFPIN_SALT: &str = "DEFAULT SALT DATA"; /* at least 16 bytes for FIPS */
const DEFPIN_ITER: CK_ULONG = 1000;
const DEFAULT_IV_SIZE: usize = 12; /* 96 bits as required by FIPS for AES GCM */

const USER_PIN_IV: &str = "UPIN";

const MAX_LOGIN_ATTEMPTS: CK_ULONG = 10;

pub struct StorageAuthInfo {
    pub max_attempts: CK_ULONG,
    pub cur_attempts: CK_ULONG,
    pub locked: bool,
    pub update_obj: bool,
}

/* Storage abstract Authentication, Confidentialiy, Integrity
 * functionality */
#[derive(Debug)]
pub struct StorageACI {
    kek: Option<Object>,
    encrypt: bool,
}

impl StorageACI {
    pub fn new(encrypt: bool) -> StorageACI {
        StorageACI {
            kek: None,
            encrypt: encrypt,
        }
    }

    pub fn encrypts(&self) -> bool {
        self.encrypt
    }

    pub fn reset(&mut self, facilities: &TokenFacilities) -> Result<()> {
        if !self.encrypt {
            return Ok(());
        }
        let class = CKO_SECRET_KEY;
        let keytyp = CKK_AES;
        let keylen = CK_ULONG::try_from(aes::MAX_AES_SIZE_BYTES)?;
        let truebool: CK_BBOOL = CK_TRUE;
        let mut template = CkAttrs::with_capacity(3);
        template.add_ulong(CKA_CLASS, &class);
        template.add_ulong(CKA_KEY_TYPE, &keytyp);
        template.add_ulong(CKA_VALUE_LEN, &keylen);
        template.add_bool(CKA_EXTRACTABLE, &truebool);
        let aes = facilities.mechanisms.get(CKM_AES_KEY_GEN)?;
        self.kek = Some(aes.generate_key(
            &CK_MECHANISM {
                mechanism: CKM_AES_KEY_GEN,
                pParameter: std::ptr::null_mut(),
                ulParameterLen: 0,
            },
            template.as_slice(),
            &facilities.mechanisms,
            &facilities.factories,
        )?);
        Ok(())
    }

    pub fn unauth(&mut self) {
        self.kek = None;
    }

    fn wrap_kek(
        &self,
        facilities: &TokenFacilities,
        wrapper: &Object,
    ) -> Result<Vec<u8>> {
        let kek = match self.kek {
            Some(ref k) => k,
            None => return Err(CKR_USER_NOT_LOGGED_IN)?,
        };
        let vlen = kek.get_attr_as_ulong(CKA_VALUE_LEN)?;
        let bs = aes::AES_BLOCK_SIZE;
        let mut buf = vec![0u8; (((vlen as usize + bs) / bs) + 1) * bs];
        let aes = facilities.mechanisms.get(CKM_AES_KEY_WRAP_KWP)?;
        let factory = facilities.factories.get_object_factory(&kek)?;
        let outlen = aes.wrap_key(
            &CK_MECHANISM {
                mechanism: CKM_AES_KEY_WRAP_KWP,
                pParameter: void_ptr!(USER_PIN_IV.as_ptr()),
                ulParameterLen: USER_PIN_IV.len() as CK_ULONG,
            },
            wrapper,
            &kek,
            buf.as_mut_slice(),
            factory,
        )?;
        buf.resize(outlen, 0);
        Ok(buf)
    }

    fn unwrap_kek(
        &mut self,
        facilities: &TokenFacilities,
        wrapper: &Object,
        wrapped: &Object,
    ) -> Result<Object> {
        let data = wrapped.get_attr_as_bytes(CKA_VALUE)?.as_slice();
        let class = CKO_SECRET_KEY;
        let keytyp = CKK_AES;
        let keylen = aes::MAX_AES_SIZE_BYTES as CK_ULONG;
        let truebool: CK_BBOOL = CK_TRUE;
        let mut template = CkAttrs::with_capacity(5);
        template.add_ulong(CKA_CLASS, &class);
        template.add_ulong(CKA_KEY_TYPE, &keytyp);
        template.add_ulong(CKA_VALUE_LEN, &keylen);
        template.add_bool(CKA_ENCRYPT, &truebool);
        template.add_bool(CKA_DECRYPT, &truebool);
        template.add_bool(CKA_EXTRACTABLE, &truebool);
        let aes = facilities.mechanisms.get(CKM_AES_KEY_WRAP_KWP)?;
        aes.unwrap_key(
            &CK_MECHANISM {
                mechanism: CKM_AES_KEY_WRAP_KWP,
                pParameter: void_ptr!(USER_PIN_IV.as_ptr()),
                ulParameterLen: USER_PIN_IV.len() as CK_ULONG,
            },
            wrapper,
            data,
            template.as_slice(),
            facilities
                .factories
                .get_obj_factory_from_key_template(template.as_slice())?,
        )
    }

    /* We should probably have lifetimes to ensure iv and aad are around for
     * the lifetime of the returned structure, but this will require substantial
     * reworking of the bindings, so for now we just get this comment.
     * ENSURE the arguments stay in scope until CK_GCM_PARAMS is needed
     * */
    fn encryption_params(iv: &[u8], aad: &[u8]) -> CK_GCM_PARAMS {
        CK_GCM_PARAMS {
            pIv: iv.as_ptr() as *mut CK_BYTE,
            ulIvLen: iv.len() as CK_ULONG,
            ulIvBits: (iv.len() * 8) as CK_ULONG,
            pAAD: aad.as_ptr() as *mut CK_BYTE,
            ulAADLen: aad.len() as CK_ULONG,
            ulTagBits: 64 as CK_ULONG,
        }
    }

    pub fn encrypt_value(
        &self,
        facilities: &TokenFacilities,
        uid: &String,
        val: &Vec<u8>,
    ) -> Result<Vec<u8>> {
        if let Some(ref kek) = self.kek {
            let mut iv = [0u8; DEFAULT_IV_SIZE];
            get_random_data(&mut iv)?;
            let mut params = Self::encryption_params(&iv, uid.as_bytes());
            let mech: CK_MECHANISM = CK_MECHANISM {
                mechanism: CKM_AES_GCM,
                pParameter: &mut params as *mut CK_GCM_PARAMS as *mut _,
                ulParameterLen: sizeof!(CK_GCM_PARAMS),
            };
            let aes = facilities.mechanisms.get(CKM_AES_GCM)?;
            let mut op = aes.encryption_new(&mech, &kek)?;
            let clen = op.encryption_len(val.len(), false)?;
            let mut encval = vec![0u8; iv.len() + clen];
            encval[..iv.len()].copy_from_slice(&iv);
            let outlen = op.encrypt(
                val.as_slice(),
                &mut encval.as_mut_slice()[iv.len()..],
            )?;
            encval.resize(iv.len() + outlen, 0);
            return Ok(encval);
        } else {
            return Err(CKR_GENERAL_ERROR)?;
        }
    }

    pub fn decrypt_value(
        &self,
        facilities: &TokenFacilities,
        uid: &String,
        val: &Vec<u8>,
    ) -> Result<Vec<u8>> {
        if let Some(ref kek) = self.kek {
            let mut params = Self::encryption_params(
                &val.as_slice()[..DEFAULT_IV_SIZE],
                uid.as_bytes(),
            );
            let mech: CK_MECHANISM = CK_MECHANISM {
                mechanism: CKM_AES_GCM,
                pParameter: &mut params as *mut CK_GCM_PARAMS as *mut _,
                ulParameterLen: sizeof!(CK_GCM_PARAMS),
            };
            let aes = facilities.mechanisms.get(CKM_AES_GCM)?;
            let mut op = aes.decryption_new(&mech, &kek)?;
            let mut plain =
                vec![
                    0u8;
                    op.decryption_len(val.len() - DEFAULT_IV_SIZE, false)?
                ];
            let outlen = op.decrypt(
                &val.as_slice()[DEFAULT_IV_SIZE..],
                plain.as_mut_slice(),
            )?;
            plain.resize(outlen, 0);
            return Ok(plain);
        } else {
            return Err(CKR_GENERAL_ERROR)?;
        }
    }

    fn random_salt(&self) -> Result<String> {
        let mut data = [0u8; 8];
        get_random_data(&mut data)?;
        Ok(hex::encode(data))
    }

    fn parse_auth_object_label(
        &self,
        obj: &Object,
    ) -> Result<(String, CK_ULONG)> {
        let label = obj.get_attr_as_string(CKA_LABEL)?;
        let parts: Vec<_> = label.as_str().split(":").collect();
        if parts.len() != 2 {
            return Err(CKR_GENERAL_ERROR)?;
        }
        Ok((
            parts[0].to_string(),
            match parts[1].parse::<CK_ULONG>() {
                Ok(u) => u,
                Err(_) => return Err(CKR_GENERAL_ERROR)?,
            },
        ))
    }

    fn pin_to_unlock_key(
        &mut self,
        facilities: &TokenFacilities,
        pin: &[u8],
        salt: Option<String>,
        iter: Option<CK_ULONG>,
    ) -> Result<Object> {
        let insalt: String;
        let psalt: &str = match salt {
            Some(s) => {
                insalt = s;
                insalt.as_str()
            }
            None => DEFPIN_SALT,
        };
        let iterations = match iter {
            Some(i) => i,
            None => DEFPIN_ITER,
        };
        let params = CK_PKCS5_PBKD2_PARAMS2 {
            saltSource: CKZ_DATA_SPECIFIED,
            pSaltSourceData: void_ptr!(psalt.as_ptr()),
            ulSaltSourceDataLen: CK_ULONG::try_from(psalt.len())?,
            iterations: iterations,
            prf: CKP_PKCS5_PBKD2_HMAC_SHA512,
            pPrfData: std::ptr::null_mut(),
            ulPrfDataLen: 0,
            pPassword: byte_ptr!(pin.as_ptr()),
            ulPasswordLen: pin.len() as CK_ULONG,
        };
        let class = CKO_SECRET_KEY;
        let keytyp = CKK_AES;
        let keylen = aes::MAX_AES_SIZE_BYTES as CK_ULONG;
        let label = format!("{}:{}", psalt, iterations);
        let truebool: CK_BBOOL = CK_TRUE;
        let mut template = CkAttrs::with_capacity(6);
        template.add_slice(CKA_LABEL, label.as_bytes())?;
        template.add_ulong(CKA_CLASS, &class);
        template.add_ulong(CKA_KEY_TYPE, &keytyp);
        template.add_ulong(CKA_VALUE_LEN, &keylen);
        template.add_bool(CKA_WRAP, &truebool);
        template.add_bool(CKA_UNWRAP, &truebool);
        let pbkdf2 = facilities.mechanisms.get(CKM_PKCS5_PBKD2)?;
        pbkdf2.generate_key(
            &CK_MECHANISM {
                mechanism: CKM_PKCS5_PBKD2,
                pParameter: &params as *const _ as *mut _,
                ulParameterLen: sizeof!(CK_PKCS5_PBKD2_PARAMS2),
            },
            template.as_slice(),
            &facilities.mechanisms,
            &facilities.factories,
        )
    }

    fn kek_to_wrapped_object(
        &mut self,
        facilities: &TokenFacilities,
        uid: &String,
        key: Object,
    ) -> Result<Object> {
        /* label contains the salt and iterations information
         * to recover the wrapping key from a pin */
        let label = key.get_attr_as_string(CKA_LABEL)?;
        let wrapped = self.wrap_kek(facilities, &key)?;
        let mut obj = Object::new();
        obj.set_zeroize();
        obj.set_attr(Attribute::from_string(CKA_UNIQUE_ID, uid.clone()))?;
        obj.set_attr(Attribute::from_bool(CKA_TOKEN, true))?;
        obj.set_attr(Attribute::from_ulong(CKA_CLASS, CKO_SECRET_KEY))?;
        obj.set_attr(Attribute::from_ulong(CKA_KEY_TYPE, CKK_GENERIC_SECRET))?;
        obj.set_attr(Attribute::from_string(CKA_LABEL, label))?;
        obj.set_attr(Attribute::from_bytes(CKA_VALUE, wrapped))?;
        obj.set_attr(Attribute::from_ulong(
            KRA_MAX_LOGIN_ATTEMPTS,
            MAX_LOGIN_ATTEMPTS,
        ))?;
        obj.set_attr(Attribute::from_ulong(KRA_LOGIN_ATTEMPTS, 0))?;

        Ok(obj)
    }

    pub fn auth_object_is_default(&self, obj: &Object) -> Result<bool> {
        Ok(self.parse_auth_object_label(obj)?.0 == DEFPIN_SALT)
    }

    /// Returns, the max available and the current attempts at
    /// authentication that resulted in a failure. A successful
    /// authentication causes current to return to 0
    pub fn user_attempts(&self, obj: &Object) -> Result<StorageAuthInfo> {
        let max = obj.get_attr_as_ulong(KRA_MAX_LOGIN_ATTEMPTS)?;
        let cur = obj.get_attr_as_ulong(KRA_LOGIN_ATTEMPTS)?;
        Ok(StorageAuthInfo {
            max_attempts: max,
            cur_attempts: cur,
            locked: cur >= max,
            update_obj: false,
        })
    }

    /// Creates a user authentication token by deriving a key from the pin.
    ///
    /// If encryption is enabled, then the kek is wrapped with this key
    /// and returned as the auth token.
    ///
    /// Otherwise the derived key is returned as the token.
    ///
    /// If the pin is not empty, it uses a random salt, otherwise uses
    /// the DEFAULT SALT (this is also used as indication that the PIN
    /// needs to be reset).
    pub fn make_auth_object(
        &mut self,
        facilities: &TokenFacilities,
        uid: &String,
        pin: &[u8],
    ) -> Result<Object> {
        let salt = if pin.len() == 0 {
            None
        } else {
            Some(self.random_salt()?)
        };
        let mut key = self.pin_to_unlock_key(facilities, pin, salt, None)?;
        if self.encrypt {
            self.kek_to_wrapped_object(facilities, uid, key)
        } else {
            key.set_attr(Attribute::from_string(CKA_UNIQUE_ID, uid.clone()))?;
            Ok(key)
        }
    }

    pub fn authenticate(
        &mut self,
        facilities: &TokenFacilities,
        auth_obj: &mut Object,
        pin: &[u8],
        set_kek: bool,
    ) -> Result<StorageAuthInfo> {
        let mut info = self.user_attempts(&auth_obj)?;
        if info.locked {
            return Ok(info);
        }

        let (salt, iterations) = self.parse_auth_object_label(auth_obj)?;
        let key = self.pin_to_unlock_key(
            facilities,
            pin,
            Some(salt),
            Some(iterations),
        )?;

        let stored = info.cur_attempts;
        if self.encrypt {
            match self.unwrap_kek(facilities, &key, auth_obj) {
                Ok(k) => {
                    if set_kek {
                        self.kek = Some(k);
                    }
                    info.cur_attempts = 0;
                }
                Err(_) => info.cur_attempts += 1,
            }
        } else {
            let stored_value = auth_obj.get_attr_as_bytes(CKA_VALUE)?;
            let value = key.get_attr_as_bytes(CKA_VALUE)?;

            if value == stored_value {
                info.cur_attempts = 0;
            } else {
                info.cur_attempts += 1;
            }
        }

        /* Store attempts back to token */
        if info.cur_attempts != stored {
            info.update_obj = true;
            auth_obj.set_attr(Attribute::from_ulong(
                KRA_LOGIN_ATTEMPTS,
                info.cur_attempts,
            ))?;
        }
        Ok(info)
    }
}
