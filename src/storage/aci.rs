// Copyright 2024 Simo Sorce
// See LICENSE.txt file for terms

use std::fmt::Debug;

use crate::aes;
use crate::attribute::CkAttrs;
use crate::error::Result;
use crate::interface::*;
use crate::kasn1::*;
use crate::misc::{byte_ptr, sizeof, void_ptr, zeromem};
use crate::object::Object;
use crate::token::TokenFacilities;
use crate::CSPRNG;

use asn1;

pub fn pbkdf2_derive(
    facilities: &TokenFacilities,
    params: &pkcs::PBKDF2Params,
    secret: &[u8],
    key_template: &[CK_ATTRIBUTE],
) -> Result<Object> {
    let mech = facilities.mechanisms.get(CKM_PKCS5_PBKD2)?;

    let ck_params = CK_PKCS5_PBKD2_PARAMS2 {
        saltSource: CKZ_SALT_SPECIFIED,
        pSaltSourceData: void_ptr!(params.salt.as_ptr()),
        ulSaltSourceDataLen: CK_ULONG::try_from(params.salt.len())?,
        iterations: CK_ULONG::try_from(params.iteration_count)?,
        prf: match params.prf.oid() {
            &oid::HMAC_WITH_SHA1_OID => CKP_PKCS5_PBKD2_HMAC_SHA1,
            &oid::HMAC_WITH_SHA256_OID => CKP_PKCS5_PBKD2_HMAC_SHA256,
            _ => return Err(CKR_MECHANISM_PARAM_INVALID)?,
        },
        pPrfData: std::ptr::null_mut(),
        ulPrfDataLen: 0,
        pPassword: byte_ptr!(secret.as_ptr()),
        ulPasswordLen: CK_ULONG::try_from(secret.len())?,
    };

    mech.generate_key(
        &CK_MECHANISM {
            mechanism: CKM_PKCS5_PBKD2,
            pParameter: void_ptr!(&ck_params),
            ulParameterLen: sizeof!(CK_PKCS5_PBKD2_PARAMS2),
        },
        key_template,
        &facilities.mechanisms,
        &facilities.factories,
    )
}

fn hkdf_expand(
    facilities: &TokenFacilities,
    params: &KKDF1Params,
    key: &Object,
    key_template: &[CK_ATTRIBUTE],
) -> Result<Object> {
    let mech = facilities.mechanisms.get(CKM_HKDF_DERIVE)?;

    let hkdf_params = CK_HKDF_PARAMS {
        bExtract: CK_FALSE,
        bExpand: CK_TRUE,
        prfHashMechanism: CKM_SHA256,
        ulSaltType: CKF_HKDF_SALT_NULL,
        pSalt: std::ptr::null_mut(),
        ulSaltLen: 0,
        hSaltKey: CK_INVALID_HANDLE,
        pInfo: byte_ptr!(params.info.as_ptr()),
        ulInfoLen: params.info.len() as CK_ULONG,
    };

    let mut op = mech.derive_operation(&CK_MECHANISM {
        mechanism: CKM_HKDF_DERIVE,
        pParameter: void_ptr!(&hkdf_params),
        ulParameterLen: sizeof!(CK_HKDF_PARAMS),
    })?;

    let mut vobj = op.derive(
        key,
        key_template,
        &facilities.mechanisms,
        &facilities.factories,
    )?;
    if vobj.len() != 1 {
        return Err(CKR_GENERAL_ERROR)?;
    }
    match vobj.pop() {
        Some(obj) => Ok(obj),
        None => Err(CKR_GENERAL_ERROR)?,
    }
}

fn aes_gcm_encrypt(
    facilities: &TokenFacilities,
    key: &Object,
    aad: &[u8],
    data: &[u8],
) -> Result<(KGCMParams, Vec<u8>)> {
    let mut gcm_params = KGCMParams {
        aes_iv: [0u8; 12],
        aes_tag: [0u8; 8],
    };

    let ck_mech = CK_MECHANISM {
        mechanism: CKM_AES_GCM,
        pParameter: std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    let mech = facilities.mechanisms.get(CKM_AES_GCM)?;
    let mut op = mech.msg_encryption_op(&ck_mech, key)?;

    let mut encrypted = vec![0u8; op.msg_encryption_len(data.len(), false)?];

    let mut params = CK_GCM_MESSAGE_PARAMS {
        pIv: gcm_params.aes_iv.as_mut_ptr(),
        ulIvLen: gcm_params.aes_iv.len() as CK_ULONG,
        ulIvFixedBits: 0,
        ivGenerator: CKG_GENERATE_RANDOM,
        pTag: gcm_params.aes_tag.as_mut_ptr(),
        ulTagBits: (gcm_params.aes_tag.len() * 8) as CK_ULONG,
    };

    let len = op.msg_encrypt(
        void_ptr!(&mut params),
        sizeof!(CK_GCM_MESSAGE_PARAMS),
        aad,
        data,
        &mut encrypted,
    )?;
    encrypted.resize(len, 0);

    Ok((gcm_params, encrypted))
}

fn aes_gcm_decrypt(
    facilities: &TokenFacilities,
    key: &Object,
    gcm_params: &KGCMParams,
    aad: &[u8],
    data: &[u8],
) -> Result<Vec<u8>> {
    let ck_mech = CK_MECHANISM {
        mechanism: CKM_AES_GCM,
        pParameter: std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    let mech = facilities.mechanisms.get(CKM_AES_GCM)?;
    let mut op = mech.msg_decryption_op(&ck_mech, key)?;

    let mut decrypted = vec![0u8; op.msg_decryption_len(data.len(), false)?];

    let mut params = CK_GCM_MESSAGE_PARAMS {
        pIv: byte_ptr!(gcm_params.aes_iv.as_ptr()),
        ulIvLen: gcm_params.aes_iv.len() as CK_ULONG,
        ulIvFixedBits: 0,
        ivGenerator: CKG_NO_GENERATE,
        pTag: byte_ptr!(gcm_params.aes_tag.as_ptr()),
        ulTagBits: (gcm_params.aes_tag.len() * 8) as CK_ULONG,
    };

    let len = op.msg_decrypt(
        void_ptr!(&mut params),
        sizeof!(CK_GCM_MESSAGE_PARAMS),
        aad,
        data,
        &mut decrypted,
    )?;
    decrypted.resize(len, 0);

    Ok(decrypted)
}

const SHA256_LEN: usize = 32;
const GEN_KEYTYP: CK_ULONG = CKK_GENERIC_SECRET;
const AES_KEYTYP: CK_ULONG = CKK_AES;
const AES_KEYLEN: CK_ULONG = aes::MAX_AES_SIZE_BYTES as CK_ULONG;

fn secret_key_template<'a>(
    keytype: &'a CK_ULONG,
    keylen: &'a CK_ULONG,
) -> CkAttrs<'a> {
    const CLASS: CK_ATTRIBUTE_TYPE = CKO_SECRET_KEY;
    const TRUEBOOL: CK_BBOOL = CK_TRUE;
    let mut template = CkAttrs::with_capacity(5);
    template.add_ulong(CKA_CLASS, &CLASS);
    template.add_ulong(CKA_KEY_TYPE, keytype);
    template.add_ulong(CKA_VALUE_LEN, keylen);
    if *keytype == CKK_GENERIC_SECRET {
        template.add_bool(CKA_DERIVE, &TRUEBOOL);
    } else {
        template.add_bool(CKA_DECRYPT, &TRUEBOOL);
        template.add_bool(CKA_ENCRYPT, &TRUEBOOL);
    }
    template
}

fn encrypt_key(
    facilities: &TokenFacilities,
    id: &str,
    pin: &[u8],
    iterations: usize,
    key_version: u64,
    key: &[u8],
) -> Result<Vec<u8>> {
    let mut salt: [u8; SHA256_LEN] = [0u8; SHA256_LEN];
    CSPRNG.with(|rng| rng.borrow_mut().generate_random(&mut salt))?;

    let pbkdf2_params = pkcs::PBKDF2Params {
        salt: &salt,
        iteration_count: u64::try_from(iterations)?,
        key_length: Some(AES_KEYLEN as u64),
        prf: Box::new(pkcs::HMAC_SHA_256_ALG),
    };

    /* compute key */
    let key_template = secret_key_template(&AES_KEYTYP, &AES_KEYLEN);
    let kek = pbkdf2_derive(
        facilities,
        &pbkdf2_params,
        pin,
        key_template.as_slice(),
    )?;
    let (gcm, data) = aes_gcm_encrypt(facilities, &kek, id.as_bytes(), key)?;

    let enc_params = KAlgorithmIdentifier {
        oid: asn1::DefinedByMarker::marker(),
        params: KAlgorithmParameters::Aes256Gcm(gcm),
    };

    let pdata = KProtectedData {
        algorithm: Box::new(KAlgorithmIdentifier {
            oid: asn1::DefinedByMarker::marker(),
            params: KAlgorithmParameters::Kkbps1(KKBPS1Params {
                key_version_number: key_version,
                key_derivation_func: Box::new(KAlgorithmIdentifier {
                    oid: asn1::DefinedByMarker::marker(),
                    params: KAlgorithmParameters::Pbkdf2(pbkdf2_params),
                }),
                encryption_scheme: Box::new(enc_params),
            }),
        }),
        data: &data,
        signature: None,
    };

    match asn1::write_single(&pdata) {
        Ok(der) => Ok(der),
        Err(_) => Err(CKR_GENERAL_ERROR)?,
    }
}

fn decrypt_key(
    facilities: &TokenFacilities,
    id: &str,
    pin: &[u8],
    data: &[u8],
) -> Result<(u64, Vec<u8>)> {
    let pdata = match asn1::parse_single::<KProtectedData>(data) {
        Ok(p) => p,
        Err(_) => return Err(CKR_DATA_INVALID)?,
    };

    let kkbps1 = match &pdata.algorithm.params {
        KAlgorithmParameters::Kkbps1(params) => params,
        _ => return Err(CKR_MECHANISM_INVALID)?,
    };

    let key = match &kkbps1.key_derivation_func.params {
        KAlgorithmParameters::Pbkdf2(params) => {
            if let Some(keylen) = params.key_length {
                if keylen != AES_KEYLEN as u64 {
                    return Err(CKR_MECHANISM_PARAM_INVALID)?;
                }
            }
            let key_template = secret_key_template(&AES_KEYTYP, &AES_KEYLEN);

            pbkdf2_derive(facilities, params, pin, key_template.as_slice())?
        }
        _ => return Err(CKR_MECHANISM_INVALID)?,
    };
    let params = match &kkbps1.encryption_scheme.params {
        KAlgorithmParameters::Aes128Gcm(gcm) => gcm,
        KAlgorithmParameters::Aes192Gcm(gcm) => gcm,
        KAlgorithmParameters::Aes256Gcm(gcm) => gcm,
        _ => return Err(CKR_MECHANISM_INVALID)?,
    };
    Ok((
        kkbps1.key_version_number,
        aes_gcm_decrypt(facilities, &key, params, id.as_bytes(), pdata.data)?,
    ))
}

fn encrypt_data(
    facilities: &TokenFacilities,
    key_version: u64,
    key: &Object,
    data_id: &str,
    data: &[u8],
) -> Result<Vec<u8>> {
    let kdf_params = KKDF1Params {
        prf: Box::new(KAlgorithmIdentifier {
            oid: asn1::DefinedByMarker::marker(),
            params: KAlgorithmParameters::HmacWithSha256(Some(())),
        }),
        info: data_id.as_bytes(),
        key_length: AES_KEYLEN as u64,
    };

    /* compute key */
    let key_template = secret_key_template(&AES_KEYTYP, &AES_KEYLEN);
    let dek =
        hkdf_expand(facilities, &kdf_params, key, key_template.as_slice())?;
    let (gcm, encrypted) =
        aes_gcm_encrypt(facilities, &dek, data_id.as_bytes(), data)?;

    /* We use a 256 bit key so Aes256Gcm is the correct algorithm */
    let enc_params = KAlgorithmIdentifier {
        oid: asn1::DefinedByMarker::marker(),
        params: KAlgorithmParameters::Aes256Gcm(gcm),
    };

    let pdata = KProtectedData {
        algorithm: Box::new(KAlgorithmIdentifier {
            oid: asn1::DefinedByMarker::marker(),
            params: KAlgorithmParameters::Kkbps1(KKBPS1Params {
                key_version_number: key_version,
                key_derivation_func: Box::new(KAlgorithmIdentifier {
                    oid: asn1::DefinedByMarker::marker(),
                    params: KAlgorithmParameters::Kkdf1(kdf_params),
                }),
                encryption_scheme: Box::new(enc_params),
            }),
        }),
        data: &encrypted,
        signature: None,
    };

    match asn1::write_single(&pdata) {
        Ok(der) => Ok(der),
        Err(_) => Err(CKR_GENERAL_ERROR)?,
    }
}

fn decrypt_data(
    facilities: &TokenFacilities,
    key_version: u64,
    key: &Object,
    data_id: &str,
    data: &[u8],
) -> Result<Vec<u8>> {
    let pdata = match asn1::parse_single::<KProtectedData>(data) {
        Ok(p) => p,
        Err(_) => return Err(CKR_DATA_INVALID)?,
    };

    let kkbps1 = match &pdata.algorithm.params {
        KAlgorithmParameters::Kkbps1(params) => params,
        _ => return Err(CKR_MECHANISM_INVALID)?,
    };
    if kkbps1.key_version_number != key_version {
        return Err(CKR_KEY_CHANGED)?;
    }

    let dek = match &kkbps1.key_derivation_func.params {
        KAlgorithmParameters::Kkdf1(params) => {
            if params.key_length != AES_KEYLEN as u64 {
                return Err(CKR_MECHANISM_PARAM_INVALID)?;
            }

            let key_template = secret_key_template(&AES_KEYTYP, &AES_KEYLEN);
            hkdf_expand(facilities, &params, key, key_template.as_slice())?
        }
        _ => return Err(CKR_MECHANISM_INVALID)?,
    };
    let params = match &kkbps1.encryption_scheme.params {
        KAlgorithmParameters::Aes128Gcm(gcm) => gcm,
        KAlgorithmParameters::Aes192Gcm(gcm) => gcm,
        KAlgorithmParameters::Aes256Gcm(gcm) => gcm,
        _ => return Err(CKR_MECHANISM_INVALID)?,
    };
    aes_gcm_decrypt(facilities, &dek, params, data_id.as_bytes(), pdata.data)
}

const MAX_LOGIN_ATTEMPTS: CK_ULONG = 10;

#[derive(Clone, Debug)]
pub struct StorageAuthInfo {
    pub default_pin: bool,
    pub user_data: Option<Vec<u8>>,
    pub max_attempts: CK_ULONG,
    pub cur_attempts: CK_ULONG,
}

impl Default for StorageAuthInfo {
    fn default() -> StorageAuthInfo {
        StorageAuthInfo {
            default_pin: false,
            user_data: None,
            max_attempts: MAX_LOGIN_ATTEMPTS,
            cur_attempts: 0,
        }
    }
}

impl Drop for StorageAuthInfo {
    fn drop(&mut self) {
        if let Some(ref mut data) = self.user_data {
            zeromem(data.as_mut_slice());
        }
    }
}

impl StorageAuthInfo {
    pub fn locked(&self) -> bool {
        self.cur_attempts >= self.max_attempts
    }
}

/* Storage abstract Authentication, Confidentialiy, Integrity
 * functionality */
#[derive(Debug)]
pub struct StorageACI {
    def_iterations: usize,
    key_version: u64,
    key: Option<Object>,
    encrypt: bool,
}

impl StorageACI {
    pub fn new(encrypt: bool) -> StorageACI {
        StorageACI {
            def_iterations: 1000,
            key_version: 0,
            key: None,
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
        /* Need to use a generic secret here, because the secret key
         * is used together with HKDF to derive the actual encryption
         * key and HKDF allows only CKK_HKDF or CKK_GENERIC_SECRET */
        let template = secret_key_template(&GEN_KEYTYP, &AES_KEYLEN);
        let mech = facilities.mechanisms.get(CKM_GENERIC_SECRET_KEY_GEN)?;
        self.key_version += 1;
        self.key = Some(mech.generate_key(
            &CK_MECHANISM {
                mechanism: CKM_GENERIC_SECRET_KEY_GEN,
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
        self.key = None;
    }

    pub fn encrypt_value(
        &self,
        facilities: &TokenFacilities,
        uid: &String,
        val: &Vec<u8>,
    ) -> Result<Vec<u8>> {
        match self.key {
            Some(ref key) => encrypt_data(
                facilities,
                self.key_version,
                key,
                uid.as_str(),
                val.as_slice(),
            ),
            _ => {
                return Err(CKR_GENERAL_ERROR)?;
            }
        }
    }

    pub fn decrypt_value(
        &self,
        facilities: &TokenFacilities,
        uid: &String,
        val: &Vec<u8>,
    ) -> Result<Vec<u8>> {
        match self.key {
            Some(ref key) => decrypt_data(
                facilities,
                self.key_version,
                key,
                uid.as_str(),
                val.as_slice(),
            ),
            _ => {
                return Err(CKR_GENERAL_ERROR)?;
            }
        }
    }

    /// Creates a user authentication token by deriving a key encryption
    /// key (kek) from the pin.
    ///
    /// If encryption is enabled, then the encryption key is wrapped
    /// with this key and returned as the auth token.
    ///
    /// Otherwise the derived key is returned as the token.
    pub fn key_to_user_data(
        &mut self,
        facilities: &TokenFacilities,
        uid: &str,
        pin: &[u8],
    ) -> Result<StorageAuthInfo> {
        let mut info = StorageAuthInfo::default();
        let ek = if self.encrypt {
            match self.key {
                Some(ref k) => k.get_attr_as_bytes(CKA_VALUE)?.as_slice(),
                None => return Err(CKR_USER_NOT_LOGGED_IN)?,
            }
        } else {
            "NO ENCRYPTION".as_bytes()
        };
        info.user_data = Some(encrypt_key(
            facilities,
            uid,
            pin,
            self.def_iterations,
            self.key_version,
            ek,
        )?);
        Ok(info)
    }

    pub fn authenticate(
        &mut self,
        facilities: &TokenFacilities,
        uid: &str,
        info: &mut StorageAuthInfo,
        pin: &[u8],
        set_key: bool,
    ) -> Result<bool> {
        if info.locked() {
            return Ok(false);
        }

        let stored = info.cur_attempts;
        let wrapped = match &info.user_data {
            Some(data) => data.as_slice(),
            None => return Err(CKR_GENERAL_ERROR)?,
        };
        match decrypt_key(facilities, uid, pin, wrapped) {
            Ok((key_version, key)) => {
                if self.encrypt {
                    if set_key {
                        let mut template =
                            secret_key_template(&GEN_KEYTYP, &AES_KEYLEN);
                        template.add_vec(CKA_VALUE, key)?;
                        self.key_version = key_version;
                        self.key = Some(
                            facilities.factories.create(template.as_slice())?,
                        );
                    }
                    info.cur_attempts = 0;
                } else {
                    if key.as_slice() == "NO ENCRYPTION".as_bytes() {
                        info.cur_attempts = 0;
                    } else {
                        info.cur_attempts += 1;
                    }
                }
            }
            Err(_) => info.cur_attempts += 1,
        }

        /* Indicate if data has changed */
        Ok(info.cur_attempts != stored)
    }
}
