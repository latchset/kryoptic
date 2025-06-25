// Copyright 2024 Simo Sorce
// See LICENSE.txt file for terms

//! This module implements Authentication, Confidentiality, and Integrity (ACI)
//! mechanisms for securing stored data, like private keys and potentially
//! other sensitive information within a storage backend. It utilizes PBKDF2,
//! HKDF, and AES-GCM.

use std::fmt::Debug;

use crate::aes;
use crate::attribute::CkAttrs;
use crate::error::Result;
use crate::kasn1::*;
use crate::misc::{byte_ptr, sizeof, void_ptr, zeromem};
use crate::object::Object;
use crate::pkcs11::*;
use crate::token::TokenFacilities;
use crate::CSPRNG;

use asn1;

/// Derives a key using PBKDF2 (CKM_PKCS5_PBKD2) based on PKCS#5 v2.1.
///
/// Uses the provided ASN.1 `PBKDF2Params` to configure the underlying
/// PKCS#11 mechanism call.
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

/// Derives a key using the HKDF-Expand phase (CKM_HKDF_DERIVE).
///
/// Uses the provided ASN.1 `KKDF1Params` (specifically the `info` field)
/// and the input `key` object (as the PRK) to configure the mechanism call.
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

/// Encrypts data using AES-GCM (CKM_AES_GCM).
///
/// Generates a random 12-byte IV. Uses the provided `key` object,
/// `aad` (Additional Authenticated Data), and plaintext `data`.
/// Returns the ASN.1 encoded `KGCMParams` (containing the IV and tag) and
/// the resulting ciphertext.
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

/// Decrypts data using AES-GCM (CKM_AES_GCM).
///
/// Uses the provided `key` object, `gcm_params` (containing IV and tag),
/// `aad` (Additional Authenticated Data), and ciphertext `data`.
/// Verifies the tag and returns the decrypted plaintext.
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

/// Helper function to produce a template for a secret key to be
/// used with PKCS#11 functions.
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

/// Encrypts a cryptographic key using a PIN-derived KEK.
///
/// Derives a KEK from the `pin` using PBKDF2 with the specified `iterations`
/// and a random salt. Encrypts the input `key` using AES-GCM with the KEK,
/// using the `id` string as AAD. Encodes the KDF parameters, GCM parameters
/// (IV, tag), and ciphertext into a `KProtectedData` ASN.1 structure.
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

/// Decrypts a cryptographic key previously encrypted with `encrypt_key`.
///
/// Parses the `KProtectedData` structure from the input `data`. Re-derives
/// the KEK using PBKDF2 with the provided `pin` and the parameters stored
/// in the structure. Decrypts the ciphertext using AES-GCM with the KEK,
/// verifying the tag and using the `id` string as AAD. Returns the key
/// version number stored in the structure and the decrypted key bytes.
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

/// Encrypts arbitrary data using a derived key encryption key (DEK).
///
/// Derives a DEK from the master `key` using HKDF-Expand (RFC 5869) with the
/// `data_id` as the `info` parameter. Encrypts the input `data` using AES-GCM
/// with the DEK, using the `data_id` as AAD. Encodes the KDF parameters, GCM
/// parameters (IV, tag), key version, and ciphertext into a `KProtectedData`
/// ASN.1 structure.
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

/// Decrypts data previously encrypted with `encrypt_data`.
///
/// Parses the `KProtectedData` structure from the input `data`. Verifies the
/// `key_version`. Re-derives the DEK using HKDF-Expand with the master `key`
/// and the parameters stored in the structure (using `data_id` as info).
/// Decrypts the ciphertext using AES-GCM with the DEK, verifying the tag
/// and using the `data_id` as AAD. Returns the decrypted data bytes.
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

/// Default maximum number of failed login attempts before locking.
const MAX_LOGIN_ATTEMPTS: CK_ULONG = 10;

/// Holds authentication information for a user (SO or User), typically
/// stored persistently (though potentially encrypted).
#[derive(Clone, Debug)]
pub struct StorageAuthInfo {
    /// Flag indicating if the PIN is the default one (not yet set by user).
    pub default_pin: bool,
    /// Encrypted master key data (if encryption enabled) or placeholder.
    pub user_data: Option<Vec<u8>>,
    /// Maximum allowed login attempts before locking.
    pub max_attempts: CK_ULONG,
    /// Current number of failed login attempts since last success.
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
    /// Returns `true` if the user account is currently locked due to too
    /// many failed login attempts.
    pub fn locked(&self) -> bool {
        self.cur_attempts >= self.max_attempts
    }
}

/// Manages Authentication, Confidentiality, and Integrity for the storage
/// backend.
///
/// Holds the master key (if encryption is enabled and user is authenticated)
/// and provides methods to encrypt/decrypt data and manage user
/// authentication based on PINs.
#[derive(Debug)]
pub struct StorageACI {
    /// Default number of iterations for PBKDF2 when wrapping the master key.
    def_iterations: usize,
    /// Current version number of the master key. Incremented on key change.
    key_version: u64,
    /// The master key object (optional, only present when authenticated).
    key: Option<Object>,
    /// Flag indicating if confidentiality (encryption) is enabled.
    encrypt: bool,
}

impl StorageACI {
    /// Instantiate a new ACI manager
    pub fn new(encrypt: bool) -> StorageACI {
        StorageACI {
            def_iterations: 1000,
            key_version: 0,
            key: None,
            encrypt: encrypt,
        }
    }

    /// Returns `true` if storage encryption is enabled.
    pub fn encrypts(&self) -> bool {
        self.encrypt
    }

    /// Resets the ACI state, generating a new master key if encryption is
    /// enabled.
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

    /// Clears the currently held master key (e.g., on logout).
    pub fn unauth(&mut self) {
        self.key = None;
    }

    /// Encrypts a value using the current master key.
    ///
    /// Derives a DEK using HKDF and encrypts using AES-GCM. Uses `uid` as AAD.
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

    /// Decrypts a value using the current master key.
    ///
    /// Derives the DEK using HKDF and decrypts using AES-GCM.
    /// Uses `uid` as AAD and verifies the key version and tag.
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

    /// Authenticates a user against their stored `StorageAuthInfo` using a PIN.
    ///
    /// Decrypts the `user_data` using a key derived from the `pin` via PBKDF2.
    /// If successful and encryption is enabled, it verifies the decrypted
    /// master key (or placeholder) and optionally sets the active master key
    /// (`self.key`) if `set_key` is true. Updates the attempt counter in
    /// info`. Returns `Ok(true)` if the attempt counter changed, `Ok(false)`
    /// otherwise, or an error.
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
