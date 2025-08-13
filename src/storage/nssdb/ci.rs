// Copyright 2024 Simo Sorce
// See LICENSE.txt file for terms

//! This module implements the cryptographic operations needed for NSS database
//! compatibility, specifically focusing on Content Integrity (CI) which
//! involves encrypting sensitive attributes and signing certain attributes for
//! integrity protection, using keys derived from the user's PIN via PBKDF2.

use std::collections::BTreeMap;
use std::sync::{RwLock, RwLockReadGuard};

use crate::attribute::CkAttrs;
use crate::error::Result;
use crate::kasn1::oid::*;
use crate::kasn1::pkcs::*;
use crate::misc::{sizeof, void_ptr, zeromem};
use crate::object::Object;
use crate::pkcs11::*;
use crate::storage::aci::pbkdf2_derive;
use crate::token::TokenFacilities;
use crate::CSPRNG;

const SHA256_LEN: usize = 32;
/// Maximum number of derived keys to keep in the cache.
const MAX_KEY_CACHE_SIZE: usize = 128;

/// Distinguishes the intended use of a derived key (for encryption or signing).
pub enum KeyOp {
    /// Key is intended for AES-CBC encryption/decryption.
    Encryption,
    /// Key is intended for HMAC-SHA256 signing/verification.
    Signature,
}

/// RAII guard holding a read lock on the key cache and the ID of the key
/// being accessed. Ensures safe access to cached key objects.
#[derive(Debug)]
pub struct LockedKey<'a> {
    // Key ID
    id: [u8; SHA256_LEN],
    // Lock Guard holding a reference to the cache
    l: RwLockReadGuard<'a, BTreeMap<[u8; SHA256_LEN], Object>>,
}

impl LockedKey<'_> {
    /// Gets the ID (derived from PBKDF2 salt) of the key being accessed.
    fn get_id(&self) -> [u8; SHA256_LEN] {
        self.id
    }

    /// Gets a reference to the cached key `Object` associated with this lock.
    /// Returns `None` if the key is unexpectedly missing (should not happen).
    pub fn get_key<'a>(&'a self) -> Option<&'a Object> {
        self.l.get(&self.id)
    }
}

/// Manages the master encryption key derived from the user PIN and a cache
/// of keys derived from the master key via PBKDF2.
#[derive(Debug)]
pub struct KeysWithCaching {
    /// The master encryption key (derived via SHA1(salt||pin)). Zeroized on drop.
    enckey: Option<Vec<u8>>,
    /// Tree of cached keys stored as Objects
    cache: RwLock<BTreeMap<[u8; SHA256_LEN], Object>>,
}

impl Default for KeysWithCaching {
    fn default() -> KeysWithCaching {
        KeysWithCaching {
            enckey: None,
            cache: RwLock::new(BTreeMap::new()),
        }
    }
}

impl Drop for KeysWithCaching {
    fn drop(&mut self) {
        if let Some(ref mut key) = &mut self.enckey {
            zeromem(key.as_mut_slice());
        }
    }
}

impl KeysWithCaching {
    /// Returns `true` if the master encryption key is currently set (user is
    /// authenticated).
    pub fn available(&self) -> bool {
        self.enckey.is_some()
    }

    /// Gets a slice reference to the raw master encryption key bytes.
    fn get_key(&self) -> Result<&[u8]> {
        match &self.enckey {
            Some(ref key) => Ok(key.as_slice()),
            None => Err(CKR_USER_NOT_LOGGED_IN)?,
        }
    }

    /// Checks if the provided `check` value matches the current master
    /// encryption key.
    pub fn check_key(&self, check: &[u8]) -> bool {
        match &self.enckey {
            Some(ref key) => key.as_slice() == check,
            None => false,
        }
    }

    /// Sets the master encryption key, zeroizing any previous key.
    pub fn set_key(&mut self, key: Vec<u8>) {
        if let Some(ref mut oldkey) = &mut self.enckey {
            zeromem(oldkey.as_mut_slice());
        }
        self.enckey = Some(key);
    }

    /// Unsets the master encryption key (zeroizing it) and clears the derived
    /// key cache.
    pub fn unset_key(&mut self) {
        if let Some(ref mut key) = &mut self.enckey {
            zeromem(key.as_mut_slice());
            self.enckey = None;
        }
    }

    /// Attempts to get a read lock (`LockedKey`) for a cached derived key
    /// identified by its PBKDF2 salt (`id`).
    ///
    /// Returns `None` if the master key is not set (user not authenticated) or
    /// if the lock cannot be acquired.
    fn get_cached_key(&self, id: &[u8; SHA256_LEN]) -> Option<LockedKey<'_>> {
        if self.enckey.is_none() {
            /* access to the cache is available only if enckey is set.
             * When unset it means the user logged off and no
             * keys should be available */
            return None;
        }
        let read_lock = match self.cache.read() {
            Ok(r) => r,
            Err(_) => return None,
        };
        Some(LockedKey {
            id: *id,
            l: read_lock,
        })
    }

    /// Adds or updates a derived key object in the cache.
    ///
    /// Identified by the PBKDF2 salt (`id`). Manages cache size, evicting the
    /// least recently used key if the maximum size is exceeded (Note: BTreeMap
    /// eviction is not strictly LRU, `pop_last` is used here).
    fn set_cached_key(&self, id: &[u8; SHA256_LEN], key: Object) -> Result<()> {
        match self.cache.write() {
            Ok(mut w) => {
                if w.len() > MAX_KEY_CACHE_SIZE {
                    let _ = w.pop_last();
                }
                let _ = w.insert(*id, key);
            }
            Err(_) => return Err(CKR_CANT_LOCK)?,
        };
        Ok(())
    }

    /// Removes a specific derived key from the cache using its `LockedKey`
    /// guard (which contains the key ID).
    fn invalidate_cached_key(&self, lk: LockedKey) {
        let id = lk.get_id();
        drop(lk);
        match self.cache.write() {
            Ok(mut w) => {
                let _ = w.remove(&id);
            }
            Err(_) => (),
        }
    }
}

/// Default PBE iteration count used by NSS (relevant for PBKDF2).
pub const NSS_MP_PBE_ITERATION_COUNT: usize = 10000;

/// ASN.1 AlgorithmIdentifier used by NSS.
///
/// NSS sometimes uses a broken encoding for algorithm parameters compared to
/// PKCS standards (e.g., AES-CBC IV encoding, PBES2 structure) for backward
/// compatibility reasons. This definition accommodates the variations.
#[derive(
    asn1::Asn1Read, asn1::Asn1Write, PartialEq, Hash, Clone, Eq, Debug,
)]
pub struct BrokenAlgorithmIdentifier<'a> {
    pub oid: asn1::DefinedByMarker<asn1::ObjectIdentifier>,
    #[defined_by(oid)]
    pub params: BrokenAlgorithmParameters<'a>,
}

/// Enum holding the different algorithm parameters used by NSS ACI structures.
#[derive(
    asn1::Asn1DefinedByRead,
    asn1::Asn1DefinedByWrite,
    PartialEq,
    Eq,
    Hash,
    Clone,
    Debug,
)]
pub enum BrokenAlgorithmParameters<'a> {
    /// Parameters for PBES2 (Password-Based Encryption Scheme 2).
    #[defined_by(PBES2_OID)]
    Pbes2(BrokenPBES2Params<'a>),
    /// Parameters for PBMAC1 (Password-Based MAC Scheme 1).
    #[defined_by(PBMAC1_OID)]
    Pbmac1(PBMAC1Params<'a>),

    /// AES-128-CBC IV parameter.
    #[defined_by(AES_128_CBC_OID)]
    Aes128Cbc(&'a [u8]),
    /// AES-256-CBC IV parameter.
    #[defined_by(AES_256_CBC_OID)]
    Aes256Cbc(&'a [u8]),
    /// HMAC-SHA256 parameters.
    #[defined_by(HMAC_WITH_SHA256_OID)]
    HmacWithSha256(Option<asn1::Null>),
}

/// NSS-specific variant of PBES2 parameters.
#[derive(
    asn1::Asn1Read, asn1::Asn1Write, PartialEq, Eq, Hash, Clone, Debug,
)]
pub struct BrokenPBES2Params<'a> {
    pub key_derivation_func: Box<AlgorithmIdentifier<'a>>,
    pub encryption_scheme: Box<BrokenAlgorithmIdentifier<'a>>,
}

/// Top-level ASN.1 structure used by NSS to store encrypted or signed data
/// along with the parameters used for the cryptographic operation.
#[derive(
    asn1::Asn1Read, asn1::Asn1Write, PartialEq, Eq, Hash, Clone, Debug,
)]
pub struct NSSEncryptedDataInfo<'a> {
    /// Algorithm identifier indicating the scheme used (e.g., PBES2, PBMAC1).
    pub algorithm: Box<BrokenAlgorithmIdentifier<'a>>,
    /// The actual encrypted data or signature bytes.
    pub enc_or_sig_data: &'a [u8],
}

/// Decrypts data using AES-CBC-PAD, handling NSS's potentially broken IV
/// encoding.
fn aes_cbc_decrypt(
    facilities: &TokenFacilities,
    key: &Object,
    iv: &[u8],
    data: &[u8],
) -> Result<Vec<u8>> {
    let mut adj_iv_vec: Vec<u8>;

    /* NSS has a Broken IV in the encoded data, so we need to adjust
     * the IV we get from the decoding and prepend it with 0x04 0x0E
     * which are the bytes that make a 16 bytes buffer "look like" a
     * DER encoded OCTET_STRING. */
    let adj_iv = match iv.len() {
        14 => {
            adj_iv_vec = Vec::with_capacity(16);
            adj_iv_vec.extend_from_slice(&[4, 14]);
            adj_iv_vec.extend_from_slice(iv);
            adj_iv_vec.as_slice()
        }
        16 => iv,
        _ => return Err(CKR_ARGUMENTS_BAD)?,
    };

    let ck_mech = CK_MECHANISM {
        mechanism: CKM_AES_CBC_PAD,
        pParameter: void_ptr!(adj_iv),
        ulParameterLen: CK_ULONG::try_from(adj_iv.len())?,
    };
    let mech = facilities.mechanisms.get(CKM_AES_CBC_PAD)?;
    let mut op = mech.decryption_new(&ck_mech, key)?;
    let mut plain = vec![0u8; op.decryption_len(data.len(), true)?];
    let len = op.decrypt(data, &mut plain)?;
    plain.resize(len, 0);
    Ok(plain)
}

/// Encrypts data using AES-CBC-PAD, generating an IV in NSS's potentially
/// broken format (missing DER OCTET STRING header).
fn aes_cbc_encrypt(
    facilities: &TokenFacilities,
    key: &Object,
    data: &[u8],
) -> Result<(Vec<u8>, Vec<u8>)> {
    /* NSS has a Broken IV in the encoded data, so we need to adjust
     * the IV to start with 0x04 0x0E which are the bytes that make a
     * 16 bytes buffer "look like" a DER encoded OCTET_STRING. */
    let mut iv: [u8; 16] = [0u8; 16];
    iv[0] = 0x04;
    iv[1] = 0x0e;
    CSPRNG.with(|rng| rng.borrow_mut().generate_random(&mut iv[2..]))?;

    let ck_mech = CK_MECHANISM {
        mechanism: CKM_AES_CBC_PAD,
        pParameter: void_ptr!(&iv),
        ulParameterLen: CK_ULONG::try_from(iv.len())?,
    };
    let mech = facilities.mechanisms.get(CKM_AES_CBC_PAD)?;
    let mut op = mech.encryption_new(&ck_mech, key)?;
    let mut encdata = vec![0u8; op.encryption_len(data.len(), true)?];
    let len = op.encrypt(data, &mut encdata)?;
    encdata.resize(len, 0);

    Ok((iv[2..].to_vec(), encdata))
}

/// Derives a key using PBKDF2 based on the master encryption key (`keys`) and
/// the provided `PBKDF2Params` (which includes the salt).
///
/// Checks the key cache first. If the key is not cached, derives it using
/// `storage::aci::pbkdf2_derive`, caches it, and returns a `LockedKey` guard.
fn derive_key_internal<'a>(
    facilities: &TokenFacilities,
    keys: &'a KeysWithCaching,
    params: &PBKDF2Params,
    operation: KeyOp,
) -> Result<LockedKey<'a>> {
    let keyid: [u8; 32] = params.salt.try_into()?;

    /* First check if we have this key in cache */
    match keys.get_cached_key(&keyid) {
        Some(lk) => match lk.get_key() {
            Some(_) => return Ok(lk),
            None => (),
        },
        None => (),
    }

    /* if not compute it */
    let ck_class: CK_OBJECT_CLASS = CKO_SECRET_KEY;
    let ck_key_type: CK_KEY_TYPE = match operation {
        KeyOp::Encryption => CKK_AES,
        KeyOp::Signature => CKK_GENERIC_SECRET,
    };
    let ck_key_len: CK_ULONG = match params.key_length {
        Some(l) => CK_ULONG::try_from(l)?,
        None => return Err(CKR_MECHANISM_PARAM_INVALID)?,
    };
    let ck_true: CK_BBOOL = CK_TRUE;
    let mut key_template = CkAttrs::with_capacity(5);
    key_template.add_ulong(CKA_CLASS, &ck_class);
    key_template.add_ulong(CKA_KEY_TYPE, &ck_key_type);
    key_template.add_ulong(CKA_VALUE_LEN, &ck_key_len);
    match operation {
        KeyOp::Encryption => {
            key_template.add_bool(CKA_DECRYPT, &ck_true);
            key_template.add_bool(CKA_ENCRYPT, &ck_true);
        }
        KeyOp::Signature => {
            key_template.add_bool(CKA_SIGN, &ck_true);
            key_template.add_bool(CKA_VERIFY, &ck_true);
        }
    }

    let key = pbkdf2_derive(
        facilities,
        params,
        keys.get_key()?,
        key_template.as_slice(),
    )?;

    /* and store in cache for later use */
    keys.set_cached_key(&keyid, key)?;
    match keys.get_cached_key(&keyid) {
        Some(lk) => match lk.get_key() {
            Some(_) => return Ok(lk),
            None => (),
        },
        None => (),
    }

    return Err(CKR_GENERAL_ERROR)?;
}

#[cfg(test)]
pub fn derive_key_test<'a>(
    facilities: &TokenFacilities,
    keys: &'a KeysWithCaching,
    params: &PBKDF2Params,
    operation: KeyOp,
) -> Result<LockedKey<'a>> {
    derive_key_internal(facilities, keys, params, operation)
}

/// Decrypts data previously encrypted by NSS ACI mechanisms.
///
/// Parses the `NSSEncryptedDataInfo` structure, identifies the PBES2 scheme,
/// derives the necessary decryption key using `derive_key_internal` (based on
/// PBKDF2 parameters in the structure), and performs AES-CBC decryption.
pub fn decrypt_data(
    facilities: &TokenFacilities,
    keys: &KeysWithCaching,
    data: &[u8],
) -> Result<Vec<u8>> {
    let info = match asn1::parse_single::<NSSEncryptedDataInfo>(data) {
        Ok(i) => i,
        Err(_) => return Err(CKR_DATA_INVALID)?,
    };

    let pbes2 = match &info.algorithm.params {
        BrokenAlgorithmParameters::Pbes2(ref params) => params,
        _ => return Err(CKR_MECHANISM_INVALID)?,
    };

    let lockedkey = match &pbes2.key_derivation_func.params {
        AlgorithmParameters::Pbkdf2(ref params) => {
            derive_key_internal(facilities, keys, params, KeyOp::Encryption)?
        }
        _ => return Err(CKR_MECHANISM_INVALID)?,
    };

    let key = match lockedkey.get_key() {
        Some(k) => k,
        None => return Err(CKR_GENERAL_ERROR)?,
    };

    let result = match &pbes2.encryption_scheme.params {
        BrokenAlgorithmParameters::Aes128Cbc(ref iv) => {
            aes_cbc_decrypt(facilities, key, iv, info.enc_or_sig_data)
        }
        BrokenAlgorithmParameters::Aes256Cbc(ref iv) => {
            aes_cbc_decrypt(facilities, key, iv, info.enc_or_sig_data)
        }
        _ => Err(CKR_MECHANISM_INVALID)?,
    };
    if result.is_err() {
        keys.invalidate_cached_key(lockedkey)
    }
    result
}

/// Encrypts data using NSS ACI mechanisms.
///
/// Generates a random salt, derives an encryption key using PBKDF2 based on
/// the salt and the master key, encrypts the data using AES-CBC, and encodes
/// the result (including PBES2 parameters, IV, and ciphertext) into an
/// `NSSEncryptedDataInfo` structure.
pub fn encrypt_data(
    facilities: &TokenFacilities,
    keys: &KeysWithCaching,
    iterations: usize,
    data: &[u8],
) -> Result<Vec<u8>> {
    /* SHA2-256 length */
    let mut salt: [u8; SHA256_LEN] = [0u8; SHA256_LEN];
    CSPRNG.with(|rng| rng.borrow_mut().generate_random(&mut salt))?;

    let pbkdf2_params = PBKDF2Params {
        salt: &salt,
        iteration_count: u64::try_from(iterations)?,
        key_length: Some(u64::try_from(SHA256_LEN)?),
        prf: Box::new(HMAC_SHA_256_ALG),
    };

    let lockedkey = derive_key_internal(
        facilities,
        keys,
        &pbkdf2_params,
        KeyOp::Encryption,
    )?;

    let key = match lockedkey.get_key() {
        Some(k) => k,
        None => return Err(CKR_GENERAL_ERROR)?,
    };

    let (iv, enc_data) = match aes_cbc_encrypt(facilities, key, data) {
        Ok(x) => x,
        Err(e) => {
            keys.invalidate_cached_key(lockedkey);
            return Err(e);
        }
    };

    let enc_params = BrokenAlgorithmIdentifier {
        oid: asn1::DefinedByMarker::marker(),
        params: BrokenAlgorithmParameters::Aes256Cbc(&iv),
    };

    let info = NSSEncryptedDataInfo {
        algorithm: Box::new(BrokenAlgorithmIdentifier {
            oid: asn1::DefinedByMarker::marker(),
            params: BrokenAlgorithmParameters::Pbes2(BrokenPBES2Params {
                key_derivation_func: Box::new(AlgorithmIdentifier {
                    oid: asn1::DefinedByMarker::marker(),
                    params: AlgorithmParameters::Pbkdf2(pbkdf2_params),
                }),
                encryption_scheme: Box::new(enc_params),
            }),
        }),
        enc_or_sig_data: &enc_data,
    };

    match asn1::write_single(&info) {
        Ok(der) => Ok(der),
        Err(_) => Err(CKR_GENERAL_ERROR)?,
    }
}

/// Verifies an HMAC-SHA256 signature for NSS attribute integrity.
///
/// Constructs the message to be verified by concatenating the object ID,
/// attribute type, and the plaintext attribute value, then performs HMAC
/// verification.
fn hmac_verify(
    facilities: &TokenFacilities,
    mechanism: CK_MECHANISM_TYPE,
    key: &Object,
    nssobjid: u32,
    sdbtype: u32,
    plaintext: &[u8],
    signature: &[u8],
) -> Result<()> {
    let siglen = CK_ULONG::try_from(signature.len())?;
    let ck_mech = CK_MECHANISM {
        mechanism: mechanism,
        pParameter: void_ptr!(&siglen),
        ulParameterLen: sizeof!(CK_ULONG),
    };
    let mech = facilities.mechanisms.get(mechanism)?;
    let mut op = mech.verify_new(&ck_mech, key)?;
    let objid = nssobjid.to_be_bytes();
    op.verify_update(&objid)?;
    let attrtype = sdbtype.to_be_bytes();
    op.verify_update(&attrtype)?;
    op.verify_update(plaintext)?;
    op.verify_final(signature)
}

/// Checks the signature of an authenticated NSS attribute.
///
/// Parses the `NSSEncryptedDataInfo` structure (expecting PBMAC1 parameters),
/// derives the HMAC key using `derive_key_internal` (based on PBKDF2
/// parameters in the structure), and calls `hmac_verify` to check the
/// signature.
pub fn check_signature(
    facilities: &TokenFacilities,
    keys: &KeysWithCaching,
    attribute: &[u8],
    signature: &[u8],
    nssobjid: u32,
    sdbtype: u32,
) -> Result<()> {
    let info = match asn1::parse_single::<NSSEncryptedDataInfo>(signature) {
        Ok(i) => i,
        Err(_) => return Err(CKR_DATA_INVALID)?,
    };

    let pbmac1 = match &info.algorithm.params {
        BrokenAlgorithmParameters::Pbmac1(ref params) => params,
        _ => return Err(CKR_MECHANISM_INVALID)?,
    };

    let lockedkey = match &pbmac1.key_derivation_func.params {
        AlgorithmParameters::Pbkdf2(ref params) => {
            derive_key_internal(facilities, keys, params, KeyOp::Signature)?
        }
        _ => return Err(CKR_MECHANISM_INVALID)?,
    };

    let key = match lockedkey.get_key() {
        Some(k) => k,
        None => return Err(CKR_GENERAL_ERROR)?,
    };

    let result = match &pbmac1.message_auth_scheme.params {
        AlgorithmParameters::HmacWithSha256(None) => hmac_verify(
            facilities,
            CKM_SHA256_HMAC_GENERAL,
            key,
            nssobjid,
            sdbtype,
            attribute,
            info.enc_or_sig_data,
        ),
        _ => Err(CKR_MECHANISM_INVALID)?,
    };
    if result.is_err() {
        keys.invalidate_cached_key(lockedkey);
    }
    result
}

/// Derives the master encryption key from a PIN and salt using the legacy
/// NSS method: SHA1(salt || pin). Used for authenticating the user and
/// obtaining the key needed for PBKDF2 derivations.
pub fn enckey_derive(
    facilities: &TokenFacilities,
    pin: &[u8],
    salt: &[u8],
) -> Result<Vec<u8>> {
    let mech = facilities.mechanisms.get(CKM_SHA_1)?;
    let mut op = mech.digest_new(&CK_MECHANISM {
        mechanism: CKM_SHA_1,
        pParameter: std::ptr::null_mut(),
        ulParameterLen: 0,
    })?;
    op.digest_update(salt)?;
    op.digest_update(pin)?;
    let mut digest = vec![0u8; op.digest_len()?];
    op.digest_final(digest.as_mut_slice())?;
    Ok(digest)
}

/// Computes an HMAC-SHA256 signature for NSS attribute integrity.
///
/// Constructs the message by concatenating the object ID, attribute type,
/// and the plaintext attribute value, then computes the HMAC using the
/// provided key object.
fn hmac_sign(
    facilities: &TokenFacilities,
    key: &Object,
    nssobjid: u32,
    sdbtype: u32,
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let ck_mech = CK_MECHANISM {
        mechanism: CKM_SHA256_HMAC,
        pParameter: std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    let mech = facilities.mechanisms.get(CKM_SHA256_HMAC)?;
    let mut op = mech.sign_new(&ck_mech, key)?;
    let mut signature = vec![0u8; op.signature_len()?];
    let objid = nssobjid.to_be_bytes();
    op.sign_update(&objid)?;
    let attrtype = sdbtype.to_be_bytes();
    op.sign_update(&attrtype)?;
    op.sign_update(plaintext)?;
    op.sign_final(signature.as_mut_slice())?;
    Ok(signature)
}

/// Creates the ASN.1 encoded signature structure (`NSSEncryptedDataInfo`) for
/// an authenticated NSS attribute.
///
/// Generates a random salt, derives an HMAC key using PBKDF2 from the salt
/// and the master key, computes the HMAC signature of the attribute data
/// using `hmac_sign`, and encodes the result using PBMAC1 parameters.
pub fn make_signature(
    facilities: &TokenFacilities,
    keys: &KeysWithCaching,
    attribute: &[u8],
    nssobjid: u32,
    sdbtype: u32,
    iterations: usize,
) -> Result<Vec<u8>> {
    let mut salt: [u8; SHA256_LEN] = [0u8; SHA256_LEN];
    CSPRNG.with(|rng| rng.borrow_mut().generate_random(&mut salt))?;

    let pbkdf2_params = PBKDF2Params {
        salt: &salt,
        iteration_count: u64::try_from(iterations)?,
        key_length: Some(u64::try_from(SHA256_LEN)?),
        prf: Box::new(HMAC_SHA_256_ALG),
    };

    let lockedkey = derive_key_internal(
        facilities,
        keys,
        &pbkdf2_params,
        KeyOp::Signature,
    )?;

    let key = match lockedkey.get_key() {
        Some(k) => k,
        None => return Err(CKR_GENERAL_ERROR)?,
    };

    let sig = match hmac_sign(facilities, key, nssobjid, sdbtype, attribute) {
        Ok(x) => x,
        Err(e) => {
            keys.invalidate_cached_key(lockedkey);
            return Err(e);
        }
    };

    let info = NSSEncryptedDataInfo {
        algorithm: Box::new(BrokenAlgorithmIdentifier {
            oid: asn1::DefinedByMarker::marker(),
            params: BrokenAlgorithmParameters::Pbmac1(PBMAC1Params {
                key_derivation_func: Box::new(AlgorithmIdentifier {
                    oid: asn1::DefinedByMarker::marker(),
                    params: AlgorithmParameters::Pbkdf2(pbkdf2_params),
                }),
                message_auth_scheme: Box::new(AlgorithmIdentifier {
                    oid: asn1::DefinedByMarker::marker(),
                    params: AlgorithmParameters::HmacWithSha256(None),
                }),
            }),
        }),
        enc_or_sig_data: &sig,
    };

    match asn1::write_single(&info) {
        Ok(der) => Ok(der),
        Err(_) => Err(CKR_GENERAL_ERROR)?,
    }
}
