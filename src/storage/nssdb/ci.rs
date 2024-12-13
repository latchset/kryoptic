// Copyright 2024 Simo Sorce
// See LICENSE.txt file for terms

use std::collections::BTreeMap;
use std::sync::{RwLock, RwLockReadGuard};

use crate::attribute::CkAttrs;
use crate::error::Result;
use crate::interface::*;
use crate::kasn1::oid::*;
use crate::kasn1::pkcs::*;
use crate::object::Object;
use crate::storage::aci::pbkdf2_derive;
use crate::token::TokenFacilities;
use crate::CSPRNG;
use crate::{sizeof, void_ptr};

use zeroize::Zeroize;

const SHA256_LEN: usize = 32;
const MAX_KEY_CACHE_SIZE: usize = 128;

enum KeyOp {
    Encryption,
    Signature,
}

#[derive(Debug)]
struct LockedKey<'a> {
    id: [u8; SHA256_LEN],
    l: RwLockReadGuard<'a, BTreeMap<[u8; SHA256_LEN], Object>>,
}

impl LockedKey<'_> {
    fn get_id(&self) -> [u8; SHA256_LEN] {
        self.id
    }

    pub fn get_key<'a>(&'a self) -> Option<&'a Object> {
        self.l.get(&self.id)
    }
}

#[derive(Debug)]
pub struct KeysWithCaching {
    enckey: Option<Vec<u8>>,
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
            key.zeroize();
        }
    }
}

impl KeysWithCaching {
    pub fn available(&self) -> bool {
        self.enckey.is_some()
    }

    fn get_key(&self) -> Result<&[u8]> {
        match &self.enckey {
            Some(ref key) => Ok(key.as_slice()),
            None => Err(CKR_USER_NOT_LOGGED_IN)?,
        }
    }

    pub fn check_key(&self, check: &[u8]) -> bool {
        match &self.enckey {
            Some(ref key) => key.as_slice() == check,
            None => false,
        }
    }

    pub fn set_key(&mut self, key: Vec<u8>) {
        self.enckey = Some(key);
    }

    pub fn unset_key(&mut self) {
        self.enckey = None;
    }

    fn get_cached_key(&self, id: &[u8; SHA256_LEN]) -> Option<LockedKey> {
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

pub const NSS_MP_PBE_ITERATION_COUNT: usize = 10000;

#[derive(
    asn1::Asn1Read, asn1::Asn1Write, PartialEq, Hash, Clone, Eq, Debug,
)]
pub struct BrokenAlgorithmIdentifier<'a> {
    pub oid: asn1::DefinedByMarker<asn1::ObjectIdentifier>,
    #[defined_by(oid)]
    pub params: BrokenAlgorithmParameters<'a>,
}

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
    #[defined_by(PBES2_OID)]
    Pbes2(BrokenPBES2Params<'a>),
    #[defined_by(PBMAC1_OID)]
    Pbmac1(PBMAC1Params<'a>),

    #[defined_by(AES_128_CBC_OID)]
    Aes128Cbc(&'a [u8]),
    #[defined_by(AES_256_CBC_OID)]
    Aes256Cbc(&'a [u8]),
    #[defined_by(HMAC_WITH_SHA256_OID)]
    HmacWithSha256(Option<asn1::Null>),
}

#[derive(
    asn1::Asn1Read, asn1::Asn1Write, PartialEq, Eq, Hash, Clone, Debug,
)]
pub struct BrokenPBES2Params<'a> {
    pub key_derivation_func: Box<AlgorithmIdentifier<'a>>,
    pub encryption_scheme: Box<BrokenAlgorithmIdentifier<'a>>,
}

#[derive(
    asn1::Asn1Read, asn1::Asn1Write, PartialEq, Eq, Hash, Clone, Debug,
)]
pub struct NSSEncryptedDataInfo<'a> {
    pub algorithm: Box<BrokenAlgorithmIdentifier<'a>>,
    pub enc_or_sig_data: &'a [u8],
}

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
    let mut plain = vec![0u8; op.decryption_len(data.len(), false)?];
    let len = op.decrypt(data, &mut plain)?;
    plain.resize(len, 0);
    Ok(plain)
}

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
    let mut encdata = vec![0u8; op.encryption_len(data.len(), false)?];
    let len = op.encrypt(data, &mut encdata)?;
    encdata.resize(len, 0);

    Ok((iv[2..].to_vec(), encdata))
}

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
