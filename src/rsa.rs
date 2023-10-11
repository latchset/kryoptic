// Copyright 2023 Simo Sorce
// See LICENSE.txt file for terms

use super::attribute;
use super::cryptography;
use super::error;
use super::interface;
use super::mechanism;
use super::object;
use super::token;
use super::{attr_element, bytes_attr_not_empty, err_rv};
use attribute::{from_bytes, from_ulong};
use cryptography::*;
use error::{KError, KResult};
use interface::*;
use mechanism::*;
use object::{
    CommonKeyTemplate, Object, ObjectAttr, ObjectTemplate, ObjectTemplates,
    ObjectType, PrivKeyTemplate, PubKeyTemplate,
};
use std::fmt::Debug;
use token::RNG;

pub const MIN_RSA_SIZE_BITS: usize = 1024;
pub const MIN_RSA_SIZE_BYTES: usize = MIN_RSA_SIZE_BITS / 8;

#[derive(Debug)]
pub struct RSAPubTemplate {
    template: Vec<ObjectAttr>,
}

impl RSAPubTemplate {
    pub fn new() -> RSAPubTemplate {
        let mut data: RSAPubTemplate = RSAPubTemplate {
            template: Vec::new(),
        };
        data.init_common_object_attrs();
        data.init_common_storage_attrs();
        data.init_common_key_attrs();
        data.init_common_public_key_attrs();
        data.template.push(attr_element!(CKA_MODULUS; req true; def false; from_bytes; val Vec::new()));
        data.template.push(attr_element!(CKA_MODULUS_BITS; req false; def false; from_ulong; val 0));
        data.template.push(attr_element!(CKA_PUBLIC_EXPONENT; req true; def false; from_bytes; val Vec::new()));
        data
    }
}

impl ObjectTemplate for RSAPubTemplate {
    fn create(&self, mut obj: Object) -> KResult<Object> {
        let mut attr_checker = self.template.clone();

        let mut ret =
            self.basic_object_attrs_checks(&mut obj, &mut attr_checker);
        if ret != CKR_OK {
            return err_rv!(ret);
        }

        ret = self.pubkey_create_attrs_checks(&mut obj);
        if ret != CKR_OK {
            return err_rv!(ret);
        }

        let modulus = match obj.get_attr_as_bytes(CKA_MODULUS) {
            Ok(m) => m,
            Err(_) => return err_rv!(CKR_TEMPLATE_INCOMPLETE),
        };
        match obj.get_attr_as_ulong(CKA_MODULUS_BITS) {
            Ok(_) => return err_rv!(CKR_ATTRIBUTE_VALUE_INVALID),
            Err(e) => match e {
                KError::NotFound(_) => (),
                _ => return Err(e),
            },
        }
        if modulus.len() < MIN_RSA_SIZE_BYTES {
            return err_rv!(CKR_ATTRIBUTE_VALUE_INVALID);
        }
        bytes_attr_not_empty!(obj; CKA_PUBLIC_EXPONENT);

        Ok(obj)
    }

    fn get_template(&mut self) -> &mut Vec<ObjectAttr> {
        &mut self.template
    }
}

impl CommonKeyTemplate for RSAPubTemplate {
    fn get_template(&mut self) -> &mut Vec<ObjectAttr> {
        &mut self.template
    }
}

impl PubKeyTemplate for RSAPubTemplate {
    fn get_template(&mut self) -> &mut Vec<ObjectAttr> {
        &mut self.template
    }
}

#[derive(Debug)]
pub struct RSAPrivTemplate {
    template: Vec<ObjectAttr>,
}

impl RSAPrivTemplate {
    pub fn new() -> RSAPrivTemplate {
        let mut data: RSAPrivTemplate = RSAPrivTemplate {
            template: Vec::new(),
        };
        data.init_common_object_attrs();
        data.init_common_storage_attrs();
        data.init_common_key_attrs();
        data.init_common_private_key_attrs();
        data.template.push(attr_element!(CKA_MODULUS; req true; def false; from_bytes; val Vec::new()));
        data.template.push(attr_element!(CKA_PUBLIC_EXPONENT; req true; def false; from_bytes; val Vec::new()));
        data.template.push(attr_element!(CKA_PRIVATE_EXPONENT; req true; def false; from_bytes; val Vec::new()));
        data.template.push(attr_element!(CKA_PRIME_1; req false; def false; from_bytes; val Vec::new()));
        data.template.push(attr_element!(CKA_PRIME_2; req false; def false; from_bytes; val Vec::new()));
        data.template.push(attr_element!(CKA_EXPONENT_1; req false; def false; from_bytes; val Vec::new()));
        data.template.push(attr_element!(CKA_EXPONENT_2; req false; def false; from_bytes; val Vec::new()));
        data.template.push(attr_element!(CKA_COEFFICIENT; req false; def false; from_bytes; val Vec::new()));
        data
    }
}

impl ObjectTemplate for RSAPrivTemplate {
    fn create(&self, mut obj: Object) -> KResult<Object> {
        let mut attr_checker = self.template.clone();

        let mut ret =
            self.basic_object_attrs_checks(&mut obj, &mut attr_checker);
        if ret != CKR_OK {
            return err_rv!(ret);
        }

        ret = self.privkey_create_attrs_checks(&mut obj);
        if ret != CKR_OK {
            return err_rv!(ret);
        }

        let modulus = match obj.get_attr_as_bytes(CKA_MODULUS) {
            Ok(m) => m,
            Err(_) => return err_rv!(CKR_TEMPLATE_INCOMPLETE),
        };
        if modulus.len() < MIN_RSA_SIZE_BYTES {
            return err_rv!(CKR_ATTRIBUTE_VALUE_INVALID);
        }
        bytes_attr_not_empty!(obj; CKA_PUBLIC_EXPONENT);
        bytes_attr_not_empty!(obj; CKA_PRIVATE_EXPONENT);

        Ok(obj)
    }

    fn get_template(&mut self) -> &mut Vec<ObjectAttr> {
        &mut self.template
    }
}

impl CommonKeyTemplate for RSAPrivTemplate {
    fn get_template(&mut self) -> &mut Vec<ObjectAttr> {
        &mut self.template
    }
}

impl PrivKeyTemplate for RSAPrivTemplate {
    fn get_template(&mut self) -> &mut Vec<ObjectAttr> {
        &mut self.template
    }
}

fn check_key_object(key: &Object, public: bool, op: CK_ULONG) -> KResult<()> {
    match key.get_attr_as_ulong(CKA_CLASS)? {
        CKO_PUBLIC_KEY => {
            if !public {
                return err_rv!(CKR_KEY_TYPE_INCONSISTENT);
            }
        }
        CKO_PRIVATE_KEY => {
            if public {
                return err_rv!(CKR_KEY_TYPE_INCONSISTENT);
            }
        }
        _ => return err_rv!(CKR_KEY_TYPE_INCONSISTENT),
    }
    match key.get_attr_as_ulong(CKA_KEY_TYPE)? {
        CKK_RSA => (),
        _ => return err_rv!(CKR_KEY_TYPE_INCONSISTENT),
    }
    match key.get_attr_as_bool(op) {
        Ok(avail) => {
            if !avail {
                return err_rv!(CKR_KEY_FUNCTION_NOT_PERMITTED);
            }
        }
        Err(_) => return err_rv!(CKR_KEY_FUNCTION_NOT_PERMITTED),
    }
    Ok(())
}

macro_rules! import_mpz {
    ($obj:expr; $id:expr; $mpz:expr) => {{
        let x = match $obj.get_attr_as_bytes($id) {
            Ok(b) => b,
            Err(_) => return err_rv!(CKR_DEVICE_ERROR),
        };
        unsafe {
            nettle_mpz_set_str_256_u(&mut $mpz, x.len(), x.as_ptr());
        }
    }};
}

fn object_to_rsa_public_key(key: &Object) -> KResult<rsa_public_key> {
    let mut k: rsa_public_key = rsa_public_key::default();
    unsafe {
        nettle_rsa_public_key_init(&mut k);
    }
    import_mpz!(key; CKA_PUBLIC_EXPONENT; k.e[0]);
    import_mpz!(key; CKA_MODULUS; k.n[0]);
    if unsafe { nettle_rsa_public_key_prepare(&mut k) } == 0 {
        err_rv!(CKR_GENERAL_ERROR)
    } else {
        Ok(k)
    }
}

fn object_to_rsa_private_key(key: &Object) -> KResult<rsa_private_key> {
    let mut k: rsa_private_key = rsa_private_key::default();
    unsafe {
        nettle_rsa_private_key_init(&mut k);
    }
    import_mpz!(key; CKA_PRIVATE_EXPONENT; k.d[0]);
    import_mpz!(key; CKA_PRIME_1; k.p[0]);
    import_mpz!(key; CKA_PRIME_2; k.q[0]);
    import_mpz!(key; CKA_EXPONENT_1; k.a[0]);
    import_mpz!(key; CKA_EXPONENT_2; k.b[0]);
    import_mpz!(key; CKA_COEFFICIENT; k.c[0]);
    if unsafe { nettle_rsa_private_key_prepare(&mut k) } == 0 {
        err_rv!(CKR_GENERAL_ERROR)
    } else {
        Ok(k)
    }
}

#[derive(Debug)]
struct RsaPKCSMechanism {
    info: CK_MECHANISM_INFO,
}

impl Mechanism for RsaPKCSMechanism {
    fn info(&self) -> &CK_MECHANISM_INFO {
        &self.info
    }

    fn encryption_new(
        &self,
        mech: &CK_MECHANISM,
        key: &Object,
    ) -> KResult<Box<dyn Encryption>> {
        if mech.mechanism != CKM_RSA_PKCS {
            return err_rv!(CKR_MECHANISM_INVALID);
        }
        if self.info.flags & CKF_ENCRYPT != CKF_ENCRYPT {
            return err_rv!(CKR_MECHANISM_INVALID);
        }
        match check_key_object(key, true, CKA_ENCRYPT) {
            Ok(_) => (),
            Err(e) => return Err(e),
        }
        let op = RsaPKCSOperation {
            mech: mech.mechanism,
            public_key: Some(object_to_rsa_public_key(key)?),
            private_key: None,
            finalized: false,
            in_use: false,
        };
        Ok(Box::new(op))
    }

    fn decryption_new(
        &self,
        mech: &CK_MECHANISM,
        key: &Object,
    ) -> KResult<Box<dyn Decryption>> {
        if mech.mechanism != CKM_RSA_PKCS {
            return err_rv!(CKR_MECHANISM_INVALID);
        }
        if self.info.flags & CKF_DECRYPT != CKF_DECRYPT {
            return err_rv!(CKR_MECHANISM_INVALID);
        }
        match check_key_object(key, false, CKA_DECRYPT) {
            Ok(_) => (),
            Err(e) => return Err(e),
        }
        let op = RsaPKCSOperation {
            mech: mech.mechanism,
            public_key: Some(object_to_rsa_public_key(key)?),
            private_key: Some(object_to_rsa_private_key(key)?),
            finalized: false,
            in_use: false,
        };
        Ok(Box::new(op))
    }
}

pub fn register(mechs: &mut Mechanisms, ot: &mut ObjectTemplates) {
    mechs.add_mechanism(
        CKM_RSA_PKCS,
        Box::new(RsaPKCSMechanism {
            info: CK_MECHANISM_INFO {
                ulMinKeySize: 1024,
                ulMaxKeySize: 4096,
                flags: CKF_ENCRYPT | CKF_DECRYPT,
            },
        }),
    );

    ot.add_template(ObjectType::RSAPubKey, Box::new(RSAPubTemplate::new()));
    ot.add_template(ObjectType::RSAPrivKey, Box::new(RSAPrivTemplate::new()));
}

#[derive(Debug)]
struct RsaPKCSOperation {
    mech: CK_MECHANISM_TYPE,
    public_key: Option<rsa_public_key>,
    private_key: Option<rsa_private_key>,
    finalized: bool,
    in_use: bool,
}

impl MechOperation for RsaPKCSOperation {
    fn mechanism(&self) -> CK_MECHANISM_TYPE {
        self.mech
    }
    fn in_use(&self) -> bool {
        self.in_use
    }
    fn finalized(&self) -> bool {
        self.finalized
    }
}

impl Encryption for RsaPKCSOperation {
    fn encrypt(
        &mut self,
        rng: &mut RNG,
        plain: CK_BYTE_PTR,
        plain_len: CK_ULONG,
        cipher: CK_BYTE_PTR,
        cipher_len: CK_ULONG_PTR,
    ) -> KResult<()> {
        if self.in_use {
            return err_rv!(CKR_OPERATION_NOT_INITIALIZED);
        }
        self.finalized = true;
        self.encrypt_update(rng, plain, plain_len, cipher, cipher_len)
    }

    fn encrypt_update(
        &mut self,
        rng: &mut RNG,
        plain: CK_BYTE_PTR,
        plain_len: CK_ULONG,
        cipher: CK_BYTE_PTR,
        cipher_len: CK_ULONG_PTR,
    ) -> KResult<()> {
        self.in_use = true;

        let key: &rsa_public_key = match self.public_key {
            None => return err_rv!(CKR_GENERAL_ERROR),
            Some(ref k) => k,
        };

        let key_size = (key.size - 1) as CK_ULONG;

        if cipher.is_null() {
            unsafe { *cipher_len = key_size };
            return Ok(());
        }

        let clen = unsafe { *cipher_len };
        if clen < key_size {
            return err_rv!(CKR_BUFFER_TOO_SMALL);
        }

        encrypt(key, rng, plain, plain_len, cipher, cipher_len)
    }

    fn encrypt_final(
        &mut self,
        _rng: &mut RNG,
        cipher: CK_BYTE_PTR,
        cipher_len: CK_ULONG_PTR,
    ) -> KResult<()> {
        unsafe { *cipher_len = 0 };
        if !cipher.is_null() {
            self.finalized = true;
        }
        Ok(())
    }
}

impl Decryption for RsaPKCSOperation {
    fn decrypt(
        &mut self,
        rng: &mut RNG,
        cipher: CK_BYTE_PTR,
        cipher_len: CK_ULONG,
        plain: CK_BYTE_PTR,
        plain_len: CK_ULONG_PTR,
    ) -> KResult<()> {
        if self.in_use {
            return err_rv!(CKR_OPERATION_NOT_INITIALIZED);
        }
        self.finalized = true;
        self.decrypt_update(rng, cipher, cipher_len, plain, plain_len)
    }
    fn decrypt_update(
        &mut self,
        rng: &mut RNG,
        cipher: CK_BYTE_PTR,
        cipher_len: CK_ULONG,
        plain: CK_BYTE_PTR,
        plain_len: CK_ULONG_PTR,
    ) -> KResult<()> {
        self.in_use = true;

        let pubkey: &rsa_public_key = match self.public_key {
            None => return err_rv!(CKR_GENERAL_ERROR),
            Some(ref k) => k,
        };
        let prikey: &rsa_private_key = match self.private_key {
            None => return err_rv!(CKR_GENERAL_ERROR),
            Some(ref k) => k,
        };

        let key_size = (pubkey.size - 1) as CK_ULONG;

        if plain.is_null() {
            unsafe { *plain_len = key_size };
            return Ok(());
        }

        decrypt(pubkey, prikey, rng, cipher, cipher_len, plain, plain_len)
    }
    fn decrypt_final(
        &mut self,
        _rng: &mut RNG,
        plain: CK_BYTE_PTR,
        plain_len: CK_ULONG_PTR,
    ) -> KResult<()> {
        unsafe { *plain_len = 0 };
        if !plain.is_null() {
            self.finalized = true;
        }
        Ok(())
    }
}

unsafe extern "C" fn get_random(
    ctx: *mut ::std::os::raw::c_void,
    length: usize,
    dst: *mut u8,
) {
    let rng = unsafe { &mut *(ctx as *mut RNG) };
    let buf = unsafe { std::slice::from_raw_parts_mut(dst, length) };
    rng.generate_random(buf).unwrap();
}

fn encrypt(
    key: &rsa_public_key,
    rng: &mut RNG,
    plain: CK_BYTE_PTR,
    plain_len: CK_ULONG,
    cipher: CK_BYTE_PTR,
    cipher_len: CK_ULONG_PTR,
) -> KResult<()> {
    let mut x: __mpz_struct = __mpz_struct::default();
    unsafe { __gmpz_init(&mut x) };

    let res = unsafe {
        nettle_rsa_encrypt(
            key,
            rng as *mut _ as *mut ::std::os::raw::c_void,
            Some(get_random),
            plain_len as usize,
            plain,
            &mut x,
        )
    };
    if res == 0 {
        return err_rv!(CKR_GENERAL_ERROR);
    }

    unsafe {
        let len = nettle_mpz_sizeinbase_256_u(&mut x);
        if len as CK_ULONG > *cipher_len {
            return err_rv!(CKR_GENERAL_ERROR);
        }
        nettle_mpz_get_str_256(len, cipher, &mut x);
        *cipher_len = len as CK_ULONG;
    }
    Ok(())
}

fn decrypt(
    pubkey: &rsa_public_key,
    prikey: &rsa_private_key,
    rng: &mut RNG,
    cipher: CK_BYTE_PTR,
    cipher_len: CK_ULONG,
    plain: CK_BYTE_PTR,
    plain_len: CK_ULONG_PTR,
) -> KResult<()> {
    let mut x: __mpz_struct = __mpz_struct::default();
    unsafe {
        nettle_mpz_init_set_str_256_s(&mut x, cipher_len as usize, cipher);
    }

    let mut plen: usize = unsafe { *plain_len } as usize;
    if plen < (pubkey.size - 1) {
        return err_rv!(CKR_BUFFER_TOO_SMALL);
    }

    let res = unsafe {
        nettle_rsa_decrypt_tr(
            pubkey,
            prikey,
            rng as *mut _ as *mut ::std::os::raw::c_void,
            Some(get_random),
            &mut plen,
            plain as *mut _ as *mut u8,
            &mut x,
        )
    };
    if res == 0 {
        return err_rv!(CKR_GENERAL_ERROR);
    }
    Ok(())
}
