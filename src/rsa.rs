// Copyright 2023 Simo Sorce
// See LICENSE.txt file for terms

use super::attribute;
use super::cryptography;
use super::error;
use super::interface;
use super::mechanism;
use super::object;
use super::sha1;
use super::sha2;
use super::token;
use super::{attr_element, bytes_attr_not_empty, err_rv};
use attribute::{from_bool, from_bytes, from_ulong};
use cryptography::*;
use error::{KError, KResult};
use interface::*;
use mechanism::*;
use num_bigint::BigUint;
use num_integer::Integer;
use num_traits::{One, Zero};
use object::{
    CommonKeyTemplate, OAFlags, Object, ObjectAttr, ObjectTemplate,
    ObjectTemplates, ObjectType, PrivKeyTemplate, PubKeyTemplate,
};
use std::fmt::Debug;
use token::RNG;

pub const MIN_RSA_SIZE_BITS: usize = 1024;
pub const MAX_RSA_SIZE_BITS: usize = 16536;
pub const MIN_RSA_SIZE_BYTES: usize = MIN_RSA_SIZE_BITS / 8;

#[derive(Debug)]
pub struct RSAPubTemplate {
    attributes: Vec<ObjectAttr>,
}

impl RSAPubTemplate {
    pub fn new() -> RSAPubTemplate {
        let mut data: RSAPubTemplate = RSAPubTemplate {
            attributes: Vec::new(),
        };
        data.init_common_object_attrs();
        data.init_common_storage_attrs();
        data.init_common_key_attrs();
        data.init_common_public_key_attrs();
        data.attributes.push(attr_element!(CKA_MODULUS; OAFlags::RequiredOnCreate | OAFlags::Unchangeable; from_bytes; val Vec::new()));
        data.attributes.push(attr_element!(CKA_MODULUS_BITS; OAFlags::RequiredOnGenerate | OAFlags::Unchangeable; from_ulong; val 0));
        data.attributes.push(attr_element!(CKA_PUBLIC_EXPONENT; OAFlags::RequiredOnCreate | OAFlags::Unchangeable; from_bytes; val Vec::new()));
        data
    }

    fn get_attributes(&self) -> &Vec<ObjectAttr> {
        &self.attributes
    }
}

impl ObjectTemplate for RSAPubTemplate {
    fn create(&self, template: &[CK_ATTRIBUTE]) -> KResult<Object> {
        let obj = self.default_object_create(template)?;

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

    fn stubpubkeyhalf(
        &self,
        pubkey_template: &[CK_ATTRIBUTE],
    ) -> KResult<Object> {
        let attributes = self.get_attributes();
        let mut obj = Object::new();
        for ck_attr in pubkey_template {
            match attributes.iter().find(|a| a.get_type() == ck_attr.type_) {
                Some(attr) => {
                    if attr.is(OAFlags::UnsettableOnGenerate) {
                        return err_rv!(CKR_ATTRIBUTE_TYPE_INVALID);
                    }
                    /* duplicate? */
                    match obj.get_attr(ck_attr.type_) {
                        Some(_) => return err_rv!(CKR_TEMPLATE_INCONSISTENT),
                        None => (),
                    }
                    if !attr.is(OAFlags::Ignored) {
                        obj.set_attr(ck_attr.to_attribute()?)?;
                    }
                }
                None => {
                    return err_rv!(CKR_ATTRIBUTE_VALUE_INVALID);
                }
            }
        }
        for attr in attributes {
            match obj.get_attr(attr.get_type()) {
                Some(_) => (),
                None => {
                    if attr.has_default() {
                        obj.set_attr(attr.clone_attr())?;
                    } else if attr.is(OAFlags::RequiredOnGenerate) {
                        return err_rv!(CKR_TEMPLATE_INCOMPLETE);
                    }
                }
            }
        }
        match obj.get_attr(CKA_CLASS) {
            Some(a) => {
                if a.to_ulong()? != CKO_PUBLIC_KEY {
                    return err_rv!(CKR_TEMPLATE_INCONSISTENT);
                }
            }
            None => {
                obj.set_attr(attribute::from_ulong(CKA_CLASS, CKO_PUBLIC_KEY))?
            }
        }
        match obj.get_attr(CKA_KEY_TYPE) {
            Some(a) => {
                if a.to_ulong()? != CKK_RSA {
                    return err_rv!(CKR_TEMPLATE_INCONSISTENT);
                }
            }
            None => {
                obj.set_attr(attribute::from_ulong(CKA_KEY_TYPE, CKK_RSA))?
            }
        }
        Ok(obj)
    }

    fn get_attributes(&self) -> &Vec<ObjectAttr> {
        &self.attributes
    }
    fn get_attributes_mut(&mut self) -> &mut Vec<ObjectAttr> {
        &mut self.attributes
    }
}

impl CommonKeyTemplate for RSAPubTemplate {
    fn get_attributes(&self) -> &Vec<ObjectAttr> {
        &self.attributes
    }

    fn get_attributes_mut(&mut self) -> &mut Vec<ObjectAttr> {
        &mut self.attributes
    }
}

impl PubKeyTemplate for RSAPubTemplate {
    fn get_attributes(&self) -> &Vec<ObjectAttr> {
        &self.attributes
    }

    fn get_attributes_mut(&mut self) -> &mut Vec<ObjectAttr> {
        &mut self.attributes
    }
}

#[derive(Debug)]
pub struct RSAPrivTemplate {
    attributes: Vec<ObjectAttr>,
}

impl RSAPrivTemplate {
    pub fn new() -> RSAPrivTemplate {
        let mut data: RSAPrivTemplate = RSAPrivTemplate {
            attributes: Vec::new(),
        };
        data.init_common_object_attrs();
        data.init_common_storage_attrs();
        data.init_common_key_attrs();
        data.init_common_private_key_attrs();
        data.attributes.push(attr_element!(CKA_MODULUS; OAFlags::Required | OAFlags::Unchangeable; from_bytes; val Vec::new()));
        data.attributes.push(attr_element!(CKA_PUBLIC_EXPONENT; OAFlags::Required | OAFlags::Unchangeable; from_bytes; val Vec::new()));
        data.attributes.push(attr_element!(CKA_PRIVATE_EXPONENT; OAFlags::Sensitive | OAFlags::Required | OAFlags::Unchangeable; from_bytes; val Vec::new()));
        data.attributes.push(attr_element!(CKA_PRIME_1; OAFlags::Sensitive | OAFlags::Unchangeable; from_bytes; val Vec::new()));
        data.attributes.push(attr_element!(CKA_PRIME_2; OAFlags::Sensitive | OAFlags::Unchangeable; from_bytes; val Vec::new()));
        data.attributes.push(attr_element!(CKA_EXPONENT_1; OAFlags::Sensitive | OAFlags::Unchangeable; from_bytes; val Vec::new()));
        data.attributes.push(attr_element!(CKA_EXPONENT_2; OAFlags::Sensitive | OAFlags::Unchangeable; from_bytes; val Vec::new()));
        data.attributes.push(attr_element!(CKA_COEFFICIENT; OAFlags::Sensitive | OAFlags::Unchangeable; from_bytes; val Vec::new()));

        /* default to private */
        let private = attr_element!(CKA_PRIVATE; OAFlags::Defval | OAFlags::ChangeOnCopy; from_bool; val true);
        match data
            .attributes
            .iter()
            .position(|x| x.get_type() == CKA_PRIVATE)
        {
            Some(idx) => data.attributes[idx] = private,
            None => data.attributes.push(private),
        }

        data
    }

    fn get_attributes(&self) -> &Vec<ObjectAttr> {
        &self.attributes
    }
}

impl ObjectTemplate for RSAPrivTemplate {
    fn create(&self, template: &[CK_ATTRIBUTE]) -> KResult<Object> {
        let mut obj = self.default_object_create(template)?;

        let modulus = match obj.get_attr_as_bytes(CKA_MODULUS) {
            Ok(m) => m,
            Err(_) => return err_rv!(CKR_TEMPLATE_INCOMPLETE),
        };
        if modulus.len() < MIN_RSA_SIZE_BYTES {
            return err_rv!(CKR_ATTRIBUTE_VALUE_INVALID);
        }
        bytes_attr_not_empty!(obj; CKA_PUBLIC_EXPONENT);
        bytes_attr_not_empty!(obj; CKA_PRIVATE_EXPONENT);

        let p = match obj.get_attr(CKA_PRIME_1) {
            Some(a) => Some(a.get_value().clone()),
            None => None,
        };
        let q = match obj.get_attr(CKA_PRIME_2) {
            Some(a) => Some(a.get_value().clone()),
            None => None,
        };
        let a = match obj.get_attr(CKA_EXPONENT_1) {
            Some(a) => Some(a.get_value().clone()),
            None => None,
        };
        let b = match obj.get_attr(CKA_EXPONENT_2) {
            Some(a) => Some(a.get_value().clone()),
            None => None,
        };
        let c = match obj.get_attr(CKA_COEFFICIENT) {
            Some(a) => Some(a.get_value().clone()),
            None => None,
        };

        if p == None || q == None || a == None || b == None || c == None {
            let mut r = RsaBigUints::new(
                obj.get_attr_as_bytes(CKA_MODULUS)?,
                obj.get_attr_as_bytes(CKA_PUBLIC_EXPONENT)?,
                obj.get_attr_as_bytes(CKA_PRIVATE_EXPONENT)?,
            );
            r.decompose()?;
            match p {
                Some(v) => comp(r.p.to_bytes_be(), v)?,
                None => obj.set_attr(attribute::from_bytes(
                    CKA_PRIME_1,
                    r.p.to_bytes_be(),
                ))?,
            }
            match q {
                Some(v) => comp(r.q.to_bytes_be(), v)?,
                None => obj.set_attr(attribute::from_bytes(
                    CKA_PRIME_2,
                    r.q.to_bytes_be(),
                ))?,
            }
            match a {
                Some(v) => comp(r.a.to_bytes_be(), v)?,
                None => obj.set_attr(attribute::from_bytes(
                    CKA_EXPONENT_1,
                    r.a.to_bytes_be(),
                ))?,
            }
            match b {
                Some(v) => comp(r.b.to_bytes_be(), v)?,
                None => obj.set_attr(attribute::from_bytes(
                    CKA_EXPONENT_2,
                    r.b.to_bytes_be(),
                ))?,
            }
            match c {
                Some(v) => comp(r.c.to_bytes_be(), v)?,
                None => obj.set_attr(attribute::from_bytes(
                    CKA_COEFFICIENT,
                    r.c.to_bytes_be(),
                ))?,
            }
        }

        Ok(obj)
    }

    fn genkeypair(
        &self,
        rng: &mut RNG,
        pubkey: &mut Object,
        prikey_template: &[CK_ATTRIBUTE],
    ) -> KResult<Object> {
        let bits = pubkey.get_attr_as_ulong(CKA_MODULUS_BITS)? as usize;
        if bits < MIN_RSA_SIZE_BITS || bits > MAX_RSA_SIZE_BITS {
            return err_rv!(CKR_ATTRIBUTE_VALUE_INVALID);
        }
        let exponent: &Vec<u8> = match pubkey.get_attr(CKA_PUBLIC_EXPONENT) {
            Some(a) => a.get_value(),
            None => {
                pubkey.set_attr(attribute::from_bytes(
                    CKA_PUBLIC_EXPONENT,
                    vec![0x01, 0x00, 0x01],
                ))?;
                pubkey.get_attr_as_bytes(CKA_PUBLIC_EXPONENT)?
            }
        };

        let attributes = self.get_attributes();
        let mut obj = Object::new();
        for ck_attr in prikey_template {
            match attributes.iter().find(|a| a.get_type() == ck_attr.type_) {
                Some(attr) => {
                    if attr.is(OAFlags::UnsettableOnGenerate) {
                        return err_rv!(CKR_ATTRIBUTE_TYPE_INVALID);
                    }
                    /* duplicate? */
                    match obj.get_attr(ck_attr.type_) {
                        Some(_) => return err_rv!(CKR_TEMPLATE_INCONSISTENT),
                        None => (),
                    }
                    if !attr.is(OAFlags::Ignored) {
                        obj.set_attr(ck_attr.to_attribute()?)?;
                    }
                }
                None => {
                    return err_rv!(CKR_ATTRIBUTE_VALUE_INVALID);
                }
            }
        }
        for attr in attributes {
            match obj.get_attr(attr.get_type()) {
                Some(_) => (),
                None => {
                    if attr.has_default() {
                        obj.set_attr(attr.clone_attr())?;
                    } else if attr.is(OAFlags::RequiredOnGenerate) {
                        return err_rv!(CKR_TEMPLATE_INCOMPLETE);
                    }
                }
            }
        }
        match obj.get_attr(CKA_CLASS) {
            Some(a) => {
                if a.to_ulong()? != CKO_PRIVATE_KEY {
                    return err_rv!(CKR_TEMPLATE_INCONSISTENT);
                }
            }
            None => {
                obj.set_attr(attribute::from_ulong(CKA_CLASS, CKO_PRIVATE_KEY))?
            }
        }
        match obj.get_attr(CKA_KEY_TYPE) {
            Some(a) => {
                if a.to_ulong()? != CKK_RSA {
                    return err_rv!(CKR_TEMPLATE_INCONSISTENT);
                }
            }
            None => {
                obj.set_attr(attribute::from_ulong(CKA_KEY_TYPE, CKK_RSA))?
            }
        }

        let mut pubk: rsa_public_key = rsa_public_key::default();
        unsafe {
            nettle_rsa_public_key_init(&mut pubk);
        }
        unsafe {
            nettle_mpz_set_str_256_u(
                &mut pubk.e[0],
                exponent.len(),
                exponent.as_ptr(),
            );
        }
        let mut prik: rsa_private_key = rsa_private_key::default();
        unsafe {
            nettle_rsa_private_key_init(&mut prik);
        }
        let res = unsafe {
            nettle_rsa_generate_keypair(
                &mut pubk,
                &mut prik,
                rng as *mut _ as *mut ::std::os::raw::c_void,
                Some(get_random),
                std::ptr::null_mut(),
                None,
                bits as ::std::os::raw::c_uint,
                0,
            )
        };
        if res == 0 {
            return err_rv!(CKR_DEVICE_ERROR);
        }

        macro_rules! mpz_to_vec {
            ($mpz:expr) => {{
                unsafe {
                    let mut v: Vec<u8> =
                        vec![0; nettle_mpz_sizeinbase_256_u(&mut $mpz)];
                    nettle_mpz_get_str_256(v.len(), v.as_mut_ptr(), &mut $mpz);
                    v
                }
            }};
        }

        let n = mpz_to_vec!(pubk.n[0]);
        pubkey.set_attr(attribute::from_bytes(CKA_MODULUS, n.clone()))?;

        obj.set_attr(attribute::from_bytes(CKA_MODULUS, n))?;
        let e = mpz_to_vec!(pubk.e[0]);
        obj.set_attr(attribute::from_bytes(CKA_PUBLIC_EXPONENT, e))?;
        let d = mpz_to_vec!(prik.d[0]);
        obj.set_attr(attribute::from_bytes(CKA_PRIVATE_EXPONENT, d))?;
        let p = mpz_to_vec!(prik.d[0]);
        obj.set_attr(attribute::from_bytes(CKA_PRIME_1, p))?;
        let q = mpz_to_vec!(prik.d[0]);
        obj.set_attr(attribute::from_bytes(CKA_PRIME_2, q))?;
        let a = mpz_to_vec!(prik.d[0]);
        obj.set_attr(attribute::from_bytes(CKA_EXPONENT_1, a))?;
        let b = mpz_to_vec!(prik.d[0]);
        obj.set_attr(attribute::from_bytes(CKA_EXPONENT_2, b))?;
        let c = mpz_to_vec!(prik.d[0]);
        obj.set_attr(attribute::from_bytes(CKA_COEFFICIENT, c))?;

        pubkey.generate_unique();
        obj.generate_unique();
        Ok(obj)
    }

    fn get_attributes(&self) -> &Vec<ObjectAttr> {
        &self.attributes
    }

    fn get_attributes_mut(&mut self) -> &mut Vec<ObjectAttr> {
        &mut self.attributes
    }
}

impl CommonKeyTemplate for RSAPrivTemplate {
    fn get_attributes(&self) -> &Vec<ObjectAttr> {
        &self.attributes
    }

    fn get_attributes_mut(&mut self) -> &mut Vec<ObjectAttr> {
        &mut self.attributes
    }
}

impl PrivKeyTemplate for RSAPrivTemplate {
    fn get_attributes(&self) -> &Vec<ObjectAttr> {
        &self.attributes
    }

    fn get_attributes_mut(&mut self) -> &mut Vec<ObjectAttr> {
        &mut self.attributes
    }
}

fn comp(a: Vec<u8>, b: Vec<u8>) -> KResult<()> {
    if a.len() > b.len() {
        let d = a.len() - b.len();
        match a[..d].iter().find(|&&v| v != 0) {
            Some(_) => return err_rv!(CKR_KEY_INDIGESTIBLE),
            None => (),
        }
        if &a[d..] != b {
            return err_rv!(CKR_KEY_INDIGESTIBLE);
        }
    } else if a.len() < b.len() {
        let d = b.len() - a.len();
        match b[..d].iter().find(|&&v| v != 0) {
            Some(_) => return err_rv!(CKR_KEY_INDIGESTIBLE),
            None => (),
        }
        if &b[d..] != a {
            return err_rv!(CKR_KEY_INDIGESTIBLE);
        }
    } else {
        if a != b {
            return err_rv!(CKR_KEY_INDIGESTIBLE);
        }
    }
    Ok(())
}

fn inner_mod_inv(
    a: &BigUint,
    b: &BigUint,
    q: &BigUint,
    n: &BigUint,
) -> (BigUint, BigUint) {
    let t = (q * a) % n;
    let r = if b >= &t { b - t } else { n - t + b };
    return (a.clone(), r);
}

fn mod_inv(a: &BigUint, n: &BigUint) -> KResult<BigUint> {
    let mut r: BigUint = Zero::zero();
    let mut i = n.clone();
    let mut tr: BigUint = One::one();
    let mut ti = a.clone();

    while ti != Zero::zero() {
        let q = &i / &ti;
        (r, tr) = inner_mod_inv(&tr, &r, &q, n);
        /* the following is guaranteed to converge to 0 */
        (i, ti) = inner_mod_inv(&ti, &i, &q, n);
    }

    if i > One::one() {
        return err_rv!(CKR_KEY_INDIGESTIBLE);
    }
    Ok(r)
}

#[derive(Debug)]
struct RsaBigUints {
    n: BigUint,
    e: BigUint,
    d: BigUint,
    p: BigUint,
    q: BigUint,
    a: BigUint,
    b: BigUint,
    c: BigUint,
}

impl Drop for RsaBigUints {
    fn drop(&mut self) {
        /* TODO:
        self.d.zeroize();
        self.p.zeroize();
        self.q.zeroize();
        self.a.zeroize();
        self.b.zeroize();
        self.c.zeroize();
        */
    }
}

impl RsaBigUints {
    pub fn new(n: &[u8], e: &[u8], d: &[u8]) -> RsaBigUints {
        RsaBigUints {
            n: BigUint::from_bytes_be(n),
            e: BigUint::from_bytes_be(e),
            d: BigUint::from_bytes_be(d),
            p: Zero::zero(),
            q: Zero::zero(),
            a: Zero::zero(),
            b: Zero::zero(),
            c: Zero::zero(),
        }
    }

    /* From SP 800 56B Appendix C.2 */
    /* NOTE: this code does not give any guarantee in terms of zeroization of
     * intermediate values or computation timing leaks and should not be used
     * in any code path that is involved in actual cryptography computations.
     *
     * It is currently implemented only to serve as a stop gap for
     * importing keys
     */
    pub fn decompose(&mut self) -> KResult<()> {
        let des1: BigUint = &self.d * &self.e - 1u8;
        let a = &des1 * &des1.gcd(&(&self.n - 1u8));
        let m = a.div_floor(&self.n);
        let r = a - &m * &self.n;
        let (mut b, b_rem) = (&self.n - r).div_rem(&(m + 1u8));
        if b_rem != Zero::zero() {
            return err_rv!(CKR_KEY_INDIGESTIBLE);
        }
        b += 1u8;
        let sqb = b.pow(2);
        let n4 = &self.n * 4u8;
        if sqb <= n4 {
            return err_rv!(CKR_KEY_INDIGESTIBLE);
        }
        let gamma = (sqb - n4).sqrt();
        self.p = (&b + &gamma) >> 1;
        self.q = (&b - &gamma) >> 1;
        self.a = &self.d % &(&self.p - 1u8);
        self.b = &self.d % &(&self.q - 1u8);

        self.c = mod_inv(&self.q, &self.p)?;
        Ok(())
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

fn empty_private_key() -> rsa_private_key {
    rsa_private_key::default()
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
        if self.info.flags & CKF_ENCRYPT != CKF_ENCRYPT {
            return err_rv!(CKR_MECHANISM_INVALID);
        }
        match check_key_object(key, true, CKA_ENCRYPT) {
            Ok(_) => (),
            Err(e) => return Err(e),
        }
        Ok(Box::new(RsaPKCSOperation::encrypt_new(
            mech, key, &self.info,
        )?))
    }

    fn decryption_new(
        &self,
        mech: &CK_MECHANISM,
        key: &Object,
    ) -> KResult<Box<dyn Decryption>> {
        if self.info.flags & CKF_DECRYPT != CKF_DECRYPT {
            return err_rv!(CKR_MECHANISM_INVALID);
        }
        match check_key_object(key, false, CKA_DECRYPT) {
            Ok(_) => (),
            Err(e) => return Err(e),
        }
        Ok(Box::new(RsaPKCSOperation::decrypt_new(
            mech, key, &self.info,
        )?))
    }
    fn sign_new(
        &self,
        mech: &CK_MECHANISM,
        key: &Object,
    ) -> KResult<Box<dyn Sign>> {
        if self.info.flags & CKF_SIGN != CKF_SIGN {
            return err_rv!(CKR_MECHANISM_INVALID);
        }
        match check_key_object(key, false, CKA_SIGN) {
            Ok(_) => (),
            Err(e) => return Err(e),
        }
        Ok(Box::new(RsaPKCSOperation::sign_new(mech, key, &self.info)?))
    }
    fn verify_new(
        &self,
        mech: &CK_MECHANISM,
        key: &Object,
    ) -> KResult<Box<dyn Verify>> {
        if self.info.flags & CKF_VERIFY != CKF_VERIFY {
            return err_rv!(CKR_MECHANISM_INVALID);
        }
        match check_key_object(key, true, CKA_VERIFY) {
            Ok(_) => (),
            Err(e) => return Err(e),
        }
        Ok(Box::new(RsaPKCSOperation::verify_new(
            mech, key, &self.info,
        )?))
    }
}

pub fn register(mechs: &mut Mechanisms, ot: &mut ObjectTemplates) {
    mechs.add_mechanism(
        CKM_RSA_PKCS,
        Box::new(RsaPKCSMechanism {
            info: CK_MECHANISM_INFO {
                ulMinKeySize: MIN_RSA_SIZE_BITS as CK_ULONG,
                ulMaxKeySize: MAX_RSA_SIZE_BITS as CK_ULONG,
                flags: CKF_ENCRYPT | CKF_DECRYPT | CKF_SIGN | CKF_VERIFY,
            },
        }),
    );
    mechs.add_mechanism(
        CKM_SHA1_RSA_PKCS,
        Box::new(RsaPKCSMechanism {
            info: CK_MECHANISM_INFO {
                ulMinKeySize: MIN_RSA_SIZE_BITS as CK_ULONG,
                ulMaxKeySize: MAX_RSA_SIZE_BITS as CK_ULONG,
                flags: CKF_SIGN | CKF_VERIFY,
            },
        }),
    );

    mechs.add_mechanism(
        CKM_SHA256_RSA_PKCS,
        Box::new(RsaPKCSMechanism {
            info: CK_MECHANISM_INFO {
                ulMinKeySize: MIN_RSA_SIZE_BITS as CK_ULONG,
                ulMaxKeySize: MAX_RSA_SIZE_BITS as CK_ULONG,
                flags: CKF_SIGN | CKF_VERIFY,
            },
        }),
    );

    mechs.add_mechanism(
        CKM_SHA384_RSA_PKCS,
        Box::new(RsaPKCSMechanism {
            info: CK_MECHANISM_INFO {
                ulMinKeySize: MIN_RSA_SIZE_BITS as CK_ULONG,
                ulMaxKeySize: MAX_RSA_SIZE_BITS as CK_ULONG,
                flags: CKF_SIGN | CKF_VERIFY,
            },
        }),
    );

    mechs.add_mechanism(
        CKM_SHA512_RSA_PKCS,
        Box::new(RsaPKCSMechanism {
            info: CK_MECHANISM_INFO {
                ulMinKeySize: MIN_RSA_SIZE_BITS as CK_ULONG,
                ulMaxKeySize: MAX_RSA_SIZE_BITS as CK_ULONG,
                flags: CKF_SIGN | CKF_VERIFY,
            },
        }),
    );

    ot.add_template(ObjectType::RSAPubKey, Box::new(RSAPubTemplate::new()));
    ot.add_template(ObjectType::RSAPrivKey, Box::new(RSAPrivTemplate::new()));
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

#[derive(Debug)]
struct RsaPKCSOperation {
    mech: CK_MECHANISM_TYPE,
    inner: Operation,
    max_input: usize,
    output_len: usize,
    public_key: rsa_public_key,
    private_key: rsa_private_key,
    finalized: bool,
    in_use: bool,
}

impl RsaPKCSOperation {
    fn encrypt_new(
        mech: &CK_MECHANISM,
        key: &Object,
        info: &CK_MECHANISM_INFO,
    ) -> KResult<RsaPKCSOperation> {
        let modulus = key.get_attr_as_bytes(CKA_MODULUS)?;
        let modulus_bits: u64 = modulus.len() as u64 * 8;
        if modulus_bits < info.ulMinKeySize
            || (info.ulMaxKeySize != 0 && modulus_bits > info.ulMaxKeySize)
        {
            return err_rv!(CKR_KEY_SIZE_RANGE);
        }
        if mech.mechanism != CKM_RSA_PKCS {
            return err_rv!(CKR_MECHANISM_INVALID);
        }
        Ok(RsaPKCSOperation {
            mech: mech.mechanism,
            inner: Operation::Empty,
            max_input: modulus.len() - 11,
            output_len: modulus.len(),
            public_key: object_to_rsa_public_key(key)?,
            private_key: empty_private_key(),
            finalized: false,
            in_use: false,
        })
    }

    fn decrypt_new(
        mech: &CK_MECHANISM,
        key: &Object,
        info: &CK_MECHANISM_INFO,
    ) -> KResult<RsaPKCSOperation> {
        let modulus = key.get_attr_as_bytes(CKA_MODULUS)?;
        let modulus_bits: u64 = modulus.len() as u64 * 8;
        if modulus_bits < info.ulMinKeySize
            || (info.ulMaxKeySize != 0 && modulus_bits > info.ulMaxKeySize)
        {
            return err_rv!(CKR_KEY_SIZE_RANGE);
        }
        if mech.mechanism != CKM_RSA_PKCS {
            return err_rv!(CKR_MECHANISM_INVALID);
        }
        Ok(RsaPKCSOperation {
            mech: mech.mechanism,
            inner: Operation::Empty,
            max_input: modulus.len(),
            output_len: modulus.len() - 11,
            public_key: object_to_rsa_public_key(key)?,
            private_key: object_to_rsa_private_key(key)?,
            finalized: false,
            in_use: false,
        })
    }

    fn sign_new(
        mech: &CK_MECHANISM,
        key: &Object,
        info: &CK_MECHANISM_INFO,
    ) -> KResult<RsaPKCSOperation> {
        let modulus = key.get_attr_as_bytes(CKA_MODULUS)?;
        let modulus_bits: u64 = modulus.len() as u64 * 8;
        if modulus_bits < info.ulMinKeySize
            || (info.ulMaxKeySize != 0 && modulus_bits > info.ulMaxKeySize)
        {
            return err_rv!(CKR_KEY_SIZE_RANGE);
        }

        Ok(RsaPKCSOperation {
            mech: mech.mechanism,
            max_input: match mech.mechanism {
                CKM_RSA_PKCS => modulus.len() - 11,
                CKM_SHA1_RSA_PKCS => 0,
                CKM_SHA256_RSA_PKCS => 0,
                CKM_SHA384_RSA_PKCS => 0,
                CKM_SHA512_RSA_PKCS => 0,
                _ => return err_rv!(CKR_MECHANISM_INVALID),
            },
            output_len: modulus.len(),
            inner: match mech.mechanism {
                CKM_RSA_PKCS => Operation::Empty,
                CKM_SHA1_RSA_PKCS => {
                    Operation::Digest(Box::new(sha1::SHA1Operation::new()))
                }
                CKM_SHA256_RSA_PKCS => {
                    Operation::Digest(Box::new(sha2::SHA256Operation::new()))
                }
                CKM_SHA384_RSA_PKCS => {
                    Operation::Digest(Box::new(sha2::SHA384Operation::new()))
                }
                CKM_SHA512_RSA_PKCS => {
                    Operation::Digest(Box::new(sha2::SHA512Operation::new()))
                }
                _ => return err_rv!(CKR_MECHANISM_INVALID),
            },
            public_key: object_to_rsa_public_key(key)?,
            private_key: object_to_rsa_private_key(key)?,
            finalized: false,
            in_use: false,
        })
    }

    fn verify_new(
        mech: &CK_MECHANISM,
        key: &Object,
        info: &CK_MECHANISM_INFO,
    ) -> KResult<RsaPKCSOperation> {
        let modulus = key.get_attr_as_bytes(CKA_MODULUS)?;
        let modulus_bits: u64 = modulus.len() as u64 * 8;
        if modulus_bits < info.ulMinKeySize
            || (info.ulMaxKeySize != 0 && modulus_bits > info.ulMaxKeySize)
        {
            return err_rv!(CKR_KEY_SIZE_RANGE);
        }

        Ok(RsaPKCSOperation {
            mech: mech.mechanism,
            max_input: match mech.mechanism {
                CKM_RSA_PKCS => modulus.len() - 11,
                CKM_SHA1_RSA_PKCS => 0,
                CKM_SHA256_RSA_PKCS => 0,
                CKM_SHA384_RSA_PKCS => 0,
                CKM_SHA512_RSA_PKCS => 0,
                _ => return err_rv!(CKR_MECHANISM_INVALID),
            },
            output_len: modulus.len(),
            inner: match mech.mechanism {
                CKM_RSA_PKCS => Operation::Empty,
                CKM_SHA1_RSA_PKCS => {
                    Operation::Digest(Box::new(sha1::SHA1Operation::new()))
                }
                CKM_SHA256_RSA_PKCS => {
                    Operation::Digest(Box::new(sha2::SHA256Operation::new()))
                }
                CKM_SHA384_RSA_PKCS => {
                    Operation::Digest(Box::new(sha2::SHA384Operation::new()))
                }
                CKM_SHA512_RSA_PKCS => {
                    Operation::Digest(Box::new(sha2::SHA512Operation::new()))
                }
                _ => return err_rv!(CKR_MECHANISM_INVALID),
            },
            public_key: object_to_rsa_public_key(key)?,
            private_key: empty_private_key(),
            finalized: false,
            in_use: false,
        })
    }

    fn emsa_prefix(&self, digest_idx: &mut usize) -> KResult<Vec<u8>> {
        /* EMSA prefixes are an ASN.1 structure containing a hash identifier
         * in OID form, and the actual hash in an octect string. Here we
         * hard code the DER strcutures as they do not change based on the
         * content of the hash which can be trated as a buffer at a fixed index.
         * The general form is defined in RFC8017 Appendix A.2.4:
         *   DigestInfo ::= SEQUENCE {
         *     digestAlgorithm DigestAlgorithm,
         *     digest OCTET STRING
         *   }
         *
         *   DigestAlgorithm ::= AlgorithmIdentifier {
         *     {PKCS1-v1-5DigestAlgorithms}
         *   }
         *
         *   AlgorithmIdentifier { ALGORITHM-IDENTIFIER:InfoObjectSet } ::=
         *     SEQUENCE {
         *       algorithm ALGORITHM-IDENTIFIER.&id({InfoObjectSet}),
         *       parameters ALGORITHM-IDENTIFIER.&Type({InfoObjectSet}{@.algorithm}) OPTIONAL
         *     }
         *
         *    ALGORITHM-IDENTIFIER ::= CLASS {
         *      &id    OBJECT IDENTIFIER  UNIQUE,
         *      &Type  OPTIONAL
         *    }
         *
         *  Although this looks complicated parameter/type is nevr used so the structure bils down
         *  to:
         *    SEQUENCE {                // [0x30, length]
         *      SEQUENCE {              // [0x30, length]
         *        OID { value }         // [OID] (0x06, lenght, ...)
         *        NULL                  // [0x05, 0]
         *      }
         *      OCTET-STRING (hash)     // [0x04, length, hash]
         *    }
         */
        match self.mech {
            CKM_SHA1_RSA_PKCS => {
                #[rustfmt::skip]
                let mut emsa: Vec<u8> = vec![
                    0x30, 33,
                      0x30, 9,
                        0x06, 0x05,
                          0x2b, 0x0e, 0x03, 0x02, 0x1a,
                        0x05, 0,
                      0x04, 20,
                ];
                *digest_idx = emsa.len();
                emsa.extend([0; 20]);
                Ok(emsa)
            }
            CKM_SHA256_RSA_PKCS => {
                #[rustfmt::skip]
                let mut emsa: Vec<u8> = vec![
                    0x30, 49,
                      0x30, 13,
                        0x06, 9,
                          0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
                        0x05, 0,
                      0x04, 32,
                ];
                *digest_idx = emsa.len();
                emsa.extend([0; 32]);
                Ok(emsa)
            }
            CKM_SHA384_RSA_PKCS => {
                #[rustfmt::skip]
                let mut emsa: Vec<u8> = vec![
                    0x30, 65,
                      0x30, 13,
                        0x06, 9,
                          0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02,
                        0x05, 0,
                      0x04, 48,
                ];
                *digest_idx = emsa.len();
                emsa.extend([0; 48]);
                Ok(emsa)
            }
            CKM_SHA512_RSA_PKCS => {
                #[rustfmt::skip]
                let mut emsa: Vec<u8> = vec![
                    0x30, 81,
                      0x30, 13,
                        0x06, 9,
                          0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03,
                        0x05, 0,
                      0x04, 64,
                ];
                *digest_idx = emsa.len();
                emsa.extend([0; 64]);
                Ok(emsa)
            }
            _ => err_rv!(CKR_GENERAL_ERROR),
        }
    }

    fn pkcs1_encrypt(
        &self,
        rng: &mut RNG,
        plain: &[u8],
        cipher: CK_BYTE_PTR,
        cipher_len: CK_ULONG_PTR,
    ) -> KResult<()> {
        let mut c: mpz_struct_wrapper = mpz_struct_wrapper::new();

        let res = unsafe {
            nettle_rsa_encrypt(
                &self.public_key,
                rng as *mut _ as *mut ::std::os::raw::c_void,
                Some(get_random),
                plain.len(),
                plain.as_ptr(),
                c.as_mut_ptr(),
            )
        };
        if res == 0 {
            return err_rv!(CKR_GENERAL_ERROR);
        }

        unsafe {
            let len = nettle_mpz_sizeinbase_256_u(c.as_mut_ptr());
            if len as CK_ULONG > *cipher_len {
                return err_rv!(CKR_GENERAL_ERROR);
            }
            nettle_mpz_get_str_256(len, cipher, c.as_mut_ptr());
            *cipher_len = len as CK_ULONG;
        }
        Ok(())
    }

    fn pkcs1_decrypt(
        &self,
        rng: &mut RNG,
        cipher: &[u8],
        plain: CK_BYTE_PTR,
        plain_len: CK_ULONG_PTR,
    ) -> KResult<()> {
        let mut c: mpz_struct_wrapper = mpz_struct_wrapper::new();
        unsafe {
            nettle_mpz_init_set_str_256_u(
                c.as_mut_ptr(),
                cipher.len(),
                cipher.as_ptr(),
            );
        }

        let mut plen: usize = unsafe { *plain_len } as usize;
        if plen < (self.public_key.size - 1) {
            return err_rv!(CKR_BUFFER_TOO_SMALL);
        }

        let res = unsafe {
            nettle_rsa_decrypt_tr(
                &self.public_key,
                &self.private_key,
                rng as *mut _ as *mut ::std::os::raw::c_void,
                Some(get_random),
                &mut plen,
                plain as *mut _ as *mut u8,
                c.as_mut_ptr(),
            )
        };
        if res == 0 {
            return err_rv!(CKR_GENERAL_ERROR);
        }
        unsafe {
            *plain_len = plen as CK_ULONG;
        }
        Ok(())
    }

    fn pkcs1_sign(
        &self,
        rng: &mut RNG,
        digest: &[u8],
        signature: &mut [u8],
    ) -> KResult<()> {
        let mut s: mpz_struct_wrapper = mpz_struct_wrapper::new();

        let res = unsafe {
            nettle_rsa_pkcs1_sign_tr(
                &self.public_key,
                &self.private_key,
                rng as *mut _ as *mut ::std::os::raw::c_void,
                Some(get_random),
                digest.len(),
                digest.as_ptr(),
                s.as_mut_ptr(),
            )
        };
        if res == 0 {
            return err_rv!(CKR_GENERAL_ERROR);
        }

        unsafe {
            let len = nettle_mpz_sizeinbase_256_u(s.as_mut_ptr());
            if len != signature.len() {
                return err_rv!(CKR_BUFFER_TOO_SMALL);
            }
            nettle_mpz_get_str_256(len, signature.as_mut_ptr(), s.as_mut_ptr());
        }
        Ok(())
    }

    fn pkcs1_verify(&self, digest: &[u8], signature: &[u8]) -> KResult<()> {
        let mut s: mpz_struct_wrapper = mpz_struct_wrapper::new();
        unsafe {
            nettle_mpz_init_set_str_256_u(
                s.as_mut_ptr(),
                signature.len(),
                signature.as_ptr(),
            );
        }
        let res = unsafe {
            nettle_rsa_pkcs1_verify(
                &self.public_key,
                digest.len(),
                digest.as_ptr(),
                s.as_mut_ptr(),
            )
        };
        if res == 0 {
            return err_rv!(CKR_SIGNATURE_INVALID);
        }
        Ok(())
    }
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
        plain: &[u8],
        cipher: CK_BYTE_PTR,
        cipher_len: CK_ULONG_PTR,
    ) -> KResult<()> {
        if self.in_use {
            return err_rv!(CKR_OPERATION_NOT_INITIALIZED);
        }
        if self.finalized {
            return err_rv!(CKR_OPERATION_NOT_INITIALIZED);
        }
        let key_size = (self.public_key.size - 1) as CK_ULONG;

        if cipher.is_null() {
            unsafe { *cipher_len = key_size };
            return Ok(());
        }

        self.finalized = true;

        let clen = unsafe { *cipher_len };
        if clen < key_size {
            return err_rv!(CKR_BUFFER_TOO_SMALL);
        }

        self.pkcs1_encrypt(rng, plain, cipher, cipher_len)
    }

    fn encrypt_update(
        &mut self,
        _rng: &mut RNG,
        _plain: &[u8],
        _cipher: CK_BYTE_PTR,
        _cipher_len: CK_ULONG_PTR,
    ) -> KResult<()> {
        self.finalized = true;
        return err_rv!(CKR_OPERATION_NOT_INITIALIZED);
    }

    fn encrypt_final(
        &mut self,
        _rng: &mut RNG,
        _cipher: CK_BYTE_PTR,
        _cipher_len: CK_ULONG_PTR,
    ) -> KResult<()> {
        self.finalized = true;
        return err_rv!(CKR_OPERATION_NOT_INITIALIZED);
    }
    fn encryption_len(&self) -> KResult<usize> {
        match self.mech {
            CKM_RSA_PKCS => Ok(self.output_len),
            _ => err_rv!(CKR_GENERAL_ERROR),
        }
    }
}

impl Decryption for RsaPKCSOperation {
    fn decrypt(
        &mut self,
        rng: &mut RNG,
        cipher: &[u8],
        plain: CK_BYTE_PTR,
        plain_len: CK_ULONG_PTR,
    ) -> KResult<()> {
        if self.in_use {
            return err_rv!(CKR_OPERATION_NOT_INITIALIZED);
        }
        if self.finalized {
            return err_rv!(CKR_OPERATION_NOT_INITIALIZED);
        }
        let key_size = (self.public_key.size - 1) as CK_ULONG;

        if plain.is_null() {
            unsafe { *plain_len = key_size };
            return Ok(());
        }

        self.finalized = true;

        let plen = unsafe { *plain_len };
        if plen < key_size {
            return err_rv!(CKR_BUFFER_TOO_SMALL);
        }

        self.pkcs1_decrypt(rng, cipher, plain, plain_len)
    }
    fn decrypt_update(
        &mut self,
        _rng: &mut RNG,
        _cipher: &[u8],
        _plain: CK_BYTE_PTR,
        _plain_len: CK_ULONG_PTR,
    ) -> KResult<()> {
        self.finalized = true;
        return err_rv!(CKR_OPERATION_NOT_INITIALIZED);
    }
    fn decrypt_final(
        &mut self,
        _rng: &mut RNG,
        _plain: CK_BYTE_PTR,
        _plain_len: CK_ULONG_PTR,
    ) -> KResult<()> {
        self.finalized = true;
        return err_rv!(CKR_OPERATION_NOT_INITIALIZED);
    }
    fn decryption_len(&self) -> KResult<usize> {
        match self.mech {
            CKM_RSA_PKCS => Ok(self.output_len),
            _ => err_rv!(CKR_GENERAL_ERROR),
        }
    }
}

impl Sign for RsaPKCSOperation {
    fn sign(
        &mut self,
        rng: &mut RNG,
        data: &[u8],
        signature: &mut [u8],
    ) -> KResult<()> {
        if self.in_use {
            return err_rv!(CKR_OPERATION_NOT_INITIALIZED);
        }
        if self.finalized {
            return err_rv!(CKR_OPERATION_NOT_INITIALIZED);
        }
        match self.mech {
            CKM_RSA_PKCS => {
                self.finalized = true;
                if data.len() > self.max_input {
                    return err_rv!(CKR_DATA_LEN_RANGE);
                }
                if signature.len() != self.output_len {
                    return err_rv!(CKR_GENERAL_ERROR);
                }
                return self.pkcs1_sign(rng, data, signature);
            }
            CKM_SHA1_RSA_PKCS => (),
            CKM_SHA256_RSA_PKCS => (),
            CKM_SHA384_RSA_PKCS => (),
            CKM_SHA512_RSA_PKCS => (),
            _ => return err_rv!(CKR_GENERAL_ERROR),
        }
        self.sign_update(data)?;
        self.sign_final(rng, signature)
    }

    fn sign_update(&mut self, data: &[u8]) -> KResult<()> {
        if self.finalized {
            return err_rv!(CKR_OPERATION_NOT_INITIALIZED);
        }
        if !self.in_use {
            if self.mech == CKM_RSA_PKCS {
                return err_rv!(CKR_OPERATION_NOT_INITIALIZED);
            }
            self.in_use = true;
        }
        match &mut self.inner {
            Operation::Digest(op) => op.digest_update(data),
            _ => err_rv!(CKR_GENERAL_ERROR),
        }
    }

    fn sign_final(
        &mut self,
        rng: &mut RNG,
        signature: &mut [u8],
    ) -> KResult<()> {
        if !self.in_use {
            return err_rv!(CKR_OPERATION_NOT_INITIALIZED);
        }
        if self.finalized {
            return err_rv!(CKR_OPERATION_NOT_INITIALIZED);
        }
        self.finalized = true;
        if signature.len() != self.output_len {
            return err_rv!(CKR_GENERAL_ERROR);
        }
        let mut digest_idx = 0;
        let mut digest = self.emsa_prefix(&mut digest_idx)?;
        match &mut self.inner {
            Operation::Digest(op) => {
                op.digest_final(&mut digest[digest_idx..])?
            }
            _ => return err_rv!(CKR_GENERAL_ERROR),
        }
        self.pkcs1_sign(rng, digest.as_slice(), signature)
    }

    fn signature_len(&self) -> KResult<usize> {
        Ok(self.output_len)
    }
}

impl Verify for RsaPKCSOperation {
    fn verify(&mut self, data: &[u8], signature: &[u8]) -> KResult<()> {
        if self.in_use {
            return err_rv!(CKR_OPERATION_NOT_INITIALIZED);
        }
        if self.finalized {
            return err_rv!(CKR_OPERATION_NOT_INITIALIZED);
        }
        match self.mech {
            CKM_RSA_PKCS => {
                self.finalized = true;
                if data.len() > self.max_input {
                    return err_rv!(CKR_DATA_LEN_RANGE);
                }
                if signature.len() < self.output_len {
                    return err_rv!(CKR_BUFFER_TOO_SMALL);
                }
                return self.pkcs1_verify(data, signature);
            }
            CKM_SHA1_RSA_PKCS => (),
            CKM_SHA256_RSA_PKCS => (),
            CKM_SHA384_RSA_PKCS => (),
            CKM_SHA512_RSA_PKCS => (),
            _ => return err_rv!(CKR_GENERAL_ERROR),
        }
        self.verify_update(data)?;
        self.verify_final(signature)
    }
    fn verify_update(&mut self, data: &[u8]) -> KResult<()> {
        if self.finalized {
            return err_rv!(CKR_OPERATION_NOT_INITIALIZED);
        }
        if !self.in_use {
            if self.mech == CKM_RSA_PKCS {
                return err_rv!(CKR_OPERATION_NOT_INITIALIZED);
            }
            self.in_use = true;
        }
        match &mut self.inner {
            Operation::Digest(op) => op.digest_update(data),
            _ => err_rv!(CKR_GENERAL_ERROR),
        }
    }
    fn verify_final(&mut self, signature: &[u8]) -> KResult<()> {
        if !self.in_use {
            return err_rv!(CKR_OPERATION_NOT_INITIALIZED);
        }
        if self.finalized {
            return err_rv!(CKR_OPERATION_NOT_INITIALIZED);
        }
        self.finalized = true;
        if signature.len() != self.output_len {
            return err_rv!(CKR_GENERAL_ERROR);
        }
        let mut digest_idx = 0;
        let mut digest = self.emsa_prefix(&mut digest_idx)?;
        match &mut self.inner {
            Operation::Digest(op) => {
                op.digest_final(&mut digest[digest_idx..])?
            }
            _ => return err_rv!(CKR_GENERAL_ERROR),
        }
        self.pkcs1_verify(digest.as_slice(), signature)
    }

    fn signature_len(&self) -> KResult<usize> {
        Ok(self.output_len)
    }
}
