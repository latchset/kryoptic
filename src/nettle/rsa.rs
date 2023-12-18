// Copyright 2023 Simo Sorce
// See LICENSE.txt file for terms

use super::hash;
use super::mechanism;
use super::nettle;
use super::rng;
use super::util;

use mechanism::*;
use nettle::*;
use rng::RNG;

use zeroize::Zeroize;

#[derive(Clone)]
struct Zvec {
    vec: Vec<u64>,
    size: usize,
}

impl Drop for Zvec {
    fn drop(&mut self) {
        self.vec.zeroize();
    }
}

impl Zvec {
    pub fn new(size: usize, capacity: usize) -> Zvec {
        assert!(size <= capacity);
        Zvec {
            vec: vec![0; capacity],
            size: size,
        }
    }

    pub fn raw(size: usize) -> Zvec {
        let mut z = Zvec {
            vec: Vec::with_capacity(size),
            size: size,
        };
        unsafe {
            z.vec.set_len(size);
        }
        z
    }

    pub fn from_slice(s: &[u64], capacity: usize) -> Zvec {
        let mut z = Self::raw(capacity);
        let (left, right) = z.vec.as_mut_slice().split_at_mut(s.len());
        left.copy_from_slice(s);
        for i in right {
            *i = 0;
        }
        z.size = s.len();
        z
    }

    pub fn from_bytes(s: &[u8], capacity: usize) -> Zvec {
        let mut z = Self::raw(capacity);
        z.size = (s.len() + 7) / 8;
        assert!(z.size <= capacity);
        let (lvec, rvec) = z.vec.as_mut_slice().split_at_mut(z.size);
        for i in rvec {
            *i = 0;
        }
        let mut n = s.len();
        let mut i = 0;
        while n > 8 {
            n -= 8;
            lvec[i] = u64::from_be_bytes(s[n..(n + 8)].try_into().unwrap());
            i += 1;
        }
        if n > 0 {
            let mut last = [0u8; 8];
            let (_, rlast) = last.split_at_mut(8 - n);
            rlast.copy_from_slice(&s[0..n]);
            lvec[i] = u64::from_be_bytes(last);
        }
        z
    }

    pub fn to_vec(&self) -> Vec<u8> {
        let mut n = self.size;
        let mut v: Vec<u8> = vec![0; n * 8];
        let mut i = 0;
        while n > 0 {
            n -= 1;
            v[i..(i + 8)].copy_from_slice(&self.vec[n].to_be_bytes());
            i += 8;
        }
        v
    }

    pub fn from_val(s: u64, capacity: usize) -> Zvec {
        let mut z = Self::new(1, capacity);
        z.vec[0] = s;
        z
    }

    pub fn len(&self) -> usize {
        self.size
    }

    pub fn capacity(&self) -> usize {
        self.vec.len()
    }

    pub fn as_ptr(&self) -> *const u64 {
        self.vec.as_ptr()
    }

    pub fn as_mut_ptr(&mut self) -> *mut u64 {
        self.vec.as_mut_ptr()
    }

    pub fn as_slice(&self) -> &[u64] {
        unsafe { std::slice::from_raw_parts(self.vec.as_ptr(), self.size) }
    }

    pub fn as_mut_slice(&mut self) -> &mut [u64] {
        unsafe {
            std::slice::from_raw_parts_mut(self.vec.as_mut_ptr(), self.size)
        }
    }

    /* carry ignored, the operand should always be >= 1 */
    fn decrement(&mut self) {
        let len = self.size as mp_size_t;
        let tmp_size = unsafe { __gmpn_sec_sub_1_itch(len) as usize };
        let mut tmp = Zvec::raw(tmp_size);
        let rp = self.vec.as_mut_ptr();
        unsafe {
            __gmpn_sec_sub_1(rp, rp, len, 1, tmp.as_mut_ptr());
        }
    }

    fn increment(&mut self) {
        assert!(self.len() < self.capacity());
        let len = self.size as mp_size_t;
        let tmp_size = unsafe { __gmpn_sec_add_1_itch(len) as usize };
        let mut tmp = Zvec::raw(tmp_size);
        let rp = self.vec.as_mut_ptr();
        let c = unsafe { __gmpn_sec_add_1(rp, rp, len, 1, tmp.as_mut_ptr()) };
        self.vec[self.size] = c;
        self.resize(self.size + 1);
    }

    fn rshift(&mut self) {
        unsafe {
            __gmpn_rshift(
                self.vec.as_mut_ptr(),
                self.vec.as_ptr(),
                self.vec.len() as mp_size_t,
                1,
            );
        }
    }

    fn resize(&mut self, size: usize) {
        assert!(size <= self.capacity());
        self.size = size;
    }

    fn reduce(&mut self) {
        let mut n = self.len();
        while n > 0 {
            n -= 1;
            if self.vec[n] != 0 {
                break;
            }
        }
        self.size = n + 1;
    }

    fn is_zero(&self) -> bool {
        let mut zero: u64 = 0;
        let mut n = 0;
        while n < self.len() {
            zero |= self.vec[n];
            n += 1;
        }
        zero == 0
    }

    /* not timing safe */
    fn cmp_int(a: &Vec<u64>, alen: usize, b: &Vec<u64>, blen: usize) -> i8 {
        let mut n = alen;
        while n > blen {
            n -= 1;
            if a[n] > 0 {
                return 1;
            }
        }
        while n > 0 {
            n -= 1;
            if a[n] > b[n] {
                return 1;
            } else if b[n] > a[n] {
                return -1;
            }
        }
        return 0;
    }

    fn cmp(&self, o: &Zvec) -> i8 {
        if self.size > o.size {
            Self::cmp_int(&self.vec, self.size, &o.vec, o.size)
        } else {
            -1i8 * Self::cmp_int(&o.vec, o.size, &self.vec, self.size)
        }
    }
}

struct RsaImport {
    capacity: usize,
}

impl RsaImport {
    fn sec_mul_int(
        &self,
        a: *const u64,
        b: *const u64,
        al: mp_size_t,
        bl: mp_size_t,
    ) -> Zvec {
        let rlen = (al + bl) as usize;
        let mut r = Zvec::new(rlen, self.capacity);
        let tl = unsafe { __gmpn_sec_mul_itch(al, bl) as usize };
        let mut t = Zvec::raw(tl);
        unsafe {
            __gmpn_sec_mul(r.as_mut_ptr(), a, al, b, bl, t.as_mut_ptr());
        }
        r
    }

    fn sec_mul(&self, a: &Zvec, b: &Zvec) -> Zvec {
        if a.len() >= b.len() {
            let aa: *const u64 = a.as_ptr();
            let al = a.len() as mp_size_t;
            let bb: *const u64 = b.as_ptr();
            let bl = b.len() as mp_size_t;
            self.sec_mul_int(aa, bb, al, bl)
        } else {
            let bb = a.as_ptr();
            let bl = a.len() as mp_size_t;
            let aa = b.as_ptr();
            let al = b.len() as mp_size_t;
            self.sec_mul_int(aa, bb, al, bl)
        }
    }

    fn gcd(&self, a: &Zvec, b: &Zvec) -> Zvec {
        unsafe {
            let mut x = __mpz_struct::default();
            let _ = __gmpz_roinit_n(&mut x, a.as_ptr(), a.len() as mp_size_t);
            let mut y = __mpz_struct::default();
            let _ = __gmpz_roinit_n(&mut y, b.as_ptr(), b.len() as mp_size_t);

            let mut r = mpz_wrapper::new();
            __gmpz_gcd(r.as_mut_ptr(), &x, &y);
            Zvec::from_slice(r.as_slice(), self.capacity)
        }
    }

    fn sec_add_n(&self, a: &Zvec, d: &Zvec) -> Zvec {
        let mut r = Zvec::new(a.len(), self.capacity);
        unsafe {
            __gmpn_add_n(
                r.as_mut_ptr(),
                a.as_ptr(),
                d.as_ptr(),
                r.len() as mp_size_t,
            );
        }
        r
    }

    fn sec_sub_n(&self, m: &Zvec, s: &Zvec) -> Zvec {
        let mut r = Zvec::new(m.len(), self.capacity);
        unsafe {
            __gmpn_sub_n(
                r.as_mut_ptr(),
                m.as_ptr(),
                s.as_ptr(),
                r.len() as mp_size_t,
            );
        }
        r
    }

    fn sec_div_qr(&self, n: &Zvec, d: &Zvec) -> (Zvec, Zvec) {
        let nlen = n.len() as mp_size_t;
        let dlen = d.len() as mp_size_t;
        let qlen = n.len() - d.len() + 1;
        let mut q = Zvec::new(qlen, self.capacity);
        let mut r = Zvec::from_slice(n.as_slice(), self.capacity);
        let tmp_size = unsafe { __gmpn_sec_div_qr_itch(nlen, dlen) as usize };
        let mut tmp = Zvec::raw(tmp_size);
        let res = unsafe {
            __gmpn_sec_div_qr(
                q.as_mut_ptr(),
                r.as_mut_ptr(),
                nlen,
                d.as_ptr(),
                dlen,
                tmp.as_mut_ptr(),
            )
        };
        q.as_mut_slice()[qlen - 1] = res;
        r.resize(d.len());
        (q, r)
    }

    fn sec_sqr(&self, op: &Zvec) -> Zvec {
        let len = op.len() as mp_size_t;
        let mut r = Zvec::new(op.len() * 2, self.capacity);
        let tmp_size = unsafe { __gmpn_sec_sqr_itch(len) as usize };
        let mut tmp = Zvec::raw(tmp_size);
        unsafe {
            __gmpn_sec_sqr(r.as_mut_ptr(), op.as_ptr(), len, tmp.as_mut_ptr());
        }
        r
    }

    fn sqrt(&self, op: &Zvec) -> (Zvec, bool) {
        let mut r = Zvec::new((op.len() + 1) / 2, self.capacity);
        let b = unsafe {
            __gmpn_sqrtrem(
                r.as_mut_ptr(),
                std::ptr::null_mut(),
                op.as_ptr(),
                op.len() as mp_size_t,
            ) == 0
        };
        (r, b)
    }

    fn modulus(&self, n: &Zvec, d: &Zvec) -> Zvec {
        let tmp_size = unsafe {
            __gmpn_sec_div_r_itch(n.len() as mp_size_t, d.len() as mp_size_t)
                as usize
        };
        let mut tmp: Vec<u64> = Vec::with_capacity(tmp_size);
        let mut r = Zvec::from_slice(n.as_slice(), self.capacity);
        unsafe {
            __gmpn_sec_div_r(
                r.as_mut_ptr(),
                r.len() as mp_size_t,
                d.as_ptr(),
                d.len() as mp_size_t,
                tmp.as_mut_ptr(),
            );
        }
        r.resize(d.len());
        r
    }

    fn sec_invert(&self, a: &Zvec, m: &Zvec) -> Option<Zvec> {
        let len = m.len() as mp_size_t;
        let tmp_size = unsafe { __gmpn_sec_invert_itch(len) as usize };
        let mut tmp: Vec<u64> = Vec::with_capacity(tmp_size);
        let mut r = Zvec::from_slice(a.as_slice(), self.capacity);
        let mut aa = Zvec::from_slice(a.as_slice(), self.capacity);
        let ret = unsafe {
            __gmpn_sec_invert(
                r.as_mut_ptr(),
                aa.as_mut_ptr(),
                m.as_ptr(),
                len,
                (len * 2 * 64) as mp_bitcnt_t,
                tmp.as_mut_ptr(),
            )
        };
        if ret == 1 {
            r.resize(m.len());
            Some(r)
        } else {
            None
        }
    }

    /* From SP 800 56B Appendix C.2 */
    /* NOTE: this code does not give strong guarantees in terms of
     * side-channel resistance because some of he functions used are
     * not side-channel safe as GMP does not offer safe channel
     * variants
     *
     * This is currently implemented only to serve as a stop gap for
     * importing keys for tests, and should not be used in any
     * cryptographic operation.
     */
    pub fn decompose(
        &self,
        nv: &Vec<u8>,
        ev: &Vec<u8>,
        dv: &Vec<u8>,
    ) -> KResult<(Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>)> {
        let n = Zvec::from_bytes(nv, self.capacity);
        let e = Zvec::from_bytes(ev, self.capacity);
        let d = Zvec::from_bytes(dv, self.capacity);

        /* (de – 1) */
        let mut de_1 = self.sec_mul(&d, &e);
        de_1.decrement();

        /* (n - 1) */
        let mut n_1 = n.clone();
        n_1.decrement();

        /* a = (de - 1) x GCD(n – 1, de – 1) */
        /* this is not side-channel safe :-/ */
        let a = self.sec_mul(&de_1, &self.gcd(&n_1, &de_1));

        /* m = a / n, r = a - mn  [m = quotient, r = reminder of a/n] */
        let (mut m, r) = self.sec_div_qr(&a, &n);

        /* b = ( (n – r)/(m + 1) ) + 1 */
        let mut bn = self.sec_sub_n(&n, &r);
        bn.reduce();
        m.increment();
        m.reduce();
        let (mut b, r) = self.sec_div_qr(&bn, &m);
        if !r.is_zero() {
            return err_rv!(CKR_KEY_INDIGESTIBLE);
        }
        b.increment();
        b.reduce();

        /* y = sqrt(b^2 – 4n) */
        /* It'd be nice to use the proper letter ϒ here, but rust says no! */
        let b2 = self.sec_sqr(&b);
        let four = Zvec::from_val(4, self.capacity);
        let mut n4 = self.sec_mul(&n, &four);
        if b2.cmp(&n4) != 1 {
            return err_rv!(CKR_KEY_INDIGESTIBLE);
        }
        n4.resize(b2.len());
        let mut y2 = self.sec_sub_n(&b2, &n4);
        y2.reduce();
        let (y, perfect) = self.sqrt(&y2);
        if !perfect {
            return err_rv!(CKR_KEY_INDIGESTIBLE);
        }

        /* p = (b + ϒ)/2 */
        let mut p = self.sec_add_n(&b, &y);
        p.rshift();
        p.reduce();

        /* q = (b – ϒ)/2 */
        let mut q = self.sec_sub_n(&b, &y);
        q.rshift();
        q.reduce();

        /* coefficients */
        /* a = d mod (p - 1) */
        let mut tp = p.clone();
        tp.decrement();
        let a = self.modulus(&d, &tp);

        /* b = d mod (q - 1) */
        let mut tq = q.clone();
        tq.decrement();
        let b = self.modulus(&d, &tq);

        /* c = q mod_inv p */
        let c = match self.sec_invert(&q, &p) {
            Some(c) => c,
            None => return err_rv!(CKR_KEY_INDIGESTIBLE),
        };

        Ok((p.to_vec(), q.to_vec(), a.to_vec(), b.to_vec(), c.to_vec()))
    }
}

pub fn rsa_import(obj: &mut Object) -> KResult<()> {
    let n = match obj.get_attr_as_bytes(CKA_MODULUS) {
        Ok(modulus) => modulus,
        Err(_) => return err_rv!(CKR_TEMPLATE_INCOMPLETE),
    };
    if n.len() < MIN_RSA_SIZE_BYTES {
        return err_rv!(CKR_ATTRIBUTE_VALUE_INVALID);
    }
    bytes_attr_not_empty!(obj; CKA_PUBLIC_EXPONENT);
    bytes_attr_not_empty!(obj; CKA_PRIVATE_EXPONENT);

    let p = match obj.get_attr(CKA_PRIME_1) {
        Some(x) => Some(x.get_value().clone()),
        None => None,
    };
    let q = match obj.get_attr(CKA_PRIME_2) {
        Some(x) => Some(x.get_value().clone()),
        None => None,
    };
    let a = match obj.get_attr(CKA_EXPONENT_1) {
        Some(x) => Some(x.get_value().clone()),
        None => None,
    };
    let b = match obj.get_attr(CKA_EXPONENT_2) {
        Some(x) => Some(x.get_value().clone()),
        None => None,
    };
    let c = match obj.get_attr(CKA_COEFFICIENT) {
        Some(x) => Some(x.get_value().clone()),
        None => None,
    };

    if p == None || q == None || a == None || b == None || c == None {
        let r = RsaImport {
            capacity: ((n.len() + 7) / 8) * 2,
        };

        let e = obj.get_attr_as_bytes(CKA_PUBLIC_EXPONENT)?;
        let d = obj.get_attr_as_bytes(CKA_PRIVATE_EXPONENT)?;

        let (mut cp, mut cq, mut ca, mut cb, mut cc) = r.decompose(n, e, d)?;

        match p {
            Some(v) => {
                let r = if v.len() >= cp.len() {
                    util::scs_cmp(
                        v.as_slice(),
                        v.len(),
                        cp.as_slice(),
                        cp.len(),
                    )
                } else {
                    util::scs_cmp(
                        cp.as_slice(),
                        cp.len(),
                        v.as_slice(),
                        v.len(),
                    )
                };
                cp.zeroize();
                if r != 0 {
                    return err_rv!(CKR_ATTRIBUTE_VALUE_INVALID);
                }
            }
            None => {
                obj.set_attr(attribute::from_bytes(CKA_PRIME_1, cp))?;
            }
        }

        match q {
            Some(v) => {
                let r = if v.len() >= cq.len() {
                    util::scs_cmp(
                        v.as_slice(),
                        v.len(),
                        cq.as_slice(),
                        cq.len(),
                    )
                } else {
                    util::scs_cmp(
                        cq.as_slice(),
                        cq.len(),
                        v.as_slice(),
                        v.len(),
                    )
                };
                cq.zeroize();
                if r != 0 {
                    return err_rv!(CKR_ATTRIBUTE_VALUE_INVALID);
                }
            }
            None => {
                obj.set_attr(attribute::from_bytes(CKA_PRIME_2, cq))?;
            }
        }

        match a {
            Some(v) => {
                let r = if v.len() >= ca.len() {
                    util::scs_cmp(
                        v.as_slice(),
                        v.len(),
                        ca.as_slice(),
                        ca.len(),
                    )
                } else {
                    util::scs_cmp(
                        ca.as_slice(),
                        ca.len(),
                        v.as_slice(),
                        v.len(),
                    )
                };
                ca.zeroize();
                if r != 0 {
                    return err_rv!(CKR_ATTRIBUTE_VALUE_INVALID);
                }
            }
            None => {
                obj.set_attr(attribute::from_bytes(CKA_EXPONENT_1, ca))?;
            }
        }

        match b {
            Some(v) => {
                let r = if v.len() >= cb.len() {
                    util::scs_cmp(
                        v.as_slice(),
                        v.len(),
                        cb.as_slice(),
                        cb.len(),
                    )
                } else {
                    util::scs_cmp(
                        cb.as_slice(),
                        cb.len(),
                        v.as_slice(),
                        v.len(),
                    )
                };
                cb.zeroize();
                if r != 0 {
                    return err_rv!(CKR_ATTRIBUTE_VALUE_INVALID);
                }
            }
            None => {
                obj.set_attr(attribute::from_bytes(CKA_EXPONENT_2, cb))?;
            }
        }

        match c {
            Some(v) => {
                let r = if v.len() >= cc.len() {
                    util::scs_cmp(
                        v.as_slice(),
                        v.len(),
                        cc.as_slice(),
                        cc.len(),
                    )
                } else {
                    util::scs_cmp(
                        cc.as_slice(),
                        cc.len(),
                        v.as_slice(),
                        v.len(),
                    )
                };
                cc.zeroize();
                if r != 0 {
                    return err_rv!(CKR_ATTRIBUTE_VALUE_INVALID);
                }
            }
            None => {
                obj.set_attr(attribute::from_bytes(CKA_COEFFICIENT, cc))?;
            }
        }
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
                CKM_SHA1_RSA_PKCS => Operation::Digest(Box::new(
                    hash::HashOperation::new(CKM_SHA_1)?,
                )),
                CKM_SHA256_RSA_PKCS => Operation::Digest(Box::new(
                    hash::HashOperation::new(CKM_SHA256)?,
                )),
                CKM_SHA384_RSA_PKCS => Operation::Digest(Box::new(
                    hash::HashOperation::new(CKM_SHA384)?,
                )),
                CKM_SHA512_RSA_PKCS => Operation::Digest(Box::new(
                    hash::HashOperation::new(CKM_SHA512)?,
                )),
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
                CKM_SHA1_RSA_PKCS => Operation::Digest(Box::new(
                    hash::HashOperation::new(CKM_SHA_1)?,
                )),
                CKM_SHA256_RSA_PKCS => Operation::Digest(Box::new(
                    hash::HashOperation::new(CKM_SHA256)?,
                )),
                CKM_SHA384_RSA_PKCS => Operation::Digest(Box::new(
                    hash::HashOperation::new(CKM_SHA384)?,
                )),
                CKM_SHA512_RSA_PKCS => Operation::Digest(Box::new(
                    hash::HashOperation::new(CKM_SHA512)?,
                )),
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
            CKM_SHA224_RSA_PKCS => {
                #[rustfmt::skip]
                let mut emsa: Vec<u8> = vec![
                    0x30, 49,
                      0x30, 13,
                        0x06, 9,
                          0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04,
                        0x05, 0,
                      0x04, 28,
                ];
                *digest_idx = emsa.len();
                emsa.extend([0; 28]);
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
            CKM_SHA3_224_RSA_PKCS => {
                #[rustfmt::skip]
                let mut emsa: Vec<u8> = vec![
                    0x30, 49,
                      0x30, 13,
                        0x06, 9,
                          0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x07,
                        0x05, 0,
                      0x04, 28,
                ];
                *digest_idx = emsa.len();
                emsa.extend([0; 28]);
                Ok(emsa)
            }
            CKM_SHA3_256_RSA_PKCS => {
                #[rustfmt::skip]
                let mut emsa: Vec<u8> = vec![
                    0x30, 49,
                      0x30, 13,
                        0x06, 9,
                          0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x08,
                        0x05, 0,
                      0x04, 32,
                ];
                *digest_idx = emsa.len();
                emsa.extend([0; 32]);
                Ok(emsa)
            }
            CKM_SHA3_384_RSA_PKCS => {
                #[rustfmt::skip]
                let mut emsa: Vec<u8> = vec![
                    0x30, 65,
                      0x30, 13,
                        0x06, 9,
                          0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x09,
                        0x05, 0,
                      0x04, 48,
                ];
                *digest_idx = emsa.len();
                emsa.extend([0; 48]);
                Ok(emsa)
            }
            CKM_SHA3_512_RSA_PKCS => {
                #[rustfmt::skip]
                let mut emsa: Vec<u8> = vec![
                    0x30, 81,
                      0x30, 13,
                        0x06, 9,
                          0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0a,
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
        let mut c: mpz_wrapper = mpz_wrapper::new();

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
        let mut c: mpz_wrapper = mpz_wrapper::new();
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
        let mut s: mpz_wrapper = mpz_wrapper::new();

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
        let mut s: mpz_wrapper = mpz_wrapper::new();
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

    fn generate_keypair(
        rng: &mut rng::RNG,
        exponent: Vec<u8>,
        bits: usize,
        pubkey: &mut Object,
        privkey: &mut Object,
    ) -> KResult<()> {
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

        let n = mpz_to_vec!(pubk.n[0]);
        pubkey.set_attr(attribute::from_bytes(CKA_MODULUS, n.clone()))?;

        privkey.set_attr(attribute::from_bytes(CKA_MODULUS, n))?;
        let e = mpz_to_vec!(pubk.e[0]);
        privkey.set_attr(attribute::from_bytes(CKA_PUBLIC_EXPONENT, e))?;
        let d = mpz_to_vec!(prik.d[0]);
        privkey.set_attr(attribute::from_bytes(CKA_PRIVATE_EXPONENT, d))?;
        let p = mpz_to_vec!(prik.d[0]);
        privkey.set_attr(attribute::from_bytes(CKA_PRIME_1, p))?;
        let q = mpz_to_vec!(prik.d[0]);
        privkey.set_attr(attribute::from_bytes(CKA_PRIME_2, q))?;
        let a = mpz_to_vec!(prik.d[0]);
        privkey.set_attr(attribute::from_bytes(CKA_EXPONENT_1, a))?;
        let b = mpz_to_vec!(prik.d[0]);
        privkey.set_attr(attribute::from_bytes(CKA_EXPONENT_2, b))?;
        let c = mpz_to_vec!(prik.d[0]);
        privkey.set_attr(attribute::from_bytes(CKA_COEFFICIENT, c))?;

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
            CKM_SHA224_RSA_PKCS => (),
            CKM_SHA256_RSA_PKCS => (),
            CKM_SHA384_RSA_PKCS => (),
            CKM_SHA512_RSA_PKCS => (),
            CKM_SHA3_224_RSA_PKCS => (),
            CKM_SHA3_256_RSA_PKCS => (),
            CKM_SHA3_384_RSA_PKCS => (),
            CKM_SHA3_512_RSA_PKCS => (),
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
            CKM_SHA224_RSA_PKCS => (),
            CKM_SHA256_RSA_PKCS => (),
            CKM_SHA384_RSA_PKCS => (),
            CKM_SHA512_RSA_PKCS => (),
            CKM_SHA3_224_RSA_PKCS => (),
            CKM_SHA3_256_RSA_PKCS => (),
            CKM_SHA3_384_RSA_PKCS => (),
            CKM_SHA3_512_RSA_PKCS => (),
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
