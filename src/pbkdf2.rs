// Copyright 2024 Simo Sorce
// See LICENSE.txt file for terms

use super::attribute;
use super::error;
use super::hmac;
use super::interface;
use super::mechanism;
use super::object;
use super::{cast_params, err_rv};

use attribute::{from_bool, from_bytes, from_ulong, CkAttrs};
use error::Result;
use interface::*;
use mechanism::*;
use object::{Object, ObjectFactories};

use super::bytes_to_vec;

use std::fmt::Debug;

#[cfg(not(feature = "fips"))]
use std::mem::swap;

pub fn register(mechs: &mut Mechanisms, _: &mut ObjectFactories) {
    PBKDF2Mechanism::register_mechanisms(mechs);
}

#[derive(Debug)]
struct PBKDF2Mechanism {
    info: CK_MECHANISM_INFO,
}

impl PBKDF2Mechanism {
    fn register_mechanisms(mechs: &mut Mechanisms) {
        mechs.add_mechanism(
            CKM_PKCS5_PBKD2,
            Box::new(PBKDF2Mechanism {
                info: CK_MECHANISM_INFO {
                    ulMinKeySize: 0,
                    ulMaxKeySize: CK_ULONG::try_from(u32::MAX).unwrap(),
                    flags: CKF_GENERATE,
                },
            }),
        );
    }

    fn mock_password_object(&self, key: Vec<u8>) -> Result<Object> {
        let mut obj = Object::new();
        obj.set_zeroize();
        obj.set_attr(from_ulong(CKA_CLASS, CKO_SECRET_KEY))?;
        obj.set_attr(from_ulong(CKA_KEY_TYPE, CKK_GENERIC_SECRET))?;
        obj.set_attr(from_ulong(
            CKA_VALUE_LEN,
            CK_ULONG::try_from(key.len())?,
        ))?;
        obj.set_attr(from_bytes(CKA_VALUE, key))?;
        obj.set_attr(from_bool(CKA_DERIVE, true))?;
        Ok(obj)
    }
}

impl Mechanism for PBKDF2Mechanism {
    fn info(&self) -> &CK_MECHANISM_INFO {
        &self.info
    }

    fn generate_key(
        &self,
        mech: &CK_MECHANISM,
        template: &[CK_ATTRIBUTE],
        mechanisms: &Mechanisms,
        objfactories: &ObjectFactories,
    ) -> Result<Object> {
        if self.info.flags & CKF_GENERATE != CKF_GENERATE {
            return err_rv!(CKR_MECHANISM_INVALID);
        }
        if mech.mechanism != CKM_PKCS5_PBKD2 {
            return err_rv!(CKR_MECHANISM_INVALID);
        }

        let params = cast_params!(mech, CK_PKCS5_PBKD2_PARAMS2);

        /* all the mechanism we support require this,
         * if we ever add GOST support we'll have to add data */
        if params.pPrfData != std::ptr::null_mut() || params.ulPrfDataLen != 0 {
            return err_rv!(CKR_MECHANISM_PARAM_INVALID);
        }

        let pbkdf2 = PBKDF2 {
            prf: match params.prf {
                CKP_PKCS5_PBKD2_HMAC_SHA1 => CKM_SHA_1_HMAC,
                CKP_PKCS5_PBKD2_HMAC_SHA224 => CKM_SHA224_HMAC,
                CKP_PKCS5_PBKD2_HMAC_SHA256 => CKM_SHA256_HMAC,
                CKP_PKCS5_PBKD2_HMAC_SHA384 => CKM_SHA384_HMAC,
                CKP_PKCS5_PBKD2_HMAC_SHA512 => CKM_SHA512_HMAC,
                _ => return err_rv!(CKR_MECHANISM_PARAM_INVALID),
            },
            pass: self.mock_password_object(bytes_to_vec!(
                params.pPassword,
                params.ulPasswordLen
            ))?,
            salt: match params.saltSource {
                CKZ_SALT_SPECIFIED => {
                    if params.pSaltSourceData == std::ptr::null_mut()
                        || params.ulSaltSourceDataLen == 0
                    {
                        return err_rv!(CKR_MECHANISM_PARAM_INVALID);
                    }
                    bytes_to_vec!(
                        params.pSaltSourceData,
                        params.ulSaltSourceDataLen
                    )
                }
                _ => return err_rv!(CKR_MECHANISM_PARAM_INVALID),
            },
            iter: usize::try_from(params.iterations)?,
        };

        /* check early that we have key class and type defined */
        let factory =
            objfactories.get_obj_factory_from_key_template(template)?;

        let keylen = match template.iter().find(|x| x.type_ == CKA_VALUE_LEN) {
            Some(a) => usize::try_from(a.to_ulong()?)?,
            None => {
                let max = hmac::hmac_size(pbkdf2.prf);
                if max == usize::try_from(CK_UNAVAILABLE_INFORMATION)? {
                    return err_rv!(CKR_MECHANISM_INVALID);
                }
                match factory.as_secret_key_factory()?.recommend_key_size(max) {
                    Ok(len) => len,
                    Err(_) => return err_rv!(CKR_TEMPLATE_INCONSISTENT),
                }
            }
        };

        let dkm = pbkdf2.derive(mechanisms, keylen)?;

        let mut tmpl = CkAttrs::from(template);
        tmpl.add_vec(CKA_VALUE, dkm)?;
        tmpl.zeroize = true;

        let mut key = factory.create(tmpl.as_slice())?;
        object::default_key_attributes(&mut key, mech.mechanism)?;
        Ok(key)
    }
}

/* PKCS#11 in their infinite wisdom decided to implement this
 * derivation as a mechanism key gen operation.
 * Key Gen in Kryoptic does not go through an Operation trait,
 * but we still want to be able to do both openssl and native
 * backends, so we encapsulate the derivation function in a
 * small structure and make implementations of the object in
 * the relevant files for FIPS/non-FIPS */

#[derive(Debug)]
struct PBKDF2 {
    prf: CK_MECHANISM_TYPE,
    pass: Object,
    salt: Vec<u8>,
    iter: usize,
}

#[cfg(feature = "fips")]
include!("ossl/pbkdf2.rs");

/* https://www.rfc-editor.org/rfc/rfc8018#section-5.2 */
#[cfg(not(feature = "fips"))]
impl PBKDF2 {
    fn prf_fn(
        &self,
        mech: &Box<dyn Mechanism>,
        i: &[u8],
        o: &mut [u8],
    ) -> Result<()> {
        mech.mac_new(
            &CK_MECHANISM {
                mechanism: self.prf,
                pParameter: std::ptr::null_mut(),
                ulParameterLen: 0,
            },
            &self.pass,
            CKF_DERIVE,
        )?
        .mac(i, o)
    }

    fn derive(&self, mechanisms: &Mechanisms, dklen: usize) -> Result<Vec<u8>> {
        let hlen = hmac::hmac_size(self.prf);
        if hlen == usize::try_from(CK_UNAVAILABLE_INFORMATION)? {
            return err_rv!(CKR_MECHANISM_INVALID);
        }

        if dklen > (hlen * usize::try_from(u32::MAX)?) {
            return err_rv!(CKR_KEY_SIZE_RANGE);
        }

        let l = (dklen + hlen - 1) / hlen;

        let mut dkm = vec![0u8; dklen];

        let mech = mechanisms.get(self.prf)?;

        for b in 0..l {
            let i = u32::try_from(b + 1)?;
            let mut t_i = vec![0u8; hlen];
            let mut u_out = vec![0u8; hlen];
            let mut u_in = self.salt.clone();
            u_in.extend_from_slice(&i.to_be_bytes());

            for _ in 0..self.iter {
                self.prf_fn(mech, u_in.as_slice(), u_out.as_mut_slice())?;
                t_i.iter_mut().zip(u_out.iter()).for_each(|(a, b)| *a ^= *b);
                if u_in.len() != u_out.len() {
                    u_in.resize(u_out.len(), 0);
                }
                swap(&mut u_in, &mut u_out);
            }

            let t = b * hlen;
            let mut r = dklen - t;
            if r > hlen {
                r = hlen
            };
            dkm[t..(t + r)].copy_from_slice(&t_i[0..r])
        }

        Ok(dkm)
    }
}
