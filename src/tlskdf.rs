// Copyright 2024 Simo Sorce
// See LICENSE.txt file for terms

use super::err_rv;
use super::error;
use super::hmac;
use super::interface;
use super::mechanism;
use super::misc;
use super::object;

use error::{KError, KResult};
use interface::*;
use mechanism::*;
use object::{Object, ObjectFactories};

use super::bytes_to_vec;

use std::fmt::Debug;

pub fn register(mechs: &mut Mechanisms, _: &mut ObjectFactories) {
    TLSKDFMechanism::register_mechanisms(mechs);
}

const TLS_MASTER_SECRET_SIZE: CK_ULONG = 48;
const TLS_RANDOM_SEED_SIZE: usize = 32;
const TLS_MASTER_SECRET_ALLOWED_MECHS: [CK_ULONG; 4] = [
    CKM_TLS12_KEY_AND_MAC_DERIVE,
    CKM_TLS12_KEY_SAFE_DERIVE,
    CKM_TLS12_KDF,
    CKM_TLS12_MAC,
];
const TLS_MASTER_SECRET_LABEL: &[u8; 13] = b"master secret";

fn tlsprf(
    key: &Object,
    mech: &Box<dyn Mechanism>,
    prf: CK_MECHANISM_TYPE,
    seed: &Vec<u8>,
    reqlen: usize,
) -> KResult<Vec<u8>> {
    let mechanism = CK_MECHANISM {
        mechanism: prf,
        pParameter: std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    let mut op = mech.mac_new(&mechanism, key, CKF_DERIVE)?;
    let maclen = op.mac_len()?;

    let mut ax = vec![0u8; maclen];
    op.mac_update(seed.as_slice())?;
    op.mac_final(ax.as_mut_slice())?;
    /* ax = A(1) */

    /* use a buffer length that is a multiple of maclen,
     * then truncate to actual reqlen before returning */
    let mut out = vec![0u8; ((reqlen + maclen - 1) / maclen) * maclen];
    let mut outlen = 0;
    while outlen < reqlen {
        let mut op = mech.mac_new(&mechanism, key, CKF_DERIVE)?;
        op.mac_update(ax.as_slice())?;
        op.mac_update(seed.as_slice())?;
        op.mac_final(&mut out[outlen..(outlen + maclen)])?;

        outlen += maclen;

        if outlen < reqlen {
            /* ax = A(x + 1) */
            let mut op = mech.mac_new(&mechanism, key, CKF_DERIVE)?;
            op.mac_update(ax.as_slice())?;
            op.mac_final(ax.as_mut_slice())?;
        }
    }
    out.resize(reqlen, 0);
    Ok(out)
}

#[cfg(test)]
pub fn test_tlsprf(
    key: &Object,
    mech: &Box<dyn Mechanism>,
    prf: CK_MECHANISM_TYPE,
    seed: &Vec<u8>,
    reqlen: usize,
) -> KResult<Vec<u8>> {
    tlsprf(key, mech, prf, seed, reqlen)
}

#[derive(Debug)]
struct TLSKDFMechanism {
    info: CK_MECHANISM_INFO,
}

impl TLSKDFMechanism {
    fn register_mechanisms(mechs: &mut Mechanisms) {
        mechs.add_mechanism(
            CKM_TLS12_MASTER_KEY_DERIVE,
            Box::new(TLSKDFMechanism {
                info: CK_MECHANISM_INFO {
                    ulMinKeySize: TLS_MASTER_SECRET_SIZE,
                    ulMaxKeySize: TLS_MASTER_SECRET_SIZE,
                    flags: CKF_DERIVE,
                },
            }),
        );
    }
}

impl Mechanism for TLSKDFMechanism {
    fn info(&self) -> &CK_MECHANISM_INFO {
        &self.info
    }

    fn derive_operation(&self, mech: &CK_MECHANISM) -> KResult<Operation> {
        if self.info.flags & CKF_DERIVE != CKF_DERIVE {
            return err_rv!(CKR_MECHANISM_INVALID);
        }

        match mech.mechanism {
            CKM_TLS12_MASTER_KEY_DERIVE => {
                Ok(Operation::Derive(Box::new(TLSKDFOperation::new(mech)?)))
            }
            _ => err_rv!(CKR_MECHANISM_INVALID),
        }
    }
}

#[derive(Debug)]
struct TLSKDFOperation {
    finalized: bool,
    client_random: Vec<u8>,
    server_random: Vec<u8>,
    version: *mut CK_VERSION,
    prf: CK_MECHANISM_TYPE,
}

unsafe impl Send for TLSKDFOperation {}
unsafe impl Sync for TLSKDFOperation {}

impl TLSKDFOperation {
    fn new(mech: &CK_MECHANISM) -> KResult<TLSKDFOperation> {
        if mech.mechanism != CKM_TLS12_MASTER_KEY_DERIVE {
            return err_rv!(CKR_MECHANISM_INVALID);
        }
        if mech.ulParameterLen as usize
            != ::std::mem::size_of::<CK_TLS12_MASTER_KEY_DERIVE_PARAMS>()
        {
            return err_rv!(CKR_ARGUMENTS_BAD);
        }
        let params = unsafe {
            *(mech.pParameter as *const CK_TLS12_MASTER_KEY_DERIVE_PARAMS)
        };

        let clirand = bytes_to_vec!(
            params.RandomInfo.pClientRandom,
            params.RandomInfo.ulClientRandomLen
        );
        let srvrand = bytes_to_vec!(
            params.RandomInfo.pServerRandom,
            params.RandomInfo.ulServerRandomLen
        );

        if clirand.len() != TLS_RANDOM_SEED_SIZE
            || srvrand.len() != TLS_RANDOM_SEED_SIZE
        {
            return err_rv!(CKR_MECHANISM_PARAM_INVALID);
        }

        let prf = match hmac::hash_to_hmac_mech(params.prfHashMechanism) {
            Ok(h) => h,
            Err(_) => return err_rv!(CKR_MECHANISM_PARAM_INVALID),
        };

        Ok(TLSKDFOperation {
            finalized: false,
            client_random: clirand,
            server_random: srvrand,
            version: params.pVersion,
            prf: prf,
        })
    }

    fn verify_key(key: &Object) -> KResult<()> {
        key.check_key_ops(CKO_SECRET_KEY, CKK_GENERIC_SECRET, CKA_DERIVE)?;
        match key.get_attr(CKA_VALUE_LEN) {
            Some(a) => match a.to_ulong() {
                Ok(l) => {
                    if l != TLS_MASTER_SECRET_SIZE {
                        return err_rv!(CKR_KEY_FUNCTION_NOT_PERMITTED);
                    }
                    Ok(())
                }
                Err(_) => return err_rv!(CKR_KEY_FUNCTION_NOT_PERMITTED),
            },
            None => return err_rv!(CKR_GENERAL_ERROR),
        }
    }

    fn verify_template(
        template: &[CK_ATTRIBUTE],
    ) -> KResult<Vec<interface::CK_ATTRIBUTE>> {
        /* augment template, then check that it has all the right values */
        let allowed = unsafe {
            std::mem::transmute::<&[CK_ULONG; 4], &[u8; 4 * misc::CK_ULONG_SIZE]>(
                &TLS_MASTER_SECRET_ALLOWED_MECHS,
            )
        };
        let tmpl = misc::fixup_template(
            template,
            &[
                CK_ATTRIBUTE::from_ulong(CKA_CLASS, &CKO_SECRET_KEY),
                CK_ATTRIBUTE::from_ulong(CKA_KEY_TYPE, &CKK_GENERIC_SECRET),
                CK_ATTRIBUTE::from_ulong(
                    CKA_VALUE_LEN,
                    &TLS_MASTER_SECRET_SIZE,
                ),
                CK_ATTRIBUTE::from_slice(CKA_ALLOWED_MECHANISMS, allowed),
            ],
        );
        for attr in &tmpl {
            match attr.type_ {
                CKA_CLASS => {
                    let val = attr.to_ulong()?;
                    if val != CKO_SECRET_KEY {
                        return err_rv!(CKR_ATTRIBUTE_VALUE_INVALID);
                    }
                }
                CKA_KEY_TYPE => {
                    let val = attr.to_ulong()?;
                    if val != CKK_GENERIC_SECRET {
                        return err_rv!(CKR_ATTRIBUTE_VALUE_INVALID);
                    }
                }
                CKA_VALUE_LEN => {
                    let val = attr.to_ulong()?;
                    if val != TLS_MASTER_SECRET_SIZE {
                        return err_rv!(CKR_ATTRIBUTE_VALUE_INVALID);
                    }
                }
                CKA_ALLOWED_MECHANISMS => {
                    let val = attr.to_slice()?;
                    if val != allowed {
                        return err_rv!(CKR_ATTRIBUTE_VALUE_INVALID);
                    }
                }
                _ => (),
            }
        }
        Ok(tmpl)
    }

    fn tls_master_secret_seed(&self) -> Vec<u8> {
        let mut seed = Vec::<u8>::with_capacity(
            TLS_MASTER_SECRET_LABEL.len()
                + self.client_random.len()
                + self.server_random.len(),
        );
        seed.extend_from_slice(TLS_MASTER_SECRET_LABEL);
        seed.extend_from_slice(self.client_random.as_slice());
        seed.extend_from_slice(self.server_random.as_slice());
        seed
    }
}

impl MechOperation for TLSKDFOperation {
    fn finalized(&self) -> bool {
        self.finalized
    }
}

impl Derive for TLSKDFOperation {
    fn derive(
        &mut self,
        key: &Object,
        template: &[CK_ATTRIBUTE],
        mechanisms: &Mechanisms,
        objfactories: &ObjectFactories,
    ) -> KResult<(Object, usize)> {
        if self.finalized {
            return err_rv!(CKR_OPERATION_NOT_INITIALIZED);
        }
        self.finalized = true;

        Self::verify_key(key)?;
        let tmpl = Self::verify_template(template)?;
        let factory =
            objfactories.get_obj_factory_from_key_template(tmpl.as_slice())?;
        let mut dkey = factory.default_object_derive(tmpl.as_slice(), key)?;

        let mech = mechanisms.get(self.prf)?;
        let seed = self.tls_master_secret_seed();
        let dkmlen = TLS_MASTER_SECRET_SIZE as usize;
        let dkm = tlsprf(key, mech, self.prf, &seed, dkmlen)?;

        factory.as_secret_key_factory()?.set_key(&mut dkey, dkm)?;

        /* fill in the version if all went well */
        if !self.version.is_null() {
            let mut maj: CK_BYTE = 0xff;
            let mut min: CK_BYTE = 0xff;
            /* not not leak bytes for long term keys, openssl really only
             * uses ephemeral session keys, so there is no business in
             * returning bytes from a long term stored token key */
            if !key.is_token() {
                let secret = match key.get_attr(CKA_VALUE) {
                    None => return err_rv!(CKR_GENERAL_ERROR),
                    Some(val) => val.to_bytes()?,
                };
                maj = secret[0];
                min = secret[1];
            }
            unsafe {
                (*self.version).major = maj;
                (*self.version).minor = min;
            }
        }

        Ok((dkey, 0))
    }
}
