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

use super::{bytes_to_vec, cast_params};

use std::fmt::Debug;

macro_rules! as_ck_bbool {
    ($key:expr, $attr:expr) => {
        match $key.get_attr_as_bool($attr) {
            Ok(v) => {
                if v {
                    CK_TRUE
                } else {
                    CK_FALSE
                }
            }
            Err(_) => return err_rv!(CKR_GENERAL_ERROR),
        }
    };
}

macro_rules! check_as_ck_bbool {
    ($attr:expr, $value:expr) => {
        match $attr.to_bool()? {
            true => {
                if $value != CK_TRUE {
                    return err_rv!(CKR_ATTRIBUTE_VALUE_INVALID);
                }
            }
            false => {
                if $value != CK_FALSE {
                    return err_rv!(CKR_ATTRIBUTE_VALUE_INVALID);
                }
            }
        }
    };
}

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
const TLS_KEY_EXPANSION_LABEL: &[u8; 13] = b"key expansion";

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
        mechs.add_mechanism(
            CKM_TLS12_KEY_AND_MAC_DERIVE,
            Box::new(TLSKDFMechanism {
                info: CK_MECHANISM_INFO {
                    ulMinKeySize: 0,
                    ulMaxKeySize: u32::MAX as CK_ULONG,
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
            CKM_TLS12_MASTER_KEY_DERIVE | CKM_TLS12_KEY_AND_MAC_DERIVE => {
                Ok(Operation::Derive(Box::new(TLSKDFOperation::new(mech)?)))
            }
            _ => err_rv!(CKR_MECHANISM_INVALID),
        }
    }
}

#[derive(Debug)]
struct TLSKDFOperation {
    finalized: bool,
    mech: CK_MECHANISM_TYPE,
    client_random: Vec<u8>,
    server_random: Vec<u8>,
    version: Option<*mut CK_VERSION>,
    prf: CK_MECHANISM_TYPE,
    maclen: CK_ULONG,
    keylen: CK_ULONG,
    ivlen: CK_ULONG,
    mat_out: Option<*mut CK_SSL3_KEY_MAT_OUT>,
}

unsafe impl Send for TLSKDFOperation {}
unsafe impl Sync for TLSKDFOperation {}

impl TLSKDFOperation {
    fn new(mech: &CK_MECHANISM) -> KResult<TLSKDFOperation> {
        match mech.mechanism {
            CKM_TLS12_MASTER_KEY_DERIVE => Self::new_tls12_mk_derive(mech),
            CKM_TLS12_KEY_AND_MAC_DERIVE => Self::new_tls12_keymac_derive(mech),
            _ => return err_rv!(CKR_MECHANISM_INVALID),
        }
    }

    fn new_tls12_mk_derive(mech: &CK_MECHANISM) -> KResult<TLSKDFOperation> {
        let params = cast_params!(mech, CK_TLS12_MASTER_KEY_DERIVE_PARAMS);

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

        let version = if params.pVersion.is_null() {
            None
        } else {
            Some(params.pVersion)
        };

        Ok(TLSKDFOperation {
            finalized: false,
            mech: mech.mechanism,
            client_random: clirand,
            server_random: srvrand,
            version: version,
            prf: prf,
            maclen: 0,
            keylen: 0,
            ivlen: 0,
            mat_out: None,
        })
    }

    fn new_tls12_keymac_derive(
        mech: &CK_MECHANISM,
    ) -> KResult<TLSKDFOperation> {
        let params = cast_params!(mech, CK_TLS12_KEY_MAT_PARAMS);

        let maclen = params.ulMacSizeInBits / 8;
        let keylen = params.ulKeySizeInBits / 8;
        let ivlen = params.ulIVSizeInBits / 8;

        if params.bIsExport != CK_FALSE {
            return err_rv!(CKR_MECHANISM_PARAM_INVALID);
        }

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

        if params.pReturnedKeyMaterial.is_null() {
            return err_rv!(CKR_MECHANISM_PARAM_INVALID);
        }

        Ok(TLSKDFOperation {
            finalized: false,
            mech: mech.mechanism,
            client_random: clirand,
            server_random: srvrand,
            version: None,
            prf: prf,
            maclen: maclen,
            keylen: if keylen > 0 {
                keylen
            } else {
                TLS_MASTER_SECRET_SIZE
            },
            ivlen: ivlen,
            mat_out: Some(params.pReturnedKeyMaterial),
        })
    }

    fn verify_key(&self, key: &Object) -> KResult<()> {
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

    fn verify_mk_template(
        &self,
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
                CK_ATTRIBUTE::from_bool(CKA_SIGN, &CK_TRUE),
                CK_ATTRIBUTE::from_bool(CKA_VERIFY, &CK_TRUE),
                CK_ATTRIBUTE::from_bool(CKA_DERIVE, &CK_TRUE),
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

    fn derive_master_key(
        &mut self,
        key: &Object,
        template: &[CK_ATTRIBUTE],
        mechanisms: &Mechanisms,
        objfactories: &ObjectFactories,
    ) -> KResult<Vec<Object>> {
        self.verify_key(key)?;
        let tmpl = self.verify_mk_template(template)?;
        let factory =
            objfactories.get_obj_factory_from_key_template(tmpl.as_slice())?;
        let mut dkey = factory.default_object_derive(tmpl.as_slice(), key)?;

        let mech = mechanisms.get(self.prf)?;
        let seed = self.tls_master_secret_seed();
        let dkmlen = TLS_MASTER_SECRET_SIZE as usize;
        let dkm = tlsprf(key, mech, self.prf, &seed, dkmlen)?;

        factory.as_secret_key_factory()?.set_key(&mut dkey, dkm)?;

        /* fill in the version if all went well */
        if let Some(version) = self.version {
            let mut maj: CK_BYTE = 0xff;
            let mut min: CK_BYTE = 0xff;
            /* do not leak bytes for long term keys, openssl really only
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
                (*version).major = maj;
                (*version).minor = min;
            }
        }

        Ok(vec![dkey])
    }

    fn verify_key_expansion_template(
        &self,
        key: &Object,
        template: &[CK_ATTRIBUTE],
    ) -> KResult<Vec<interface::CK_ATTRIBUTE>> {
        /* augment template, then check that it has all the right values */
        let is_sensitive = as_ck_bbool!(key, CKA_SENSITIVE);
        let is_extractable = as_ck_bbool!(key, CKA_EXTRACTABLE);
        let tmpl = misc::fixup_template(
            template,
            &[
                CK_ATTRIBUTE::from_ulong(CKA_CLASS, &CKO_SECRET_KEY),
                CK_ATTRIBUTE::from_ulong(CKA_KEY_TYPE, &CKK_GENERIC_SECRET),
                CK_ATTRIBUTE::from_ulong(CKA_VALUE_LEN, &self.keylen),
                CK_ATTRIBUTE::from_bool(CKA_ENCRYPT, &CK_TRUE),
                CK_ATTRIBUTE::from_bool(CKA_DECRYPT, &CK_TRUE),
                CK_ATTRIBUTE::from_bool(CKA_DERIVE, &CK_TRUE),
                CK_ATTRIBUTE::from_bool(CKA_SENSITIVE, &is_sensitive),
                CK_ATTRIBUTE::from_bool(CKA_EXTRACTABLE, &is_extractable),
            ],
        );
        for attr in &tmpl {
            match attr.type_ {
                CKA_VALUE_LEN => {
                    let val = attr.to_ulong()?;
                    if val != self.keylen {
                        return err_rv!(CKR_ATTRIBUTE_VALUE_INVALID);
                    }
                }
                CKA_SENSITIVE => check_as_ck_bbool!(attr, is_sensitive),
                CKA_EXTRACTABLE => check_as_ck_bbool!(attr, is_extractable),
                _ => (),
            }
        }
        Ok(tmpl)
    }

    fn tls_key_expansion_seed(&self) -> Vec<u8> {
        let mut seed = Vec::<u8>::with_capacity(
            TLS_KEY_EXPANSION_LABEL.len()
                + self.client_random.len()
                + self.server_random.len(),
        );
        seed.extend_from_slice(TLS_KEY_EXPANSION_LABEL);
        seed.extend_from_slice(self.server_random.as_slice());
        seed.extend_from_slice(self.client_random.as_slice());
        seed
    }

    fn derive_mac_key(
        &mut self,
        key: &Object,
        template: &[CK_ATTRIBUTE],
        mechanisms: &Mechanisms,
        objfactories: &ObjectFactories,
    ) -> KResult<Vec<Object>> {
        self.verify_key(key)?;
        let key_tmpl = self.verify_key_expansion_template(key, template)?;

        let mech = mechanisms.get(self.prf)?;
        let seed = self.tls_key_expansion_seed();
        let dkmlen = (2 * (self.maclen + self.keylen + self.ivlen)) as usize;
        let dkm = tlsprf(key, mech, self.prf, &seed, dkmlen)?;

        let mut keys = Vec::<Object>::with_capacity(4);
        let mut i = 0;

        if self.maclen > 0 {
            let maclen = self.maclen as usize;
            let is_sensitive = as_ck_bbool!(key, CKA_SENSITIVE);
            let is_extractable = as_ck_bbool!(key, CKA_EXTRACTABLE);
            let mac_tmpl = [
                CK_ATTRIBUTE::from_ulong(CKA_CLASS, &CKO_SECRET_KEY),
                CK_ATTRIBUTE::from_ulong(CKA_KEY_TYPE, &CKK_GENERIC_SECRET),
                CK_ATTRIBUTE::from_bool(CKA_SIGN, &CK_TRUE),
                CK_ATTRIBUTE::from_bool(CKA_VERIFY, &CK_TRUE),
                CK_ATTRIBUTE::from_bool(CKA_SENSITIVE, &is_sensitive),
                CK_ATTRIBUTE::from_bool(CKA_EXTRACTABLE, &is_extractable),
            ];

            let factory =
                objfactories.get_obj_factory_from_key_template(&mac_tmpl)?;
            let mut climac = factory.default_object_derive(&mac_tmpl, key)?;
            factory
                .as_secret_key_factory()?
                .set_key(&mut climac, dkm[i..(i + maclen)].to_vec())?;

            i += maclen;
            keys.push(climac);
            let mut srvmac = factory.default_object_derive(&mac_tmpl, key)?;
            factory
                .as_secret_key_factory()?
                .set_key(&mut srvmac, dkm[i..(i + maclen)].to_vec())?;
            i += maclen;
            keys.push(srvmac);
        }

        if self.keylen > 0 {
            let keylen = self.keylen as usize;
            let factory = objfactories
                .get_obj_factory_from_key_template(key_tmpl.as_slice())?;
            let mut clikey =
                factory.default_object_derive(key_tmpl.as_slice(), key)?;
            factory
                .as_secret_key_factory()?
                .set_key(&mut clikey, dkm[i..(i + keylen)].to_vec())?;

            i += keylen;
            keys.push(clikey);
            let mut srvkey =
                factory.default_object_derive(key_tmpl.as_slice(), key)?;
            factory
                .as_secret_key_factory()?
                .set_key(&mut srvkey, dkm[i..(i + keylen)].to_vec())?;
            i += keylen;
            keys.push(srvkey);
        }

        if self.ivlen > 0 {
            let ivlen = self.ivlen as usize;
            let mat_out = match self.mat_out {
                Some(mo) => mo,
                None => return err_rv!(CKR_GENERAL_ERROR),
            };
            let cliiv = unsafe {
                core::slice::from_raw_parts_mut((*mat_out).pIVClient, ivlen)
            };
            cliiv.copy_from_slice(&dkm[i..(i + ivlen)]);
            i += ivlen;
            let srviv = unsafe {
                core::slice::from_raw_parts_mut((*mat_out).pIVServer, ivlen)
            };
            srviv.copy_from_slice(&dkm[i..(i + ivlen)]);
        }

        Ok(keys)
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
    ) -> KResult<Vec<Object>> {
        if self.finalized {
            return err_rv!(CKR_OPERATION_NOT_INITIALIZED);
        }
        self.finalized = true;

        match self.mech {
            CKM_TLS12_MASTER_KEY_DERIVE => {
                self.derive_master_key(key, template, mechanisms, objfactories)
            }
            CKM_TLS12_KEY_AND_MAC_DERIVE => {
                self.derive_mac_key(key, template, mechanisms, objfactories)
            }
            _ => err_rv!(CKR_MECHANISM_INVALID),
        }
    }
}
