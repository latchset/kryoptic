// Copyright 2024 Simo Sorce
// See LICENSE.txt file for terms

use super::attribute;
use super::err_rv;
use super::error;
use super::hmac;
use super::interface;
use super::mechanism;
use super::misc;
use super::object;

use attribute::CkAttrs;
use error::Result;
use interface::*;
use mechanism::*;
use object::{Object, ObjectFactories};

use super::{bytes_to_slice, bytes_to_vec, cast_params};

use std::fmt::Debug;

use constant_time_eq::constant_time_eq;
use once_cell::sync::Lazy;

macro_rules! as_ck_bbool {
    ($key:expr, $attr:expr, $def:expr) => {{
        let b = match $key.get_attr_as_bool($attr) {
            Ok(v) => v,
            Err(_) => {
                if let Some(b) = $def {
                    b
                } else {
                    return err_rv!(CKR_GENERAL_ERROR);
                }
            }
        };
        if b {
            CK_TRUE
        } else {
            CK_FALSE
        }
    }};
}

pub fn register(mechs: &mut Mechanisms, _: &mut ObjectFactories) {
    TLSPRFMechanism::register_mechanisms(mechs);
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
const TLS_SERVER_FINISHED: &[u8; 15] = b"server finished";
const TLS_CLIENT_FINISHED: &[u8; 15] = b"client finished";

#[derive(Debug)]
struct TLSPRF {
    op: Box<dyn Mac>,
}

impl TLSPRF {
    fn init(
        key: &Object,
        mech: &Box<dyn Mechanism>,
        prf: CK_MECHANISM_TYPE,
    ) -> Result<TLSPRF> {
        Ok(TLSPRF {
            op: mech.mac_new(
                &CK_MECHANISM {
                    mechanism: prf,
                    pParameter: std::ptr::null_mut(),
                    ulParameterLen: 0,
                },
                key,
                CKF_DERIVE,
            )?,
        })
    }

    fn finish(&mut self, seed: &Vec<u8>, reqlen: usize) -> Result<Vec<u8>> {
        let maclen = self.op.mac_len()?;

        let mut ax = vec![0u8; maclen];
        self.op.mac_update(seed.as_slice())?;
        self.op.mac_final(ax.as_mut_slice())?;
        /* ax = A(1) */

        /* use a buffer length that is a multiple of maclen,
         * then truncate to actual reqlen before returning */
        let mut out = vec![0u8; ((reqlen + maclen - 1) / maclen) * maclen];
        let mut outlen = 0;
        while outlen < reqlen {
            self.op.reset()?;
            self.op.mac_update(ax.as_slice())?;
            self.op.mac_update(seed.as_slice())?;
            self.op.mac_final(&mut out[outlen..(outlen + maclen)])?;

            outlen += maclen;

            if outlen < reqlen {
                /* ax = A(x + 1) */
                self.op.reset()?;
                self.op.mac_update(ax.as_slice())?;
                self.op.mac_final(ax.as_mut_slice())?;
            }
        }
        out.resize(reqlen, 0);
        Ok(out)
    }
}

#[cfg(test)]
pub fn test_tlsprf(
    key: &Object,
    mech: &Box<dyn Mechanism>,
    prf: CK_MECHANISM_TYPE,
    seed: &Vec<u8>,
    reqlen: usize,
) -> Result<Vec<u8>> {
    let mut tlsprf = TLSPRF::init(key, mech, prf)?;
    tlsprf.finish(seed, reqlen)
}

#[derive(Debug)]
struct TLSPRFMechanism {
    info: CK_MECHANISM_INFO,
}

impl TLSPRFMechanism {
    fn register_mechanisms(mechs: &mut Mechanisms) {
        mechs.add_mechanism(
            CKM_TLS12_MASTER_KEY_DERIVE,
            Box::new(TLSPRFMechanism {
                info: CK_MECHANISM_INFO {
                    ulMinKeySize: TLS_MASTER_SECRET_SIZE,
                    ulMaxKeySize: TLS_MASTER_SECRET_SIZE,
                    flags: CKF_DERIVE,
                },
            }),
        );
        mechs.add_mechanism(
            CKM_TLS12_KEY_AND_MAC_DERIVE,
            Box::new(TLSPRFMechanism {
                info: CK_MECHANISM_INFO {
                    ulMinKeySize: 0,
                    ulMaxKeySize: u32::MAX as CK_ULONG,
                    flags: CKF_DERIVE,
                },
            }),
        );
        mechs.add_mechanism(
            CKM_TLS12_KEY_SAFE_DERIVE,
            Box::new(TLSPRFMechanism {
                info: CK_MECHANISM_INFO {
                    ulMinKeySize: 0,
                    ulMaxKeySize: u32::MAX as CK_ULONG,
                    flags: CKF_DERIVE,
                },
            }),
        );
        mechs.add_mechanism(
            CKM_TLS_MAC,
            Box::new(TLSPRFMechanism {
                info: CK_MECHANISM_INFO {
                    ulMinKeySize: 0,
                    ulMaxKeySize: u32::MAX as CK_ULONG,
                    flags: CKF_SIGN | CKF_VERIFY,
                },
            }),
        );
        mechs.add_mechanism(
            CKM_TLS12_MAC,
            Box::new(TLSPRFMechanism {
                info: CK_MECHANISM_INFO {
                    ulMinKeySize: 0,
                    ulMaxKeySize: u32::MAX as CK_ULONG,
                    flags: CKF_SIGN | CKF_VERIFY,
                },
            }),
        );
        mechs.add_mechanism(
            CKM_TLS_KDF,
            Box::new(TLSPRFMechanism {
                info: CK_MECHANISM_INFO {
                    ulMinKeySize: TLS_MASTER_SECRET_SIZE,
                    ulMaxKeySize: TLS_MASTER_SECRET_SIZE,
                    flags: CKF_DERIVE,
                },
            }),
        );
        mechs.add_mechanism(
            CKM_TLS12_KDF,
            Box::new(TLSPRFMechanism {
                info: CK_MECHANISM_INFO {
                    ulMinKeySize: TLS_MASTER_SECRET_SIZE,
                    ulMaxKeySize: TLS_MASTER_SECRET_SIZE,
                    flags: CKF_DERIVE,
                },
            }),
        );
    }
}

impl Mechanism for TLSPRFMechanism {
    fn info(&self) -> &CK_MECHANISM_INFO {
        &self.info
    }

    fn derive_operation(&self, mech: &CK_MECHANISM) -> Result<Operation> {
        if self.info.flags & CKF_DERIVE != CKF_DERIVE {
            return err_rv!(CKR_MECHANISM_INVALID);
        }

        match mech.mechanism {
            CKM_TLS12_MASTER_KEY_DERIVE
            | CKM_TLS12_KEY_AND_MAC_DERIVE
            | CKM_TLS12_KEY_SAFE_DERIVE
            | CKM_TLS12_KDF
            | CKM_TLS_KDF => {
                Ok(Operation::Derive(Box::new(TLSKDFOperation::new(mech)?)))
            }
            _ => err_rv!(CKR_MECHANISM_INVALID),
        }
    }
    fn sign_new(
        &self,
        mech: &CK_MECHANISM,
        key: &object::Object,
    ) -> Result<Box<dyn Sign>> {
        if self.info.flags & CKF_SIGN != CKF_SIGN {
            return err_rv!(CKR_MECHANISM_INVALID);
        }
        match mech.mechanism {
            CKM_TLS_MAC | CKM_TLS12_MAC => {
                Ok(Box::new(TLSMACOperation::new(mech, key)?))
            }
            _ => err_rv!(CKR_MECHANISM_INVALID),
        }
    }
    fn verify_new(
        &self,
        mech: &CK_MECHANISM,
        key: &object::Object,
    ) -> Result<Box<dyn Verify>> {
        if self.info.flags & CKF_VERIFY != CKF_VERIFY {
            return err_rv!(CKR_MECHANISM_INVALID);
        }
        match mech.mechanism {
            CKM_TLS_MAC | CKM_TLS12_MAC => {
                Ok(Box::new(TLSMACOperation::new(mech, key)?))
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
    label: &'static [u8],
    context: &'static [u8],
    maclen: CK_ULONG,
    keylen: CK_ULONG,
    ivlen: CK_ULONG,
    mat_out: Option<*mut CK_SSL3_KEY_MAT_OUT>,
}

unsafe impl Send for TLSKDFOperation {}
unsafe impl Sync for TLSKDFOperation {}

impl TLSKDFOperation {
    fn new(mech: &CK_MECHANISM) -> Result<TLSKDFOperation> {
        match mech.mechanism {
            CKM_TLS12_MASTER_KEY_DERIVE => Self::new_tls12_mk_derive(mech),
            CKM_TLS12_KEY_AND_MAC_DERIVE => Self::new_tls12_keymac_derive(mech),
            CKM_TLS12_KEY_SAFE_DERIVE => Self::new_tls12_keymac_derive(mech),
            CKM_TLS12_KDF => Self::new_tls_generic_key_derive(mech),
            CKM_TLS_KDF => Self::new_tls_generic_key_derive(mech),
            _ => return err_rv!(CKR_MECHANISM_INVALID),
        }
    }

    fn new_tls12_mk_derive(mech: &CK_MECHANISM) -> Result<TLSKDFOperation> {
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
            label: TLS_MASTER_SECRET_LABEL,
            context: &[],
            maclen: 0,
            keylen: 0,
            ivlen: 0,
            mat_out: None,
        })
    }

    fn new_tls12_keymac_derive(mech: &CK_MECHANISM) -> Result<TLSKDFOperation> {
        let params = cast_params!(mech, CK_TLS12_KEY_MAT_PARAMS);

        let maclen = params.ulMacSizeInBits / 8;
        let keylen = params.ulKeySizeInBits / 8;
        let ivlen = if mech.mechanism == CKM_TLS12_KEY_SAFE_DERIVE {
            0
        } else {
            params.ulIVSizeInBits / 8
        };

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
            label: TLS_KEY_EXPANSION_LABEL,
            context: &[],
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

    fn new_tls_generic_key_derive(
        mech: &CK_MECHANISM,
    ) -> Result<TLSKDFOperation> {
        let params = cast_params!(mech, CK_TLS_KDF_PARAMS);

        if params.ulLabelLength == 0 {
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

        let prf = match hmac::hash_to_hmac_mech(params.prfMechanism) {
            Ok(h) => h,
            Err(_) => return err_rv!(CKR_MECHANISM_PARAM_INVALID),
        };

        Ok(TLSKDFOperation {
            finalized: false,
            mech: mech.mechanism,
            client_random: clirand,
            server_random: srvrand,
            version: None,
            prf: prf,
            label: bytes_to_slice!(params.pLabel, params.ulLabelLength, u8),
            context: bytes_to_slice!(
                params.pContextData,
                params.ulContextDataLength,
                u8
            ),
            maclen: 0,
            keylen: 0,
            ivlen: 0,
            mat_out: None,
        })
    }

    fn verify_key(&self, key: &Object) -> Result<()> {
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

    fn verify_mk_template<'a>(
        &self,
        template: &'a [CK_ATTRIBUTE],
    ) -> Result<CkAttrs<'a>> {
        /* augment template, then check that it has all the right values */
        let allowed = unsafe {
            std::mem::transmute::<&[CK_ULONG; 4], &[u8; 4 * misc::CK_ULONG_SIZE]>(
                &TLS_MASTER_SECRET_ALLOWED_MECHS,
            )
        };
        let mut tmpl = CkAttrs::from(template);
        tmpl.add_missing_ulong(CKA_CLASS, &CKO_SECRET_KEY);
        tmpl.add_missing_ulong(CKA_KEY_TYPE, &CKK_GENERIC_SECRET);
        tmpl.add_missing_ulong(CKA_VALUE_LEN, &TLS_MASTER_SECRET_SIZE);
        tmpl.add_missing_slice(CKA_ALLOWED_MECHANISMS, allowed);
        tmpl.add_missing_bool(CKA_SIGN, &CK_TRUE);
        tmpl.add_missing_bool(CKA_VERIFY, &CK_TRUE);
        tmpl.add_missing_bool(CKA_DERIVE, &CK_TRUE);
        for attr in tmpl.as_slice() {
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

    fn tls_prf_seed(&self, cli_first: bool) -> Vec<u8> {
        let mut seed = Vec::<u8>::with_capacity(
            self.label.len()
                + self.client_random.len()
                + self.server_random.len()
                + self.context.len(),
        );
        seed.extend_from_slice(self.label);
        if cli_first {
            seed.extend_from_slice(self.client_random.as_slice());
            seed.extend_from_slice(self.server_random.as_slice());
        } else {
            seed.extend_from_slice(self.server_random.as_slice());
            seed.extend_from_slice(self.client_random.as_slice());
        }
        if self.context.len() > 0 {
            seed.extend_from_slice(self.context);
        }
        seed
    }

    fn derive_master_key(
        &mut self,
        key: &Object,
        template: &[CK_ATTRIBUTE],
        mechanisms: &Mechanisms,
        objfactories: &ObjectFactories,
    ) -> Result<Vec<Object>> {
        self.verify_key(key)?;
        let tmpl = self.verify_mk_template(template)?;
        let factory =
            objfactories.get_obj_factory_from_key_template(tmpl.as_slice())?;
        let mut dkey = factory.default_object_derive(tmpl.as_slice(), key)?;

        let mech = mechanisms.get(self.prf)?;
        let seed = self.tls_prf_seed(true);
        let dkmlen = TLS_MASTER_SECRET_SIZE as usize;
        let mut tlsprf = TLSPRF::init(key, mech, self.prf)?;
        let dkm = tlsprf.finish(&seed, dkmlen)?;

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

    fn verify_key_expansion_template<'a>(
        &'a self,
        key: &Object,
        template: &'a [CK_ATTRIBUTE],
    ) -> Result<CkAttrs<'a>> {
        /* augment template, then check that it has all the right values */
        let is_sensitive = key.is_sensitive();
        let is_extractable = key.is_extractable();
        let mut tmpl = CkAttrs::from(template);
        tmpl.add_missing_ulong(CKA_CLASS, &CKO_SECRET_KEY);
        tmpl.add_missing_ulong(CKA_KEY_TYPE, &CKK_GENERIC_SECRET);
        tmpl.add_missing_ulong(CKA_VALUE_LEN, &self.keylen);
        tmpl.add_missing_bool(CKA_ENCRYPT, &CK_TRUE);
        tmpl.add_missing_bool(CKA_DECRYPT, &CK_TRUE);
        tmpl.add_missing_bool(CKA_DERIVE, &CK_TRUE);
        if is_sensitive {
            tmpl.add_missing_bool(CKA_SENSITIVE, &CK_TRUE);
        } else {
            tmpl.add_missing_bool(CKA_SENSITIVE, &CK_FALSE);
        }
        if is_extractable {
            tmpl.add_missing_bool(CKA_EXTRACTABLE, &CK_TRUE);
        } else {
            tmpl.add_missing_bool(CKA_EXTRACTABLE, &CK_FALSE);
        }

        for attr in tmpl.as_slice() {
            match attr.type_ {
                CKA_VALUE_LEN => {
                    let val = attr.to_ulong()?;
                    if val != self.keylen {
                        return err_rv!(CKR_ATTRIBUTE_VALUE_INVALID);
                    }
                }
                CKA_SENSITIVE => {
                    let val = attr.to_bool()?;
                    if val != is_sensitive {
                        return err_rv!(CKR_ATTRIBUTE_VALUE_INVALID);
                    }
                }
                CKA_EXTRACTABLE => {
                    let val = attr.to_bool()?;
                    if val != is_extractable {
                        return err_rv!(CKR_ATTRIBUTE_VALUE_INVALID);
                    }
                }
                _ => (),
            }
        }
        Ok(tmpl)
    }

    fn derive_mac_key(
        &mut self,
        key: &Object,
        template: &[CK_ATTRIBUTE],
        mechanisms: &Mechanisms,
        objfactories: &ObjectFactories,
    ) -> Result<Vec<Object>> {
        self.verify_key(key)?;
        let key_tmpl = self.verify_key_expansion_template(key, template)?;

        let mech = mechanisms.get(self.prf)?;
        let seed = self.tls_prf_seed(false);
        let dkmlen = (2 * (self.maclen + self.keylen + self.ivlen)) as usize;
        let mut tlsprf = TLSPRF::init(key, mech, self.prf)?;
        let dkm = tlsprf.finish(&seed, dkmlen)?;

        let mut keys = Vec::<Object>::with_capacity(4);
        let mut i = 0;

        if self.maclen > 0 {
            let maclen = self.maclen as usize;
            let is_sensitive = as_ck_bbool!(key, CKA_SENSITIVE, Some(true));
            let is_extractable =
                as_ck_bbool!(key, CKA_EXTRACTABLE, Some(false));
            let mut mac_tmpl = CkAttrs::with_capacity(6);
            mac_tmpl.add_ulong(CKA_CLASS, &CKO_SECRET_KEY);
            mac_tmpl.add_ulong(CKA_KEY_TYPE, &CKK_GENERIC_SECRET);
            mac_tmpl.add_bool(CKA_SIGN, &CK_TRUE);
            mac_tmpl.add_bool(CKA_VERIFY, &CK_TRUE);
            mac_tmpl.add_bool(CKA_SENSITIVE, &is_sensitive);
            mac_tmpl.add_bool(CKA_EXTRACTABLE, &is_extractable);

            let factory = objfactories
                .get_obj_factory_from_key_template(mac_tmpl.as_slice())?;
            let mut climac =
                factory.default_object_derive(mac_tmpl.as_slice(), key)?;
            factory
                .as_secret_key_factory()?
                .set_key(&mut climac, dkm[i..(i + maclen)].to_vec())?;

            i += maclen;
            keys.push(climac);
            let mut srvmac =
                factory.default_object_derive(mac_tmpl.as_slice(), key)?;
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

    fn derive_generic_key(
        &mut self,
        key: &Object,
        template: &[CK_ATTRIBUTE],
        mechanisms: &Mechanisms,
        objfactories: &ObjectFactories,
    ) -> Result<Vec<Object>> {
        self.verify_key(key)?;
        let mut tmpl = CkAttrs::from(template);
        tmpl.add_missing_ulong(CKA_CLASS, &CKO_SECRET_KEY);
        tmpl.add_missing_ulong(CKA_KEY_TYPE, &CKK_GENERIC_SECRET);

        let factory =
            objfactories.get_obj_factory_from_key_template(tmpl.as_slice())?;
        let mut dkey = factory.default_object_derive(tmpl.as_slice(), key)?;
        let dkmlen = match dkey.get_attr_as_ulong(CKA_VALUE_LEN) {
            Ok(n) => n as usize,
            Err(_) => return err_rv!(CKR_TEMPLATE_INCOMPLETE),
        };

        let mech = mechanisms.get(self.prf)?;
        let seed = self.tls_prf_seed(true);
        let mut tlsprf = TLSPRF::init(key, mech, self.prf)?;
        let dkm = tlsprf.finish(&seed, dkmlen)?;

        factory.as_secret_key_factory()?.set_key(&mut dkey, dkm)?;
        Ok(vec![dkey])
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
    ) -> Result<Vec<Object>> {
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
            CKM_TLS12_KEY_SAFE_DERIVE => {
                self.derive_mac_key(key, template, mechanisms, objfactories)
            }
            CKM_TLS12_KDF | CKM_TLS_KDF => {
                self.derive_generic_key(key, template, mechanisms, objfactories)
            }
            _ => err_rv!(CKR_MECHANISM_INVALID),
        }
    }
}

static MAC_MECHANISMS: Lazy<Mechanisms> = Lazy::new(|| {
    let mut mechanisms = mechanism::Mechanisms::new();
    hmac::register_mechs_only(&mut mechanisms);
    mechanisms
});

#[derive(Debug)]
struct TLSMACOperation {
    finalized: bool,
    in_use: bool,
    outputlen: usize,
    seed: Vec<u8>,
    tlsprf: TLSPRF,
}

impl TLSMACOperation {
    fn new(mech: &CK_MECHANISM, key: &Object) -> Result<TLSMACOperation> {
        match mech.mechanism {
            CKM_TLS_MAC | CKM_TLS12_MAC => (),
            _ => return err_rv!(CKR_MECHANISM_INVALID),
        }
        let params = cast_params!(mech, CK_TLS_MAC_PARAMS);
        let prf = match hmac::hash_to_hmac_mech(params.prfHashMechanism) {
            Ok(h) => h,
            Err(_) => return err_rv!(CKR_MECHANISM_PARAM_INVALID),
        };
        let maclen = params.ulMacLength as usize;
        let label = match params.ulServerOrClient {
            1 => TLS_SERVER_FINISHED,
            2 => TLS_CLIENT_FINISHED,
            _ => return err_rv!(CKR_MECHANISM_PARAM_INVALID),
        };

        let mac = MAC_MECHANISMS.get(prf)?;

        Ok(TLSMACOperation {
            finalized: false,
            in_use: false,
            outputlen: maclen,
            seed: label.to_vec(),
            tlsprf: TLSPRF::init(key, mac, prf)?,
        })
    }

    fn begin(&mut self) -> Result<()> {
        if self.in_use {
            return err_rv!(CKR_OPERATION_NOT_INITIALIZED);
        }
        Ok(())
    }
    fn update(&mut self, data: &[u8]) -> Result<()> {
        if self.finalized {
            return err_rv!(CKR_OPERATION_NOT_INITIALIZED);
        }
        self.in_use = true;
        self.seed.extend_from_slice(data);
        Ok(())
    }
    fn finalize(&mut self, output: &mut [u8]) -> Result<()> {
        if self.finalized {
            return err_rv!(CKR_OPERATION_NOT_INITIALIZED);
        }
        if !self.in_use {
            return err_rv!(CKR_OPERATION_NOT_INITIALIZED);
        }
        self.finalized = true;
        if output.len() != self.outputlen {
            return err_rv!(CKR_GENERAL_ERROR);
        }

        let out = self.tlsprf.finish(&self.seed, self.outputlen)?;
        output.copy_from_slice(out.as_slice());
        Ok(())
    }
}

impl MechOperation for TLSMACOperation {
    fn finalized(&self) -> bool {
        self.finalized
    }
}

impl Sign for TLSMACOperation {
    fn sign(&mut self, data: &[u8], signature: &mut [u8]) -> Result<()> {
        self.begin()?;
        self.update(data)?;
        self.finalize(signature)
    }

    fn sign_update(&mut self, data: &[u8]) -> Result<()> {
        self.update(data)
    }

    fn sign_final(&mut self, signature: &mut [u8]) -> Result<()> {
        self.finalize(signature)
    }

    fn signature_len(&self) -> Result<usize> {
        Ok(self.outputlen)
    }
}

impl Verify for TLSMACOperation {
    fn verify(&mut self, data: &[u8], signature: &[u8]) -> Result<()> {
        self.begin()?;
        self.update(data)?;
        self.verify_final(signature)
    }

    fn verify_update(&mut self, data: &[u8]) -> Result<()> {
        self.update(data)
    }

    fn verify_final(&mut self, signature: &[u8]) -> Result<()> {
        let mut verify: Vec<u8> = vec![0; self.outputlen];
        self.finalize(verify.as_mut_slice())?;
        if !constant_time_eq(&verify, signature) {
            return err_rv!(CKR_SIGNATURE_INVALID);
        }
        Ok(())
    }

    fn signature_len(&self) -> Result<usize> {
        Ok(self.outputlen)
    }
}
