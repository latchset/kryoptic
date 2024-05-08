// Copyright 2023 Simo Sorce
// See LICENSE.txt file for terms

use super::err_rv;
use super::error;
use super::interface;
use super::mechanism;
use super::object;

use error::{KError, KResult};
use interface::*;
use mechanism::*;
use object::{Object, ObjectFactories};

use std::fmt::Debug;

static HASH_MECH_SET: [(CK_MECHANISM_TYPE, CK_MECHANISM_TYPE); 9] = [
    (CKM_SHA_1, CKM_SHA1_KEY_DERIVATION),
    (CKM_SHA224, CKM_SHA224_KEY_DERIVATION),
    (CKM_SHA256, CKM_SHA256_KEY_DERIVATION),
    (CKM_SHA384, CKM_SHA384_KEY_DERIVATION),
    (CKM_SHA512, CKM_SHA512_KEY_DERIVATION),
    (CKM_SHA3_224, CKM_SHA3_224_KEY_DERIVATION),
    (CKM_SHA3_256, CKM_SHA3_256_KEY_DERIVATION),
    (CKM_SHA3_384, CKM_SHA3_384_KEY_DERIVATION),
    (CKM_SHA3_512, CKM_SHA3_512_KEY_DERIVATION),
];

#[derive(Debug)]
struct HashMechanism {
    info: CK_MECHANISM_INFO,
}

impl Mechanism for HashMechanism {
    fn info(&self) -> &CK_MECHANISM_INFO {
        &self.info
    }

    fn digest_new(&self, mech: &CK_MECHANISM) -> KResult<Box<dyn Digest>> {
        if self.info.flags & CKF_DIGEST != CKF_DIGEST {
            return err_rv!(CKR_MECHANISM_INVALID);
        }
        Ok(Box::new(HashOperation::new(mech.mechanism)?))
    }

    fn derive_operation(&self, mech: &CK_MECHANISM) -> KResult<Operation> {
        if self.info.flags & CKF_DERIVE != CKF_DERIVE {
            return err_rv!(CKR_MECHANISM_INVALID);
        }

        for hs in &HASH_MECH_SET {
            if hs.1 == mech.mechanism {
                return Ok(Operation::Derive(Box::new(HashKDFOperation::new(
                    hs.0,
                )?)));
            }
        }

        err_rv!(CKR_MECHANISM_INVALID)
    }
}

#[derive(Debug)]
pub struct HashOperation {
    state: HashState,
    finalized: bool,
    in_use: bool,
}

#[derive(Debug)]
struct HashKDFOperation {
    prf: CK_MECHANISM_TYPE,
    finalized: bool,
}

impl HashKDFOperation {
    fn register_mechanisms(mechs: &mut Mechanisms) {
        for hs in &HASH_MECH_SET {
            if mechs.get(hs.0).is_err() {
                continue;
            }
            mechs.add_mechanism(
                hs.1,
                Box::new(HashMechanism {
                    info: CK_MECHANISM_INFO {
                        ulMinKeySize: 0,
                        ulMaxKeySize: 0,
                        flags: CKF_DERIVE,
                    },
                }),
            );
        }
    }

    fn new(prf: CK_MECHANISM_TYPE) -> KResult<HashKDFOperation> {
        Ok(HashKDFOperation {
            prf: prf,
            finalized: false,
        })
    }
}

impl MechOperation for HashKDFOperation {
    fn finalized(&self) -> bool {
        self.finalized
    }
}

impl Derive for HashKDFOperation {
    fn derive(
        &mut self,
        key: &Object,
        template: &[CK_ATTRIBUTE],
        _mechanisms: &Mechanisms,
        objfactories: &ObjectFactories,
    ) -> KResult<(Object, usize)> {
        if self.finalized {
            return err_rv!(CKR_OPERATION_NOT_INITIALIZED);
        }
        self.finalized = true;

        key.check_key_ops(
            CKO_SECRET_KEY,
            CK_UNAVAILABLE_INFORMATION,
            CKA_DERIVE,
        )?;

        let mut op = HashOperation::new(self.prf)?;
        let hashsize = op.hashlen();
        let mut keysize = hashsize as CK_ULONG;

        let gensec: CK_ULONG = CKK_GENERIC_SECRET;
        let mut templ_plus = Vec::<CK_ATTRIBUTE>::new();
        let mut tptr = template;
        if template.iter().find(|a| a.type_ == CKA_KEY_TYPE).is_none() {
            if templ_plus.len() == 0 {
                if templ_plus.try_reserve(template.len() + 1).is_err() {
                    return err_rv!(CKR_HOST_MEMORY);
                }
                templ_plus.extend_from_slice(template);
            }
            templ_plus.push(CK_ATTRIBUTE::from_ulong(CKA_KEY_TYPE, &gensec));
            tptr = templ_plus.as_slice()
        }

        let factory = objfactories.get_obj_factory_from_key_template(tptr)?;

        match template.iter().find(|a| a.type_ == CKA_VALUE_LEN) {
            Some(a) => {
                let size = a.to_ulong()?;
                if size > keysize {
                    return err_rv!(CKR_TEMPLATE_INCONSISTENT);
                }
                keysize = size;
            }
            None => {
                if templ_plus.len() == 0 {
                    if templ_plus.try_reserve(template.len() + 1).is_err() {
                        return err_rv!(CKR_HOST_MEMORY);
                    }
                    templ_plus.extend_from_slice(template);
                }

                keysize = factory
                    .as_secret_key_factory()?
                    .recommend_key_size(hashsize)?
                    as CK_ULONG;

                templ_plus
                    .push(CK_ATTRIBUTE::from_ulong(CKA_VALUE_LEN, &keysize));
                tptr = templ_plus.as_slice()
            }
        }

        let mut obj = factory.default_object_derive(tptr, key)?;

        let mut dkm = vec![0u8; hashsize];
        op.digest(
            key.get_attr_as_bytes(CKA_VALUE)?.as_slice(),
            dkm.as_mut_slice(),
        )?;

        let keyval = dkm[..(keysize as usize)].to_vec();
        factory.as_secret_key_factory()?.set_key(&mut obj, keyval)?;

        Ok((obj, 0))
    }

    fn derive_additional_key(
        &mut self,
    ) -> KResult<(Object, CK_OBJECT_HANDLE_PTR)> {
        return err_rv!(CKR_GENERAL_ERROR);
    }
}

pub fn register(mechs: &mut Mechanisms, _: &mut object::ObjectFactories) {
    HashOperation::register_mechanisms(mechs);
    HashKDFOperation::register_mechanisms(mechs);
}

include! {"ossl/hash.rs"}
