// Copyright 2024 Simo Sorce
// See LICENSE.txt file for terms

//! This module implements encryption heleprs used internally for data
//! confidentiality and data integrity

use crate::aes;
use crate::attribute::CkAttrs;
use crate::error::Result;
use crate::kasn1::*;
use crate::mechanism::{Mechanism, Mechanisms};
use crate::misc::{byte_ptr, sizeof, void_ptr};
use crate::object::{Object, ObjectFactories};
use crate::pkcs11::*;

pub(crate) fn ephemeral_key() -> Object {
    let mut attrs = CkAttrs::with_capacity(3);
    attrs.add_owned_ulong(CKA_VALUE_LEN, 32).unwrap();
    attrs.add_owned_bool(CKA_ENCRYPT, CK_TRUE).unwrap();
    attrs.add_owned_bool(CKA_DECRYPT, CK_TRUE).unwrap();
    aes::AesMechanism::new(CKF_ENCRYPT | CKF_DECRYPT)
        .generate_key(
            &CK_MECHANISM {
                mechanism: CKM_AES_KEY_GEN,
                pParameter: std::ptr::null_mut(),
                ulParameterLen: 0,
            },
            attrs.as_slice(),
            &Mechanisms::new(),      /* unused */
            &ObjectFactories::new(), /* unused */
        )
        .unwrap()
}

pub(crate) const AES_GCM_IV_LEN: usize = 12;
pub(crate) const AES_GCM_TAG_LEN: usize = 8;

/// Encrypts data using AES-GCM (CKM_AES_GCM).
///
/// Generates a random 12-byte IV. Uses the provided `key` object,
/// `aad` (Additional Authenticated Data), and plaintext `data`.
/// Returns the ASN.1 encoded `KGCMParams` (containing the IV and tag) and
/// the resulting ciphertext.
pub(crate) fn aes_gcm_encrypt(
    mechanisms: &Mechanisms,
    key: &Object,
    aad: &[u8],
    data: &[u8],
) -> Result<(KGCMParams, Vec<u8>)> {
    let mut gcm_params = KGCMParams {
        aes_iv: [0u8; AES_GCM_IV_LEN],
        aes_tag: [0u8; AES_GCM_TAG_LEN],
    };

    let ck_mech = CK_MECHANISM {
        mechanism: CKM_AES_GCM,
        pParameter: std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    let mech = mechanisms.get(CKM_AES_GCM)?;
    let mut op = mech.msg_encryption_op(&ck_mech, key)?;

    let mut encrypted = vec![0u8; op.msg_encryption_len(data.len(), false)?];

    let mut params = CK_GCM_MESSAGE_PARAMS {
        pIv: gcm_params.aes_iv.as_mut_ptr(),
        ulIvLen: gcm_params.aes_iv.len() as CK_ULONG,
        ulIvFixedBits: 0,
        ivGenerator: CKG_GENERATE_RANDOM,
        pTag: gcm_params.aes_tag.as_mut_ptr(),
        ulTagBits: (gcm_params.aes_tag.len() * 8) as CK_ULONG,
    };

    let len = op.msg_encrypt(
        void_ptr!(&mut params),
        sizeof!(CK_GCM_MESSAGE_PARAMS),
        aad,
        data,
        &mut encrypted,
    )?;
    encrypted.resize(len, 0);

    Ok((gcm_params, encrypted))
}

/// Decrypts data using AES-GCM (CKM_AES_GCM).
///
/// Uses the provided `key` object, `gcm_params` (containing IV and tag),
/// `aad` (Additional Authenticated Data), and ciphertext `data`.
/// Verifies the tag and returns the decrypted plaintext.
pub(crate) fn aes_gcm_decrypt(
    mechanisms: &Mechanisms,
    key: &Object,
    gcm_params: &KGCMParams,
    aad: &[u8],
    data: &[u8],
) -> Result<Vec<u8>> {
    let ck_mech = CK_MECHANISM {
        mechanism: CKM_AES_GCM,
        pParameter: std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    let mech = mechanisms.get(CKM_AES_GCM)?;
    let mut op = mech.msg_decryption_op(&ck_mech, key)?;

    let mut decrypted = vec![0u8; op.msg_decryption_len(data.len(), false)?];

    let mut params = CK_GCM_MESSAGE_PARAMS {
        pIv: byte_ptr!(gcm_params.aes_iv.as_ptr()),
        ulIvLen: gcm_params.aes_iv.len() as CK_ULONG,
        ulIvFixedBits: 0,
        ivGenerator: CKG_NO_GENERATE,
        pTag: byte_ptr!(gcm_params.aes_tag.as_ptr()),
        ulTagBits: (gcm_params.aes_tag.len() * 8) as CK_ULONG,
    };

    let len = op.msg_decrypt(
        void_ptr!(&mut params),
        sizeof!(CK_GCM_MESSAGE_PARAMS),
        aad,
        data,
        &mut decrypted,
    )?;
    decrypted.resize(len, 0);

    Ok(decrypted)
}
