// Copyright 2026 Alexandre Laroche
// See LICENSE.txt file for terms

//! Known-answer tests for the IKE-derive mechanism family. Expected outputs
//! were computed independently with Python's `hmac`/`hashlib` (RFC 2409
//! SS5/Appendix B, RFC 7296 SS2.13 -- all four constructions reduce to
//! documented concatenations fed to HMAC-SHA-256) against the exact same
//! fixed inputs used here, not derived from this implementation.

use crate::tests::*;

use serial_test::parallel;

fn import_generic_secret(
    session: CK_ULONG,
    value: &[u8],
    derive: bool,
) -> CK_OBJECT_HANDLE {
    ret_or_panic!(import_object(
        session,
        CKO_SECRET_KEY,
        &[(CKA_KEY_TYPE, CKK_GENERIC_SECRET)],
        &[(CKA_VALUE, value)],
        &[(CKA_DERIVE, derive)],
    ))
}

fn import_hmac_sha256_key(
    session: CK_ULONG,
    value: &[u8],
    derive: bool,
) -> CK_OBJECT_HANDLE {
    ret_or_panic!(import_object(
        session,
        CKO_SECRET_KEY,
        &[(CKA_KEY_TYPE, CKK_SHA256_HMAC)],
        &[(CKA_VALUE, value)],
        &[(CKA_DERIVE, derive)],
    ))
}

fn import_aes_key(session: CK_ULONG, derive: bool) -> CK_OBJECT_HANDLE {
    let value = [0xabu8; 16];
    ret_or_panic!(import_object(
        session,
        CKO_SECRET_KEY,
        &[(CKA_KEY_TYPE, CKK_AES)],
        &[(CKA_VALUE, &value)],
        &[(CKA_DERIVE, derive)],
    ))
}

/// Derives a key without specifying `CKA_KEY_TYPE` in the template and returns
/// the `CKA_KEY_TYPE` of the derived key object.
fn derive_and_read_type(
    session: CK_ULONG,
    base_key: CK_OBJECT_HANDLE,
    mechanism: &mut CK_MECHANISM,
    out_len: usize,
) -> CK_KEY_TYPE {
    let mut derive_template = make_attr_template(
        &[
            (CKA_CLASS, CKO_SECRET_KEY),
            (CKA_VALUE_LEN, out_len as CK_ULONG),
        ],
        &[],
        &[(CKA_SENSITIVE, false), (CKA_EXTRACTABLE, true)],
    );
    let mut drv_handle = CK_INVALID_HANDLE;
    let ret = fn_derive_key(
        session,
        mechanism,
        base_key,
        derive_template.as_mut_ptr(),
        derive_template.len() as CK_ULONG,
        &mut drv_handle,
    );
    assert_eq!(ret, CKR_OK);

    let mut key_type: CK_ULONG = 0;
    let mut extract_template = make_ptrs_template(&[(
        CKA_KEY_TYPE,
        void_ptr!(&mut key_type),
        std::mem::size_of::<CK_ULONG>(),
    )]);
    let ret = fn_get_attribute_value(
        session,
        drv_handle,
        extract_template.as_mut_ptr(),
        extract_template.len() as CK_ULONG,
    );
    assert_eq!(ret, CKR_OK);
    key_type
}

fn derive_and_read(
    session: CK_ULONG,
    base_key: CK_OBJECT_HANDLE,
    mechanism: &mut CK_MECHANISM,
    out_len: usize,
) -> Vec<u8> {
    let mut derive_template = make_attr_template(
        &[
            (CKA_CLASS, CKO_SECRET_KEY),
            (CKA_KEY_TYPE, CKK_GENERIC_SECRET),
            (CKA_VALUE_LEN, out_len as CK_ULONG),
        ],
        &[],
        &[(CKA_SENSITIVE, false), (CKA_EXTRACTABLE, true)],
    );

    let mut drv_handle = CK_INVALID_HANDLE;
    let ret = fn_derive_key(
        session,
        mechanism,
        base_key,
        derive_template.as_mut_ptr(),
        derive_template.len() as CK_ULONG,
        &mut drv_handle,
    );
    assert_eq!(ret, CKR_OK);

    let mut result = vec![0u8; out_len];
    let mut extract_template = make_ptrs_template(&[(
        CKA_VALUE,
        void_ptr!(result.as_mut_ptr()),
        out_len,
    )]);
    let ret = fn_get_attribute_value(
        session,
        drv_handle,
        extract_template.as_mut_ptr(),
        extract_template.len() as CK_ULONG,
    );
    assert_eq!(ret, CKR_OK);
    assert_eq!(extract_template[0].ulValueLen, out_len as CK_ULONG);
    result
}

/// `CKM_IKE_PRF_DERIVE`, case 2 (`bDataAsKey = false`, `bRekey = false`):
/// `prf(inKey, Ni||Nr)`.
#[cfg(feature = "ike")]
#[test]
#[parallel]
fn test_ike_prf_derive() {
    let mut testtokn = TestToken::initialized("test_ike_prf_derive", None);
    let session = testtokn.get_session(true);
    testtokn.login();

    let in_key: Vec<u8> = (0..32u16).map(|b| b as u8).collect();
    let ni = [0x11u8; 16];
    let nr = [0x22u8; 16];
    let expected = hex::decode(
        "1ba3f33e6dc7a742958e0a14833d0f7182769d3a7ec48f9157fc8e450eba9612",
    )
    .expect("bad hex");

    let key_handle = import_hmac_sha256_key(session, &in_key, true);

    let params = CK_IKE_PRF_DERIVE_PARAMS {
        prfMechanism: CKM_SHA256_HMAC,
        bDataAsKey: CK_FALSE,
        bRekey: CK_FALSE,
        pNi: byte_ptr!(ni.as_ptr()),
        ulNiLen: ni.len() as CK_ULONG,
        pNr: byte_ptr!(nr.as_ptr()),
        ulNrLen: nr.len() as CK_ULONG,
        hNewKey: CK_INVALID_HANDLE,
    };
    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_IKE_PRF_DERIVE,
        pParameter: void_ptr!(&params),
        ulParameterLen: sizeof!(CK_IKE_PRF_DERIVE_PARAMS),
    };

    let result = derive_and_read(session, key_handle, &mut mechanism, 32);
    assert_eq!(result, expected);

    testtokn.finalize();
}

/// `CKM_IKE_PRF_DERIVE`, case 2 (`bDataAsKey = false`, `bRekey = false`),
/// NSS-sourced vector: key and data taken from `ike_sha256_known_key` /
/// `ike_sha256_known_plain_text` in `lib/softoken/sftkike.c`; expected
/// output is `ike_sha256_known_mac` from the same file.  The original NSS
/// key is 16 bytes; it is zero-padded to 32 bytes here to satisfy the
/// `CKK_SHA256_HMAC` key-length requirement.  The HMAC output is unchanged
/// because HMAC right-pads short keys with zeros to the block size.
#[cfg(feature = "ike")]
#[test]
#[parallel]
fn test_ike_prf_derive_nss() {
    let mut testtokn = TestToken::initialized("test_ike_prf_derive_nss", None);
    let session = testtokn.get_session(true);
    testtokn.login();

    let in_key = hex::decode(
        "9da2d58f57f039f9204e0dd0ef04f37200000000000000000000000000000000",
    )
    .expect("bad hex");
    // NSS ike_sha256_known_plain_text split into two 16-byte nonces so that
    // Ni||Nr equals the original 32-byte buffer; the HMAC output is unchanged.
    let ni = hex::decode("33f17afcb6134cbf1cab59877d42db35").expect("bad hex");
    let nr = hex::decode("82226eff74dd37eb8b75e675645fc169").expect("bad hex");
    let expected = hex::decode(
        "804b4a1e0ec593cfb6e454524149396de234d0dae29f34a8fdb5f9afe76ea652",
    )
    .expect("bad hex");

    let key_handle = import_hmac_sha256_key(session, &in_key, true);

    let params = CK_IKE_PRF_DERIVE_PARAMS {
        prfMechanism: CKM_SHA256_HMAC,
        bDataAsKey: CK_FALSE,
        bRekey: CK_FALSE,
        pNi: byte_ptr!(ni.as_ptr()),
        ulNiLen: ni.len() as CK_ULONG,
        pNr: byte_ptr!(nr.as_ptr()),
        ulNrLen: nr.len() as CK_ULONG,
        hNewKey: CK_INVALID_HANDLE,
    };
    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_IKE_PRF_DERIVE,
        pParameter: void_ptr!(&params),
        ulParameterLen: sizeof!(CK_IKE_PRF_DERIVE_PARAMS),
    };

    let result = derive_and_read(session, key_handle, &mut mechanism, 32);
    assert_eq!(result, expected);

    testtokn.finalize();
}

/// `CKM_IKE_PRF_DERIVE`, case 1 (`bDataAsKey = true`, `bRekey = false`):
/// `prf(Ni||Nr, inKey)` — Ni||Nr is the HMAC key; inKey is the data.
/// IKEv1 SKEYID (DH-secret variant) / IKEv2 SKEYSEED.
#[cfg(feature = "ike")]
#[test]
#[parallel]
fn test_ike_prf_derive_data_as_key() {
    let mut testtokn =
        TestToken::initialized("test_ike_prf_derive_data_as_key", None);
    let session = testtokn.get_session(true);
    testtokn.login();

    let in_key: Vec<u8> = (0..32u16).map(|b| b as u8).collect();
    let ni = [0x11u8; 16];
    let nr = [0x22u8; 16];
    // prf(Ni||Nr, inKey) = HMAC-SHA256(key=Ni||Nr, data=inKey)
    let expected = hex::decode(
        "7101848cd9561d0635e651f963af107891302264a5818c614b57b38598882802",
    )
    .expect("bad hex");

    let key_handle = import_generic_secret(session, &in_key, true);

    let params = CK_IKE_PRF_DERIVE_PARAMS {
        prfMechanism: CKM_SHA256_HMAC,
        bDataAsKey: CK_TRUE,
        bRekey: CK_FALSE,
        pNi: byte_ptr!(ni.as_ptr()),
        ulNiLen: ni.len() as CK_ULONG,
        pNr: byte_ptr!(nr.as_ptr()),
        ulNrLen: nr.len() as CK_ULONG,
        hNewKey: CK_INVALID_HANDLE,
    };
    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_IKE_PRF_DERIVE,
        pParameter: void_ptr!(&params),
        ulParameterLen: sizeof!(CK_IKE_PRF_DERIVE_PARAMS),
    };

    let result = derive_and_read(session, key_handle, &mut mechanism, 32);
    assert_eq!(result, expected);

    testtokn.finalize();
}

/// `CKM_IKE_PRF_DERIVE`, case 3 (`bDataAsKey = false`, `bRekey = true`):
/// `prf(inKey, newKey||Ni||Nr)` — IKEv2 rekey SKEYSEED.
#[cfg(feature = "ike")]
#[test]
#[parallel]
fn test_ike_prf_derive_rekey() {
    let mut testtokn =
        TestToken::initialized("test_ike_prf_derive_rekey", None);
    let session = testtokn.get_session(true);
    testtokn.login();

    let in_key: Vec<u8> = (0..32u16).map(|b| b as u8).collect();
    let new_key = [0xaau8; 16];
    let ni = [0x11u8; 16];
    let nr = [0x22u8; 16];
    // prf(inKey, newKey||Ni||Nr) = HMAC-SHA256(key=inKey, data=newKey||Ni||Nr)
    let expected = hex::decode(
        "93425e52b86bbdd0520e77dcf786fdd048e2981ae46dc60fbccbd059316c5f83",
    )
    .expect("bad hex");

    let key_handle = import_hmac_sha256_key(session, &in_key, true);
    let new_key_handle = import_generic_secret(session, &new_key, false);

    let params = CK_IKE_PRF_DERIVE_PARAMS {
        prfMechanism: CKM_SHA256_HMAC,
        bDataAsKey: CK_FALSE,
        bRekey: CK_TRUE,
        pNi: byte_ptr!(ni.as_ptr()),
        ulNiLen: ni.len() as CK_ULONG,
        pNr: byte_ptr!(nr.as_ptr()),
        ulNrLen: nr.len() as CK_ULONG,
        hNewKey: new_key_handle,
    };
    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_IKE_PRF_DERIVE,
        pParameter: void_ptr!(&params),
        ulParameterLen: sizeof!(CK_IKE_PRF_DERIVE_PARAMS),
    };

    let result = derive_and_read(session, key_handle, &mut mechanism, 32);
    assert_eq!(result, expected);

    testtokn.finalize();
}

/// `bDataAsKey` and `bRekey` are mutually exclusive per the mechanism's own
/// description; both set must fail without deriving anything.
#[cfg(feature = "ike")]
#[test]
#[parallel]
fn test_ike_prf_derive_data_as_key_and_rekey_conflict() {
    let mut testtokn =
        TestToken::initialized("test_ike_prf_derive_conflict", None);
    let session = testtokn.get_session(true);
    testtokn.login();

    let in_key = [0x01u8; 32];
    let ni = [0x11u8; 16];
    let nr = [0x22u8; 16];
    let key_handle = import_generic_secret(session, &in_key, true);

    let params = CK_IKE_PRF_DERIVE_PARAMS {
        prfMechanism: CKM_SHA256_HMAC,
        bDataAsKey: CK_TRUE,
        bRekey: CK_TRUE,
        pNi: byte_ptr!(ni.as_ptr()),
        ulNiLen: ni.len() as CK_ULONG,
        pNr: byte_ptr!(nr.as_ptr()),
        ulNrLen: nr.len() as CK_ULONG,
        hNewKey: CK_INVALID_HANDLE,
    };
    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_IKE_PRF_DERIVE,
        pParameter: void_ptr!(&params),
        ulParameterLen: sizeof!(CK_IKE_PRF_DERIVE_PARAMS),
    };
    let mut derive_template = make_attr_template(
        &[
            (CKA_CLASS, CKO_SECRET_KEY),
            (CKA_KEY_TYPE, CKK_GENERIC_SECRET),
            (CKA_VALUE_LEN, 32),
        ],
        &[],
        &[(CKA_SENSITIVE, false), (CKA_EXTRACTABLE, true)],
    );
    let mut drv_handle = CK_INVALID_HANDLE;
    let ret = fn_derive_key(
        session,
        &mut mechanism,
        key_handle,
        derive_template.as_mut_ptr(),
        derive_template.len() as CK_ULONG,
        &mut drv_handle,
    );
    assert_eq!(ret, CKR_MECHANISM_PARAM_INVALID);

    testtokn.finalize();
}

/// `CKM_IKE1_PRF_DERIVE` (RFC 2409 SS5), no previous key:
/// `prf(inKey, gxy||CKY_I||CKY_R||keyNumber)`.
#[cfg(feature = "ike")]
#[test]
#[parallel]
fn test_ike1_prf_derive() {
    let mut testtokn = TestToken::initialized("test_ike1_prf_derive", None);
    let session = testtokn.get_session(true);
    testtokn.login();

    let in_key: Vec<u8> = (1..33u16).map(|b| b as u8).collect();
    let gxy = [0x33u8; 24];
    let cky_i = [0x44u8; 8];
    let cky_r = [0x55u8; 8];
    let expected = hex::decode(
        "caf409b1e6d35743be50019d800d90b2381c0b1f669ed8fcf423b582b7600776",
    )
    .expect("bad hex");

    let key_handle = import_hmac_sha256_key(session, &in_key, true);
    let gxy_handle = import_generic_secret(session, &gxy, false);

    let params = CK_IKE1_PRF_DERIVE_PARAMS {
        prfMechanism: CKM_SHA256_HMAC,
        bHasPrevKey: CK_FALSE,
        hKeygxy: gxy_handle,
        hPrevKey: CK_INVALID_HANDLE,
        pCKYi: byte_ptr!(cky_i.as_ptr()),
        ulCKYiLen: cky_i.len() as CK_ULONG,
        pCKYr: byte_ptr!(cky_r.as_ptr()),
        ulCKYrLen: cky_r.len() as CK_ULONG,
        keyNumber: 0,
    };
    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_IKE1_PRF_DERIVE,
        pParameter: void_ptr!(&params),
        ulParameterLen: sizeof!(CK_IKE1_PRF_DERIVE_PARAMS),
    };

    let result = derive_and_read(session, key_handle, &mut mechanism, 32);
    assert_eq!(result, expected);

    testtokn.finalize();
}

/// `CKM_IKE1_PRF_DERIVE` rejects CKY_i shorter than 8 bytes (ISAKMP minimum).
#[cfg(feature = "ike")]
#[test]
#[parallel]
fn test_ike1_prf_derive_short_cookie() {
    let mut testtokn =
        TestToken::initialized("test_ike1_prf_derive_short_cookie", None);
    let session = testtokn.get_session(true);
    testtokn.login();

    let in_key = [0x01u8; 32];
    let gxy = [0x33u8; 24];
    let cky_i = [0x44u8; 4]; // only 4 bytes — must fail
    let cky_r = [0x55u8; 8];

    let key_handle = import_generic_secret(session, &in_key, true);
    let gxy_handle = import_generic_secret(session, &gxy, false);

    let params = CK_IKE1_PRF_DERIVE_PARAMS {
        prfMechanism: CKM_SHA256_HMAC,
        bHasPrevKey: CK_FALSE,
        hKeygxy: gxy_handle,
        hPrevKey: CK_INVALID_HANDLE,
        pCKYi: byte_ptr!(cky_i.as_ptr()),
        ulCKYiLen: cky_i.len() as CK_ULONG,
        pCKYr: byte_ptr!(cky_r.as_ptr()),
        ulCKYrLen: cky_r.len() as CK_ULONG,
        keyNumber: 0,
    };
    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_IKE1_PRF_DERIVE,
        pParameter: void_ptr!(&params),
        ulParameterLen: sizeof!(CK_IKE1_PRF_DERIVE_PARAMS),
    };
    let mut derive_template = make_attr_template(
        &[
            (CKA_CLASS, CKO_SECRET_KEY),
            (CKA_KEY_TYPE, CKK_GENERIC_SECRET),
            (CKA_VALUE_LEN, 32usize as CK_ULONG),
        ],
        &[],
        &[(CKA_SENSITIVE, false), (CKA_EXTRACTABLE, true)],
    );
    let mut drv_handle = CK_INVALID_HANDLE;
    let ret = fn_derive_key(
        session,
        &mut mechanism,
        key_handle,
        derive_template.as_mut_ptr(),
        derive_template.len() as CK_ULONG,
        &mut drv_handle,
    );
    assert_eq!(ret, CKR_MECHANISM_PARAM_INVALID);

    testtokn.finalize();
}

/// `CKM_IKE1_EXTENDED_DERIVE` (RFC 2409 Appendix B), no `gxy`, forced into
/// the chaining path by non-empty extra data, requesting two PRF blocks:
/// `K1 = prf(K, extra)`, `K2 = prf(K, K1||extra)`.
#[cfg(feature = "ike")]
#[test]
#[parallel]
fn test_ike1_extended_derive() {
    let mut testtokn =
        TestToken::initialized("test_ike1_extended_derive", None);
    let session = testtokn.get_session(true);
    testtokn.login();

    let in_key: Vec<u8> = (2..34u16).map(|b| b as u8).collect();
    let extra = [0x66u8; 20];
    let expected = hex::decode(
        "f16e255d2faedc287141841478e2da3f5d8e300dece119cc9c039c5e64a002d\
         d48ba3d5d5f76bee9e514e4f74ae08e8d18746ed9fd2b24c359a10a892a3991a7",
    )
    .expect("bad hex");

    let key_handle = import_hmac_sha256_key(session, &in_key, true);

    let params = CK_IKE1_EXTENDED_DERIVE_PARAMS {
        prfMechanism: CKM_SHA256_HMAC,
        bHasKeygxy: CK_FALSE,
        hKeygxy: CK_INVALID_HANDLE,
        pExtraData: byte_ptr!(extra.as_ptr()),
        ulExtraDataLen: extra.len() as CK_ULONG,
    };
    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_IKE1_EXTENDED_DERIVE,
        pParameter: void_ptr!(&params),
        ulParameterLen: sizeof!(CK_IKE1_EXTENDED_DERIVE_PARAMS),
    };

    let result = derive_and_read(session, key_handle, &mut mechanism, 64);
    assert_eq!(result, expected);

    testtokn.finalize();
}

/// `CKM_IKE1_EXTENDED_DERIVE` rejects CKA_VALUE_LEN > 255 × PRF output size
/// (PKCS#11 v3.0 §6.46.6). With HMAC-SHA256 (32 bytes) that cap is 8160.
#[cfg(feature = "ike")]
#[test]
#[parallel]
fn test_ike1_extended_derive_length_limit() {
    let mut testtokn =
        TestToken::initialized("test_ike1_extended_derive_limit", None);
    let session = testtokn.get_session(true);
    testtokn.login();

    let in_key = [0x02u8; 32];
    let extra = [0x66u8; 20];
    let key_handle = import_hmac_sha256_key(session, &in_key, true);

    let params = CK_IKE1_EXTENDED_DERIVE_PARAMS {
        prfMechanism: CKM_SHA256_HMAC,
        bHasKeygxy: CK_FALSE,
        hKeygxy: CK_INVALID_HANDLE,
        pExtraData: byte_ptr!(extra.as_ptr()),
        ulExtraDataLen: extra.len() as CK_ULONG,
    };
    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_IKE1_EXTENDED_DERIVE,
        pParameter: void_ptr!(&params),
        ulParameterLen: sizeof!(CK_IKE1_EXTENDED_DERIVE_PARAMS),
    };
    // 255*32 + 1 = 8161 bytes exceeds the limit
    let mut derive_template = make_attr_template(
        &[
            (CKA_CLASS, CKO_SECRET_KEY),
            (CKA_KEY_TYPE, CKK_GENERIC_SECRET),
            (CKA_VALUE_LEN, 8161usize as CK_ULONG),
        ],
        &[],
        &[(CKA_SENSITIVE, false), (CKA_EXTRACTABLE, true)],
    );
    let mut drv_handle = CK_INVALID_HANDLE;
    let ret = fn_derive_key(
        session,
        &mut mechanism,
        key_handle,
        derive_template.as_mut_ptr(),
        derive_template.len() as CK_ULONG,
        &mut drv_handle,
    );
    assert_eq!(ret, CKR_KEY_SIZE_RANGE);

    testtokn.finalize();
}

/// `CKM_IKE1_EXTENDED_DERIVE` requires an explicit output length -- there is
/// no PRF-derived default the way `CKM_IKE_PRF_DERIVE` has one.
#[cfg(feature = "ike")]
#[test]
#[parallel]
fn test_ike1_extended_derive_requires_length() {
    let mut testtokn =
        TestToken::initialized("test_ike1_extended_derive_nolen", None);
    let session = testtokn.get_session(true);
    testtokn.login();

    let in_key = [0x02u8; 32];
    let key_handle = import_hmac_sha256_key(session, &in_key, true);

    let params = CK_IKE1_EXTENDED_DERIVE_PARAMS {
        prfMechanism: CKM_SHA256_HMAC,
        bHasKeygxy: CK_FALSE,
        hKeygxy: CK_INVALID_HANDLE,
        pExtraData: std::ptr::null_mut(),
        ulExtraDataLen: 0,
    };
    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_IKE1_EXTENDED_DERIVE,
        pParameter: void_ptr!(&params),
        ulParameterLen: sizeof!(CK_IKE1_EXTENDED_DERIVE_PARAMS),
    };
    let mut derive_template = make_attr_template(
        &[
            (CKA_CLASS, CKO_SECRET_KEY),
            (CKA_KEY_TYPE, CKK_GENERIC_SECRET),
        ],
        &[],
        &[(CKA_SENSITIVE, false), (CKA_EXTRACTABLE, true)],
    );
    let mut drv_handle = CK_INVALID_HANDLE;
    let ret = fn_derive_key(
        session,
        &mut mechanism,
        key_handle,
        derive_template.as_mut_ptr(),
        derive_template.len() as CK_ULONG,
        &mut drv_handle,
    );
    assert_eq!(ret, CKR_TEMPLATE_INCOMPLETE);

    testtokn.finalize();
}

/// `CKM_IKE2_PRF_PLUS_DERIVE` (RFC 7296 SS2.13 prf+), no seed key,
/// requesting a non-block-aligned length so the final block is truncated:
/// `T1 = prf(K, S||0x01)`, `T2 = prf(K, T1||S||0x02)`, output = `(T1||T2)[..48]`.
#[cfg(feature = "ike")]
#[test]
#[parallel]
fn test_ike2_prf_plus_derive() {
    let mut testtokn =
        TestToken::initialized("test_ike2_prf_plus_derive", None);
    let session = testtokn.get_session(true);
    testtokn.login();

    let in_key: Vec<u8> = (3..35u16).map(|b| b as u8).collect();
    let seed_data = [0x77u8; 24];
    let expected = hex::decode(
        "d320b427ab76a7f65a193bc400f9f20bbc8f4f7525e5da7c627c3c6747e727f\
         d11c8adba78cde7f78b227028ca91df31",
    )
    .expect("bad hex");

    let key_handle = import_hmac_sha256_key(session, &in_key, true);

    let params = CK_IKE2_PRF_PLUS_DERIVE_PARAMS {
        prfMechanism: CKM_SHA256_HMAC,
        bHasSeedKey: CK_FALSE,
        hSeedKey: CK_INVALID_HANDLE,
        pSeedData: byte_ptr!(seed_data.as_ptr()),
        ulSeedDataLen: seed_data.len() as CK_ULONG,
    };
    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_IKE2_PRF_PLUS_DERIVE,
        pParameter: void_ptr!(&params),
        ulParameterLen: sizeof!(CK_IKE2_PRF_PLUS_DERIVE_PARAMS),
    };

    let result = derive_and_read(session, key_handle, &mut mechanism, 48);
    assert_eq!(result, expected);

    testtokn.finalize();
}

/// `CKM_IKE2_PRF_PLUS_DERIVE`, NSS-sourced vector: key and seed data taken
/// from `ike_sha256_known_key` / `ike_sha256_known_plain_text` in
/// `lib/softoken/sftkike.c`; expected output is `ike_known_sha256_prf_plus`
/// from the same file (64 bytes, two full PRF blocks).  The original NSS
/// key is 16 bytes; it is zero-padded to 32 bytes here to satisfy the
/// `CKK_SHA256_HMAC` key-length requirement.  The output is unchanged
/// because HMAC right-pads short keys with zeros to the block size.
#[cfg(feature = "ike")]
#[test]
#[parallel]
fn test_ike2_prf_plus_derive_nss() {
    let mut testtokn =
        TestToken::initialized("test_ike2_prf_plus_derive_nss", None);
    let session = testtokn.get_session(true);
    testtokn.login();

    let in_key = hex::decode(
        "9da2d58f57f039f9204e0dd0ef04f37200000000000000000000000000000000",
    )
    .expect("bad hex");
    let seed_data = hex::decode(
        "33f17afcb6134cbf1cab59877d42db3582226eff74dd37eb8b75e675645fc169",
    )
    .expect("bad hex");
    let expected = hex::decode(
        "e6f19b4a02e97372939fdb461db149cb5308983d4136fa8b470449110d6e961d\
         abbe9428a0b79ca329e140f8f888b9b540d4544d25ab94d498d800bf6fefe839",
    )
    .expect("bad hex");

    let key_handle = import_hmac_sha256_key(session, &in_key, true);

    let params = CK_IKE2_PRF_PLUS_DERIVE_PARAMS {
        prfMechanism: CKM_SHA256_HMAC,
        bHasSeedKey: CK_FALSE,
        hSeedKey: CK_INVALID_HANDLE,
        pSeedData: byte_ptr!(seed_data.as_ptr()),
        ulSeedDataLen: seed_data.len() as CK_ULONG,
    };
    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_IKE2_PRF_PLUS_DERIVE,
        pParameter: void_ptr!(&params),
        ulParameterLen: sizeof!(CK_IKE2_PRF_PLUS_DERIVE_PARAMS),
    };

    let result = derive_and_read(session, key_handle, &mut mechanism, 64);
    assert_eq!(result, expected);

    testtokn.finalize();
}

/// `CKM_IKE_PRF_DERIVE` with `bDataAsKey = true` rejects a base key that is
/// not `CKK_GENERIC_SECRET` (§6.64.3).
#[cfg(feature = "ike")]
#[test]
#[parallel]
fn test_ike_prf_derive_data_as_key_base_key_type() {
    let mut testtokn =
        TestToken::initialized("test_ike_prf_data_as_key_type", None);
    let session = testtokn.get_session(true);
    testtokn.login();

    let ni = [0x11u8; 16];
    let nr = [0x22u8; 16];
    let base_key = import_aes_key(session, true);

    let params = CK_IKE_PRF_DERIVE_PARAMS {
        prfMechanism: CKM_SHA256_HMAC,
        bDataAsKey: CK_TRUE,
        bRekey: CK_FALSE,
        pNi: byte_ptr!(ni.as_ptr()),
        ulNiLen: ni.len() as CK_ULONG,
        pNr: byte_ptr!(nr.as_ptr()),
        ulNrLen: nr.len() as CK_ULONG,
        hNewKey: CK_INVALID_HANDLE,
    };
    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_IKE_PRF_DERIVE,
        pParameter: void_ptr!(&params),
        ulParameterLen: sizeof!(CK_IKE_PRF_DERIVE_PARAMS),
    };
    let mut derive_template = make_attr_template(
        &[
            (CKA_CLASS, CKO_SECRET_KEY),
            (CKA_KEY_TYPE, CKK_GENERIC_SECRET),
            (CKA_VALUE_LEN, 32),
        ],
        &[],
        &[(CKA_SENSITIVE, false), (CKA_EXTRACTABLE, true)],
    );
    let mut drv_handle = CK_INVALID_HANDLE;
    let ret = fn_derive_key(
        session,
        &mut mechanism,
        base_key,
        derive_template.as_mut_ptr(),
        derive_template.len() as CK_ULONG,
        &mut drv_handle,
    );
    assert_eq!(ret, CKR_KEY_TYPE_INCONSISTENT);

    testtokn.finalize();
}

/// `CKM_IKE_PRF_DERIVE` with `bRekey = true` rejects an `hNewKey` that is not
/// `CKK_GENERIC_SECRET` (§6.64.3).
#[cfg(feature = "ike")]
#[test]
#[parallel]
fn test_ike_prf_derive_rekey_new_key_type() {
    let mut testtokn =
        TestToken::initialized("test_ike_prf_rekey_new_type", None);
    let session = testtokn.get_session(true);
    testtokn.login();

    let in_key = [0x01u8; 32];
    let ni = [0x11u8; 16];
    let nr = [0x22u8; 16];
    let base_key = import_hmac_sha256_key(session, &in_key, true);
    let wrong_new_key = import_aes_key(session, false);

    let params = CK_IKE_PRF_DERIVE_PARAMS {
        prfMechanism: CKM_SHA256_HMAC,
        bDataAsKey: CK_FALSE,
        bRekey: CK_TRUE,
        pNi: byte_ptr!(ni.as_ptr()),
        ulNiLen: ni.len() as CK_ULONG,
        pNr: byte_ptr!(nr.as_ptr()),
        ulNrLen: nr.len() as CK_ULONG,
        hNewKey: wrong_new_key,
    };
    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_IKE_PRF_DERIVE,
        pParameter: void_ptr!(&params),
        ulParameterLen: sizeof!(CK_IKE_PRF_DERIVE_PARAMS),
    };
    let mut derive_template = make_attr_template(
        &[
            (CKA_CLASS, CKO_SECRET_KEY),
            (CKA_KEY_TYPE, CKK_GENERIC_SECRET),
            (CKA_VALUE_LEN, 32),
        ],
        &[],
        &[(CKA_SENSITIVE, false), (CKA_EXTRACTABLE, true)],
    );
    let mut drv_handle = CK_INVALID_HANDLE;
    let ret = fn_derive_key(
        session,
        &mut mechanism,
        base_key,
        derive_template.as_mut_ptr(),
        derive_template.len() as CK_ULONG,
        &mut drv_handle,
    );
    assert_eq!(ret, CKR_KEY_TYPE_INCONSISTENT);

    testtokn.finalize();
}

/// `CKM_IKE_PRF_DERIVE` defaults the derived key type to the matching HMAC
/// key type when `CKA_KEY_TYPE` is absent from the template.
#[cfg(feature = "ike")]
#[test]
#[parallel]
fn test_ike_prf_derive_default_output_type() {
    let mut testtokn =
        TestToken::initialized("test_ike_prf_default_out_type", None);
    let session = testtokn.get_session(true);
    testtokn.login();

    let in_key: Vec<u8> = (0..32u16).map(|b| b as u8).collect();
    let ni = [0x11u8; 16];
    let nr = [0x22u8; 16];
    let base_key = import_hmac_sha256_key(session, &in_key, true);

    let params = CK_IKE_PRF_DERIVE_PARAMS {
        prfMechanism: CKM_SHA256_HMAC,
        bDataAsKey: CK_FALSE,
        bRekey: CK_FALSE,
        pNi: byte_ptr!(ni.as_ptr()),
        ulNiLen: ni.len() as CK_ULONG,
        pNr: byte_ptr!(nr.as_ptr()),
        ulNrLen: nr.len() as CK_ULONG,
        hNewKey: CK_INVALID_HANDLE,
    };
    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_IKE_PRF_DERIVE,
        pParameter: void_ptr!(&params),
        ulParameterLen: sizeof!(CK_IKE_PRF_DERIVE_PARAMS),
    };

    let key_type = derive_and_read_type(session, base_key, &mut mechanism, 32);
    assert_eq!(key_type, CKK_SHA256_HMAC);

    testtokn.finalize();
}

/// `CKM_IKE1_PRF_DERIVE` rejects an `hKeygxy` that is not `CKK_GENERIC_SECRET`
/// (§6.64.4).
#[cfg(feature = "ike")]
#[test]
#[parallel]
fn test_ike1_prf_derive_gxy_key_type() {
    let mut testtokn = TestToken::initialized("test_ike1_prf_gxy_type", None);
    let session = testtokn.get_session(true);
    testtokn.login();

    let in_key: Vec<u8> = (1..33u16).map(|b| b as u8).collect();
    let cky_i = [0x44u8; 8];
    let cky_r = [0x55u8; 8];
    let base_key = import_hmac_sha256_key(session, &in_key, true);
    let wrong_gxy = import_aes_key(session, false);

    let params = CK_IKE1_PRF_DERIVE_PARAMS {
        prfMechanism: CKM_SHA256_HMAC,
        bHasPrevKey: CK_FALSE,
        hKeygxy: wrong_gxy,
        hPrevKey: CK_INVALID_HANDLE,
        pCKYi: byte_ptr!(cky_i.as_ptr()),
        ulCKYiLen: cky_i.len() as CK_ULONG,
        pCKYr: byte_ptr!(cky_r.as_ptr()),
        ulCKYrLen: cky_r.len() as CK_ULONG,
        keyNumber: 0,
    };
    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_IKE1_PRF_DERIVE,
        pParameter: void_ptr!(&params),
        ulParameterLen: sizeof!(CK_IKE1_PRF_DERIVE_PARAMS),
    };
    let mut derive_template = make_attr_template(
        &[
            (CKA_CLASS, CKO_SECRET_KEY),
            (CKA_KEY_TYPE, CKK_GENERIC_SECRET),
            (CKA_VALUE_LEN, 32),
        ],
        &[],
        &[(CKA_SENSITIVE, false), (CKA_EXTRACTABLE, true)],
    );
    let mut drv_handle = CK_INVALID_HANDLE;
    let ret = fn_derive_key(
        session,
        &mut mechanism,
        base_key,
        derive_template.as_mut_ptr(),
        derive_template.len() as CK_ULONG,
        &mut drv_handle,
    );
    assert_eq!(ret, CKR_KEY_TYPE_INCONSISTENT);

    testtokn.finalize();
}

/// `CKM_IKE1_PRF_DERIVE` requires `CKA_KEY_TYPE` in the derive template
/// (§6.64.4).
#[cfg(feature = "ike")]
#[test]
#[parallel]
fn test_ike1_prf_derive_template_key_type() {
    let mut testtokn =
        TestToken::initialized("test_ike1_prf_tmpl_key_type", None);
    let session = testtokn.get_session(true);
    testtokn.login();

    let in_key: Vec<u8> = (1..33u16).map(|b| b as u8).collect();
    let gxy = [0x33u8; 24];
    let cky_i = [0x44u8; 8];
    let cky_r = [0x55u8; 8];
    let base_key = import_hmac_sha256_key(session, &in_key, true);
    let gxy_handle = import_generic_secret(session, &gxy, false);

    let params = CK_IKE1_PRF_DERIVE_PARAMS {
        prfMechanism: CKM_SHA256_HMAC,
        bHasPrevKey: CK_FALSE,
        hKeygxy: gxy_handle,
        hPrevKey: CK_INVALID_HANDLE,
        pCKYi: byte_ptr!(cky_i.as_ptr()),
        ulCKYiLen: cky_i.len() as CK_ULONG,
        pCKYr: byte_ptr!(cky_r.as_ptr()),
        ulCKYrLen: cky_r.len() as CK_ULONG,
        keyNumber: 0,
    };
    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_IKE1_PRF_DERIVE,
        pParameter: void_ptr!(&params),
        ulParameterLen: sizeof!(CK_IKE1_PRF_DERIVE_PARAMS),
    };
    // Template intentionally omits CKA_KEY_TYPE.
    let mut derive_template = make_attr_template(
        &[(CKA_CLASS, CKO_SECRET_KEY), (CKA_VALUE_LEN, 32)],
        &[],
        &[(CKA_SENSITIVE, false), (CKA_EXTRACTABLE, true)],
    );
    let mut drv_handle = CK_INVALID_HANDLE;
    let ret = fn_derive_key(
        session,
        &mut mechanism,
        base_key,
        derive_template.as_mut_ptr(),
        derive_template.len() as CK_ULONG,
        &mut drv_handle,
    );
    assert_eq!(ret, CKR_TEMPLATE_INCOMPLETE);

    testtokn.finalize();
}

/// `CKM_IKE1_EXTENDED_DERIVE` rejects an `hKeygxy` that is not
/// `CKK_GENERIC_SECRET` (§6.64.6).
#[cfg(feature = "ike")]
#[test]
#[parallel]
fn test_ike1_extended_derive_gxy_key_type() {
    let mut testtokn = TestToken::initialized("test_ike1_ext_gxy_type", None);
    let session = testtokn.get_session(true);
    testtokn.login();

    let in_key: Vec<u8> = (2..34u16).map(|b| b as u8).collect();
    let base_key = import_hmac_sha256_key(session, &in_key, true);
    let wrong_gxy = import_aes_key(session, false);

    let params = CK_IKE1_EXTENDED_DERIVE_PARAMS {
        prfMechanism: CKM_SHA256_HMAC,
        bHasKeygxy: CK_TRUE,
        hKeygxy: wrong_gxy,
        pExtraData: std::ptr::null_mut(),
        ulExtraDataLen: 0,
    };
    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_IKE1_EXTENDED_DERIVE,
        pParameter: void_ptr!(&params),
        ulParameterLen: sizeof!(CK_IKE1_EXTENDED_DERIVE_PARAMS),
    };
    let mut derive_template = make_attr_template(
        &[
            (CKA_CLASS, CKO_SECRET_KEY),
            (CKA_KEY_TYPE, CKK_GENERIC_SECRET),
            (CKA_VALUE_LEN, 32),
        ],
        &[],
        &[(CKA_SENSITIVE, false), (CKA_EXTRACTABLE, true)],
    );
    let mut drv_handle = CK_INVALID_HANDLE;
    let ret = fn_derive_key(
        session,
        &mut mechanism,
        base_key,
        derive_template.as_mut_ptr(),
        derive_template.len() as CK_ULONG,
        &mut drv_handle,
    );
    assert_eq!(ret, CKR_KEY_TYPE_INCONSISTENT);

    testtokn.finalize();
}

/// `CKM_IKE1_EXTENDED_DERIVE` defaults the derived key type to
/// `CKK_GENERIC_SECRET` when `CKA_KEY_TYPE` is absent from the template.
#[cfg(feature = "ike")]
#[test]
#[parallel]
fn test_ike1_extended_derive_default_output_type() {
    let mut testtokn =
        TestToken::initialized("test_ike1_ext_default_out_type", None);
    let session = testtokn.get_session(true);
    testtokn.login();

    let in_key: Vec<u8> = (2..34u16).map(|b| b as u8).collect();
    let extra = [0x66u8; 20];
    let base_key = import_hmac_sha256_key(session, &in_key, true);

    let params = CK_IKE1_EXTENDED_DERIVE_PARAMS {
        prfMechanism: CKM_SHA256_HMAC,
        bHasKeygxy: CK_FALSE,
        hKeygxy: CK_INVALID_HANDLE,
        pExtraData: byte_ptr!(extra.as_ptr()),
        ulExtraDataLen: extra.len() as CK_ULONG,
    };
    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_IKE1_EXTENDED_DERIVE,
        pParameter: void_ptr!(&params),
        ulParameterLen: sizeof!(CK_IKE1_EXTENDED_DERIVE_PARAMS),
    };

    let key_type = derive_and_read_type(session, base_key, &mut mechanism, 32);
    assert_eq!(key_type, CKK_GENERIC_SECRET);

    testtokn.finalize();
}

/// `CKM_IKE2_PRF_PLUS_DERIVE` defaults the derived key type to
/// `CKK_GENERIC_SECRET` when `CKA_KEY_TYPE` is absent from the template.
#[cfg(feature = "ike")]
#[test]
#[parallel]
fn test_ike2_prf_plus_derive_default_output_type() {
    let mut testtokn =
        TestToken::initialized("test_ike2_prf_default_out_type", None);
    let session = testtokn.get_session(true);
    testtokn.login();

    let in_key: Vec<u8> = (3..35u16).map(|b| b as u8).collect();
    let seed_data = [0x77u8; 24];
    let base_key = import_hmac_sha256_key(session, &in_key, true);

    let params = CK_IKE2_PRF_PLUS_DERIVE_PARAMS {
        prfMechanism: CKM_SHA256_HMAC,
        bHasSeedKey: CK_FALSE,
        hSeedKey: CK_INVALID_HANDLE,
        pSeedData: byte_ptr!(seed_data.as_ptr()),
        ulSeedDataLen: seed_data.len() as CK_ULONG,
    };
    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_IKE2_PRF_PLUS_DERIVE,
        pParameter: void_ptr!(&params),
        ulParameterLen: sizeof!(CK_IKE2_PRF_PLUS_DERIVE_PARAMS),
    };

    let key_type = derive_and_read_type(session, base_key, &mut mechanism, 32);
    assert_eq!(key_type, CKK_GENERIC_SECRET);

    testtokn.finalize();
}

/// `CKM_IKE2_PRF_PLUS_DERIVE` requires either a seed key or non-empty seed
/// data -- neither present must fail.
#[cfg(feature = "ike")]
#[test]
#[parallel]
fn test_ike2_prf_plus_derive_requires_seed() {
    let mut testtokn =
        TestToken::initialized("test_ike2_prf_plus_derive_noseed", None);
    let session = testtokn.get_session(true);
    testtokn.login();

    let in_key = [0x03u8; 32];
    let key_handle = import_generic_secret(session, &in_key, true);

    let params = CK_IKE2_PRF_PLUS_DERIVE_PARAMS {
        prfMechanism: CKM_SHA256_HMAC,
        bHasSeedKey: CK_FALSE,
        hSeedKey: CK_INVALID_HANDLE,
        pSeedData: std::ptr::null_mut(),
        ulSeedDataLen: 0,
    };
    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_IKE2_PRF_PLUS_DERIVE,
        pParameter: void_ptr!(&params),
        ulParameterLen: sizeof!(CK_IKE2_PRF_PLUS_DERIVE_PARAMS),
    };
    let mut derive_template = make_attr_template(
        &[
            (CKA_CLASS, CKO_SECRET_KEY),
            (CKA_KEY_TYPE, CKK_GENERIC_SECRET),
            (CKA_VALUE_LEN, 32),
        ],
        &[],
        &[(CKA_SENSITIVE, false), (CKA_EXTRACTABLE, true)],
    );
    let mut drv_handle = CK_INVALID_HANDLE;
    let ret = fn_derive_key(
        session,
        &mut mechanism,
        key_handle,
        derive_template.as_mut_ptr(),
        derive_template.len() as CK_ULONG,
        &mut drv_handle,
    );
    assert_eq!(ret, CKR_MECHANISM_PARAM_INVALID);

    testtokn.finalize();
}
