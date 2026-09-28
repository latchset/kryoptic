// Copyright 2024 Simo Sorce
// See LICENSE.txt file for terms

use crate::tests::*;

use crate::error::Result;
use crate::mechanism::Mechanism;
use crate::object::Object;
use crate::storage::StorageDBInfo;
use crate::Token;

use serial_test::parallel;

#[test]
#[parallel]
fn test_get_mechs() {
    let mut testtokn = TestToken::initialized("test_get_mechs", None);

    let mut count: CK_ULONG = 0;
    let ret = fn_get_mechanism_list(
        testtokn.get_slot(),
        std::ptr::null_mut(),
        &mut count,
    );
    assert_eq!(ret, CKR_OK);
    let mut mechs: Vec<CK_MECHANISM_TYPE> = vec![0; count as usize];
    let ret = fn_get_mechanism_list(
        testtokn.get_slot(),
        mechs.as_mut_ptr() as CK_MECHANISM_TYPE_PTR,
        &mut count,
    );
    assert_eq!(ret, CKR_OK);
    assert_eq!(true, count > 4);
    #[cfg(feature = "no_sha1")]
    {
        let mut sha1_found = 0;
        let sha1_list = [
            CKM_SHA1_RSA_PKCS,
            CKM_SHA1_RSA_X9_31,
            CKM_SHA1_RSA_PKCS_PSS,
            CKM_DSA_SHA1,
            CKM_SHA_1,
            CKM_SHA_1_HMAC,
            CKM_SHA_1_HMAC_GENERAL,
            CKM_SSL3_SHA1_MAC,
            CKM_SHA1_KEY_DERIVATION,
            CKM_PBE_SHA1_CAST128_CBC,
            CKM_PBE_SHA1_RC4_128,
            CKM_PBE_SHA1_RC4_40,
            CKM_PBE_SHA1_DES3_EDE_CBC,
            CKM_PBE_SHA1_DES2_EDE_CBC,
            CKM_PBE_SHA1_RC2_128_CBC,
            CKM_PBE_SHA1_RC2_40_CBC,
            CKM_PBA_SHA1_WITH_SHA1_HMAC,
            CKM_ECDSA_SHA1,
            CKM_SHA_1_KEY_GEN,
            CKM_PBE_SHA1_CAST128_CBC,
        ];
        for mech in &mechs {
            if sha1_list.contains(mech) {
                sha1_found += 1;
            }
        }
        assert_eq!(sha1_found, 0);
    }
    let mut info: CK_MECHANISM_INFO = Default::default();
    let ret = fn_get_mechanism_info(testtokn.get_slot(), mechs[0], &mut info);
    assert_eq!(ret, CKR_OK);

    testtokn.finalize();
}

/// Regression test: a mechanism must never be listed by
/// `C_GetMechanismList` if it then unconditionally fails on every real
/// use ("advertised then failing" -- PKCS#11 v3.2 §5.2). AWS-LC has no
/// feedback-mode KBKDF primitive at all, so under `awslc-fips` (which
/// routes `CKM_SP800_108_FEEDBACK_KDF` through the AWS-LC-backed
/// `crate::awslc::kbkdf`) it must be absent from the list entirely, not
/// merely fail when attempted. Plain `awslc` is unaffected -- non-FIPS
/// builds use `crate::native::sp800_108`, which genuinely supports it.
#[test]
#[parallel]
#[cfg(feature = "sp800_108")]
fn test_mechanism_list_omits_unsupported_feedback_kdf_under_awslc_fips() {
    let mut testtokn = TestToken::initialized(
        "test_mechanism_list_omits_unsupported_feedback_kdf_under_awslc_fips",
        None,
    );

    let mut count: CK_ULONG = 0;
    let ret = fn_get_mechanism_list(
        testtokn.get_slot(),
        std::ptr::null_mut(),
        &mut count,
    );
    assert_eq!(ret, CKR_OK);
    let mut mechs: Vec<CK_MECHANISM_TYPE> = vec![0; count as usize];
    let ret = fn_get_mechanism_list(
        testtokn.get_slot(),
        mechs.as_mut_ptr() as CK_MECHANISM_TYPE_PTR,
        &mut count,
    );
    assert_eq!(ret, CKR_OK);

    if cfg!(feature = "awslc-fips") {
        assert!(
            !mechs.contains(&CKM_SP800_108_FEEDBACK_KDF),
            "CKM_SP800_108_FEEDBACK_KDF must not be advertised under \
             awslc-fips, since AWS-LC has no feedback-mode KBKDF \
             primitive and every C_DeriveKey call on it would fail"
        );
    } else {
        assert!(
            mechs.contains(&CKM_SP800_108_FEEDBACK_KDF),
            "CKM_SP800_108_FEEDBACK_KDF should be usable (and therefore \
             listed) on this backend"
        );
    }

    testtokn.finalize();
}

/// Regression test: same "advertised then failing" anti-pattern as above
/// (PKCS#11 v3.2 §5.2), for `CKM_AES_CTS`. AWS-LC has no ciphertext-
/// stealing primitive at all, so it must be absent from the mechanism
/// list under both `awslc`/`awslc-fips`, not merely fail when attempted.
#[test]
#[parallel]
#[cfg(feature = "aes")]
fn test_mechanism_list_omits_unsupported_cts_under_awslc() {
    let mut testtokn = TestToken::initialized(
        "test_mechanism_list_omits_unsupported_cts_under_awslc",
        None,
    );

    let mut count: CK_ULONG = 0;
    let ret = fn_get_mechanism_list(
        testtokn.get_slot(),
        std::ptr::null_mut(),
        &mut count,
    );
    assert_eq!(ret, CKR_OK);
    let mut mechs: Vec<CK_MECHANISM_TYPE> = vec![0; count as usize];
    let ret = fn_get_mechanism_list(
        testtokn.get_slot(),
        mechs.as_mut_ptr() as CK_MECHANISM_TYPE_PTR,
        &mut count,
    );
    assert_eq!(ret, CKR_OK);

    if cfg!(any(feature = "awslc", feature = "awslc-fips")) {
        assert!(
            !mechs.contains(&CKM_AES_CTS),
            "CKM_AES_CTS must not be advertised under awslc/awslc-fips, \
             since AWS-LC has no ciphertext-stealing primitive and every \
             C_EncryptInit/C_DecryptInit call on it would fail"
        );
    } else {
        assert!(
            mechs.contains(&CKM_AES_CTS),
            "CKM_AES_CTS should be usable (and therefore listed) on this \
             backend"
        );
    }

    testtokn.finalize();
}

#[test]
#[parallel]
fn test_allow_mechs() {
    let dbname = String::from("test_allow_mechs");
    let mut testtokn = TestToken::new(dbname);
    testtokn.setup_db(None);
    let confname = format!("{}/test_allow_mechs.conf", TESTDIR);
    testtokn.make_config_file(
        &confname,
        Some(vec![String::from("CKM_AES_KEY_GEN")]),
        None,
    );

    let mut args =
        TestToken::make_init_args(Some(format!("kryoptic_conf={}", confname)));
    let args_ptr = &mut args as *mut CK_C_INITIALIZE_ARGS;
    let ret = fn_initialize(args_ptr as *mut std::ffi::c_void);
    assert_in!(ret, [CKR_OK, CKR_CRYPTOKI_ALREADY_INITIALIZED]);

    let mut count: CK_ULONG = 0;
    let ret = fn_get_mechanism_list(
        testtokn.get_slot(),
        std::ptr::null_mut(),
        &mut count,
    );
    assert_eq!(ret, CKR_OK);
    assert_eq!(count, 1);
    let mut mechs: Vec<CK_MECHANISM_TYPE> = vec![0; count as usize];
    let ret = fn_get_mechanism_list(
        testtokn.get_slot(),
        mechs.as_mut_ptr() as CK_MECHANISM_TYPE_PTR,
        &mut count,
    );
    assert_eq!(ret, CKR_OK);
    assert_eq!(mechs[0], CKM_AES_KEY_GEN);

    testtokn.finalize();
}

#[test]
#[parallel]
fn test_deny_mechs() {
    let dbname = String::from("test_deny_mechs");
    let mut testtokn = TestToken::new(dbname);
    testtokn.setup_db(None);
    let confname = format!("{}/test_deny_mechs.conf", TESTDIR);
    testtokn.make_config_file(
        &confname,
        Some(vec![String::from("DENY"), String::from("CKM_AES_KEY_GEN")]),
        None,
    );

    let mut args =
        TestToken::make_init_args(Some(format!("kryoptic_conf={}", confname)));
    let args_ptr = &mut args as *mut CK_C_INITIALIZE_ARGS;
    let ret = fn_initialize(args_ptr as *mut std::ffi::c_void);
    assert_in!(ret, [CKR_OK, CKR_CRYPTOKI_ALREADY_INITIALIZED]);

    let mut count: CK_ULONG = 0;
    let ret = fn_get_mechanism_list(
        testtokn.get_slot(),
        std::ptr::null_mut(),
        &mut count,
    );
    assert_eq!(ret, CKR_OK);
    let mut mechs: Vec<CK_MECHANISM_TYPE> = vec![0; count as usize];
    let ret = fn_get_mechanism_list(
        testtokn.get_slot(),
        mechs.as_mut_ptr() as CK_MECHANISM_TYPE_PTR,
        &mut count,
    );
    assert_eq!(ret, CKR_OK);
    assert_eq!(mechs.contains(&CKM_AES_KEY_GEN), false);

    testtokn.finalize();
}

#[test]
#[parallel]
fn test_mechanism_objects() {
    let mut testtokn = TestToken::initialized("test_mechanism_objects", None);
    let session = testtokn.get_session(true);

    let mut tmpl = make_attr_template(&[(CKA_CLASS, CKO_MECHANISM)], &[], &[]);

    let ret = fn_find_objects_init(
        session,
        tmpl.as_mut_ptr(),
        tmpl.len() as CK_ULONG,
    );
    assert_eq!(ret, CKR_OK);

    let mut handles = Vec::<CK_OBJECT_HANDLE>::with_capacity(64);
    let mut count = 64;
    while count == 64 {
        let mut ph = [CK_INVALID_HANDLE; 64];
        let ret = fn_find_objects(session, ph.as_mut_ptr(), 64, &mut count);
        assert_eq!(ret, CKR_OK);
        if count > 0 {
            handles.extend_from_slice(&ph[..count as usize]);
        }
    }

    let ret = fn_find_objects_final(session);
    assert_eq!(ret, CKR_OK);

    assert!(handles.len() > 0, "No mechanism objects found");

    for mech_type in [
        #[cfg(feature = "rsa")]
        CKM_RSA_PKCS_KEY_PAIR_GEN,
        #[cfg(feature = "hash")]
        CKM_SHA256,
        CKM_GENERIC_SECRET_KEY_GEN,
    ] {
        let mut search_tmpl = make_attr_template(
            &[(CKA_CLASS, CKO_MECHANISM), (CKA_MECHANISM_TYPE, mech_type)],
            &[],
            &[],
        );

        let ret = fn_find_objects_init(
            session,
            search_tmpl.as_mut_ptr(),
            search_tmpl.len() as CK_ULONG,
        );
        assert_eq!(ret, CKR_OK);

        let mut found_handle = CK_INVALID_HANDLE;
        let mut found_count = 0;
        let ret =
            fn_find_objects(session, &mut found_handle, 1, &mut found_count);
        assert_eq!(ret, CKR_OK);
        assert_eq!(found_count, 1);

        let ret = fn_find_objects_final(session);
        assert_eq!(ret, CKR_OK);
    }

    testtokn.finalize();
}

/// Regression test: C_GetMechanismList with a too-small list buffer must return
/// CKR_BUFFER_TOO_SMALL *and* report the real mechanism count in *pulCount (PKCS#11 v3.2 5.2),
/// not leave it at whatever the caller originally passed in.
#[test]
#[parallel]
fn test_get_mechanism_list_buffer_too_small_reports_required_len() {
    let mut testtokn = TestToken::initialized(
        "test_get_mechanism_list_buffer_too_small_reports_required_len",
        None,
    );

    let mut real_count: CK_ULONG = 0;
    let ret = fn_get_mechanism_list(
        testtokn.get_slot(),
        std::ptr::null_mut(),
        &mut real_count,
    );
    assert_eq!(ret, CKR_OK);
    assert!(real_count > 1);

    let mut mechs: Vec<CK_MECHANISM_TYPE> = vec![0; 1];
    let mut count: CK_ULONG = 1;
    let ret = fn_get_mechanism_list(
        testtokn.get_slot(),
        mechs.as_mut_ptr() as CK_MECHANISM_TYPE_PTR,
        &mut count,
    );
    assert_eq!(ret, CKR_BUFFER_TOO_SMALL);
    assert_eq!(
        count, real_count,
        "CKR_BUFFER_TOO_SMALL must report the real mechanism count ({}), \
         not leave *pulCount at whatever the caller originally passed in (1)",
        real_count
    );

    testtokn.finalize();
}

/// Regression test: C_GetSlotList with a too-small slot-list buffer must return
/// CKR_BUFFER_TOO_SMALL *and* report the real slot count in *pulCount.
#[test]
#[parallel]
fn test_get_slot_list_buffer_too_small_reports_required_len() {
    let mut testtokn = TestToken::initialized(
        "test_get_slot_list_buffer_too_small_reports_required_len",
        None,
    );

    let mut real_count: CK_ULONG = 0;
    let ret = fn_get_slot_list(CK_FALSE, std::ptr::null_mut(), &mut real_count);
    assert_eq!(ret, CKR_OK);
    assert!(real_count > 0);

    if real_count > 1 {
        let mut slots: Vec<CK_SLOT_ID> = vec![0; 1];
        let mut count: CK_ULONG = 1;
        let ret = fn_get_slot_list(
            CK_FALSE,
            slots.as_mut_ptr() as CK_SLOT_ID_PTR,
            &mut count,
        );
        assert_eq!(ret, CKR_BUFFER_TOO_SMALL);
        assert_eq!(
            count, real_count,
            "CKR_BUFFER_TOO_SMALL must report the real slot count ({}), \
             not leave *pulCount at whatever the caller originally passed in (1)",
            real_count
        );
    }

    testtokn.finalize();
}

/// Regression test: C_GetInterfaceList with a too-small interface-list buffer must return
/// CKR_BUFFER_TOO_SMALL *and* report the real interface count in *pulCount.
#[test]
#[parallel]
fn test_get_interface_list_buffer_too_small_reports_required_len() {
    let mut testtokn = TestToken::initialized(
        "test_get_interface_list_buffer_too_small_reports_required_len",
        None,
    );

    let mut real_count: CK_ULONG = 0;
    let ret = fn_get_interface_list(std::ptr::null_mut(), &mut real_count);
    assert_eq!(ret, CKR_OK);
    assert!(real_count > 1);

    let mut ifaces: Vec<CK_INTERFACE> = Vec::with_capacity(1);
    unsafe { ifaces.set_len(1) };
    let mut count: CK_ULONG = 1;
    let ret = fn_get_interface_list(ifaces.as_mut_ptr(), &mut count);
    assert_eq!(ret, CKR_BUFFER_TOO_SMALL);
    assert_eq!(
        count, real_count,
        "CKR_BUFFER_TOO_SMALL must report the real interface count ({}), \
         not leave *pulCount at whatever the caller originally passed in (1)",
        real_count
    );

    testtokn.finalize();
}

/// Regression test for the general "advertised but not implemented" bug
/// class R-02 and R-03 both represented: a mechanism appears in
/// `C_GetMechanismList` with a capability flag set, but the concrete
/// `Mechanism` implementation never actually overrides the trait method
/// that flag implies, so a real caller unconditionally hits
/// `CKR_MECHANISM_INVALID` -- the exact sentinel every default method on
/// `crate::mechanism::Mechanism` returns verbatim (see that trait's
/// definition: every one of its ~15 operation-constructor methods has a
/// default body of `Err(CKR_MECHANISM_INVALID)?`).
///
/// Drives every registered mechanism's entry-point constructor directly
/// against the internal `Mechanisms` registry (bypassing full
/// session/object setup, which is irrelevant to this check) with a
/// minimal, deliberately-underspecified key and null mechanism
/// parameters, and flags anything that returns that literal sentinel: a
/// real implementation should reject bad/missing input with a more
/// specific `CK_RV` (`CKR_ARGUMENTS_BAD`, `CKR_MECHANISM_PARAM_INVALID`,
/// `CKR_KEY_TYPE_INCONSISTENT`, etc.), matching the convention already
/// used throughout this codebase for "this specific variant isn't
/// supported" rejections (e.g. `crate::awslc::mldsa`'s
/// `CKH_DETERMINISTIC_REQUIRED` handling uses
/// `CKR_MECHANISM_PARAM_INVALID`, not `CKR_MECHANISM_INVALID`).
///
/// This would have caught R-02 (`CKM_SP800_108_FEEDBACK_KDF` advertised
/// under `awslc-fips` while routing to a `derive_operation` that
/// unconditionally rejected it) and R-03 (`CKM_AES_CTS` advertised while
/// AWS-LC has no primitive for it at all) before either was fixed by
/// de-registering the mechanism outright.
#[test]
#[parallel]
fn test_every_advertised_mechanism_has_a_real_implementation() {
    // Db-agnostic on purpose: this test only needs the registered
    // Mechanisms/ObjectFactories Token::new() always builds, not real
    // storage, so it must build under either db backend alone (mirroring
    // TestToken::get_default_db's own sqlitedb/nssdb selection, which
    // isn't reusable here since it's private). `cleanup_path` is the real
    // filesystem path to remove afterwards (nssdb's `dbargs` also carries
    // the `configDir=` key prefix, which isn't itself a path).
    std::fs::create_dir_all("test").unwrap();
    #[cfg(feature = "sqlitedb")]
    let (dbtype, dbargs, cleanup_path) = {
        let path = format!(
            "test/kryoptic_mech_coverage_test_{:x}.sql",
            std::process::id()
        );
        (crate::storage::sqlite::DBINFO.dbtype(), path.clone(), path)
    };
    #[cfg(all(not(feature = "sqlitedb"), feature = "nssdb"))]
    let (dbtype, dbargs, cleanup_path) = {
        let path = format!(
            "test/kryoptic_mech_coverage_test_{:x}",
            std::process::id()
        );
        (
            crate::storage::nssdb::DBINFO.dbtype(),
            format!("configDir={}/", path),
            path,
        )
    };
    let _ = std::fs::remove_file(&cleanup_path);
    let _ = std::fs::remove_dir_all(&cleanup_path);
    let token = Token::new(dbtype, Some(dbargs.clone())).expect("Token::new");
    let mechs = token.get_mechanisms();
    let factories = token.get_object_factories();

    // A generic-secret-key factory, used only to obtain *some*
    // `&Box<dyn ObjectFactory>` for the wrap/unwrap/encapsulate/decapsulate
    // probes below -- none of those calls are expected to succeed with
    // this deliberately minimal input, they only need a factory reference
    // to reach the mechanism's own dispatch logic.
    let class: CK_ULONG = CKO_SECRET_KEY;
    let key_type: CK_ULONG = CKK_GENERIC_SECRET;
    let generic_template = [
        CK_ATTRIBUTE {
            type_: CKA_CLASS,
            pValue: &class as *const CK_ULONG as CK_VOID_PTR,
            ulValueLen: std::mem::size_of::<CK_ULONG>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_KEY_TYPE,
            pValue: &key_type as *const CK_ULONG as CK_VOID_PTR,
            ulValueLen: std::mem::size_of::<CK_ULONG>() as CK_ULONG,
        },
    ];
    let factory = factories
        .get_obj_factory_from_key_template(&generic_template)
        .expect("generic-secret factory must exist");

    // Deliberately minimal: no CKA_VALUE, no CKA_MODULUS, nothing --
    // exercising the "operation constructor rejects this before even
    // reaching AWS-LC" path, not a real crypto operation.
    let dummy_key = Object::new(CKO_SECRET_KEY);

    fn is_unimplemented_stub<T>(r: &Result<T>) -> bool {
        matches!(r, Err(e) if e.rv() == CKR_MECHANISM_INVALID)
    }

    let mut violations: Vec<(CK_MECHANISM_TYPE, &'static str)> = Vec::new();
    for mech_type in mechs.list() {
        let entry = mechs.get(mech_type).expect("just listed");
        let flags = entry.info().flags;
        let mech = CK_MECHANISM {
            mechanism: mech_type,
            pParameter: std::ptr::null_mut(),
            ulParameterLen: 0,
        };

        if flags & CKF_ENCRYPT != 0
            && is_unimplemented_stub(&entry.encryption_new(&mech, &dummy_key))
        {
            violations.push((mech_type, "encrypt"));
        }
        if flags & CKF_DECRYPT != 0
            && is_unimplemented_stub(&entry.decryption_new(&mech, &dummy_key))
        {
            violations.push((mech_type, "decrypt"));
        }
        if flags & CKF_DIGEST != 0
            && is_unimplemented_stub(&entry.digest_new(&mech))
        {
            violations.push((mech_type, "digest"));
        }
        if flags & CKF_SIGN != 0
            && is_unimplemented_stub(&entry.sign_new(&mech, &dummy_key))
        {
            violations.push((mech_type, "sign"));
        }
        if flags & CKF_VERIFY != 0
            && is_unimplemented_stub(&entry.verify_new(&mech, &dummy_key))
        {
            violations.push((mech_type, "verify"));
        }
        if flags & CKF_DERIVE != 0
            && is_unimplemented_stub(&entry.derive_operation(&mech))
        {
            violations.push((mech_type, "derive"));
        }
        if flags & CKF_GENERATE != 0
            && is_unimplemented_stub(&entry.generate_key(
                &mech,
                &[],
                mechs,
                factories,
            ))
        {
            violations.push((mech_type, "generate"));
        }
        if flags & CKF_GENERATE_KEY_PAIR != 0
            && is_unimplemented_stub(&entry.generate_keypair(&mech, &[], &[]))
        {
            violations.push((mech_type, "generate_keypair"));
        }
        if flags & CKF_WRAP != 0 {
            let mut out: [u8; 0] = [];
            let r = entry
                .wrap_key(&mech, &dummy_key, &dummy_key, &mut out, factory);
            if is_unimplemented_stub(&r) {
                violations.push((mech_type, "wrap"));
            }
        }
        if flags & CKF_UNWRAP != 0
            && is_unimplemented_stub(&entry.unwrap_key(
                &mech,
                &dummy_key,
                &[],
                &[],
                factory,
            ))
        {
            violations.push((mech_type, "unwrap"));
        }
        if flags & CKF_ENCAPSULATE != 0 {
            let mut out: [u8; 0] = [];
            let r =
                entry.encapsulate(&mech, &dummy_key, factory, &[], &mut out);
            if is_unimplemented_stub(&r) {
                violations.push((mech_type, "encapsulate"));
            }
        }
        if flags & CKF_DECAPSULATE != 0
            && is_unimplemented_stub(&entry.decapsulate(
                &mech,
                &dummy_key,
                factory,
                &[],
                &[],
            ))
        {
            violations.push((mech_type, "decapsulate"));
        }
    }

    drop(token);
    let _ = std::fs::remove_file(&cleanup_path);
    let _ = std::fs::remove_dir_all(&cleanup_path);

    assert!(
        violations.is_empty(),
        "mechanisms advertised via C_GetMechanismList with a capability \
         flag set, but whose corresponding operation constructor is the \
         unimplemented trait default (always CKR_MECHANISM_INVALID \
         regardless of input): {:?}",
        violations
    );
}
