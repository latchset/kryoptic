// Copyright 2023 Simo Sorce
// See LICENSE.txt file for terms

use super::*;
use hex;
use std::ffi::CString;
use std::sync::Once;

#[macro_use]
mod util;
use util::*;

mod token;

/* note that the following concoction to sync threads is not entirely race free
 * as it assumes all tests initialize before all of the others complete. */
static FINI: RwLock<u64> = RwLock::new(0);
static SYNC: RwLock<u64> = RwLock::new(0);

static INIT: Once = Once::new();
fn test_finalizer() -> Option<RwLockWriteGuard<'static, u64>> {
    let mut winner: Option<RwLockWriteGuard<u64>> = None;
    INIT.call_once(|| {
        winner = Some(FINI.write().unwrap());
    });
    winner
}

struct Slots {
    id: u64,
}

static SLOTS: RwLock<Slots> = RwLock::new(Slots { id: 0 });

struct TestToken<'a> {
    slot: CK_SLOT_ID,
    filename: &'a str,
    finalize: Option<RwLockWriteGuard<'a, u64>>,
    sync: Option<RwLockReadGuard<'a, u64>>,
    session: CK_SESSION_HANDLE,
    session_rw: bool,
}

impl TestToken<'_> {
    fn new<'a>(filename: &'a str) -> TestToken {
        let mut slots = SLOTS.write().unwrap();
        slots.id += 1;
        TestToken {
            slot: slots.id,
            filename: filename,
            finalize: test_finalizer(),
            sync: Some(SYNC.read().unwrap()),
            session: CK_INVALID_HANDLE,
            session_rw: false,
        }
    }

    fn setup_db<'a>(&mut self, source: Option<&'a str>) {
        let basic = "testdata/test_basic.json";
        let filename = match source {
            Some(s) => s,
            None => basic,
        };
        let test_data = storage::json::JsonToken::load(filename).unwrap();
        if self.filename.ends_with(".json") {
            test_data.save(self.filename).unwrap();
        } else if self.filename.ends_with(".sql") {
            let mut cache = storage::memory::memory();
            test_data.prime_cache(&mut cache).unwrap();
            let mut sql = storage::sqlite::sqlite();
            match sql.open(&self.filename.to_string()) {
                Ok(()) => (),
                Err(err) => match err {
                    KError::RvError(ref e) => {
                        if e.rv != CKR_CRYPTOKI_NOT_INITIALIZED {
                            panic!("Unexpected error: {}", e.rv);
                        }
                    }
                    _ => panic!("Unexpected error: {}", err),
                },
            }
            /* reset db in all cases */
            sql.reinit().unwrap();
            let objects = cache.search(&[]).unwrap();
            for obj in objects {
                let uid = obj.get_attr_as_string(CKA_UNIQUE_ID).unwrap();
                sql.store(&uid, obj.clone()).unwrap()
            }
        } else {
            panic!("Unknown file type");
        }
    }

    fn get_slot(&self) -> CK_SLOT_ID {
        self.slot
    }

    fn make_init_string(&self) -> String {
        format!("{}:{}", self.filename, self.slot)
    }

    fn make_init_args(&self) -> CK_C_INITIALIZE_ARGS {
        let reserved: String = self.make_init_string();

        CK_C_INITIALIZE_ARGS {
            CreateMutex: None,
            DestroyMutex: None,
            LockMutex: None,
            UnlockMutex: None,
            flags: 0,
            pReserved: CString::new(reserved).unwrap().into_raw()
                as *mut std::ffi::c_void,
        }
    }

    fn make_empty_init_args(&self) -> CK_C_INITIALIZE_ARGS {
        CK_C_INITIALIZE_ARGS {
            CreateMutex: None,
            DestroyMutex: None,
            LockMutex: None,
            UnlockMutex: None,
            flags: 0,
            pReserved: std::ptr::null_mut(),
        }
    }

    fn finalize(&mut self) {
        self.logout();
        self.close_session();
        if self.finalize.is_none() {
            self.sync = None;
            /* wait until we can read, which means the winner finalized the module */
            drop(FINI.read().unwrap());
        } else {
            self.sync = None;
            /* wait for all others to complete */
            drop(SYNC.write().unwrap());
            let ret = fn_finalize(std::ptr::null_mut());
            assert_eq!(ret, CKR_OK);
            /* winner finalized and completed the tests */
            self.finalize = None;
        }
        std::fs::remove_file(self.filename).unwrap_or(());
    }

    fn initialized<'a>(
        filename: &'a str,
        db: Option<&'a str>,
    ) -> TestToken<'a> {
        let mut td = Self::new(filename);
        td.setup_db(db);

        let mut args = td.make_init_args();
        let args_ptr = &mut args as *mut CK_C_INITIALIZE_ARGS;
        let ret = fn_initialize(args_ptr as *mut std::ffi::c_void);
        assert_eq!(ret, CKR_OK);
        td
    }

    fn get_session(&mut self, rw: bool) -> CK_SESSION_HANDLE {
        if self.session != CK_INVALID_HANDLE {
            if rw == self.session_rw {
                return self.session;
            }
            self.close_session();
        }
        let mut flags = CKF_SERIAL_SESSION;
        if rw {
            flags |= CKF_RW_SESSION;
        };
        let ret = fn_open_session(
            self.get_slot(),
            flags,
            std::ptr::null_mut(),
            None,
            &mut self.session,
        );
        assert_eq!(ret, CKR_OK);
        self.session
    }

    fn login(&mut self) {
        let pin = "12345678";
        let ret = fn_login(
            self.session,
            CKU_USER,
            pin.as_ptr() as *mut _,
            pin.len() as CK_ULONG,
        );
        assert_eq!(ret, CKR_OK);
    }

    fn logout(&self) {
        if self.session != CK_INVALID_HANDLE {
            fn_logout(self.session);
        }
    }

    fn close_session(&mut self) {
        if self.session != CK_INVALID_HANDLE {
            let ret = fn_close_session(self.session);
            assert_eq!(ret, CKR_OK);
            self.session = CK_INVALID_HANDLE;
        }
    }
}

mod random;

mod login;

mod attrs;

mod objects;

#[test]
fn test_create_ec_objects() {
    let mut testtokn =
        TestToken::initialized("test_create_ec_objects.sql", None);
    let session = testtokn.get_session(true);

    /* login */
    testtokn.login();

    let mut handle: CK_ULONG = CK_INVALID_HANDLE;

    let mut class = CKO_PUBLIC_KEY;
    let mut ktype = CKK_EC;
    let mut verify: CK_BBOOL = CK_TRUE;
    let label = "EC Public Signature Key";
    let point_hex = "041b803bf0586decf25616e879b0399aa3daab60916fc76c9b6c687fc1454cba90d5f15aeb36e7070cffb4966499b71b389453c0075203fa047d4f3e44343edc84fb793bf1b8ca94dd3f293afbe68e3be93f1245be9fb71be3c50f1263bc12d516";
    let params_hex = "06052b81040022";
    let point = hex::decode(point_hex).expect("Failed to decode hex point");
    let params = hex::decode(params_hex).expect("Failed to decode hex params");
    let mut template = vec![
        make_attribute!(CKA_CLASS, &mut class as *mut _, CK_ULONG_SIZE),
        make_attribute!(CKA_KEY_TYPE, &mut ktype as *mut _, CK_ULONG_SIZE),
        make_attribute!(CKA_VERIFY, &mut verify as *mut _, CK_BBOOL_SIZE),
        make_attribute!(
            CKA_LABEL,
            label.as_ptr() as *mut std::ffi::c_void,
            label.len()
        ),
        make_attribute!(
            CKA_EC_POINT,
            point.as_ptr() as *mut std::ffi::c_void,
            point.len()
        ),
        make_attribute!(
            CKA_EC_PARAMS,
            params.as_ptr() as *mut std::ffi::c_void,
            params.len()
        ),
    ];

    let ret = fn_create_object(
        session,
        template.as_mut_ptr(),
        template.len() as CK_ULONG,
        &mut handle,
    );
    assert_eq!(ret, CKR_OK);

    /* Private EC key */
    class = CKO_PRIVATE_KEY;
    let mut ktype = CKK_EC;
    let mut sign: CK_BBOOL = CK_TRUE;
    let label = "EC Private Signature Key";
    let value_hex = "4a77d1245d2c4751ff178040cc9e527b4d6cbb067b8fb01265b854fa581fd62dadc706025cbf515d80fd226f8f552f34";
    let value = hex::decode(value_hex).expect("Failed to decode value");
    template = vec![
        make_attribute!(CKA_CLASS, &mut class as *mut _, CK_ULONG_SIZE),
        make_attribute!(CKA_KEY_TYPE, &mut ktype as *mut _, CK_ULONG_SIZE),
        make_attribute!(CKA_SIGN, &mut sign as *mut _, CK_BBOOL_SIZE),
        make_attribute!(
            CKA_LABEL,
            label.as_ptr() as *mut std::ffi::c_void,
            label.len()
        ),
        make_attribute!(
            CKA_VALUE,
            value.as_ptr() as *mut std::ffi::c_void,
            value.len()
        ),
        make_attribute!(
            CKA_EC_PARAMS,
            params.as_ptr() as *mut std::ffi::c_void,
            params.len()
        ),
    ];

    let ret = fn_create_object(
        session,
        template.as_mut_ptr(),
        template.len() as CK_ULONG,
        &mut handle,
    );
    assert_eq!(ret, CKR_OK);

    testtokn.finalize();
}

mod init;

mod mechs;

mod aes;

mod rsa;

mod session;

#[test]
fn test_ecc_operations() {
    let mut testtokn = TestToken::initialized(
        "test_ecc_operations.sql",
        Some("testdata/test_ecc_operations.json"),
    );
    let session = testtokn.get_session(true);

    /* login */
    testtokn.login();

    /* private key */
    let mut handle: CK_ULONG = CK_INVALID_HANDLE;
    let mut template = vec![make_attribute!(
        CKA_UNIQUE_ID,
        CString::new("5").unwrap().into_raw(),
        1
    )];
    let mut ret = fn_find_objects_init(session, template.as_mut_ptr(), 1);
    assert_eq!(ret, CKR_OK);
    let mut count: CK_ULONG = 0;
    ret = fn_find_objects(session, &mut handle, 1, &mut count);
    assert_eq!(ret, CKR_OK);
    assert_eq!(count, 1);
    assert_ne!(handle, CK_INVALID_HANDLE);
    ret = fn_find_objects_final(session);
    assert_eq!(ret, CKR_OK);

    /* sign init */
    let mut mechanism: CK_MECHANISM = CK_MECHANISM {
        mechanism: CKM_ECDSA,
        pParameter: std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    ret = fn_sign_init(session, &mut mechanism, handle);
    assert_eq!(ret, CKR_OK);

    /* a second invocation should return an error */
    ret = fn_sign_init(session, &mut mechanism, handle);
    assert_eq!(ret, CKR_OPERATION_ACTIVE);

    let data = "plaintext";
    let sign: [u8; 64] = [0; 64];
    let mut sign_len: CK_ULONG = 64;
    ret = fn_sign(
        session,
        CString::new(data).unwrap().into_raw() as *mut u8,
        data.len() as CK_ULONG,
        sign.as_ptr() as *mut _,
        &mut sign_len,
    );
    assert_eq!(ret, CKR_OK);
    assert_eq!(sign_len, 64);

    /* a second invocation should return an error */
    ret = fn_sign(
        session,
        CString::new(data).unwrap().into_raw() as *mut u8,
        data.len() as CK_ULONG,
        sign.as_ptr() as *mut _,
        &mut sign_len,
    );
    assert_eq!(ret, CKR_OPERATION_NOT_INITIALIZED);

    /* test that signature verification works */
    template = vec![make_attribute!(
        CKA_UNIQUE_ID,
        CString::new("4").unwrap().into_raw(),
        1
    )];
    ret = fn_find_objects_init(session, template.as_mut_ptr(), 1);
    assert_eq!(ret, CKR_OK);
    let mut count: CK_ULONG = 0;
    ret = fn_find_objects(session, &mut handle, 1, &mut count);
    assert_eq!(ret, CKR_OK);
    assert_eq!(count, 1);
    assert_ne!(handle, CK_INVALID_HANDLE);
    ret = fn_find_objects_final(session);
    assert_eq!(ret, CKR_OK);

    ret = fn_verify_init(session, &mut mechanism, handle);
    assert_eq!(ret, CKR_OK);

    ret = fn_verify(
        session,
        data.as_ptr() as *mut u8,
        data.len() as CK_ULONG,
        sign.as_ptr() as *mut u8,
        sign_len,
    );
    assert_eq!(ret, CKR_OK);

    /* P-521 private key */
    let mut handle: CK_ULONG = CK_INVALID_HANDLE;
    let mut template = vec![make_attribute!(
        CKA_UNIQUE_ID,
        CString::new("7").unwrap().into_raw(),
        1
    )];
    ret = fn_find_objects_init(session, template.as_mut_ptr(), 1);
    assert_eq!(ret, CKR_OK);
    let mut count: CK_ULONG = 0;
    ret = fn_find_objects(session, &mut handle, 1, &mut count);
    assert_eq!(ret, CKR_OK);
    assert_eq!(count, 1);
    assert_ne!(handle, CK_INVALID_HANDLE);
    ret = fn_find_objects_final(session);
    assert_eq!(ret, CKR_OK);

    /* sign init */
    let mut mechanism: CK_MECHANISM = CK_MECHANISM {
        mechanism: CKM_ECDSA,
        pParameter: std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    ret = fn_sign_init(session, &mut mechanism, handle);
    assert_eq!(ret, CKR_OK);

    /* a second invocation should return an error */
    ret = fn_sign_init(session, &mut mechanism, handle);
    assert_eq!(ret, CKR_OPERATION_ACTIVE);

    let data = "plaintext";
    let sign: [u8; 132] = [0; 132];
    let mut sign_len: CK_ULONG = 132;
    ret = fn_sign(
        session,
        CString::new(data).unwrap().into_raw() as *mut u8,
        data.len() as CK_ULONG,
        sign.as_ptr() as *mut _,
        &mut sign_len,
    );
    assert_eq!(ret, CKR_OK);
    assert_eq!(sign_len, 132);

    /* a second invocation should return an error */
    ret = fn_sign(
        session,
        CString::new(data).unwrap().into_raw() as *mut u8,
        data.len() as CK_ULONG,
        sign.as_ptr() as *mut _,
        &mut sign_len,
    );
    assert_eq!(ret, CKR_OPERATION_NOT_INITIALIZED);

    /* test that signature verification works */
    template = vec![make_attribute!(
        CKA_UNIQUE_ID,
        CString::new("6").unwrap().into_raw(),
        1
    )];
    ret = fn_find_objects_init(session, template.as_mut_ptr(), 1);
    assert_eq!(ret, CKR_OK);
    let mut count: CK_ULONG = 0;
    ret = fn_find_objects(session, &mut handle, 1, &mut count);
    assert_eq!(ret, CKR_OK);
    assert_eq!(count, 1);
    assert_ne!(handle, CK_INVALID_HANDLE);
    ret = fn_find_objects_final(session);
    assert_eq!(ret, CKR_OK);

    ret = fn_verify_init(session, &mut mechanism, handle);
    assert_eq!(ret, CKR_OK);

    ret = fn_verify(
        session,
        data.as_ptr() as *mut u8,
        data.len() as CK_ULONG,
        sign.as_ptr() as *mut u8,
        sign_len,
    );
    assert_eq!(ret, CKR_OK);

    testtokn.finalize();
}

#[test]
fn test_hashes_digest() {
    let mut testtokn = TestToken::initialized(
        "test_hashes.sql",
        Some("testdata/test_hashes.json"),
    );
    let session = testtokn.get_session(false);

    /* get test data */
    let mut handle: CK_ULONG = CK_INVALID_HANDLE;
    let mut template = vec![make_attribute!(
        CKA_UNIQUE_ID,
        CString::new("2").unwrap().into_raw(),
        1
    )];
    let mut ret = fn_find_objects_init(session, template.as_mut_ptr(), 1);
    assert_eq!(ret, CKR_OK);
    let mut count: CK_ULONG = 0;
    ret = fn_find_objects(session, &mut handle, 1, &mut count);
    assert_eq!(ret, CKR_OK);
    ret = fn_find_objects_final(session);
    assert_eq!(ret, CKR_OK);

    /* get values */
    let mut hash: [u8; 32] = [0; 32];
    let mut value: [u8; 32] = [0; 32];
    template.clear();
    template.push(make_attribute!(CKA_VALUE, value.as_mut_ptr(), value.len()));
    template.push(make_attribute!(
        CKA_OBJECT_ID,
        hash.as_mut_ptr(),
        hash.len()
    ));
    ret = fn_get_attribute_value(
        session,
        handle,
        template.as_mut_ptr(),
        template.len() as u64,
    );
    assert_eq!(ret, CKR_OK);

    let value_len = template[0].ulValueLen;

    /* one shot digest */
    let mut mechanism: CK_MECHANISM = CK_MECHANISM {
        mechanism: CKM_SHA256,
        pParameter: std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    ret = fn_digest_init(session, &mut mechanism);
    assert_eq!(ret, CKR_OK);

    let mut digest: [u8; 32] = [0; 32];
    let mut digest_len: CK_ULONG = digest.len() as CK_ULONG;
    ret = fn_digest(
        session,
        value.as_mut_ptr(),
        value_len,
        digest.as_mut_ptr(),
        &mut digest_len,
    );
    assert_eq!(ret, CKR_OK);
    assert_eq!(hash, digest);

    /* update digest */
    ret = fn_digest_init(session, &mut mechanism);
    assert_eq!(ret, CKR_OK);

    ret = fn_digest_update(session, value.as_mut_ptr(), value_len);
    assert_eq!(ret, CKR_OK);

    let mut digest2_len: CK_ULONG = 0;
    ret = fn_digest_final(session, std::ptr::null_mut(), &mut digest2_len);
    assert_eq!(ret, CKR_OK);
    assert_eq!(digest_len, digest2_len);

    let mut digest2: [u8; 32] = [0; 32];
    ret = fn_digest_final(session, digest2.as_mut_ptr(), &mut digest2_len);
    assert_eq!(ret, CKR_OK);
    assert_eq!(hash, digest);

    /* ==== SHA 384 ==== */

    /* get test data */
    let mut handle: CK_ULONG = CK_INVALID_HANDLE;
    let mut template = vec![make_attribute!(
        CKA_UNIQUE_ID,
        CString::new("3").unwrap().into_raw(),
        1
    )];
    ret = fn_find_objects_init(session, template.as_mut_ptr(), 1);
    assert_eq!(ret, CKR_OK);
    let mut count: CK_ULONG = 0;
    ret = fn_find_objects(session, &mut handle, 1, &mut count);
    assert_eq!(ret, CKR_OK);
    ret = fn_find_objects_final(session);
    assert_eq!(ret, CKR_OK);

    /* get values */
    let mut hash: [u8; 48] = [0; 48];
    let mut value: [u8; 48] = [0; 48];
    template.clear();
    template.push(make_attribute!(CKA_VALUE, value.as_mut_ptr(), value.len()));
    template.push(make_attribute!(
        CKA_OBJECT_ID,
        hash.as_mut_ptr(),
        hash.len()
    ));
    ret = fn_get_attribute_value(
        session,
        handle,
        template.as_mut_ptr(),
        template.len() as u64,
    );
    assert_eq!(ret, CKR_OK);

    let value_len = template[0].ulValueLen;

    /* one shot digest */
    let mut mechanism: CK_MECHANISM = CK_MECHANISM {
        mechanism: CKM_SHA384,
        pParameter: std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    ret = fn_digest_init(session, &mut mechanism);
    assert_eq!(ret, CKR_OK);

    let mut digest: [u8; 48] = [0; 48];
    let mut digest_len: CK_ULONG = digest.len() as CK_ULONG;
    ret = fn_digest(
        session,
        value.as_mut_ptr(),
        value_len,
        digest.as_mut_ptr(),
        &mut digest_len,
    );
    assert_eq!(ret, CKR_OK);
    assert_eq!(hash, digest);

    /* ==== SHA 512 ==== */

    /* get test data */
    let mut handle: CK_ULONG = CK_INVALID_HANDLE;
    let mut template = vec![make_attribute!(
        CKA_UNIQUE_ID,
        CString::new("4").unwrap().into_raw(),
        1
    )];
    ret = fn_find_objects_init(session, template.as_mut_ptr(), 1);
    assert_eq!(ret, CKR_OK);
    let mut count: CK_ULONG = 0;
    ret = fn_find_objects(session, &mut handle, 1, &mut count);
    assert_eq!(ret, CKR_OK);
    ret = fn_find_objects_final(session);
    assert_eq!(ret, CKR_OK);

    /* get values */
    let mut hash: [u8; 64] = [0; 64];
    let mut value: [u8; 64] = [0; 64];
    template.clear();
    template.push(make_attribute!(CKA_VALUE, value.as_mut_ptr(), value.len()));
    template.push(make_attribute!(
        CKA_OBJECT_ID,
        hash.as_mut_ptr(),
        hash.len()
    ));
    ret = fn_get_attribute_value(
        session,
        handle,
        template.as_mut_ptr(),
        template.len() as u64,
    );
    assert_eq!(ret, CKR_OK);

    let value_len = template[0].ulValueLen;

    /* one shot digest */
    let mut mechanism: CK_MECHANISM = CK_MECHANISM {
        mechanism: CKM_SHA512,
        pParameter: std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    ret = fn_digest_init(session, &mut mechanism);
    assert_eq!(ret, CKR_OK);

    let mut digest: [u8; 64] = [0; 64];
    let mut digest_len: CK_ULONG = digest.len() as CK_ULONG;
    ret = fn_digest(
        session,
        value.as_mut_ptr(),
        value_len,
        digest.as_mut_ptr(),
        &mut digest_len,
    );
    assert_eq!(ret, CKR_OK);
    assert_eq!(hash, digest);

    /* ==== SHA 1 ==== */

    /* get test data */
    let mut handle: CK_ULONG = CK_INVALID_HANDLE;
    let mut template = vec![make_attribute!(
        CKA_UNIQUE_ID,
        CString::new("5").unwrap().into_raw(),
        1
    )];
    ret = fn_find_objects_init(session, template.as_mut_ptr(), 1);
    assert_eq!(ret, CKR_OK);
    let mut count: CK_ULONG = 0;
    ret = fn_find_objects(session, &mut handle, 1, &mut count);
    assert_eq!(ret, CKR_OK);
    ret = fn_find_objects_final(session);
    assert_eq!(ret, CKR_OK);

    /* get values */
    let mut hash: [u8; 20] = [0; 20];
    let mut value: [u8; 20] = [0; 20];
    template.clear();
    template.push(make_attribute!(CKA_VALUE, value.as_mut_ptr(), value.len()));
    template.push(make_attribute!(
        CKA_OBJECT_ID,
        hash.as_mut_ptr(),
        hash.len()
    ));
    ret = fn_get_attribute_value(
        session,
        handle,
        template.as_mut_ptr(),
        template.len() as u64,
    );
    assert_eq!(ret, CKR_OK);

    let value_len = template[0].ulValueLen;

    /* one shot digest */
    let mut mechanism: CK_MECHANISM = CK_MECHANISM {
        mechanism: CKM_SHA_1,
        pParameter: std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    ret = fn_digest_init(session, &mut mechanism);
    assert_eq!(ret, CKR_OK);

    let mut digest: [u8; 20] = [0; 20];
    let mut digest_len: CK_ULONG = digest.len() as CK_ULONG;
    ret = fn_digest(
        session,
        value.as_mut_ptr(),
        value_len,
        digest.as_mut_ptr(),
        &mut digest_len,
    );
    assert_eq!(ret, CKR_OK);
    assert_eq!(hash, digest);

    testtokn.finalize();
}

struct TestCase {
    value: Vec<u8>,
    result: Vec<u8>,
}

/* name in CKA_APPLICATION
 * value in CKA_VALUE
 * result in CKA_OBJECT_ID
 * additional value (like an IV) in CKA_LABEL as a Base64 encoded text
 */

fn get_test_case_data(session: CK_SESSION_HANDLE, name: &str) -> TestCase {
    let mut handle: CK_ULONG = CK_INVALID_HANDLE;
    let mut template = vec![make_attribute!(
        CKA_APPLICATION,
        CString::new(name).unwrap().into_raw(),
        name.len()
    )];
    let mut ret = fn_find_objects_init(session, template.as_mut_ptr(), 1);
    assert_eq!(ret, CKR_OK);
    let mut count: CK_ULONG = 0;
    ret = fn_find_objects(session, &mut handle, 1, &mut count);
    assert_eq!(ret, CKR_OK);
    ret = fn_find_objects_final(session);
    assert_eq!(ret, CKR_OK);

    /* get values */
    template.clear();
    template.push(make_attribute!(CKA_VALUE, std::ptr::null_mut(), 0));
    template.push(make_attribute!(CKA_OBJECT_ID, std::ptr::null_mut(), 0));
    ret = fn_get_attribute_value(
        session,
        handle,
        template.as_mut_ptr(),
        template.len() as CK_ULONG,
    );
    assert_eq!(ret, CKR_OK);
    let mut tc = TestCase {
        value: vec![0; template[0].ulValueLen as usize],
        result: vec![0; template[1].ulValueLen as usize],
    };
    template[0].pValue = tc.value.as_mut_ptr() as CK_VOID_PTR;
    template[1].pValue = tc.result.as_mut_ptr() as CK_VOID_PTR;
    ret = fn_get_attribute_value(
        session,
        handle,
        template.as_mut_ptr(),
        template.len() as CK_ULONG,
    );
    assert_eq!(ret, CKR_OK);

    tc
}

#[test]
fn test_signatures() {
    /* Test Vectors from python cryptography's pkcs1v15sign-vectors.txt */
    let mut testtokn = TestToken::initialized(
        "test_sign_verify.sql",
        Some("testdata/test_sign_verify.json"),
    );
    let session = testtokn.get_session(false);

    /* login */
    testtokn.login();

    /* ### CKM_RSA_PKCS ### */

    /* get test data */
    let mut testcase = get_test_case_data(session, "CKM_RSA_PKCS");
    let pri_key_handle =
        match get_test_key_handle(session, "Example 15", CKO_PRIVATE_KEY) {
            Ok(k) => k,
            Err(e) => panic!("{}", e),
        };
    let pub_key_handle =
        match get_test_key_handle(session, "Example 15", CKO_PUBLIC_KEY) {
            Ok(k) => k,
            Err(e) => panic!("{}", e),
        };

    /* verify test vector */
    let mut mechanism: CK_MECHANISM = CK_MECHANISM {
        mechanism: CKM_SHA1_RSA_PKCS,
        pParameter: std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    let ret = sig_verify(
        session,
        pub_key_handle,
        &mut testcase.value,
        &mut testcase.result,
        &mut mechanism,
    );
    assert_eq!(ret, CKR_OK);

    let result = match sig_gen(
        session,
        pri_key_handle,
        &mut testcase.value,
        &mut mechanism,
    ) {
        Ok(r) => r,
        Err(e) => panic!("f{e}"),
    };
    assert_eq!(testcase.result, result);

    let result = match sig_gen_multipart(
        session,
        pri_key_handle,
        &mut testcase.value,
        &mut mechanism,
    ) {
        Ok(r) => r,
        Err(e) => panic!("f{e}"),
    };
    assert_eq!(testcase.result, result);

    /* ### CKM_ECDSA ### */

    /* get test data */
    let mut testcase = get_test_case_data(session, "CKM_ECDSA_SHA512");
    let pri_key_handle = match get_test_key_handle(
        session,
        "FIPS_186-3/SigGen: [P-521,SHA-512]",
        CKO_PRIVATE_KEY,
    ) {
        Ok(k) => k,
        Err(e) => panic!("{}", e),
    };
    let pub_key_handle = match get_test_key_handle(
        session,
        "FIPS_186-3/SigGen: [P-521,SHA-512]",
        CKO_PUBLIC_KEY,
    ) {
        Ok(k) => k,
        Err(e) => panic!("{}", e),
    };

    /* verify test vector */
    let mut mechanism: CK_MECHANISM = CK_MECHANISM {
        mechanism: CKM_ECDSA_SHA512,
        pParameter: std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    let ret = sig_verify(
        session,
        pub_key_handle,
        &mut testcase.value,
        &mut testcase.result,
        &mut mechanism,
    );
    assert_eq!(ret, CKR_OK);

    let mut result = match sig_gen(
        session,
        pri_key_handle,
        &mut testcase.value,
        &mut mechanism,
    ) {
        Ok(r) => r,
        Err(e) => panic!("f{e}"),
    };
    // the ECDSA is non-deterministic -- we can not just compare the signature, but we can verify
    let ret = sig_verify(
        session,
        pub_key_handle,
        &mut testcase.value,
        &mut result,
        &mut mechanism,
    );
    assert_eq!(ret, CKR_OK);

    /* ### HMACs ### */

    /* get test keys */
    let key_handle =
        match get_test_key_handle(session, "HMAC Test Key", CKO_SECRET_KEY) {
            Ok(k) => k,
            Err(e) => panic!("{}", e),
        };

    /* ### SHA-1 HMAC */

    /* get test data */
    let mut testcase = get_test_case_data(session, "CKM_SHA_1_HMAC");

    /* verify test vector */
    let mut mechanism: CK_MECHANISM = CK_MECHANISM {
        mechanism: CKM_SHA_1_HMAC,
        pParameter: std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    let ret = sig_verify(
        session,
        key_handle,
        &mut testcase.value,
        &mut testcase.result,
        &mut mechanism,
    );
    assert_eq!(ret, CKR_OK);

    let result =
        match sig_gen(session, key_handle, &mut testcase.value, &mut mechanism)
        {
            Ok(r) => r,
            Err(e) => panic!("f{e}"),
        };
    assert_eq!(testcase.result, result);

    /* ### SHA256 HMAC */

    /* get test data */
    let mut testcase = get_test_case_data(session, "CKM_SHA256_HMAC");

    /* verify test vector */
    let mut mechanism: CK_MECHANISM = CK_MECHANISM {
        mechanism: CKM_SHA256_HMAC,
        pParameter: std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    let ret = sig_verify(
        session,
        key_handle,
        &mut testcase.value,
        &mut testcase.result,
        &mut mechanism,
    );
    assert_eq!(ret, CKR_OK);

    let result =
        match sig_gen(session, key_handle, &mut testcase.value, &mut mechanism)
        {
            Ok(r) => r,
            Err(e) => panic!("f{e}"),
        };
    assert_eq!(testcase.result, result);

    /* ### SHA384 HMAC */

    /* get test data */
    let mut testcase = get_test_case_data(session, "CKM_SHA384_HMAC");

    /* verify test vector */
    let mut mechanism: CK_MECHANISM = CK_MECHANISM {
        mechanism: CKM_SHA384_HMAC,
        pParameter: std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    let ret = sig_verify(
        session,
        key_handle,
        &mut testcase.value,
        &mut testcase.result,
        &mut mechanism,
    );
    assert_eq!(ret, CKR_OK);

    let result =
        match sig_gen(session, key_handle, &mut testcase.value, &mut mechanism)
        {
            Ok(r) => r,
            Err(e) => panic!("f{e}"),
        };
    assert_eq!(testcase.result, result);

    /* ### SHA512 HMAC */

    /* get test data */
    let mut testcase = get_test_case_data(session, "CKM_SHA512_HMAC");

    /* verify test vector */
    let mut mechanism: CK_MECHANISM = CK_MECHANISM {
        mechanism: CKM_SHA512_HMAC,
        pParameter: std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    let ret = sig_verify(
        session,
        key_handle,
        &mut testcase.value,
        &mut testcase.result,
        &mut mechanism,
    );
    assert_eq!(ret, CKR_OK);

    let result =
        match sig_gen(session, key_handle, &mut testcase.value, &mut mechanism)
        {
            Ok(r) => r,
            Err(e) => panic!("f{e}"),
        };
    assert_eq!(testcase.result, result);

    /* ### SHA3 256 HMAC ### */

    /* get test keys */
    let key_handle = match get_test_key_handle(
        session,
        "HMAC SHA-3-256 Test Key",
        CKO_SECRET_KEY,
    ) {
        Ok(k) => k,
        Err(e) => panic!("{}", e),
    };

    /* get test data */
    let mut testcase = get_test_case_data(session, "CKM_SHA3_256_HMAC");

    /* verify test vector */
    let mut mechanism: CK_MECHANISM = CK_MECHANISM {
        mechanism: CKM_SHA3_256_HMAC,
        pParameter: std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    let ret = sig_verify(
        session,
        key_handle,
        &mut testcase.value,
        &mut testcase.result,
        &mut mechanism,
    );
    assert_eq!(ret, CKR_OK);

    let result =
        match sig_gen(session, key_handle, &mut testcase.value, &mut mechanism)
        {
            Ok(r) => r,
            Err(e) => panic!("f{e}"),
        };
    assert_eq!(testcase.result, result);

    /* check different HMAC fails due to key being specific to HMAC */
    mechanism.mechanism = CKM_SHA256_HMAC;
    let result =
        sig_gen(session, key_handle, &mut testcase.value, &mut mechanism);
    assert!(result.is_err());

    testtokn.finalize();
}

#[test]
fn test_key() {
    let mut testtokn = TestToken::initialized("test_key.sql", None);
    let session = testtokn.get_session(true);

    /* login */
    testtokn.login();

    /* Generic Secret */
    let mut mechanism: CK_MECHANISM = CK_MECHANISM {
        mechanism: CKM_GENERIC_SECRET_KEY_GEN,
        pParameter: std::ptr::null_mut(),
        ulParameterLen: 0,
    };

    let mut handle: CK_ULONG = CK_INVALID_HANDLE;

    let mut class = CKO_SECRET_KEY;
    let mut ktype = CKK_GENERIC_SECRET;
    let mut len: CK_ULONG = 16;
    let mut truebool = CK_TRUE;
    let mut template = vec![
        make_attribute!(CKA_CLASS, &mut class as *mut _, CK_ULONG_SIZE),
        make_attribute!(CKA_KEY_TYPE, &mut ktype as *mut _, CK_ULONG_SIZE),
        make_attribute!(CKA_VALUE_LEN, &mut len as *mut _, CK_ULONG_SIZE),
        make_attribute!(CKA_WRAP, &mut truebool as *mut _, CK_BBOOL_SIZE),
        make_attribute!(CKA_UNWRAP, &mut truebool as *mut _, CK_BBOOL_SIZE),
        make_attribute!(CKA_DERIVE, &mut truebool as *mut _, CK_BBOOL_SIZE),
        make_attribute!(
            CKA_EXTRACTABLE,
            &mut truebool as *mut _,
            CK_BBOOL_SIZE
        ),
    ];

    let mut ret = fn_generate_key(
        session,
        &mut mechanism,
        template.as_mut_ptr(),
        template.len() as CK_ULONG,
        &mut handle,
    );
    assert_eq!(ret, CKR_OK);

    /* RSA key pair */
    let mut mechanism: CK_MECHANISM = CK_MECHANISM {
        mechanism: CKM_RSA_PKCS_KEY_PAIR_GEN,
        pParameter: std::ptr::null_mut(),
        ulParameterLen: 0,
    };

    let mut pubkey = CK_INVALID_HANDLE;
    let mut prikey = CK_INVALID_HANDLE;

    let mut len: CK_ULONG = 2048;
    let mut pub_template = vec![
        make_attribute!(CKA_ENCRYPT, &mut truebool as *mut _, CK_BBOOL_SIZE),
        make_attribute!(CKA_VERIFY, &mut truebool as *mut _, CK_BBOOL_SIZE),
        make_attribute!(CKA_MODULUS_BITS, &mut len as *mut _, CK_ULONG_SIZE),
        make_attribute!(CKA_WRAP, &mut truebool as *mut _, CK_BBOOL_SIZE),
    ];
    let mut class = CKO_PRIVATE_KEY;
    let mut ktype = CKK_RSA;
    let mut pri_template = vec![
        make_attribute!(CKA_CLASS, &mut class as *mut _, CK_ULONG_SIZE),
        make_attribute!(CKA_KEY_TYPE, &mut ktype as *mut _, CK_ULONG_SIZE),
        make_attribute!(CKA_PRIVATE, &mut truebool as *mut _, CK_BBOOL_SIZE),
        make_attribute!(CKA_SENSITIVE, &mut truebool as *mut _, CK_BBOOL_SIZE),
        make_attribute!(CKA_TOKEN, &mut truebool as *mut _, CK_BBOOL_SIZE),
        make_attribute!(CKA_DECRYPT, &mut truebool as *mut _, CK_BBOOL_SIZE),
        make_attribute!(CKA_SIGN, &mut truebool as *mut _, CK_BBOOL_SIZE),
        make_attribute!(CKA_UNWRAP, &mut truebool as *mut _, CK_BBOOL_SIZE),
        make_attribute!(
            CKA_EXTRACTABLE,
            &mut truebool as *mut _,
            CK_BBOOL_SIZE
        ),
    ];

    ret = fn_generate_key_pair(
        session,
        &mut mechanism,
        pub_template.as_mut_ptr(),
        pub_template.len() as CK_ULONG,
        pri_template.as_mut_ptr(),
        pri_template.len() as CK_ULONG,
        &mut pubkey,
        &mut prikey,
    );
    assert_eq!(ret, CKR_OK);

    let mut sig_mechanism: CK_MECHANISM = CK_MECHANISM {
        mechanism: CKM_SHA256_RSA_PKCS,
        pParameter: std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    ret = fn_sign_init(session, &mut sig_mechanism, prikey);
    assert_eq!(ret, CKR_OK);

    let data = "plaintext";
    let sign: [u8; 256] = [0; 256];
    let mut sign_len: CK_ULONG = 256;
    ret = fn_sign(
        session,
        CString::new(data).unwrap().into_raw() as *mut u8,
        data.len() as CK_ULONG,
        sign.as_ptr() as *mut _,
        &mut sign_len,
    );
    assert_eq!(ret, CKR_OK);
    assert_eq!(sign_len, 256);

    ret = fn_verify_init(session, &mut sig_mechanism, pubkey);
    assert_eq!(ret, CKR_OK);

    ret = fn_verify(
        session,
        data.as_ptr() as *mut u8,
        data.len() as CK_ULONG,
        sign.as_ptr() as *mut u8,
        sign_len,
    );
    assert_eq!(ret, CKR_OK);

    /* Wrap RSA key in AES */
    let mut mechanism: CK_MECHANISM = CK_MECHANISM {
        mechanism: CKM_AES_ECB,
        pParameter: std::ptr::null_mut(),
        ulParameterLen: 0,
    };

    let mut wrapped = vec![0u8; 65536];
    let mut wrapped_len = wrapped.len() as CK_ULONG;

    ret = fn_wrap_key(
        session,
        &mut mechanism,
        handle,
        prikey,
        wrapped.as_mut_ptr(),
        &mut wrapped_len,
    );
    assert_eq!(ret, CKR_OK);

    let mut prikey2 = CK_INVALID_HANDLE;
    ret = fn_unwrap_key(
        session,
        &mut mechanism,
        handle,
        wrapped.as_mut_ptr(),
        wrapped_len,
        pri_template.as_mut_ptr(),
        pri_template.len() as CK_ULONG,
        &mut prikey2,
    );
    assert_eq!(ret, CKR_OK);

    /* Test the unwrapped key can be used */
    ret = fn_sign_init(session, &mut sig_mechanism, prikey2);
    assert_eq!(ret, CKR_OK);

    let data = "plaintext";
    let sign: [u8; 256] = [0; 256];
    let mut sign_len: CK_ULONG = 256;
    ret = fn_sign(
        session,
        CString::new(data).unwrap().into_raw() as *mut u8,
        data.len() as CK_ULONG,
        sign.as_ptr() as *mut _,
        &mut sign_len,
    );
    assert_eq!(ret, CKR_OK);
    assert_eq!(sign_len, 256);

    /* And signature verified by the original public key */
    ret = fn_verify_init(session, &mut sig_mechanism, pubkey);
    assert_eq!(ret, CKR_OK);

    ret = fn_verify(
        session,
        data.as_ptr() as *mut u8,
        data.len() as CK_ULONG,
        sign.as_ptr() as *mut u8,
        sign_len,
    );
    assert_eq!(ret, CKR_OK);

    /* Wrap AES Key in RSA PKCS */
    let mut mechanism: CK_MECHANISM = CK_MECHANISM {
        mechanism: CKM_RSA_PKCS,
        pParameter: std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    let mut wrapped_len = wrapped.len() as CK_ULONG;

    ret = fn_wrap_key(
        session,
        &mut mechanism,
        pubkey,
        handle,
        wrapped.as_mut_ptr(),
        &mut wrapped_len,
    );
    assert_eq!(ret, CKR_OK);

    /* need to unwrap the key with a template that
     * will work for an encryption operation */
    let mut class = CKO_SECRET_KEY;
    let mut ktype = CKK_AES;
    let mut len: CK_ULONG = 16;
    let mut truebool = CK_TRUE;
    let mut template = vec![
        make_attribute!(CKA_CLASS, &mut class as *mut _, CK_ULONG_SIZE),
        make_attribute!(CKA_KEY_TYPE, &mut ktype as *mut _, CK_ULONG_SIZE),
        make_attribute!(CKA_VALUE_LEN, &mut len as *mut _, CK_ULONG_SIZE),
        make_attribute!(CKA_ENCRYPT, &mut truebool as *mut _, CK_BBOOL_SIZE),
        make_attribute!(CKA_DECRYPT, &mut truebool as *mut _, CK_BBOOL_SIZE),
    ];

    let mut handle2 = CK_INVALID_HANDLE;
    ret = fn_unwrap_key(
        session,
        &mut mechanism,
        prikey,
        wrapped.as_mut_ptr(),
        wrapped_len,
        template.as_mut_ptr(),
        template.len() as CK_ULONG,
        &mut handle2,
    );
    assert_eq!(ret, CKR_OK);

    /* test the unwrapped key works */
    let mut mechanism: CK_MECHANISM = CK_MECHANISM {
        mechanism: CKM_AES_ECB,
        pParameter: std::ptr::null_mut(),
        ulParameterLen: 0,
    };

    ret = fn_encrypt_init(session, &mut mechanism, handle2);
    assert_eq!(ret, CKR_OK);

    /* init is sufficient to ensure the key is well formed,
     * terminate current operation */
    ret = fn_encrypt_init(session, std::ptr::null_mut(), handle2);
    assert_eq!(ret, CKR_OK);

    /* RSA 4k key pair */
    let mut mechanism: CK_MECHANISM = CK_MECHANISM {
        mechanism: CKM_RSA_PKCS_KEY_PAIR_GEN,
        pParameter: std::ptr::null_mut(),
        ulParameterLen: 0,
    };

    let mut pubkey = CK_INVALID_HANDLE;
    let mut prikey = CK_INVALID_HANDLE;

    let mut len: CK_ULONG = 4096;
    let mut pub_template = vec![
        make_attribute!(CKA_ENCRYPT, &mut truebool as *mut _, CK_BBOOL_SIZE),
        make_attribute!(CKA_VERIFY, &mut truebool as *mut _, CK_BBOOL_SIZE),
        make_attribute!(CKA_MODULUS_BITS, &mut len as *mut _, CK_ULONG_SIZE),
        make_attribute!(CKA_WRAP, &mut truebool as *mut _, CK_BBOOL_SIZE),
    ];
    let mut class = CKO_PRIVATE_KEY;
    let mut ktype = CKK_RSA;
    let mut pri_template = vec![
        make_attribute!(CKA_CLASS, &mut class as *mut _, CK_ULONG_SIZE),
        make_attribute!(CKA_KEY_TYPE, &mut ktype as *mut _, CK_ULONG_SIZE),
        make_attribute!(CKA_PRIVATE, &mut truebool as *mut _, CK_BBOOL_SIZE),
        make_attribute!(CKA_SENSITIVE, &mut truebool as *mut _, CK_BBOOL_SIZE),
        make_attribute!(CKA_TOKEN, &mut truebool as *mut _, CK_BBOOL_SIZE),
        make_attribute!(CKA_DECRYPT, &mut truebool as *mut _, CK_BBOOL_SIZE),
        make_attribute!(CKA_SIGN, &mut truebool as *mut _, CK_BBOOL_SIZE),
        make_attribute!(CKA_UNWRAP, &mut truebool as *mut _, CK_BBOOL_SIZE),
        make_attribute!(
            CKA_EXTRACTABLE,
            &mut truebool as *mut _,
            CK_BBOOL_SIZE
        ),
    ];

    ret = fn_generate_key_pair(
        session,
        &mut mechanism,
        pub_template.as_mut_ptr(),
        pub_template.len() as CK_ULONG,
        pri_template.as_mut_ptr(),
        pri_template.len() as CK_ULONG,
        &mut pubkey,
        &mut prikey,
    );
    assert_eq!(ret, CKR_OK);

    let mut sig_mechanism: CK_MECHANISM = CK_MECHANISM {
        mechanism: CKM_SHA256_RSA_PKCS,
        pParameter: std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    ret = fn_sign_init(session, &mut sig_mechanism, prikey);
    assert_eq!(ret, CKR_OK);

    let data = "plaintext";
    let sign: [u8; 512] = [0; 512];
    let mut sign_len: CK_ULONG = 512;
    ret = fn_sign(
        session,
        CString::new(data).unwrap().into_raw() as *mut u8,
        data.len() as CK_ULONG,
        sign.as_ptr() as *mut _,
        &mut sign_len,
    );
    assert_eq!(ret, CKR_OK);
    assert_eq!(sign_len, 512);

    ret = fn_verify_init(session, &mut sig_mechanism, pubkey);
    assert_eq!(ret, CKR_OK);

    ret = fn_verify(
        session,
        data.as_ptr() as *mut u8,
        data.len() as CK_ULONG,
        sign.as_ptr() as *mut u8,
        sign_len,
    );
    assert_eq!(ret, CKR_OK);

    /* EC key pair */
    let mut mechanism: CK_MECHANISM = CK_MECHANISM {
        mechanism: CKM_EC_KEY_PAIR_GEN,
        pParameter: std::ptr::null_mut(),
        ulParameterLen: 0,
    };

    let mut pubkey = CK_INVALID_HANDLE;
    let mut prikey = CK_INVALID_HANDLE;

    let mut truebool = CK_TRUE;
    let ec_params_hex = "06052B81040022"; // secp384r1
    let ec_params =
        hex::decode(ec_params_hex).expect("Failed to decode hex ec_params");
    let mut ktype = CKK_EC;
    let mut class = CKO_PUBLIC_KEY;
    let mut pub_template = vec![
        make_attribute!(CKA_CLASS, &mut class as *mut _, CK_ULONG_SIZE),
        make_attribute!(CKA_KEY_TYPE, &mut ktype as *mut _, CK_ULONG_SIZE),
        make_attribute!(CKA_VERIFY, &mut truebool as *mut _, CK_BBOOL_SIZE),
        make_attribute!(
            CKA_EC_PARAMS,
            ec_params.as_ptr() as *mut std::ffi::c_void,
            ec_params.len()
        ),
    ];
    let mut class = CKO_PRIVATE_KEY;
    let mut pri_template = vec![
        make_attribute!(CKA_CLASS, &mut class as *mut _, CK_ULONG_SIZE),
        make_attribute!(CKA_KEY_TYPE, &mut ktype as *mut _, CK_ULONG_SIZE),
        make_attribute!(CKA_PRIVATE, &mut truebool as *mut _, CK_BBOOL_SIZE),
        make_attribute!(CKA_SENSITIVE, &mut truebool as *mut _, CK_BBOOL_SIZE),
        make_attribute!(CKA_TOKEN, &mut truebool as *mut _, CK_BBOOL_SIZE),
        make_attribute!(CKA_SIGN, &mut truebool as *mut _, CK_BBOOL_SIZE),
        make_attribute!(
            CKA_EXTRACTABLE,
            &mut truebool as *mut _,
            CK_BBOOL_SIZE
        ),
    ];

    ret = fn_generate_key_pair(
        session,
        &mut mechanism,
        pub_template.as_mut_ptr(),
        pub_template.len() as CK_ULONG,
        pri_template.as_mut_ptr(),
        pri_template.len() as CK_ULONG,
        &mut pubkey,
        &mut prikey,
    );
    assert_eq!(ret, CKR_OK);

    let mut sig_mechanism: CK_MECHANISM = CK_MECHANISM {
        mechanism: CKM_ECDSA_SHA256,
        pParameter: std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    ret = fn_sign_init(session, &mut sig_mechanism, prikey);
    assert_eq!(ret, CKR_OK);

    let data = "plaintext";
    let sign: [u8; 96] = [0; 96];
    let mut sign_len: CK_ULONG = 96;
    ret = fn_sign(
        session,
        CString::new(data).unwrap().into_raw() as *mut u8,
        data.len() as CK_ULONG,
        sign.as_ptr() as *mut _,
        &mut sign_len,
    );
    assert_eq!(ret, CKR_OK);
    assert_eq!(sign_len, 96);

    ret = fn_verify_init(session, &mut sig_mechanism, pubkey);
    assert_eq!(ret, CKR_OK);

    ret = fn_verify(
        session,
        data.as_ptr() as *mut u8,
        data.len() as CK_ULONG,
        sign.as_ptr() as *mut u8,
        sign_len,
    );
    assert_eq!(ret, CKR_OK);

    /* Wrap EC key in AES */
    let mut mechanism: CK_MECHANISM = CK_MECHANISM {
        mechanism: CKM_AES_ECB,
        pParameter: std::ptr::null_mut(),
        ulParameterLen: 0,
    };

    let mut wrapped = vec![0u8; 65536];
    let mut wrapped_len = wrapped.len() as CK_ULONG;

    ret = fn_wrap_key(
        session,
        &mut mechanism,
        handle,
        prikey,
        wrapped.as_mut_ptr(),
        &mut wrapped_len,
    );
    assert_eq!(ret, CKR_OK);

    let mut prikey2 = CK_INVALID_HANDLE;
    ret = fn_unwrap_key(
        session,
        &mut mechanism,
        handle,
        wrapped.as_mut_ptr(),
        wrapped_len,
        pri_template.as_mut_ptr(),
        pri_template.len() as CK_ULONG,
        &mut prikey2,
    );
    assert_eq!(ret, CKR_OK);

    /* Test the unwrapped key can be used */
    ret = fn_sign_init(session, &mut sig_mechanism, prikey2);
    assert_eq!(ret, CKR_OK);

    let data = "plaintext";
    let sign: [u8; 96] = [0; 96];
    let mut sign_len: CK_ULONG = 96;
    ret = fn_sign(
        session,
        CString::new(data).unwrap().into_raw() as *mut u8,
        data.len() as CK_ULONG,
        sign.as_ptr() as *mut _,
        &mut sign_len,
    );
    assert_eq!(ret, CKR_OK);
    assert_eq!(sign_len, 96);

    /* And signature verified by the original public key */
    ret = fn_verify_init(session, &mut sig_mechanism, pubkey);
    assert_eq!(ret, CKR_OK);

    ret = fn_verify(
        session,
        data.as_ptr() as *mut u8,
        data.len() as CK_ULONG,
        sign.as_ptr() as *mut u8,
        sign_len,
    );
    assert_eq!(ret, CKR_OK);

    /* Test key derivation */
    let mut class = CKO_SECRET_KEY;
    let mut ktype = CKK_AES;
    let mut len: CK_ULONG = 16;
    let mut truebool = CK_TRUE;
    let derive_template = [
        make_attribute!(CKA_CLASS, &mut class as *mut _, CK_ULONG_SIZE),
        make_attribute!(CKA_KEY_TYPE, &mut ktype as *mut _, CK_ULONG_SIZE),
        make_attribute!(CKA_VALUE_LEN, &mut len as *mut _, CK_ULONG_SIZE),
        make_attribute!(CKA_ENCRYPT, &mut truebool as *mut _, CK_BBOOL_SIZE),
        make_attribute!(CKA_DECRYPT, &mut truebool as *mut _, CK_BBOOL_SIZE),
    ];

    let mut counter_format = CK_SP800_108_COUNTER_FORMAT {
        bLittleEndian: 0,
        ulWidthInBits: 8,
    };

    let mut data_params = [CK_PRF_DATA_PARAM {
        type_: CK_SP800_108_ITERATION_VARIABLE,
        pValue: &mut counter_format as *mut _ as CK_VOID_PTR,
        ulValueLen: std::mem::size_of::<CK_SP800_108_COUNTER_FORMAT>()
            as CK_ULONG,
    }];

    let mut params = CK_SP800_108_KDF_PARAMS {
        prfType: CKM_SHA3_384_HMAC,
        ulNumberOfDataParams: data_params.len() as CK_ULONG,
        pDataParams: data_params.as_mut_ptr(),
        ulAdditionalDerivedKeys: 0,
        pAdditionalDerivedKeys: std::ptr::null_mut(),
    };

    let mut derive_mech = CK_MECHANISM {
        mechanism: CKM_SP800_108_COUNTER_KDF,
        pParameter: &mut params as *mut _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_SP800_108_KDF_PARAMS>()
            as CK_ULONG,
    };

    let mut handle3 = CK_INVALID_HANDLE;
    ret = fn_derive_key(
        session,
        &mut derive_mech,
        handle,
        derive_template.as_ptr() as *mut _,
        derive_template.len() as CK_ULONG,
        &mut handle3,
    );
    assert_eq!(ret, CKR_OK);

    /* try again but derive additional keys */
    let mut handle4 = CK_INVALID_HANDLE;
    let mut handle5 = CK_UNAVAILABLE_INFORMATION;
    let mut handle6 = CK_UNAVAILABLE_INFORMATION;
    let mut addl_keys = [
        CK_DERIVED_KEY {
            pTemplate: derive_template.as_ptr() as *mut _,
            ulAttributeCount: derive_template.len() as CK_ULONG,
            phKey: &mut handle5,
        },
        CK_DERIVED_KEY {
            pTemplate: derive_template.as_ptr() as *mut _,
            ulAttributeCount: derive_template.len() as CK_ULONG,
            phKey: &mut handle6,
        },
    ];
    params.ulAdditionalDerivedKeys = 2;
    params.pAdditionalDerivedKeys = addl_keys.as_mut_ptr();
    ret = fn_derive_key(
        session,
        &mut derive_mech,
        handle,
        derive_template.as_ptr() as *mut _,
        derive_template.len() as CK_ULONG,
        &mut handle4,
    );
    assert_eq!(ret, CKR_OK);

    /* check each key */
    let mut val: CK_ULONG = 0;
    let attrtmpl = [make_attribute!(
        CKA_VALUE_LEN,
        &mut val as *mut _,
        CK_ULONG_SIZE
    )];

    ret = fn_get_attribute_value(
        session,
        handle3,
        attrtmpl.as_ptr() as *mut _,
        attrtmpl.len() as CK_ULONG,
    );
    assert_eq!(ret, CKR_OK);
    assert_eq!(val, 16);

    val = 0;
    ret = fn_get_attribute_value(
        session,
        handle4,
        attrtmpl.as_ptr() as *mut _,
        attrtmpl.len() as CK_ULONG,
    );
    assert_eq!(ret, CKR_OK);
    assert_eq!(val, 16);

    val = 0;
    ret = fn_get_attribute_value(
        session,
        handle5,
        attrtmpl.as_ptr() as *mut _,
        attrtmpl.len() as CK_ULONG,
    );
    assert_eq!(ret, CKR_OK);
    assert_eq!(val, 16);

    val = 0;
    ret = fn_get_attribute_value(
        session,
        handle6,
        attrtmpl.as_ptr() as *mut _,
        attrtmpl.len() as CK_ULONG,
    );
    assert_eq!(ret, CKR_OK);
    assert_eq!(val, 16);

    /* Test Sp800 108 feedback key derivation */
    let mut class = CKO_SECRET_KEY;
    let mut ktype = CKK_GENERIC_SECRET;
    let mut len: CK_ULONG = 1234;
    let mut truebool = CK_TRUE;
    let derive_template = [
        make_attribute!(CKA_CLASS, &mut class as *mut _, CK_ULONG_SIZE),
        make_attribute!(CKA_KEY_TYPE, &mut ktype as *mut _, CK_ULONG_SIZE),
        make_attribute!(CKA_VALUE_LEN, &mut len as *mut _, CK_ULONG_SIZE),
        make_attribute!(CKA_DERIVE, &mut truebool as *mut _, CK_BBOOL_SIZE),
    ];

    let mut counter_format = CK_SP800_108_COUNTER_FORMAT {
        bLittleEndian: 0,
        ulWidthInBits: 32,
    };

    let mut data_params = [
        CK_PRF_DATA_PARAM {
            type_: CK_SP800_108_ITERATION_VARIABLE,
            pValue: std::ptr::null_mut(),
            ulValueLen: 0,
        },
        CK_PRF_DATA_PARAM {
            type_: CK_SP800_108_COUNTER,
            pValue: &mut counter_format as *mut _ as CK_VOID_PTR,
            ulValueLen: std::mem::size_of::<CK_SP800_108_COUNTER_FORMAT>()
                as CK_ULONG,
        },
    ];

    /* openssl requires 32 bit IV here */
    #[cfg(feature = "fips")]
    let mut iv = [123u8; 32];

    #[cfg(not(feature = "fips"))]
    let mut iv = [1u8; 5];

    let mut params = CK_SP800_108_FEEDBACK_KDF_PARAMS {
        prfType: CKM_SHA256_HMAC,
        ulNumberOfDataParams: data_params.len() as CK_ULONG,
        pDataParams: data_params.as_mut_ptr(),
        ulIVLen: iv.len() as CK_ULONG,
        pIV: iv.as_mut_ptr(),
        ulAdditionalDerivedKeys: 0,
        pAdditionalDerivedKeys: std::ptr::null_mut(),
    };

    let mut derive_mech = CK_MECHANISM {
        mechanism: CKM_SP800_108_FEEDBACK_KDF,
        pParameter: &mut params as *mut _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_SP800_108_FEEDBACK_KDF_PARAMS>()
            as CK_ULONG,
    };

    let mut handle7 = CK_INVALID_HANDLE;
    ret = fn_derive_key(
        session,
        &mut derive_mech,
        handle,
        derive_template.as_ptr() as *mut _,
        derive_template.len() as CK_ULONG,
        &mut handle7,
    );
    assert_eq!(ret, CKR_OK);

    /* Test AES_ECB/AES_CBC Key derivation */
    let mut mechanism: CK_MECHANISM = CK_MECHANISM {
        mechanism: CKM_AES_KEY_GEN,
        pParameter: std::ptr::null_mut(),
        ulParameterLen: 0,
    };

    let mut class = CKO_SECRET_KEY;
    let mut ktype = CKK_AES;
    let mut len: CK_ULONG = 32;
    let mut truebool = CK_TRUE;
    let mut template = vec![
        make_attribute!(CKA_CLASS, &mut class as *mut _, CK_ULONG_SIZE),
        make_attribute!(CKA_KEY_TYPE, &mut ktype as *mut _, CK_ULONG_SIZE),
        make_attribute!(CKA_VALUE_LEN, &mut len as *mut _, CK_ULONG_SIZE),
        make_attribute!(CKA_DERIVE, &mut truebool as *mut _, CK_BBOOL_SIZE),
    ];

    let mut aeskey = CK_INVALID_HANDLE;
    ret = fn_generate_key(
        session,
        &mut mechanism,
        template.as_mut_ptr(),
        template.len() as CK_ULONG,
        &mut aeskey,
    );
    assert_eq!(ret, CKR_OK);

    let mut class = CKO_SECRET_KEY;
    let mut ktype = CKK_AES;
    let mut len: CK_ULONG = 16;
    let mut truebool = CK_TRUE;
    let derive_template = [
        make_attribute!(CKA_CLASS, &mut class as *mut _, CK_ULONG_SIZE),
        make_attribute!(CKA_KEY_TYPE, &mut ktype as *mut _, CK_ULONG_SIZE),
        make_attribute!(CKA_VALUE_LEN, &mut len as *mut _, CK_ULONG_SIZE),
        make_attribute!(CKA_DERIVE, &mut truebool as *mut _, CK_BBOOL_SIZE),
    ];

    let data = "derive keys data";
    let mut derive_params = CK_KEY_DERIVATION_STRING_DATA {
        pData: data.as_ptr() as CK_BYTE_PTR,
        ulLen: data.len() as CK_ULONG,
    };
    let mut derive_mech = CK_MECHANISM {
        mechanism: CKM_AES_ECB_ENCRYPT_DATA,
        pParameter: &mut derive_params as *mut _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_KEY_DERIVATION_STRING_DATA>()
            as CK_ULONG,
    };

    let mut aeskey2 = CK_INVALID_HANDLE;
    ret = fn_derive_key(
        session,
        &mut derive_mech,
        aeskey,
        derive_template.as_ptr() as *mut _,
        derive_template.len() as CK_ULONG,
        &mut aeskey2,
    );
    assert_eq!(ret, CKR_OK);

    let mut derive_params = CK_AES_CBC_ENCRYPT_DATA_PARAMS {
        iv: [1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
        pData: data.as_ptr() as CK_BYTE_PTR,
        length: data.len() as CK_ULONG,
    };
    let mut derive_mech = CK_MECHANISM {
        mechanism: CKM_AES_CBC_ENCRYPT_DATA,
        pParameter: &mut derive_params as *mut _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_AES_CBC_ENCRYPT_DATA_PARAMS>()
            as CK_ULONG,
    };

    let mut aeskey3 = CK_INVALID_HANDLE;
    ret = fn_derive_key(
        session,
        &mut derive_mech,
        aeskey2,
        derive_template.as_ptr() as *mut _,
        derive_template.len() as CK_ULONG,
        &mut aeskey3,
    );
    assert_eq!(ret, CKR_OK);

    /* Test Hash based derivation */

    /* No length or type */
    let class = CKO_SECRET_KEY;
    let truebool = CK_TRUE;
    let derive_template = [
        make_attribute!(CKA_CLASS, &class as *const _, CK_ULONG_SIZE),
        make_attribute!(CKA_EXTRACTABLE, &truebool as *const _, CK_BBOOL_SIZE),
    ];

    let mut derive_mech = CK_MECHANISM {
        mechanism: CKM_SHA256_KEY_DERIVATION,
        pParameter: std::ptr::null_mut(),
        ulParameterLen: 0,
    };

    let mut hashkey1 = CK_INVALID_HANDLE;
    ret = fn_derive_key(
        session,
        &mut derive_mech,
        aeskey,
        derive_template.as_ptr() as *mut _,
        derive_template.len() as CK_ULONG,
        &mut hashkey1,
    );
    assert_eq!(ret, CKR_OK);

    let mut extract_template = [CK_ATTRIBUTE {
        type_: CKA_VALUE,
        pValue: std::ptr::null_mut(),
        ulValueLen: 0,
    }];

    ret = fn_get_attribute_value(
        session,
        hashkey1,
        extract_template.as_mut_ptr(),
        extract_template.len() as CK_ULONG,
    );
    assert_eq!(ret, CKR_OK);
    assert_eq!(extract_template[0].ulValueLen, 32);

    /* Key len too big */
    let mut keylen: CK_ULONG = 42;
    let mut derive_template = [
        make_attribute!(CKA_CLASS, &class as *const _, CK_ULONG_SIZE),
        make_attribute!(CKA_VALUE_LEN, &keylen as *const _, CK_ULONG_SIZE),
        make_attribute!(CKA_EXTRACTABLE, &truebool as *const _, CK_BBOOL_SIZE),
    ];

    let mut hashkey2 = CK_INVALID_HANDLE;
    ret = fn_derive_key(
        session,
        &mut derive_mech,
        aeskey,
        derive_template.as_mut_ptr(),
        derive_template.len() as CK_ULONG,
        &mut hashkey2,
    );
    assert_eq!(ret, CKR_TEMPLATE_INCONSISTENT);

    /* Valid Key len defined */
    keylen = 22;
    derive_template[1].pValue = &keylen as *const _ as CK_VOID_PTR;
    let mut hashkey2 = CK_INVALID_HANDLE;
    ret = fn_derive_key(
        session,
        &mut derive_mech,
        aeskey,
        derive_template.as_mut_ptr(),
        derive_template.len() as CK_ULONG,
        &mut hashkey2,
    );
    assert_eq!(ret, CKR_OK);

    extract_template[0].ulValueLen = 0;

    ret = fn_get_attribute_value(
        session,
        hashkey2,
        extract_template.as_mut_ptr(),
        extract_template.len() as CK_ULONG,
    );
    assert_eq!(ret, CKR_OK);
    assert_eq!(extract_template[0].ulValueLen, 22);

    /* No length but key type defined */
    let ktype = CKK_AES;
    let derive_template = [
        make_attribute!(CKA_CLASS, &class as *const _, CK_ULONG_SIZE),
        make_attribute!(CKA_KEY_TYPE, &ktype as *const _, CK_ULONG_SIZE),
        make_attribute!(CKA_EXTRACTABLE, &truebool as *const _, CK_BBOOL_SIZE),
    ];

    let mut derive_mech = CK_MECHANISM {
        mechanism: CKM_SHA512_KEY_DERIVATION,
        pParameter: std::ptr::null_mut(),
        ulParameterLen: 0,
    };

    let mut hashkey3 = CK_INVALID_HANDLE;
    ret = fn_derive_key(
        session,
        &mut derive_mech,
        aeskey,
        derive_template.as_ptr() as *mut _,
        derive_template.len() as CK_ULONG,
        &mut hashkey3,
    );
    assert_eq!(ret, CKR_OK);

    extract_template[0].ulValueLen = 0;

    ret = fn_get_attribute_value(
        session,
        hashkey3,
        extract_template.as_mut_ptr(),
        extract_template.len() as CK_ULONG,
    );
    assert_eq!(ret, CKR_OK);
    assert_eq!(extract_template[0].ulValueLen, 32);

    /* Key type define and incompatible length */
    keylen = 42;
    let mut derive_template = [
        make_attribute!(CKA_CLASS, &class as *const _, CK_ULONG_SIZE),
        make_attribute!(CKA_KEY_TYPE, &ktype as *const _, CK_ULONG_SIZE),
        make_attribute!(CKA_VALUE_LEN, &keylen as *const _, CK_ULONG_SIZE),
        make_attribute!(CKA_EXTRACTABLE, &truebool as *const _, CK_BBOOL_SIZE),
    ];

    let mut hashkey4 = CK_INVALID_HANDLE;
    ret = fn_derive_key(
        session,
        &mut derive_mech,
        aeskey,
        derive_template.as_mut_ptr(),
        derive_template.len() as CK_ULONG,
        &mut hashkey4,
    );
    assert_eq!(ret, CKR_TEMPLATE_INCONSISTENT);

    /* Key type and length defined */
    keylen = 32;
    derive_template[2].pValue = &keylen as *const _ as CK_VOID_PTR;
    let mut hashkey4 = CK_INVALID_HANDLE;
    ret = fn_derive_key(
        session,
        &mut derive_mech,
        aeskey,
        derive_template.as_mut_ptr(),
        derive_template.len() as CK_ULONG,
        &mut hashkey4,
    );
    assert_eq!(ret, CKR_OK);

    extract_template[0].ulValueLen = 0;

    ret = fn_get_attribute_value(
        session,
        hashkey4,
        extract_template.as_mut_ptr(),
        extract_template.len() as CK_ULONG,
    );
    assert_eq!(ret, CKR_OK);
    assert_eq!(extract_template[0].ulValueLen, 32);

    testtokn.finalize();
}

use std::io;
use std::io::BufRead;

#[derive(Debug, PartialEq)]
enum KdfCtrlLoc {
    Undefined,
    AfterFixed,
    AfterIter,
    BeforeFixed,
    BeforeIter,
    MiddleFixed,
}

#[derive(Debug)]
struct KdfTestUnit {
    line: usize,
    count: usize,
    l: usize,
    ki: Vec<u8>,
    iv_len: usize,
    iv: Vec<u8>,
    data_len: usize,
    data: Vec<u8>,
    data_before_len: usize,
    data_before: Vec<u8>,
    ko: Vec<u8>,
}

#[derive(Debug)]
struct KdfTestSection {
    kdf: CK_MECHANISM_TYPE,
    prf: CK_MECHANISM_TYPE,
    ctr_location: KdfCtrlLoc,
    rlen: usize,
    units: Vec<KdfTestUnit>,
}

macro_rules! parse_or_panic {
    ($e:expr; $line:expr; $ln:expr) => {
        match $e {
            Ok(r) => r,
            Err(_) => panic!("Malformed line '{}' (line {})", $line, $ln),
        }
    };
}

fn parse_kdf_vector(filename: &str) -> Vec<KdfTestSection> {
    let file = ret_or_panic!(std::fs::File::open(filename));

    let mut kdf: CK_MECHANISM_TYPE = CK_UNAVAILABLE_INFORMATION;
    let mut data = Vec::<KdfTestSection>::new();

    for (l, line) in io::BufReader::new(file).lines().flatten().enumerate() {
        let ln = l + 1;
        if line.starts_with("#") {
            match line.as_str() {
                "# KDF Mode Supported: Counter Mode" => {
                    kdf = CKM_SP800_108_COUNTER_KDF
                }
                "# KDF Mode Supported: Feedback Mode" => {
                    kdf = CKM_SP800_108_FEEDBACK_KDF
                }
                _ => (),
            }
            continue;
        }

        if line.len() == 0 {
            continue;
        }

        if line.starts_with("[PRF=") {
            /* we ignore tests for algorithms we do not care to support like Triple DES,
             * for those we still need to parse the section, but we'll mark it as
             * unknown and skip all units */
            let section = KdfTestSection {
                kdf: kdf,
                prf: match &line[5..] {
                    "CMAC_AES128]" => CKM_AES_CMAC,
                    "CMAC_AES192]" => CKM_AES_CMAC,
                    "CMAC_AES256]" => CKM_AES_CMAC,
                    "HMAC_SHA1]" => CKM_SHA_1_HMAC,
                    "HMAC_SHA224]" => CKM_SHA224_HMAC,
                    "HMAC_SHA256]" => CKM_SHA256_HMAC,
                    "HMAC_SHA384]" => CKM_SHA384_HMAC,
                    "HMAC_SHA512]" => CKM_SHA512_HMAC,
                    _ => CK_UNAVAILABLE_INFORMATION,
                },
                ctr_location: KdfCtrlLoc::Undefined,
                rlen: 0,
                units: Vec::with_capacity(39),
            };
            data.push(section);
            continue;
        }
        let section = match data.last_mut() {
            Some(s) => s,
            None => continue,
        };
        if section.prf == CK_UNAVAILABLE_INFORMATION {
            continue;
        }
        if line.starts_with("[CTRLOCATION=") {
            if section.ctr_location != KdfCtrlLoc::Undefined {
                panic!(
                    "Repeat CTRLOCATION? Malformed test file? (line {})",
                    ln
                );
            }
            match &line[13..] {
                "AFTER_FIXED]" => section.ctr_location = KdfCtrlLoc::AfterFixed,
                "AFTER_ITER]" => section.ctr_location = KdfCtrlLoc::AfterIter,
                "BEFORE_FIXED]" => {
                    section.ctr_location = KdfCtrlLoc::BeforeFixed
                }
                "BEFORE_ITER]" => section.ctr_location = KdfCtrlLoc::BeforeIter,
                "MIDDLE_FIXED]" => {
                    section.ctr_location = KdfCtrlLoc::MiddleFixed
                }
                _ => panic!("Unrecognized input: {} (line {})", line, ln),
            }
            continue;
        }
        if line.starts_with("[RLEN=") {
            if section.rlen != 0 {
                panic!("Repeat RLEN? Malformed test file?");
            }
            match &line[6..] {
                "8_BITS]" => section.rlen = 8,
                "16_BITS]" => section.rlen = 16,
                "24_BITS]" => section.rlen = 24,
                "32_BITS]" => section.rlen = 32,
                _ => panic!("Unrecognized input: {} (line {})", line, ln),
            }
            continue;
        }

        /* units */
        if line.starts_with("COUNT=") {
            let unit = KdfTestUnit {
                line: ln,
                count: (&line[6..]).parse().unwrap(),
                l: 0,
                ki: Vec::new(),
                iv_len: 0,
                iv: Vec::new(),
                data_len: 0,
                data: Vec::new(),
                data_before: Vec::new(),
                data_before_len: 0,
                ko: Vec::new(),
            };
            section.units.push(unit);
            continue;
        }

        let unit = match section.units.last_mut() {
            Some(u) => u,
            None => panic!("No unit defined in section (line {})", ln),
        };

        if line.starts_with("L = ") {
            unit.l = parse_or_panic!((&line[4..]).parse(); line; ln);
            continue;
        }

        if line.starts_with("KI = ") {
            unit.ki = parse_or_panic!(hex::decode(&line[5..]); line; ln);
            continue;
        }

        if line.starts_with("IVlen = ") {
            unit.iv_len = parse_or_panic!((&line[8..]).parse(); line; ln);
            continue;
        }

        if line.starts_with("IV = ") {
            unit.iv = parse_or_panic!(hex::decode(&line[5..]); line; ln);
            if unit.iv.len() != unit.iv_len / 8 {
                panic!("Length of iv ({} bytes) does not match length of data ({} bits) (line {})", unit.iv.len(), unit.iv_len, ln);
            }
            continue;
        }

        match &section.ctr_location {
            KdfCtrlLoc::AfterFixed | KdfCtrlLoc::AfterIter => {
                if line.starts_with("FixedInputDataByteLen = ") {
                    unit.data_len =
                        parse_or_panic!((&line[24..]).parse(); line; ln);
                    continue;
                }

                if line.starts_with("FixedInputData = ") {
                    unit.data =
                        parse_or_panic!(hex::decode(&line[17..]); line; ln);
                    if unit.data.len() != unit.data_len {
                        panic!("Length of data ({}) does not match data ({}) (line {})", unit.data_before.len(), unit.data_before_len, ln);
                    }
                    continue;
                }
            }
            KdfCtrlLoc::BeforeFixed | KdfCtrlLoc::BeforeIter => {
                if line.starts_with("FixedInputDataByteLen = ") {
                    unit.data_len =
                        parse_or_panic!((&line[24..]).parse(); line; ln);
                    continue;
                }

                if line.starts_with("FixedInputData = ") {
                    unit.data =
                        parse_or_panic!(hex::decode(&line[17..]); line; ln);
                    if unit.data.len() != unit.data_len {
                        panic!("Length of data ({}) does not match data ({}) (line {})", unit.data.len(), unit.data_len, ln);
                    }
                    continue;
                }
            }
            KdfCtrlLoc::MiddleFixed => {
                if line.starts_with("DataBeforeCtrLen = ") {
                    unit.data_before_len =
                        parse_or_panic!((&line[19..]).parse(); line; ln);
                    continue;
                }

                if line.starts_with("DataBeforeCtrData = ") {
                    unit.data_before =
                        parse_or_panic!(hex::decode(&line[20..]); line; ln);
                    if unit.data_before.len() != unit.data_before_len {
                        panic!("Length of data ({}) does not match data ({}) (line {})", unit.data_before.len(), unit.data_before_len, ln);
                    }
                    continue;
                }
                if line.starts_with("DataAfterCtrLen = ") {
                    unit.data_len =
                        parse_or_panic!((&line[18..]).parse(); line; ln);
                    continue;
                }

                if line.starts_with("DataAfterCtrData = ") {
                    unit.data =
                        parse_or_panic!(hex::decode(&line[19..]); line; ln);
                    if unit.data.len() != unit.data_len {
                        panic!("Length of data ({}) does not match data ({}) (line {})", unit.data.len(), unit.data_len, ln);
                    }
                    continue;
                }
            }
            _ => panic!("Unextpected Counter Location type (line {})", ln),
        }

        if line.starts_with("\t") {
            /* ignore */
            continue;
        }

        if line.starts_with("KO = ") {
            unit.ko = parse_or_panic!(hex::decode(&line[5..]); line; ln);
            if unit.ko.len() * 8 != unit.l {
                panic!(
                    "Length of KO ({}) does not match L ({}) (line {})",
                    unit.ko.len(),
                    unit.l,
                    ln
                );
            }
            continue;
        }
    }

    data
}

fn create_secret_key(
    session: CK_ULONG,
    label: &String,
    key_type: CK_KEY_TYPE,
    key: &Vec<u8>,
) -> CK_OBJECT_HANDLE {
    let class = CKO_SECRET_KEY;
    let lb = label.as_bytes();
    let truebool = CK_TRUE;
    let template = vec![
        make_attribute!(CKA_CLASS, &class as *const _, CK_ULONG_SIZE),
        make_attribute!(CKA_KEY_TYPE, &key_type as *const _, CK_ULONG_SIZE),
        make_attribute!(
            CKA_LABEL,
            lb.as_ptr() as CK_VOID_PTR,
            lb.len() as CK_ULONG
        ),
        make_attribute!(
            CKA_VALUE,
            key.as_ptr() as CK_VOID_PTR,
            key.len() as CK_ULONG
        ),
        make_attribute!(CKA_DERIVE, &truebool as *const _, CK_BBOOL_SIZE),
    ];

    let mut handle: CK_OBJECT_HANDLE = CK_INVALID_HANDLE;
    let _ = fn_create_object(
        session,
        template.as_ptr() as CK_ATTRIBUTE_PTR,
        template.len() as CK_ULONG,
        &mut handle,
    );

    handle
}

macro_rules! make_prf_data_param {
    ($type:expr, $value:expr, $a:ty) => {
        CK_PRF_DATA_PARAM {
            type_: $type,
            pValue: $value as *const _ as CK_VOID_PTR,
            ulValueLen: std::mem::size_of::<$a>() as CK_ULONG,
        }
    };
    ($type:expr, $value:expr, $a:expr) => {
        CK_PRF_DATA_PARAM {
            type_: $type,
            pValue: $value as *const _ as CK_VOID_PTR,
            ulValueLen: $a as CK_ULONG,
        }
    };
}

fn test_kdf_units(session: CK_SESSION_HANDLE, test_data: Vec<KdfTestSection>) {
    let iter = make_prf_data_param!(
        CK_SP800_108_ITERATION_VARIABLE,
        std::ptr::null::<std::ffi::c_void>(),
        0
    );

    for section in test_data {
        if section.prf == CKM_AES_CMAC {
            /* unsupported currently */
            continue;
        }

        /* Currently we use the OpenSSL KBKDF backend for FIPS mode and
         * it supports only if the counter is before any fixed data and
         * (in feedback) after the IV */
        #[cfg(feature = "fips")]
        if section.kdf == CKM_SP800_108_COUNTER_KDF
            && section.ctr_location != KdfCtrlLoc::BeforeFixed
        {
            continue;
        }
        #[cfg(feature = "fips")]
        if section.kdf == CKM_SP800_108_FEEDBACK_KDF
            || section.ctr_location != KdfCtrlLoc::AfterIter
        {
            continue;
        }

        for unit in section.units {
            println!("Executing test at line {}", unit.line);
            /* create key */
            let key_handle = create_secret_key(
                session,
                &format!(
                    "Key for mech {}, COUNT={}, line {}",
                    section.prf, unit.count, unit.line
                ),
                CKK_GENERIC_SECRET,
                &unit.ki,
            );

            let class = CKO_SECRET_KEY;
            let ktype = CKK_GENERIC_SECRET;
            let klen = unit.ko.len() as CK_ULONG;
            let truebool = CK_TRUE;
            let derive_template = [
                make_attribute!(CKA_CLASS, &class as *const _, CK_ULONG_SIZE),
                make_attribute!(
                    CKA_KEY_TYPE,
                    &ktype as *const _,
                    CK_ULONG_SIZE
                ),
                make_attribute!(
                    CKA_VALUE_LEN,
                    &klen as *const _,
                    CK_ULONG_SIZE
                ),
                make_attribute!(
                    CKA_EXTRACTABLE,
                    &truebool as *const _,
                    CK_BBOOL_SIZE
                ),
            ];

            let mut dk_handle = CK_INVALID_HANDLE;

            match section.kdf {
                CKM_SP800_108_COUNTER_KDF => {
                    let mut data_params = Vec::<CK_PRF_DATA_PARAM>::new();

                    let counter_format = CK_SP800_108_COUNTER_FORMAT {
                        bLittleEndian: 0,
                        ulWidthInBits: section.rlen as CK_ULONG,
                    };
                    let counter = make_prf_data_param!(
                        CK_SP800_108_ITERATION_VARIABLE,
                        &counter_format,
                        CK_SP800_108_COUNTER_FORMAT
                    );

                    match &section.ctr_location {
                        KdfCtrlLoc::AfterFixed => {
                            let data = make_prf_data_param!(
                                CK_SP800_108_BYTE_ARRAY,
                                unit.data.as_ptr(),
                                unit.data.len()
                            );
                            data_params.push(data);
                            data_params.push(counter);
                        }
                        KdfCtrlLoc::BeforeFixed => {
                            let data = make_prf_data_param!(
                                CK_SP800_108_BYTE_ARRAY,
                                unit.data.as_ptr(),
                                unit.data.len()
                            );
                            data_params.push(counter);
                            data_params.push(data);
                        }
                        KdfCtrlLoc::MiddleFixed => {
                            let data_after = make_prf_data_param!(
                                CK_SP800_108_BYTE_ARRAY,
                                unit.data.as_ptr(),
                                unit.data.len()
                            );
                            let data_before = make_prf_data_param!(
                                CK_SP800_108_BYTE_ARRAY,
                                unit.data_before.as_ptr(),
                                unit.data_before.len()
                            );
                            data_params.push(data_before);
                            data_params.push(counter);
                            data_params.push(data_after);
                        }
                        _ => panic!("Unextpected Counter Location type"),
                    };

                    let mut params = CK_SP800_108_KDF_PARAMS {
                        prfType: section.prf,
                        ulNumberOfDataParams: data_params.len() as CK_ULONG,
                        pDataParams: data_params.as_ptr() as *mut _,
                        ulAdditionalDerivedKeys: 0,
                        pAdditionalDerivedKeys: std::ptr::null_mut(),
                    };

                    let derive_mech = CK_MECHANISM {
                        mechanism: CKM_SP800_108_COUNTER_KDF,
                        pParameter: &mut params as *mut _ as CK_VOID_PTR,
                        ulParameterLen: std::mem::size_of::<
                            CK_SP800_108_KDF_PARAMS,
                        >() as CK_ULONG,
                    };

                    let ret = fn_derive_key(
                        session,
                        &derive_mech as *const _ as CK_MECHANISM_PTR,
                        key_handle,
                        derive_template.as_ptr() as *mut _,
                        derive_template.len() as CK_ULONG,
                        &mut dk_handle,
                    );
                    if ret != CKR_OK {
                        panic!(
                            "Failed ({}) unit test at line {}",
                            ret, unit.line
                        );
                    }
                }
                CKM_SP800_108_FEEDBACK_KDF => {
                    let mut data_params = Vec::<CK_PRF_DATA_PARAM>::new();

                    let counter_format = CK_SP800_108_COUNTER_FORMAT {
                        bLittleEndian: 0,
                        ulWidthInBits: section.rlen as CK_ULONG,
                    };

                    let counter = make_prf_data_param!(
                        CK_SP800_108_COUNTER,
                        &counter_format,
                        CK_SP800_108_COUNTER_FORMAT
                    );

                    match &section.ctr_location {
                        KdfCtrlLoc::AfterFixed => {
                            let data = make_prf_data_param!(
                                CK_SP800_108_BYTE_ARRAY,
                                unit.data.as_ptr(),
                                unit.data.len()
                            );
                            data_params.push(iter);
                            data_params.push(data);
                            data_params.push(counter);
                        }
                        KdfCtrlLoc::AfterIter => {
                            let data = make_prf_data_param!(
                                CK_SP800_108_BYTE_ARRAY,
                                unit.data.as_ptr(),
                                unit.data.len()
                            );
                            data_params.push(iter);
                            data_params.push(counter);
                            data_params.push(data);
                        }
                        KdfCtrlLoc::BeforeIter => {
                            let data = make_prf_data_param!(
                                CK_SP800_108_BYTE_ARRAY,
                                unit.data.as_ptr(),
                                unit.data.len()
                            );
                            data_params.push(counter);
                            data_params.push(iter);
                            data_params.push(data);
                        }
                        _ => panic!("Unextpected Counter Location type"),
                    };

                    let mut params = CK_SP800_108_FEEDBACK_KDF_PARAMS {
                        prfType: section.prf,
                        ulNumberOfDataParams: data_params.len() as CK_ULONG,
                        pDataParams: data_params.as_ptr() as *mut _,
                        ulIVLen: unit.iv.len() as CK_ULONG,
                        pIV: if unit.iv.len() > 0 {
                            unit.iv.as_ptr() as *mut _
                        } else {
                            std::ptr::null_mut()
                        },
                        ulAdditionalDerivedKeys: 0,
                        pAdditionalDerivedKeys: std::ptr::null_mut(),
                    };

                    let derive_mech = CK_MECHANISM {
                        mechanism: CKM_SP800_108_FEEDBACK_KDF,
                        pParameter: &mut params as *mut _ as CK_VOID_PTR,
                        ulParameterLen: std::mem::size_of::<
                            CK_SP800_108_FEEDBACK_KDF_PARAMS,
                        >() as CK_ULONG,
                    };

                    let ret = fn_derive_key(
                        session,
                        &derive_mech as *const _ as CK_MECHANISM_PTR,
                        key_handle,
                        derive_template.as_ptr() as *mut _,
                        derive_template.len() as CK_ULONG,
                        &mut dk_handle,
                    );
                    if ret != CKR_OK {
                        panic!(
                            "Failed ({}) unit test at line {}",
                            ret, unit.line
                        );
                    }
                }
                _ => panic!("Invalid KDF mechanism {}", section.kdf),
            };

            let mut value = vec![0u8; unit.ko.len()];
            let mut extract_template =
                [make_attribute!(CKA_VALUE, value.as_mut_ptr(), value.len())];

            let ret = fn_get_attribute_value(
                session,
                dk_handle,
                extract_template.as_mut_ptr(),
                extract_template.len() as CK_ULONG,
            );
            assert_eq!(ret, CKR_OK);

            if value != unit.ko {
                panic!("Failed ({}) unit test at line {} - values differ [{} != {}]", ret, unit.line, hex::encode(value), hex::encode(unit.ko));
            }
        }
    }
}

#[test]
fn test_kdf_ctr_vector() {
    let test_data = parse_kdf_vector("testdata/KDFCTR_gen.txt");

    let mut testtokn = TestToken::initialized("test_kdf_ctr_vector.sql", None);
    let session = testtokn.get_session(false);

    /* login */
    testtokn.login();

    test_kdf_units(session, test_data);

    testtokn.finalize();
}

#[test]
fn test_kdf_feedback_vector() {
    let test_data = parse_kdf_vector("testdata/KDFFeedback_gen.txt");

    let mut testtokn =
        TestToken::initialized("test_kdf_feedback_vector.sql", None);
    let session = testtokn.get_session(false);

    /* login */
    testtokn.login();
    test_kdf_units(session, test_data);

    testtokn.finalize();
}