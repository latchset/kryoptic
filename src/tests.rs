// Copyright 2023 Simo Sorce
// See LICENSE.txt file for terms

use super::*;
use hex;
use std::ffi::CString;
use std::sync::Once;

const CK_ULONG_SIZE: usize = std::mem::size_of::<CK_ULONG>();
const CK_BBOOL_SIZE: usize = std::mem::size_of::<CK_BBOOL>();
macro_rules! make_attribute {
    ($type:expr, $value:expr, $length:expr) => {
        CK_ATTRIBUTE {
            type_: $type,
            pValue: $value as CK_VOID_PTR,
            ulValueLen: $length as CK_ULONG,
        }
    };
}

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

struct TestData<'a> {
    slot: CK_SLOT_ID,
    filename: &'a str,
    created: bool,
    finalize: Option<RwLockWriteGuard<'a, u64>>,
    sync: Option<RwLockReadGuard<'a, u64>>,
}

impl TestData<'_> {
    fn new<'a>(filename: &'a str) -> TestData {
        let mut slots = SLOTS.write().unwrap();
        slots.id += 1;
        TestData {
            slot: slots.id,
            filename: filename,
            created: false,
            finalize: test_finalizer(),
            sync: Some(SYNC.read().unwrap()),
        }
    }

    fn setup_db(&mut self) {
        let test_token = serde_json::json!({
            "objects": [{
                "attributes": {
                    "CKA_UNIQUE_ID": "0",
                    "CKA_CLASS": 4,
                    "CKA_KEY_TYPE": 16,
                    "CKA_LABEL": "SO PIN",
                    "CKA_VALUE": "MTIzNDU2Nzg=",
                    "CKA_TOKEN": true
                }
            }, {
                "attributes": {
                    "CKA_UNIQUE_ID": "1",
                    "CKA_CLASS": 4,
                    "CKA_KEY_TYPE": 16,
                    "CKA_LABEL": "User PIN",
                    "CKA_VALUE": "MTIzNDU2Nzg=",
                    "CKA_TOKEN": true
                }
            }, {
                "attributes": {
                    "CKA_UNIQUE_ID": "2",
                    "CKA_CLASS": 2,
                    "CKA_KEY_TYPE": 0,
                    "CKA_DESTROYABLE": false,
                    "CKA_ID": "AQ==",
                    "CKA_LABEL": "Test RSA Key",
                    "CKA_MODIFIABLE": true,
                    "CKA_MODULUS": "AQIDBAUGBwg=",
                    "CKA_PRIVATE": false,
                    "CKA_PUBLIC_EXPONENT": "AQAB",
                    "CKA_TOKEN": true
                }
            }, {
                "attributes": {
                    "CKA_UNIQUE_ID": "3",
                    "CKA_CLASS": 3,
                    "CKA_KEY_TYPE": 0,
                    "CKA_DESTROYABLE": false,
                    "CKA_ID": "AQ==",
                    "CKA_LABEL": "Test RSA Key",
                    "CKA_MODIFIABLE": false,
                    "CKA_MODULUS": "AQIDBAUGBwg=",
                    "CKA_PRIVATE": true,
                    "CKA_SENSITIVE": true,
                    "CKA_EXTRACTABLE": false,
                    "CKA_PUBLIC_EXPONENT": "AQAB",
                    "CKA_PRIVATE_EXPONENT": "AQAD",
                    "CKA_TOKEN": true
                }
            }]
        });
        let file = std::fs::File::create(self.filename).unwrap();
        serde_json::to_writer_pretty(file, &test_token).unwrap();
        self.created = true;
    }

    fn get_slot(&self) -> CK_SLOT_ID {
        self.slot
    }

    fn mark_file_created(&mut self) {
        self.created = true;
    }

    fn make_init_args(&self) -> CK_C_INITIALIZE_ARGS {
        let reserved: String = format!("{}:{}", self.filename, self.slot);

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

    fn finalize(&mut self) {
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
        if self.created {
            std::fs::remove_file(self.filename).unwrap_or(());
        }
    }
}

#[test]
fn test_token() {
    let mut testdata = TestData::new("testdata/test_token.json");
    testdata.setup_db();

    let mut plist: CK_FUNCTION_LIST_PTR = std::ptr::null_mut();
    let pplist = &mut plist;
    let result = C_GetFunctionList(&mut *pplist);
    assert_eq!(result, 0);
    unsafe {
        let list: CK_FUNCTION_LIST = *plist;
        match list.C_Initialize {
            Some(value) => {
                let mut args = testdata.make_init_args();
                let args_ptr = &mut args as *mut CK_C_INITIALIZE_ARGS;
                let ret = value(args_ptr as *mut std::ffi::c_void);
                assert_eq!(ret, CKR_OK)
            }
            None => todo!(),
        }
    }

    testdata.finalize();
}

#[test]
fn test_random() {
    let mut testdata = TestData::new("testdata/test_random.json");
    testdata.setup_db();

    let mut args = testdata.make_init_args();
    let args_ptr = &mut args as *mut CK_C_INITIALIZE_ARGS;
    let mut ret = fn_initialize(args_ptr as *mut std::ffi::c_void);
    assert_eq!(ret, CKR_OK);
    let mut handle: CK_SESSION_HANDLE = CK_UNAVAILABLE_INFORMATION;
    ret = fn_open_session(
        testdata.get_slot(),
        CKF_SERIAL_SESSION,
        std::ptr::null_mut(),
        None,
        &mut handle,
    );
    assert_eq!(ret, CKR_OK);
    let data: &[u8] = &mut [0, 0, 0, 0];
    ret = fn_generate_random(
        handle,
        data.as_ptr() as *mut u8,
        data.len() as CK_ULONG,
    );
    assert_eq!(ret, CKR_OK);
    assert_ne!(data, &[0, 0, 0, 0]);
    ret = fn_close_session(handle);
    assert_eq!(ret, CKR_OK);

    testdata.finalize();
}

#[test]
fn test_login() {
    let mut testdata = TestData::new("testdata/test_login.json");
    testdata.setup_db();

    let mut args = testdata.make_init_args();
    let args_ptr = &mut args as *mut CK_C_INITIALIZE_ARGS;
    let mut ret = fn_initialize(args_ptr as *mut std::ffi::c_void);
    assert_eq!(ret, CKR_OK);

    let mut handle: CK_SESSION_HANDLE = CK_UNAVAILABLE_INFORMATION;
    ret = fn_open_session(
        testdata.get_slot(),
        CKF_SERIAL_SESSION,
        std::ptr::null_mut(),
        None,
        &mut handle,
    );
    assert_eq!(ret, CKR_OK);

    let mut info = CK_SESSION_INFO {
        slotID: CK_UNAVAILABLE_INFORMATION,
        state: CK_UNAVAILABLE_INFORMATION,
        flags: 0,
        ulDeviceError: 0,
    };
    ret = fn_get_session_info(handle, &mut info);
    assert_eq!(ret, CKR_OK);
    assert_eq!(info.state, CKS_RO_PUBLIC_SESSION);

    let mut handle2: CK_SESSION_HANDLE = CK_UNAVAILABLE_INFORMATION;
    ret = fn_open_session(
        testdata.get_slot(),
        CKF_SERIAL_SESSION | CKF_RW_SESSION,
        std::ptr::null_mut(),
        None,
        &mut handle2,
    );
    assert_eq!(ret, CKR_OK);
    ret = fn_get_session_info(handle2, &mut info);
    assert_eq!(ret, CKR_OK);
    assert_eq!(info.state, CKS_RW_PUBLIC_SESSION);

    /* login */
    let pin = "12345678";
    ret = fn_login(
        handle,
        CKU_USER,
        pin.as_ptr() as *mut _,
        pin.len() as CK_ULONG,
    );
    assert_eq!(ret, CKR_OK);

    ret = fn_get_session_info(handle, &mut info);
    assert_eq!(ret, CKR_OK);
    assert_eq!(info.state, CKS_RO_USER_FUNCTIONS);

    ret = fn_get_session_info(handle2, &mut info);
    assert_eq!(ret, CKR_OK);
    assert_eq!(info.state, CKS_RW_USER_FUNCTIONS);

    ret = fn_login(
        handle,
        CKU_USER,
        pin.as_ptr() as *mut _,
        pin.len() as CK_ULONG,
    );
    assert_eq!(ret, CKR_USER_ALREADY_LOGGED_IN);

    ret = fn_logout(handle2);
    assert_eq!(ret, CKR_OK);

    ret = fn_get_session_info(handle, &mut info);
    assert_eq!(ret, CKR_OK);
    assert_eq!(info.state, CKS_RO_PUBLIC_SESSION);

    ret = fn_get_session_info(handle2, &mut info);
    assert_eq!(ret, CKR_OK);
    assert_eq!(info.state, CKS_RW_PUBLIC_SESSION);

    ret = fn_logout(handle);
    assert_eq!(ret, CKR_USER_NOT_LOGGED_IN);

    ret = fn_close_session(handle);
    assert_eq!(ret, CKR_OK);
    ret = fn_close_session(handle2);
    assert_eq!(ret, CKR_OK);

    testdata.finalize();
}

#[test]
fn test_get_attr() {
    let mut testdata = TestData::new("testdata/test_get_attr.json");
    testdata.setup_db();

    let mut args = testdata.make_init_args();
    let args_ptr = &mut args as *mut CK_C_INITIALIZE_ARGS;
    let mut ret = fn_initialize(args_ptr as *mut std::ffi::c_void);
    assert_eq!(ret, CKR_OK);
    let mut session: CK_SESSION_HANDLE = CK_UNAVAILABLE_INFORMATION;
    ret = fn_open_session(
        testdata.get_slot(),
        CKF_SERIAL_SESSION,
        std::ptr::null_mut(),
        None,
        &mut session,
    );
    assert_eq!(ret, CKR_OK);

    let mut template = Vec::<CK_ATTRIBUTE>::new();
    let mut handle: CK_ULONG = CK_INVALID_HANDLE;

    /* public key data */
    template.push(make_attribute!(
        CKA_UNIQUE_ID,
        CString::new("2").unwrap().into_raw(),
        1
    ));
    ret = fn_find_objects_init(session, template.as_mut_ptr(), 1);
    assert_eq!(ret, CKR_OK);
    let mut count: CK_ULONG = 0;
    ret = fn_find_objects(session, &mut handle, 1, &mut count);
    assert_eq!(ret, CKR_OK);
    assert_eq!(count, 1);
    assert_ne!(handle, CK_INVALID_HANDLE);
    ret = fn_find_objects_final(session);
    assert_eq!(ret, CKR_OK);

    template.clear();
    template.push(make_attribute!(CKA_LABEL, std::ptr::null_mut(), 0));

    ret = fn_get_attribute_value(session, handle, template.as_mut_ptr(), 1);
    assert_eq!(ret, CKR_OK);
    assert_ne!(template[0].ulValueLen, 0);

    let data: &mut [u8] = &mut [0; 128];
    template[0].pValue = data.as_ptr() as *mut std::ffi::c_void;
    template[0].ulValueLen = 128;

    ret = fn_get_attribute_value(session, handle, template.as_mut_ptr(), 1);
    assert_eq!(ret, CKR_OK);
    let size = template[0].ulValueLen as usize;
    let value = std::str::from_utf8(&data[0..size]).unwrap();
    assert_eq!(value, "Test RSA Key");

    template[0].ulValueLen = 1;
    ret = fn_get_attribute_value(session, handle, template.as_mut_ptr(), 1);
    assert_eq!(ret, CKR_BUFFER_TOO_SMALL);

    /* private key data */
    template.clear();
    handle = CK_INVALID_HANDLE;
    template.push(make_attribute!(
        CKA_UNIQUE_ID,
        CString::new("3").unwrap().into_raw(),
        1
    ));
    /* first try should not find it */
    ret = fn_find_objects_init(session, template.as_mut_ptr(), 1);
    assert_eq!(ret, CKR_OK);
    let mut count: CK_ULONG = 0;
    ret = fn_find_objects(session, &mut handle, 1, &mut count);
    assert_eq!(ret, CKR_OK);
    assert_eq!(count, 0);
    assert_eq!(handle, CK_INVALID_HANDLE);
    ret = fn_find_objects_final(session);
    assert_eq!(ret, CKR_OK);

    /* login */
    let pin = "12345678";
    ret = fn_login(
        session,
        CKU_USER,
        pin.as_ptr() as *mut _,
        pin.len() as CK_ULONG,
    );
    assert_eq!(ret, CKR_OK);

    /* after login should find it */
    ret = fn_find_objects_init(session, template.as_mut_ptr(), 1);
    assert_eq!(ret, CKR_OK);
    let mut count: CK_ULONG = 0;
    ret = fn_find_objects(session, &mut handle, 1, &mut count);
    assert_eq!(ret, CKR_OK);
    assert_eq!(count, 1);
    assert_ne!(handle, CK_INVALID_HANDLE);
    ret = fn_find_objects_final(session);
    assert_eq!(ret, CKR_OK);

    template.clear();
    template.push(make_attribute!(
        CKA_PRIVATE_EXPONENT,
        (&mut [0; 128]).as_ptr(),
        128
    ));

    /* should fail for sensitive attributes */
    ret = fn_get_attribute_value(session, handle, template.as_mut_ptr(), 1);
    assert_eq!(ret, CKR_ATTRIBUTE_SENSITIVE);

    /* and succeed for public ones */
    template[0].type_ = CKA_PUBLIC_EXPONENT;
    template[0].ulValueLen = 128;
    ret = fn_get_attribute_value(session, handle, template.as_mut_ptr(), 1);
    assert_eq!(ret, CKR_OK);
    assert_eq!(template[0].ulValueLen, 3);

    ret = fn_logout(session);
    assert_eq!(ret, CKR_OK);
    ret = fn_close_session(session);
    assert_eq!(ret, CKR_OK);

    testdata.finalize();
}

#[test]
fn test_set_attr() {
    let mut testdata = TestData::new("testdata/test_set_attr.json");
    testdata.setup_db();

    let mut args = testdata.make_init_args();
    let args_ptr = &mut args as *mut CK_C_INITIALIZE_ARGS;
    let mut ret = fn_initialize(args_ptr as *mut std::ffi::c_void);
    assert_eq!(ret, CKR_OK);
    let mut session: CK_SESSION_HANDLE = CK_UNAVAILABLE_INFORMATION;
    ret = fn_open_session(
        testdata.get_slot(),
        CKF_SERIAL_SESSION,
        std::ptr::null_mut(),
        None,
        &mut session,
    );
    assert_eq!(ret, CKR_OK);

    let mut template = Vec::<CK_ATTRIBUTE>::new();
    let mut handle: CK_ULONG = CK_INVALID_HANDLE;

    /* public key data */
    template.push(make_attribute!(
        CKA_UNIQUE_ID,
        CString::new("2").unwrap().into_raw(),
        1
    ));
    ret = fn_find_objects_init(session, template.as_mut_ptr(), 1);
    assert_eq!(ret, CKR_OK);
    let mut count: CK_ULONG = 0;
    ret = fn_find_objects(session, &mut handle, 1, &mut count);
    assert_eq!(ret, CKR_OK);
    assert_eq!(count, 1);
    assert_ne!(handle, CK_INVALID_HANDLE);
    ret = fn_find_objects_final(session);
    assert_eq!(ret, CKR_OK);

    let label = "new label";
    template.clear();
    template.push(make_attribute!(CKA_LABEL, label.as_ptr(), label.len()));
    ret = fn_set_attribute_value(session, handle, template.as_mut_ptr(), 1);
    assert_eq!(ret, CKR_USER_NOT_LOGGED_IN);

    /* login */
    let pin = "12345678";
    ret = fn_login(
        session,
        CKU_USER,
        pin.as_ptr() as *mut _,
        pin.len() as CK_ULONG,
    );
    assert_eq!(ret, CKR_OK);

    ret = fn_set_attribute_value(session, handle, template.as_mut_ptr(), 1);
    assert_eq!(ret, CKR_SESSION_READ_ONLY);

    ret = fn_open_session(
        testdata.get_slot(),
        CKF_SERIAL_SESSION | CKF_RW_SESSION,
        std::ptr::null_mut(),
        None,
        &mut session,
    );
    assert_eq!(ret, CKR_OK);

    ret = fn_set_attribute_value(session, handle, template.as_mut_ptr(), 1);
    assert_eq!(ret, CKR_OK);

    let unique = "unsettable";
    template.clear();
    template.push(make_attribute!(
        CKA_UNIQUE_ID,
        unique.as_ptr(),
        unique.len()
    ));

    ret = fn_set_attribute_value(session, handle, template.as_mut_ptr(), 1);
    assert_eq!(ret, CKR_ATTRIBUTE_READ_ONLY);

    ret = fn_logout(session);
    assert_eq!(ret, CKR_OK);
    ret = fn_close_session(session);
    assert_eq!(ret, CKR_OK);

    testdata.finalize();
}

#[test]
fn test_copy_objects() {
    let mut testdata = TestData::new("testdata/test_copy_objects.json");
    testdata.setup_db();

    let mut args = testdata.make_init_args();
    let args_ptr = &mut args as *mut CK_C_INITIALIZE_ARGS;
    let mut ret = fn_initialize(args_ptr as *mut std::ffi::c_void);
    assert_eq!(ret, CKR_OK);
    let mut session: CK_SESSION_HANDLE = CK_UNAVAILABLE_INFORMATION;
    ret = fn_open_session(
        testdata.get_slot(),
        CKF_SERIAL_SESSION,
        std::ptr::null_mut(),
        None,
        &mut session,
    );
    assert_eq!(ret, CKR_OK);

    /* login */
    let pin = "12345678";
    ret = fn_login(
        session,
        CKU_USER,
        pin.as_ptr() as *mut _,
        pin.len() as CK_ULONG,
    );
    assert_eq!(ret, CKR_OK);

    /* public key data */
    let mut handle: CK_ULONG = CK_INVALID_HANDLE;
    let mut template = vec![make_attribute!(
        CKA_UNIQUE_ID,
        CString::new("2").unwrap().into_raw(),
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

    /* copy token object to session object */
    let mut intoken: CK_BBOOL = CK_FALSE;
    let mut private: CK_BBOOL = CK_TRUE;
    let mut template = vec![
        make_attribute!(CKA_TOKEN, &mut intoken as *mut _, CK_BBOOL_SIZE),
        make_attribute!(CKA_PRIVATE, &mut private as *mut _, CK_BBOOL_SIZE),
    ];
    let mut handle2: CK_ULONG = CK_INVALID_HANDLE;
    ret = fn_copy_object(
        session,
        handle,
        template.as_mut_ptr(),
        template.len() as CK_ULONG,
        &mut handle2,
    );
    assert_eq!(ret, CKR_OK);

    /* make not copyable object */
    let mut class = CKO_DATA;
    let mut copyable: CK_BBOOL = CK_FALSE;
    let application = "nocopy";
    let data = "data";
    let mut template = vec![
        make_attribute!(CKA_CLASS, &mut class as *mut _, CK_ULONG_SIZE),
        make_attribute!(CKA_COPYABLE, &mut copyable as *mut _, CK_BBOOL_SIZE),
        make_attribute!(
            CKA_APPLICATION,
            CString::new(application).unwrap().into_raw(),
            application.len()
        ),
        make_attribute!(
            CKA_VALUE,
            CString::new(data).unwrap().into_raw(),
            data.len()
        ),
    ];
    let mut handle: CK_ULONG = CK_INVALID_HANDLE;
    ret = fn_create_object(
        session,
        template.as_mut_ptr(),
        template.len() as CK_ULONG,
        &mut handle,
    );
    assert_eq!(ret, CKR_OK);

    /* copy token object to session object */
    let mut intoken: CK_BBOOL = CK_FALSE;
    let mut template = vec![make_attribute!(
        CKA_TOKEN,
        &mut intoken as *mut _,
        CK_BBOOL_SIZE
    )];
    let mut handle2: CK_ULONG = CK_INVALID_HANDLE;
    ret = fn_copy_object(
        session,
        handle,
        template.as_mut_ptr(),
        template.len() as CK_ULONG,
        &mut handle2,
    );
    assert_eq!(ret, CKR_ACTION_PROHIBITED);

    ret = fn_logout(session);
    assert_eq!(ret, CKR_OK);
    ret = fn_close_session(session);
    assert_eq!(ret, CKR_OK);

    testdata.finalize();
}

#[test]
fn test_create_objects() {
    let mut testdata = TestData::new("testdata/test_create_objects.json");
    testdata.setup_db();

    let mut args = testdata.make_init_args();
    let args_ptr = &mut args as *mut CK_C_INITIALIZE_ARGS;
    let mut ret = fn_initialize(args_ptr as *mut std::ffi::c_void);
    assert_eq!(ret, CKR_OK);
    let mut session: CK_SESSION_HANDLE = CK_UNAVAILABLE_INFORMATION;
    ret = fn_open_session(
        testdata.get_slot(),
        CKF_SERIAL_SESSION,
        std::ptr::null_mut(),
        None,
        &mut session,
    );
    assert_eq!(ret, CKR_OK);

    let mut class = CKO_DATA;
    let application = "test";
    let data = "payload";
    let mut template = vec![
        make_attribute!(CKA_CLASS, &mut class as *mut _, CK_ULONG_SIZE),
        make_attribute!(
            CKA_APPLICATION,
            CString::new(application).unwrap().into_raw(),
            application.len()
        ),
        make_attribute!(
            CKA_VALUE,
            CString::new(data).unwrap().into_raw(),
            data.len()
        ),
    ];

    let mut handle: CK_ULONG = CK_INVALID_HANDLE;
    ret = fn_create_object(
        session,
        template.as_mut_ptr(),
        template.len() as CK_ULONG,
        &mut handle,
    );
    assert_eq!(ret, CKR_USER_NOT_LOGGED_IN);

    /* login */
    let pin = "12345678";
    ret = fn_login(
        session,
        CKU_USER,
        pin.as_ptr() as *mut _,
        pin.len() as CK_ULONG,
    );
    assert_eq!(ret, CKR_OK);

    ret = fn_create_object(
        session,
        template.as_mut_ptr(),
        template.len() as CK_ULONG,
        &mut handle,
    );
    assert_eq!(ret, CKR_OK);

    let mut intoken: CK_BBOOL = CK_TRUE;
    template.push(make_attribute!(
        CKA_TOKEN,
        &mut intoken as *mut _,
        CK_BBOOL_SIZE
    ));

    ret = fn_create_object(
        session,
        template.as_mut_ptr(),
        template.len() as CK_ULONG,
        &mut handle,
    );
    assert_eq!(ret, CKR_SESSION_READ_ONLY);

    let login_session = session;

    ret = fn_open_session(
        testdata.get_slot(),
        CKF_SERIAL_SESSION | CKF_RW_SESSION,
        std::ptr::null_mut(),
        None,
        &mut session,
    );
    assert_eq!(ret, CKR_OK);

    ret = fn_create_object(
        session,
        template.as_mut_ptr(),
        template.len() as CK_ULONG,
        &mut handle,
    );
    assert_eq!(ret, CKR_OK);

    class = CKO_CERTIFICATE;
    let mut ctype = CKC_X_509;
    let mut trusted: CK_BBOOL = CK_FALSE;
    let ignored = "ignored";
    let bogus = "bogus";
    template = vec![
        make_attribute!(CKA_CLASS, &mut class as *mut _, CK_ULONG_SIZE),
        make_attribute!(CKA_TOKEN, &mut intoken as *mut _, CK_BBOOL_SIZE),
        make_attribute!(
            CKA_CERTIFICATE_TYPE,
            &mut ctype as *mut _,
            CK_ULONG_SIZE
        ),
        make_attribute!(CKA_TRUSTED, &mut trusted as *mut _, CK_BBOOL_SIZE),
        make_attribute!(CKA_CHECK_VALUE, ignored.as_ptr(), 42),
        make_attribute!(CKA_SUBJECT, bogus.as_ptr(), bogus.len()),
        make_attribute!(CKA_VALUE, bogus.as_ptr(), bogus.len()),
    ];

    ret = fn_create_object(
        session,
        template.as_mut_ptr(),
        template.len() as CK_ULONG,
        &mut handle,
    );
    assert_eq!(ret, CKR_OK);

    class = CKO_PUBLIC_KEY;
    let mut ktype = CKK_RSA;
    let mut encrypt: CK_BBOOL = CK_TRUE;
    let label = "RSA Public Encryption Key";
    let modulus_hex = "9D2E7820CE719B9194CDFE0FD751214193C4E9BE9BFA24D0E91B0FC3541C85885CB3CA95F8FDA4E129558EE41F653481E66A04ECB75808D57BD76ED9069767A2AFC9C3188F2BD42F045D0575765ADE27AD033B338DD5C2C1AAA899B89201A34BBB6ED9CCD0511325ADCF1C69718BD27196447D567F17E35A5865A3BC1FB35B3A605C25294D2A02E5F53D170C57814D8246F50CAE32321D8A5C44508238AC50519BD12221C740620198B762C2D1670A4B94655C783EAAD0E9A1244F8AE86D3B4A3DF26AC532B6A4EAA4FB4A35DF5C3A1B755DC5C17E451643D2DB722113C1E3E2CA59CFA592C80FB9B2D7056E19F5C84198371465CE7DFBA7390C3CE19D878121";
    let modulus =
        hex::decode(modulus_hex).expect("Failed to decode hex modulus");
    let exponent = hex::decode("010001").expect("Failed to decode exponent");
    template = vec![
        make_attribute!(CKA_CLASS, &mut class as *mut _, CK_ULONG_SIZE),
        make_attribute!(CKA_KEY_TYPE, &mut ktype as *mut _, CK_ULONG_SIZE),
        make_attribute!(CKA_ENCRYPT, &mut encrypt as *mut _, CK_BBOOL_SIZE),
        make_attribute!(
            CKA_LABEL,
            label.as_ptr() as *mut std::ffi::c_void,
            label.len()
        ),
        make_attribute!(
            CKA_MODULUS,
            modulus.as_ptr() as *mut std::ffi::c_void,
            modulus.len()
        ),
        make_attribute!(
            CKA_PUBLIC_EXPONENT,
            exponent.as_ptr() as *mut std::ffi::c_void,
            exponent.len()
        ),
    ];

    ret = fn_create_object(
        session,
        template.as_mut_ptr(),
        template.len() as CK_ULONG,
        &mut handle,
    );
    assert_eq!(ret, CKR_OK);

    let mut size: CK_ULONG = 0;
    ret = fn_get_object_size(session, handle, &mut size);
    assert_eq!(ret, CKR_OK);
    assert_ne!(size, 0);

    ret = fn_destroy_object(session, handle);
    assert_eq!(ret, CKR_OK);

    ret = fn_logout(login_session);
    assert_eq!(ret, CKR_OK);
    ret = fn_close_session(login_session);
    assert_eq!(ret, CKR_OK);
    ret = fn_close_session(session);
    assert_eq!(ret, CKR_OK);

    testdata.finalize();
}

#[test]
fn test_init_token() {
    let mut testdata = TestData::new("testdata/test_init_token.json");
    /* skip setup, we are creating an unitiliaized token */

    /* but mark the file as created,
     * so it will be cleaned up when the test is complete */
    testdata.mark_file_created();

    let mut args = testdata.make_init_args();
    let args_ptr = &mut args as *mut CK_C_INITIALIZE_ARGS;
    let mut ret = fn_initialize(args_ptr as *mut std::ffi::c_void);
    assert_eq!(ret, CKR_OK);
    let mut session: CK_SESSION_HANDLE = CK_UNAVAILABLE_INFORMATION;
    let mut ro_session: CK_SESSION_HANDLE = CK_UNAVAILABLE_INFORMATION;

    /* init once */
    let pin_value = "SO Pin Value";
    ret = fn_init_token(
        testdata.get_slot(),
        CString::new(pin_value).unwrap().into_raw() as *mut u8,
        pin_value.len() as CK_ULONG,
        std::ptr::null_mut(),
    );
    assert_eq!(ret, CKR_OK);

    /* verify wrong SO PIN fails */
    let bad_value = "SO Bad Value";
    ret = fn_init_token(
        testdata.get_slot(),
        CString::new(bad_value).unwrap().into_raw() as *mut u8,
        pin_value.len() as CK_ULONG,
        std::ptr::null_mut(),
    );
    assert_eq!(ret, CKR_PIN_INCORRECT);

    /* re-init */
    let pin_value = "SO Pin Value";
    ret = fn_init_token(
        testdata.get_slot(),
        CString::new(pin_value).unwrap().into_raw() as *mut u8,
        pin_value.len() as CK_ULONG,
        std::ptr::null_mut(),
    );
    assert_eq!(ret, CKR_OK);

    /* login as so */
    ret = fn_open_session(
        testdata.get_slot(),
        CKF_SERIAL_SESSION | CKF_RW_SESSION,
        std::ptr::null_mut(),
        None,
        &mut session,
    );
    assert_eq!(ret, CKR_OK);
    ret = fn_login(
        session,
        CKU_SO,
        CString::new(pin_value).unwrap().into_raw() as *mut u8,
        pin_value.len() as CK_ULONG,
    );
    assert_eq!(ret, CKR_OK);

    /* change so pin */
    let new_pin = "New SO Pin Value";
    ret = fn_set_pin(
        session,
        CString::new(pin_value).unwrap().into_raw() as *mut u8,
        pin_value.len() as CK_ULONG,
        CString::new(new_pin).unwrap().into_raw() as *mut u8,
        new_pin.len() as CK_ULONG,
    );
    assert_eq!(ret, CKR_OK);

    /* try to open ro_session and fail */
    ret = fn_open_session(
        testdata.get_slot(),
        CKF_SERIAL_SESSION,
        std::ptr::null_mut(),
        None,
        &mut ro_session,
    );
    assert_eq!(ret, CKR_SESSION_READ_WRITE_SO_EXISTS);

    /* logout and retry */
    ret = fn_logout(session);
    assert_eq!(ret, CKR_OK);
    ret = fn_open_session(
        testdata.get_slot(),
        CKF_SERIAL_SESSION,
        std::ptr::null_mut(),
        None,
        &mut ro_session,
    );
    assert_eq!(ret, CKR_OK);

    /* try to change pin and fail with ro_session */
    ret = fn_set_pin(
        ro_session,
        CString::new(pin_value).unwrap().into_raw() as *mut u8,
        pin_value.len() as CK_ULONG,
        CString::new(new_pin).unwrap().into_raw() as *mut u8,
        new_pin.len() as CK_ULONG,
    );
    assert_eq!(ret, CKR_SESSION_READ_ONLY);

    /* try to login again and fail because of ro_session exists */
    ret = fn_login(
        session,
        CKU_SO,
        CString::new(new_pin).unwrap().into_raw() as *mut u8,
        new_pin.len() as CK_ULONG,
    );
    assert_eq!(ret, CKR_SESSION_READ_ONLY_EXISTS);

    /* try again after closing ro_session */
    ret = fn_close_session(ro_session);
    assert_eq!(ret, CKR_OK);
    ret = fn_login(
        session,
        CKU_SO,
        CString::new(new_pin).unwrap().into_raw() as *mut u8,
        new_pin.len() as CK_ULONG,
    );
    assert_eq!(ret, CKR_OK);

    /* set user pin */
    let user_pin = "User PIN Value";
    ret = fn_init_pin(
        session,
        CString::new(user_pin).unwrap().into_raw() as *mut u8,
        user_pin.len() as CK_ULONG,
    );
    assert_eq!(ret, CKR_OK);

    /* try to log in as user and fail because SO active */
    ret = fn_login(
        session,
        CKU_USER,
        CString::new(user_pin).unwrap().into_raw() as *mut u8,
        user_pin.len() as CK_ULONG,
    );
    assert_eq!(ret, CKR_USER_ANOTHER_ALREADY_LOGGED_IN);

    /* retry user login after logout */
    ret = fn_logout(session);
    assert_eq!(ret, CKR_OK);
    ret = fn_login(
        session,
        CKU_USER,
        CString::new(user_pin).unwrap().into_raw() as *mut u8,
        user_pin.len() as CK_ULONG,
    );
    assert_eq!(ret, CKR_OK);

    /* change user pin as user */
    let new_user_pin = "New User PIN Value";
    ret = fn_set_pin(
        session,
        CString::new(user_pin).unwrap().into_raw() as *mut u8,
        user_pin.len() as CK_ULONG,
        CString::new(new_user_pin).unwrap().into_raw() as *mut u8,
        new_user_pin.len() as CK_ULONG,
    );
    assert_eq!(ret, CKR_OK);

    ret = fn_logout(session);
    assert_eq!(ret, CKR_OK);

    /* change back user pin after logout */
    ret = fn_set_pin(
        session,
        CString::new(new_user_pin).unwrap().into_raw() as *mut u8,
        new_user_pin.len() as CK_ULONG,
        CString::new(user_pin).unwrap().into_raw() as *mut u8,
        user_pin.len() as CK_ULONG,
    );
    assert_eq!(ret, CKR_OK);

    ret = fn_logout(session);
    assert_eq!(ret, CKR_OK);
    ret = fn_close_session(session);
    assert_eq!(ret, CKR_OK);

    testdata.finalize();
}

#[test]
fn test_get_mechs() {
    let mut testdata = TestData::new("testdata/test_get_mechs.json");
    testdata.setup_db();

    let mut args = testdata.make_init_args();
    let args_ptr = &mut args as *mut CK_C_INITIALIZE_ARGS;
    let mut ret = fn_initialize(args_ptr as *mut std::ffi::c_void);
    assert_eq!(ret, CKR_OK);
    let mut count: CK_ULONG = 0;
    ret = fn_get_mechanism_list(
        testdata.get_slot(),
        std::ptr::null_mut(),
        &mut count,
    );
    assert_eq!(ret, CKR_OK);
    let mut mechs: Vec<CK_MECHANISM_TYPE> = vec![0; count as usize];
    ret = fn_get_mechanism_list(
        testdata.get_slot(),
        mechs.as_mut_ptr() as CK_MECHANISM_TYPE_PTR,
        &mut count,
    );
    assert_eq!(ret, CKR_OK);
    assert_eq!(count, 2);
    assert_eq!(mechs[0], 1);
    let mut info: CK_MECHANISM_INFO = Default::default();
    ret = fn_get_mechanism_info(testdata.get_slot(), mechs[0], &mut info);
    assert_eq!(ret, CKR_OK);
    assert_eq!(info.ulMinKeySize, 1024);

    testdata.finalize();
}

#[test]
fn test_rsa_operations() {
    let mut testdata = TestData::new("testdata/test_rsa_operations.json");

    let mut args = testdata.make_init_args();
    let args_ptr = &mut args as *mut CK_C_INITIALIZE_ARGS;
    let mut ret = fn_initialize(args_ptr as *mut std::ffi::c_void);
    assert_eq!(ret, CKR_OK);

    /* open session */
    let mut session: CK_SESSION_HANDLE = CK_UNAVAILABLE_INFORMATION;
    ret = fn_open_session(
        testdata.get_slot(),
        CKF_SERIAL_SESSION,
        std::ptr::null_mut(),
        None,
        &mut session,
    );
    assert_eq!(ret, CKR_OK);

    /* login */
    let pin = "12345678";
    ret = fn_login(
        session,
        CKU_USER,
        pin.as_ptr() as *mut _,
        pin.len() as CK_ULONG,
    );
    assert_eq!(ret, CKR_OK);

    /* public key data */
    let mut handle: CK_ULONG = CK_INVALID_HANDLE;
    let mut template = vec![make_attribute!(
        CKA_UNIQUE_ID,
        CString::new("2").unwrap().into_raw(),
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

    /* encrypt init */
    let mut mechanism: CK_MECHANISM = CK_MECHANISM {
        mechanism: CKM_RSA_PKCS,
        pParameter: std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    ret = fn_encrypt_init(session, &mut mechanism, handle);
    assert_eq!(ret, CKR_OK);

    /* a second invocation should return an error */
    ret = fn_encrypt_init(session, &mut mechanism, handle);
    assert_eq!(ret, CKR_OPERATION_ACTIVE);

    let data = "plaintext";
    let enc: [u8; 512] = [0; 512];
    let mut enc_len: CK_ULONG = 512;
    ret = fn_encrypt(
        session,
        CString::new(data).unwrap().into_raw() as *mut u8,
        data.len() as CK_ULONG,
        enc.as_ptr() as *mut _,
        &mut enc_len,
    );
    assert_eq!(ret, CKR_OK);
    assert_eq!(enc_len, 256);

    /* a second invocation should return an error */
    ret = fn_encrypt(
        session,
        CString::new(data).unwrap().into_raw() as *mut u8,
        data.len() as CK_ULONG,
        enc.as_ptr() as *mut _,
        &mut enc_len,
    );
    assert_eq!(ret, CKR_OPERATION_NOT_INITIALIZED);

    /* calling final should also return error */
    let mut fin_len: CK_ULONG = 256;
    ret = fn_encrypt_final(session, enc.as_ptr() as *mut _, &mut fin_len);
    assert_eq!(ret, CKR_OPERATION_NOT_INITIALIZED);

    /* reinit and check via parts interface */
    ret = fn_encrypt_init(session, &mut mechanism, handle);
    assert_eq!(ret, CKR_OK);

    ret = fn_encrypt_update(
        session,
        CString::new(data).unwrap().into_raw() as *mut u8,
        data.len() as CK_ULONG,
        enc.as_ptr() as *mut _,
        &mut enc_len,
    );
    assert_eq!(ret, CKR_OK);

    /* a second time should still be fine */
    ret = fn_encrypt_update(
        session,
        CString::new(data).unwrap().into_raw() as *mut u8,
        data.len() as CK_ULONG,
        enc.as_ptr() as *mut _,
        &mut enc_len,
    );
    assert_eq!(ret, CKR_OK);

    /* but fn_encrypt should return an error */
    ret = fn_encrypt(
        session,
        CString::new(data).unwrap().into_raw() as *mut u8,
        data.len() as CK_ULONG,
        enc.as_ptr() as *mut _,
        &mut enc_len,
    );
    assert_eq!(ret, CKR_OPERATION_NOT_INITIALIZED);

    /* and an init should also return an error */
    ret = fn_encrypt_init(session, &mut mechanism, handle);
    assert_eq!(ret, CKR_OPERATION_ACTIVE);

    ret = fn_encrypt_final(session, enc.as_ptr() as *mut _, &mut fin_len);
    assert_eq!(ret, CKR_OK);
    assert_eq!(fin_len, 0);

    /* test that decryption returns the same data back */
    template = vec![make_attribute!(
        CKA_UNIQUE_ID,
        CString::new("3").unwrap().into_raw(),
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

    ret = fn_decrypt_init(session, &mut mechanism, handle);
    assert_eq!(ret, CKR_OK);

    let dec: [u8; 512] = [0; 512];
    let mut dec_len: CK_ULONG = 512;
    ret = fn_decrypt(
        session,
        enc.as_ptr() as *mut u8,
        enc_len,
        dec.as_ptr() as *mut u8,
        &mut dec_len,
    );
    assert_eq!(ret, CKR_OK);

    ret = fn_logout(session);
    assert_eq!(ret, CKR_OK);
    ret = fn_close_session(session);
    assert_eq!(ret, CKR_OK);

    testdata.finalize();
}

#[test]
fn test_session_objects() {
    let mut testdata = TestData::new("testdata/test_session_objects.json");
    testdata.setup_db();

    let mut args = testdata.make_init_args();
    let args_ptr = &mut args as *mut CK_C_INITIALIZE_ARGS;
    let mut ret = fn_initialize(args_ptr as *mut std::ffi::c_void);
    assert_eq!(ret, CKR_OK);
    let mut login_session: CK_SESSION_HANDLE = CK_UNAVAILABLE_INFORMATION;
    ret = fn_open_session(
        testdata.get_slot(),
        CKF_SERIAL_SESSION,
        std::ptr::null_mut(),
        None,
        &mut login_session,
    );
    assert_eq!(ret, CKR_OK);

    /* login */
    let pin = "12345678";
    ret = fn_login(
        login_session,
        CKU_USER,
        pin.as_ptr() as *mut _,
        pin.len() as CK_ULONG,
    );
    assert_eq!(ret, CKR_OK);

    let mut session: CK_SESSION_HANDLE = CK_UNAVAILABLE_INFORMATION;
    ret = fn_open_session(
        testdata.get_slot(),
        CKF_SERIAL_SESSION | CKF_RW_SESSION,
        std::ptr::null_mut(),
        None,
        &mut session,
    );
    assert_eq!(ret, CKR_OK);

    /* ephemeral session object */
    let mut class = CKO_DATA;
    let app1 = "app1";
    let data1 = "session data";
    let mut template = vec![
        make_attribute!(CKA_CLASS, &mut class as *mut _, CK_ULONG_SIZE),
        make_attribute!(
            CKA_APPLICATION,
            CString::new(app1).unwrap().into_raw(),
            app1.len()
        ),
        make_attribute!(
            CKA_VALUE,
            CString::new(data1).unwrap().into_raw(),
            data1.len()
        ),
    ];

    let mut handle1: CK_ULONG = CK_INVALID_HANDLE;
    ret = fn_create_object(
        session,
        template.as_mut_ptr(),
        template.len() as CK_ULONG,
        &mut handle1,
    );
    assert_eq!(ret, CKR_OK);

    /* store in token object */
    let mut intoken: CK_BBOOL = CK_TRUE;
    let app2 = "app2";
    let data2 = "token data";
    let mut template = vec![
        make_attribute!(CKA_CLASS, &mut class as *mut _, CK_ULONG_SIZE),
        make_attribute!(
            CKA_APPLICATION,
            CString::new(app2).unwrap().into_raw(),
            app2.len()
        ),
        make_attribute!(
            CKA_VALUE,
            CString::new(data2).unwrap().into_raw(),
            data2.len()
        ),
        make_attribute!(CKA_TOKEN, &mut intoken as *mut _, CK_BBOOL_SIZE),
    ];

    let mut handle2: CK_ULONG = CK_INVALID_HANDLE;
    ret = fn_create_object(
        session,
        template.as_mut_ptr(),
        template.len() as CK_ULONG,
        &mut handle2,
    );
    assert_eq!(ret, CKR_OK);

    ret = fn_close_session(session);
    assert_eq!(ret, CKR_OK);

    ret = fn_open_session(
        testdata.get_slot(),
        CKF_SERIAL_SESSION | CKF_RW_SESSION,
        std::ptr::null_mut(),
        None,
        &mut session,
    );
    assert_eq!(ret, CKR_OK);

    /* check that the session object handle invalid now */
    template.clear();
    template.push(make_attribute!(CKA_VALUE, std::ptr::null_mut(), 0));

    ret = fn_get_attribute_value(session, handle1, template.as_mut_ptr(), 1);
    assert_eq!(ret, CKR_OBJECT_HANDLE_INVALID);

    /* check that the session object is gone */
    template.clear();
    template.push(make_attribute!(
        CKA_APPLICATION,
        CString::new(app1).unwrap().into_raw(),
        app1.len()
    ));

    ret = fn_find_objects_init(session, template.as_mut_ptr(), 1);
    assert_eq!(ret, CKR_OK);
    let mut count: CK_ULONG = 0;
    ret = fn_find_objects(session, &mut handle1, 1, &mut count);
    assert_eq!(ret, CKR_OK);
    assert_eq!(count, 0);
    ret = fn_find_objects_final(session);
    assert_eq!(ret, CKR_OK);

    /* check that the token object is there */
    template.clear();
    template.push(make_attribute!(
        CKA_APPLICATION,
        CString::new(app2).unwrap().into_raw(),
        app2.len()
    ));

    handle2 = CK_INVALID_HANDLE;
    ret = fn_find_objects_init(session, template.as_mut_ptr(), 1);
    assert_eq!(ret, CKR_OK);
    ret = fn_find_objects(session, &mut handle2, 1, &mut count);
    assert_eq!(ret, CKR_OK);
    assert_eq!(count, 1);
    assert_ne!(handle2, CK_INVALID_HANDLE);
    ret = fn_find_objects_final(session);
    assert_eq!(ret, CKR_OK);

    ret = fn_logout(login_session);
    assert_eq!(ret, CKR_OK);
    ret = fn_close_session(login_session);
    assert_eq!(ret, CKR_OK);
    ret = fn_close_session(session);
    assert_eq!(ret, CKR_OK);

    testdata.finalize();
}
