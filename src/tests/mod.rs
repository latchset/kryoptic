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

mod init;

mod mechs;

mod aes;

mod rsa;

mod session;

mod ecc;

mod hashes;

mod signatures;

mod keys;

mod kdf_vectors;

mod kdfs;

mod aes_cmac_vectors;
