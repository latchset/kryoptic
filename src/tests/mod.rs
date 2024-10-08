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

const SO_PIN: &str = "12345678";
const USER_PIN: &str = "12345678";
const TOKEN_LABEL: &str = "INTERNAL TEST TOKEN";

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
    id: CK_ULONG,
}

static SLOTS: RwLock<Slots> = RwLock::new(Slots { id: 0 });

struct TestToken<'a> {
    slot: CK_SLOT_ID,
    filename: &'a str,
    finalize: Option<RwLockWriteGuard<'a, u64>>,
    sync: Option<RwLockReadGuard<'a, u64>>,
    session: CK_SESSION_HANDLE,
    session_rw: bool,
    encrypted: bool,
}

impl TestToken<'_> {
    fn new<'a>(filename: &'a str, encrypted: bool) -> TestToken {
        let mut slots = SLOTS.write().unwrap();
        slots.id += 1;
        while check_test_slot_busy(slots.id) {
            slots.id += 1;
        }

        TestToken {
            slot: slots.id,
            filename: filename,
            finalize: test_finalizer(),
            sync: Some(SYNC.read().unwrap()),
            session: CK_INVALID_HANDLE,
            session_rw: false,
            encrypted: encrypted,
        }
    }

    fn setup_db<'a>(&mut self, source: Option<&'a str>) {
        let basic = "testdata/test_basic.json";
        let filename = match source {
            Some(s) => s,
            None => basic,
        };
        /* remove the target filename if any */
        std::fs::remove_file(self.filename).unwrap_or(());

        let so_pin = SO_PIN.as_bytes().to_vec();
        let user_pin = USER_PIN.as_bytes().to_vec();
        let mut label = TOKEN_LABEL.as_bytes().to_vec();
        label.resize(32, 0x20);
        /* Init a brand new token */
        let mut token = Token::new(self.filename.to_string()).unwrap();
        token.use_encryption(self.encrypted);
        token.initialize(&so_pin, &label).unwrap();
        token.set_pin(CKU_USER, &user_pin, &vec![0u8; 0]).unwrap();
        token.login(CKU_USER, &user_pin);

        let test_data = storage::json::JsonToken::load(filename).unwrap();
        let mut cache = storage::memory::memory();
        test_data.prime_cache(&mut cache).unwrap();

        let objects = cache.search(&[]).unwrap();
        for obj in objects {
            token.insert_object(CK_INVALID_HANDLE, obj.clone()).unwrap();
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
        let mut td = Self::new(filename, false);
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

#[cfg(feature = "aes")]
mod aes;

#[cfg(feature = "rsa")]
mod rsa;

mod session;

#[cfg(feature = "ecc")]
mod ecc;

#[cfg(feature = "ecc")]
mod ecdh;

#[cfg(feature = "ecc")]
mod ecdh_vectors;

#[cfg(all(feature = "eddsa", not(feature = "fips")))]
mod eddsa;

#[cfg(feature = "hash")]
mod hashes;

mod signatures;

mod keys;

#[cfg(feature = "sp800_108")]
mod kdf_vectors;

mod kdfs;

#[cfg(feature = "hmac")]
mod mac_vectors;

#[cfg(feature = "aes")]
mod aes_kw_vectors;

#[cfg(feature = "tlskdf")]
mod tls;
