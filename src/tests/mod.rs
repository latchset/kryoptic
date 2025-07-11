// Copyright 2023 Simo Sorce
// See LICENSE.txt file for terms

use std::ffi::CString;
use std::fs::{create_dir_all, remove_dir_all, OpenOptions};
use std::io::Write;
use std::sync::Once;

#[cfg(feature = "log")]
use crate::log;

use crate::misc::*;
use crate::storage::StorageDBInfo;
use crate::*;

use hex;

#[macro_use]
mod util;
use util::*;

mod json_objects;
mod token;

const TESTDIR: &str = "test/kryoptic";
const SO_PIN: &str = "12345678";
const USER_PIN: &str = "12345678";
const TOKEN_LABEL: &str = "INTERNAL TEST TOKEN";

/* note that the following concoction to sync threads is not entirely race free
 * as it assumes all tests initialize before all of the others complete. */
static FINI: RwLock<u64> = RwLock::new(0);
static SYNC: RwLock<u64> = RwLock::new(0);

static INIT: Once = Once::new();
fn test_initialize() -> Option<RwLockWriteGuard<'static, u64>> {
    #[cfg(feature = "log")]
    log::test_init();

    let mut winner: Option<RwLockWriteGuard<u64>> = None;
    INIT.call_once(|| {
        /* ignore failure to remove */
        let _ = remove_dir_all(TESTDIR);
        create_dir_all(TESTDIR).unwrap();

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
    name: String,
    dbtype: String,
    dbargs: String,
    finalize: Option<RwLockWriteGuard<'a, u64>>,
    sync: Option<RwLockReadGuard<'a, u64>>,
    session: CK_SESSION_HANDLE,
    session_rw: bool,
}

impl TestToken<'_> {
    fn new<'a>(name: String) -> TestToken<'a> {
        let (dbtype, dbargs) = Self::get_default_db(&name);

        Self::new_type(String::from(dbtype), dbargs, name)
    }

    fn new_type<'a>(
        dbtype: String,
        dbargs: String,
        name: String,
    ) -> TestToken<'a> {
        let mut slots = SLOTS.write().unwrap();
        slots.id += 1;
        while check_test_slot_busy(slots.id) {
            slots.id += 1;
        }

        let finalizer = test_initialize();

        TestToken {
            slot: slots.id,
            name: name,
            dbtype: dbtype,
            dbargs: dbargs,
            finalize: finalizer,
            sync: Some(SYNC.read().unwrap()),
            session: CK_INVALID_HANDLE,
            session_rw: false,
        }
    }

    fn setup_db<'a>(&mut self, import: Option<&'a str>) {
        let so_pin = SO_PIN.as_bytes().to_vec();
        let user_pin = USER_PIN.as_bytes().to_vec();
        let mut label = TOKEN_LABEL.as_bytes().to_vec();
        label.resize(32, 0x20);
        /* Init a brand new token */
        let mut token =
            Token::new(&self.dbtype, Some(self.dbargs.clone())).unwrap();
        token.initialize(&so_pin, &label).unwrap();
        token.login(CKU_SO, &so_pin);
        token.set_pin(CKU_USER, &user_pin, &vec![0u8; 0]).unwrap();
        token.logout();
        token.login(CKU_USER, &user_pin);

        match import {
            Some(s) => {
                let test_data = json_objects::JsonObjects::load(s).unwrap();
                let mut tstore = json_objects::TransferStorage::new();
                test_data.prime_store(&mut tstore).unwrap();

                let objects = tstore.search(&[]).unwrap();
                for obj in objects {
                    token
                        .insert_object(CK_INVALID_HANDLE, obj.clone())
                        .unwrap();
                }
            }
            None => (),
        };
    }

    fn get_slot(&self) -> CK_SLOT_ID {
        self.slot
    }

    fn make_config_file(&self, confname: &str, mechs: Option<Vec<String>>) {
        let mut conf = config::Config::new();
        let mut slot =
            config::Slot::with_db(&self.dbtype, Some(self.dbargs.clone()));
        slot.slot = u32::try_from(self.get_slot()).unwrap();
        slot.mechanisms = mechs;
        conf.add_slot(slot).unwrap();
        let data = toml::to_string(&conf).unwrap();
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(confname)
            .unwrap();
        file.write(data.as_bytes()).unwrap();
    }

    fn make_init_string(&self) -> String {
        let confname = format!("{}/{}.conf", TESTDIR, self.name);
        self.make_config_file(&confname, None);
        format!("kryoptic_conf={}", confname)
    }

    fn make_init_args(reserved: Option<String>) -> CK_C_INITIALIZE_ARGS {
        CK_C_INITIALIZE_ARGS {
            CreateMutex: None,
            DestroyMutex: None,
            LockMutex: None,
            UnlockMutex: None,
            flags: 0,
            pReserved: match reserved {
                Some(r) => void_ptr!(CString::new(r).unwrap().into_raw()),
                None => std::ptr::null_mut(),
            },
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
    }

    #[allow(unreachable_code)]
    fn get_default_db(name: &str) -> (&'static str, String) {
        /* in order of preference, the first wins */
        #[cfg(feature = "nssdb")]
        {
            let ret = format!("configDir={}/{}/", TESTDIR, name);
            return (storage::nssdb::DBINFO.dbtype(), ret);
        }
        #[cfg(feature = "sqlitedb")]
        {
            let ret = format!("{}/{}.sql", TESTDIR, name);
            return (storage::sqlite::DBINFO.dbtype(), ret);
        }
        #[cfg(feature = "memorydb")]
        {
            let ret = format!("flags=encrypt");
            return (storage::memory::DBINFO.dbtype(), ret);
        }
        panic!("At least one of the storage backends needs to be enabled")
    }

    fn initialized<'a>(
        name: &'a str,
        import: Option<&'a str>,
    ) -> TestToken<'a> {
        let mut td = Self::new(String::from(name));
        td.setup_db(import);

        let mut args = Self::make_init_args(Some(td.make_init_string()));
        let args_ptr = &mut args as *mut CK_C_INITIALIZE_ARGS;
        let ret = fn_initialize(args_ptr as *mut std::ffi::c_void);
        assert_eq!(ret, CKR_OK);

        /* By default we force relaxed behavior so tests can access
         * data to check results */
        #[cfg(feature = "fips")]
        set_fips_behavior(
            td.get_slot(),
            config::FipsBehavior {
                keys_always_sensitive: false,
            },
        );

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

#[cfg(feature = "ecdsa")]
mod ecc;

#[cfg(feature = "ec_montgomery")]
mod ec_montgomery;

#[cfg(feature = "ecdh")]
mod ecdh;

#[cfg(feature = "ecdh")]
mod ecdh_vectors;

#[cfg(feature = "eddsa")]
mod eddsa;

#[cfg(feature = "ffdh")]
mod ffdh;

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

#[cfg(feature = "simplekdf")]
mod simplekdf;

#[cfg(feature = "nssdb")]
mod nssdb;

mod combined;

#[cfg(feature = "mlkem")]
mod mlkem;

#[cfg(feature = "mldsa")]
mod mldsa;
