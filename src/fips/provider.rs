// Copyright 2024-2026 Simo Sorce
// See LICENSE.txt file for terms

//! This module implements support for using just the fips provider as
//! the "openssl crypto" provider, by wrapping the fips provider with
//! enough scaffolding to be able to use it directly instead of using
//! it through libcrypto.

use std::ffi::{c_char, c_int, c_uchar, c_void};
use std::ffi::{CStr, CString};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::ptr::{null, null_mut};
use std::slice;
use std::sync::{LazyLock, Mutex};

use crate::error::Result;
use crate::ossl::common::osslctx;

use ossl::bindings::*;
use ossl::OsslContext;

use getrandom;
use libc;

/* Entropy Stuff */
unsafe extern "C" fn fips_get_entropy(
    _handle: *const OSSL_CORE_HANDLE,
    pout: *mut *mut c_uchar,
    entropy: c_int,
    min_len: usize,
    max_len: usize,
) -> usize {
    if pout.is_null() {
        return 0;
    }
    let Ok(mut len) = usize::try_from(entropy) else {
        return 0;
    };
    if len < min_len {
        len = min_len;
    }
    if len > max_len {
        len = max_len;
    }
    /* FIXME: use secure alloc */
    let out = unsafe { fips_malloc(len, null(), 0) };
    if out.is_null() {
        return 0;
    }
    let r = unsafe { slice::from_raw_parts_mut(out as *mut u8, len) };
    if getrandom::fill(r).is_err() {
        unsafe { fips_clear_free(out, len, null(), 0) };
        return 0;
    }
    unsafe { *pout = out as *mut u8 };
    len
}

unsafe extern "C" fn fips_cleanup_entropy(
    _handle: *const OSSL_CORE_HANDLE,
    buf: *mut c_uchar,
    len: usize,
) {
    unsafe { fips_clear_free(buf as *mut c_void, len, null(), 0) }
}

unsafe extern "C" fn fips_get_nonce(
    handle: *const OSSL_CORE_HANDLE,
    pout: *mut *mut c_uchar,
    min_len: usize,
    max_len: usize,
    salt: *const c_void,
    salt_len: usize,
) -> usize {
    /* FIXME: OpenSSL returns some timer + salt string,
     * we return just getrandom data | salt string.
     * Need to check if this is ok */

    if pout.is_null() {
        return 0;
    }
    let Ok(entropy) = c_int::try_from(min_len) else {
        return 0;
    };

    let out =
        unsafe { fips_get_entropy(handle, pout, entropy, min_len, max_len) };
    if out == 0 {
        return 0;
    }
    if out < min_len {
        unsafe {
            fips_cleanup_entropy(handle, *pout, out);
            *pout = null_mut();
        }
        return 0;
    }

    if !salt.is_null() && salt_len > 0 {
        let mut len = out;
        if salt_len < len {
            len = salt_len;
        }

        let r = unsafe { slice::from_raw_parts_mut(*pout, len) };
        let s = unsafe { slice::from_raw_parts(salt as *const u8, len) };

        for p in r.iter_mut().zip(s.iter()) {
            *p.0 |= *p.1;
        }
    }

    return out;
}

#[cfg(test)]
static FIPS_MODULE_MAC: &CStr = c"2B:50:2F:5B:7C:78:13:E5:32:F2:EA:70:1F:D7:E1:96:A6:18:FB:00:D3:80:51:EA:D0:7F:A8:3C:11:9C:59:32";

static FIPS_DUMMY_CONTENT: &[u8; 59] =
    b"Dummy content for self-test integrity check with cargo test";

static FIPS_MODULE_FILE_NAME: LazyLock<CString> = LazyLock::new(|| {
    if cfg!(test) {
        let out_path = PathBuf::from(std::env!("OUT_DIR"));
        let dummy_file = out_path.join("dummy.txt");
        std::fs::write(&dummy_file, FIPS_DUMMY_CONTENT).unwrap();
        CString::new(dummy_file.to_string_lossy().as_bytes()).unwrap()
    } else {
        unsafe {
            let mut dlinfo = libc::Dl_info {
                dli_fname: null(),
                dli_fbase: null_mut(),
                dli_sname: null(),
                dli_saddr: null_mut(),
            };
            let res = libc::dladdr(
                OSSL_provider_init_int as *const c_void,
                &mut dlinfo,
            );
            if res == 0 {
                /* uh oh! */
                CStr::from_bytes_with_nul(&[0u8; 1]).unwrap().to_owned()
            } else {
                CStr::from_ptr(dlinfo.dli_fname).to_owned()
            }
        }
    }
});

static FIPS_INSTALL_VERSION: &CStr = c"1";
static FIPS_CONDITIONAL_ERRORS: &CStr = c"1";
static FIPS_SECURITY_CHECKS: &CStr = c"0";
static FIPS_PARAM_TLS1_PRF_EMS_CHECK: &CStr = c"1";
static FIPS_PARAM_DRBG_TRUNC_DIGEST: &CStr = c"1";
static FIPS_PARAM_RSA_PKCS15_PAD_DISABLED: &CStr = c"0";
static FIPS_PARAM_DEFER_TESTS_ENABLED: &CStr = c"1";

macro_rules! set_config_string {
    ($params:expr, $key:expr, $val:expr) => {
        let key = $key.as_ptr();
        let p = unsafe { OSSL_PARAM_locate($params, key as *const c_char) };
        if !p.is_null() {
            if unsafe { OSSL_PARAM_set_utf8_ptr(p, $val.as_ptr()) } != 1 {
                return 0;
            }
        }
    };
}

/* This function is used to return configuration options to the FIPS provider */
unsafe extern "C" fn fips_get_params(
    _prov: *const OSSL_CORE_HANDLE,
    params: *mut OSSL_PARAM,
) -> c_int {
    /* config options */
    set_config_string!(
        params,
        OSSL_PROV_PARAM_CORE_MODULE_FILENAME,
        FIPS_MODULE_FILE_NAME
    );

    #[cfg(test)]
    set_config_string!(
        params,
        OSSL_PROV_FIPS_PARAM_MODULE_MAC,
        FIPS_MODULE_MAC
    );
    set_config_string!(
        params,
        OSSL_PROV_FIPS_PARAM_INSTALL_VERSION,
        FIPS_INSTALL_VERSION
    );
    set_config_string!(
        params,
        OSSL_PROV_FIPS_PARAM_CONDITIONAL_ERRORS,
        FIPS_CONDITIONAL_ERRORS
    );
    set_config_string!(
        params,
        OSSL_PROV_FIPS_PARAM_DEFER_TESTS,
        FIPS_PARAM_DEFER_TESTS_ENABLED
    );

    /* features */
    set_config_string!(
        params,
        OSSL_PROV_FIPS_PARAM_SECURITY_CHECKS,
        FIPS_SECURITY_CHECKS
    );
    set_config_string!(
        params,
        OSSL_PROV_FIPS_PARAM_TLS1_PRF_EMS_CHECK,
        FIPS_PARAM_TLS1_PRF_EMS_CHECK
    );
    set_config_string!(
        params,
        OSSL_PROV_FIPS_PARAM_DRBG_TRUNC_DIGEST,
        FIPS_PARAM_DRBG_TRUNC_DIGEST
    );
    set_config_string!(
        params,
        OSSL_PROV_PARAM_RSA_PKCS15_PAD_DISABLED,
        FIPS_PARAM_RSA_PKCS15_PAD_DISABLED
    );

    return 1;
}

unsafe extern "C" fn fips_get_libctx(
    prov: *const OSSL_CORE_HANDLE,
) -> *mut OPENSSL_CORE_CTX {
    /* avoid looping during initialization, when FIPS_CANARY
     * is not yet set as the core handle */
    if prov.is_null() {
        return null_mut();
    }
    osslctx().ptr() as *mut OPENSSL_CORE_CTX
}

unsafe extern "C" fn fips_thread_start(
    _prov: *const OSSL_CORE_HANDLE,
    _handfn: OSSL_thread_stop_handler_fn,
    _arg: *mut c_void,
) -> c_int {
    /* FIXME: we currently ignore this and never call the callback */
    return 1;
}

/* Error reporting */
/* FIXME: deal with error reporting */

unsafe extern "C" fn fips_new_error(_prov: *const OSSL_CORE_HANDLE) {}
unsafe extern "C" fn fips_set_error_debug(
    _prov: *const OSSL_CORE_HANDLE,
    _file: *const c_char,
    _line: c_int,
    _func: *const c_char,
) {
}
#[allow(unused_variables)]
unsafe extern "C" fn fips_vset_error(
    _prov: *const OSSL_CORE_HANDLE,
    reason: u32,
    fmt: *const c_char,
    args: *mut c_void,
) {
    #[cfg(feature = "log")]
    {
        use log::{debug, error};
        use vsprintf::vsprintf;

        if !fmt.is_null() {
            match unsafe { vsprintf(fmt, args) } {
                Ok(s) => error!("Openssl Error({}): {:?}", reason, s),
                Err(e) => error!("Openssl Reason: {} [{:?}]", reason, e),
            }
        } else {
            debug!("Openssl Reason: {}", reason);
        }
    }
}
unsafe extern "C" fn fips_set_error_mark(
    _prov: *const OSSL_CORE_HANDLE,
) -> c_int {
    return 1;
}
unsafe extern "C" fn fips_clear_last_error_mark(
    _prov: *const OSSL_CORE_HANDLE,
) -> c_int {
    return 1;
}
unsafe extern "C" fn fips_pop_error_to_mark(
    _prov: *const OSSL_CORE_HANDLE,
) -> c_int {
    return 1;
}

/* BIO functions */

struct FileBio {
    file: File,
}

impl FileBio {
    fn new(filename: &str) -> Result<FileBio> {
        Ok(FileBio {
            file: File::open(Path::new(filename))?,
        })
    }

    fn read(&mut self, v: &mut [u8]) -> std::io::Result<usize> {
        let size = self.file.metadata()?.len();
        let pos = self.file.seek(SeekFrom::Current(0))?;
        if pos >= size {
            return Ok(0);
        }
        let mut avail = usize::try_from(size - pos).map_err(|e| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, e)
        })?;
        if v.len() < avail {
            avail = v.len();
        }
        self.file.read(&mut v[0..avail])
    }
}

struct MemBio<'a> {
    mem: &'a mut [u8],
    cursor: usize,
}

impl MemBio<'_> {
    fn new(v: &mut [u8]) -> MemBio<'_> {
        MemBio { mem: v, cursor: 0 }
    }

    fn read(&mut self, v: &mut [u8]) -> std::io::Result<usize> {
        let avail = self.mem.len() - self.cursor;
        if avail == 0 {
            return Ok(0);
        }
        if v.len() >= avail {
            v[0..avail].copy_from_slice(&self.mem[self.cursor..self.mem.len()]);
            self.cursor = self.mem.len();
            Ok(avail)
        } else {
            let end = self.cursor + v.len();
            v.copy_from_slice(&self.mem[self.cursor..end]);
            self.cursor = end;
            Ok(v.len())
        }
    }
}

enum Bio<'a> {
    FileOp(FileBio),
    MemOp(MemBio<'a>),
}

struct FipsBio<'a> {
    op: Bio<'a>,
}

/* FIXME: deal with mode, deal with errors */
unsafe extern "C" fn fips_bio_new_file(
    filename: *const c_char,
    _mode: *const c_char,
) -> *mut OSSL_CORE_BIO {
    if filename.is_null() {
        return null_mut();
    }
    let cstr_filename = unsafe { CStr::from_ptr(filename) };
    let name = match cstr_filename.to_str() {
        Ok(n) => n,
        Err(_) => return null_mut(),
    };
    let bio = match FileBio::new(name) {
        Ok(b) => b,
        Err(_) => return null_mut(),
    };
    Box::into_raw(Box::new(FipsBio {
        op: Bio::FileOp(bio),
    })) as *mut OSSL_CORE_BIO
}

unsafe extern "C" fn fips_bio_new_membuf(
    buf: *const c_void,
    len: c_int,
) -> *mut OSSL_CORE_BIO {
    if len == 0 {
        return null_mut();
    }
    let size = match usize::try_from(len) {
        Ok(s) => s,
        Err(_) => unsafe { libc::strlen(buf as *const c_char) },
    };
    let v = unsafe { slice::from_raw_parts_mut(buf as *mut u8, size) };
    Box::into_raw(Box::new(FipsBio {
        op: Bio::MemOp(MemBio::new(v)),
    })) as *mut OSSL_CORE_BIO
}

unsafe extern "C" fn fips_bio_read_ex(
    bio: *mut OSSL_CORE_BIO,
    data: *mut c_void,
    data_len: usize,
    bytes_read: *mut usize,
) -> c_int {
    if bio.is_null() {
        return 0;
    }

    let mut readvec =
        unsafe { slice::from_raw_parts_mut(data as *mut u8, data_len) };
    let mut fbio: Box<FipsBio> = unsafe { Box::from_raw(bio as *mut FipsBio) };

    let ret = match fbio.op {
        Bio::FileOp(ref mut op) => op.read(&mut readvec),
        Bio::MemOp(ref mut op) => op.read(&mut readvec),
    };

    /* make sure we do not free the data yet */
    let _ = Box::leak(fbio);

    if let Ok(b) = ret {
        if b != 0 {
            unsafe { *bytes_read = b };
            return 1;
        }
    }

    0
}

unsafe extern "C" fn fips_bio_free(bio: *mut OSSL_CORE_BIO) -> c_int {
    if !bio.is_null() {
        /* take control of the Bio again,
         * this will free it once it goes out of scope */
        let _: Box<FipsBio> = unsafe { Box::from_raw(bio as *mut FipsBio) };
    }
    return 1;
}

unsafe extern "C" fn fips_bio_vsnprintf(
    _buf: *mut c_char,
    _n: usize,
    _fmt: *const c_char,
    _args: *mut c_void,
) -> c_int {
    return 0;
}

/* Allocation functions */

unsafe fn fips_cleanse(addr: *mut c_void, pos: usize, len: usize) {
    unsafe { OPENSSL_cleanse(addr.wrapping_add(pos), len) }
}

unsafe extern "C" fn fips_malloc(
    num: usize,
    _file: *const std::os::raw::c_char,
    _line: std::os::raw::c_int,
) -> *mut std::os::raw::c_void {
    unsafe { libc::malloc(num) }
}

unsafe extern "C" fn fips_zalloc(
    num: usize,
    _file: *const std::os::raw::c_char,
    _line: std::os::raw::c_int,
) -> *mut std::os::raw::c_void {
    unsafe { libc::calloc(1, num) }
}

unsafe extern "C" fn fips_free(
    ptr: *mut c_void,
    _file: *const c_char,
    _line: c_int,
) {
    unsafe { libc::free(ptr) };
}

unsafe extern "C" fn fips_clear_free(
    ptr: *mut c_void,
    num: usize,
    file: *const c_char,
    line: c_int,
) {
    if !ptr.is_null() {
        if num != 0 {
            unsafe { fips_cleanse(ptr, 0, num) };
        }
        unsafe { fips_free(ptr, file, line) }
    }
}

unsafe extern "C" fn fips_realloc(
    addr: *mut c_void,
    num: usize,
    file: *const c_char,
    line: c_int,
) -> *mut c_void {
    if addr.is_null() {
        return unsafe { fips_malloc(num, file, line) };
    }
    if num == 0 {
        unsafe { fips_free(addr, file, line) };
        return null_mut();
    }
    unsafe { libc::realloc(addr, num) }
}

unsafe extern "C" fn fips_clear_realloc(
    addr: *mut c_void,
    old_num: usize,
    num: usize,
    file: *const c_char,
    line: c_int,
) -> *mut c_void {
    if addr.is_null() {
        return unsafe { fips_malloc(num, file, line) };
    }
    if num == 0 {
        unsafe { fips_clear_free(addr, old_num, file, line) };
        return null_mut();
    }
    if num < old_num {
        unsafe { fips_cleanse(addr, num, old_num - num) };
        return addr;
    }

    let ret = unsafe { fips_malloc(num, file, line) };
    if !ret.is_null() {
        unsafe {
            libc::memcpy(ret, addr, old_num);
            fips_clear_free(addr, old_num, file, line)
        };
    }
    ret
}

unsafe extern "C" fn fips_secure_allocated(_ptr: *const c_void) -> c_int {
    /* FIXME: once we have secure memory, return something sensible */
    return 0;
}

static FIPS_INDICATOR_CB: LazyLock<Mutex<OSSL_INDICATOR_CALLBACK>> =
    LazyLock::new(|| Mutex::new(None));

pub fn set_fips_indicator_callback(cb: OSSL_INDICATOR_CALLBACK) {
    let mut cell = FIPS_INDICATOR_CB.lock().unwrap();
    *cell = cb;
}

unsafe extern "C" fn fips_get_indicator_cb(
    _ptr: *mut OPENSSL_CORE_CTX,
    cb: *mut OSSL_INDICATOR_CALLBACK,
) {
    /* This is the function that is called by libfips.a to source
     * the fips indicator callback. Within the kryoptic's pkcs#11
     * driver we always return our own callback */

    if !cb.is_null() {
        let callback = match FIPS_INDICATOR_CB.lock() {
            Ok(cell) => *cell,
            Err(_) => None,
        };
        unsafe {
            *cb = callback;
        }
    }
}

/* FIPS Provider wrapping and initialization */

#[repr(C)]
struct FipsCanary {
    unused: [u8; 0],
}

static FIPS_CANARY: FipsCanary = FipsCanary { unused: [0u8; 0] };

struct FipsProvider {
    provider: *mut PROV_CTX,
    #[allow(dead_code)]
    dispatch: *const OSSL_DISPATCH,
    context: OsslContext,
}

unsafe impl Send for FipsProvider {}
unsafe impl Sync for FipsProvider {}

macro_rules! dispatcher_struct {
    (args1; $fn_id:expr; $fn:expr) => {
        OSSL_DISPATCH {
            function_id: i32::try_from($fn_id).unwrap(),
            function: Some(std::mem::transmute::<
                unsafe extern "C" fn(_) -> _,
                unsafe extern "C" fn(),
            >($fn)),
        }
    };
    (args2; $fn_id:expr; $fn:expr) => {
        OSSL_DISPATCH {
            function_id: i32::try_from($fn_id).unwrap(),
            function: Some(std::mem::transmute::<
                unsafe extern "C" fn(_, _) -> _,
                unsafe extern "C" fn(),
            >($fn)),
        }
    };
    (args3; $fn_id:expr; $fn:expr) => {
        OSSL_DISPATCH {
            function_id: i32::try_from($fn_id).unwrap(),
            function: Some(std::mem::transmute::<
                unsafe extern "C" fn(_, _, _) -> _,
                unsafe extern "C" fn(),
            >($fn)),
        }
    };
    (args4; $fn_id:expr; $fn:expr) => {
        OSSL_DISPATCH {
            function_id: i32::try_from($fn_id).unwrap(),
            function: Some(std::mem::transmute::<
                unsafe extern "C" fn(_, _, _, _) -> _,
                unsafe extern "C" fn(),
            >($fn)),
        }
    };
    (args5; $fn_id:expr; $fn:expr) => {
        OSSL_DISPATCH {
            function_id: i32::try_from($fn_id).unwrap(),
            function: Some(std::mem::transmute::<
                unsafe extern "C" fn(_, _, _, _, _) -> _,
                unsafe extern "C" fn(),
            >($fn)),
        }
    };
    (args6; $fn_id:expr; $fn:expr) => {
        OSSL_DISPATCH {
            function_id: i32::try_from($fn_id).unwrap(),
            function: Some(std::mem::transmute::<
                unsafe extern "C" fn(_, _, _, _, _, _) -> _,
                unsafe extern "C" fn(),
            >($fn)),
        }
    };
}

static FIPS_PROVIDER: LazyLock<FipsProvider> = LazyLock::new(|| unsafe {
    let core_dispatch = [
        /* Seeding functions */
        dispatcher_struct!(args5; OSSL_FUNC_GET_ENTROPY; fips_get_entropy),
        dispatcher_struct!(args5; OSSL_FUNC_GET_USER_ENTROPY; fips_get_entropy),
        dispatcher_struct!(args3; OSSL_FUNC_CLEANUP_ENTROPY; fips_cleanup_entropy),
        dispatcher_struct!(args3; OSSL_FUNC_CLEANUP_USER_ENTROPY; fips_cleanup_entropy),
        dispatcher_struct!(args6; OSSL_FUNC_GET_NONCE; fips_get_nonce),
        dispatcher_struct!(args6; OSSL_FUNC_GET_USER_NONCE; fips_get_nonce),
        dispatcher_struct!(args3; OSSL_FUNC_CLEANUP_NONCE; fips_cleanup_entropy),
        dispatcher_struct!(args3; OSSL_FUNC_CLEANUP_USER_NONCE; fips_cleanup_entropy),
        /* Initialization related functions */
        dispatcher_struct!(args2; OSSL_FUNC_CORE_GET_PARAMS; fips_get_params),
        dispatcher_struct!(args1; OSSL_FUNC_CORE_GET_LIBCTX; fips_get_libctx),
        dispatcher_struct!(args3; OSSL_FUNC_CORE_THREAD_START; fips_thread_start),
        /* FIXME: error handling is all a no-op */
        dispatcher_struct!(args1; OSSL_FUNC_CORE_NEW_ERROR; fips_new_error),
        dispatcher_struct!(args4; OSSL_FUNC_CORE_SET_ERROR_DEBUG; fips_set_error_debug),
        dispatcher_struct!(args4; OSSL_FUNC_CORE_VSET_ERROR; fips_vset_error),
        dispatcher_struct!(args1; OSSL_FUNC_CORE_SET_ERROR_MARK; fips_set_error_mark),
        dispatcher_struct!(args1; OSSL_FUNC_CORE_CLEAR_LAST_ERROR_MARK; fips_clear_last_error_mark),
        dispatcher_struct!(args1; OSSL_FUNC_CORE_POP_ERROR_TO_MARK; fips_pop_error_to_mark),
        /* FIXME: Bio functions */
        dispatcher_struct!(args2; OSSL_FUNC_BIO_NEW_FILE; fips_bio_new_file),
        dispatcher_struct!(args2; OSSL_FUNC_BIO_NEW_MEMBUF; fips_bio_new_membuf),
        dispatcher_struct!(args4; OSSL_FUNC_BIO_READ_EX; fips_bio_read_ex),
        dispatcher_struct!(args1; OSSL_FUNC_BIO_FREE; fips_bio_free),
        dispatcher_struct!(args4; OSSL_FUNC_BIO_VSNPRINTF; fips_bio_vsnprintf),
        /* Allocation functions */
        dispatcher_struct!(args3; OSSL_FUNC_CRYPTO_MALLOC; fips_malloc),
        dispatcher_struct!(args3; OSSL_FUNC_CRYPTO_ZALLOC; fips_zalloc),
        dispatcher_struct!(args3; OSSL_FUNC_CRYPTO_FREE; fips_free),
        dispatcher_struct!(args4; OSSL_FUNC_CRYPTO_CLEAR_FREE; fips_clear_free),
        dispatcher_struct!(args4; OSSL_FUNC_CRYPTO_REALLOC; fips_realloc),
        dispatcher_struct!(args5; OSSL_FUNC_CRYPTO_CLEAR_REALLOC; fips_clear_realloc),
        /* FIXME: research how to get mlocked, aka secure, memory */
        dispatcher_struct!(args3; OSSL_FUNC_CRYPTO_SECURE_MALLOC; fips_malloc),
        dispatcher_struct!(args3; OSSL_FUNC_CRYPTO_SECURE_ZALLOC; fips_zalloc),
        dispatcher_struct!(args3; OSSL_FUNC_CRYPTO_SECURE_FREE; fips_free),
        dispatcher_struct!(args4; OSSL_FUNC_CRYPTO_SECURE_CLEAR_FREE; fips_clear_free),
        dispatcher_struct!(args1; OSSL_FUNC_CRYPTO_SECURE_ALLOCATED; fips_secure_allocated),
        /* Indicator function */
        dispatcher_struct!(args2; OSSL_FUNC_INDICATOR_CB; fips_get_indicator_cb),
        /* terminate table */
        OSSL_DISPATCH {
            function_id: 0,
            function: None,
        },
    ];

    let mut provider: *mut PROV_CTX = null_mut();
    let provider_ptr: *mut *mut PROV_CTX = &mut provider;

    let mut fips_dispatch: *const OSSL_DISPATCH = null_mut();

    let ret = OSSL_provider_init_int(
        null_mut(),
        core_dispatch.as_ptr(),
        &mut fips_dispatch,
        provider_ptr as *mut *mut std::os::raw::c_void,
    );
    assert!(ret == 1);

    ossl_prov_ctx_set0_handle(
        provider,
        &FIPS_CANARY as *const _ as *const ossl_core_handle_st,
    );

    /* we assume libctx is created once for the provider and
     * never changed afterwards */
    let osslctx = ossl_prov_ctx_get0_libctx(provider);
    FipsProvider {
        provider: provider,
        dispatch: fips_dispatch,
        context: OsslContext::from_ctx(osslctx),
    }
});

pub fn init() {
    assert!((*FIPS_PROVIDER).provider != null_mut());
}

pub(crate) fn get_libctx() -> OsslContext {
    OsslContext::from_fips(
        (*FIPS_PROVIDER).context.ptr(),
        (*FIPS_PROVIDER).provider as *mut c_void,
    )
}
