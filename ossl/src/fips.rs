// Copyright 2025 Simo Sorce
// See LICENSE.txt file for terms

//! This module implements support for using just the fips provider as
//! the "openssl crypto" provider, by wrapping the fips provider with
//! enough scaffolding to be able to use it directly instead of using
//! it through libcrypto.

use std::cell::Cell;
use std::ffi::{c_char, c_int, c_uchar, c_void};
use std::ffi::{CStr, CString};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;
use std::slice;
use std::sync::LazyLock;

use crate::bindings::*;
use crate::pkey::EvpPkey;
use crate::signature::SigAlg;
use crate::{cstr, void_ptr, Error, ErrorKind, OsslContext};

use getrandom;
use libc;

/* Entropy Stuff */
unsafe extern "C" fn fips_get_entropy(
    _handle: *const OSSL_CORE_HANDLE,
    pout: *mut *mut ::std::os::raw::c_uchar,
    entropy: ::std::os::raw::c_int,
    min_len: usize,
    max_len: usize,
) -> usize {
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
    let out = fips_malloc(len, std::ptr::null(), 0);
    if out == std::ptr::null_mut() {
        return 0;
    }
    let r = slice::from_raw_parts_mut(out as *mut u8, len);
    if getrandom::fill(r).is_err() {
        fips_clear_free(out, len, std::ptr::null(), 0);
        return 0;
    }
    *pout = out as *mut u8;
    len
}

unsafe extern "C" fn fips_cleanup_entropy(
    _handle: *const OSSL_CORE_HANDLE,
    buf: *mut ::std::os::raw::c_uchar,
    len: usize,
) {
    fips_clear_free(
        buf as *mut ::std::os::raw::c_void,
        len,
        std::ptr::null(),
        0,
    );
}

unsafe extern "C" fn fips_get_nonce(
    handle: *const OSSL_CORE_HANDLE,
    pout: *mut *mut ::std::os::raw::c_uchar,
    min_len: usize,
    max_len: usize,
    salt: *const ::std::os::raw::c_void,
    salt_len: usize,
) -> usize {
    /* FIXME: OpenSSL returns some timer + salt string,
     * we return just getrandom data | salt string.
     * Need to check if this is ok */

    let Ok(entropy) = c_int::try_from(min_len) else {
        return 0;
    };

    let out = fips_get_entropy(handle, pout, entropy, min_len, max_len);
    if out == 0 {
        return 0;
    }
    if out < min_len {
        fips_cleanup_entropy(handle, *pout, out);
        *pout = std::ptr::null_mut();
        return 0;
    }

    let mut len = out;
    if salt_len < len {
        len = salt_len;
    }

    let r = slice::from_raw_parts_mut(*pout as *mut u8, len);
    let s = slice::from_raw_parts(salt as *const u8, len);

    for p in r.iter_mut().zip(s.iter()) {
        *p.0 |= *p.1;
    }

    return out;
}

#[cfg(feature = "dummy-integrity")]
static FIPS_MODULE_MAC: &CStr = c"2B:50:2F:5B:7C:78:13:E5:32:F2:EA:70:1F:D7:E1:96:A6:18:FB:00:D3:80:51:EA:D0:7F:A8:3C:11:9C:59:32";

#[cfg(feature = "dummy-integrity")]
static FIPS_DUMMY_CONTENT: &[u8; 59] =
    b"Dummy content for self-test integrity check with cargo test";

static FIPS_MODULE_FILE_NAME: LazyLock<CString> = LazyLock::new(|| {
    #[cfg(feature = "dummy-integrity")]
    {
        let out_path = std::path::PathBuf::from(std::env!("OUT_DIR"));
        let dummy_file = out_path.join("dummy.txt");
        std::fs::write(&dummy_file, FIPS_DUMMY_CONTENT).unwrap();
        CString::new(dummy_file.to_string_lossy().as_bytes()).unwrap()
    }
    #[cfg(not(feature = "dummy-integrity"))]
    {
        unsafe {
            let mut dlinfo = libc::Dl_info {
                dli_fname: std::ptr::null(),
                dli_fbase: std::ptr::null_mut(),
                dli_sname: std::ptr::null(),
                dli_saddr: std::ptr::null_mut(),
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

/* Lets always run KATS for now:
 * static FIPS_INSTALL_MAC: &str = "41:9C:38:C2:8F:59:09:43:2C:AA:2F:58:36:2D:D9:04:F9:6C:56:8B:09:E0:18:3A:2E:D6:CC:69:05:04:E1:11\0";
 * static FIPS_INSTALL_STATUS: &str = "INSTALL_SELF_TEST_KATS_RUN\0"; */

static FIPS_INSTALL_VERSION: &CStr = c"1";
static FIPS_CONDITIONAL_ERRORS: &CStr = c"1";
static FIPS_SECURITY_CHECKS: &CStr = c"0";
static FIPS_PARAM_TLS1_PRF_EMS_CHECK: &CStr = c"1";
static FIPS_PARAM_DRBG_TRUNC_DIGEST: &CStr = c"1";
static FIPS_PARAM_RSA_PKCS15_PAD_DISABLED: &CStr = c"0";

macro_rules! set_config_string {
    ($params:expr, $key:expr, $val:expr) => {
        let key = $key.as_ptr();
        let p = unsafe { OSSL_PARAM_locate($params, key) };
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
) -> ::std::os::raw::c_int {
    /* config options */
    set_config_string!(
        params,
        cstr!(OSSL_PROV_PARAM_CORE_MODULE_FILENAME),
        FIPS_MODULE_FILE_NAME
    );

    #[cfg(feature = "dummy-integrity")]
    set_config_string!(
        params,
        cstr!(OSSL_PROV_FIPS_PARAM_MODULE_MAC),
        FIPS_MODULE_MAC
    );
    /* Lets always run KATS for now:
     *  set_config_string!(
     *      params,
     *      OSSL_PROV_FIPS_PARAM_INSTALL_MAC,
     *      FIPS_INSTALL_MAC
     *  );
     *  set_config_string!(
     *      params,
     *      OSSL_PROV_FIPS_PARAM_INSTALL_STATUS,
     *      FIPS_INSTALL_STATUS
     *  );
     */
    set_config_string!(
        params,
        cstr!(OSSL_PROV_FIPS_PARAM_INSTALL_VERSION),
        FIPS_INSTALL_VERSION
    );
    set_config_string!(
        params,
        cstr!(OSSL_PROV_FIPS_PARAM_CONDITIONAL_ERRORS),
        FIPS_CONDITIONAL_ERRORS
    );

    /* features */
    set_config_string!(
        params,
        cstr!(OSSL_PROV_FIPS_PARAM_SECURITY_CHECKS),
        FIPS_SECURITY_CHECKS
    );
    set_config_string!(
        params,
        cstr!(OSSL_PROV_FIPS_PARAM_TLS1_PRF_EMS_CHECK),
        FIPS_PARAM_TLS1_PRF_EMS_CHECK
    );
    set_config_string!(
        params,
        cstr!(OSSL_PROV_FIPS_PARAM_DRBG_TRUNC_DIGEST),
        FIPS_PARAM_DRBG_TRUNC_DIGEST
    );
    set_config_string!(
        params,
        cstr!(OSSL_PROV_PARAM_RSA_PKCS15_PAD_DISABLED),
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
        return std::ptr::null_mut();
    }
    get_libctx().ptr() as *mut OPENSSL_CORE_CTX
}

unsafe extern "C" fn fips_thread_start(
    _prov: *const OSSL_CORE_HANDLE,
    _handfn: OSSL_thread_stop_handler_fn,
    _arg: *mut ::std::os::raw::c_void,
) -> ::std::os::raw::c_int {
    /* FIXME: we currently ignore this and never call the callback */
    return 1;
}

/* Error reporting */
/* FIXME: deal with error reporting */

unsafe extern "C" fn fips_new_error(_prov: *const OSSL_CORE_HANDLE) {}
unsafe extern "C" fn fips_set_error_debug(
    _prov: *const OSSL_CORE_HANDLE,
    _file: *const ::std::os::raw::c_char,
    _line: ::std::os::raw::c_int,
    _func: *const ::std::os::raw::c_char,
) {
}
#[allow(unused_variables)]
unsafe extern "C" fn fips_vset_error(
    _prov: *const OSSL_CORE_HANDLE,
    reason: u32,
    fmt: *const ::std::os::raw::c_char,
    args: *mut c_void,
) {
    #[cfg(feature = "log")]
    {
        use log::{debug, error};
        use vsprintf::vsprintf;

        if !fmt.is_null() {
            match vsprintf(fmt, args) {
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
) -> ::std::os::raw::c_int {
    return 1;
}
unsafe extern "C" fn fips_clear_last_error_mark(
    _prov: *const OSSL_CORE_HANDLE,
) -> ::std::os::raw::c_int {
    return 1;
}
unsafe extern "C" fn fips_pop_error_to_mark(
    _prov: *const OSSL_CORE_HANDLE,
) -> ::std::os::raw::c_int {
    return 1;
}

/* BIO functions */

struct FileBio {
    file: File,
}

impl FileBio {
    fn new(filename: &str) -> Result<FileBio, Error> {
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
    filename: *const ::std::os::raw::c_char,
    _mode: *const ::std::os::raw::c_char,
) -> *mut OSSL_CORE_BIO {
    if filename == std::ptr::null_mut() {
        return std::ptr::null_mut();
    }
    let name = match CStr::from_ptr(filename as *const _).to_str() {
        Ok(n) => n,
        Err(_) => return std::ptr::null_mut(),
    };
    let bio = match FileBio::new(name) {
        Ok(b) => b,
        Err(_) => return std::ptr::null_mut(),
    };
    Box::into_raw(Box::new(FipsBio {
        op: Bio::FileOp(bio),
    })) as *mut OSSL_CORE_BIO
}

unsafe extern "C" fn fips_bio_new_membuf(
    buf: *const ::std::os::raw::c_void,
    len: ::std::os::raw::c_int,
) -> *mut OSSL_CORE_BIO {
    let size = if len > 0 {
        usize::try_from(len).unwrap()
    } else if len < 0 {
        usize::try_from(libc::strlen(buf as *const c_char)).unwrap()
    } else {
        return std::ptr::null_mut();
    };
    let v = slice::from_raw_parts_mut(buf as *mut u8, size);
    Box::into_raw(Box::new(FipsBio {
        op: Bio::MemOp(MemBio::new(v)),
    })) as *mut OSSL_CORE_BIO
}

unsafe extern "C" fn fips_bio_read_ex(
    bio: *mut OSSL_CORE_BIO,
    data: *mut ::std::os::raw::c_void,
    data_len: usize,
    bytes_read: *mut usize,
) -> ::std::os::raw::c_int {
    let mut ret: std::os::raw::c_int = 0;
    if bio == std::ptr::null_mut() {
        return ret;
    }
    let mut readvec = slice::from_raw_parts_mut(data as *mut u8, data_len);
    let mut fbio: Box<FipsBio> = Box::from_raw(bio as *mut FipsBio);
    match fbio.op {
        Bio::FileOp(ref mut op) => match op.read(&mut readvec) {
            Ok(b) => {
                if b != 0 {
                    ret = 1;
                    *bytes_read = b;
                }
            }
            Err(_) => ret = 0,
        },
        Bio::MemOp(ref mut op) => match op.read(&mut readvec) {
            Ok(b) => {
                if b != 0 {
                    ret = 1;
                    *bytes_read = b
                }
            }
            Err(_) => ret = 0,
        },
    }

    /* make sure we do not free the data yet */
    let _ = Box::leak(fbio);
    return ret;
}

unsafe extern "C" fn fips_bio_free(
    bio: *mut OSSL_CORE_BIO,
) -> ::std::os::raw::c_int {
    if bio != std::ptr::null_mut() {
        /* take control of the Bio again,
         * this will free it once it goes out of scope */
        let _: Box<FipsBio> = Box::from_raw(bio as *mut FipsBio);
    }
    return 1;
}
unsafe extern "C" fn fips_bio_vsnprintf(
    _buf: *mut ::std::os::raw::c_char,
    _n: usize,
    _fmt: *const ::std::os::raw::c_char,
    _args: *mut c_void,
) -> ::std::os::raw::c_int {
    return 0;
}

/* Allocation functions */

unsafe fn fips_cleanse(
    addr: *mut ::std::os::raw::c_void,
    pos: usize,
    len: usize,
) {
    let slice: &mut [u8] =
        slice::from_raw_parts_mut(addr as *mut u8, pos + len);
    let (_, clear) = slice.split_at_mut(pos);
    OPENSSL_cleanse(void_ptr!(clear.as_ptr()), clear.len());
}

unsafe extern "C" fn fips_malloc(
    num: usize,
    _file: *const std::os::raw::c_char,
    _line: std::os::raw::c_int,
) -> *mut std::os::raw::c_void {
    libc::malloc(num)
}

unsafe extern "C" fn fips_zalloc(
    num: usize,
    _file: *const std::os::raw::c_char,
    _line: std::os::raw::c_int,
) -> *mut std::os::raw::c_void {
    libc::calloc(1, num)
}

unsafe extern "C" fn fips_free(
    ptr: *mut ::std::os::raw::c_void,
    _file: *const ::std::os::raw::c_char,
    _line: ::std::os::raw::c_int,
) {
    libc::free(ptr);
}

unsafe extern "C" fn fips_clear_free(
    ptr: *mut ::std::os::raw::c_void,
    num: usize,
    file: *const ::std::os::raw::c_char,
    line: ::std::os::raw::c_int,
) {
    if ptr != std::ptr::null_mut() {
        if num != 0 {
            fips_cleanse(ptr, 0, num);
        }
        fips_free(ptr, file, line)
    }
}

unsafe extern "C" fn fips_realloc(
    addr: *mut ::std::os::raw::c_void,
    num: usize,
    file: *const ::std::os::raw::c_char,
    line: ::std::os::raw::c_int,
) -> *mut ::std::os::raw::c_void {
    if addr == std::ptr::null_mut() {
        return fips_malloc(num, file, line);
    }
    if num == 0 {
        fips_free(addr, file, line);
        return std::ptr::null_mut();
    }
    libc::realloc(addr, num)
}

unsafe extern "C" fn fips_clear_realloc(
    addr: *mut ::std::os::raw::c_void,
    old_num: usize,
    num: usize,
    file: *const ::std::os::raw::c_char,
    line: ::std::os::raw::c_int,
) -> *mut ::std::os::raw::c_void {
    if addr == std::ptr::null_mut() {
        return fips_malloc(num, file, line);
    }
    if num == 0 {
        fips_clear_free(addr, old_num, file, line);
        return std::ptr::null_mut();
    }
    if num < old_num {
        fips_cleanse(addr, num, old_num - num);
        return addr;
    }

    let ret = fips_malloc(num, file, line);
    if ret != std::ptr::null_mut() {
        libc::memcpy(ret, addr, old_num);
        fips_clear_free(addr, old_num, file, line);
    }
    ret
}

unsafe extern "C" fn fips_secure_allocated(
    _ptr: *const ::std::os::raw::c_void,
) -> ::std::os::raw::c_int {
    /* FIXME: once we have secure memory, return something sensible */
    return 0;
}

unsafe extern "C" fn fips_get_indicator_cb(
    _ptr: *mut OPENSSL_CORE_CTX,
    cb: *mut OSSL_INDICATOR_CALLBACK,
) {
    /* This is the function that is called by libfips.a to source
     * the fips indicator callback. Within the kryoptic's pkcs#11
     * driver we always return our own callback */

    if !cb.is_null() {
        unsafe {
            *cb = Some(fips_indicator_callback);
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

    let mut provider: *mut PROV_CTX = std::ptr::null_mut();
    let provider_ptr: *mut *mut PROV_CTX = &mut provider;

    let mut fips_dispatch: *const OSSL_DISPATCH = std::ptr::null_mut();

    let ret = OSSL_provider_init_int(
        std::ptr::null_mut(),
        core_dispatch.as_ptr(),
        &mut fips_dispatch,
        provider_ptr as *mut *mut std::os::raw::c_void,
    );
    assert!(ret == 1);

    ossl_prov_ctx_set0_handle(
        provider,
        &FIPS_CANARY as *const _ as *const ossl_core_handle_st,
    );

    /* we assume libctx is crated once for the provider and
     * never changed afterwards */
    let osslctx = ossl_prov_ctx_get0_libctx(provider);
    FipsProvider {
        provider: provider,
        dispatch: fips_dispatch,
        context: OsslContext::from_ctx(osslctx),
    }
});

pub fn init() {
    assert!((*FIPS_PROVIDER).provider != std::ptr::null_mut());
}

pub fn get_libctx() -> &'static OsslContext {
    &(*FIPS_PROVIDER).context
}

/* The Openssl FIPS indicator callback is inadequate for easily
 * accessing individual indicators in the context of a single
 * operation because it is tied to the general library context,
 * which can be shared across multiple threads in an application.
 * Therefore the only way to make this work in a thread safe way
 * is to use thread local variables */
thread_local! {
    static FIPS_INDICATOR: Cell<u32> = Cell::new(0);
}

unsafe extern "C" fn fips_indicator_callback(
    _type_: *const ::std::os::raw::c_char,
    _desc: *const ::std::os::raw::c_char,
    _params: *const OSSL_PARAM,
) -> ::std::os::raw::c_int {
    /* We ignore type, desc, params, for now, and just register
     * if a change in state occurred.
     *
     * We could track individual events in the callback, but
     * a) it is really hard to know what they are because the
     *    "type" is an arbitrary string and you need to go and
     *    find in the specific openssl fips provider sources to
     *    figure out what it is...
     * b) it is expensive as it ends up having to do a bunch
     *    of string compares, and based on that then modify
     *    some slot in a preallocated vector ...
     *
     * Within the context of a thread only one operation at
     * a time is performed, so, as long as the code correctly
     * resets the indicator before an operation is started and
     * immediately checks it at the end, tracking the status in
     * th operation context, it can get away with tracking
     * everything in a single per-thread variable and count on
     * the serial nature of code executing within a thread.
     *
     * Note that the callback is called only when the
     * underlying OpenSSL code believes there was an unapproved
     * condition. In strict mode the callback is not called and
     * the underlying function fails directly.
     */

    /* Set the indicator up, this means there was an unapproved
     * use. */
    FIPS_INDICATOR.set(1);

    /* Returning 1, allows OpenSSL to continue the operation.
     * Unless and until we implement a strict FIPS mode we never
     * want to cause a failure for an unapproved use, so we just
     * return all ok, FIPS_INDICATOR will allow us to propagate the
     * fact that the operation was unapproved by setting PKCS#11
     * indicators */
    return 1;
}

pub fn set_error_state() {
    unsafe {
        ossl_set_error_state(OSSL_SELF_TEST_TYPE_PCT.as_ptr() as *const c_char)
    };
}

pub fn check_state_ok() -> bool {
    if unsafe { ossl_prov_is_running() } == 0 {
        return false;
    }
    return true;
}

/// Helper function to convert legacy name to ossl name for fetching
fn sigalg_to_legacy_name(alg: SigAlg) -> &'static CStr {
    match alg {
        SigAlg::Ecdsa
        | SigAlg::EcdsaSha1
        | SigAlg::EcdsaSha2_224
        | SigAlg::EcdsaSha2_256
        | SigAlg::EcdsaSha2_384
        | SigAlg::EcdsaSha2_512
        | SigAlg::EcdsaSha3_224
        | SigAlg::EcdsaSha3_256
        | SigAlg::EcdsaSha3_384
        | SigAlg::EcdsaSha3_512 => c"ECDSA",
        SigAlg::Ed25519
        | SigAlg::Ed25519ctx
        | SigAlg::Ed25519ph
        | SigAlg::Ed448
        | SigAlg::Ed448ph => c"EDDSA",
        SigAlg::Rsa
        | SigAlg::RsaNoPad
        | SigAlg::RsaSha1
        | SigAlg::RsaSha2_224
        | SigAlg::RsaSha2_256
        | SigAlg::RsaSha2_384
        | SigAlg::RsaSha2_512
        | SigAlg::RsaSha3_224
        | SigAlg::RsaSha3_256
        | SigAlg::RsaSha3_384
        | SigAlg::RsaSha3_512
        | SigAlg::RsaPss
        | SigAlg::RsaPssSha1
        | SigAlg::RsaPssSha2_224
        | SigAlg::RsaPssSha2_256
        | SigAlg::RsaPssSha2_384
        | SigAlg::RsaPssSha2_512
        | SigAlg::RsaPssSha3_224
        | SigAlg::RsaPssSha3_256
        | SigAlg::RsaPssSha3_384
        | SigAlg::RsaPssSha3_512 => c"RSA",
        SigAlg::Mldsa44 | SigAlg::Mldsa65 | SigAlg::Mldsa87 => c"",
        SigAlg::SlhdsaSha2_128s
        | SigAlg::SlhdsaShake128s
        | SigAlg::SlhdsaSha2_128f
        | SigAlg::SlhdsaShake128f
        | SigAlg::SlhdsaSha2_192s
        | SigAlg::SlhdsaShake192s
        | SigAlg::SlhdsaSha2_192f
        | SigAlg::SlhdsaShake192f
        | SigAlg::SlhdsaSha2_256s
        | SigAlg::SlhdsaShake256s
        | SigAlg::SlhdsaSha2_256f
        | SigAlg::SlhdsaShake256f => c"",
    }
}

/* The OpenSSL FIPS Provider do not export helper functions to set up
 * digest-sign operations. So we'll just have to brute force it */
#[derive(Debug)]
pub struct ProviderSignatureCtx {
    vtable: *mut EVP_SIGNATURE,
    ctx: *mut c_void,
}

impl ProviderSignatureCtx {
    pub fn new(alg: SigAlg) -> Result<ProviderSignatureCtx, Error> {
        let sigtable = unsafe {
            EVP_SIGNATURE_fetch(
                get_libctx().ptr(),
                sigalg_to_legacy_name(alg).as_ptr(),
                std::ptr::null(),
            )
        };
        if sigtable.is_null() {
            return Err(Error::new(ErrorKind::NullPtr));
        }

        let ctx = unsafe {
            match (*sigtable).newctx {
                Some(f) => f(
                    (*FIPS_PROVIDER).provider as *mut c_void,
                    std::ptr::null(),
                ),
                None => return Err(Error::new(ErrorKind::NullPtr)),
            }
        };
        if ctx.is_null() {
            return Err(Error::new(ErrorKind::NullPtr));
        }

        Ok(ProviderSignatureCtx {
            vtable: sigtable,
            ctx: ctx,
        })
    }

    pub fn digest_sign_init(
        &mut self,
        mdname: *const c_char,
        pkey: &EvpPkey,
        params: *const OSSL_PARAM,
    ) -> Result<(), Error> {
        unsafe {
            match (*self.vtable).digest_sign_init {
                Some(f) => {
                    if f(
                        self.ctx,
                        mdname,
                        (*pkey.as_ptr()).keydata as *mut c_void,
                        params,
                    ) != 1
                    {
                        return Err(Error::new(ErrorKind::OsslError));
                    }
                }
                None => return Err(Error::new(ErrorKind::NullPtr)),
            }
        }
        Ok(())
    }

    pub fn digest_sign_update(&mut self, data: &[u8]) -> Result<(), Error> {
        unsafe {
            match (*self.vtable).digest_sign_update {
                Some(f) => {
                    if f(self.ctx, data.as_ptr() as *const c_uchar, data.len())
                        != 1
                    {
                        return Err(Error::new(ErrorKind::OsslError));
                    }
                }
                None => return Err(Error::new(ErrorKind::NullPtr)),
            }
        }
        Ok(())
    }

    pub fn digest_sign_final(
        &mut self,
        signature: &mut [u8],
    ) -> Result<usize, Error> {
        unsafe {
            match (*self.vtable).digest_sign_final {
                Some(f) => {
                    let mut siglen = 0usize;
                    let siglen_ptr: *mut usize = &mut siglen;
                    let res = f(
                        self.ctx,
                        signature.as_mut_ptr() as *mut c_uchar,
                        siglen_ptr,
                        signature.len(),
                    );
                    if res != 1 {
                        return Err(Error::new(ErrorKind::OsslError));
                    }
                    Ok(siglen)
                }
                None => Err(Error::new(ErrorKind::NullPtr)),
            }
        }
    }

    pub fn digest_sign(
        &mut self,
        mut signature: Option<&mut [u8]>,
        tbs: &[u8],
    ) -> Result<usize, Error> {
        unsafe {
            match (*self.vtable).digest_sign {
                Some(f) => {
                    let mut siglen: usize;
                    let sigptr: *mut c_uchar;
                    match &mut signature {
                        Some(s) => {
                            sigptr = s.as_mut_ptr();
                            siglen = s.len();
                        }
                        None => {
                            sigptr = std::ptr::null_mut() as *mut c_uchar;
                            siglen = 0usize;
                        }
                    }
                    let siglen_ptr: *mut usize = &mut siglen;
                    let res = f(
                        self.ctx,
                        sigptr,
                        siglen_ptr,
                        siglen,
                        tbs.as_ptr() as *mut c_uchar,
                        tbs.len(),
                    );
                    if res != 1 {
                        return Err(Error::new(ErrorKind::OsslError));
                    }
                    Ok(siglen)
                }
                None => Err(Error::new(ErrorKind::NullPtr)),
            }
        }
    }

    pub fn digest_verify_init(
        &mut self,
        mdname: *const c_char,
        pkey: &EvpPkey,
        params: *const OSSL_PARAM,
    ) -> Result<(), Error> {
        unsafe {
            match (*self.vtable).digest_verify_init {
                Some(f) => {
                    if f(
                        self.ctx,
                        mdname,
                        (*pkey.as_ptr()).keydata as *mut c_void,
                        params,
                    ) != 1
                    {
                        return Err(Error::new(ErrorKind::OsslError));
                    }
                }
                None => return Err(Error::new(ErrorKind::NullPtr)),
            }
        }
        Ok(())
    }

    pub fn digest_verify_update(&mut self, data: &[u8]) -> Result<(), Error> {
        unsafe {
            match (*self.vtable).digest_verify_update {
                Some(f) => {
                    if f(self.ctx, data.as_ptr() as *const c_uchar, data.len())
                        != 1
                    {
                        return Err(Error::new(ErrorKind::OsslError));
                    }
                }
                None => return Err(Error::new(ErrorKind::NullPtr)),
            }
        }
        Ok(())
    }

    pub fn digest_verify_final(
        &mut self,
        signature: &[u8],
    ) -> Result<(), Error> {
        unsafe {
            match (*self.vtable).digest_verify_final {
                Some(f) => {
                    if f(
                        self.ctx,
                        signature.as_ptr() as *const c_uchar,
                        signature.len(),
                    ) != 1
                    {
                        return Err(Error::new(ErrorKind::OsslError));
                    }
                }
                None => return Err(Error::new(ErrorKind::NullPtr)),
            }
        }
        Ok(())
    }

    pub fn digest_verify(
        &mut self,
        signature: &[u8],
        tbs: &[u8],
    ) -> Result<(), Error> {
        unsafe {
            match (*self.vtable).digest_verify {
                Some(f) => {
                    if f(
                        self.ctx,
                        signature.as_ptr() as *const c_uchar,
                        signature.len(),
                        tbs.as_ptr() as *const c_uchar,
                        tbs.len(),
                    ) != 1
                    {
                        return Err(Error::new(ErrorKind::OsslError));
                    }
                }
                None => return Err(Error::new(ErrorKind::NullPtr)),
            }
        }
        Ok(())
    }
}

unsafe impl Send for ProviderSignatureCtx {}
unsafe impl Sync for ProviderSignatureCtx {}

/// This structure represent whether a service execetuion is approved.
/// It has access to the internal OpenSSL fips indicator callbacks
/// and can query the fips indicators to establish if a non-approved
/// operation occurred.
#[derive(Debug)]
pub struct FipsApproval {
    approved: Option<bool>,
}

impl FipsApproval {
    /// clear the thread local fips indicator so that any
    /// new indicator trigger can be detected
    fn clear_indicator() {
        FIPS_INDICATOR.set(0);
    }

    /// Checks thread local fips indicator to see if it has
    /// been triggered
    fn check_indicator() -> bool {
        FIPS_INDICATOR.get() != 0
    }

    /// Clears indicators and creates a new FipsApproval object
    pub fn init() -> FipsApproval {
        Self::clear_indicator();
        FipsApproval { approved: None }
    }

    /// Resets FipsApproval status
    pub fn reset(&mut self) {
        self.approved = None;
    }

    /// Clears indicators
    pub fn clear(&self) {
        Self::clear_indicator();
    }

    /// Check if any indicator has triggered and updates
    /// internal status if that happened.
    pub fn update(&mut self) {
        if Self::check_indicator() {
            /* The indicator was set, therefore there was an unapproved use */
            self.approved = Some(false);
        }
    }

    /// Resutrns current approval status
    pub fn approval(&self) -> Option<bool> {
        self.approved
    }

    /// Check if operation is approved, returns true only
    /// if the operation has been positively marked as
    /// approved.
    pub fn is_approved(&self) -> bool {
        if self.approved.is_some_and(|b| b == true) {
            return true;
        }
        return false;
    }

    /// Check if operation is not approved, returns true only
    /// if the operation has been positively marked as not
    /// approved.
    pub fn is_not_approved(&self) -> bool {
        if self.approved.is_some_and(|b| b == false) {
            return true;
        }
        return false;
    }

    /// Sets approval status.
    /// Note: approval can only go from true -> false
    /// A non-approved operation cannot be marked approved later.
    pub fn set(&mut self, b: bool) {
        if self.approved.is_some_and(|b| b == false) {
            return;
        }
        self.approved = Some(b);
    }

    /// Finalizes approval status, generaly used after the last operation
    /// for the service.
    pub fn finalize(&mut self) {
        self.update();
        /* this is the last check, mark approval as true if not set so far */
        self.set(true);
    }
}

pub(crate) fn pkey_type_name(pkey: *const EVP_PKEY) -> *const c_char {
    if pkey.is_null() {
        return std::ptr::null();
    }
    let keymgmt = unsafe { (*pkey).keymgmt };
    if keymgmt.is_null() {
        return std::ptr::null();
    }
    return unsafe { (*keymgmt).type_name };
}
