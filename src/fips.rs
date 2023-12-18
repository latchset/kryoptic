// Copyright 2023 Simo Sorce
// See LICENSE.txt file for terms

#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(dead_code)]
#![allow(non_snake_case)]
include!("fips/bindings.rs");

use getrandom;
use libc;
use once_cell::sync::Lazy;
use std::ffi::CStr;
use std::fs::File;
use std::io::Read;
use std::io::Result;
use std::io::Seek;
use std::io::SeekFrom;
use std::path::Path;
use std::slice;
use zeroize::Zeroize;

/* Entropy Stuff */

unsafe extern "C" fn fips_get_entropy(
    _handle: *const OSSL_CORE_HANDLE,
    pout: *mut *mut ::std::os::raw::c_uchar,
    entropy: ::std::os::raw::c_int,
    min_len: usize,
    max_len: usize,
) -> usize {
    let mut len = entropy as usize;
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
    if getrandom::getrandom(r).is_err() {
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
    /* FIXME: OpenSSL returns some tiemr + salt string,
     * we return just getrandom data | salt string.
     * Need to check if this is ok */

    let out = fips_get_entropy(
        handle,
        pout,
        min_len as ::std::os::raw::c_int,
        min_len,
        max_len,
    );
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

static FIPS_MODULE_FILE_NAME: &str = "./dummy.txt\0";
static FIPS_MODULE_MAC: &str = "C5:91:22:79:AF:0D:28:F7:DD:6B:BF:03:6B:01:D0:E5:50:81:C5:93:18:8C:7C:77:A3:97:98:CE:56:1B:67:80\0";
static FIPS_INSTALL_MAC: &str = "41:9C:38:C2:8F:59:09:43:2C:AA:2F:58:36:2D:D9:04:F9:6C:56:8B:09:E0:18:3A:2E:D6:CC:69:05:04:E1:11\0";
static FIPS_INSTALL_STATUS: &str = "INSTALL_SELF_TEST_KATS_RUN\0";
static FIPS_INSTALL_VERSION: &str = "1\0";
static FIPS_CONDITIONAL_ERRORS: &str = "1\0";
static FIPS_SECURITY_CHECKS: &str = "1\0";
static FIPS_PARAM_TLS1_PRF_EMS_CHECK: &str = "1\0";
static FIPS_PARAM_DRBG_TRUNC_DIGEST: &str = "1\0";

macro_rules! set_config_string {
    ($params:expr, $key:expr, $val:expr) => {
        let p =
            unsafe { OSSL_PARAM_locate($params, $key.as_ptr() as *const i8) };
        if p != std::ptr::null_mut() {
            unsafe {
                let _ = OSSL_PARAM_set_utf8_ptr(p, $val.as_ptr() as *const i8);
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
        OSSL_PROV_PARAM_CORE_MODULE_FILENAME,
        FIPS_MODULE_FILE_NAME
    );

    set_config_string!(
        params,
        OSSL_PROV_FIPS_PARAM_MODULE_MAC,
        FIPS_MODULE_MAC
    );
    set_config_string!(
        params,
        OSSL_PROV_FIPS_PARAM_INSTALL_MAC,
        FIPS_INSTALL_MAC
    );
    set_config_string!(
        params,
        OSSL_PROV_FIPS_PARAM_INSTALL_STATUS,
        FIPS_INSTALL_STATUS
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

    return 1;
}

unsafe extern "C" fn fips_get_libctx(
    _prov: *const OSSL_CORE_HANDLE,
) -> *mut OPENSSL_CORE_CTX {
    get_libctx() as *mut OPENSSL_CORE_CTX
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
unsafe extern "C" fn fips_vset_error(
    _prov: *const OSSL_CORE_HANDLE,
    _reason: u32,
    _fmt: *const ::std::os::raw::c_char,
    _args: *mut __va_list_tag,
) {
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
    fn new(filename: &str) -> Result<FileBio> {
        Ok(FileBio {
            file: File::open(Path::new(filename))?,
        })
    }

    fn read(&mut self, v: &mut [u8]) -> Result<usize> {
        let size = self.file.metadata()?.len();
        let pos = self.file.seek(SeekFrom::Current(0))?;
        if pos >= size {
            return Ok(0);
        }
        let mut avail = (size - pos) as usize;
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
    fn new(v: &mut [u8]) -> MemBio {
        MemBio { mem: v, cursor: 0 }
    }

    fn read(&mut self, v: &mut [u8]) -> Result<usize> {
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
        len as usize
    } else if len < 0 {
        libc::strlen(buf as *const i8) as usize
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
    _args: *mut __va_list_tag,
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
    clear.zeroize()
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

/* FIPS Provider wrapping an intialization */

struct FipsProvider {
    provider: *mut OSSL_PROVIDER,
    dispatch: *const OSSL_DISPATCH,
}

unsafe impl Send for FipsProvider {}
unsafe impl Sync for FipsProvider {}

macro_rules! dispatcher_struct {
    (args1; $fn_id:expr; $fn:expr) => {
        OSSL_DISPATCH {
            function_id: $fn_id as i32,
            function: Some(std::mem::transmute::<
                unsafe extern "C" fn(_) -> _,
                unsafe extern "C" fn(),
            >($fn)),
        }
    };
    (args2; $fn_id:expr; $fn:expr) => {
        OSSL_DISPATCH {
            function_id: $fn_id as i32,
            function: Some(std::mem::transmute::<
                unsafe extern "C" fn(_, _) -> _,
                unsafe extern "C" fn(),
            >($fn)),
        }
    };
    (args3; $fn_id:expr; $fn:expr) => {
        OSSL_DISPATCH {
            function_id: $fn_id as i32,
            function: Some(std::mem::transmute::<
                unsafe extern "C" fn(_, _, _) -> _,
                unsafe extern "C" fn(),
            >($fn)),
        }
    };
    (args4; $fn_id:expr; $fn:expr) => {
        OSSL_DISPATCH {
            function_id: $fn_id as i32,
            function: Some(std::mem::transmute::<
                unsafe extern "C" fn(_, _, _, _) -> _,
                unsafe extern "C" fn(),
            >($fn)),
        }
    };
    (args5; $fn_id:expr; $fn:expr) => {
        OSSL_DISPATCH {
            function_id: $fn_id as i32,
            function: Some(std::mem::transmute::<
                unsafe extern "C" fn(_, _, _, _, _) -> _,
                unsafe extern "C" fn(),
            >($fn)),
        }
    };
    (args6; $fn_id:expr; $fn:expr) => {
        OSSL_DISPATCH {
            function_id: $fn_id as i32,
            function: Some(std::mem::transmute::<
                unsafe extern "C" fn(_, _, _, _, _, _) -> _,
                unsafe extern "C" fn(),
            >($fn)),
        }
    };
}

static FIPS_PROVIDER: Lazy<FipsProvider> = Lazy::new(|| unsafe {
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
    ];

    let mut provider: *mut OSSL_PROVIDER = std::ptr::null_mut();
    let provider_ptr: *mut *mut OSSL_PROVIDER = &mut provider;

    let mut fips_dispatch: *const OSSL_DISPATCH = std::ptr::null_mut();

    let ret = OSSL_provider_init_int(
        std::ptr::null_mut(),
        core_dispatch.as_ptr(),
        &mut fips_dispatch,
        provider_ptr as *mut *mut std::os::raw::c_void,
    );
    assert!(ret == 1);

    FipsProvider {
        provider: provider,
        dispatch: fips_dispatch,
    }
});

pub fn init() {
    assert!(FIPS_PROVIDER.provider != std::ptr::null_mut());
}

pub fn get_libctx() -> *mut OSSL_LIB_CTX {
    unsafe { ossl_prov_ctx_get0_libctx(FIPS_PROVIDER.provider) }
}
