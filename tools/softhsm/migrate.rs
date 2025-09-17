// Copyright 2025 Simo Sorce
// See LICENSE.txt file for terms

use std::ffi::{c_void, CStr, CString};
use std::fmt;
use std::fs::{read_dir, File};
use std::io::Read;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;
use libc;

use kryoptic_lib::pkcs11::*;

pub const CK_ULONG_SIZE: usize = std::mem::size_of::<CK_ULONG>();
pub const CK_BBOOL_SIZE: usize = std::mem::size_of::<CK_BBOOL>();
macro_rules! make_attribute {
    ($type:expr, $value:expr, $length:expr) => {
        CK_ATTRIBUTE {
            type_: $type,
            pValue: $value as *const _ as CK_VOID_PTR,
            ulValueLen: $length as CK_ULONG,
        }
    };
}

struct Error {
    msg: String,
}

impl From<std::io::Error> for Error {
    fn from(error: std::io::Error) -> Error {
        Error {
            msg: error.to_string(),
        }
    }
}
impl From<String> for Error {
    fn from(msg: String) -> Error {
        Error { msg: msg }
    }
}

impl From<&str> for Error {
    fn from(msg: &str) -> Error {
        Error::from(msg.to_string())
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.msg)
    }
}

fn dl_error() -> String {
    let cstr = unsafe { libc::dlerror() };
    if cstr.is_null() {
        String::from("<none>")
    } else {
        unsafe {
            String::from_utf8_lossy(CStr::from_ptr(cstr).to_bytes()).to_string()
        }
    }
}

struct FuncList {
    fntable: *mut CK_FUNCTION_LIST,
    slot: CK_ULONG,
    session: CK_SESSION_HANDLE,
}

impl FuncList {
    fn from_symbol_name(
        handle: *mut c_void,
        name: &str,
    ) -> Result<FuncList, String> {
        let fname = CString::new(name).unwrap();
        let list_fn: CK_C_GetFunctionList = unsafe {
            let ptr = libc::dlsym(handle, fname.as_ptr());
            if ptr.is_null() {
                None
            } else {
                Some(std::mem::transmute::<
                    *mut c_void,
                    unsafe extern "C" fn(*mut *mut CK_FUNCTION_LIST) -> CK_RV,
                >(ptr))
            }
        };
        let mut fn_list: *mut CK_FUNCTION_LIST = std::ptr::null_mut();
        let rv = match list_fn {
            None => {
                return Err(dl_error().to_string());
            }
            Some(func) => unsafe { func(&mut fn_list) },
        };
        if rv != CKR_OK {
            return Err(format!("Failed to load pkcs11 function list: {}", rv));
        }
        Ok(FuncList {
            fntable: fn_list,
            slot: 0,
            session: CK_INVALID_HANDLE,
        })
    }

    fn initialize(&self, initargs: &CStr) -> Result<(), Error> {
        unsafe {
            match (*self.fntable).C_Initialize {
                None => {
                    return Err(format!(
                        "Broken pkcs11 module, no C_Initialize function"
                    )
                    .into())
                }
                Some(func) => {
                    let reserved = if initargs.count_bytes() > 0 {
                        initargs.as_ptr()
                    } else {
                        std::ptr::null()
                    };

                    let mut targs = CK_C_INITIALIZE_ARGS {
                        CreateMutex: None,
                        DestroyMutex: None,
                        LockMutex: None,
                        UnlockMutex: None,
                        flags: 0,
                        pReserved: reserved as CK_VOID_PTR,
                    };
                    let targs_ptr = &mut targs as *mut CK_C_INITIALIZE_ARGS;
                    let rv = func(targs_ptr as *mut c_void);
                    if rv != CKR_OK {
                        return Err(format!(
                            "Pkcs11 Token Initialization failed: {}",
                            rv
                        )
                        .into());
                    }
                    Ok(())
                }
            }
        }
    }

    fn open_session(&mut self) -> Result<CK_SESSION_HANDLE, Error> {
        if self.session != CK_INVALID_HANDLE {
            return Ok(self.session);
        }
        self.session = unsafe {
            match (*self.fntable).C_OpenSession {
                None => {
                    return Err(format!(
                        "Broken pkcs11 module, no C_OpenSession function"
                    )
                    .into())
                }
                Some(func) => {
                    let mut session: CK_ULONG = CK_INVALID_HANDLE;
                    let flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
                    let rv = func(
                        self.slot,
                        flags,
                        std::ptr::null_mut(),
                        None,
                        &mut session,
                    );
                    if rv != CKR_OK {
                        return Err(format!(
                            "Failed to open R/W session on slot {}: {}",
                            self.slot, rv
                        )
                        .into());
                    }
                    session
                }
            }
        };
        Ok(self.session)
    }

    fn login(&mut self, pin: &str) -> Result<CK_SESSION_HANDLE, Error> {
        unsafe {
            match (*self.fntable).C_Login {
                None => {
                    return Err(format!(
                        "Broken pkcs11 module, no C_Login function"
                    )
                    .into())
                }
                Some(func) => {
                    let spin = CString::new(pin).unwrap();
                    let session = self.open_session()?;
                    let rv = func(
                        session,
                        CKU_USER,
                        spin.as_ptr() as *const _ as *mut u8,
                        spin.as_bytes().len() as CK_ULONG,
                    );
                    if rv != CKR_OK {
                        return Err(format!(
                            "Failed to login slot {}: {}",
                            self.slot, rv
                        )
                        .into());
                    }
                    Ok(session)
                }
            }
        }
    }

    fn get_digest(
        &self,
        session: CK_SESSION_HANDLE,
        mech: CK_MECHANISM_TYPE,
        data: Vec<u8>,
    ) -> Result<Vec<u8>, Error> {
        let mut mechanism = CK_MECHANISM {
            mechanism: mech,
            pParameter: std::ptr::null_mut(),
            ulParameterLen: 0,
        };
        self.digest_init(session, &mut mechanism)?;
        let mut out = Vec::<u8>::new();
        self.digest(session, &data, &mut out)?;
        Ok(out)
    }

    fn digest_init(
        &self,
        session: CK_SESSION_HANDLE,
        mechanism: &mut CK_MECHANISM,
    ) -> Result<(), Error> {
        unsafe {
            match (*self.fntable).C_DigestInit {
                None => {
                    return Err(format!(
                        "Broken pkcs11 module, no C_DigestInit function"
                    )
                    .into())
                }
                Some(func) => {
                    let rv = func(session, mechanism);
                    if rv != CKR_OK {
                        return Err(format!(
                            "Failed to init digest on slot {}: {}",
                            self.slot, rv
                        )
                        .into());
                    }
                    Ok(())
                }
            }
        }
    }

    fn digest(
        &self,
        session: CK_SESSION_HANDLE,
        data: &Vec<u8>,
        hash: &mut Vec<u8>,
    ) -> Result<(), Error> {
        unsafe {
            match (*self.fntable).C_Digest {
                None => {
                    return Err(format!(
                        "Broken pkcs11 module, no C_Digest function"
                    )
                    .into())
                }
                Some(func) => {
                    if hash.len() == 0 {
                        let mut len: CK_ULONG = 0;
                        let rv = func(
                            session,
                            data.as_ptr() as *const _ as *mut u8,
                            data.len() as CK_ULONG,
                            std::ptr::null_mut() as *mut u8,
                            &mut len,
                        );
                        if rv != CKR_OK {
                            return Err(format!(
                                "Failed to get digest len on slot {}: {}",
                                self.slot, rv
                            )
                            .into());
                        }
                        hash.resize(len as usize, 0);
                    }
                    let mut len = hash.len() as CK_ULONG;

                    let rv = func(
                        session,
                        data.as_ptr() as *const _ as *mut u8,
                        data.len() as CK_ULONG,
                        hash.as_mut_ptr(),
                        &mut len,
                    );
                    if rv != CKR_OK {
                        return Err(format!(
                            "Failed to digest on slot {}: {}",
                            self.slot, rv
                        )
                        .into());
                    }
                    Ok(())
                }
            }
        }
    }

    fn import_aes_key(
        &self,
        session: CK_SESSION_HANDLE,
        data: &Vec<u8>,
    ) -> Result<CK_OBJECT_HANDLE, Error> {
        let mut key_class: CK_ULONG = CKO_SECRET_KEY;
        let mut key_type: CK_ULONG = CKK_AES;
        let mut token: CK_BBOOL = CK_FALSE;
        let mut encrypt: CK_BBOOL = CK_TRUE;
        let mut decrypt: CK_BBOOL = CK_TRUE;
        let attrs: [CK_ATTRIBUTE; 6] = [
            make_attribute!(CKA_CLASS, &mut key_class, CK_ULONG_SIZE),
            make_attribute!(CKA_KEY_TYPE, &mut key_type, CK_ULONG_SIZE),
            make_attribute!(CKA_VALUE, data.as_ptr(), data.len()),
            make_attribute!(CKA_TOKEN, &mut token, CK_BBOOL_SIZE),
            make_attribute!(CKA_ENCRYPT, &mut encrypt, CK_BBOOL_SIZE),
            make_attribute!(CKA_DECRYPT, &mut decrypt, CK_BBOOL_SIZE),
        ];

        self.create_object(session, attrs.as_slice())
    }

    fn create_object(
        &self,
        session: CK_SESSION_HANDLE,
        template: &[CK_ATTRIBUTE],
    ) -> Result<CK_OBJECT_HANDLE, Error> {
        unsafe {
            match (*self.fntable).C_CreateObject {
                None => {
                    return Err(format!(
                        "Broken pkcs11 module, no C_CreateObject function"
                    )
                    .into())
                }
                Some(func) => {
                    let mut handle: CK_OBJECT_HANDLE = CK_INVALID_HANDLE;
                    let rv = func(
                        session,
                        template.as_ptr() as *const _ as *mut CK_ATTRIBUTE,
                        template.len() as CK_ULONG,
                        &mut handle,
                    );
                    if rv != CKR_OK {
                        return Err(format!(
                            "Failed to create object on slot {}: {}",
                            self.slot, rv
                        )
                        .into());
                    }
                    Ok(handle)
                }
            }
        }
    }

    fn decrypt_buffer(
        &self,
        session: CK_SESSION_HANDLE,
        mechanism: &CK_MECHANISM,
        handle: CK_OBJECT_HANDLE,
        data: &[u8],
    ) -> Result<Vec<u8>, Error> {
        self.decrypt_init(session, mechanism, handle)?;
        self.decrypt(session, data)
    }

    fn decrypt_init(
        &self,
        session: CK_SESSION_HANDLE,
        mechanism: &CK_MECHANISM,
        handle: CK_OBJECT_HANDLE,
    ) -> Result<(), Error> {
        unsafe {
            match (*self.fntable).C_DecryptInit {
                None => {
                    return Err(format!(
                        "Broken pkcs11 module, no C_DecryptInit function"
                    )
                    .into())
                }
                Some(func) => {
                    let rv = func(
                        session,
                        mechanism as *const _ as CK_MECHANISM_PTR,
                        handle,
                    );
                    if rv != CKR_OK {
                        return Err(format!(
                            "Failed to init decrypt on slot {}: {}",
                            self.slot, rv
                        )
                        .into());
                    }
                    Ok(())
                }
            }
        }
    }

    fn decrypt(
        &self,
        session: CK_SESSION_HANDLE,
        data: &[u8],
    ) -> Result<Vec<u8>, Error> {
        unsafe {
            match (*self.fntable).C_Decrypt {
                None => {
                    return Err(format!(
                        "Broken pkcs11 module, no C_Decrypt function"
                    )
                    .into())
                }
                Some(func) => {
                    let mut len: CK_ULONG = 0;
                    let rv = func(
                        session,
                        data.as_ptr() as *const _ as *mut u8,
                        data.len() as CK_ULONG,
                        std::ptr::null_mut() as *mut u8,
                        &mut len,
                    );
                    if rv != CKR_OK {
                        return Err(format!(
                            "Failed to decrypt on slot {}: {}",
                            self.slot, rv
                        )
                        .into());
                    }
                    let mut out = vec![0u8; len as usize];
                    let rv = func(
                        session,
                        data.as_ptr() as *const _ as *mut u8,
                        data.len() as CK_ULONG,
                        out.as_mut_ptr(),
                        &mut len,
                    );
                    out.resize(len as usize, 0);
                    if rv != CKR_OK {
                        return Err(format!(
                            "Failed to decrypt on slot {}: {}",
                            self.slot, rv
                        )
                        .into());
                    }
                    Ok(out)
                }
            }
        }
    }
}

fn decrypt_cbc_buffer(
    pkcs11: &mut FuncList,
    buf: &[u8],
    key: &Vec<u8>,
) -> Result<Vec<u8>, Error> {
    let session = pkcs11.open_session()?;

    let handle = pkcs11.import_aes_key(session, key)?;
    let mechanism = CK_MECHANISM {
        mechanism: CKM_AES_CBC_PAD,
        pParameter: buf.as_ptr() as *const _ as CK_VOID_PTR,
        ulParameterLen: 16,
    };
    Ok(pkcs11.decrypt_buffer(session, &mechanism, handle, &buf[16..])?)
}

fn u64_from_buf(buf: &[u8], idx: usize) -> u64 {
    u64::from_be_bytes(buf[idx..idx + 8].try_into().unwrap())
}

fn ck_ulong_from_buf(buf: &[u8], idx: usize) -> CK_ULONG {
    let v64 = u64_from_buf(buf, idx);
    if v64 == u64::MAX {
        return CK_ULONG::MAX;
    }
    v64 as CK_ULONG
}

const BOOLEAN_ATTR: u64 = 1;
const ULONG_ATTR: u64 = 2;
const BYTESTR_ATTR: u64 = 3;
const ATTRMAP_ATTR: u64 = 4;
const MECHSET_ATTR: u64 = 5;

struct Attribute {
    value: Vec<u8>,
    attr: CK_ATTRIBUTE,
}

fn read_next_attribute(
    data: &[u8],
    attr: &mut Attribute,
) -> Result<usize, Error> {
    let mut index = 0;

    if data.len() < index + 8 {
        return Err("Error parsing next attribute type (short read)".into());
    }
    let attr_type = u64_from_buf(data, index);
    index += 8;

    if data.len() < index + 8 {
        return Err(format!(
            "Error parsing {} attr kind (short read)",
            attr_type
        )
        .into());
    }
    let attr_kind = u64_from_buf(data, index);
    index += 8;

    match attr_kind {
        BOOLEAN_ATTR => {
            if data.len() < index + 1 {
                return Err(format!(
                    "Error parsing boolean attr {} (short read)",
                    attr_type
                )
                .into());
            }
            let value = if data[index] == 0 { CK_FALSE } else { CK_TRUE };
            attr.value.extend_from_slice(&value.to_ne_bytes());
            index += 1;
        }
        ULONG_ATTR => {
            if data.len() < index + 8 {
                return Err(format!(
                    "Error parsing ulong attr {} (short read)",
                    attr_type
                )
                .into());
            }
            let value = ck_ulong_from_buf(&data, index);
            attr.value.extend_from_slice(&value.to_ne_bytes());
            index += 8;
        }
        BYTESTR_ATTR => {
            if data.len() < index + 8 {
                return Err(format!(
                    "Error parsing bytestr attr {} (short read)",
                    attr_type
                )
                .into());
            }
            let len = u64_from_buf(data, index) as usize;
            index += 8;

            if len > 0 {
                if data.len() < index + len {
                    return Err(format!(
                        "Error parsing bytestr attr {} (out of bounds)",
                        attr_type
                    )
                    .into());
                }
                attr.value.extend_from_slice(&data[index..index + len]);
                index += len;
            }
        }
        ATTRMAP_ATTR => {
            if data.len() < index + 8 {
                return Err(format!(
                    "Error parsing attrmap attr {} (short read)",
                    attr_type
                )
                .into());
            }
            let len = u64_from_buf(data, index) as usize;
            index += 8;
            if data.len() < index + len {
                return Err(format!(
                    "Error parsing attrmap attr {} (out of bounds)",
                    attr_type
                )
                .into());
            }
            let mut subidx = 0;
            let mut subattrs = Vec::<Attribute>::new();
            while subidx < len {
                let mut subattr = Attribute {
                    value: Vec::new(),
                    attr: CK_ATTRIBUTE {
                        type_: 0,
                        pValue: std::ptr::null_mut(),
                        ulValueLen: 0,
                    },
                };
                let step = read_next_attribute(
                    &data[index..index + len],
                    &mut subattr,
                )?;
                subidx += step;
                subattrs.push(subattr);
            }

            /* Caution, this is fragile but needed for FFI reasons:
             * This is an array of CK_ATTRIBUTE structures, that means
             * they embed a memory pointer to the actual data.
             * We store the raw data from the file in the Attribute
             * value vector. Once the array is complete we re-parse it
             * to make all pointer point to the correct memory location.
             * This allows rust to reallocate the vector as we grow it
             * without invalidating the memory addresses.
             */

            for a in &subattrs {
                /* First pass, add all CK_ATTRIBUTE structure data as a linear
                 * memory array */
                let mut next: Vec<u8> =
                    vec![0; std::mem::size_of::<CK_ATTRIBUTE>()];
                let mut idx = 0;
                let mut sz = std::mem::size_of::<CK_ULONG>();
                next[idx..idx + sz]
                    .copy_from_slice(&a.attr.type_.to_ne_bytes());
                idx += sz;
                sz = std::mem::size_of::<*const u8>();
                let zeros = vec![0u8; sz];
                next[idx..idx + sz].copy_from_slice(zeros.as_slice());
                idx += sz;
                sz = std::mem::size_of::<CK_ULONG>();
                next[idx..idx + sz]
                    .copy_from_slice(&a.attr.ulValueLen.to_ne_bytes());
                attr.value.extend_from_slice(next.as_slice());
            }

            /* save index where actual data starts */
            let mut data_idx = attr.value.len();

            for a in &subattrs {
                /* Second pass copy all the data values */
                attr.value.extend_from_slice(a.value.as_slice());
            }

            let mut obj_idx = 0;
            for a in &subattrs {
                /* Third pass, fix pointers */
                let ptr_idx = obj_idx + std::mem::size_of::<CK_ULONG>();
                let sz = std::mem::size_of::<*const u8>();
                let ptr = unsafe {
                    std::mem::transmute::<*const u8, usize>(
                        attr.value.as_ptr().wrapping_add(data_idx),
                    )
                };
                attr.value[ptr_idx..ptr_idx + sz]
                    .copy_from_slice(&ptr.to_ne_bytes());
                data_idx += a.attr.ulValueLen as usize;
                obj_idx += std::mem::size_of::<CK_ATTRIBUTE>();
            }
            index += len;
        }
        MECHSET_ATTR => {
            if data.len() < index + 8 {
                return Err(format!(
                    "Error parsing mechset attr {} (short read)",
                    attr_type
                )
                .into());
            }
            let count = u64_from_buf(data, index) as usize;
            index += 8;

            if count > 0 {
                let len = count * 8;
                if data.len() < index + len {
                    return Err(format!(
                        "Error parsing mechset attr {} (out of bounds)",
                        attr_type
                    )
                    .into());
                }
                attr.value.extend_from_slice(&data[index..index + len]);
                index += len;
            }
        }
        _ => return Err(format!("Invalid type for attr {}", attr_type).into()),
    }

    attr.attr.type_ = attr_type as CK_ULONG;
    if attr.value.len() > 0 {
        attr.attr.pValue = attr.value.as_ptr() as *const _ as CK_VOID_PTR;
        attr.attr.ulValueLen = attr.value.len() as CK_ULONG;
    } else {
        attr.attr.pValue = std::ptr::null_mut();
        attr.attr.ulValueLen = 0;
    }
    Ok(index)
}

/* not the shiniest code, but the file format is a trainwreck anyway */
fn read_object(path: &PathBuf) -> Result<Vec<Attribute>, Error> {
    let mut f = File::open(path)?;

    let mut data = Vec::new();
    let size = f.read_to_end(&mut data)?;
    if size < 8 {
        return Err("Short read while fetching object".into());
    }

    let mut attrs = Vec::<Attribute>::new();

    /* skip generation number */
    let mut index = 8;

    while size > index {
        let mut attr = Attribute {
            value: Vec::new(),
            attr: CK_ATTRIBUTE {
                type_: 0,
                pValue: std::ptr::null_mut(),
                ulValueLen: 0,
            },
        };
        let step = read_next_attribute(&data[index..], &mut attr)?;
        index += step;
        attrs.push(attr);
    }
    Ok(attrs)
}

const PBE_ITERATION_BASE_COUNT: usize = 1500;
const MAGIC_VALUE: [u8; 3] = [0x52, 0x4A, 0x52];

fn encryption_key(
    pkcs11: &mut FuncList,
    ek: &Vec<u8>,
    pin: &Vec<u8>,
) -> Result<Vec<u8>, Error> {
    let salt = &ek[0..8]; /* 8 bytes salt */

    let session = pkcs11.open_session()?;

    /* Derive key from pin.
     * SoftHSM2 indicated a Key Derivation specified in RFC4800 is used,
     * but not exactly which if the variants, so here is a description
     * of what it does:
     *
     * Salt s must be 8 bytes
     * Iteration counter c is 1500 + the last byte of the salt as a u8 number
     * Hash function H is SHA-256
     *
     * I = H(s || pin)
     * V(0) = H(I)
     * V(x) = H(V(x-1))
     * Iterate x from 1 to c
     */

    let c = PBE_ITERATION_BASE_COUNT + salt[7] as usize;

    let mut data = salt.to_vec();
    data.extend_from_slice(pin.as_slice());
    for _ in 0..c {
        data = pkcs11.get_digest(session, CKM_SHA256, data)?;
    }

    let key = decrypt_cbc_buffer(pkcs11, &ek[8..], &data)?;
    if key[0..3] != MAGIC_VALUE {
        return Err("Invalid PIN, magic value check failed!".into());
    }
    Ok(key[3..].to_vec())
}

fn find_ulong(
    attrs: &Vec<Attribute>,
    typ: CK_ATTRIBUTE_TYPE,
) -> CK_OBJECT_CLASS {
    let mut val = CK_UNAVAILABLE_INFORMATION;
    for a in attrs {
        if a.attr.type_ == typ {
            val = unsafe { *(a.attr.pValue as CK_ULONG_PTR) };
            break;
        }
    }
    return val;
}

fn import_obj(
    pkcs11: &mut FuncList,
    class: CK_OBJECT_CLASS,
    attrs: &Vec<Attribute>,
) -> Result<(), String> {
    let mut tmpl = Vec::<CK_ATTRIBUTE>::with_capacity(attrs.len());
    for a in attrs {
        if a.value.len() == 0 {
            /* No point in importing empty values */
            continue;
        }
        /* some attributes are never settable, let's skip them on import
         * for now */
        if a.attr.type_ == CKA_UNIQUE_ID {
            continue;
        }
        match class {
            CKO_PRIVATE_KEY => {
                if a.attr.type_ == CKA_LOCAL
                    || a.attr.type_ == CKA_KEY_GEN_MECHANISM
                    || a.attr.type_ == CKA_ALWAYS_SENSITIVE
                    || a.attr.type_ == CKA_NEVER_EXTRACTABLE
                {
                    continue;
                }
            }
            CKO_SECRET_KEY => {
                if a.attr.type_ == CKA_LOCAL
                    || a.attr.type_ == CKA_KEY_GEN_MECHANISM
                    || a.attr.type_ == CKA_ALWAYS_SENSITIVE
                    || a.attr.type_ == CKA_NEVER_EXTRACTABLE
                    || a.attr.type_ == CKA_TRUSTED
                {
                    continue;
                }
            }
            CKO_PUBLIC_KEY => {
                if a.attr.type_ == CKA_LOCAL
                    || a.attr.type_ == CKA_KEY_GEN_MECHANISM
                    || a.attr.type_ == CKA_TRUSTED
                {
                    continue;
                }
            }
            CKO_CERTIFICATE => (),
            _ => return Err(format!("Internal error: unknown class")),
        }

        tmpl.push(a.attr);
    }

    let session = match pkcs11.open_session() {
        Ok(s) => s,
        Err(e) => return Err(format!("Failed to get pkcs11 session: {}", e)),
    };

    match pkcs11.create_object(session, tmpl.as_slice()) {
        Ok(_) => (),
        Err(e) => return Err(format!("Failed to create object: {}", e)),
    }

    Ok(())
}

fn import_key(
    pkcs11: &mut FuncList,
    class: CK_OBJECT_CLASS,
    attrs: &mut Vec<Attribute>,
    ekey: &Vec<u8>,
) -> Result<(), String> {
    let key_type = find_ulong(attrs, CKA_KEY_TYPE);
    if key_type == CK_UNAVAILABLE_INFORMATION {
        return Err("Key type not found".to_string());
    }
    match key_type {
        CKK_RSA | CKK_EC | CKK_GENERIC_SECRET | CKK_AES | CKK_SHA_1_HMAC
        | CKK_SHA256_HMAC | CKK_SHA384_HMAC | CKK_SHA512_HMAC
        | CKK_SHA224_HMAC | CKK_SHA3_224_HMAC | CKK_SHA3_256_HMAC
        | CKK_SHA3_384_HMAC | CKK_SHA3_512_HMAC | CKK_EC_EDWARDS
        | CKK_EC_MONTGOMERY | CKK_HKDF => (),
        _ => return Err(format!("Unsupported key type {:x}", key_type)),
    }

    for a in &mut *attrs {
        /* Skip values that are not byte buffers but can be larger than 16 bytes */
        match a.attr.type_ {
            CKA_ALLOWED_MECHANISMS => continue,
            _ => (),
        }
        /* Assume all other values bigger than 16 bytes (IV size) are encrypted */
        if a.attr.ulValueLen > 16 {
            match decrypt_cbc_buffer(pkcs11, a.value.as_slice(), ekey) {
                Ok(v) => {
                    /* replace encrypted with plain text */
                    a.value = v;
                    a.attr.pValue = a.value.as_ptr() as *const _ as CK_VOID_PTR;
                    a.attr.ulValueLen = a.value.len() as CK_ULONG;
                }
                Err(e) => {
                    return Err(format!("Failed to decrypt key values: {}", e));
                }
            }
        }
    }
    import_obj(pkcs11, class, attrs)
}

const CKA_VENDOR_SOFTHSM: CK_ULONG = CKA_VENDOR_DEFINED + 0x5348;
/*
const CKA_OS_TOKENLABEL: CK_ULONG = CKA_VENDOR_SOFTHSM + 1;
const CKA_OS_TOKENSERIAL: CK_ULONG = CKA_VENDOR_SOFTHSM + 2;
const CKA_OS_TOKENFLAGS: CK_ULONG = CKA_VENDOR_SOFTHSM + 3;
const CKA_OS_SOPIN: CK_ULONG = CKA_VENDOR_SOFTHSM + 4;
*/
const CKA_OS_USERPIN: CK_ULONG = CKA_VENDOR_SOFTHSM + 5;

fn migrate(pkcs11: &mut FuncList, token: &PathBuf, pin: &Vec<u8>) -> u8 {
    /* check this is a token dir */
    let mut tokfile = token.clone();
    tokfile.push("token.object");

    let attrs = match read_object(&tokfile) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("{}", e);
            return 0xFE;
        }
    };

    let pin_attr = match attrs.iter().find(|a| a.attr.type_ == CKA_OS_USERPIN) {
        Some(a) => a,
        None => {
            eprintln!("Encryption key not found!");
            return 0xFE;
        }
    };

    let encryptionkey = match encryption_key(pkcs11, &pin_attr.value, pin) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("Failed to get key: {}", e);
            return 0xFE;
        }
    };

    let mut error = 0u8;

    for ent in read_dir(token).unwrap() {
        let f = ent.unwrap();
        if !f.file_type().unwrap().is_file() {
            continue;
        }
        let fname = f.file_name().into_string().unwrap();
        if !fname.ends_with(".object") || fname == "token.object" {
            continue;
        }

        println!("Importing {}", fname);

        let mut attrs = match read_object(&f.path()) {
            Ok(a) => a,
            Err(e) => {
                eprintln!("Failed to parse: {}", e);
                error += 1;
                continue;
            }
        };

        let class = find_ulong(&attrs, CKA_CLASS);
        match class {
            CKO_PRIVATE_KEY | CKO_SECRET_KEY => {
                match import_key(pkcs11, class, &mut attrs, &encryptionkey) {
                    Ok(()) => println!("Key imported"),
                    Err(s) => {
                        eprintln!("Failed to import key: {}", s);
                        error += 1;
                    }
                }
            }
            CKO_CERTIFICATE | CKO_PUBLIC_KEY => {
                match import_obj(pkcs11, class, &attrs) {
                    Ok(()) => println!("Object imported"),
                    Err(s) => {
                        eprintln!("Failed to import object {}:", s);
                        error += 1;
                    }
                }
            }
            _ => {
                eprintln!("Unsupported object class({})", class);
                error += 1;
            }
        }
    }
    error
}

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Arguments {
    #[arg(short = 'm', long)]
    pkcs11_module: String,

    #[arg(short = 'i', long)]
    pkcs11_initargs: Option<String>,

    #[arg(short = 'p', long)]
    pkcs11_pin: Option<String>,

    #[arg(short = 's', long)]
    pkcs11_slot: Option<u64>,

    #[arg(short = 'q', long)]
    softhsm2_pin: String,

    softhsm2_token: String,
}

fn main() -> ExitCode {
    let args = Arguments::parse();

    /* Let's try to load the library */
    let soname = CString::new(args.pkcs11_module).unwrap();
    let rtld_flags = libc::RTLD_LOCAL | libc::RTLD_NOW;
    let lib_handle =
        unsafe { libc::dlopen(soname.as_c_str().as_ptr(), rtld_flags) };
    if lib_handle.is_null() {
        eprintln!("Failed to load pkcs11 module: {}", dl_error());
        return ExitCode::from(0xFF);
    }

    /* Get entrypoint */
    let mut pkcs11 =
        match FuncList::from_symbol_name(lib_handle, "C_GetFunctionList") {
            Ok(x) => x,
            Err(e) => {
                eprintln!("{}", e);
                return ExitCode::from(0xFF);
            }
        };

    /* initialize the token */
    let initargs = if let Some(ia) = args.pkcs11_initargs.as_deref() {
        CString::new(ia)
    } else {
        CString::new("")
    }
    .unwrap();
    match pkcs11.initialize(initargs.as_c_str()) {
        Ok(()) => (),
        Err(e) => {
            eprintln!("{}", e);
            return ExitCode::from(0xFF);
        }
    }

    if let Some(pin) = args.pkcs11_pin.as_deref() {
        match pkcs11.login(pin) {
            Ok(_) => (),
            Err(e) => {
                eprintln!("{}", e);
                return ExitCode::from(0xFF);
            }
        }
    }

    let spin = args.softhsm2_pin.as_bytes().to_vec();

    let ret = migrate(&mut pkcs11, &PathBuf::from(args.softhsm2_token), &spin);
    ExitCode::from(ret)
}
