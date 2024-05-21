// Copyright 2024 Simo Sorce
// See LICENSE.txt file for terms

use super::tests;
use tests::*;

pub const CK_ULONG_SIZE: usize = std::mem::size_of::<CK_ULONG>();
pub const CK_BBOOL_SIZE: usize = std::mem::size_of::<CK_BBOOL>();

macro_rules! make_attribute {
    ($type:expr, $value:expr, $length:expr) => {
        CK_ATTRIBUTE {
            type_: $type,
            pValue: $value as CK_VOID_PTR,
            ulValueLen: $length as CK_ULONG,
        }
    };
}

macro_rules! ret_or_panic {
    ($ret:expr) => {
        match $ret {
            Ok(r) => r,
            Err(e) => panic!("{e}"),
        }
    };
}

macro_rules! err_or_panic {
    ($ret:expr, $err:expr) => {
        if !match $ret {
            Ok(_) => false,
            Err(e) => match e {
                KError::RvError(r) => r.rv == $err,
                _ => false,
            },
        } {
            panic!("Should have returned error {}", $err);
        }
    };
}

macro_rules! parse_or_panic {
    ($e:expr; $line:expr; $ln:expr) => {
        match $e {
            Ok(r) => r,
            Err(_) => panic!("Malformed line '{}' (line {})", $line, $ln),
        }
    };
}

pub fn get_test_data(
    session: CK_SESSION_HANDLE,
    name: &str,
    data: &str,
) -> Result<Vec<u8>, CK_RV> {
    let mut handle: CK_ULONG = CK_INVALID_HANDLE;
    let mut template = vec![
        make_attribute!(
            CKA_APPLICATION,
            CString::new(name).unwrap().into_raw(),
            name.len()
        ),
        make_attribute!(
            CKA_LABEL,
            CString::new(data).unwrap().into_raw(),
            data.len()
        ),
    ];
    let mut ret = fn_find_objects_init(
        session,
        template.as_mut_ptr(),
        template.len() as CK_ULONG,
    );
    if ret != CKR_OK {
        return Err(ret);
    }
    let mut count: CK_ULONG = 0;
    ret = fn_find_objects(session, &mut handle, 1, &mut count);
    if ret != CKR_OK {
        return Err(ret);
    }
    ret = fn_find_objects_final(session);
    if ret != CKR_OK {
        return Err(ret);
    }

    /* get value */
    template.clear();
    template.push(make_attribute!(CKA_VALUE, std::ptr::null_mut(), 0));
    ret = fn_get_attribute_value(
        session,
        handle,
        template.as_mut_ptr(),
        template.len() as CK_ULONG,
    );
    if ret != CKR_OK {
        return Err(ret);
    }

    let mut value = vec![0; template[0].ulValueLen as usize];
    template[0].pValue = value.as_mut_ptr() as CK_VOID_PTR;
    ret = fn_get_attribute_value(
        session,
        handle,
        template.as_mut_ptr(),
        template.len() as CK_ULONG,
    );
    if ret != CKR_OK {
        return Err(ret);
    }

    Ok(value)
}

pub fn decrypt(
    session: CK_SESSION_HANDLE,
    key: CK_OBJECT_HANDLE,
    ciphertext: &[u8],
    mechanism: &CK_MECHANISM,
) -> KResult<Vec<u8>> {
    let ret = fn_decrypt_init(
        session,
        mechanism as *const _ as CK_MECHANISM_PTR,
        key,
    );
    if ret != CKR_OK {
        return err_rv!(ret);
    }

    let mut dec_len: CK_ULONG = 0;
    let ret = fn_decrypt(
        session,
        ciphertext.as_ptr() as *mut u8,
        ciphertext.len() as CK_ULONG,
        std::ptr::null_mut(),
        &mut dec_len,
    );
    if ret != CKR_OK {
        return err_rv!(ret);
    }

    let mut dec = vec![0u8; dec_len as usize];
    let ret = fn_decrypt(
        session,
        ciphertext.as_ptr() as *mut u8,
        ciphertext.len() as CK_ULONG,
        dec.as_mut_ptr(),
        &mut dec_len,
    );
    if ret != CKR_OK {
        return err_rv!(ret);
    }
    dec.resize(dec_len as usize, 0);

    Ok(dec)
}

pub fn encrypt(
    session: CK_SESSION_HANDLE,
    key: CK_OBJECT_HANDLE,
    plaintext: &[u8],
    mechanism: &CK_MECHANISM,
) -> KResult<Vec<u8>> {
    let ret = fn_encrypt_init(
        session,
        mechanism as *const _ as CK_MECHANISM_PTR,
        key,
    );
    if ret != CKR_OK {
        return err_rv!(ret);
    }

    let mut enc_len: CK_ULONG = 0;
    let ret = fn_encrypt(
        session,
        plaintext.as_ptr() as *mut u8,
        plaintext.len() as CK_ULONG,
        std::ptr::null_mut(),
        &mut enc_len,
    );
    if ret != CKR_OK {
        return err_rv!(ret);
    }

    let mut enc = vec![0u8; enc_len as usize];
    let ret = fn_encrypt(
        session,
        plaintext.as_ptr() as *mut u8,
        plaintext.len() as CK_ULONG,
        enc.as_mut_ptr(),
        &mut enc_len,
    );
    if ret != CKR_OK {
        return err_rv!(ret);
    }
    enc.resize(enc_len as usize, 0);

    Ok(enc)
}

/* name in CKA_ID */
pub fn get_test_key_handle(
    session: CK_SESSION_HANDLE,
    name: &str,
    class: CK_ULONG,
) -> KResult<CK_OBJECT_HANDLE> {
    let mut handle: CK_ULONG = CK_INVALID_HANDLE;
    let mut classbuf = class;
    let mut template = vec![
        make_attribute!(
            CKA_ID,
            CString::new(name).unwrap().into_raw(),
            name.len()
        ),
        make_attribute!(CKA_CLASS, &mut classbuf as *mut _, CK_ULONG_SIZE),
    ];
    let ret = fn_find_objects_init(session, template.as_mut_ptr(), 2);
    if ret != CKR_OK {
        return err_rv!(ret);
    }
    let mut count: CK_ULONG = 0;
    let ret = fn_find_objects(session, &mut handle, 1, &mut count);
    if ret != CKR_OK {
        return err_rv!(ret);
    }
    if count != 1 {
        return err_not_found!(format!("count {} != 1", count));
    }
    let ret = fn_find_objects_final(session);
    if ret != CKR_OK {
        return err_rv!(ret);
    }

    Ok(handle)
}

pub fn sig_verify(
    session: CK_SESSION_HANDLE,
    key: CK_OBJECT_HANDLE,
    data: &[u8],
    signature: &[u8],
    mechanism: &CK_MECHANISM,
) -> CK_RV {
    let ret =
        fn_verify_init(session, mechanism as *const _ as CK_MECHANISM_PTR, key);
    if ret != CKR_OK {
        return ret;
    }

    fn_verify(
        session,
        byte_ptr!(data),
        data.len() as CK_ULONG,
        byte_ptr!(signature),
        signature.len() as CK_ULONG,
    )
}

pub fn sig_gen(
    session: CK_SESSION_HANDLE,
    key: CK_OBJECT_HANDLE,
    data: &[u8],
    mechanism: &CK_MECHANISM,
) -> KResult<Vec<u8>> {
    let ret =
        fn_sign_init(session, mechanism as *const _ as CK_MECHANISM_PTR, key);
    if ret != CKR_OK {
        return err_rv!(ret);
    }

    /* get signature length */
    let mut siglen: CK_ULONG = 0;
    let ret = fn_sign(
        session,
        byte_ptr!(data),
        data.len() as CK_ULONG,
        std::ptr::null_mut(),
        &mut siglen,
    );
    if ret != CKR_OK {
        return err_rv!(ret);
    }

    let mut signature: Vec<u8> = vec![0; siglen as usize];
    let ret = fn_sign(
        session,
        byte_ptr!(data),
        data.len() as CK_ULONG,
        signature.as_mut_ptr(),
        &mut siglen,
    );
    if ret != CKR_OK {
        return err_rv!(ret);
    }
    signature.resize(siglen as usize, 0);

    Ok(signature)
}

pub fn sig_gen_multipart(
    session: CK_SESSION_HANDLE,
    key: CK_OBJECT_HANDLE,
    data: &Vec<u8>,
    mechanism: &CK_MECHANISM,
) -> KResult<Vec<u8>> {
    let ret =
        fn_sign_init(session, mechanism as *const _ as CK_MECHANISM_PTR, key);
    if ret != CKR_OK {
        return err_rv!(ret);
    }

    let half_len = data.len() / 2;
    // just send data in two chunks
    let ret =
        fn_sign_update(session, data.as_ptr() as *mut u8, half_len as CK_ULONG);
    if ret != CKR_OK {
        return err_rv!(ret);
    }
    let ret = fn_sign_update(
        session,
        data[half_len..].as_ptr() as *mut u8,
        (data.len() - half_len) as CK_ULONG,
    );
    if ret != CKR_OK {
        return err_rv!(ret);
    }
    let mut siglen: CK_ULONG = 0;
    let ret = fn_sign_final(session, std::ptr::null_mut(), &mut siglen);
    if ret != CKR_OK {
        return err_rv!(ret);
    }

    let mut signature: Vec<u8> = vec![0; siglen as usize];
    let ret =
        fn_sign_final(session, signature.as_ptr() as *mut u8, &mut siglen);
    if ret != CKR_OK {
        return err_rv!(ret);
    }
    signature.resize(siglen as usize, 0);

    Ok(signature)
}

const TRUEBOOL: CK_BBOOL = CK_TRUE;
const FALSEBOOL: CK_BBOOL = CK_FALSE;

pub struct TestTemplate {
    longs: Vec<CK_ULONG>,
    vec: Vec<CK_ATTRIBUTE>,
}

impl TestTemplate {
    pub fn as_ptr(&self) -> *const CK_ATTRIBUTE {
        self.vec.as_ptr()
    }

    pub fn as_mut_ptr(&mut self) -> CK_ATTRIBUTE_PTR {
        self.vec.as_mut_ptr()
    }

    pub fn push(&mut self, attr: CK_ATTRIBUTE) {
        self.vec.push(attr)
    }

    pub fn len(&self) -> usize {
        self.vec.len()
    }
}

pub fn make_attr_template(
    ulongs: &[(CK_ATTRIBUTE_TYPE, CK_ULONG)],
    bytes: &[(CK_ATTRIBUTE_TYPE, &[u8])],
    bools: &[(CK_ATTRIBUTE_TYPE, bool)],
) -> TestTemplate {
    /* Add one more, often code adds a class attribute later */
    let capacity = ulongs.len() + bytes.len() + bools.len() + 1;
    let mut template = TestTemplate {
        longs: Vec::with_capacity(ulongs.len()),
        vec: Vec::<CK_ATTRIBUTE>::with_capacity(capacity),
    };
    for u in ulongs {
        template.longs.push(u.1);
        if let Some(ptr) = template.longs.last() {
            template.push(make_attribute!(u.0, ptr as *const _, CK_ULONG_SIZE));
        }
    }
    for b in bytes {
        template.push(make_attribute!(b.0, b.1.as_ptr(), b.1.len()));
    }
    for b in bools {
        template.push(make_attribute!(
            b.0,
            if b.1 { &TRUEBOOL } else { &FALSEBOOL } as *const _,
            CK_BBOOL_SIZE
        ));
    }
    template
}

pub fn make_ptrs_template(
    ptrs: &[(CK_ATTRIBUTE_TYPE, CK_VOID_PTR, usize)],
) -> Vec<CK_ATTRIBUTE> {
    let mut template = Vec::<CK_ATTRIBUTE>::with_capacity(ptrs.len());
    for p in ptrs {
        template.push(make_attribute!(p.0, p.1, p.2 as CK_ULONG));
    }
    template
}

pub fn import_object(
    session: CK_ULONG,
    class: CK_OBJECT_CLASS,
    ulongs: &[(CK_ATTRIBUTE_TYPE, CK_ULONG)],
    bytes: &[(CK_ATTRIBUTE_TYPE, &[u8])],
    bools: &[(CK_ATTRIBUTE_TYPE, bool)],
) -> KResult<CK_OBJECT_HANDLE> {
    let mut template = make_attr_template(ulongs, bytes, bools);
    template.push(make_attribute!(
        CKA_CLASS,
        &class as *const _,
        CK_ULONG_SIZE
    ));

    let mut handle: CK_OBJECT_HANDLE = CK_INVALID_HANDLE;
    let ret = fn_create_object(
        session,
        template.as_ptr() as CK_ATTRIBUTE_PTR,
        template.len() as CK_ULONG,
        &mut handle,
    );

    if ret != CKR_OK {
        return err_rv!(ret);
    }
    Ok(handle)
}

pub fn generate_key(
    session: CK_ULONG,
    mech: CK_MECHANISM_TYPE,
    mechdata: CK_VOID_PTR,
    mechdlen: CK_ULONG,
    ulongs: &[(CK_ATTRIBUTE_TYPE, CK_ULONG)],
    bytes: &[(CK_ATTRIBUTE_TYPE, &[u8])],
    bools: &[(CK_ATTRIBUTE_TYPE, bool)],
) -> KResult<CK_OBJECT_HANDLE> {
    let class = CKO_SECRET_KEY;
    let mut template = make_attr_template(ulongs, bytes, bools);
    template.push(make_attribute!(
        CKA_CLASS,
        &class as *const _,
        CK_ULONG_SIZE
    ));

    let mut mechanism: CK_MECHANISM = CK_MECHANISM {
        mechanism: mech,
        pParameter: mechdata,
        ulParameterLen: mechdlen,
    };

    let mut handle: CK_OBJECT_HANDLE = CK_INVALID_HANDLE;
    let ret = fn_generate_key(
        session,
        &mut mechanism,
        template.as_ptr() as CK_ATTRIBUTE_PTR,
        template.len() as CK_ULONG,
        &mut handle,
    );

    if ret != CKR_OK {
        return err_rv!(ret);
    }
    Ok(handle)
}

pub fn generate_key_pair(
    session: CK_ULONG,
    mech: CK_MECHANISM_TYPE,
    pub_ulongs: &[(CK_ATTRIBUTE_TYPE, CK_ULONG)],
    pub_bytes: &[(CK_ATTRIBUTE_TYPE, &[u8])],
    pub_bools: &[(CK_ATTRIBUTE_TYPE, bool)],
    pri_ulongs: &[(CK_ATTRIBUTE_TYPE, CK_ULONG)],
    pri_bytes: &[(CK_ATTRIBUTE_TYPE, &[u8])],
    pri_bools: &[(CK_ATTRIBUTE_TYPE, bool)],
) -> KResult<(CK_OBJECT_HANDLE, CK_OBJECT_HANDLE)> {
    let pub_template = make_attr_template(pub_ulongs, pub_bytes, pub_bools);
    let pri_template = make_attr_template(pri_ulongs, pri_bytes, pri_bools);

    let mut mechanism: CK_MECHANISM = CK_MECHANISM {
        mechanism: mech,
        pParameter: std::ptr::null_mut(),
        ulParameterLen: 0,
    };

    let mut pub_key: CK_OBJECT_HANDLE = CK_INVALID_HANDLE;
    let mut pri_key: CK_OBJECT_HANDLE = CK_INVALID_HANDLE;
    let ret = fn_generate_key_pair(
        session,
        &mut mechanism,
        pub_template.as_ptr() as CK_ATTRIBUTE_PTR,
        pub_template.len() as CK_ULONG,
        pri_template.as_ptr() as CK_ATTRIBUTE_PTR,
        pri_template.len() as CK_ULONG,
        &mut pub_key,
        &mut pri_key,
    );

    if ret != CKR_OK {
        return err_rv!(ret);
    }
    Ok((pub_key, pri_key))
}
