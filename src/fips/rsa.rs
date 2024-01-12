// Copyright 2023 Simo Sorce
// See LICENSE.txt file for terms

use super::fips;
use super::mechanism;

use fips::*;
use mechanism::*;

use std::slice;
use zeroize::Zeroize;

pub fn rsa_import(obj: &mut Object) -> KResult<()> {
    let modulus = match obj.get_attr_as_bytes(CKA_MODULUS) {
        Ok(m) => m,
        Err(_) => return err_rv!(CKR_TEMPLATE_INCOMPLETE),
    };
    if modulus.len() < MIN_RSA_SIZE_BYTES {
        return err_rv!(CKR_ATTRIBUTE_VALUE_INVALID);
    }
    bytes_attr_not_empty!(obj; CKA_PUBLIC_EXPONENT);
    bytes_attr_not_empty!(obj; CKA_PRIVATE_EXPONENT);
    /* The FIPS module can handle missing p,q,a,b,c */
    Ok(())
}

macro_rules! make_bn {
    ($name:expr; $vin:expr; $vout:expr) => {{
        let bn = unsafe {
            BN_bin2bn(
                $vin.as_ptr() as *mut u8,
                $vin.len() as i32,
                std::ptr::null_mut(),
            )
        };
        if bn.is_null() {
            return err_rv!(CKR_DEVICE_ERROR);
        }
        let mut param = unsafe {
            OSSL_PARAM_construct_BN(
                $name as *const u8 as *const i8,
                std::ptr::null_mut(),
                0,
            )
        };
        /* calculate needed size */
        unsafe {
            OSSL_PARAM_set_BN(&mut param, bn);
        }
        $vout.resize(param.return_size, 0);
        unsafe {
            param.data = $vout.as_mut_ptr() as *mut std::os::raw::c_void;
            param.data_size = $vout.len();
            OSSL_PARAM_set_BN(&mut param, bn);
        }
        param
    }};
}

macro_rules! make_bn_from_obj {
    ($obj:expr; $id:expr; $name:expr; $vec:expr) => {{
        let x = match $obj.get_attr_as_bytes($id) {
            Ok(b) => b,
            Err(_) => return err_rv!(CKR_DEVICE_ERROR),
        };
        make_bn!($name; x; $vec)
    }};
}

macro_rules! param_bn_to_vec {
    ($params:expr; $name:expr; $vec:expr) => {{
        let p = unsafe {
            OSSL_PARAM_locate($params, $name as *const u8 as *const i8)
        };
        if p.is_null() {
            return err_rv!(CKR_DEVICE_ERROR);
        }
        let mut bn: *mut BIGNUM = std::ptr::null_mut();
        if unsafe { OSSL_PARAM_get_BN(p, &mut bn) } != 1 {
            return err_rv!(CKR_DEVICE_ERROR);
        }
        let big_num = BigNum::from_ptr(bn)?;
        $vec.resize(bn_num_bytes(big_num.as_ptr()), 0);
        if unsafe {
            BN_bn2bin(
                big_num.as_ptr(),
                $vec.as_mut_ptr() as *mut std::os::raw::c_uchar,
            ) as usize
        } != $vec.len()
        {
            return err_rv!(CKR_DEVICE_ERROR);
        }
    }};
}

macro_rules! param_bn_to_obj_attr {
    ($params:expr; $name:expr; $obj:expr; $attr:expr) => {{
        let mut vec = Vec::<u8>::new();
        param_bn_to_vec!($params; $name; vec);
        $obj.set_attr(attribute::from_bytes($attr, vec))?;
    }};
}

fn new_pkey_ctx() -> KResult<EvpPkeyCtx> {
    Ok(EvpPkeyCtx::from_ptr(unsafe {
        EVP_PKEY_CTX_new_from_name(
            get_libctx(),
            b"RSA\0".as_ptr() as *const i8,
            std::ptr::null(),
        )
    })?)
}

fn object_to_rsa_public_key(key: &Object) -> KResult<EvpPkey> {
    let mut nvec: Vec<u8> = Vec::new();
    let mut evec: Vec<u8> = Vec::new();
    let mut params = [
        make_bn_from_obj!(key; CKA_MODULUS; OSSL_PKEY_PARAM_RSA_N; nvec),
        make_bn_from_obj!(key; CKA_PUBLIC_EXPONENT; OSSL_PKEY_PARAM_RSA_E; evec),
        unsafe { OSSL_PARAM_construct_end() },
    ];

    let mut ctx = new_pkey_ctx()?;
    if unsafe { EVP_PKEY_fromdata_init(ctx.as_mut_ptr()) } != 1 {
        return err_rv!(CKR_DEVICE_ERROR);
    }
    let mut pkey: *mut EVP_PKEY = std::ptr::null_mut();
    if unsafe {
        EVP_PKEY_fromdata(
            ctx.as_mut_ptr(),
            &mut pkey,
            EVP_PKEY_PUBLIC_KEY as i32,
            params.as_mut_ptr(),
        )
    } != 1
    {
        return err_rv!(CKR_DEVICE_ERROR);
    }
    nvec.zeroize();
    evec.zeroize();
    EvpPkey::from_ptr(pkey)
}

fn object_to_rsa_private_key(key: &Object) -> KResult<EvpPkey> {
    let mut nvec: Vec<u8> = Vec::new();
    let mut evec: Vec<u8> = Vec::new();
    let mut dvec: Vec<u8> = Vec::new();
    let mut pvec: Vec<u8> = Vec::new();
    let mut qvec: Vec<u8> = Vec::new();
    let mut avec: Vec<u8> = Vec::new();
    let mut bvec: Vec<u8> = Vec::new();
    let mut cvec: Vec<u8> = Vec::new();
    let mut params = [
        make_bn_from_obj!(key; CKA_MODULUS; OSSL_PKEY_PARAM_RSA_N; nvec),
        make_bn_from_obj!(key; CKA_PUBLIC_EXPONENT; OSSL_PKEY_PARAM_RSA_E; evec),
        make_bn_from_obj!(key; CKA_PRIVATE_EXPONENT; OSSL_PKEY_PARAM_RSA_D; dvec),
        unsafe { OSSL_PARAM_construct_end() },
        unsafe { OSSL_PARAM_construct_end() },
        unsafe { OSSL_PARAM_construct_end() },
        unsafe { OSSL_PARAM_construct_end() },
        unsafe { OSSL_PARAM_construct_end() },
        unsafe { OSSL_PARAM_construct_end() },
        unsafe { OSSL_PARAM_construct_end() },
    ];
    if key.get_attr(CKA_PRIME_1).is_some()
        && key.get_attr(CKA_PRIME_2).is_some()
        && key.get_attr(CKA_EXPONENT_1).is_some()
        && key.get_attr(CKA_EXPONENT_2).is_some()
        && key.get_attr(CKA_COEFFICIENT).is_some()
    {
        params[3] = make_bn_from_obj!(key; CKA_PRIME_1; OSSL_PKEY_PARAM_RSA_FACTOR1; pvec);
        params[4] = make_bn_from_obj!(key; CKA_PRIME_2; OSSL_PKEY_PARAM_RSA_FACTOR2; qvec);
        params[5] = make_bn_from_obj!(key; CKA_EXPONENT_1; OSSL_PKEY_PARAM_RSA_EXPONENT1; avec);
        params[6] = make_bn_from_obj!(key; CKA_EXPONENT_2; OSSL_PKEY_PARAM_RSA_EXPONENT2; bvec);
        params[7] = make_bn_from_obj!(key; CKA_COEFFICIENT; OSSL_PKEY_PARAM_RSA_COEFFICIENT1; cvec);
    }

    let mut ctx = new_pkey_ctx()?;
    if unsafe { EVP_PKEY_fromdata_init(ctx.as_mut_ptr()) } != 1 {
        return err_rv!(CKR_DEVICE_ERROR);
    }
    let mut pkey: *mut EVP_PKEY = std::ptr::null_mut();
    if unsafe {
        EVP_PKEY_fromdata(
            ctx.as_mut_ptr(),
            &mut pkey,
            EVP_PKEY_PRIVATE_KEY as i32,
            params.as_mut_ptr(),
        )
    } != 1
    {
        return err_rv!(CKR_DEVICE_ERROR);
    }
    nvec.zeroize();
    evec.zeroize();
    dvec.zeroize();
    pvec.zeroize();
    qvec.zeroize();
    avec.zeroize();
    bvec.zeroize();
    cvec.zeroize();
    EvpPkey::from_ptr(pkey)
}

fn empty_private_key() -> EvpPkey {
    EvpPkey::empty()
}

macro_rules! name_to_vec {
    ($name:expr) => {
        unsafe {
            slice::from_raw_parts(
                $name.as_ptr() as *const std::os::raw::c_char,
                $name.len(),
            )
            .to_vec()
        }
    };
}

fn get_digest_name(
    mech: CK_MECHANISM_TYPE,
) -> KResult<Vec<std::os::raw::c_char>> {
    Ok(match mech {
        CKM_RSA_PKCS => Vec::new(),
        CKM_SHA1_RSA_PKCS => name_to_vec!(OSSL_DIGEST_NAME_SHA1),
        CKM_SHA224_RSA_PKCS => name_to_vec!(OSSL_DIGEST_NAME_SHA2_224),
        CKM_SHA256_RSA_PKCS => name_to_vec!(OSSL_DIGEST_NAME_SHA2_256),
        CKM_SHA384_RSA_PKCS => name_to_vec!(OSSL_DIGEST_NAME_SHA2_384),
        CKM_SHA512_RSA_PKCS => name_to_vec!(OSSL_DIGEST_NAME_SHA2_512),
        CKM_SHA3_224_RSA_PKCS => name_to_vec!(OSSL_DIGEST_NAME_SHA3_224),
        CKM_SHA3_256_RSA_PKCS => name_to_vec!(OSSL_DIGEST_NAME_SHA3_256),
        CKM_SHA3_384_RSA_PKCS => name_to_vec!(OSSL_DIGEST_NAME_SHA3_384),
        CKM_SHA3_512_RSA_PKCS => name_to_vec!(OSSL_DIGEST_NAME_SHA3_512),
        _ => return err_rv!(CKR_GENERAL_ERROR),
    })
}

static RSA_NAME: &[u8; 4] = b"RSA\0";
fn rsa_name_as_char() -> *const std::os::raw::c_char {
    RSA_NAME.as_ptr() as *const std::os::raw::c_char
}

#[derive(Debug)]
struct RsaPKCSOperation {
    mech: CK_MECHANISM_TYPE,
    max_input: usize,
    output_len: usize,
    public_key: EvpPkey,
    private_key: EvpPkey,
    finalized: bool,
    in_use: bool,
    sigctx: Option<ProviderSignatureCtx>,
    mdname: Vec<std::os::raw::c_char>,
}

impl RsaPKCSOperation {
    fn encrypt_new(
        mech: &CK_MECHANISM,
        key: &Object,
        info: &CK_MECHANISM_INFO,
    ) -> KResult<RsaPKCSOperation> {
        let modulus = key.get_attr_as_bytes(CKA_MODULUS)?;
        let modulus_bits: u64 = modulus.len() as u64 * 8;
        if modulus_bits < info.ulMinKeySize
            || (info.ulMaxKeySize != 0 && modulus_bits > info.ulMaxKeySize)
        {
            return err_rv!(CKR_KEY_SIZE_RANGE);
        }
        if mech.mechanism != CKM_RSA_PKCS {
            return err_rv!(CKR_MECHANISM_INVALID);
        }
        Ok(RsaPKCSOperation {
            mech: mech.mechanism,
            max_input: modulus.len() - 11,
            output_len: modulus.len(),
            public_key: object_to_rsa_public_key(key)?,
            private_key: empty_private_key(),
            finalized: false,
            in_use: false,
            sigctx: None,
            mdname: Vec::new(),
        })
    }

    fn decrypt_new(
        mech: &CK_MECHANISM,
        key: &Object,
        info: &CK_MECHANISM_INFO,
    ) -> KResult<RsaPKCSOperation> {
        let modulus = key.get_attr_as_bytes(CKA_MODULUS)?;
        let modulus_bits: u64 = modulus.len() as u64 * 8;
        if modulus_bits < info.ulMinKeySize
            || (info.ulMaxKeySize != 0 && modulus_bits > info.ulMaxKeySize)
        {
            return err_rv!(CKR_KEY_SIZE_RANGE);
        }
        if mech.mechanism != CKM_RSA_PKCS {
            return err_rv!(CKR_MECHANISM_INVALID);
        }
        Ok(RsaPKCSOperation {
            mech: mech.mechanism,
            max_input: modulus.len(),
            output_len: modulus.len() - 11,
            public_key: object_to_rsa_public_key(key)?,
            private_key: object_to_rsa_private_key(key)?,
            finalized: false,
            in_use: false,
            sigctx: None,
            mdname: Vec::new(),
        })
    }

    fn sign_new(
        mech: &CK_MECHANISM,
        key: &Object,
        info: &CK_MECHANISM_INFO,
    ) -> KResult<RsaPKCSOperation> {
        let modulus = key.get_attr_as_bytes(CKA_MODULUS)?;
        let modulus_bits: u64 = modulus.len() as u64 * 8;
        if modulus_bits < info.ulMinKeySize
            || (info.ulMaxKeySize != 0 && modulus_bits > info.ulMaxKeySize)
        {
            return err_rv!(CKR_KEY_SIZE_RANGE);
        }

        Ok(RsaPKCSOperation {
            mech: mech.mechanism,
            max_input: match mech.mechanism {
                CKM_RSA_PKCS => modulus.len() - 11,
                _ => 0,
            },
            output_len: modulus.len(),
            public_key: object_to_rsa_public_key(key)?,
            private_key: object_to_rsa_private_key(key)?,
            finalized: false,
            in_use: false,
            sigctx: match mech.mechanism {
                CKM_RSA_PKCS => None,
                _ => Some(ProviderSignatureCtx::new(rsa_name_as_char())?),
            },
            mdname: get_digest_name(mech.mechanism)?,
        })
    }

    fn verify_new(
        mech: &CK_MECHANISM,
        key: &Object,
        info: &CK_MECHANISM_INFO,
    ) -> KResult<RsaPKCSOperation> {
        let modulus = key.get_attr_as_bytes(CKA_MODULUS)?;
        let modulus_bits: u64 = modulus.len() as u64 * 8;
        if modulus_bits < info.ulMinKeySize
            || (info.ulMaxKeySize != 0 && modulus_bits > info.ulMaxKeySize)
        {
            return err_rv!(CKR_KEY_SIZE_RANGE);
        }

        Ok(RsaPKCSOperation {
            mech: mech.mechanism,
            max_input: match mech.mechanism {
                CKM_RSA_PKCS => modulus.len() - 11,
                _ => 0,
            },
            output_len: modulus.len(),
            public_key: object_to_rsa_public_key(key)?,
            private_key: empty_private_key(),
            finalized: false,
            in_use: false,
            sigctx: match mech.mechanism {
                CKM_RSA_PKCS => None,
                _ => Some(ProviderSignatureCtx::new(rsa_name_as_char())?),
            },
            mdname: get_digest_name(mech.mechanism)?,
        })
    }

    fn generate_keypair(
        exponent: Vec<u8>,
        bits: usize,
        pubkey: &mut Object,
        privkey: &mut Object,
    ) -> KResult<()> {
        let mut ctx = new_pkey_ctx()?;
        if unsafe { EVP_PKEY_keygen_init(ctx.as_mut_ptr()) } != 1 {
            return err_rv!(CKR_DEVICE_ERROR);
        }
        let mut rsa_bits = bits;
        let rsa_bits_ptr = &mut rsa_bits;
        let mut evec = Vec::<u8>::new();
        let params = [
            make_bn!(OSSL_PKEY_PARAM_RSA_E; exponent; evec),
            unsafe {
                OSSL_PARAM_construct_size_t(
                    OSSL_PKEY_PARAM_BITS as *const u8 as *const i8,
                    rsa_bits_ptr,
                )
            },
            unsafe { OSSL_PARAM_construct_end() },
        ];
        if unsafe { EVP_PKEY_CTX_set_params(ctx.as_mut_ptr(), params.as_ptr()) }
            != 1
        {
            return err_rv!(CKR_DEVICE_ERROR);
        }
        let mut pkey: *mut EVP_PKEY = std::ptr::null_mut();
        if unsafe { EVP_PKEY_generate(ctx.as_mut_ptr(), &mut pkey) } != 1 {
            return err_rv!(CKR_DEVICE_ERROR);
        }
        let evp_pkey = EvpPkey::from_ptr(pkey)?;
        let mut params: *mut OSSL_PARAM = std::ptr::null_mut();

        if unsafe {
            EVP_PKEY_todata(
                evp_pkey.as_ptr(),
                EVP_PKEY_KEYPAIR as std::os::raw::c_int,
                &mut params,
            )
        } != 1
        {
            return err_rv!(CKR_DEVICE_ERROR);
        }
        let mut ossl_params = OsslParam::from_ptr(params)?;
        /* Public Key (has E already set) */
        param_bn_to_obj_attr!(
            ossl_params.as_mut_ptr();
            OSSL_PKEY_PARAM_RSA_N;
            pubkey;
            CKA_MODULUS);

        /* Private Key */
        param_bn_to_obj_attr!(
            ossl_params.as_mut_ptr();
            OSSL_PKEY_PARAM_RSA_N;
            privkey;
            CKA_MODULUS);
        param_bn_to_obj_attr!(
            ossl_params.as_mut_ptr();
            OSSL_PKEY_PARAM_RSA_E;
            privkey;
            CKA_PUBLIC_EXPONENT);
        param_bn_to_obj_attr!(
            ossl_params.as_mut_ptr();
            OSSL_PKEY_PARAM_RSA_D;
            privkey;
            CKA_PRIVATE_EXPONENT);
        param_bn_to_obj_attr!(
            ossl_params.as_mut_ptr();
            OSSL_PKEY_PARAM_RSA_FACTOR1;
            privkey;
            CKA_PRIME_1);
        param_bn_to_obj_attr!(
            ossl_params.as_mut_ptr();
            OSSL_PKEY_PARAM_RSA_FACTOR2;
            privkey;
            CKA_PRIME_2);
        param_bn_to_obj_attr!(
            ossl_params.as_mut_ptr();
            OSSL_PKEY_PARAM_RSA_EXPONENT1;
            privkey;
            CKA_EXPONENT_1);
        param_bn_to_obj_attr!(
            ossl_params.as_mut_ptr();
            OSSL_PKEY_PARAM_RSA_EXPONENT2;
            privkey;
            CKA_EXPONENT_2);
        param_bn_to_obj_attr!(
            ossl_params.as_mut_ptr();
            OSSL_PKEY_PARAM_RSA_COEFFICIENT1;
            privkey;
            CKA_COEFFICIENT);
        Ok(())
    }
}

impl MechOperation for RsaPKCSOperation {
    fn mechanism(&self) -> CK_MECHANISM_TYPE {
        self.mech
    }
    fn in_use(&self) -> bool {
        self.in_use
    }
    fn finalized(&self) -> bool {
        self.finalized
    }
}

impl Encryption for RsaPKCSOperation {
    fn encrypt(
        &mut self,
        plain: &[u8],
        cipher: CK_BYTE_PTR,
        cipher_len: CK_ULONG_PTR,
    ) -> KResult<()> {
        if self.in_use {
            return err_rv!(CKR_OPERATION_NOT_INITIALIZED);
        }
        if self.finalized {
            return err_rv!(CKR_OPERATION_NOT_INITIALIZED);
        }
        let mut ctx = EvpPkeyCtx::from_ptr(unsafe {
            EVP_PKEY_CTX_new_from_pkey(
                get_libctx(),
                self.public_key.as_mut_ptr(),
                std::ptr::null_mut(),
            )
        })?;
        if unsafe { EVP_PKEY_encrypt_init(ctx.as_mut_ptr()) } != 1 {
            return err_rv!(CKR_DEVICE_ERROR);
        }
        let params = [
            unsafe {
                OSSL_PARAM_construct_utf8_string(
                    OSSL_PKEY_PARAM_PAD_MODE.as_ptr() as *const i8,
                    OSSL_PKEY_RSA_PAD_MODE_PKCSV15.as_ptr() as *mut i8,
                    OSSL_PKEY_RSA_PAD_MODE_PKCSV15.len(),
                )
            },
            unsafe { OSSL_PARAM_construct_end() },
        ];
        if unsafe { EVP_PKEY_CTX_set_params(ctx.as_mut_ptr(), params.as_ptr()) }
            != 1
        {
            return err_rv!(CKR_DEVICE_ERROR);
        }

        let mut outlen = 0usize;
        let outlen_ptr: *mut usize = &mut outlen;
        if unsafe {
            EVP_PKEY_encrypt(
                ctx.as_mut_ptr(),
                std::ptr::null_mut(),
                outlen_ptr,
                plain.as_ptr(),
                plain.len(),
            )
        } != 1
        {
            return err_rv!(CKR_DEVICE_ERROR);
        }
        if cipher.is_null() {
            unsafe {
                *cipher_len = outlen as CK_ULONG;
            }
            return Ok(());
        } else {
            unsafe {
                if (*cipher_len as usize) < outlen {
                    return err_rv!(CKR_BUFFER_TOO_SMALL);
                }
            }
        }

        self.finalized = true;

        if unsafe {
            EVP_PKEY_encrypt(
                ctx.as_mut_ptr(),
                cipher,
                outlen_ptr,
                plain.as_ptr(),
                plain.len(),
            )
        } != 1
        {
            return err_rv!(CKR_DEVICE_ERROR);
        }
        unsafe {
            *cipher_len = outlen as CK_ULONG;
        }
        Ok(())
    }

    fn encrypt_update(
        &mut self,
        _plain: &[u8],
        _cipher: CK_BYTE_PTR,
        _cipher_len: CK_ULONG_PTR,
    ) -> KResult<()> {
        self.finalized = true;
        return err_rv!(CKR_OPERATION_NOT_INITIALIZED);
    }

    fn encrypt_final(
        &mut self,
        _cipher: CK_BYTE_PTR,
        _cipher_len: CK_ULONG_PTR,
    ) -> KResult<()> {
        self.finalized = true;
        return err_rv!(CKR_OPERATION_NOT_INITIALIZED);
    }

    fn encryption_len(&self) -> KResult<usize> {
        match self.mech {
            CKM_RSA_PKCS => Ok(self.output_len),
            _ => err_rv!(CKR_GENERAL_ERROR),
        }
    }
}

impl Decryption for RsaPKCSOperation {
    fn decrypt(
        &mut self,
        cipher: &[u8],
        plain: CK_BYTE_PTR,
        plain_len: CK_ULONG_PTR,
    ) -> KResult<()> {
        if self.in_use {
            return err_rv!(CKR_OPERATION_NOT_INITIALIZED);
        }
        if self.finalized {
            return err_rv!(CKR_OPERATION_NOT_INITIALIZED);
        }
        unsafe {
            let mut ctx = EvpPkeyCtx::from_ptr(EVP_PKEY_CTX_new_from_pkey(
                get_libctx(),
                self.private_key.as_mut_ptr(),
                std::ptr::null_mut(),
            ))?;
            if EVP_PKEY_decrypt_init(ctx.as_mut_ptr()) != 1 {
                return err_rv!(CKR_DEVICE_ERROR);
            }
            let params = [
                OSSL_PARAM_construct_utf8_string(
                    OSSL_PKEY_PARAM_PAD_MODE.as_ptr() as *const i8,
                    OSSL_PKEY_RSA_PAD_MODE_PKCSV15.as_ptr() as *mut i8,
                    OSSL_PKEY_RSA_PAD_MODE_PKCSV15.len(),
                ),
                OSSL_PARAM_construct_end(),
            ];
            if EVP_PKEY_CTX_set_params(ctx.as_mut_ptr(), params.as_ptr()) != 1 {
                return err_rv!(CKR_DEVICE_ERROR);
            }

            let mut outlen = 0usize;
            let outlen_ptr: *mut usize = &mut outlen;
            if EVP_PKEY_decrypt(
                ctx.as_mut_ptr(),
                std::ptr::null_mut(),
                outlen_ptr,
                cipher.as_ptr(),
                cipher.len(),
            ) != 1
            {
                return err_rv!(CKR_DEVICE_ERROR);
            }
            if plain.is_null() {
                *plain_len = outlen as CK_ULONG;
                return Ok(());
            } else {
                if (*plain_len as usize) < outlen {
                    return err_rv!(CKR_BUFFER_TOO_SMALL);
                }
            }

            self.finalized = true;

            if EVP_PKEY_decrypt(
                ctx.as_mut_ptr(),
                plain,
                outlen_ptr,
                cipher.as_ptr(),
                cipher.len(),
            ) != 1
            {
                return err_rv!(CKR_DEVICE_ERROR);
            }
            *plain_len = outlen as CK_ULONG;
        }
        Ok(())
    }

    fn decrypt_update(
        &mut self,
        _cipher: &[u8],
        _plain: CK_BYTE_PTR,
        _plain_len: CK_ULONG_PTR,
    ) -> KResult<()> {
        self.finalized = true;
        return err_rv!(CKR_OPERATION_NOT_INITIALIZED);
    }

    fn decrypt_final(
        &mut self,
        _plain: CK_BYTE_PTR,
        _plain_len: CK_ULONG_PTR,
    ) -> KResult<()> {
        self.finalized = true;
        return err_rv!(CKR_OPERATION_NOT_INITIALIZED);
    }

    fn decryption_len(&self) -> KResult<usize> {
        match self.mech {
            CKM_RSA_PKCS => Ok(self.output_len),
            _ => err_rv!(CKR_GENERAL_ERROR),
        }
    }
}

impl Sign for RsaPKCSOperation {
    fn sign(&mut self, data: &[u8], signature: &mut [u8]) -> KResult<()> {
        if self.in_use {
            return err_rv!(CKR_OPERATION_NOT_INITIALIZED);
        }
        if self.finalized {
            return err_rv!(CKR_OPERATION_NOT_INITIALIZED);
        }
        if self.mech == CKM_RSA_PKCS {
            self.finalized = true;
            if data.len() > self.max_input {
                return err_rv!(CKR_DATA_LEN_RANGE);
            }
            if signature.len() != self.output_len {
                return err_rv!(CKR_GENERAL_ERROR);
            }
            let mut ctx = EvpPkeyCtx::from_ptr(unsafe {
                EVP_PKEY_CTX_new_from_pkey(
                    get_libctx(),
                    self.private_key.as_mut_ptr(),
                    std::ptr::null_mut(),
                )
            })?;
            if unsafe { EVP_PKEY_sign_init(ctx.as_mut_ptr()) } != 1 {
                return err_rv!(CKR_DEVICE_ERROR);
            }
            let params = [
                unsafe {
                    OSSL_PARAM_construct_utf8_string(
                        OSSL_PKEY_PARAM_PAD_MODE.as_ptr() as *const i8,
                        OSSL_PKEY_RSA_PAD_MODE_PKCSV15.as_ptr() as *mut i8,
                        OSSL_PKEY_RSA_PAD_MODE_PKCSV15.len(),
                    )
                },
                unsafe { OSSL_PARAM_construct_end() },
            ];
            if unsafe {
                EVP_PKEY_CTX_set_params(ctx.as_mut_ptr(), params.as_ptr())
            } != 1
            {
                return err_rv!(CKR_DEVICE_ERROR);
            }

            self.finalized = true;

            let mut siglen = 0usize;
            let siglen_ptr: *mut usize = &mut siglen;
            if unsafe {
                EVP_PKEY_sign(
                    ctx.as_mut_ptr(),
                    std::ptr::null_mut(),
                    siglen_ptr,
                    data.as_ptr(),
                    data.len(),
                )
            } != 1
            {
                return err_rv!(CKR_DEVICE_ERROR);
            }
            if signature.len() != siglen {
                return err_rv!(CKR_GENERAL_ERROR);
            }

            if unsafe {
                EVP_PKEY_sign(
                    ctx.as_mut_ptr(),
                    signature.as_mut_ptr(),
                    siglen_ptr,
                    data.as_ptr(),
                    data.len(),
                )
            } != 1
            {
                return err_rv!(CKR_DEVICE_ERROR);
            }

            return Ok(());
        }
        self.sign_update(data)?;
        self.sign_final(signature)
    }

    fn sign_update(&mut self, data: &[u8]) -> KResult<()> {
        if self.finalized {
            return err_rv!(CKR_OPERATION_NOT_INITIALIZED);
        }
        if !self.in_use {
            if self.mech == CKM_RSA_PKCS {
                return err_rv!(CKR_OPERATION_NOT_INITIALIZED);
            }
            self.in_use = true;

            let params = [
                unsafe {
                    OSSL_PARAM_construct_utf8_string(
                        OSSL_SIGNATURE_PARAM_PAD_MODE.as_ptr() as *const i8,
                        OSSL_PKEY_RSA_PAD_MODE_PKCSV15.as_ptr() as *mut i8,
                        OSSL_PKEY_RSA_PAD_MODE_PKCSV15.len(),
                    )
                },
                unsafe { OSSL_PARAM_construct_end() },
            ];
            self.sigctx.as_mut().unwrap().digest_sign_init(
                self.mdname.as_ptr(),
                &self.private_key,
                params.as_ptr(),
            )?;
        }

        self.sigctx.as_mut().unwrap().digest_sign_update(data)
    }

    fn sign_final(&mut self, signature: &mut [u8]) -> KResult<()> {
        if !self.in_use {
            return err_rv!(CKR_OPERATION_NOT_INITIALIZED);
        }
        if self.finalized {
            return err_rv!(CKR_OPERATION_NOT_INITIALIZED);
        }
        self.finalized = true;

        self.sigctx.as_mut().unwrap().digest_sign_final(signature)
    }

    fn signature_len(&self) -> KResult<usize> {
        Ok(self.output_len)
    }
}

impl Verify for RsaPKCSOperation {
    fn verify(&mut self, data: &[u8], signature: &[u8]) -> KResult<()> {
        if self.in_use {
            return err_rv!(CKR_OPERATION_NOT_INITIALIZED);
        }
        if self.finalized {
            return err_rv!(CKR_OPERATION_NOT_INITIALIZED);
        }
        if self.mech == CKM_RSA_PKCS {
            self.finalized = true;
            if data.len() > self.max_input {
                return err_rv!(CKR_DATA_LEN_RANGE);
            }
            if signature.len() != self.output_len {
                return err_rv!(CKR_GENERAL_ERROR);
            }
            let mut ctx = EvpPkeyCtx::from_ptr(unsafe {
                EVP_PKEY_CTX_new_from_pkey(
                    get_libctx(),
                    self.public_key.as_mut_ptr(),
                    std::ptr::null_mut(),
                )
            })?;
            if unsafe { EVP_PKEY_verify_init(ctx.as_mut_ptr()) } != 1 {
                return err_rv!(CKR_DEVICE_ERROR);
            }
            let params = [
                unsafe {
                    OSSL_PARAM_construct_utf8_string(
                        OSSL_PKEY_PARAM_PAD_MODE.as_ptr() as *const i8,
                        OSSL_PKEY_RSA_PAD_MODE_PKCSV15.as_ptr() as *mut i8,
                        OSSL_PKEY_RSA_PAD_MODE_PKCSV15.len(),
                    )
                },
                unsafe { OSSL_PARAM_construct_end() },
            ];
            if unsafe {
                EVP_PKEY_CTX_set_params(ctx.as_mut_ptr(), params.as_ptr())
            } != 1
            {
                return err_rv!(CKR_DEVICE_ERROR);
            }

            self.finalized = true;

            let mut siglen = signature.len();
            let siglen_ptr: *mut usize = &mut siglen;
            if unsafe {
                EVP_PKEY_sign(
                    ctx.as_mut_ptr(),
                    signature.as_ptr() as *mut u8,
                    siglen_ptr,
                    data.as_ptr(),
                    data.len(),
                )
            } != 1
            {
                return err_rv!(CKR_DEVICE_ERROR);
            }
            return Ok(());
        }
        self.verify_update(data)?;
        self.verify_final(signature)
    }

    fn verify_update(&mut self, data: &[u8]) -> KResult<()> {
        if self.finalized {
            return err_rv!(CKR_OPERATION_NOT_INITIALIZED);
        }
        if !self.in_use {
            if self.mech == CKM_RSA_PKCS {
                return err_rv!(CKR_OPERATION_NOT_INITIALIZED);
            }
            self.in_use = true;

            let params = [
                unsafe {
                    OSSL_PARAM_construct_utf8_string(
                        OSSL_SIGNATURE_PARAM_PAD_MODE.as_ptr() as *const i8,
                        OSSL_PKEY_RSA_PAD_MODE_PKCSV15.as_ptr() as *mut i8,
                        OSSL_PKEY_RSA_PAD_MODE_PKCSV15.len(),
                    )
                },
                unsafe { OSSL_PARAM_construct_end() },
            ];
            self.sigctx.as_mut().unwrap().digest_verify_init(
                self.mdname.as_ptr(),
                &self.public_key,
                params.as_ptr(),
            )?;
        }

        self.sigctx.as_mut().unwrap().digest_verify_update(data)
    }

    fn verify_final(&mut self, signature: &[u8]) -> KResult<()> {
        if !self.in_use {
            return err_rv!(CKR_OPERATION_NOT_INITIALIZED);
        }
        if self.finalized {
            return err_rv!(CKR_OPERATION_NOT_INITIALIZED);
        }
        self.finalized = true;

        self.sigctx.as_mut().unwrap().digest_verify_final(signature)
    }

    fn signature_len(&self) -> KResult<usize> {
        Ok(self.output_len)
    }
}
