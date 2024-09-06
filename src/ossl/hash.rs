#[cfg(feature = "fips")]
use {super::fips, fips::*};

#[cfg(not(feature = "fips"))]
use {super::ossl, ossl::*};

use std::os::raw::*;

#[derive(Debug)]
pub struct HashState {
    md: EvpMd,
    ctx: EvpMdCtx,
}

impl HashState {
    pub fn new(alg: &[u8]) -> Result<HashState> {
        Ok(HashState {
            md: EvpMd::new(alg.as_ptr() as *const c_char)?,
            ctx: EvpMdCtx::new()?,
        })
    }
}

unsafe impl Send for HashState {}
unsafe impl Sync for HashState {}

impl HashOperation {
    pub fn new(mech: CK_MECHANISM_TYPE) -> Result<HashOperation> {
        let alg: &[u8] = match mech {
            CKM_SHA_1 => OSSL_DIGEST_NAME_SHA1,
            CKM_SHA224 => OSSL_DIGEST_NAME_SHA2_224,
            CKM_SHA256 => OSSL_DIGEST_NAME_SHA2_256,
            CKM_SHA384 => OSSL_DIGEST_NAME_SHA2_384,
            CKM_SHA512 => OSSL_DIGEST_NAME_SHA2_512,
            CKM_SHA3_224 => OSSL_DIGEST_NAME_SHA3_224,
            CKM_SHA3_256 => OSSL_DIGEST_NAME_SHA3_256,
            CKM_SHA3_384 => OSSL_DIGEST_NAME_SHA3_384,
            CKM_SHA3_512 => OSSL_DIGEST_NAME_SHA3_512,
            _ => return err_rv!(CKR_MECHANISM_INVALID),
        };
        Ok(HashOperation {
            mech: mech,
            state: HashState::new(alg)?,
            finalized: false,
            in_use: false,
        })
    }
    fn digest_init(&mut self) -> Result<()> {
        unsafe {
            match EVP_DigestInit(
                self.state.ctx.as_mut_ptr(),
                self.state.md.as_ptr(),
            ) {
                1 => Ok(()),
                _ => err_rv!(CKR_DEVICE_ERROR),
            }
        }
    }
}

impl MechOperation for HashOperation {
    fn mechanism(&self) -> Result<CK_MECHANISM_TYPE> {
        Ok(self.mech)
    }

    fn finalized(&self) -> bool {
        self.finalized
    }
    fn reset(&mut self) -> Result<()> {
        self.finalized = false;
        self.in_use = false;
        Ok(())
    }
}

impl Digest for HashOperation {
    fn digest(&mut self, data: &[u8], digest: &mut [u8]) -> Result<()> {
        if self.in_use || self.finalized {
            return err_rv!(CKR_OPERATION_NOT_INITIALIZED);
        }
        if digest.len() != self.digest_len()? {
            return err_rv!(CKR_GENERAL_ERROR);
        }
        self.finalized = true;
        /* NOTE: It is ok if data and digest point to the same buffer*/
        let mut digest_len = c_uint::try_from(self.digest_len()?)?;
        let r = unsafe {
            EVP_Digest(
                data.as_ptr() as *const c_void,
                data.len(),
                digest.as_mut_ptr(),
                &mut digest_len,
                self.state.md.as_ptr(),
                std::ptr::null_mut(),
            )
        };
        if r != 1 || usize::try_from(digest_len)? != digest.len() {
            return err_rv!(CKR_GENERAL_ERROR);
        }
        Ok(())
    }

    fn digest_update(&mut self, data: &[u8]) -> Result<()> {
        if self.finalized {
            return err_rv!(CKR_OPERATION_NOT_INITIALIZED);
        }
        if !self.in_use {
            self.digest_init()?;
            self.in_use = true;
        }
        let r = unsafe {
            EVP_DigestUpdate(
                self.state.ctx.as_mut_ptr(),
                data.as_ptr() as *const c_void,
                data.len(),
            )
        };
        match r {
            1 => Ok(()),
            _ => {
                self.finalized = true;
                err_rv!(CKR_DEVICE_ERROR)
            }
        }
    }

    fn digest_final(&mut self, digest: &mut [u8]) -> Result<()> {
        if !self.in_use {
            return err_rv!(CKR_OPERATION_NOT_INITIALIZED);
        }
        if self.finalized {
            return err_rv!(CKR_OPERATION_NOT_INITIALIZED);
        }
        if digest.len() != self.digest_len()? {
            return err_rv!(CKR_GENERAL_ERROR);
        }
        self.finalized = true;
        let mut digest_len = c_uint::try_from(self.digest_len()?)?;
        let r = unsafe {
            EVP_DigestFinal_ex(
                self.state.ctx.as_mut_ptr(),
                digest.as_mut_ptr(),
                &mut digest_len,
            )
        };
        if r != 1 || usize::try_from(digest_len)? != digest.len() {
            return err_rv!(CKR_GENERAL_ERROR);
        }
        Ok(())
    }

    fn digest_len(&self) -> Result<usize> {
        let len = unsafe { EVP_MD_get_size(self.state.md.as_ptr()) };
        Ok(usize::try_from(len)?)
    }
}
