// Copyright 2024 Simo Sorce
// See LICENSE.txt file for terms

use std::fmt::Debug;

use crate::error::Result;
use crate::hmac::*;
use crate::interface::*;
use crate::mechanism::*;
use crate::misc::zeromem;
use crate::ossl::bindings::*;
use crate::ossl::common::*;
use crate::ossl::fips::*;

use constant_time_eq::constant_time_eq;

#[derive(Debug)]
pub struct HMACOperation {
    mech: CK_MECHANISM_TYPE,
    finalized: bool,
    in_use: bool,
    outputlen: usize,
    maclen: usize,
    key: HmacKey,
    ctx: EvpMacCtx,
    fips_approved: Option<bool>,
}

impl HMACOperation {
    pub fn new(
        mech: CK_MECHANISM_TYPE,
        key: HmacKey,
        outputlen: usize,
    ) -> Result<HMACOperation> {
        let mut ctx = EvpMacCtx::new(name_as_char(OSSL_MAC_NAME_HMAC))?;
        let hash = hmac_mech_to_hash_mech(mech)?;
        let mut params = OsslParam::with_capacity(1);
        params.add_const_c_string(
            name_as_char(OSSL_MAC_PARAM_DIGEST),
            mech_type_to_digest_name(hash),
        )?;
        params.finalize();

        if unsafe {
            EVP_MAC_init(
                ctx.as_mut_ptr(),
                key.raw.as_ptr(),
                key.raw.len(),
                params.as_ptr(),
            )
        } != 1
        {
            return Err(CKR_DEVICE_ERROR)?;
        }
        Ok(HMACOperation {
            mech: mech,
            finalized: false,
            in_use: false,
            outputlen: outputlen,
            maclen: unsafe { EVP_MAC_CTX_get_mac_size(ctx.as_mut_ptr()) },
            key: key,
            ctx: ctx,
            fips_approved: None,
        })
    }

    fn begin(&mut self) -> Result<()> {
        if self.in_use {
            return Err(CKR_OPERATION_NOT_INITIALIZED)?;
        }
        Ok(())
    }

    fn update(&mut self, data: &[u8]) -> Result<()> {
        if self.finalized {
            return Err(CKR_OPERATION_NOT_INITIALIZED)?;
        }
        self.in_use = true;

        if unsafe {
            EVP_MAC_update(self.ctx.as_mut_ptr(), data.as_ptr(), data.len())
        } != 1
        {
            return Err(CKR_DEVICE_ERROR)?;
        }

        Ok(())
    }

    fn finalize(&mut self, output: &mut [u8]) -> Result<()> {
        if self.finalized {
            return Err(CKR_OPERATION_NOT_INITIALIZED)?;
        }
        /* It is valid to finalize without any update */
        self.in_use = true;
        self.finalized = true;

        if output.len() != self.outputlen {
            return Err(CKR_GENERAL_ERROR)?;
        }

        let mut buf = vec![0u8; self.maclen];
        let mut outlen: usize = 0;
        if unsafe {
            EVP_MAC_final(
                self.ctx.as_mut_ptr(),
                buf.as_mut_ptr(),
                &mut outlen,
                buf.len(),
            )
        } != 1
        {
            return Err(CKR_DEVICE_ERROR)?;
        }
        if outlen != self.maclen {
            zeromem(buf.as_mut_slice());
            return Err(CKR_GENERAL_ERROR)?;
        }

        output.copy_from_slice(&buf[..output.len()]);
        zeromem(buf.as_mut_slice());

        self.fips_approved = check_mac_fips_indicators(&mut self.ctx)?;
        Ok(())
    }

    fn reinit(&mut self) -> Result<()> {
        if unsafe {
            EVP_MAC_init(
                self.ctx.as_mut_ptr(),
                self.key.raw.as_ptr(),
                self.key.raw.len(),
                std::ptr::null_mut(),
            )
        } != 1
        {
            return Err(CKR_DEVICE_ERROR)?;
        }
        self.finalized = false;
        self.in_use = false;
        self.fips_approved = None;
        Ok(())
    }
}

impl MechOperation for HMACOperation {
    fn mechanism(&self) -> Result<CK_MECHANISM_TYPE> {
        Ok(self.mech)
    }

    fn finalized(&self) -> bool {
        self.finalized
    }
    fn reset(&mut self) -> Result<()> {
        self.reinit()
    }
    fn fips_approved(&self) -> Option<bool> {
        self.fips_approved
    }
}

impl Mac for HMACOperation {
    fn mac(&mut self, data: &[u8], mac: &mut [u8]) -> Result<()> {
        self.begin()?;
        self.update(data)?;
        self.finalize(mac)
    }

    fn mac_update(&mut self, data: &[u8]) -> Result<()> {
        self.update(data)
    }

    fn mac_final(&mut self, mac: &mut [u8]) -> Result<()> {
        self.finalize(mac)
    }

    fn mac_len(&self) -> Result<usize> {
        Ok(self.outputlen)
    }
}

impl Sign for HMACOperation {
    fn sign(&mut self, data: &[u8], signature: &mut [u8]) -> Result<()> {
        self.begin()?;
        self.update(data)?;
        self.finalize(signature)
    }

    fn sign_update(&mut self, data: &[u8]) -> Result<()> {
        self.update(data)
    }

    fn sign_final(&mut self, signature: &mut [u8]) -> Result<()> {
        self.finalize(signature)
    }

    fn signature_len(&self) -> Result<usize> {
        Ok(self.outputlen)
    }
}

impl Verify for HMACOperation {
    fn verify(&mut self, data: &[u8], signature: &[u8]) -> Result<()> {
        self.begin()?;
        self.update(data)?;
        self.verify_final(signature)
    }

    fn verify_update(&mut self, data: &[u8]) -> Result<()> {
        self.update(data)
    }

    fn verify_final(&mut self, signature: &[u8]) -> Result<()> {
        let mut verify: Vec<u8> = vec![0; self.outputlen];
        self.finalize(verify.as_mut_slice())?;
        if !constant_time_eq(&verify, signature) {
            return Err(CKR_SIGNATURE_INVALID)?;
        }
        Ok(())
    }

    fn signature_len(&self) -> Result<usize> {
        Ok(self.outputlen)
    }
}
