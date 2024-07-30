// Copyright 2024 Simo Sorce
// See LICENSE.txt file for terms

use {super::fips, fips::*};

#[derive(Debug)]
struct HMACOperation {
    finalized: bool,
    in_use: bool,
    outputlen: usize,
    maclen: usize,
    key: HmacKey,
    ctx: EvpMacCtx,
}

impl HMACOperation {
    fn new(
        hash: CK_MECHANISM_TYPE,
        key: HmacKey,
        outputlen: usize,
    ) -> KResult<HMACOperation> {
        let mut ctx = EvpMacCtx::new(name_as_char(OSSL_MAC_NAME_HMAC))?;
        let params = OsslParam::new()
            .add_const_c_string(
                name_as_char(OSSL_MAC_PARAM_DIGEST),
                mech_type_to_digest_name(hash),
            )?
            .finalize();

        if unsafe {
            EVP_MAC_init(
                ctx.as_mut_ptr(),
                key.raw.as_ptr(),
                key.raw.len(),
                params.as_ptr(),
            )
        } != 1
        {
            return err_rv!(CKR_DEVICE_ERROR);
        }
        Ok(HMACOperation {
            finalized: false,
            in_use: false,
            outputlen: outputlen,
            maclen: unsafe { EVP_MAC_CTX_get_mac_size(ctx.as_mut_ptr()) },
            key: key,
            ctx: ctx,
        })
    }

    fn begin(&mut self) -> KResult<()> {
        if self.in_use {
            return err_rv!(CKR_OPERATION_NOT_INITIALIZED);
        }
        Ok(())
    }

    fn update(&mut self, data: &[u8]) -> KResult<()> {
        if self.finalized {
            return err_rv!(CKR_OPERATION_NOT_INITIALIZED);
        }
        self.in_use = true;

        if unsafe {
            EVP_MAC_update(self.ctx.as_mut_ptr(), data.as_ptr(), data.len())
        } != 1
        {
            return err_rv!(CKR_DEVICE_ERROR);
        }

        Ok(())
    }

    fn finalize(&mut self, output: &mut [u8]) -> KResult<()> {
        if self.finalized {
            return err_rv!(CKR_OPERATION_NOT_INITIALIZED);
        }
        /* It is valid to finalize without any update */
        self.in_use = true;
        self.finalized = true;

        if output.len() != self.outputlen {
            return err_rv!(CKR_GENERAL_ERROR);
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
            return err_rv!(CKR_DEVICE_ERROR);
        }
        if outlen != self.maclen {
            buf.zeroize();
            return err_rv!(CKR_GENERAL_ERROR);
        }

        output.copy_from_slice(&buf[..output.len()]);
        buf.zeroize();
        Ok(())
    }

    fn reinit(&mut self) -> KResult<()> {
        if unsafe {
            EVP_MAC_init(
                self.ctx.as_mut_ptr(),
                self.key.raw.as_ptr(),
                self.key.raw.len(),
                std::ptr::null_mut(),
            )
        } != 1
        {
            return err_rv!(CKR_DEVICE_ERROR);
        }
        self.finalized = false;
        self.in_use = false;
        Ok(())
    }
}
