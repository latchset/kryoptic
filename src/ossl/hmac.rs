// Copyright 2024 Simo Sorce
// See LICENSE.txt file for terms

use constant_time_eq::constant_time_eq;
use zeroize::Zeroize;

#[derive(Debug)]
struct HMACOperation {
    finalized: bool,
    in_use: bool,
    outputlen: usize,
    maclen: usize,
    _key: HashKey,
    _mac: EvpMac,
    ctx: EvpMacCtx,
}

impl HMACOperation {
    fn init(
        hash: CK_MECHANISM_TYPE,
        key: HashKey,
        outputlen: usize,
    ) -> KResult<HMACOperation> {
        let mut mac = match EvpMac::from_ptr(unsafe {
            EVP_MAC_fetch(
                get_libctx(),
                name_as_char(OSSL_MAC_NAME_HMAC),
                std::ptr::null(),
            )
        }) {
            Ok(em) => em,
            Err(_) => return err_rv!(CKR_DEVICE_ERROR),
        };
        let mut ctx = match EvpMacCtx::from_ptr(unsafe {
            EVP_MAC_CTX_new(mac.as_mut_ptr())
        }) {
            Ok(emc) => emc,
            Err(_) => return err_rv!(CKR_DEVICE_ERROR),
        };
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
            _key: key,
            _mac: mac,
            ctx: ctx,
        })
    }

    pub fn new_mechanism(
        hs: &HashBasedOp,
        minlen: usize,
    ) -> Box<dyn Mechanism> {
        Box::new(HMACMechanism {
            info: CK_MECHANISM_INFO {
                ulMinKeySize: 0,
                ulMaxKeySize: 0,
                flags: CKF_SIGN | CKF_VERIFY,
            },
            keytype: hs.key_type,
            minlen: minlen,
            maxlen: hs.hash_size,
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
    pub fn register_mechanisms(mechs: &mut Mechanisms) {
        for hs in &HASH_MECH_SET {
            mechs.add_mechanism(hs.mac, Self::new_mechanism(hs, hs.hash_size));
            mechs.add_mechanism(hs.mac_general, Self::new_mechanism(hs, 1));
        }
    }
}

impl MechOperation for HMACOperation {
    fn finalized(&self) -> bool {
        self.finalized
    }
}

impl Mac for HMACOperation {
    fn mac(&mut self, data: &[u8], mac: &mut [u8]) -> KResult<()> {
        self.begin()?;
        self.update(data)?;
        self.finalize(mac)
    }

    fn mac_update(&mut self, data: &[u8]) -> KResult<()> {
        self.update(data)
    }

    fn mac_final(&mut self, mac: &mut [u8]) -> KResult<()> {
        self.finalize(mac)
    }

    fn mac_len(&self) -> KResult<usize> {
        Ok(self.outputlen)
    }
}

impl Sign for HMACOperation {
    fn sign(&mut self, data: &[u8], signature: &mut [u8]) -> KResult<()> {
        self.begin()?;
        self.update(data)?;
        self.finalize(signature)
    }

    fn sign_update(&mut self, data: &[u8]) -> KResult<()> {
        self.update(data)
    }

    fn sign_final(&mut self, signature: &mut [u8]) -> KResult<()> {
        self.finalize(signature)
    }

    fn signature_len(&self) -> KResult<usize> {
        Ok(self.outputlen)
    }
}

impl Verify for HMACOperation {
    fn verify(&mut self, data: &[u8], signature: &[u8]) -> KResult<()> {
        self.begin()?;
        self.update(data)?;
        self.verify_final(signature)
    }

    fn verify_update(&mut self, data: &[u8]) -> KResult<()> {
        self.update(data)
    }

    fn verify_final(&mut self, signature: &[u8]) -> KResult<()> {
        let mut verify: Vec<u8> = vec![0; self.outputlen];
        self.finalize(verify.as_mut_slice())?;
        if !constant_time_eq(&verify, signature) {
            return err_rv!(CKR_SIGNATURE_INVALID);
        }
        Ok(())
    }

    fn signature_len(&self) -> KResult<usize> {
        Ok(self.outputlen)
    }
}
