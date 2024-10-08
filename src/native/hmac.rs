// Copyright 2024 Simo Sorce
// See LICENSE.txt file for terms

use std::fmt::Debug;

use crate::error::Result;
use crate::hash;
use crate::hmac::*;
use crate::interface::*;
use crate::mechanism::*;

use constant_time_eq::constant_time_eq;
use zeroize::Zeroize;

/* HMAC spec From FIPS 198-1 */

#[derive(Debug)]
pub struct HMACOperation {
    mech: CK_MECHANISM_TYPE,
    key: HmacKey,
    hash: CK_MECHANISM_TYPE,
    hashlen: usize,
    blocklen: usize,
    outputlen: usize,
    state: Vec<u8>,
    ipad: Vec<u8>,
    opad: Vec<u8>,
    inner: Operation,
    finalized: bool,
    in_use: bool,
}

impl Drop for HMACOperation {
    fn drop(&mut self) {
        self.state.zeroize();
        self.ipad.zeroize();
        self.opad.zeroize();
    }
}

impl HMACOperation {
    pub fn new(
        mech: CK_MECHANISM_TYPE,
        key: HmacKey,
        outputlen: usize,
    ) -> Result<HMACOperation> {
        let mut hmac = HMACOperation {
            mech: mech,
            key: key,
            hash: hmac_mech_to_hash_mech(mech)?,
            hashlen: 0usize,
            blocklen: 0usize,
            outputlen: outputlen,
            state: Vec::new(),
            ipad: Vec::new(),
            opad: Vec::new(),
            inner: Operation::Empty,
            finalized: false,
            in_use: false,
        };
        hmac.init()?;
        Ok(hmac)
    }

    fn init(&mut self) -> Result<()> {
        /* The hash mechanism is unimportant here,
         * what matters is the psecdef algorithm */
        let hashop = hash::internal_hash_op(self.hash)?;
        self.hashlen = hash::hash_size(self.hash);
        self.blocklen = hash::block_size(self.hash);
        self.inner = Operation::Digest(hashop);

        /* K0 */
        if self.key.raw.len() <= self.blocklen {
            self.state.extend_from_slice(self.key.raw.as_slice());
        } else {
            self.state.resize(self.hashlen, 0);
            match &mut self.inner {
                Operation::Digest(op) => op.digest(
                    self.key.raw.as_slice(),
                    self.state.as_mut_slice(),
                )?,
                _ => return Err(CKR_GENERAL_ERROR)?,
            }
        }
        self.state.resize(self.blocklen, 0);
        /* K0 ^ ipad */
        self.ipad.resize(self.blocklen, 0x36);
        self.ipad
            .iter_mut()
            .zip(self.state.iter())
            .for_each(|(i1, i2)| *i1 ^= *i2);
        /* K0 ^ opad */
        self.opad.resize(self.blocklen, 0x5c);
        self.opad
            .iter_mut()
            .zip(self.state.iter())
            .for_each(|(i1, i2)| *i1 ^= *i2);
        /* H((K0 ^ ipad) || .. ) */
        match &mut self.inner {
            Operation::Digest(op) => {
                op.reset()?;
                op.digest_update(self.ipad.as_slice())?;
            }
            _ => return Err(CKR_GENERAL_ERROR)?,
        }
        Ok(())
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

        /* H( .. || text ..) */
        let ret = match &mut self.inner {
            Operation::Digest(op) => op.digest_update(data),
            _ => Err(CKR_GENERAL_ERROR)?,
        };
        if ret.is_err() {
            self.finalized = true;
        }
        ret
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

        self.state.resize(self.hashlen, 0);
        /* state = H((K0 ^ ipad) || text) */
        match &mut self.inner {
            Operation::Digest(op) => {
                op.digest_final(self.state.as_mut_slice())?;
            }
            _ => return Err(CKR_GENERAL_ERROR)?,
        }
        /* state = H((K0 ^ opad) || H((K0 ^ ipad) || text)) */
        match &mut self.inner {
            Operation::Digest(op) => {
                op.reset()?;
                op.digest_update(self.opad.as_slice())?;
                op.digest_update(self.state.as_slice())?;
                op.digest_final(self.state.as_mut_slice())?;
            }
            _ => return Err(CKR_GENERAL_ERROR)?,
        }
        /* state -> output */
        output.copy_from_slice(&self.state[..output.len()]);
        Ok(())
    }

    fn reinit(&mut self) -> Result<()> {
        self.hashlen = 0;
        self.blocklen = 0;
        self.state = Vec::new();
        self.ipad = Vec::new();
        self.opad = Vec::new();
        self.inner = Operation::Empty;
        self.finalized = false;
        self.in_use = false;
        self.init()
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
    #[cfg(feature = "fips")]
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
