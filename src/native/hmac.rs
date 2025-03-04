// Copyright 2024 Simo Sorce
// See LICENSE.txt file for terms

use std::fmt::Debug;

use crate::error::Result;
use crate::hash;
use crate::hmac::*;
use crate::interface::*;
use crate::mechanism::*;
use crate::misc::zeromem;

use constant_time_eq::constant_time_eq;

/* max algo right now is SHA3_224 with 144 bytes blocksize,
 * use slightly larger for good measure (and alignment) */
const MAX_BSZ: usize = 160;
const IPAD_INIT: [u8; MAX_BSZ] = [0x36; MAX_BSZ];
const OPAD_INIT: [u8; MAX_BSZ] = [0x5c; MAX_BSZ];

/* HMAC spec From FIPS 198-1 */

#[derive(Debug)]
pub struct HMACOperation {
    mech: CK_MECHANISM_TYPE,
    key: HmacKey,
    hashlen: usize,
    blocklen: usize,
    outputlen: usize,
    state: [u8; MAX_BSZ],
    ipad: [u8; MAX_BSZ],
    opad: [u8; MAX_BSZ],
    inner: Box<dyn Digest>,
    finalized: bool,
    in_use: bool,
}

impl Drop for HMACOperation {
    fn drop(&mut self) {
        zeromem(&mut self.state);
        zeromem(&mut self.ipad);
        zeromem(&mut self.opad);
    }
}

impl HMACOperation {
    pub fn new(
        mech: CK_MECHANISM_TYPE,
        key: HmacKey,
        outputlen: usize,
    ) -> Result<HMACOperation> {
        let hash = hmac_mech_to_hash_mech(mech)?;
        let hashlen = hash::hash_size(hash);
        let blocklen = hash::block_size(hash);
        let op = hash::internal_hash_op(hash)?;
        let mut hmac = HMACOperation {
            mech: mech,
            key: key,
            hashlen: hashlen,
            blocklen: blocklen,
            outputlen: outputlen,
            state: [0u8; MAX_BSZ],
            ipad: IPAD_INIT,
            opad: OPAD_INIT,
            inner: op,
            finalized: false,
            in_use: false,
        };
        hmac.init()?;
        Ok(hmac)
    }

    fn init(&mut self) -> Result<()> {
        /* K0 */
        if self.key.raw.len() <= self.blocklen {
            self.state[0..self.key.raw.len()]
                .copy_from_slice(self.key.raw.as_slice());
        } else {
            self.inner.digest(
                self.key.raw.as_slice(),
                &mut self.state[..self.hashlen],
            )?;
        }
        let ipad = &mut self.ipad[..self.blocklen];
        let opad = &mut self.opad[..self.blocklen];
        let state = &self.state[..self.blocklen];
        for i in 0..self.blocklen {
            /* K0 ^ ipad */
            ipad[i] ^= state[i];
            /* K0 ^ opad */
            opad[i] ^= state[i];
        }
        /* H((K0 ^ ipad) || .. ) */
        self.inner.reset()?;
        self.inner.digest_update(ipad)?;

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
        let ret = self.inner.digest_update(data);
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

        /* state = H((K0 ^ ipad) || text) */
        self.inner.digest_final(&mut self.state[..self.hashlen])?;

        /* state = H((K0 ^ opad) || H((K0 ^ ipad) || text)) */
        self.inner.reset()?;
        self.inner.digest_update(&self.opad[..self.blocklen])?;
        self.inner.digest_update(&self.state[..self.hashlen])?;
        self.inner.digest_final(&mut self.state[..self.hashlen])?;

        /* state -> output */
        output.copy_from_slice(&self.state[..output.len()]);
        Ok(())
    }

    fn reinit(&mut self) -> Result<()> {
        zeromem(&mut self.state);
        self.ipad.copy_from_slice(&IPAD_INIT);
        self.opad.copy_from_slice(&OPAD_INIT);
        self.inner.reset()?;
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
