// Copyright 2024 Simo Sorce
// See LICENSE.txt file for terms

use std::fmt::Debug;

use crate::error::Result;
use crate::hmac::*;
use crate::mechanism::{Mac, MechOperation, Sign, Verify, VerifySignature};
use crate::misc::zeromem;
use crate::ossl::common::osslctx;
use crate::pkcs11::*;

use constant_time_eq::constant_time_eq;
use ossl::mac::{MacAlg, OsslMac};
use ossl::OsslSecret;

use ossl::fips::FipsApproval;

fn hmac_mech_to_mac_alg(mech: CK_MECHANISM_TYPE) -> Result<MacAlg> {
    Ok(match mech {
        #[cfg(not(feature = "no_sha1"))]
        CKM_SHA_1_HMAC | CKM_SHA_1_HMAC_GENERAL => MacAlg::HmacSha1,
        CKM_SHA224_HMAC | CKM_SHA224_HMAC_GENERAL => MacAlg::HmacSha2_224,
        CKM_SHA256_HMAC | CKM_SHA256_HMAC_GENERAL => MacAlg::HmacSha2_256,
        CKM_SHA384_HMAC | CKM_SHA384_HMAC_GENERAL => MacAlg::HmacSha2_384,
        CKM_SHA512_HMAC | CKM_SHA512_HMAC_GENERAL => MacAlg::HmacSha2_512,
        CKM_SHA3_224_HMAC | CKM_SHA3_224_HMAC_GENERAL => MacAlg::HmacSha3_224,
        CKM_SHA3_256_HMAC | CKM_SHA3_256_HMAC_GENERAL => MacAlg::HmacSha3_256,
        CKM_SHA3_384_HMAC | CKM_SHA3_384_HMAC_GENERAL => MacAlg::HmacSha3_384,
        CKM_SHA3_512_HMAC | CKM_SHA3_512_HMAC_GENERAL => MacAlg::HmacSha3_512,
        CKM_SHA512_224_HMAC | CKM_SHA512_224_HMAC_GENERAL => {
            MacAlg::HmacSha2_512_224
        }
        CKM_SHA512_256_HMAC | CKM_SHA512_256_HMAC_GENERAL => {
            MacAlg::HmacSha2_512_256
        }
        _ => return Err(CKR_MECHANISM_INVALID)?,
    })
}

#[derive(Debug)]
pub struct HMACOperation {
    mech: CK_MECHANISM_TYPE,
    finalized: bool,
    in_use: bool,
    outputlen: usize,
    ctx: OsslMac,
    #[cfg(feature = "fips")]
    fips_approval: FipsApproval,
    signature: Option<Vec<u8>>,
}

impl HMACOperation {
    pub fn new(
        mech: CK_MECHANISM_TYPE,
        mut key: HmacKey,
        outputlen: usize,
        signature: Option<&[u8]>,
    ) -> Result<HMACOperation> {
        #[cfg(feature = "fips")]
        let mut fips_approval = FipsApproval::init();

        let secret = OsslSecret::from_vec(key.take());

        let ctx = OsslMac::new(osslctx(), hmac_mech_to_mac_alg(mech)?, secret)?;

        #[cfg(feature = "fips")]
        fips_approval.update();

        Ok(HMACOperation {
            mech: mech,
            finalized: false,
            in_use: false,
            outputlen: outputlen,
            ctx: ctx,
            #[cfg(feature = "fips")]
            fips_approval: fips_approval,
            signature: match signature {
                Some(s) => {
                    if s.len() != outputlen {
                        return Err(CKR_SIGNATURE_LEN_RANGE)?;
                    }
                    Some(s.to_vec())
                }
                None => None,
            },
        })
    }

    pub fn restore(
        _mech: CK_MECHANISM_TYPE,
        _key: HmacKey,
        _signature: Option<&[u8]>,
        _state: &[u8],
    ) -> Result<HMACOperation> {
        Err(CKR_SAVED_STATE_INVALID)?
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

        #[cfg(feature = "fips")]
        self.fips_approval.clear();

        let ret = self.ctx.update(data);

        #[cfg(feature = "fips")]
        self.fips_approval.update();

        Ok(ret?)
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

        #[cfg(feature = "fips")]
        self.fips_approval.clear();

        let mut buf = vec![0u8; self.ctx.size()];
        let outlen = self.ctx.finalize(&mut buf)?;

        if outlen != self.ctx.size() {
            zeromem(buf.as_mut_slice());
            return Err(CKR_GENERAL_ERROR)?;
        }

        output.copy_from_slice(&buf[..output.len()]);
        zeromem(buf.as_mut_slice());

        /*
         * The OpenSSL implementation verifies the truncation is > 112b
         * according to the FIPS 140-3 IG, C.D Use of a Truncated HMAC
         */
        #[cfg(feature = "fips")]
        self.fips_approval.finalize();

        Ok(())
    }

    fn reinit(&mut self) -> Result<()> {
        #[cfg(feature = "fips")]
        self.fips_approval.reset();

        self.ctx.reinit()?;

        #[cfg(feature = "fips")]
        self.fips_approval.update();

        self.finalized = false;
        self.in_use = false;
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
        self.fips_approval.approval()
    }
    fn state_size(&self) -> Result<usize> {
        Err(CKR_STATE_UNSAVEABLE)?
    }
    fn state_save(&self, _state: &mut [u8]) -> Result<usize> {
        Err(CKR_STATE_UNSAVEABLE)?
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
        Verify::verify_final(self, signature)
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

impl VerifySignature for HMACOperation {
    fn verify(&mut self, data: &[u8]) -> Result<()> {
        self.begin()?;
        self.update(data)?;
        VerifySignature::verify_final(self)
    }

    fn verify_update(&mut self, data: &[u8]) -> Result<()> {
        self.update(data)
    }

    fn verify_final(&mut self) -> Result<()> {
        let mut verify: Vec<u8> = vec![0; self.outputlen];
        self.finalize(verify.as_mut_slice())?;
        match &self.signature {
            Some(sig) => {
                if !constant_time_eq(&verify, sig.as_slice()) {
                    return Err(CKR_SIGNATURE_INVALID)?;
                }
                Ok(())
            }
            None => Err(CKR_GENERAL_ERROR)?,
        }
    }
}
