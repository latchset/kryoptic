// Copyright 2024 Simo Sorce
// See LICENSE.txt file for terms

//! This module implements the Keyed-Hash Message Authentication Code (HMAC)
//! operation defined in [FIPS 198-1](https://doi.org/10.6028/NIST.FIPS.198-1)

use std::fmt::Debug;

use crate::error::Result;
use crate::hash;
use crate::hmac::*;
use crate::mechanism::*;
use crate::misc::zeromem;
use crate::pkcs11::*;

use constant_time_eq::constant_time_eq;

/// Maximum size for internal buffers
///
/// Currently the algorithm with the largest block size is SHA3_224 with
/// a blocksize of 144 bytes, we use slightly larger maximum for good
/// measure (and memory alignment) */
const MAX_BSZ: usize = 160;
/// Initial value for the ipad buffer
const IPAD_INIT: [u8; MAX_BSZ] = [0x36; MAX_BSZ];
/// Initial value for the opad buffer
const OPAD_INIT: [u8; MAX_BSZ] = [0x5c; MAX_BSZ];

/// Returns the underlying hash mechanism type from the HMAC mechanism type
fn hmac_mech_to_hash_mech(
    mech: CK_MECHANISM_TYPE,
) -> Result<CK_MECHANISM_TYPE> {
    Ok(match mech {
        CKM_SHA_1_HMAC | CKM_SHA_1_HMAC_GENERAL => CKM_SHA_1,
        CKM_SHA224_HMAC | CKM_SHA224_HMAC_GENERAL => CKM_SHA224,
        CKM_SHA256_HMAC | CKM_SHA256_HMAC_GENERAL => CKM_SHA256,
        CKM_SHA384_HMAC | CKM_SHA384_HMAC_GENERAL => CKM_SHA384,
        CKM_SHA512_HMAC | CKM_SHA512_HMAC_GENERAL => CKM_SHA512,
        CKM_SHA3_224_HMAC | CKM_SHA3_224_HMAC_GENERAL => CKM_SHA3_224,
        CKM_SHA3_256_HMAC | CKM_SHA3_256_HMAC_GENERAL => CKM_SHA3_256,
        CKM_SHA3_384_HMAC | CKM_SHA3_384_HMAC_GENERAL => CKM_SHA3_384,
        CKM_SHA3_512_HMAC | CKM_SHA3_512_HMAC_GENERAL => CKM_SHA3_512,
        CKM_SHA512_224_HMAC | CKM_SHA512_224_HMAC_GENERAL => CKM_SHA512_224,
        CKM_SHA512_256_HMAC | CKM_SHA512_256_HMAC_GENERAL => CKM_SHA512_256,
        _ => return Err(CKR_MECHANISM_INVALID)?,
    })
}

/// Object that represents the HMAC operation
#[derive(Debug)]
pub struct HMACOperation {
    /// The Specific HMAC mechanism
    mech: CK_MECHANISM_TYPE,
    /// The raw key to be used in the HMAC operation
    key: Vec<u8>,
    /// The associated Hash output size
    hashlen: usize,
    /// The associated Hash internal block size
    blocklen: usize,
    /// The request HMAC output length
    outputlen: usize,
    /// Internal state buffer
    state: [u8; MAX_BSZ],
    /// Inner pad buffer
    ipad: [u8; MAX_BSZ],
    /// Outer pad buffer
    opad: [u8; MAX_BSZ],
    /// The digest 'inner' operation
    inner: Box<dyn Digest>,
    /// Flag that marks the operation as finalized
    finalized: bool,
    /// Flag that marks that the operation has started
    in_use: bool,
    /// Optional signature holding vector
    ///
    /// This is used by the VerifySignature API
    #[allow(dead_code)]
    signature: Option<Vec<u8>>,
}

impl Drop for HMACOperation {
    fn drop(&mut self) {
        zeromem(self.key.as_mut_slice());
        zeromem(&mut self.state);
        zeromem(&mut self.ipad);
        zeromem(&mut self.opad);
    }
}

impl HMACOperation {
    /// Instantiates a new HMAC operation
    pub fn new(
        mech: CK_MECHANISM_TYPE,
        mut key: HmacKey,
        outputlen: usize,
        signature: Option<&[u8]>,
    ) -> Result<HMACOperation> {
        let hash = hmac_mech_to_hash_mech(mech)?;
        let hashlen = hash::hash_size(hash);
        let blocklen = hash::block_size(hash);
        let op = hash::internal_hash_op(hash)?;
        let mut hmac = HMACOperation {
            mech: mech,
            key: key.take(),
            hashlen: hashlen,
            blocklen: blocklen,
            outputlen: outputlen,
            state: [0u8; MAX_BSZ],
            ipad: IPAD_INIT,
            opad: OPAD_INIT,
            inner: op,
            finalized: false,
            in_use: false,
            signature: match signature {
                Some(s) => {
                    if s.len() != outputlen {
                        return Err(CKR_SIGNATURE_LEN_RANGE)?;
                    }
                    Some(s.to_vec())
                }
                None => None,
            },
        };
        hmac.init()?;
        Ok(hmac)
    }

    /// Internal initialization function
    ///
    /// Performs the initial step of the HMAC algorithm
    ///
    /// Called by [Self::new()] and [Self::reinit()]
    fn init(&mut self) -> Result<()> {
        /* K0 */
        if self.key.len() <= self.blocklen {
            self.state[0..self.key.len()].copy_from_slice(self.key.as_slice());
        } else {
            self.inner
                .digest(self.key.as_slice(), &mut self.state[..self.hashlen])?;
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

    /// Marks that the operation has commenced
    fn begin(&mut self) -> Result<()> {
        if self.in_use {
            return Err(CKR_OPERATION_NOT_INITIALIZED)?;
        }
        Ok(())
    }

    /// Feeds data into the HMAC algorithm
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

    /// Finalizes the HMAC operation and produces the HMAC output
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

    /// Reinitializes an HMAC Operation
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
