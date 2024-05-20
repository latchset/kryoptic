// Copyright 2023 Simo Sorce
// See LICENSE.txt file for terms

use constant_time_eq::constant_time_eq;
use zeroize::Zeroize;

/* HMAC spec From FIPS 198-1 */
#[derive(Debug)]
struct HMACOperation {
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
    fn init(
        hash: CK_MECHANISM_TYPE,
        key: HashKey,
        outputlen: usize,
    ) -> KResult<HMACOperation> {
        let mut hmac = HMACOperation {
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
        /* The hash mechanism is unimportant here,
         * what matters is the psecdef algorithm */
        let hashop = HashOperation::new(hash)?;
        hmac.hashlen = hashop.hashlen();
        hmac.blocklen = hashop.blocklen();
        hmac.inner = Operation::Digest(Box::new(hashop));

        /* K0 */
        if key.raw.len() <= hmac.blocklen {
            hmac.state.extend_from_slice(key.raw.as_slice());
        } else {
            hmac.state.resize(hmac.hashlen, 0);
            match &mut hmac.inner {
                Operation::Digest(op) => {
                    op.digest(key.raw.as_slice(), hmac.state.as_mut_slice())?
                }
                _ => return err_rv!(CKR_GENERAL_ERROR),
            }
        }
        hmac.state.resize(hmac.blocklen, 0);
        /* K0 ^ ipad */
        hmac.ipad.resize(hmac.blocklen, 0x36);
        hmac.ipad
            .iter_mut()
            .zip(hmac.state.iter())
            .for_each(|(i1, i2)| *i1 ^= *i2);
        /* K0 ^ opad */
        hmac.opad.resize(hmac.blocklen, 0x5c);
        hmac.opad
            .iter_mut()
            .zip(hmac.state.iter())
            .for_each(|(i1, i2)| *i1 ^= *i2);
        /* H((K0 ^ ipad) || .. ) */
        match &mut hmac.inner {
            Operation::Digest(op) => {
                op.reset()?;
                op.digest_update(hmac.ipad.as_slice())?;
            }
            _ => return err_rv!(CKR_GENERAL_ERROR),
        }
        Ok(hmac)
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

        /* H( .. || text ..) */
        let ret = match &mut self.inner {
            Operation::Digest(op) => op.digest_update(data),
            _ => err_rv!(CKR_GENERAL_ERROR),
        };
        if ret.is_err() {
            self.finalized = true;
        }
        ret
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

        self.state.resize(self.hashlen, 0);
        /* state = H((K0 ^ ipad) || text) */
        match &mut self.inner {
            Operation::Digest(op) => {
                op.digest_final(self.state.as_mut_slice())?;
            }
            _ => return err_rv!(CKR_GENERAL_ERROR),
        }
        /* state = H((K0 ^ opad) || H((K0 ^ ipad) || text)) */
        match &mut self.inner {
            Operation::Digest(op) => {
                op.reset()?;
                op.digest_update(self.opad.as_slice())?;
                op.digest_update(self.state.as_slice())?;
                op.digest_final(self.state.as_mut_slice())?;
            }
            _ => return err_rv!(CKR_GENERAL_ERROR),
        }
        /* state -> output */
        output.copy_from_slice(&self.state[..output.len()]);
        Ok(())
    }

    pub fn register_mechanisms(mechs: &mut Mechanisms) {
        for hs in &HASH_MECH_SET {
            /* skip HMACs for which we do not have valid Hashes */
            let hashop = match HashOperation::new(hs.hash) {
                Ok(op) => op,
                Err(_) => continue,
            };
            mechs.add_mechanism(
                hs.mac,
                Box::new(HMACMechanism {
                    info: CK_MECHANISM_INFO {
                        ulMinKeySize: 0,
                        ulMaxKeySize: 0,
                        flags: CKF_SIGN | CKF_VERIFY,
                    },
                    keytype: hs.key_type,
                    minlen: hs.hash_size,
                    maxlen: hs.hash_size,
                }),
            );
            mechs.add_mechanism(
                hs.mac_general,
                Box::new(HMACMechanism {
                    info: CK_MECHANISM_INFO {
                        ulMinKeySize: 0,
                        ulMaxKeySize: 0,
                        flags: CKF_SIGN | CKF_VERIFY,
                    },
                    keytype: hs.key_type,
                    minlen: 1,
                    maxlen: hs.hash_size,
                }),
            );
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
