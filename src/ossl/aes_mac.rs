// Copyright 2024 Simo Sorce
// See LICENSE.txt file for terms

use super::{byte_ptr, void_ptr};

#[derive(Debug)]
struct AesMacOperation {
    finalized: bool,
    in_use: bool,
    padbuf: [u8; AES_BLOCK_SIZE],
    padlen: usize,
    macbuf: [u8; AES_BLOCK_SIZE],
    maclen: usize,
    op: AesOperation,
}

impl Drop for AesMacOperation {
    fn drop(&mut self) {
        self.padbuf.zeroize();
        self.macbuf.zeroize();
    }
}

impl AesMacOperation {
    fn register_mechanisms(mechs: &mut Mechanisms) {
        for ckm in &[CKM_AES_MAC, CKM_AES_MAC_GENERAL] {
            mechs.add_mechanism(*ckm, new_mechanism(CKF_SIGN | CKF_VERIFY));
        }
    }

    fn init(mech: &CK_MECHANISM, key: &Object) -> KResult<AesMacOperation> {
        let maclen = match mech.mechanism {
            CKM_AES_MAC_GENERAL => {
                if mech.ulParameterLen as usize
                    != ::std::mem::size_of::<CK_MAC_GENERAL_PARAMS>()
                {
                    return err_rv!(CKR_ARGUMENTS_BAD);
                }
                let val: usize =
                    unsafe { *(mech.pParameter as CK_MAC_GENERAL_PARAMS_PTR) }
                        as usize;
                if val > AES_BLOCK_SIZE {
                    return err_rv!(CKR_MECHANISM_PARAM_INVALID);
                }
                val
            }
            CKM_AES_MAC => {
                if mech.ulParameterLen != 0 {
                    return err_rv!(CKR_ARGUMENTS_BAD);
                }
                AES_BLOCK_SIZE / 2
            }
            _ => return err_rv!(CKR_MECHANISM_INVALID),
        };
        let iv = [0u8; AES_BLOCK_SIZE];
        Ok(AesMacOperation {
            finalized: false,
            in_use: false,
            padbuf: [0; AES_BLOCK_SIZE],
            padlen: 0,
            macbuf: [0; AES_BLOCK_SIZE],
            maclen: maclen,
            op: AesOperation::encrypt_new(
                &CK_MECHANISM {
                    mechanism: CKM_AES_CBC,
                    pParameter: void_ptr!(iv.as_ptr()),
                    ulParameterLen: iv.len() as CK_ULONG,
                },
                key,
            )?,
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

        let mut data_len = self.padlen + data.len();
        let mut cursor = 0;
        let mut outlen: CK_ULONG = AES_BLOCK_SIZE as CK_ULONG;

        if data_len < AES_BLOCK_SIZE {
            self.padbuf[self.padlen..data_len].copy_from_slice(data);
            self.padlen = data_len;
            return Ok(());
        }
        if self.padlen > 0 {
            /* first full block */
            cursor = AES_BLOCK_SIZE - self.padlen;
            self.padbuf[self.padlen..].copy_from_slice(&data[..cursor]);
            if !self
                .op
                .encrypt_update(
                    &self.padbuf,
                    byte_ptr!(self.macbuf.as_ptr()),
                    &mut outlen,
                )
                .is_ok()
                || outlen != AES_BLOCK_SIZE as CK_ULONG
            {
                self.finalized = true;
                return err_rv!(CKR_GENERAL_ERROR);
            }
            data_len -= AES_BLOCK_SIZE;
        }

        /* whole blocks */
        while data_len > AES_BLOCK_SIZE {
            if !self
                .op
                .encrypt_update(
                    &data[cursor..(cursor + AES_BLOCK_SIZE)],
                    byte_ptr!(self.macbuf.as_ptr()),
                    &mut outlen,
                )
                .is_ok()
                || outlen != AES_BLOCK_SIZE as CK_ULONG
            {
                self.finalized = true;
                return err_rv!(CKR_GENERAL_ERROR);
            }
            cursor += AES_BLOCK_SIZE;
            data_len -= AES_BLOCK_SIZE;
        }

        if data_len > 0 {
            self.padbuf[..data_len].copy_from_slice(&data[cursor..]);
        }
        self.padlen = data_len;
        Ok(())
    }

    fn finalize(&mut self, output: &mut [u8]) -> KResult<()> {
        if !self.in_use {
            return err_rv!(CKR_OPERATION_NOT_INITIALIZED);
        }
        if self.finalized {
            return err_rv!(CKR_OPERATION_NOT_INITIALIZED);
        }
        self.finalized = true;

        if output.len() != self.maclen {
            return err_rv!(CKR_GENERAL_ERROR);
        }

        if self.padlen > 0 {
            /* last full block */
            self.padbuf[self.padlen..].fill(0);
            let mut outlen: CK_ULONG = AES_BLOCK_SIZE as CK_ULONG;
            if !self
                .op
                .encrypt_update(
                    &self.padbuf,
                    byte_ptr!(self.macbuf.as_ptr()),
                    &mut outlen,
                )
                .is_ok()
                || outlen != AES_BLOCK_SIZE as CK_ULONG
            {
                return err_rv!(CKR_GENERAL_ERROR);
            }
        }

        output.copy_from_slice(&self.macbuf[..output.len()]);
        Ok(())
    }
}

impl MechOperation for AesMacOperation {
    fn finalized(&self) -> bool {
        self.finalized
    }
}

impl Sign for AesMacOperation {
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
        Ok(self.maclen)
    }
}

impl Verify for AesMacOperation {
    fn verify(&mut self, data: &[u8], signature: &[u8]) -> KResult<()> {
        self.begin()?;
        self.update(data)?;
        self.verify_final(signature)
    }

    fn verify_update(&mut self, data: &[u8]) -> KResult<()> {
        self.update(data)
    }

    fn verify_final(&mut self, signature: &[u8]) -> KResult<()> {
        let mut verify: Vec<u8> = vec![0; self.maclen];
        self.finalize(verify.as_mut_slice())?;
        if !constant_time_eq(&verify, signature) {
            return err_rv!(CKR_SIGNATURE_INVALID);
        }
        Ok(())
    }

    fn signature_len(&self) -> KResult<usize> {
        Ok(self.maclen)
    }
}
