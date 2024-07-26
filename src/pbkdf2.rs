// Copyright 2024 Simo Sorce
// See LICENSE.txt file for terms

use std::mem::swap;

/* https://www.rfc-editor.org/rfc/rfc8018#section-5.2 */
impl PBKDF2 {
    fn prf_fn(
        &self,
        mech: &Box<dyn Mechanism>,
        i: &[u8],
        o: &mut [u8],
    ) -> KResult<()> {
        mech.mac_new(
            &CK_MECHANISM {
                mechanism: self.prf,
                pParameter: std::ptr::null_mut(),
                ulParameterLen: 0,
            },
            &self.pass,
            CKF_DERIVE,
        )?
        .mac(i, o)
    }

    fn derive(
        &self,
        mechanisms: &Mechanisms,
        dklen: usize,
    ) -> KResult<Vec<u8>> {
        let hlen = hmac::hmac_size(self.prf);
        if hlen == CK_UNAVAILABLE_INFORMATION as usize {
            return err_rv!(CKR_MECHANISM_INVALID);
        }

        if dklen > (hlen * (u32::MAX as usize)) {
            return err_rv!(CKR_KEY_SIZE_RANGE);
        }

        let l = (dklen + hlen - 1) / hlen;

        let mut dkm = vec![0u8; dklen];

        let mech = mechanisms.get(self.prf)?;

        for b in 0..l {
            let i = b as u32 + 1;
            let mut t_i = vec![0u8; hlen];
            let mut u_out = vec![0u8; hlen];
            let mut u_in = self.salt.clone();
            u_in.extend_from_slice(&i.to_be_bytes());

            for _ in 0..self.iter {
                self.prf_fn(mech, u_in.as_slice(), u_out.as_mut_slice())?;
                t_i.iter_mut().zip(u_out.iter()).for_each(|(a, b)| *a ^= *b);
                if u_in.len() != u_out.len() {
                    u_in.resize(u_out.len(), 0);
                }
                swap(&mut u_in, &mut u_out);
            }

            let t = b * hlen;
            let mut r = dklen - t;
            if r > hlen {
                r = hlen
            };
            dkm[t..(t + r)].copy_from_slice(&t_i[0..r])
        }

        Ok(dkm)
    }
}
