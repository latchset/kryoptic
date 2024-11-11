// Copyright 2024 Simo Sorce
// See LICENSE.txt file for terms

use std::mem::swap;

use crate::error::Result;
use crate::hmac;
use crate::interface::*;
use crate::mechanism::{Mechanism, Mechanisms};
use crate::object::Object;

fn prf_fn(
    mech: &Box<dyn Mechanism>,
    prf: CK_MECHANISM_TYPE,
    pass: &Object,
    i: &[u8],
    o: &mut [u8],
) -> Result<()> {
    mech.mac_new(
        &CK_MECHANISM {
            mechanism: prf,
            pParameter: std::ptr::null_mut(),
            ulParameterLen: 0,
        },
        pass,
        CKF_DERIVE,
    )?
    .mac(i, o)
}

pub fn pbkdf2_derive(
    mechanisms: &Mechanisms,
    prf: CK_MECHANISM_TYPE,
    pass: &Object,
    salt: &Vec<u8>,
    iter: usize,
    dklen: usize,
) -> Result<Vec<u8>> {
    let hlen = hmac::hmac_size(prf);
    if hlen == usize::try_from(CK_UNAVAILABLE_INFORMATION)? {
        return Err(CKR_MECHANISM_INVALID)?;
    }

    if dklen / hlen > usize::try_from(u32::MAX)? {
        return Err(CKR_KEY_SIZE_RANGE)?;
    }

    let l = (dklen + hlen - 1) / hlen;

    let mut dkm = vec![0u8; dklen];

    let mech = mechanisms.get(prf)?;

    for b in 0..l {
        let i = u32::try_from(b + 1)?;
        let mut t_i = vec![0u8; hlen];
        let mut u_out = vec![0u8; hlen];
        let mut u_in = salt.clone();
        u_in.extend_from_slice(&i.to_be_bytes());

        for _ in 0..iter {
            prf_fn(mech, prf, pass, u_in.as_slice(), u_out.as_mut_slice())?;
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
