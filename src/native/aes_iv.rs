// Copyright 2024 Simo Sorce
// See LICENSE.txt file for terms

//! This module implements shared AES IV generation and FIPS approval
//! logic used by both the OpenSSL and AWS-LC backends.

use crate::error::Result;
#[cfg(feature = "fips")]
use crate::fips::FipsApproval;
use crate::misc::zeromem;
use crate::pkcs11::*;

/// AES Initialization Vector Object
///
/// Defines the characteristics of the IV to be used in the AES operation
/// it is referenced from. Size, generation method, counter, etc..
#[derive(Debug)]
pub struct AesIvData {
    /// The IV buffer. May hold the initial value or be updated by a generator.
    pub buf: Vec<u8>,
    /// Number of fixed bits at the start of the IV (for counter modes).
    pub fixedbits: usize,
    /// IV generation method (e.g., `CKG_GENERATE_COUNTER`).
    pub generator: CK_GENERATOR_FUNCTION,
    /// Current counter value (if applicable).
    pub counter: u64,
    /// Maximum counter value before wrapping/error (if applicable).
    pub maxcount: u64,
}

impl AesIvData {
    /// Returns an empty IV container
    pub fn none() -> Result<AesIvData> {
        Ok(AesIvData {
            buf: Vec::new(),
            fixedbits: 0,
            generator: CKG_NO_GENERATE,
            counter: 0,
            maxcount: 0,
        })
    }

    /// Returns an IV container with the specified IV
    pub fn simple(iv: Vec<u8>) -> Result<AesIvData> {
        Ok(AesIvData {
            buf: iv,
            fixedbits: 0,
            generator: CKG_NO_GENERATE,
            counter: 0,
            maxcount: 0,
        })
    }
}

impl Drop for AesIvData {
    fn drop(&mut self) {
        zeromem(self.buf.as_mut_slice());
    }
}

/// Helper function that generates IVs according to the parameters
/// stored in the object.
///
/// Each call returns the next IV and updates counters or any other
/// data in the operation object as needed.
pub fn generate_iv(iv: &mut AesIvData) -> Result<()> {
    let genbits = iv.buf.len() * 8 - iv.fixedbits;
    if iv.counter == 0 {
        iv.maxcount = if genbits >= 64 {
            u64::MAX
        } else {
            1u64 << genbits
        }
    }

    if iv.counter >= iv.maxcount {
        return Err(CKR_DATA_LEN_RANGE)?;
    }

    let mut genidx = iv.fixedbits / 8;
    let bits = genbits % 8;
    let mask = if bits == 0 { 0xff } else { (1u8 << bits) - 1 };
    let genbytes = (genbits + 7) / 8;

    match iv.generator {
        CKG_GENERATE | CKG_GENERATE_COUNTER => {
            let cntbuf = iv.counter.to_be_bytes();
            iv.buf[genidx] &= !mask;
            if genbytes > cntbuf.len() {
                genidx += 1;
                let cntidx = iv.buf.len() - cntbuf.len();
                iv.buf[genidx..cntidx].fill(0);
                iv.buf[cntidx..].copy_from_slice(&cntbuf);
            } else {
                let cntidx = cntbuf.len() - genbytes;
                iv.buf[genidx] |= cntbuf[cntidx] & mask;
                iv.buf[(genidx + 1)..].copy_from_slice(&cntbuf[(cntidx + 1)..]);
            }
        }
        CKG_GENERATE_COUNTER_XOR => {
            let cntbuf = iv.counter.to_be_bytes();
            if genbytes > cntbuf.len() {
                let cntidx = iv.buf.len() - cntbuf.len();
                iv.buf[cntidx..]
                    .iter_mut()
                    .zip(cntbuf.iter())
                    .for_each(|(iv, cn)| *iv ^= *cn);
            } else {
                let cntidx = cntbuf.len() - genbytes;
                iv.buf[genidx] ^= cntbuf[cntidx] & mask;
                iv.buf[(genidx + 1)..]
                    .iter_mut()
                    .zip(cntbuf[(cntidx + 1)..].iter())
                    .for_each(|(iv, cn)| *iv ^= *cn);
            }
        }
        CKG_GENERATE_RANDOM => {
            let mut genbuf = vec![0u8; (genbits + 7) / 8];
            crate::get_random_data(&mut genbuf)?;
            iv.buf[genidx] ^= genbuf[0] & mask;
            iv.buf[(genidx + 1)..].copy_from_slice(&genbuf[1..]);
        }
        _ => return Err(CKR_GENERAL_ERROR)?,
    }

    iv.counter += 1;
    Ok(())
}

/// AEAD specific FIPS checks
#[cfg(feature = "fips")]
pub fn fips_approval_aead(
    fips_approval: &mut FipsApproval,
    iv: &AesIvData,
    op: CK_FLAGS,
    taglen: usize,
) -> Result<()> {
    if fips_approval.is_not_approved() {
        /* if the indicator is already set as not approved,
         * just return, there is no point testing further
         * as we should never overwrite an unapproved state
         */
        return Ok(());
    }

    /* For AEAD we handle indicators directly because OpenSSL has an
     * inflexible API that provides incorrect answers when we
     * generate the IV outside of that code */

    /* The IV size must be 12 in FIPS mode */
    if iv.buf.len() != 12 {
        fips_approval.set(false);
        return Ok(());
    }

    /* The IV must be generated in FIPS mode */
    match iv.generator {
        CKG_NO_GENERATE => match op {
            CKF_ENCRYPT | CKF_WRAP | CKF_MESSAGE_ENCRYPT => {
                fips_approval.set(false);
            }
            CKF_DECRYPT | CKF_UNWRAP | CKF_MESSAGE_DECRYPT => {
                fips_approval.set(true);
            }
            _ => return Err(CKR_GENERAL_ERROR)?,
        },
        CKG_GENERATE_RANDOM => {
            let random_bits = iv.buf.len() * 8 - iv.fixedbits;
            if random_bits < 96 {
                fips_approval.set(false);
            } else {
                fips_approval.set(true);
            }
        }
        CKG_GENERATE | CKG_GENERATE_COUNTER => {
            if iv.fixedbits < 32 {
                fips_approval.set(false);
            } else {
                fips_approval.set(true);
            }
        }
        CKG_GENERATE_COUNTER_XOR => {
            let counter_bits = iv.buf.len() * 8 - iv.fixedbits;
            if counter_bits < 64 {
                fips_approval.set(false);
            } else {
                fips_approval.set(true)
            }
        }
        _ => return Err(CKR_GENERAL_ERROR)?,
    };

    /*
     * NIST SP 800-38D: 5.2.1.2 Output Data
     * > t may be any one of the following five values: 128, 120, 112,
     * > 104, or 96. For certain applications, t may be 64 or 32;
     *
     * We assume here that 64b (8B) is still acceptable value and since
     * we take the length from user in bytes, we do not have to bother
     * about values non-dividable by 8.
     */
    if taglen < 8 {
        fips_approval.set(false);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn iv(
        buf_len: usize,
        fixedbits: usize,
        generator: CK_ULONG,
        counter: u64,
    ) -> AesIvData {
        AesIvData {
            buf: vec![0u8; buf_len],
            fixedbits,
            generator,
            counter,
            maxcount: u64::MAX,
        }
    }

    #[test]
    fn test_generate_iv_counter_writes_big_endian_into_non_fixed_bits() {
        let mut data = iv(12, 32, CKG_GENERATE_COUNTER, 1);
        generate_iv(&mut data).unwrap();
        // Fixed bits are the first 4 bytes (32 bits); the counter occupies
        // the remaining 8 bytes, big-endian.
        assert_eq!(&data.buf[4..12], &1u64.to_be_bytes());
    }

    #[test]
    fn test_generate_iv_counter_increments_across_calls() {
        let mut data = iv(12, 32, CKG_GENERATE_COUNTER, 1);
        generate_iv(&mut data).unwrap();
        generate_iv(&mut data).unwrap();
        assert_eq!(&data.buf[4..12], &2u64.to_be_bytes());
    }

    #[test]
    fn test_generate_iv_counter_xor_xors_into_non_fixed_bits() {
        let mut data = iv(12, 32, CKG_GENERATE_COUNTER_XOR, 1);
        data.buf[4..12].copy_from_slice(&[0xFFu8; 8]);
        generate_iv(&mut data).unwrap();
        // The pre-existing buffer content is XORed with the big-endian
        // counter value (1), not overwritten: only the low-order byte
        // changes, and the result differs from a plain big-endian write
        // of the same counter value.
        assert_eq!(
            &data.buf[4..12],
            &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE]
        );
        assert_ne!(&data.buf[4..12], &1u64.to_be_bytes());
    }

    #[test]
    fn test_generate_iv_random_fills_non_fixed_bits() {
        let mut data = iv(12, 0, CKG_GENERATE_RANDOM, 0);
        generate_iv(&mut data).unwrap();
        assert_ne!(data.buf, vec![0u8; 12]);
    }

    #[test]
    fn test_generate_iv_fixed_bits_boundary_leaves_fixed_prefix_untouched() {
        // fixedbits == 88 means the first 11 bytes are fixed; only the
        // last byte holds non-fixed (generated) bits. (fixedbits == 96,
        // i.e. the entire 12-byte buffer fixed, is out of scope here:
        // the real generate_iv indexes buf[fixedbits / 8] unconditionally,
        // which would be an out-of-bounds access when there are zero
        // non-fixed bits at all.)
        let mut data = iv(12, 88, CKG_GENERATE_COUNTER, 1);
        data.buf[0..11].copy_from_slice(&[0xAAu8; 11]);
        generate_iv(&mut data).unwrap();
        assert_eq!(&data.buf[0..11], &[0xAAu8; 11]);
        assert_eq!(data.buf[11], 1u8);
    }
}
