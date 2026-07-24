use rustls::crypto::hash::Hash;
use rustls::crypto::hmac::Key;
#[cfg(feature = "tls12")]
use rustls::crypto::tls12::Prf;
use rustls::crypto::tls13::{Hkdf, HkdfExpander, OkmBlock, OutputLengthError};
use rustls::crypto::ActiveKeyExchange;

use ossl::derive::{HkdfDerive, HkdfMode, Tls1PrfDerive};

use crate::hash;
use crate::hmac;
use crate::osslctx;

const MAX_TLS_HKDF_INFO_SIZE: usize = 514;

#[cfg(feature = "tls12")]
pub struct OsslPrf(pub &'static hash::OsslHash);

#[cfg(feature = "tls12")]
impl Prf for OsslPrf {
    fn for_key_exchange(
        &self,
        output: &mut [u8; 48],
        kx: Box<dyn ActiveKeyExchange>,
        peer_pub_key: &[u8],
        label: &[u8],
        seed: &[u8],
    ) -> Result<(), rustls::Error> {
        let secret = kx.complete(peer_pub_key)?;
        self.for_secret(output, secret.secret_bytes(), label, seed);
        Ok(())
    }

    fn for_secret(
        &self,
        output: &mut [u8],
        secret: &[u8],
        label: &[u8],
        seed: &[u8],
    ) {
        let mut prf = Tls1PrfDerive::new(osslctx(), self.0 .0)
            .expect("TLS1 PRF could not be initialized");
        prf.set_key(secret);
        prf.add_seed(label);
        prf.add_seed(seed);
        prf.derive(output).expect("TLS1 PRF derivatio failed");
    }
}

#[cfg(feature = "tls12")]
pub(crate) static PRF_SHA256: OsslPrf = OsslPrf(&hash::SHA256);
#[cfg(feature = "tls12")]
pub(crate) static PRF_SHA384: OsslPrf = OsslPrf(&hash::SHA384);

pub struct OsslHkdf(pub &'static hash::OsslHash);

impl Hkdf for OsslHkdf {
    fn extract_from_zero_ikm(
        &self,
        salt: Option<&[u8]>,
    ) -> Box<dyn HkdfExpander> {
        let secret = [0u8; hash::MAX_DIGEST_SIZE];
        self.extract_from_secret(salt, &secret[..self.0.output_len()])
    }

    fn extract_from_secret(
        &self,
        salt: Option<&[u8]>,
        secret: &[u8],
    ) -> Box<dyn HkdfExpander> {
        let mut hkdf = HkdfDerive::new(osslctx(), self.0 .0)
            .expect("HKDF Initialization failed");
        hkdf.set_mode(HkdfMode::ExtractOnly);
        hkdf.set_key(secret);
        if let Some(s) = salt {
            hkdf.set_salt(s);
        }
        let mut exp = OsslHkdfExpander {
            priv_key: [0u8; hash::MAX_DIGEST_SIZE],
            priv_size: self.0.output_len(),
            alg: self.0,
        };
        hkdf.derive(&mut exp.priv_key[..exp.priv_size])
            .expect("HKDF Derive failed");
        Box::new(exp)
    }

    fn expander_for_okm(&self, okm: &OkmBlock) -> Box<dyn HkdfExpander> {
        let key = okm.as_ref();
        let mut exp = OsslHkdfExpander {
            priv_key: [0u8; hash::MAX_DIGEST_SIZE],
            priv_size: key.len(),
            alg: self.0,
        };
        exp.priv_key[..exp.priv_size].copy_from_slice(key);
        Box::new(exp)
    }

    fn hmac_sign(
        &self,
        key: &OkmBlock,
        message: &[u8],
    ) -> rustls::crypto::hmac::Tag {
        hmac::from_digest_key(self.0 .0, key.as_ref()).sign(&[message])
    }
}

pub struct OsslHkdfExpander {
    priv_key: [u8; hash::MAX_DIGEST_SIZE],
    priv_size: usize,
    alg: &'static hash::OsslHash,
}

impl HkdfExpander for OsslHkdfExpander {
    fn expand_slice(
        &self,
        info: &[&[u8]],
        output: &mut [u8],
    ) -> Result<(), OutputLengthError> {
        let mut hkdf = HkdfDerive::new(osslctx(), self.alg.0)
            .map_err(|_| OutputLengthError)?;
        hkdf.set_mode(HkdfMode::ExpandOnly);
        hkdf.set_key(&self.priv_key[..self.priv_size]);
        let mut info_buf = [0u8; MAX_TLS_HKDF_INFO_SIZE];
        let mut idx = 0;
        for i in info {
            if idx + i.len() > MAX_TLS_HKDF_INFO_SIZE {
                return Err(OutputLengthError);
            }
            info_buf[idx..(idx + i.len())].copy_from_slice(i);
            idx += i.len();
        }
        if idx != 0 {
            hkdf.set_info(&info_buf[0..idx]);
        }
        hkdf.derive(output).map_err(|_| OutputLengthError)
    }

    fn expand_block(&self, info: &[&[u8]]) -> OkmBlock {
        let mut output = [0u8; hash::MAX_DIGEST_SIZE];
        let size = self.hash_len();
        self.expand_slice(info, &mut output[..size]).unwrap();
        OkmBlock::new(&output[..size])
    }

    fn hash_len(&self) -> usize {
        self.alg.output_len()
    }
}

pub(crate) static HKDF_SHA256: OsslHkdf = OsslHkdf(&hash::SHA256);
pub(crate) static HKDF_SHA384: OsslHkdf = OsslHkdf(&hash::SHA384);
