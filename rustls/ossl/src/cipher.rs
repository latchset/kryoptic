use ossl::cipher::{AeadParams, AesSize, EncAlg, OsslCipher};
use ossl::OsslSecret;
use rustls::crypto::cipher::NONCE_LEN;
use rustls::Error;
use rustls::Error::{DecryptError, EncryptError};

use crate::osslctx;

pub const TAG_LEN: usize = 16;

#[derive(Clone, Copy, Debug)]
pub struct AeadAlgorithm {
    pub alg: EncAlg,
    pub key_size: usize,
}

impl AeadAlgorithm {
    pub fn encrypt_data(
        &self,
        key: &[u8],
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        data: &mut [u8],
    ) -> Result<[u8; TAG_LEN], Error> {
        let mut cipher = OsslCipher::new(
            osslctx(),
            self.alg,
            true,
            OsslSecret::from_slice(key),
            Some(nonce.to_vec()),
            Some(AeadParams::new(Some(aad.to_vec()), TAG_LEN, 0)),
        )
        .map_err(|_| EncryptError)?;

        let res = cipher.update_in_place(data).map_err(|_| EncryptError)?;
        if res != data.len() {
            return Err(EncryptError);
        }
        if cipher.finalize(&mut []).map_err(|_| EncryptError)? != 0 {
            return Err(EncryptError);
        }
        let mut tag = [0u8; TAG_LEN];
        cipher.get_tag(&mut tag).map_err(|_| EncryptError)?;
        Ok(tag)
    }

    pub fn decrypt_data(
        &self,
        key: &[u8],
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        data: &mut [u8],
    ) -> Result<usize, Error> {
        if data.len() < TAG_LEN {
            return Err(DecryptError);
        }

        let mut cipher = OsslCipher::new(
            osslctx(),
            self.alg,
            false,
            OsslSecret::from_slice(key),
            Some(nonce.to_vec()),
            Some(AeadParams::new(Some(aad.to_vec()), TAG_LEN, 0)),
        )
        .map_err(|_| DecryptError)?;

        let (enc, tag) = data.split_at_mut(data.len() - TAG_LEN);
        cipher.set_tag(tag).map_err(|_| DecryptError)?;
        let res = cipher.update_in_place(enc).map_err(|_| DecryptError)?;
        if res != enc.len() {
            return Err(DecryptError);
        }
        if cipher.finalize(&mut []).map_err(|_| DecryptError)? != 0 {
            return Err(DecryptError);
        }
        Ok(res)
    }
}

pub(crate) static AES_128_GCM: AeadAlgorithm = AeadAlgorithm {
    alg: EncAlg::AesGcm(AesSize::Aes128),
    key_size: 16,
};

pub(crate) static AES_256_GCM: AeadAlgorithm = AeadAlgorithm {
    alg: EncAlg::AesGcm(AesSize::Aes256),
    key_size: 32,
};

pub(crate) static CHACHA20_POLY1305: AeadAlgorithm = AeadAlgorithm {
    alg: EncAlg::ChaCha20Poly1305,
    key_size: 32,
};
