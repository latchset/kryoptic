use ossl::cipher::{AesSize, EncAlg};
use rustls::crypto::cipher::{
    make_tls12_aad, AeadKey, InboundOpaqueMessage, InboundPlainMessage, Iv,
    KeyBlockShape, MessageDecrypter, MessageEncrypter, Nonce,
    OutboundOpaqueMessage, OutboundPlainMessage, PrefixedPayload,
    Tls12AeadAlgorithm, UnsupportedOperationError, NONCE_LEN,
};
use rustls::{ConnectionTrafficSecrets, Error};

use crate::cipher::{AeadAlgorithm, TAG_LEN};

const GCM_EXPLICIT_NONCE_LEN: usize = 8;

impl Tls12AeadAlgorithm for AeadAlgorithm {
    fn encrypter(
        &self,
        key: AeadKey,
        iv: &[u8],
        extra: &[u8],
    ) -> Box<dyn MessageEncrypter> {
        let mut full_iv = [0u8; NONCE_LEN];
        full_iv[..iv.len()].copy_from_slice(iv);
        full_iv[iv.len()..].copy_from_slice(extra);
        Box::new(Tls12Message {
            alg: *self,
            key,
            iv: Iv::new(full_iv),
        })
    }

    fn decrypter(&self, key: AeadKey, iv: &[u8]) -> Box<dyn MessageDecrypter> {
        let mut implicit_iv = [0u8; NONCE_LEN];
        implicit_iv[..iv.len()].copy_from_slice(iv);
        Box::new(Tls12Message {
            alg: *self,
            key,
            iv: Iv::new(implicit_iv),
        })
    }

    fn key_block_shape(&self) -> KeyBlockShape {
        match self.alg {
            EncAlg::AesGcm(_) => KeyBlockShape {
                enc_key_len: self.key_size,
                fixed_iv_len: NONCE_LEN - GCM_EXPLICIT_NONCE_LEN,
                explicit_nonce_len: GCM_EXPLICIT_NONCE_LEN,
            },
            _ => panic!("Unexpected AeadAlgorithm type"),
        }
    }

    fn extract_keys(
        &self,
        key: AeadKey,
        iv: &[u8],
        explicit: &[u8],
    ) -> Result<ConnectionTrafficSecrets, UnsupportedOperationError> {
        let mut full_iv = [0; NONCE_LEN];
        full_iv[..iv.len()].copy_from_slice(iv);
        full_iv[iv.len()..].copy_from_slice(explicit);
        let iv = Iv::new(full_iv);
        match self.alg {
            EncAlg::AesGcm(AesSize::Aes128) => {
                Ok(ConnectionTrafficSecrets::Aes128Gcm { key, iv })
            }
            EncAlg::AesGcm(AesSize::Aes256) => {
                Ok(ConnectionTrafficSecrets::Aes256Gcm { key, iv })
            }
            _ => return Err(UnsupportedOperationError),
        }
    }

    fn fips(&self) -> bool {
        crate::fips()
    }
}

struct Tls12Message {
    alg: AeadAlgorithm,
    key: AeadKey,
    iv: Iv,
}

impl MessageEncrypter for Tls12Message {
    fn encrypt(
        &mut self,
        msg: OutboundPlainMessage,
        seq: u64,
    ) -> Result<OutboundOpaqueMessage, Error> {
        let nonce = Nonce::new(&self.iv, seq);
        let full_len = self.encrypted_payload_len(msg.payload.len());
        let mut payload = PrefixedPayload::with_capacity(full_len);
        let pstart = GCM_EXPLICIT_NONCE_LEN;
        let pend = full_len - TAG_LEN;

        /* skips the implict nonce part */
        let i = NONCE_LEN - GCM_EXPLICIT_NONCE_LEN;
        payload.extend_from_slice(&nonce.0[i..]);
        payload.extend_from_chunks(&msg.payload);

        let tag = self.alg.encrypt_data(
            self.key.as_ref(),
            &nonce.0,
            &make_tls12_aad(seq, msg.typ, msg.version, msg.payload.len()),
            &mut payload.as_mut()[pstart..pend],
        )?;
        payload.extend_from_slice(&tag);

        Ok(OutboundOpaqueMessage::new(msg.typ, msg.version, payload))
    }

    fn encrypted_payload_len(&self, payload_len: usize) -> usize {
        GCM_EXPLICIT_NONCE_LEN + payload_len + TAG_LEN
    }
}

impl MessageDecrypter for Tls12Message {
    fn decrypt<'a>(
        &mut self,
        mut msg: InboundOpaqueMessage<'a>,
        seq: u64,
    ) -> Result<InboundPlainMessage<'a>, Error> {
        if msg.payload.len() < GCM_EXPLICIT_NONCE_LEN + TAG_LEN {
            return Err(Error::DecryptError);
        }
        let pstart = GCM_EXPLICIT_NONCE_LEN;
        let pend = msg.payload.len() - TAG_LEN;

        let i = NONCE_LEN - GCM_EXPLICIT_NONCE_LEN;
        let mut nonce = [0u8; NONCE_LEN];
        nonce[..i].copy_from_slice(&self.iv.as_ref()[..i]);
        nonce[i..].copy_from_slice(&msg.payload[..GCM_EXPLICIT_NONCE_LEN]);

        if self.alg.decrypt_data(
            self.key.as_ref(),
            &nonce,
            &make_tls12_aad(seq, msg.typ, msg.version, pend - pstart),
            &mut msg.payload.as_mut()[pstart..],
        )? != pend - pstart
        {
            return Err(Error::DecryptError);
        }

        Ok(msg.into_plain_message_range(pstart..pend))
    }
}
