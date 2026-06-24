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
        in_iv: &[u8],
        extra: &[u8],
    ) -> Box<dyn MessageEncrypter> {
        let iv = match self.alg {
            EncAlg::AesGcm(_) => {
                let mut full_iv = [0u8; NONCE_LEN];
                full_iv[..in_iv.len()].copy_from_slice(in_iv);
                full_iv[in_iv.len()..].copy_from_slice(extra);
                Iv::new(full_iv)
            }
            EncAlg::ChaCha20Poly1305 => Iv::copy(in_iv),
            _ => panic!("Unexpected AeadAlgorithm type"),
        };
        Box::new(Tls12Message {
            alg: *self,
            key,
            iv,
        })
    }

    fn decrypter(
        &self,
        key: AeadKey,
        in_iv: &[u8],
    ) -> Box<dyn MessageDecrypter> {
        let iv = match self.alg {
            EncAlg::AesGcm(_) => {
                let mut implicit_iv = [0u8; NONCE_LEN];
                implicit_iv[..in_iv.len()].copy_from_slice(in_iv);
                Iv::new(implicit_iv)
            }
            EncAlg::ChaCha20Poly1305 => Iv::copy(in_iv),
            _ => panic!("Unexpected AeadAlgorithm type"),
        };
        Box::new(Tls12Message {
            alg: *self,
            key,
            iv,
        })
    }

    fn key_block_shape(&self) -> KeyBlockShape {
        match self.alg {
            EncAlg::AesGcm(_) => KeyBlockShape {
                enc_key_len: self.key_size,
                fixed_iv_len: NONCE_LEN - GCM_EXPLICIT_NONCE_LEN,
                explicit_nonce_len: GCM_EXPLICIT_NONCE_LEN,
            },
            EncAlg::ChaCha20Poly1305 => KeyBlockShape {
                enc_key_len: self.key_size,
                fixed_iv_len: NONCE_LEN,
                explicit_nonce_len: 0,
            },
            _ => panic!("Unexpected AeadAlgorithm type"),
        }
    }

    fn extract_keys(
        &self,
        key: AeadKey,
        in_iv: &[u8],
        explicit: &[u8],
    ) -> Result<ConnectionTrafficSecrets, UnsupportedOperationError> {
        let iv = if self.alg == EncAlg::ChaCha20Poly1305 {
            Iv::copy(in_iv)
        } else {
            let mut full_iv = [0; NONCE_LEN];
            full_iv[..in_iv.len()].copy_from_slice(in_iv);
            full_iv[in_iv.len()..].copy_from_slice(explicit);
            Iv::new(full_iv)
        };
        match self.alg {
            EncAlg::AesGcm(AesSize::Aes128) => {
                Ok(ConnectionTrafficSecrets::Aes128Gcm { key, iv })
            }
            EncAlg::AesGcm(AesSize::Aes256) => {
                Ok(ConnectionTrafficSecrets::Aes256Gcm { key, iv })
            }
            EncAlg::ChaCha20Poly1305 => {
                Ok(ConnectionTrafficSecrets::Chacha20Poly1305 { key, iv })
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
        let aad = make_tls12_aad(seq, msg.typ, msg.version, msg.payload.len());

        let buffer = match self.alg.alg {
            EncAlg::AesGcm(_) => {
                let pstart = GCM_EXPLICIT_NONCE_LEN;
                let pend = full_len - TAG_LEN;

                /* skips the implict nonce part */
                let i = NONCE_LEN - GCM_EXPLICIT_NONCE_LEN;
                payload.extend_from_slice(&nonce.0[i..]);
                payload.extend_from_chunks(&msg.payload);

                &mut payload.as_mut()[pstart..pend]
            }
            EncAlg::ChaCha20Poly1305 => {
                payload.extend_from_chunks(&msg.payload);
                payload.as_mut()
            }
            _ => panic!("Unexpected AeadAlgorithm type"),
        };
        let tag =
            self.alg
                .encrypt_data(self.key.as_ref(), &nonce.0, &aad, buffer)?;
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
        if msg.payload.len() < TAG_LEN {
            return Err(Error::DecryptError);
        }
        let pend = msg.payload.len() - TAG_LEN;
        let (nonce, pstart) = match self.alg.alg {
            EncAlg::AesGcm(_) => {
                if msg.payload.len() < GCM_EXPLICIT_NONCE_LEN + TAG_LEN {
                    return Err(Error::DecryptError);
                }
                let i = NONCE_LEN - GCM_EXPLICIT_NONCE_LEN;
                let mut nonce = [0u8; NONCE_LEN];
                nonce[..i].copy_from_slice(&self.iv.as_ref()[..i]);
                nonce[i..]
                    .copy_from_slice(&msg.payload[..GCM_EXPLICIT_NONCE_LEN]);
                (Nonce(nonce), GCM_EXPLICIT_NONCE_LEN)
            }
            EncAlg::ChaCha20Poly1305 => (Nonce::new(&self.iv, seq), 0),
            _ => panic!("Unexpected AeadAlgorithm type"),
        };

        let aad = make_tls12_aad(seq, msg.typ, msg.version, pend - pstart);
        if self.alg.decrypt_data(
            self.key.as_ref(),
            &nonce.0,
            &aad,
            &mut msg.payload.as_mut()[pstart..],
        )? != pend - pstart
        {
            return Err(Error::DecryptError);
        }

        Ok(msg.into_plain_message_range(pstart..pend))
    }
}
