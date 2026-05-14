use ossl::cipher::{AesSize, EncAlg};
use rustls::crypto::cipher::{
    make_tls13_aad, AeadKey, InboundOpaqueMessage, InboundPlainMessage, Iv,
    MessageDecrypter, MessageEncrypter, Nonce, OutboundOpaqueMessage,
    OutboundPlainMessage, PrefixedPayload, Tls13AeadAlgorithm,
    UnsupportedOperationError,
};
use rustls::{ConnectionTrafficSecrets, Error};

use crate::cipher::{AeadAlgorithm, TAG_LEN};

impl Tls13AeadAlgorithm for AeadAlgorithm {
    fn encrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageEncrypter> {
        Box::new(Tls13Message {
            alg: *self,
            key,
            iv,
        })
    }

    fn decrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageDecrypter> {
        Box::new(Tls13Message {
            alg: *self,
            key,
            iv,
        })
    }

    fn key_len(&self) -> usize {
        self.key_size
    }

    fn extract_keys(
        &self,
        key: AeadKey,
        iv: Iv,
    ) -> Result<ConnectionTrafficSecrets, UnsupportedOperationError> {
        match self.alg {
            EncAlg::AesGcm(AesSize::Aes128) => {
                Ok(ConnectionTrafficSecrets::Aes128Gcm { key, iv })
            }
            EncAlg::AesGcm(AesSize::Aes256) => {
                Ok(ConnectionTrafficSecrets::Aes256Gcm { key, iv })
            }
            _ => Err(UnsupportedOperationError),
        }
    }
}

struct Tls13Message {
    alg: AeadAlgorithm,
    key: AeadKey,
    iv: Iv,
}

impl MessageEncrypter for Tls13Message {
    fn encrypt(
        &mut self,
        msg: OutboundPlainMessage,
        seq: u64,
    ) -> Result<OutboundOpaqueMessage, Error> {
        let full_len = self.encrypted_payload_len(msg.payload.len());
        let mut payload = PrefixedPayload::with_capacity(full_len);
        payload.extend_from_chunks(&msg.payload);
        payload.extend_from_slice(&msg.typ.to_array());

        let tag = self.alg.encrypt_data(
            self.key.as_ref(),
            &Nonce::new(&self.iv, seq).0,
            &make_tls13_aad(full_len),
            payload.as_mut(),
        )?;
        payload.extend_from_slice(&tag);

        Ok(OutboundOpaqueMessage::new(
            rustls::ContentType::ApplicationData,
            rustls::ProtocolVersion::TLSv1_2,
            payload,
        ))
    }

    fn encrypted_payload_len(&self, payload_len: usize) -> usize {
        payload_len + 1 + TAG_LEN
    }
}

impl MessageDecrypter for Tls13Message {
    fn decrypt<'a>(
        &mut self,
        mut msg: InboundOpaqueMessage<'a>,
        seq: u64,
    ) -> Result<InboundPlainMessage<'a>, Error> {
        let plen = self.alg.decrypt_data(
            self.key.as_ref(),
            &Nonce::new(&self.iv, seq).0,
            &make_tls13_aad(msg.payload.len()),
            msg.payload.as_mut(),
        )?;
        msg.payload.truncate(plen);
        msg.into_tls13_unpadded_message()
    }
}
