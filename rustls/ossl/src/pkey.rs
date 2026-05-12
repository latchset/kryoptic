use rustls::crypto::KeyProvider;
use rustls::pki_types::PrivateKeyDer;
use rustls::sign::SigningKey;

#[derive(Debug)]
pub struct OsslKeyProvider;

impl KeyProvider for OsslKeyProvider {
    fn load_private_key(
        &self,
        _key_der: PrivateKeyDer<'static>,
    ) -> Result<std::sync::Arc<dyn SigningKey>, rustls::Error> {
        unimplemented!()
    }
}
